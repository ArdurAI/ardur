"""Lowering compiler: Mission Declaration typed policies -> Biscuit facts/checks.

``MissionDeclaration`` already carries typed ``resource_policies``,
``effect_policies``, ``flow_policies``, and ``lineage_budgets`` over the wire. Until now they
were validated for shape but not enforced -- ``biscuit_passport`` only
emitted facts from the flat ``MissionPassport`` (allowed/forbidden tools,
resource_scope as bare strings).

This module is the compiler surface for closing that loop: it takes the typed
policies and lowers each one into ``biscuit_auth.Fact`` /
``biscuit_auth.Check`` primitives that an issuance path can append to the root
``BiscuitBuilder``. Those facts and checks are intended to travel inside the
token and fire when the proxy's authorizer asserts per-tool-call facts
(``resource``, ``url_host``, ``budget_delta``, ``information_flow``,
``budget_spent``, ...).

Design intent (the "don't be Tenuo++" axis):
    Tenuo exposes named constraints directly on the warrant wire format
    (Subpath, UrlPattern, UrlSafe, Shlex, CEL, Cidr, Regex, ...). Our
    Mission speaks *org-language* policy a level above -- a Mission is
    written in terms of what the issuing org cares about (resource
    scope, budget, telemetry obligations). This compiler is one emit
    target (AAT/Biscuit); the same Mission can lower to Macaroons,
    UCAN, or ZCap-LD by swapping the backend. Mission is the semantic
    invariant; the capability-token vocabulary is a codegen detail.

All string terms go through biscuit-python's parameter-binding API --
never f-string interpolation -- to avoid the escape-grammar mismatch
that Lane B (2026-04-19) fixed in ``biscuit_passport._add_fact``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from biscuit_auth import Check, Fact


class MissionCompileError(ValueError):
    """Raised when a typed Mission policy fails shape validation."""


class MissionPolicyNotImplementedError(NotImplementedError):
    """Raised when a mission declares a policy category whose compiler is not
    yet wired up.

    This is *louder than silence*: before this guard existed, a mission
    carrying non-empty ``effect_policies``, ``flow_policies``, or
    ``lineage_budgets`` would serialize
    over the wire without any corresponding Biscuit check -- the mission
    author thought they were bounded, but the proxy enforced nothing. That
    silent no-op is more dangerous than failing loudly, because the author
    has no signal that their declared bound is vaporware.

    Remove the guard only when the corresponding ``lower_*_policies`` function
    exists, is wired into the issuance path, and has tests.
    """


@dataclass(frozen=True, slots=True)
class SubpathPolicy:
    """Resource path must equal ``root`` or be a slash-delimited descendant.

    NOT a naive string prefix: ``/data`` matches ``/data`` and ``/data/x`` but
    NOT ``/database`` or ``/dataplane``. The lowered Biscuit check is
    ``$r == root or $r.starts_with(root + "/")`` -- the explicit ``/``
    separator prevents prefix-sibling collisions (the 2026-04-21 audit fix).
    """

    root: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SubpathPolicy":
        root = raw.get("root")
        if not isinstance(root, str) or not root.startswith("/"):
            raise MissionCompileError("subpath.root must be an absolute path string")
        # 2026-04-21 audit fix: reject ``..`` segments in the declared
        # root so an operator can't accidentally author a policy whose
        # matched resources resolve outside the intended subtree after
        # the executor normalizes paths. Defense-in-depth: the emitted
        # Biscuit check also refuses resources containing ``/..``.
        if ".." in root.split("/"):
            raise MissionCompileError(
                "subpath.root must not contain '..'  segments; canonicalize the path first"
            )
        root = root.rstrip("/") or "/"
        return cls(root=root)


@dataclass(frozen=True, slots=True)
class UrlAllowlistPolicy:
    """URL tool calls must target one of ``allow_domains`` (exact host match)."""

    allow_domains: tuple[str, ...]

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "UrlAllowlistPolicy":
        allow = raw.get("allow_domains")
        if (
            not isinstance(allow, list)
            or not allow
            or not all(isinstance(d, str) and d for d in allow)
        ):
            raise MissionCompileError(
                "url_allowlist.allow_domains must be a non-empty list of non-empty strings"
            )
        return cls(allow_domains=tuple(allow))


_POLICY_TYPES: dict[str, type] = {
    "subpath": SubpathPolicy,
    "url_allowlist": UrlAllowlistPolicy,
}

_VALID_SIDE_EFFECT_CLASSES: frozenset[str] = frozenset(
    {"read", "write", "network", "exec", "external_send"}
)

_VALID_FLOW_ACTIONS: frozenset[str] = frozenset({"allow", "deny"})


@dataclass(frozen=True, slots=True)
class EffectPolicy:
    """Per-event budget-delta bound for a single side-effect class.

    ``limit`` is the maximum ``budget_delta`` a single observed action of
    this class MAY consume.  ``limit == 0`` denies the class entirely.
    """

    side_effect_class: str
    limit: int

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "EffectPolicy":
        sec = raw.get("side_effect_class")
        if not isinstance(sec, str) or sec not in _VALID_SIDE_EFFECT_CLASSES:
            raise MissionCompileError(
                f"effect_policy.side_effect_class must be one of "
                f"{sorted(_VALID_SIDE_EFFECT_CLASSES)!r}, got {sec!r}"
            )
        limit = raw.get("limit")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise MissionCompileError(
                "effect_policy.limit must be a non-negative integer"
            )
        return cls(side_effect_class=sec, limit=limit)


@dataclass(frozen=True, slots=True)
class FlowPolicy:
    """IFC-style source-to-sink flow rule.

    ``action`` is ``"allow"`` or ``"deny"``.  Deny beats allow when both
    match the same (from_class, to_class) pair -- conflict resolution happens
    at compile time so the emitted facts already reflect the effective set.
    """

    from_class: str
    to_class: str
    action: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "FlowPolicy":
        from_cls = raw.get("from_class")
        if not isinstance(from_cls, str) or not from_cls:
            raise MissionCompileError(
                "flow_policy.from_class must be a non-empty string"
            )
        to_cls = raw.get("to_class")
        if not isinstance(to_cls, str) or not to_cls:
            raise MissionCompileError(
                "flow_policy.to_class must be a non-empty string"
            )
        action = raw.get("action")
        if action not in _VALID_FLOW_ACTIONS:
            raise MissionCompileError(
                f"flow_policy.action must be one of {sorted(_VALID_FLOW_ACTIONS)!r}, "
                f"got {action!r}"
            )
        return cls(from_class=from_cls, to_class=to_cls, action=action)


def load_resource_policy(raw: dict[str, Any]) -> SubpathPolicy | UrlAllowlistPolicy:
    """Validate a single ``resource_policies`` entry against the typed vocab."""
    type_name = raw.get("type")
    if not isinstance(type_name, str):
        raise MissionCompileError("resource_policy entry must carry a string 'type'")
    cls = _POLICY_TYPES.get(type_name)
    if cls is None:
        raise MissionCompileError(f"unknown resource_policy type: {type_name!r}")
    return cls.from_dict(raw)


def lower_effect_policies(
    raw_policies: Sequence[dict[str, Any]],
) -> tuple[list[Fact], list[Check]]:
    """Compile ``MissionDeclaration.effect_policies`` to Biscuit primitives.

    Emits one ``effect_limit(class, limit)`` fact per entry and a single
    combined check::

        check if budget_delta($class, $delta), effect_limit($class, $limit),
                $delta <= $limit

    Proxy contract: the proxy MUST assert ``budget_delta($class, $delta)``
    before authorizing any tool call for the class being evaluated.  The
    check passes when the asserted delta is within the declared limit for
    that class; it fails when the delta exceeds the limit or when no
    ``budget_delta`` is asserted (fail-closed).

    For the common single-class-per-authorization path this check enforces
    exactly the declared per-event limit.  Operations that touch multiple
    side-effect classes in a single authorization still need the proxy to
    enforce per-class limits via application-level fact queries.
    """
    if not raw_policies:
        return [], []

    facts: list[Fact] = []
    seen: set[str] = set()

    for raw in raw_policies:
        policy = EffectPolicy.from_dict(raw)
        if policy.side_effect_class in seen:
            raise MissionCompileError(
                f"duplicate side_effect_class in effect_policies: "
                f"{policy.side_effect_class!r}"
            )
        seen.add(policy.side_effect_class)
        facts.append(
            Fact(
                "effect_limit({cls}, {limit})",
                {"cls": policy.side_effect_class, "limit": policy.limit},
            )
        )

    checks = [
        Check(
            "check if budget_delta($class, $delta), "
            "effect_limit($class, $limit), $delta <= $limit"
        )
    ]
    return facts, checks


def lower_flow_policies(
    raw_policies: Sequence[dict[str, Any]],
) -> tuple[list[Fact], list[Check]]:
    """Compile ``MissionDeclaration.flow_policies`` to Biscuit primitives.

    Deny beats allow: if both an ``allow`` and a ``deny`` rule cover the same
    (from_class, to_class) pair, the pair is absent from the emitted
    ``flow_allow`` facts.  Conflict resolution happens at compile time so the
    token carries only the effective allow set.

    Emits one ``flow_allow(from, to)`` fact per effective allow pair and a
    single check::

        check if information_flow($from, $to), flow_allow($from, $to)

    The check passes when the proxy's asserted flow has an explicit allow
    entry; it fails on any asserted flow that has no allow (deny-only,
    conflict, or undeclared pair).  Default policy is deny: pairs not
    mentioned in any rule are blocked.

    Proxy contract: the proxy MUST assert ``information_flow($from, $to)``
    before authorizing any data-movement operation; no assertion means
    the check fails-closed.
    """
    if not raw_policies:
        return [], []

    allow_set: set[tuple[str, str]] = set()
    deny_set: set[tuple[str, str]] = set()

    for raw in raw_policies:
        policy = FlowPolicy.from_dict(raw)
        pair = (policy.from_class, policy.to_class)
        if policy.action == "allow":
            allow_set.add(pair)
        else:
            deny_set.add(pair)

    effective_allows = allow_set - deny_set

    facts: list[Fact] = [
        Fact("flow_allow({from_c}, {to_c})", {"from_c": fc, "to_c": tc})
        for fc, tc in sorted(effective_allows)
    ]

    checks = [Check("check if information_flow($from, $to), flow_allow($from, $to)")]
    return facts, checks


def lower_lineage_budgets(
    raw_budgets: dict[str, Any],
) -> tuple[list[Fact], list[Check]]:
    """Compile ``MissionDeclaration.lineage_budgets`` to Biscuit primitives.

    ``raw_budgets`` must match the ``lineage_budgets`` schema: an object with
    ``per_effect_class`` whose five keys (read, write, network, exec,
    external_send) each map to ``{"reserved": int, "ceiling": int}``.

    Emits one ``lineage_ceiling(class, ceiling)`` fact per class and a
    single check::

        check if budget_spent($class, $total), lineage_ceiling($class, $ceiling),
                $total <= $ceiling

    Validates at compile time that ``reserved <= ceiling`` for every class --
    the spec requires verifiers to reject missions that violate this invariant.

    Proxy contract: the proxy MUST assert ``budget_spent($class, $total)``
    (queried from the runtime ``FileLineageBudgetLedger``) before authorizing
    any tool call covered by a mission with lineage budgets.
    """
    if not raw_budgets:
        return [], []

    per_class = raw_budgets.get("per_effect_class")
    if not isinstance(per_class, dict):
        raise MissionCompileError(
            "lineage_budgets must have a 'per_effect_class' object"
        )

    missing = _VALID_SIDE_EFFECT_CLASSES - set(per_class.keys())
    if missing:
        raise MissionCompileError(
            f"lineage_budgets.per_effect_class missing classes: {sorted(missing)!r}"
        )

    facts: list[Fact] = []

    for cls in sorted(_VALID_SIDE_EFFECT_CLASSES):
        pair = per_class[cls]
        if not isinstance(pair, dict):
            raise MissionCompileError(
                f"lineage_budgets.per_effect_class.{cls} must be an object"
            )
        reserved = pair.get("reserved")
        ceiling = pair.get("ceiling")
        if not isinstance(reserved, int) or isinstance(reserved, bool) or reserved < 0:
            raise MissionCompileError(
                f"lineage_budgets.per_effect_class.{cls}.reserved must be a "
                f"non-negative integer"
            )
        if not isinstance(ceiling, int) or isinstance(ceiling, bool) or ceiling < 0:
            raise MissionCompileError(
                f"lineage_budgets.per_effect_class.{cls}.ceiling must be a "
                f"non-negative integer"
            )
        if reserved > ceiling:
            raise MissionCompileError(
                f"lineage_budgets.per_effect_class.{cls}: reserved ({reserved}) "
                f"must not exceed ceiling ({ceiling})"
            )
        facts.append(
            Fact("lineage_ceiling({cls}, {ceiling})", {"cls": cls, "ceiling": ceiling})
        )

    checks = [
        Check(
            "check if budget_spent($class, $total), "
            "lineage_ceiling($class, $ceiling), $total <= $ceiling"
        )
    ]
    return facts, checks


def compile_mission(
    resource_policies: Sequence[dict[str, Any]] = (),
    effect_policies: Sequence[dict[str, Any]] = (),
    flow_policies: Sequence[dict[str, Any]] = (),
    lineage_budgets: dict[str, Any] | None = None,
) -> tuple[list[Fact], list[Check]]:
    """Compile a mission's typed policies into Biscuit facts and checks.

    Aggregates :func:`lower_resource_policies`, :func:`lower_effect_policies`,
    :func:`lower_flow_policies`, and :func:`lower_lineage_budgets`.
    """
    facts: list[Fact] = []
    checks: list[Check] = []
    for lower_fn, input_policies in (
        (lower_resource_policies, resource_policies),
        (lower_effect_policies, effect_policies),
        (lower_flow_policies, flow_policies),
    ):
        sub_facts, sub_checks = lower_fn(input_policies)
        facts.extend(sub_facts)
        checks.extend(sub_checks)

    if lineage_budgets is not None:
        sub_facts, sub_checks = lower_lineage_budgets(lineage_budgets)
        facts.extend(sub_facts)
        checks.extend(sub_checks)

    return facts, checks


def lower_resource_policies(
    raw_policies: Sequence[dict[str, Any]],
) -> tuple[list[Fact], list[Check]]:
    """Compile ``MissionDeclaration.resource_policies`` to Biscuit primitives.

    Returns ``(facts, checks)``. Callers append facts+checks to the root
    ``BiscuitBuilder`` at issuance. Facts are visible via the authorizer's
    ``query``; checks fire against per-tool-call facts the proxy asserts
    (``resource($r)``, ``url_host($h)``) at authorization time.

    All policies of the same type share a SINGLE check with the matching
    roots/domains emitted as facts (2026-04-21 audit fix: the prior code
    emitted one check per policy, and Biscuit ANDs all checks -- two
    SubpathPolicy entries with different roots produced an impossible
    intersection where no resource could satisfy both).

    SubpathPolicy also guards against path-traversal bypass: the emitted
    check rejects any resource whose string contains ``/..``, so an
    executor that later normalizes ``/safe/../secret.txt`` can't slip a
    traversal past the authorizer.
    """
    facts: list[Fact] = []
    checks: list[Check] = []

    subpath_policies: list[SubpathPolicy] = []
    url_allowlist_policies: list[UrlAllowlistPolicy] = []
    for raw in raw_policies:
        policy = load_resource_policy(raw)
        if isinstance(policy, SubpathPolicy):
            subpath_policies.append(policy)
        elif isinstance(policy, UrlAllowlistPolicy):
            url_allowlist_policies.append(policy)

    if subpath_policies:
        for policy in subpath_policies:
            root_prefix = "/" if policy.root == "/" else f"{policy.root}/"
            facts.append(
                Fact("resource_subpath_root({root})", {"root": policy.root})
            )
            facts.append(
                Fact(
                    "resource_subpath_prefix({prefix})",
                    {"prefix": root_prefix},
                )
            )
        checks.append(
            Check(
                'check if resource($r), !$r.contains("/.."), '
                "resource_subpath_root($r) "
                'or resource($r), !$r.contains("/.."), '
                "resource_subpath_prefix($p), $r.starts_with($p)"
            )
        )

    if url_allowlist_policies:
        for policy in url_allowlist_policies:
            for domain in policy.allow_domains:
                facts.append(
                    Fact("url_allowed_domain({d})", {"d": domain})
                )
        checks.append(
            Check("check if url_host($h), url_allowed_domain($h)")
        )

    return facts, checks
