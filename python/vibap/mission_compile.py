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
(``resource``, ``url_host``, ...).

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
    over the wire without any corresponding Biscuit check — the mission
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
    ``$r == root or $r.starts_with(root + "/")`` — the explicit ``/``
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
                "subpath.root must not contain '..' segments; canonicalize the path first"
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

    NOT YET IMPLEMENTED. Non-empty input raises :class:`MissionPolicyNotImplementedError`
    to prevent silent no-op enforcement. See the class docstring for rationale.
    """
    if raw_policies:
        raise MissionPolicyNotImplementedError(
            "effect_policies lowering is not yet implemented; a mission "
            "declaring effect_policies would ship without any Biscuit check "
            "being emitted. Remove effect_policies from the mission until "
            "support lands, or implement lower_effect_policies() and remove "
            "this guard."
        )
    return [], []


def lower_flow_policies(
    raw_policies: Sequence[dict[str, Any]],
) -> tuple[list[Fact], list[Check]]:
    """Compile ``MissionDeclaration.flow_policies`` to Biscuit primitives.

    NOT YET IMPLEMENTED. Non-empty input raises :class:`MissionPolicyNotImplementedError`
    to prevent silent no-op enforcement.
    """
    if raw_policies:
        raise MissionPolicyNotImplementedError(
            "flow_policies lowering is not yet implemented; a mission "
            "declaring flow_policies would ship without any Biscuit check "
            "being emitted. Remove flow_policies from the mission until "
            "support lands, or implement lower_flow_policies() and remove "
            "this guard."
        )
    return [], []


def lower_lineage_budgets(
    raw_budgets: Sequence[dict[str, Any]],
) -> tuple[list[Fact], list[Check]]:
    """Compile mission-declared lineage budgets to Biscuit primitives.

    Phase 1 intentionally defers this category. Runtime delegation already uses
    ``FileLineageBudgetLedger`` to reserve child budgets, but a non-empty
    mission-level ``lineage_budgets`` declaration is not yet lowered into
    verifier state. Raising here keeps unsupported budget policy from being
    accepted as a silent no-op.
    """
    if raw_budgets:
        raise MissionPolicyNotImplementedError(
            "lineage_budgets lowering is Phase 1 deferred; mission-declared "
            "lineage budgets are not enforced by the compiler yet. Remove "
            "lineage_budgets from the mission until support lands, or "
            "implement lower_lineage_budgets() and wire it into issuance."
        )
    return [], []


def compile_mission(
    resource_policies: Sequence[dict[str, Any]] = (),
    effect_policies: Sequence[dict[str, Any]] = (),
    flow_policies: Sequence[dict[str, Any]] = (),
    lineage_budgets: Sequence[dict[str, Any]] = (),
) -> tuple[list[Fact], list[Check]]:
    """Compile a mission's typed policies into Biscuit facts and checks.

    Aggregates :func:`lower_resource_policies`, :func:`lower_effect_policies`,
    :func:`lower_flow_policies`, and :func:`lower_lineage_budgets`. Non-empty
    effect/flow/lineage budget policies currently raise
    :class:`MissionPolicyNotImplementedError` — see that class for why silence
    was the wrong default.
    """
    facts: list[Fact] = []
    checks: list[Check] = []
    for lower_fn, input_policies in (
        (lower_resource_policies, resource_policies),
        (lower_effect_policies, effect_policies),
        (lower_flow_policies, flow_policies),
        (lower_lineage_budgets, lineage_budgets),
    ):
        sub_facts, sub_checks = lower_fn(input_policies)
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
    emitted one check per policy, and Biscuit ANDs all checks — two
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
        # Single check, OR-joined across all declared subpath roots/prefixes.
        # $r must (a) not contain "/..", AND (b) either equal a declared
        # subpath root exactly, OR start with a declared subpath prefix.
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
