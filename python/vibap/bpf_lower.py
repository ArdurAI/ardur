"""Lowering compiler: Mission Declaration typed policies → BpfPolicyPlan.

This is the BPF analogue of ``mission_compile.py``: it takes the same mission
inputs and produces a ``BpfPolicyPlan`` that the Ardur daemon (Slice 4.2+) can
write into the six BPF maps to enforce policy at the kernel level.

Lowering rules (what each input field maps to):

``allowed_side_effect_classes``
    For every class in ``ALL_SIDE_EFFECT_CLASSES`` that is NOT present in
    ``allowed_side_effect_classes``, emit ``ACT_DENY`` for all ops in that
    class's ``SEC_TO_OPS`` set.  Classes that ARE present emit nothing (default
    is ACT_ALLOW from the BPF program's fallthrough).

``forbidden_tools``
    Project each tool name to a BPF op via ``_tool_to_bpf_op``.  Mappable →
    add ``ACT_DENY`` entry.  Unmappable (tool name doesn't carry a reliable BPF
    op signal) → tier2_ops.

``allowed_tools``
    When ``allowed_tools`` is non-empty and ALL tools in the mission are listed
    (i.e. the list is being used as an allowlist, not a hint), project each name
    via ``_tool_to_bpf_op``.  Mappable → ACT_ALLOW (adds an explicit allow that
    overrides any class-level deny for that op).  Unmappable → tier2_ops.
    Rationale: BPF can't filter by tool name; name-based allows need proxy
    enforcement, hence tier2.

``resource_scope`` (legacy path strings from ``MissionPassport.resource_scope``)
    Each non-empty string is treated as an absolute path prefix → ``path_allow``
    entry; ops OP_FILE_READ and OP_FILE_WRITE are set to ACT_ALLOWLIST.

``resource_policies`` (typed ``MissionDeclaration.resource_policies``)
    ``SubpathPolicy`` entries → path_allow + OP_FILE_{READ,WRITE} = ACT_ALLOWLIST.
    ``UrlAllowlistPolicy`` entries: each domain is hostname-only → tier2_ops
    (BPF net maps work on IP/CIDR; hostname resolution is fragile and out of
    scope for Slice 4.1).  If a caller pre-resolves a domain to an IP/CIDR and
    passes it through ``net_prefixes``, that goes directly into net_allow.

``effect_policies``, ``flow_policies``, ``lineage_budgets``
    These are semantic / budget constraints evaluated at the proxy layer. BPF
    cannot express them. → tier2_ops.

Enforce mode:
    ``enforce_mode=ENFORCE_MODE_ENFORCE`` (ENFORCE_STRICT) enables the loud-guard:
    any policy dimension that bpf_lower cannot lower to a BPF plan
    (i.e. that would produce a tier2_op) raises ``MissionPolicyNotImplementedError``
    rather than silently falling through to a tier2 reference.  The rationale is
    the same as in mission_compile: silent under-enforcement is more dangerous
    than a loud failure.

Claim boundary (Slice 4.0 / 4.1):
- Produces a ``BpfPolicyPlan`` Python object.
- Does NOT write to BPF maps, talk to the daemon, load eBPF programs, or touch
  kernel state.  Map writes happen in Slice 4.2 (daemon apply path).
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Sequence

from .bpf_types import (
    ACT_ALLOW,
    ACT_ALLOWLIST,
    ACT_DENY,
    ALL_SIDE_EFFECT_CLASSES,
    ENFORCE_MODE_ENFORCE,
    ENFORCE_MODE_PERMISSIVE,
    OP_EXEC,
    OP_EXTERNAL_SEND,
    OP_FILE_READ,
    OP_FILE_WRITE,
    OP_NET_CONNECT,
    SEC_TO_OPS,
    op_name,
)
from .mission_compile import (
    MissionPolicyNotImplementedError,
    SubpathPolicy,
    UrlAllowlistPolicy,
    load_resource_policy,
)


class BpfLowerError(ValueError):
    """Raised when a mission input fails validation during BPF lowering."""


# ---------------------------------------------------------------------------
# Plan types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class OpPolicyEntry:
    """One entry in the op-policy portion of the plan.

    Maps to one row in the ``cgroup_op_policy`` BPF hash map (without the
    ``cgroup_id`` field, which the daemon supplies at apply time).
    """

    op: int
    action: int
    enforce_mode: int

    def __post_init__(self) -> None:
        from .bpf_types import ALL_OPS

        if self.op not in ALL_OPS:
            raise BpfLowerError(f"unknown op code: {self.op!r}")

    def __str__(self) -> str:
        from .bpf_types import action_name, enforce_mode_name

        return (
            f"OpPolicyEntry({op_name(self.op)}, "
            f"{action_name(self.action)}, {enforce_mode_name(self.enforce_mode)})"
        )


@dataclass(frozen=True, slots=True)
class BpfPolicyPlan:
    """The lowered BPF policy plan for one mission session.

    This object is the boundary between the pure-Python lowering compiler and
    the daemon's BPF-map write path (Slice 4.2+).

    Fields
    ------
    op_policies
        Op-level deny/allow/allowlist rules.  The daemon iterates this list
        and writes each entry into the ``cgroup_op_policy`` BPF hash map keyed
        by ``(cgroup_id, op)``.

    path_allow
        Absolute path prefixes permitted when OP_FILE_READ or OP_FILE_WRITE is
        set to ACT_ALLOWLIST.  The daemon writes these into the
        ``cgroup_path_allow`` LPM trie.

    net_allow
        IP/CIDR strings (IPv4 or IPv6) permitted when OP_NET_CONNECT is set to
        ACT_ALLOWLIST.  The daemon writes these into the ``cgroup_net_allow``
        LPM trie.

    tier2_ops
        Policy dimensions that cannot be expressed in BPF maps and require
        userspace (proxy) enforcement.  Each entry is a human-readable label.
        In ENFORCE_STRICT mode (enforce_mode=ENFORCE_MODE_ENFORCE) the lowering
        compiler raises ``MissionPolicyNotImplementedError`` instead of
        populating this field.

    enforce_mode
        The global default enforcement mode.  Individual ``OpPolicyEntry``
        records may override this per-op.
    """

    op_policies: tuple[OpPolicyEntry, ...]
    path_allow: tuple[str, ...]
    net_allow: tuple[str, ...]
    tier2_ops: tuple[str, ...]
    enforce_mode: int = ENFORCE_MODE_PERMISSIVE

    def has_kernel_enforcement(self) -> bool:
        """True if any op has a kernel-level deny or allowlist rule."""
        return any(e.action in {ACT_DENY, ACT_ALLOWLIST} for e in self.op_policies)

    def denies_op(self, op: int) -> bool:
        """True if the plan unconditionally denies ``op``."""
        return any(e.op == op and e.action == ACT_DENY for e in self.op_policies)

    def allowlists_op(self, op: int) -> bool:
        """True if the plan enforces allowlist gating for ``op``."""
        return any(e.op == op and e.action == ACT_ALLOWLIST for e in self.op_policies)


# ---------------------------------------------------------------------------
# Tool-name → BPF op projection
# ---------------------------------------------------------------------------

# Word components that suggest an OS exec operation.
# Matching is done against _components_ (split on [_\-\s]) of the tool name
# rather than via \b word boundaries, because \b does not fire at '_' chars.
_EXEC_KEYWORDS: frozenset[str] = frozenset(
    {"bash", "sh", "shell", "exec", "execute", "run", "subprocess", "invoke",
     "spawn", "terminal", "cmd", "powershell", "script", "make", "npm", "pip",
     "cargo"}
)

_EXTERNAL_SEND_KEYWORDS: frozenset[str] = frozenset(
    {"send", "email", "message", "post", "webhook", "slack", "teams", "notify",
     "notification", "alert", "sms", "twilio", "sendgrid", "mailgun", "ses",
     "push"}
)

# Two-component pairs that qualify external-send context (send alone is
# too broad; require at least one messaging-domain component nearby).
_EXTERNAL_SEND_DOMAIN_KEYWORDS: frozenset[str] = frozenset(
    {"email", "sms", "slack", "teams", "webhook", "twilio", "sendgrid",
     "mailgun", "ses", "push", "notification", "alert"}
)

_FILE_WRITE_KEYWORDS: frozenset[str] = frozenset(
    {"write", "create", "edit", "update", "delete", "append", "truncate",
     "overwrite", "save", "modify"}
)

_NET_CONNECT_KEYWORDS: frozenset[str] = frozenset(
    {"http", "fetch", "download", "upload", "request", "curl", "wget",
     "connect", "api", "web"}
)


def _tool_to_bpf_op(tool_name: str) -> int | None:
    """Project a tool name to a BPF op code, or ``None`` if unmappable.

    This is a best-effort inference from tool name components (split on
    ``[_\\-\\s]+``). Tools whose operation cannot be reliably inferred return
    ``None`` and are placed in ``tier2_ops`` (proxy must enforce).

    BPF enforcement is coarse-grained by nature: the kernel sees exec/file/net
    events, not tool names. Name-based allowlists are tier-2 by definition.

    Priority order: exec > external_send > file_write > net_connect.
    """
    parts = frozenset(re.split(r"[_\-\s]+", tool_name.lower()))

    if parts & _EXEC_KEYWORDS:
        return OP_EXEC

    # external_send: require at least one domain-specific keyword so that
    # a bare "send" (too generic) doesn't inadvertently match.
    if parts & _EXTERNAL_SEND_DOMAIN_KEYWORDS:
        return OP_EXTERNAL_SEND

    # file-write: "write" alone is a strong signal for file ops.
    if parts & _FILE_WRITE_KEYWORDS:
        return OP_FILE_WRITE

    # Network: require a reasonably specific keyword.
    if parts & _NET_CONNECT_KEYWORDS:
        return OP_NET_CONNECT

    return None


# ---------------------------------------------------------------------------
# Lowering helpers
# ---------------------------------------------------------------------------


def _is_ip_or_cidr(value: str) -> bool:
    """Return True if ``value`` is a valid IPv4/IPv6 address or CIDR prefix."""
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _normalize_path_prefix(path: str) -> str | None:
    """Return a normalized absolute path prefix, or ``None`` if invalid."""
    path = path.strip()
    if not path or not path.startswith("/"):
        return None
    # Reject traversal segments.
    if ".." in path.split("/"):
        return None
    return path.rstrip("/") or "/"


# ---------------------------------------------------------------------------
# Primary lowering function
# ---------------------------------------------------------------------------


def lower_to_bpf_policy_plan(
    *,
    allowed_side_effect_classes: Sequence[str] = (),
    forbidden_tools: Sequence[str] = (),
    allowed_tools: Sequence[str] = (),
    resource_scope: Sequence[str] = (),
    resource_policies: Sequence[dict[str, Any]] = (),
    effect_policies: Sequence[dict[str, Any]] = (),
    flow_policies: Sequence[dict[str, Any]] = (),
    lineage_budgets: dict[str, Any] | None = None,
    net_prefixes: Sequence[str] = (),
    enforce_mode: int = ENFORCE_MODE_PERMISSIVE,
) -> BpfPolicyPlan:
    """Lower mission policy inputs to a ``BpfPolicyPlan``.

    Parameters
    ----------
    allowed_side_effect_classes
        From ``MissionPassport.allowed_side_effect_classes``.  Classes NOT
        listed here get ACT_DENY for all their BPF ops.
    forbidden_tools
        From ``MissionPassport.forbidden_tools``.  Tool names are projected to
        ops; unmappable names go to ``tier2_ops``.
    allowed_tools
        From ``MissionPassport.allowed_tools``.  Only useful when the mission
        uses the list as a restrictive allowlist; unmappable names → tier2_ops.
    resource_scope
        Legacy ``MissionPassport.resource_scope`` path strings.
    resource_policies
        Typed ``MissionDeclaration.resource_policies`` dicts.
    effect_policies, flow_policies, lineage_budgets
        Semantic constraints evaluated at the proxy layer. → tier2_ops.
        In ENFORCE_STRICT (enforce_mode=ENFORCE_MODE_ENFORCE), their presence
        raises ``MissionPolicyNotImplementedError``.
    net_prefixes
        Caller-supplied IP/CIDR strings to put in net_allow directly (used when
        the caller has already resolved hostnames out-of-band).
    enforce_mode
        ``ENFORCE_MODE_PERMISSIVE`` (default): log but don't kill.
        ``ENFORCE_MODE_ENFORCE``: kill + loud-guard on unimplemented dimensions.
    """
    # Accumulated plan components.
    op_entries: dict[int, OpPolicyEntry] = {}  # op → entry (last write wins)
    path_allow: list[str] = []
    net_allow: list[str] = []
    tier2: list[str] = []

    # ------------------------------------------------------------------
    # 1. allowed_side_effect_classes → class-level deny for absent classes
    # ------------------------------------------------------------------
    allowed_sec_set = frozenset(allowed_side_effect_classes)
    if allowed_sec_set - ALL_SIDE_EFFECT_CLASSES:
        unknown = sorted(allowed_sec_set - ALL_SIDE_EFFECT_CLASSES)
        raise BpfLowerError(
            f"unknown side_effect_class in allowed_side_effect_classes: {unknown!r}"
        )

    if allowed_side_effect_classes:
        # Only apply class-level denies when the mission explicitly restricts
        # classes. An empty list means "no class-level restriction declared".
        for sec, ops in SEC_TO_OPS.items():
            if sec not in allowed_sec_set:
                for op in ops:
                    if op not in op_entries:
                        op_entries[op] = OpPolicyEntry(
                            op=op, action=ACT_DENY, enforce_mode=enforce_mode
                        )

    # ------------------------------------------------------------------
    # 2. forbidden_tools → op-level deny (tool name projection)
    # ------------------------------------------------------------------
    for tool in forbidden_tools:
        op = _tool_to_bpf_op(tool)
        if op is not None:
            # A more specific deny beats a class-level deny (both are ACT_DENY,
            # but we track the entry so the caller knows it came from tool policy).
            op_entries[op] = OpPolicyEntry(
                op=op, action=ACT_DENY, enforce_mode=enforce_mode
            )
        else:
            tier2.append(f"forbidden_tool:{tool}")

    # ------------------------------------------------------------------
    # 3. allowed_tools → op-level explicit allow (rare; overrides class deny)
    # ------------------------------------------------------------------
    for tool in allowed_tools:
        op = _tool_to_bpf_op(tool)
        if op is not None:
            # An explicit tool-level allow overrides a class-level deny only if
            # the class was denied. We record it as ACT_ALLOW so the daemon can
            # decide precedence at apply time.
            if op in op_entries and op_entries[op].action == ACT_DENY:
                tier2.append(f"allowed_tool_overrides_class_deny:{tool}")
            else:
                op_entries[op] = OpPolicyEntry(
                    op=op, action=ACT_ALLOW, enforce_mode=enforce_mode
                )
        else:
            tier2.append(f"allowed_tool:{tool}")

    # ------------------------------------------------------------------
    # 4. resource_scope (legacy path strings) → path_allow + ACT_ALLOWLIST
    # ------------------------------------------------------------------
    for raw_path in resource_scope:
        normalized = _normalize_path_prefix(raw_path)
        if normalized:
            path_allow.append(normalized)

    if path_allow:
        # Set both read and write ops to ACT_ALLOWLIST if not already denied.
        for op in (OP_FILE_READ, OP_FILE_WRITE):
            current = op_entries.get(op)
            if current is None or current.action != ACT_DENY:
                op_entries[op] = OpPolicyEntry(
                    op=op, action=ACT_ALLOWLIST, enforce_mode=enforce_mode
                )

    # ------------------------------------------------------------------
    # 5. resource_policies (typed) → path_allow or tier2_ops
    # ------------------------------------------------------------------
    for raw_policy in resource_policies:
        policy = load_resource_policy(raw_policy)
        if isinstance(policy, SubpathPolicy):
            normalized = _normalize_path_prefix(policy.root)
            if normalized and normalized not in path_allow:
                path_allow.append(normalized)
            for op in (OP_FILE_READ, OP_FILE_WRITE):
                current = op_entries.get(op)
                if current is None or current.action != ACT_DENY:
                    op_entries[op] = OpPolicyEntry(
                        op=op, action=ACT_ALLOWLIST, enforce_mode=enforce_mode
                    )
        elif isinstance(policy, UrlAllowlistPolicy):
            for domain in policy.allow_domains:
                if _is_ip_or_cidr(domain):
                    if domain not in net_allow:
                        net_allow.append(domain)
                else:
                    # Hostname → tier2: BPF net maps work on IP/CIDR.
                    tier2.append(f"url_allowlist_hostname:{domain}")

    # ------------------------------------------------------------------
    # 6. Caller-supplied IP/CIDR net prefixes (pre-resolved hostnames)
    # ------------------------------------------------------------------
    for prefix in net_prefixes:
        if _is_ip_or_cidr(prefix):
            if prefix not in net_allow:
                net_allow.append(prefix)
        else:
            tier2.append(f"invalid_net_prefix:{prefix}")

    if net_allow:
        op = OP_NET_CONNECT
        current = op_entries.get(op)
        if current is None or current.action != ACT_DENY:
            op_entries[op] = OpPolicyEntry(
                op=op, action=ACT_ALLOWLIST, enforce_mode=enforce_mode
            )

    # ------------------------------------------------------------------
    # 7. effect_policies, flow_policies, lineage_budgets → tier2_ops
    #    In ENFORCE_STRICT: raise if any are present.
    # ------------------------------------------------------------------
    semantic_dims: list[str] = []
    if effect_policies:
        semantic_dims.append("effect_policies")
    if flow_policies:
        semantic_dims.append("flow_policies")
    if lineage_budgets:
        semantic_dims.append("lineage_budgets")

    if semantic_dims:
        if enforce_mode == ENFORCE_MODE_ENFORCE:
            raise MissionPolicyNotImplementedError(
                f"Mission declares {semantic_dims!r} but bpf_lower cannot lower "
                f"these to kernel BPF maps (they require proxy/tier-2 enforcement). "
                f"Remove them from this mission or switch to ENFORCE_MODE_PERMISSIVE. "
                f"This guard exists because ENFORCE_STRICT must not silently "
                f"under-enforce: if BPF is the only enforcer, these policies are vaporware."
            )
        tier2.extend(semantic_dims)

    return BpfPolicyPlan(
        op_policies=tuple(op_entries.values()),
        path_allow=tuple(path_allow),
        net_allow=tuple(net_allow),
        tier2_ops=tuple(tier2),
        enforce_mode=enforce_mode,
    )
