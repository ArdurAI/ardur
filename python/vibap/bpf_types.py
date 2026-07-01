"""Kernel-op taxonomy and BPF map schema types for the Ardur enforcement bridge.

This module defines the frozen vocabulary shared between:

- ``bpf_lower.py``   — Python lowering compiler (Slice 4.1)
- ``process_enforce.bpf.c``  — BPF-LSM program (Slice 4.2, not yet written)
- ``go/pkg/kernelcapture/bpf_enforce_types.go``  — Go daemon map-write path (Slice 4.2)

ADDING A NEW OP: bump the op constant, add a ``SEC_TO_OPS`` entry, add a
``_OP_NAMES`` entry, and update the BPF C program. Do NOT change existing
constant values — the BPF map key schema is stable across daemon restarts via
the ``generation`` field.

Slice-4 claim boundary (what this module does):
- Defines constants only; does NOT load eBPF programs, open maps, or touch kernel state.
- Constants are used by ``bpf_lower`` to construct ``BpfPolicyPlan`` objects.
- The ``BpfPolicyPlan`` is later applied to BPF maps by the daemon (Slice 4.2+).
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Kernel op codes (cgroup_op_policy map key: op field)
# These must match the ``enum ardur_op`` in process_enforce.bpf.c (Slice 4.2).
# ---------------------------------------------------------------------------

OP_EXEC: int = 0x01
"""sched_process_exec tracepoint: a process is exec'd within the cgroup."""

OP_FILE_READ: int = 0x02
"""BPF-LSM file_open hook (FMODE_READ): a process reads a file."""

OP_FILE_WRITE: int = 0x03
"""BPF-LSM file_open hook (FMODE_WRITE | FMODE_PWRITE): a process writes a file."""

OP_NET_CONNECT: int = 0x04
"""BPF-LSM socket_connect hook: a process opens an outbound network connection."""

OP_EXTERNAL_SEND: int = 0x05
"""Synthetic op: an external-send tool call (email, webhook, Slack, etc.)
detected by the proxy layer. No kernel hook; policy is enforced userspace-side
(tier-2) unless the proxy can feed the signal into a BPF map via the daemon."""

# Set of all valid op codes (for validation).
ALL_OPS: frozenset[int] = frozenset(
    {OP_EXEC, OP_FILE_READ, OP_FILE_WRITE, OP_NET_CONNECT, OP_EXTERNAL_SEND}
)

_OP_NAMES: dict[int, str] = {
    OP_EXEC: "OP_EXEC",
    OP_FILE_READ: "OP_FILE_READ",
    OP_FILE_WRITE: "OP_FILE_WRITE",
    OP_NET_CONNECT: "OP_NET_CONNECT",
    OP_EXTERNAL_SEND: "OP_EXTERNAL_SEND",
}


def op_name(op: int) -> str:
    """Return the human-readable name for an op code, or ``"OP_UNKNOWN(0x%02x)"``."""
    return _OP_NAMES.get(op, f"OP_UNKNOWN(0x{op:02x})")


# ---------------------------------------------------------------------------
# Policy actions (cgroup_op_policy map value: action field)
# These must match the ``enum ardur_action`` in process_enforce.bpf.c.
# ---------------------------------------------------------------------------

ACT_ALLOW: int = 0x00
"""Permit the op unconditionally."""

ACT_DENY: int = 0x01
"""Deny the op; log an enforcement event to the ``enforce_events`` ringbuf."""

ACT_ALLOWLIST: int = 0x02
"""Permit only if the target (path/host) matches an entry in the
corresponding LPM trie (``cgroup_path_allow`` or ``cgroup_net_allow``).
Falls back to DENY on a miss."""

_ACT_NAMES: dict[int, str] = {
    ACT_ALLOW: "ACT_ALLOW",
    ACT_DENY: "ACT_DENY",
    ACT_ALLOWLIST: "ACT_ALLOWLIST",
}


def action_name(act: int) -> str:
    """Return the human-readable name for an action code."""
    return _ACT_NAMES.get(act, f"ACT_UNKNOWN(0x{act:02x})")


# ---------------------------------------------------------------------------
# Enforcement modes (cgroup_op_policy map value: enforce_mode field)
# ---------------------------------------------------------------------------

ENFORCE_MODE_PERMISSIVE: int = 0x00
"""Log the violation but do not kill/deny the syscall. Safe for onboarding."""

ENFORCE_MODE_ENFORCE: int = 0x01
"""Kill the offending syscall (return -EPERM) and log the event."""

_ENFORCE_MODE_NAMES: dict[int, str] = {
    ENFORCE_MODE_PERMISSIVE: "ENFORCE_MODE_PERMISSIVE",
    ENFORCE_MODE_ENFORCE: "ENFORCE_MODE_ENFORCE",
}


def enforce_mode_name(mode: int) -> str:
    """Return the human-readable name for an enforcement mode."""
    return _ENFORCE_MODE_NAMES.get(mode, f"ENFORCE_MODE_UNKNOWN(0x{mode:02x})")


# ---------------------------------------------------------------------------
# Kill-switch
# ---------------------------------------------------------------------------

KILL_SWITCH_INDEX: int = 0
"""Index into the ``kill_switch`` BPF array map. Value 1 means all enforcement
is suspended globally (hot-disable without unloading the BPF program)."""

# ---------------------------------------------------------------------------
# Side-effect class → op mapping
#
# Aligns to mission_compile._VALID_SIDE_EFFECT_CLASSES.  Each class maps to
# one or more BPF op codes.  A class absent from
# ``allowed_side_effect_classes`` → ACT_DENY for ALL its ops.
# ---------------------------------------------------------------------------

SEC_TO_OPS: dict[str, frozenset[int]] = {
    "exec": frozenset({OP_EXEC}),
    "read": frozenset({OP_FILE_READ}),
    "write": frozenset({OP_FILE_WRITE}),
    "network": frozenset({OP_NET_CONNECT}),
    "external_send": frozenset({OP_EXTERNAL_SEND}),
}

# All side-effect classes in this taxonomy.
ALL_SIDE_EFFECT_CLASSES: frozenset[str] = frozenset(SEC_TO_OPS.keys())

# ---------------------------------------------------------------------------
# BPF map schema types (Python representation of the C struct layout)
#
# These dataclasses document what the BPF maps hold.  In Slice 4.2 the daemon
# will ctypes-pack / struct.pack these into map values; here they are schema
# documentation only.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CgroupOpKey:
    """Key for the ``cgroup_op_policy`` BPF hash map.

    C layout (12 bytes, packed)::

        struct ardur_cgroup_op_key {
            __u64 cgroup_id;   // from bpf_get_current_cgroup_id()
            __u32 op;          // ardur_op enum value
        };
    """

    cgroup_id: int
    op: int


@dataclass(frozen=True, slots=True)
class CgroupOpValue:
    """Value for the ``cgroup_op_policy`` BPF hash map.

    C layout (12 bytes, packed)::

        struct ardur_cgroup_op_value {
            __u32 action;        // ardur_action enum value
            __u32 enforce_mode;  // ardur_enforce_mode enum value
            __u32 generation;    // policy generation (for atomic replace)
        };
    """

    action: int
    enforce_mode: int
    generation: int


@dataclass(frozen=True, slots=True)
class PathAllowKey:
    """Key for the ``cgroup_path_allow`` LPM trie map.

    C layout::

        struct ardur_path_allow_key {
            __u32 prefixlen;           // number of significant bits
            __u64 cgroup_id;           // scoped per cgroup
            char  path[ARDUR_PATH_MAX]; // null-padded path prefix
        };
    """

    cgroup_id: int
    path_prefix: str


@dataclass(frozen=True, slots=True)
class NetAllowKey:
    """Key for the ``cgroup_net_allow`` LPM trie map (IPv4 or IPv6).

    C layout::

        struct ardur_net_allow_key {
            __u32 prefixlen;     // significant bits
            __u64 cgroup_id;
            __u8  addr[16];      // IPv4-mapped IPv6 or native IPv6
        };
    """

    cgroup_id: int
    addr: bytes          # 16-byte IPv4-mapped-IPv6 address
    prefix_len: int      # CIDR prefix length


@dataclass(frozen=True, slots=True)
class EnforceEvent:
    """Record emitted to the ``enforce_events`` BPF ringbuf on a policy hit.

    C layout::

        struct ardur_enforce_event {
            __u64 cgroup_id;
            __u32 pid;
            __u32 op;
            __u32 action_taken;    // ACT_DENY applied
            __u32 enforce_mode;
            __u64 observed_ns;     // bpf_ktime_get_ns()
            char  comm[16];        // task_comm
            char  path[256];       // for OP_FILE_*, empty otherwise
        };
    """

    cgroup_id: int
    pid: int
    op: int
    action_taken: int
    enforce_mode: int
    observed_ns: int
    comm: str
    path: str
