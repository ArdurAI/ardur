// Package kernelcapture — BPF enforce-map types for the Ardur enforcement bridge.
//
// This file defines the Go-side schema for the six BPF maps that the deny-policy
// BPF-LSM program (Slice 4.2, not yet written) will use at runtime. The daemon
// writes policy into these maps; the BPF program reads them to enforce.
//
// Slice-4 claim boundary: type definitions ONLY.
// This file does NOT load eBPF programs, pin maps, or interact with the kernel.
// The map layouts here must exactly match:
//   - Python: python/vibap/bpf_types.py
//   - C:      bpf/process_enforce.bpf.c (Slice 4.2, not yet written)
//
// When Slice 4.2 adds the C program, enforce field sizes / alignments match
// the struct layouts documented in bpf_types.py.
package kernelcapture

// BpfOp identifies the operation class being enforced.
// Values must match the “enum ardur_op“ in process_enforce.bpf.c.
type BpfOp uint32

const (
	BpfOpExec         BpfOp = 0x01
	BpfOpFileRead     BpfOp = 0x02
	BpfOpFileWrite    BpfOp = 0x03
	BpfOpNetConnect   BpfOp = 0x04
	BpfOpExternalSend BpfOp = 0x05
)

func (op BpfOp) String() string {
	switch op {
	case BpfOpExec:
		return "OP_EXEC"
	case BpfOpFileRead:
		return "OP_FILE_READ"
	case BpfOpFileWrite:
		return "OP_FILE_WRITE"
	case BpfOpNetConnect:
		return "OP_NET_CONNECT"
	case BpfOpExternalSend:
		return "OP_EXTERNAL_SEND"
	default:
		return "OP_UNKNOWN"
	}
}

// BpfAction is the enforcement action stored in cgroup_op_policy map values.
// Values must match the “enum ardur_action“ in process_enforce.bpf.c.
type BpfAction uint32

const (
	// BpfActionAllow permits the op unconditionally.
	BpfActionAllow BpfAction = 0x00
	// BpfActionDeny kills the syscall (EPERM) in ENFORCE mode; logs in PERMISSIVE.
	BpfActionDeny BpfAction = 0x01
	// BpfActionAllowlist permits the op if the target is in the path/net LPM trie.
	BpfActionAllowlist BpfAction = 0x02
)

func (a BpfAction) String() string {
	switch a {
	case BpfActionAllow:
		return "ACT_ALLOW"
	case BpfActionDeny:
		return "ACT_DENY"
	case BpfActionAllowlist:
		return "ACT_ALLOWLIST"
	default:
		return "ACT_UNKNOWN"
	}
}

// BpfEnforceMode controls whether violations kill the syscall or only log.
// Values must match the “enum ardur_enforce_mode“ in process_enforce.bpf.c.
type BpfEnforceMode uint32

const (
	// BpfEnforceModePermissive logs violations but does not kill the syscall.
	BpfEnforceModePermissive BpfEnforceMode = 0x00
	// BpfEnforceModeEnforce kills the offending syscall and logs an event.
	BpfEnforceModeEnforce BpfEnforceMode = 0x01
)

func (m BpfEnforceMode) String() string {
	switch m {
	case BpfEnforceModePermissive:
		return "PERMISSIVE"
	case BpfEnforceModeEnforce:
		return "ENFORCE"
	default:
		return "UNKNOWN"
	}
}

// KillSwitchIndex is the only valid index into the kill_switch BPF array map.
// A value of 1 at this index suspends all enforcement globally.
const KillSwitchIndex = 0

// CgroupOpMapKey is the key for the “cgroup_op_policy“ BPF hash map.
//
// C layout (16 bytes, naturally aligned):
//
//	struct ardur_cgroup_op_key { __u64 cgroup_id; __u32 op; __u32 slot; };
//
// Slot is the double-buffer index (0 or 1) — see CgroupManagedMapValue.
type CgroupOpMapKey struct {
	CgroupID uint64
	Op       BpfOp
	Slot     uint32
}

// CgroupOpMapValue is the value for the “cgroup_op_policy“ BPF hash map.
//
// C layout (12 bytes):
//
//	struct ardur_cgroup_op_value { __u32 action; __u32 enforce_mode; __u32 generation; };
type CgroupOpMapValue struct {
	Action      BpfAction
	EnforceMode BpfEnforceMode
	// Generation is provenance/debugging metadata only (which apply_policy
	// call wrote this entry). It is NOT consulted by the BPF lookup path —
	// CgroupOpMapKey.Slot plus CgroupManagedMapValue.ActiveSlot is what makes
	// a policy swap atomic: the daemon always writes a full generation into
	// the slot NOT referenced by ActiveSlot, then flips ActiveSlot last.
	Generation uint32
}

// CgroupManagedMapValue is the value for the “cgroup_managed“ BPF hash map.
//
// C layout (12 bytes):
//
//	struct ardur_managed_value { __u32 flags; __u32 generation; __u32 active_slot; };
type CgroupManagedMapValue struct {
	Flags      uint32
	Generation uint32
	// ActiveSlot selects which double-buffer slot of cgroup_op_policy is
	// currently live (0 or 1).
	ActiveSlot uint32
}

// PathAllowPrefix is one entry in the “cgroup_path_allow“ LPM trie map.
// The trie key includes a cgroup_id scope so entries from different sessions
// don't interfere.
//
// C key layout:
//
//	struct ardur_path_allow_key { __u32 prefixlen; __u64 cgroup_id; char path[4096]; };
type PathAllowPrefix struct {
	CgroupID   uint64
	PathPrefix string // Absolute path prefix (must start with "/")
}

// NetAllowPrefix is one entry in the “cgroup_net_allow“ LPM trie map.
// The “Addr“ field is a 16-byte IPv4-mapped-IPv6 or native-IPv6 address.
//
// C key layout:
//
//	struct ardur_net_allow_key { __u32 prefixlen; __u64 cgroup_id; __u8 addr[16]; };
type NetAllowPrefix struct {
	CgroupID  uint64
	Addr      [16]byte // IPv4-mapped or IPv6
	PrefixLen uint32   // CIDR prefix length (0–128)
}

// BpfEnforceEvent is the record emitted to the “enforce_events“ ringbuf
// when a policy violation is detected. The daemon reads these from the ringbuf
// and appends them to per-session evidence logs.
//
// C layout (approximate):
//
//	struct ardur_enforce_event {
//	  __u64 cgroup_id;
//	  __u32 pid;
//	  __u32 op;
//	  __u32 action_taken;
//	  __u32 enforce_mode;
//	  __u64 observed_ns;
//	  char  comm[16];
//	  char  path[256];
//	};
type BpfEnforceEvent struct {
	CgroupID    uint64
	PID         uint32
	Op          BpfOp
	ActionTaken BpfAction
	EnforceMode BpfEnforceMode
	ObservedNS  uint64
	Comm        string // up to 16 bytes (TASK_COMM_LEN)
	Path        string // up to 256 bytes; empty for non-file ops
}

// BpfPolicyGeneration tracks the monotonic generation counter the daemon uses
// when applying a new policy plan to the BPF maps. Callers start at 1 and
// increment on each update; generation 0 is treated as "uninitialized" by the
// BPF program.
type BpfPolicyGeneration = uint32
