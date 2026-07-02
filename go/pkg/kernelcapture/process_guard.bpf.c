//go:build ignore

// process_guard.bpf.c — BPF-LSM enforcement program for Ardur agent governance.
//
// Compiled by bpf2go into embedded object files. Enforces per-cgroup op policies
// loaded by the daemon via apply_policy. This is the kernel half of Epic A —
// it converts a DENY action stored in the policy maps into a prevented syscall.
//
// Hooks:
//   lsm/bprm_check_security — exec policy (OP_EXEC)
//   lsm.s/file_open         — file open policy (OP_FILE_READ / OP_FILE_WRITE)
//   lsm/socket_connect      — network policy (OP_NET_CONNECT)
//
// Map write ordering (enforced by daemon apply_policy):
//   1. Write cgroup_op_policy entries into the INACTIVE double-buffer slot
//      (the slot not referenced by the current cgroup_managed.active_slot),
//      then cgroup_path_allow, cgroup_net_allow entries.
//   2. Write cgroup_managed LAST, pointing active_slot at the slot just
//      populated. This is the atomic gate: readers never observe a partially
//      written generation, because the slot they're reading from is never
//      mutated concurrently with a write — the writer always targets the
//      *other* slot until this final flip.
//
// Until cgroup_managed is written, the cgroup is ungoverned and all ops pass.

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// ---------------------------------------------------------------------------
// Constants — must match bpf_enforce_types.go and bpf_types.py
// ---------------------------------------------------------------------------

#define ARDUR_ACT_ALLOW     0
#define ARDUR_ACT_DENY      1
#define ARDUR_ACT_ALLOWLIST 2

#define ARDUR_ENFORCE_PERMISSIVE 0
#define ARDUR_ENFORCE_ENFORCE    1

#define ARDUR_OP_EXEC          1
#define ARDUR_OP_FILE_READ     2
#define ARDUR_OP_FILE_WRITE    3
#define ARDUR_OP_NET_CONNECT   4

// cgroup_managed flags
#define ARDUR_MANAGED_STRICT   1  // bit 0: deny on no-rule (fail-closed)

// kill_switch array index
#define ARDUR_KILL_SWITCH_IDX  0
// kill_switch value: 0 = enforcement active, 1 = kill switch engaged (pass all)
#define ARDUR_KILL_SWITCH_OFF  0
#define ARDUR_KILL_SWITCH_ON   1

// Path buffer size — matches BpfEnforceEvent.Path in bpf_enforce_types.go.
// Used for the full path read from the kernel (bprm->filename / bpf_d_path)
// and for the ringbuf event's path field.
#define ARDUR_PATH_LEN 256

// BPF_MAP_TYPE_LPM_TRIE hard-caps a key's data portion (everything after the
// __u32 prefixlen) at 256 bytes (LPM_DATA_SIZE_MAX in kernel/bpf/lpm_trie.c) —
// map creation fails with EINVAL above that, and it's a whole-map failure,
// not a per-entry one, so it takes every path/net allowlist policy down with
// it. ardur_path_lpm_key's data portion is cgroup_raw[8] + path[...], so the
// path field gets 8 fewer bytes than ARDUR_PATH_LEN to stay under the cap.
// Longer paths are truncated for allowlist matching only; the full path
// still reaches the ringbuf event via ARDUR_PATH_LEN-sized buffers elsewhere.
#define ARDUR_PATH_LPM_DATA_LEN (256 - 8)

// Network constants
#define AF_INET  2
#define AF_INET6 10

// O_ACCMODE mask (open mode bits)
#define O_ACCMODE 3

// ---------------------------------------------------------------------------
// Kernel struct definitions (CO-RE with preserve_access_index)
// ---------------------------------------------------------------------------

struct linux_binprm {
	const char *filename;
} __attribute__((preserve_access_index));

struct path {
	void *mnt;
	void *dentry;
} __attribute__((preserve_access_index));

struct file {
	struct path f_path;
	unsigned int f_flags;
} __attribute__((preserve_access_index));

struct socket {
	short type;
} __attribute__((preserve_access_index));

// struct sockaddr — minimal CO-RE shim. Not pulled in transitively by
// linux/bpf.h or the libbpf headers, so lsm/socket_connect's `address->sa_family`
// has no type to resolve against without either this shim or vmlinux.h. Only
// the field this program reads is declared; sockaddr_in/sockaddr_in6 payload
// bytes past sa_family are read via raw offset arithmetic below (stable UAPI
// layout, not CO-RE'd).
struct sockaddr {
	unsigned short sa_family;
} __attribute__((preserve_access_index));

// ---------------------------------------------------------------------------
// BPF map key/value structs
// ---------------------------------------------------------------------------

// cgroup_op_policy key: {cgroup_id, op, slot}
// C layout must match CgroupOpMapKey in bpf_enforce_types.go.
// __u64 + __u32 + __u32 = 16 bytes, naturally aligned (no implicit padding).
//
// `slot` is the double-buffer index (0 or 1) this entry belongs to. The daemon
// always writes a full policy generation into the slot NOT referenced by the
// current cgroup_managed.active_slot, then flips active_slot — so a reader
// never observes entries from two different apply_policy calls mixed together
// for the same cgroup+op.
struct ardur_cgroup_op_key {
	__u64 cgroup_id;
	__u32 op;
	__u32 slot;
};

// cgroup_op_policy value: {action, enforce_mode, generation}
// generation is provenance/debugging only (which apply_policy call wrote this
// entry); it is NOT consulted by the lookup path — slot selection via
// cgroup_managed.active_slot is what makes the swap atomic.
struct ardur_cgroup_op_value {
	__u32 action;
	__u32 enforce_mode;
	__u32 generation;
};

// cgroup_managed key: raw 8 bytes for cgroup_id (avoids __u64 alignment at offset 4)
struct ardur_managed_key {
	__u8 cgroup_raw[8];
};

// cgroup_managed value: {flags, generation, active_slot}
// flags bit 0 = ARDUR_MANAGED_STRICT.  active_slot selects which double-buffer
// slot of cgroup_op_policy is currently live (0 or 1).
struct ardur_managed_value {
	__u32 flags;
	__u32 generation;
	__u32 active_slot;
};

// Path LPM trie key: {prefixlen, cgroup_raw[8], path[ARDUR_PATH_LPM_DATA_LEN]}
// prefixlen in bits = 64 (cgroup scope) + path_bytes * 8.
struct ardur_path_lpm_key {
	__u32 prefixlen;
	__u8  cgroup_raw[8];
	char  path[ARDUR_PATH_LPM_DATA_LEN];
};

// Net LPM trie key: {prefixlen, cgroup_raw[8], addr[16]}
// prefixlen in bits = 64 (cgroup scope) + CIDR prefix length.
// IPv4 stored as 4 bytes in addr[0..3] (network byte order); remaining bytes 0.
// IPv6 stored as 16 bytes in addr[0..15] (network byte order).
struct ardur_net_lpm_key {
	__u32 prefixlen;
	__u8  cgroup_raw[8];
	__u8  addr[16];
};

// Ringbuf event emitted on each policy decision for a governed cgroup.
struct ardur_enforce_event {
	__u64 cgroup_id;
	__u32 pid;
	__u32 op;
	__u32 action_taken;
	__u32 enforce_mode;
	__u64 observed_ns;
	char  comm[16];
	char  path[ARDUR_PATH_LEN];
};

// ---------------------------------------------------------------------------
// BPF maps
// ---------------------------------------------------------------------------

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	// 2x headroom vs. a single-buffer design: each governed {cgroup,op} pair
	// occupies at most 2 entries (one per double-buffer slot) at any time.
	__uint(max_entries, 16384);
	__type(key,   struct ardur_cgroup_op_key);
	__type(value, struct ardur_cgroup_op_value);
} cgroup_op_policy SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__type(key,   struct ardur_path_lpm_key);
	__type(value, __u64);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cgroup_path_allow SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__type(key,   struct ardur_net_lpm_key);
	__type(value, __u64);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cgroup_net_allow SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key,   struct ardur_managed_key);
	__type(value, struct ardur_managed_value);
} cgroup_managed SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key,   __u32);
	__type(value, __u32);
} kill_switch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 14);  // 16 KB
} enforce_events SEC(".maps");

// Per-CPU scratch map for the path LPM key — avoids a 272-byte BPF stack alloc.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key,   __u32);
	__type(value, struct ardur_path_lpm_key);
} path_lpm_scratch SEC(".maps");

// Per-CPU scratch map for the net LPM key.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key,   __u32);
	__type(value, struct ardur_net_lpm_key);
} net_lpm_scratch SEC(".maps");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static __always_inline int kill_switch_is_on(void)
{
	__u32 idx = ARDUR_KILL_SWITCH_IDX;
	__u32 *v = bpf_map_lookup_elem(&kill_switch, &idx);
	return v && *v == ARDUR_KILL_SWITCH_ON;
}

static __always_inline struct ardur_managed_value *
lookup_managed(__u64 cgroup_id)
{
	struct ardur_managed_key k;
	__builtin_memcpy(k.cgroup_raw, &cgroup_id, 8);
	return bpf_map_lookup_elem(&cgroup_managed, &k);
}

static __always_inline struct ardur_cgroup_op_value *
lookup_op_policy(__u64 cgroup_id, __u32 op, __u32 active_slot)
{
	struct ardur_cgroup_op_key k = {
		.cgroup_id = cgroup_id,
		.op = op,
		.slot = active_slot,
	};
	return bpf_map_lookup_elem(&cgroup_op_policy, &k);
}

// path_is_allowed looks the supplied path up in the cgroup_path_allow LPM trie.
// Uses the per-CPU scratch map to avoid large stack allocations.
// Returns 1 if the path is explicitly allowed, 0 otherwise.
static int path_is_allowed(__u64 cgroup_id, const char *path_src, int path_len)
{
	if (path_len <= 0)
		return 0;

	__u32 scratch_idx = 0;
	struct ardur_path_lpm_key *lk =
		bpf_map_lookup_elem(&path_lpm_scratch, &scratch_idx);
	if (!lk)
		return 0;

	__builtin_memset(lk, 0, sizeof(*lk));
	__builtin_memcpy(lk->cgroup_raw, &cgroup_id, 8);

	// Clamp to [0, ARDUR_PATH_LPM_DATA_LEN] — lk->path's actual size, smaller
	// than the ARDUR_PATH_LEN source buffer path_src was read into (see
	// ARDUR_PATH_LPM_DATA_LEN's comment: the LPM trie key has 8 fewer bytes
	// of headroom than a plain path buffer). The ternary alone gives the
	// verifier a provable static upper bound on copy_len, so
	// bpf_probe_read_kernel's size argument is always in range. (A bitmask
	// clamp here is a trap: masking by (N-1) wraps copy_len==N to 0, silently
	// zeroing a full-length path read.)
	__u32 copy_len = path_len < ARDUR_PATH_LPM_DATA_LEN ? (__u32)path_len : (__u32)ARDUR_PATH_LPM_DATA_LEN;
	bpf_probe_read_kernel(lk->path, copy_len, path_src);

	// prefixlen: 64 bits for cgroup_raw + path bytes (excluding null terminator)
	int prefix_bytes = copy_len > 0 ? (int)copy_len - 1 : 0;
	lk->prefixlen = 64 + ((__u32)prefix_bytes) * 8;

	__u64 *allowed = bpf_map_lookup_elem(&cgroup_path_allow, lk);
	return allowed && *allowed != 0;
}

// net_is_allowed looks the IP address up in the cgroup_net_allow LPM trie.
// addr_bytes: pointer to the raw address bytes (network byte order).
// addr_len:   4 for IPv4, 16 for IPv6.
// Returns 1 if the address is explicitly allowed, 0 otherwise.
static int net_is_allowed(__u64 cgroup_id, const __u8 *addr_bytes, int addr_len)
{
	__u32 scratch_idx = 0;
	struct ardur_net_lpm_key *lk =
		bpf_map_lookup_elem(&net_lpm_scratch, &scratch_idx);
	if (!lk)
		return 0;

	__builtin_memset(lk, 0, sizeof(*lk));
	__builtin_memcpy(lk->cgroup_raw, &cgroup_id, 8);

	// Same clamp-not-mask reasoning as path_is_allowed: masking by 15 would
	// wrap a full 16-byte IPv6 read (copy_len==16) to 0.
	__u32 copy_len = addr_len < 16 ? (__u32)addr_len : (__u32)16;
	bpf_probe_read_kernel(lk->addr, copy_len, addr_bytes);

	// prefixlen: 64 bits for cgroup scope + full address length for host lookup.
	// LPM trie will find the longest stored prefix ≤ this.
	lk->prefixlen = 64 + ((__u32)addr_len) * 8;

	__u64 *allowed = bpf_map_lookup_elem(&cgroup_net_allow, lk);
	return allowed && *allowed != 0;
}

// emit_event writes one decision record to the enforce_events ringbuf.
// path_src may be NULL for network ops.
static __always_inline void emit_event(
	__u64 cgroup_id, __u32 op, __u32 action, __u32 enforce_mode,
	const char *path_src)
{
	struct ardur_enforce_event *ev =
		bpf_ringbuf_reserve(&enforce_events, sizeof(*ev), 0);
	if (!ev)
		return;
	__builtin_memset(ev, 0, sizeof(*ev));
	ev->cgroup_id    = cgroup_id;
	ev->pid          = (__u32)(bpf_get_current_pid_tgid() >> 32);
	ev->op           = op;
	ev->action_taken = action;
	ev->enforce_mode = enforce_mode;
	ev->observed_ns  = bpf_ktime_get_ns();
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));
	if (path_src)
		bpf_probe_read_kernel_str(ev->path, sizeof(ev->path), path_src);
	bpf_ringbuf_submit(ev, 0);
}

// decide_ctx packs decide()'s inputs into a single pointer argument.
// BPF-to-BPF calls (decide is `static`, not `__always_inline`, so clang emits
// a real subprogram call) allow at most 5 register args (r1-r5); the previous
// 6-scalar signature (cgroup_id, op, path_src, path_len, addr_bytes, addr_len)
// exceeded that and also tripped "stack arguments are not supported". One
// pointer arg sidesteps both limits.
struct decide_ctx {
	__u64 cgroup_id;
	__u32 op;
	int path_len;
	int addr_len;
	const char *path_src;
	const __u8 *addr_bytes;
};

// decide returns 0 (allow) or -1 (-EPERM, deny) and emits an event.
// For allowlist ops, ctx->path_src/path_len (or addr_bytes/addr_len) carry the
// path or address to check against the LPM allowlist.
//
// Used by guard_bprm_check and guard_socket_connect (both regular, non-
// sleepable LSM programs), so it may freely reach the LPM_TRIE allowlist
// maps (cgroup_path_allow, cgroup_net_allow) via path_is_allowed/
// net_is_allowed. guard_file_open is SLEEPABLE (lsm.s, required for
// bpf_d_path) and the kernel forbids sleepable programs from touching
// LPM_TRIE maps AT ALL — not just at runtime: the verifier rejects a
// sleepable program if its *compiled call graph* reaches an incompatible
// map type, even through a branch that's never taken at runtime, and
// decide/decide_file_open are separate `static` (not `__always_inline`)
// subprograms specifically so the map-reachability sets don't merge. Do not
// make guard_file_open call this function — see decide_file_open below,
// which is deliberately a separate copy of this logic with no LPM calls in
// its compiled body. (Confirmed on a real BPF-LSM kernel: sharing this
// function with guard_file_open fails program load with "Sleepable programs
// can only use array, hash, ringbuf and local storage maps".)
static int decide(struct decide_ctx *ctx)
{
	__u64 cgroup_id = ctx->cgroup_id;
	__u32 op = ctx->op;
	const char *path_src = ctx->path_src;

	if (kill_switch_is_on())
		return 0;

	struct ardur_managed_value *mv = lookup_managed(cgroup_id);
	if (!mv)
		return 0;  // cgroup not governed — untouched

	struct ardur_cgroup_op_value *pol =
		lookup_op_policy(cgroup_id, op, mv->active_slot);

	if (!pol) {
		// No rule for this op in the active slot
		if (mv->flags & ARDUR_MANAGED_STRICT) {
			emit_event(cgroup_id, op, ARDUR_ACT_DENY, ARDUR_ENFORCE_ENFORCE, path_src);
			return -1;  // -EPERM: fail-closed
		}
		emit_event(cgroup_id, op, ARDUR_ACT_ALLOW, ARDUR_ENFORCE_PERMISSIVE, path_src);
		return 0;
	}

	if (pol->action == ARDUR_ACT_DENY) {
		emit_event(cgroup_id, op, ARDUR_ACT_DENY, pol->enforce_mode, path_src);
		if (pol->enforce_mode == ARDUR_ENFORCE_ENFORCE)
			return -1;  // -EPERM
		return 0;  // permissive: log only
	}

	if (pol->action == ARDUR_ACT_ALLOWLIST) {
		int ok = 0;
		if (op == ARDUR_OP_NET_CONNECT && ctx->addr_bytes && ctx->addr_len > 0)
			ok = net_is_allowed(cgroup_id, ctx->addr_bytes, ctx->addr_len);
		else if (path_src && ctx->path_len > 0)
			ok = path_is_allowed(cgroup_id, path_src, ctx->path_len);

		if (!ok) {
			emit_event(cgroup_id, op, ARDUR_ACT_DENY, pol->enforce_mode, path_src);
			if (pol->enforce_mode == ARDUR_ENFORCE_ENFORCE)
				return -1;
			return 0;
		}
		emit_event(cgroup_id, op, ARDUR_ACT_ALLOW, pol->enforce_mode, path_src);
		return 0;
	}

	// ACT_ALLOW or unrecognised: pass
	emit_event(cgroup_id, op, ARDUR_ACT_ALLOW, pol->enforce_mode, path_src);
	return 0;
}

// decide_file_open is decide()'s counterpart for guard_file_open (the only
// sleepable hook). Identical except its ACT_ALLOWLIST branch never calls
// path_is_allowed — see decide()'s doc comment for why sleepable programs
// can't reach cgroup_path_allow (LPM_TRIE) at all. Path allowlisting for
// OP_FILE_READ/OP_FILE_WRITE fails closed instead: logged and denied under
// ENFORCE_STRICT, logged and allowed under PERMISSIVE — the same fallback
// the "no rule" case below already uses. OP_EXEC and OP_NET_CONNECT
// allowlisting (bprm_check, socket_connect — both non-sleepable, both still
// call decide() above) are unaffected by this; only file-op path-prefix
// allowlisting is unavailable, and only because of this kernel constraint.
static int decide_file_open(struct decide_ctx *ctx)
{
	__u64 cgroup_id = ctx->cgroup_id;
	__u32 op = ctx->op;
	const char *path_src = ctx->path_src;

	if (kill_switch_is_on())
		return 0;

	struct ardur_managed_value *mv = lookup_managed(cgroup_id);
	if (!mv)
		return 0;  // cgroup not governed — untouched

	struct ardur_cgroup_op_value *pol =
		lookup_op_policy(cgroup_id, op, mv->active_slot);

	if (!pol) {
		// No rule for this op in the active slot
		if (mv->flags & ARDUR_MANAGED_STRICT) {
			emit_event(cgroup_id, op, ARDUR_ACT_DENY, ARDUR_ENFORCE_ENFORCE, path_src);
			return -1;  // -EPERM: fail-closed
		}
		emit_event(cgroup_id, op, ARDUR_ACT_ALLOW, ARDUR_ENFORCE_PERMISSIVE, path_src);
		return 0;
	}

	if (pol->action == ARDUR_ACT_DENY) {
		emit_event(cgroup_id, op, ARDUR_ACT_DENY, pol->enforce_mode, path_src);
		if (pol->enforce_mode == ARDUR_ENFORCE_ENFORCE)
			return -1;  // -EPERM
		return 0;  // permissive: log only
	}

	if (pol->action == ARDUR_ACT_ALLOWLIST) {
		// No LPM access from a sleepable program (see function doc comment
		// above) — fail closed rather than silently pass every file open
		// through unchecked.
		emit_event(cgroup_id, op, ARDUR_ACT_DENY, pol->enforce_mode, path_src);
		if (pol->enforce_mode == ARDUR_ENFORCE_ENFORCE)
			return -1;
		return 0;
	}

	// ACT_ALLOW or unrecognised: pass
	emit_event(cgroup_id, op, ARDUR_ACT_ALLOW, pol->enforce_mode, path_src);
	return 0;
}

// ---------------------------------------------------------------------------
// LSM hooks
// ---------------------------------------------------------------------------

// guard_bprm_check — intercepts execve/execveat.
// Reads the executable path via bpf_probe_read_kernel_str on bprm->filename.
SEC("lsm/bprm_check_security")
int BPF_PROG(guard_bprm_check, struct linux_binprm *bprm, int ret)
{
	if (ret != 0)
		return ret;

	__u64 cgroup_id = bpf_get_current_cgroup_id();

	char exec_path[ARDUR_PATH_LEN];
	__builtin_memset(exec_path, 0, sizeof(exec_path));
	const char *filename = BPF_CORE_READ(bprm, filename);
	long pret = bpf_probe_read_kernel_str(exec_path, sizeof(exec_path), filename);
	int path_len = pret > 0 ? (int)pret : 0;

	struct decide_ctx dctx = {
		.cgroup_id = cgroup_id,
		.op = ARDUR_OP_EXEC,
		.path_src = exec_path,
		.path_len = path_len,
	};
	return decide(&dctx);
}

// guard_file_open — intercepts open(2)/openat(2) etc.
// Uses lsm.s (sleepable) to call bpf_d_path for the full resolved path.
// Distinguishes read vs write by examining f_flags & O_ACCMODE.
//
// Calls decide_file_open, NOT decide — this is the one sleepable hook, and
// it must never reach an LPM_TRIE map (see decide()'s doc comment).
SEC("lsm.s/file_open")
int BPF_PROG(guard_file_open, struct file *file, int ret)
{
	if (ret != 0)
		return ret;

	__u64 cgroup_id = bpf_get_current_cgroup_id();

	unsigned int flags = BPF_CORE_READ(file, f_flags);
	__u32 op = ((flags & O_ACCMODE) == 0) ? ARDUR_OP_FILE_READ : ARDUR_OP_FILE_WRITE;

	char path_buf[ARDUR_PATH_LEN];
	__builtin_memset(path_buf, 0, sizeof(path_buf));
	long pret = bpf_d_path(&file->f_path, path_buf, sizeof(path_buf));
	int path_len = pret > 0 ? (int)pret : 0;

	struct decide_ctx dctx = {
		.cgroup_id = cgroup_id,
		.op = op,
		.path_src = path_buf,
		.path_len = path_len,
	};
	return decide_file_open(&dctx);
}

// guard_socket_connect — intercepts connect(2).
// Reads sa_family and extracts the raw IP address for net LPM lookup.
SEC("lsm/socket_connect")
int BPF_PROG(guard_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen, int ret)
{
	if (ret != 0)
		return ret;

	__u64 cgroup_id = bpf_get_current_cgroup_id();

	__u16 sa_family = 0;
	bpf_probe_read_kernel(&sa_family, sizeof(sa_family), &address->sa_family);

	__u8 addr_buf[16];
	__builtin_memset(addr_buf, 0, sizeof(addr_buf));
	int addr_len = 0;

	if (sa_family == AF_INET) {
		// sin_addr.s_addr is at offset 4 in struct sockaddr_in (after sin_family + sin_port)
		bpf_probe_read_kernel(addr_buf, 4, (char *)address + 4);
		addr_len = 4;
	} else if (sa_family == AF_INET6) {
		// sin6_addr is at offset 8 in struct sockaddr_in6 (after sin6_family + sin6_port + sin6_flowinfo)
		bpf_probe_read_kernel(addr_buf, 16, (char *)address + 8);
		addr_len = 16;
	} else {
		// Non-IP socket (e.g. AF_UNIX): pass unconditionally.
		return 0;
	}

	struct decide_ctx dctx = {
		.cgroup_id = cgroup_id,
		.op = ARDUR_OP_NET_CONNECT,
		.addr_bytes = addr_buf,
		.addr_len = addr_len,
	};
	return decide(&dctx);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
