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
//   1. Write cgroup_op_policy, cgroup_path_allow, cgroup_net_allow entries.
//   2. Write cgroup_managed LAST (generation-atomic gate).
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

// Path buffer size — matches BpfEnforceEvent.Path in bpf_enforce_types.go
#define ARDUR_PATH_LEN 256

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

// ---------------------------------------------------------------------------
// BPF map key/value structs
// ---------------------------------------------------------------------------

// cgroup_op_policy key: {cgroup_id, op}
// C layout must match CgroupOpMapKey in bpf_enforce_types.go.
// __u64 then __u32 → 12 bytes, natural alignment OK (no padding needed for hash).
struct ardur_cgroup_op_key {
	__u64 cgroup_id;
	__u32 op;
};

// cgroup_op_policy value: {action, enforce_mode, generation}
struct ardur_cgroup_op_value {
	__u32 action;
	__u32 enforce_mode;
	__u32 generation;
};

// cgroup_managed key: raw 8 bytes for cgroup_id (avoids __u64 alignment at offset 4)
struct ardur_managed_key {
	__u8 cgroup_raw[8];
};

// cgroup_managed value: {flags, generation}
// flags bit 0 = ARDUR_MANAGED_STRICT.  generation must match op-policy entries.
struct ardur_managed_value {
	__u32 flags;
	__u32 generation;
};

// Path LPM trie key: {prefixlen, cgroup_raw[8], path[ARDUR_PATH_LEN]}
// prefixlen in bits = 64 (cgroup scope) + path_bytes * 8.
struct ardur_path_lpm_key {
	__u32 prefixlen;
	__u8  cgroup_raw[8];
	char  path[ARDUR_PATH_LEN];
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
	__uint(max_entries, 8192);
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
lookup_op_policy(__u64 cgroup_id, __u32 op, __u32 active_generation)
{
	struct ardur_cgroup_op_key k = {.cgroup_id = cgroup_id, .op = op};
	struct ardur_cgroup_op_value *v = bpf_map_lookup_elem(&cgroup_op_policy, &k);
	if (!v || v->generation != active_generation)
		return NULL;
	return v;
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

	int copy_len = path_len < ARDUR_PATH_LEN ? path_len : ARDUR_PATH_LEN;
	bpf_probe_read_kernel(lk->path, copy_len & (ARDUR_PATH_LEN - 1), path_src);

	// prefixlen: 64 bits for cgroup_raw + path bytes (excluding null terminator)
	int prefix_bytes = copy_len > 0 ? copy_len - 1 : 0;
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

	int copy_len = addr_len < 16 ? addr_len : 16;
	bpf_probe_read_kernel(lk->addr, copy_len & 15, addr_bytes);

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

// decide returns 0 (allow) or -1 (-EPERM, deny) and emits an event.
// For allowlist ops, path_src/path_len carry the path or addr string for the LPM check.
static int decide(
	__u64 cgroup_id, __u32 op,
	const char *path_src, int path_len,
	const __u8 *addr_bytes, int addr_len)
{
	if (kill_switch_is_on())
		return 0;

	struct ardur_managed_value *mv = lookup_managed(cgroup_id);
	if (!mv)
		return 0;  // cgroup not governed — untouched

	struct ardur_cgroup_op_value *pol =
		lookup_op_policy(cgroup_id, op, mv->generation);

	if (!pol) {
		// No rule for this op in the active generation
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
		if (op == ARDUR_OP_NET_CONNECT && addr_bytes && addr_len > 0)
			ok = net_is_allowed(cgroup_id, addr_bytes, addr_len);
		else if (path_src && path_len > 0)
			ok = path_is_allowed(cgroup_id, path_src, path_len);

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

	return decide(cgroup_id, ARDUR_OP_EXEC,
	              exec_path, path_len, NULL, 0);
}

// guard_file_open — intercepts open(2)/openat(2) etc.
// Uses lsm.s (sleepable) to call bpf_d_path for the full resolved path.
// Distinguishes read vs write by examining f_flags & O_ACCMODE.
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

	return decide(cgroup_id, op, path_buf, path_len, NULL, 0);
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

	return decide(cgroup_id, ARDUR_OP_NET_CONNECT,
	              NULL, 0, addr_buf, addr_len);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
