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
//      then cgroup_file_allow, cgroup_net_allow entries (cgroup_path_allow
//      too, if a future caller ever populates it — see its doc comment).
//   2. Write cgroup_managed LAST, pointing active_slot at the slot just
//      populated. This is the atomic gate: readers never observe a partially
//      written generation, because the slot they're reading from is never
//      mutated concurrently with a write — the writer always targets the
//      *other* slot until this final flip.
//
// Until cgroup_managed is written, the cgroup is ungoverned and all ops pass.
//
// Path allowlisting uses two different map types depending on which hook
// checks it: cgroup_path_allow (LPM_TRIE, byte-prefix match) for the two
// non-sleepable hooks, cgroup_file_allow (HASH, directory-boundary-aware
// ancestor walk) for the sleepable lsm.s/file_open hook, which cannot touch
// an LPM_TRIE at all. See ardur_file_allow_key's doc comment below for the
// full explanation — this split exists because of a real kernel constraint,
// not a design preference.

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// barrier_var: opaque compiler barrier on a single scalar, the standard
// kernel/BPF idiom for when a value is genuinely bounded but the compiler's
// own optimizer proves that bound so thoroughly it discards the very
// instructions (e.g. a redundant-looking mask) the *verifier* needs to see
// in order to independently re-derive the same bound at a given use site.
// Used once below, at exactly the spot that needed it — see the comment
// there for the concrete failure this fixes.
#define barrier_var(var) asm volatile("" : "+r"(var))

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
//
// NOTE: this LPM trie is reachable only from decide() (guard_bprm_check /
// guard_socket_connect, both non-sleepable). guard_file_open is sleepable
// and cannot use it at all — see cgroup_file_allow below, which is what
// actually backs OP_FILE_READ/OP_FILE_WRITE ACT_ALLOWLIST today.
#define ARDUR_PATH_LPM_DATA_LEN (256 - 8)

// cgroup_file_allow (below) walks a resolved path's ancestor directory
// boundaries from the root outward, probing each one against the hash map,
// via file_allow_walk_cb + bpf_loop() (Linux 5.17+ — see
// file_path_is_allowed's doc comment for why a bpf_loop() callback, not a
// plain `for` loop, is what actually loads: every plain-loop version tried
// blew the verifier's ~1M-instruction complexity budget, regardless of this
// bound's value). 32 ancestor matches covers any realistic policy root depth
// (SubpathPolicy roots are typically 2-6 components, e.g.
// /home/user/project); a root nested deeper than this is rejected at
// lowering time instead of silently never matching — see bpf_lower.py's
// ancestor-depth guard (_FILE_ALLOW_MAX_ANCESTOR_DEPTH, which must be kept
// equal to this constant).
#define ARDUR_FILE_ALLOW_MAX_ANCESTORS 32

#define ARDUR_BOOTSTRAP_USR          (1U << 0)
#define ARDUR_BOOTSTRAP_LD_CACHE     (1U << 1)
#define ARDUR_BOOTSTRAP_CA_CERTS     (1U << 2)
#define ARDUR_BOOTSTRAP_URANDOM      (1U << 3)
#define ARDUR_BOOTSTRAP_PROC         (1U << 4)
#define ARDUR_BOOTSTRAP_LIB          (1U << 5)
#define ARDUR_BOOTSTRAP_LIB64        (1U << 6)

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

struct vfsmount {
	int mnt_flags;
} __attribute__((preserve_access_index));

struct path {
	struct vfsmount *mnt;
	void *dentry;
} __attribute__((preserve_access_index));

struct super_block {
	__u32 s_dev;
} __attribute__((preserve_access_index));

struct inode {
	unsigned long i_ino;
	struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct file {
	struct path f_path;
	unsigned int f_flags;
	struct inode *f_inode;
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

// File allow hash key: {cgroup_raw[8], path[ARDUR_PATH_LEN]}.
// Unlike ardur_path_lpm_key, this is an EXACT-match key for a HASH map, not a
// byte-prefix key for an LPM trie: the value stored at a given path is either
// present (that exact path string, zero-padded, is an allowed directory or
// file) or absent. Directory-prefix ("subpath") matching is implemented by
// the *caller* (file_path_is_allowed) probing this map once per ancestor
// directory boundary of the resolved path, not by the map itself doing
// prefix matching — this is what makes it usable from a sleepable program
// (BPF_MAP_TYPE_HASH is one of the map types sleepable programs may touch;
// BPF_MAP_TYPE_LPM_TRIE is not) and, as a side effect, what makes matching
// directory-boundary-aware: probing only ever tests strings that end exactly
// at a '/' or at the full path, so an entry for "/data" can never spuriously
// match a query for "/database" the way LPM byte-prefix matching would. This
// mirrors the boundary-aware semantics SubpathPolicy already documents and
// the Biscuit/proxy layer already enforces (mission_compile.py, 2026-04-21
// audit fix) — this map brings the BPF layer's matching in line with that,
// not just the sleepable-vs-LPM constraint.
struct ardur_file_allow_key {
	__u8 cgroup_raw[8];
	char path[ARDUR_PATH_LEN];
};

// Trusted runtime reads are deliberately separate from mission file allows:
// they are valid only for one daemon-observed root TGID and one live policy
// generation, and guard_file_open consults them only for OP_FILE_READ.
struct ardur_trusted_root_value {
	__u32 root_tgid;
	__u32 generation;
	__u32 allow_mask;
};

struct ardur_bootstrap_file_key {
	__u8 cgroup_raw[8];
	__u64 device;
	__u64 inode;
};

struct ardur_bootstrap_file_value {
	__u32 generation;
};

struct ardur_bootstrap_observation_key {
	__u32 observer_tgid;
	__u32 padding;
	__u64 inode;
};

struct ardur_bootstrap_observation_value {
	__u8 cgroup_raw[8];
	__u32 generation;
	__u32 registered;
	__u64 device;
};

// Exact embedded-governance endpoint. Port bytes stay in sockaddr network
// order so userspace and BPF can compare the wire tuple without conversion.
struct ardur_control_plane_key {
	__u8 cgroup_raw[8];
	__u16 family;
	__u8 port[2];
	__u8 addr[16];
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

// cgroup_file_allow backs OP_FILE_READ / OP_FILE_WRITE ACT_ALLOWLIST for
// guard_file_open (the sleepable hook — see ardur_file_allow_key's doc
// comment for why this is a HASH map, not the LPM trie the other allowlists
// use). One entry per (cgroup, allowed-path) pair, same population as
// cgroup_path_allow would have held for file ops before this map existed;
// max_entries mirrors cgroup_path_allow's budget for the same reason (one
// entry per SubpathPolicy/resource_scope root across all governed cgroups).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key,   struct ardur_file_allow_key);
	__type(value, __u64);
} cgroup_file_allow SEC(".maps");

// Exact executable/script objects registered by the daemon while the root
// process is stopped at exec. The LSM itself records superblock device + inode,
// avoiding userspace namespace translation. The trusted-root map separately
// proves TGID and generation, so descendants cannot use these entries.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384); // 4 daemon-observed objects x 4,096 sessions
	__type(key,   struct ardur_bootstrap_file_key);
	__type(value, struct ardur_bootstrap_file_value);
} cgroup_bootstrap_file_allow SEC(".maps");

// One-shot daemon observation requests. Userspace supplies its own TGID, the
// already-observed inode, target cgroup, and generation, then opens that file.
// guard_file_open records the kernel-native device and acknowledges success.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct ardur_bootstrap_observation_key);
	__type(value, struct ardur_bootstrap_observation_value);
} bootstrap_file_observation SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key,   struct ardur_managed_key);
	__type(value, struct ardur_trusted_root_value);
} cgroup_trusted_root SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key,   struct ardur_control_plane_key);
	__type(value, __u32);  // policy generation
} cgroup_control_plane_allow SEC(".maps");

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

// enforce_events_dropped (issue #122) counts decision events lost when the
// enforce_events ringbuf is full: bpf_ringbuf_reserve returns NULL in
// emit_event and the record is dropped in-kernel. cilium/ebpf's ringbuf.Record
// carries no lost-sample counter (unlike perf), so without this the daemon
// reports LostSamples=0 forever and the hash-chained receipt log silently
// under-counts denials under load — a gap the "no gaps" claim cannot see.
// A single global __u64, incremented atomically; the daemon reads it and folds
// the delta into the enforcement summary's LostSamples.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key,   __u32);
	__type(value, __u64);
} enforce_events_dropped SEC(".maps");

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

// Task-local scratch value for file_allow_scratch: one canonical lookup key
// plus the resolved path. The file-open program is sleepable, so mutable
// per-CPU scratch may be reused by another task while a helper sleeps. Task
// storage follows the current task across scheduling and is released at exit.
struct ardur_file_allow_scratch {
	struct ardur_file_allow_key policy_key;
	char path_copy[ARDUR_PATH_LEN];
};

// TASK_STORAGE arrived in Linux 5.11, below this program's existing Linux
// 5.17 floor from bpf_loop.
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key,   int);
	__type(value, struct ardur_file_allow_scratch);
} file_allow_scratch SEC(".maps");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static __always_inline int kill_switch_is_on(void)
{
	__u32 idx = ARDUR_KILL_SWITCH_IDX;
	__u32 *v = bpf_map_lookup_elem(&kill_switch, &idx);
	return v && *v == ARDUR_KILL_SWITCH_ON;
}

static __always_inline struct ardur_file_allow_scratch *
current_file_allow_scratch(void)
{
	void *task = bpf_get_current_task_btf();
	return bpf_task_storage_get(
		&file_allow_scratch, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
}

static __always_inline __u64 file_device(struct file *file)
{
	return (__u64)BPF_CORE_READ(file, f_inode, i_sb, s_dev);
}

static __always_inline void observe_bootstrap_file(struct file *file)
{
	__u64 inode = BPF_CORE_READ(file, f_inode, i_ino);
	if (inode == 0)
		return;
	struct ardur_bootstrap_observation_key request_key = {
		.observer_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32),
		.inode = inode,
	};
	struct ardur_bootstrap_observation_value *request =
		bpf_map_lookup_elem(&bootstrap_file_observation, &request_key);
	if (!request)
		return;
	__u64 device = file_device(file);
	if (device == 0)
		return;
	struct ardur_bootstrap_file_key allow_key = {
		.device = device,
		.inode = inode,
	};
	__builtin_memcpy(allow_key.cgroup_raw, request->cgroup_raw, 8);
	struct ardur_bootstrap_file_value allow_value = {
		.generation = request->generation,
	};
	if (bpf_map_update_elem(
			&cgroup_bootstrap_file_allow, &allow_key, &allow_value, BPF_ANY) == 0) {
		request->device = device;
		request->registered = 1;
	}
}

static __always_inline struct ardur_managed_value *
lookup_managed(__u64 cgroup_id)
{
	struct ardur_managed_key k;
	__builtin_memcpy(k.cgroup_raw, &cgroup_id, 8);
	return bpf_map_lookup_elem(&cgroup_managed, &k);
}

static __always_inline struct ardur_trusted_root_value *
lookup_trusted_root(__u64 cgroup_id, __u32 generation)
{
	struct ardur_managed_key k;
	__builtin_memcpy(k.cgroup_raw, &cgroup_id, 8);
	struct ardur_trusted_root_value *trusted =
		bpf_map_lookup_elem(&cgroup_trusted_root, &k);
	__u32 current_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	if (!trusted || trusted->root_tgid != current_tgid ||
		trusted->generation != generation)
		return 0;
	return trusted;
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
	barrier_var(copy_len);
	copy_len &= 0xff;
	if (copy_len > ARDUR_PATH_LPM_DATA_LEN)
		copy_len = ARDUR_PATH_LPM_DATA_LEN;
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
	barrier_var(copy_len);
	copy_len &= 0x1f;
	if (copy_len > 16)
		copy_len = 16;
	bpf_probe_read_kernel(lk->addr, copy_len, addr_bytes);

	// prefixlen: 64 bits for cgroup scope + full address length for host lookup.
	// LPM trie will find the longest stored prefix ≤ this.
	lk->prefixlen = 64 + ((__u32)addr_len) * 8;

	__u64 *allowed = bpf_map_lookup_elem(&cgroup_net_allow, lk);
	return allowed && *allowed != 0;
}

static __always_inline int control_plane_is_allowed(
	__u64 cgroup_id, __u32 generation, __u16 family,
	const __u8 *port, const __u8 *addr, int addr_len)
{
	struct ardur_control_plane_key key;
	__builtin_memset(&key, 0, sizeof(key));
	__builtin_memcpy(key.cgroup_raw, &cgroup_id, 8);
	if (!lookup_trusted_root(cgroup_id, generation))
		return 0;
	key.family = family;
	bpf_probe_read_kernel(key.port, 2, port);
	__u32 copy_len = addr_len < 16 ? (__u32)addr_len : (__u32)16;
	barrier_var(copy_len);
	copy_len &= 0x1f;
	if (copy_len > 16)
		copy_len = 16;
	bpf_probe_read_kernel(key.addr, copy_len, addr);
	__u32 *allowed_generation =
		bpf_map_lookup_elem(&cgroup_control_plane_allow, &key);
	return allowed_generation && *allowed_generation == generation;
}

// file_allow_lookup probes cgroup_file_allow for the exact string
// path_src[0:len). Shared by every candidate check in file_path_is_allowed
// so the scratch-key fill logic (zero, stamp cgroup, copy) lives in one
// place. len must be <= ARDUR_PATH_LEN (the scratch key's path field size);
// callers are responsible for that bound.
static __always_inline int file_allow_lookup(
	struct ardur_file_allow_scratch *scratch, __u64 cgroup_id,
	const char *path_src, __u32 len)
{
	struct ardur_file_allow_key *fk = &scratch->policy_key;
	__builtin_memset(fk, 0, sizeof(*fk));
	__builtin_memcpy(fk->cgroup_raw, &cgroup_id, 8);
	bpf_probe_read_kernel(fk->path, len, path_src);
	__u64 *allowed = bpf_map_lookup_elem(&cgroup_file_allow, fk);
	return allowed && *allowed != 0;
}

// file_allow_walk_ctx carries file_path_is_allowed's loop state into
// file_allow_walk_cb across the bpf_loop() call — see file_path_is_allowed's
// doc comment for why this indirection (a kfunc callback) exists instead of
// a plain `for` loop.
struct file_allow_walk_ctx {
	struct ardur_file_allow_scratch *scratch;
	__u64 cgroup_id;
	char *local;
	int full_len;
	int checked;
	int found;
};

// file_allow_walk_cb is bpf_loop()'s per-iteration callback: idx runs
// 0..nr_loops-1, mapped to ancestor scan position i = idx+1 (skipping index
// 0, the leading '/', which never marks a useful ancestor boundary on its
// own — see file_path_is_allowed's root-path special case instead). Returns
// 1 to stop the loop (match found, or scan/ancestor-cap exhausted), 0 to
// continue. Signature is bpf_loop()'s required
// `long (*callback_fn)(u32 index, void *ctx)`.
static long file_allow_walk_cb(__u32 idx, void *ctx_)
{
	struct file_allow_walk_ctx *ctx = ctx_;

	// Clamp idx itself before any arithmetic on it: file_path_is_allowed
	// calls bpf_loop(full_len - 1, ...), so idx is only ever < full_len - 1
	// (< ARDUR_PATH_LEN - 1) at runtime, but the verifier does not carry
	// that caller-side bound into the callback body — without this check,
	// load fails with "invalid argument: value -2147483648 makes map_value
	// pointer be out of bounds" (idx treated as an unbounded __u32, so
	// (int)idx + 1 can appear to overflow to INT_MIN from the verifier's
	// point of view). Bounded to ARDUR_PATH_LEN - 1, not ARDUR_PATH_LEN: i
	// (= idx + 1) must stay a valid index into ctx->local's ARDUR_PATH_LEN
	// bytes, i.e. i <= ARDUR_PATH_LEN - 1, i.e. idx <= ARDUR_PATH_LEN - 2.
	if (idx >= ARDUR_PATH_LEN - 1)
		return 1;
	int i = (int)idx + 1;

	if (i >= ctx->full_len)
		return 1;
	if (ctx->checked >= ARDUR_FILE_ALLOW_MAX_ANCESTORS)
		return 1;

	// A direct ctx->local[i] dereference here is rejected at load ("R6
	// unbounded memory access, make sure to bounds check any such access"):
	// ctx->local is a `char *` loaded from a struct field inside a
	// bpf_loop() callback, and the verifier does not carry forward the
	// "this points into a fixed ARDUR_PATH_LEN-byte scratch buffer"
	// provenance through that indirection the way it would for a pointer
	// declared directly in this function — even with `i` itself fully
	// bounded (see above). bpf_probe_read_kernel doesn't have this
	// problem: unlike a raw load, its whole purpose is reading through a
	// pointer whose bounds the verifier can't fully prove up front, with
	// the length argument (1 byte, here) checked instead. Confirmed on a
	// real BPF-LSM kernel: this is what actually loads.
	char b = 0;
	bpf_probe_read_kernel(&b, 1, ctx->local + i);
	if (b != '/')
		return 0;
	ctx->checked++;

	// Re-clamp i (both bounds) right at this use site rather than trusting
	// the range narrowed above to still be visible to the verifier here:
	// bpf_probe_read_kernel below is called via file_allow_lookup with i as
	// its length argument, and confirmed on a real kernel that without this,
	// load fails with "R2 min value is negative, either use unsigned or
	// 'var &= const'" — the verifier's full log showed exactly what that
	// hint means here: R2's 32-bit sub-register was correctly bounded
	// (smax32=255) but its 64-bit smin showed as 0xffffffff80000000 (i.e.
	// sign-extended, not zero-extended). An `& (ARDUR_PATH_LEN - 1)` mask
	// (a no-op numerically: blen is already < ARDUR_PATH_LEN, and
	// ARDUR_PATH_LEN is a power of 2, so this can't wrap a valid value to
	// something smaller the way masking warns against elsewhere in this
	// file — see path_is_allowed's clamp-not-mask comment, which is about a
	// non-power-of-2 bound) is the right fix in principle, forcing a
	// zero-extending AND. In practice the first attempt at exactly that
	// mask made no difference at all: -O2 proved the mask redundant (blen
	// was already known <= 255) and deleted it, regenerating the identical
	// instructions the verifier had already rejected. barrier_var forces an
	// opaque round-trip through an empty asm statement between establishing
	// the bound and using it, so the compiler can no longer treat the mask
	// as provably redundant and elide it. Confirmed on a real kernel: this
	// combination — clamp, barrier, THEN mask — is what actually loads.
	__u32 blen = (i > 0 && i < ARDUR_PATH_LEN) ? (__u32)i : 0;
	barrier_var(blen);
	blen &= (ARDUR_PATH_LEN - 1);
	if (blen == 0)
		return 1;
	if (file_allow_lookup(ctx->scratch, ctx->cgroup_id, ctx->local, blen)) {
		ctx->found = 1;
		return 1;
	}
	return 0;
}

// file_path_is_allowed reports whether path_src (a resolved, absolute path
// of path_len bytes, as produced by bpf_d_path in guard_file_open) falls
// under any directory registered in cgroup_file_allow, or is itself exactly
// registered. Safe to call from a sleepable program: cgroup_file_allow and
// file_allow_scratch are both sleepable-compatible map types (HASH,
// TASK_STORAGE) —
// see ardur_file_allow_key's doc comment for why this replaces LPM-trie
// prefix matching instead of reusing path_is_allowed/cgroup_path_allow.
//
// Checks, in order:
//   1. The literal root path "/" (an allow-everything policy).
//   2. The full resolved path (an exact-file allow entry).
//   3. Each ancestor directory boundary from the root outward — i.e. for
//      "/a/b/c/file.txt", "/a", "/a/b", "/a/b/c" — up to
//      ARDUR_FILE_ALLOW_MAX_ANCESTORS matches, via file_allow_walk_cb.
//      Candidates only ever end exactly at a '/' or at the full path, so
//      this can't spuriously match a sibling with a shared string prefix
//      (e.g. an allowed "/data" does NOT match a query for "/database").
// Returns 1 on the first match, 0 if none of the above hit.
//
// Why a bpf_loop() callback instead of a plain `for` loop over `local`: it
// isn't. Four different plain-loop shapes were tried first, and every one
// of them failed to load on a real kernel with "argument list too long: BPF
// program is too large. Processed 1000001 insn" (the verifier's ~1M
// processed-instruction/state complexity budget) — confirmed empirically
// via kernel-smoke-equivalent local testing, not a theoretical concern (a
// darwin build or a non-privileged Linux CI run can't catch any of this):
//  1. Scan-and-lookup in one loop, indexing path_src[i] directly (path_src
//     being a `const char *` parameter of this BPF-to-BPF subprogram): too
//     large regardless of ARDUR_FILE_ALLOW_MAX_ANCESTORS (32, then 8) or
//     the scan bound (256, then 32).
//  2. Splitting the scan (cheap: byte compares) from the lookups
//     (expensive: a helper call each) into two loops, passing found offsets
//     through a stack array: worse, not better — the verifier lost the
//     provable range on the loop induction variable once it round-tripped
//     through the array.
//  3. Copying path_src into a local buffer first (this function still does
//     this part — see below) so the scan indexes memory this function
//     fully owns instead of a pointer parameter: still too large. Bisecting
//     down to `for (i=1;i<256;i++) { if (i<full_len && checked<MAX &&
//     local[i]=='/') checked++; }` — no break, no continue, a single
//     non-data-dependent loop-exit condition, ONE conditional increment,
//     NO helper call at all in the body — still too large. This ruled out
//     "the lookup call" and "early-exit branch shape" as the cause: the
//     verifier's state-space exploration of ANY loop that repeatedly reads
//     memory through a map-lookup-derived pointer, with a per-iteration
//     branch on the loaded value, exceeded budget on this kernel,
//     regardless of how simple the branch was.
// bpf_loop() (Linux 5.17+, comfortably below what BPF-LSM sleepable
// programs already require) exists precisely for this: the verifier checks
// file_allow_walk_cb's body ONCE, with a complexity independent of
// nr_loops's runtime value, then trusts the kernel's own bounded-loop
// implementation to actually iterate. Confirmed on a real BPF-LSM kernel:
// this loads and enforces correctly where every plain-loop version did not
// even load.
static int file_path_is_allowed(__u64 cgroup_id, const char *path_src, int path_len)
{
	if (path_len <= 0)
		return 0;

	struct ardur_file_allow_scratch *scratch = current_file_allow_scratch();
	if (!scratch)
		return 0;
	if (file_allow_lookup(scratch, cgroup_id, "/", 1))
		return 1;

	// barrier_var + mask: same fix, same reason, as file_allow_walk_cb's
	// `blen` a few functions below — a signed-int-to-__u32 ternary like this
	// one leaves the verifier unable to prove the register's upper 32 bits
	// are zero at the bpf_probe_read_kernel call sites below, even though
	// the value is provably small. See that comment for the full story.
	//
	// Clamped to ARDUR_PATH_LEN - 1, not ARDUR_PATH_LEN: the mask below is
	// only a numeric no-op if full_len is strictly LESS than ARDUR_PATH_LEN
	// (a power of 2) going in — masking an already-exact ARDUR_PATH_LEN
	// (256) by (ARDUR_PATH_LEN - 1) (255) would silently produce 0, turning
	// a full-length read into a zero-length one for any path at or beyond
	// the buffer size. One byte of extra truncation on the longest possible
	// paths is negligible and consistent with this file's existing
	// truncate-oversize-paths behavior elsewhere (e.g. pathLpmKey/
	// bpfPathLpmDataLen on the Go side).
	__u32 full_len = path_len < ARDUR_PATH_LEN ? (__u32)path_len : (__u32)(ARDUR_PATH_LEN - 1);
	barrier_var(full_len);
	full_len &= (ARDUR_PATH_LEN - 1);
	if (file_allow_lookup(scratch, cgroup_id, path_src, full_len))
		return 1;

	// guard_file_open resolved the path directly into this task's storage, so
	// the callback can reuse it without a second copy or shared scratch.
	char *local = scratch->path_copy;

	struct file_allow_walk_ctx wctx = {
		.scratch = scratch,
		.cgroup_id = cgroup_id,
		.local = local,
		.full_len = (int)full_len,
	};
	// full_len - 1 iterations: ancestor position i ranges 1..full_len-1
	// (file_allow_walk_cb maps idx -> i = idx+1). full_len is always >= 1
	// here (path_len > 0 was checked above, and full_len is path_len
	// clamped to a smaller-or-equal positive bound), so this never
	// underflows.
	bpf_loop(full_len - 1, file_allow_walk_cb, &wctx, 0);
	return wctx.found;
}

static __always_inline int path_boundary_matches(
	const char *path_src, int path_len, __u32 offset, int allow_subtree)
{
	if (path_len <= (int)offset)
		return 0;
	char boundary = 1;
	if (bpf_probe_read_kernel(&boundary, 1, path_src + offset) < 0)
		return 0;
	return boundary == '\0' || (allow_subtree && boundary == '/');
}

// bootstrap_runtime_path_allowed checks only daemon-defined runtime roots.
// The caller has already proved the current TGID is the session root and the
// trusted-root generation equals cgroup_managed.generation. No client path is
// compared here and writes never call this helper.
static __always_inline int bootstrap_runtime_path_allowed(
	const char *path_src, int path_len, __u32 allow_mask)
{
	if ((allow_mask & ARDUR_BOOTSTRAP_USR) && path_len >= 4 &&
		bpf_strncmp(path_src, 4, "/usr") == 0 &&
		path_boundary_matches(path_src, path_len, 4, 1))
		return 1;
	if ((allow_mask & ARDUR_BOOTSTRAP_LIB) && path_len >= 4 &&
		bpf_strncmp(path_src, 4, "/lib") == 0 &&
		path_boundary_matches(path_src, path_len, 4, 1))
		return 1;
	if ((allow_mask & ARDUR_BOOTSTRAP_LIB64) && path_len >= 6 &&
		bpf_strncmp(path_src, 6, "/lib64") == 0 &&
		path_boundary_matches(path_src, path_len, 6, 1))
		return 1;
	if ((allow_mask & ARDUR_BOOTSTRAP_LD_CACHE) && path_len >= 16 &&
		bpf_strncmp(path_src, 16, "/etc/ld.so.cache") == 0 &&
		path_boundary_matches(path_src, path_len, 16, 0))
		return 1;
	if ((allow_mask & ARDUR_BOOTSTRAP_CA_CERTS) && path_len >= 14 &&
		bpf_strncmp(path_src, 14, "/etc/ssl/certs") == 0 &&
		path_boundary_matches(path_src, path_len, 14, 1))
		return 1;
	if ((allow_mask & ARDUR_BOOTSTRAP_URANDOM) && path_len >= 12 &&
		bpf_strncmp(path_src, 12, "/dev/urandom") == 0 &&
		path_boundary_matches(path_src, path_len, 12, 0))
		return 1;
	if ((allow_mask & ARDUR_BOOTSTRAP_PROC) && path_len >= 5 &&
		bpf_strncmp(path_src, 5, "/proc") == 0 &&
		path_boundary_matches(path_src, path_len, 5, 1))
		return 1;
	return 0;
}

// bootstrap_initial_file_allowed requires the kernel-native superblock device
// and inode registered by observe_bootstrap_file for this cgroup/generation.
static __always_inline int bootstrap_initial_file_allowed(
	struct file *file, __u64 cgroup_id, __u32 generation)
{
	__u64 device = file_device(file);
	__u64 inode = BPF_CORE_READ(file, f_inode, i_ino);
	if (device == 0 || inode == 0)
		return 0;
	struct ardur_bootstrap_file_key key = {
		.device = device,
		.inode = inode,
	};
	__builtin_memcpy(key.cgroup_raw, &cgroup_id, 8);
	struct ardur_bootstrap_file_value *allowed =
		bpf_map_lookup_elem(&cgroup_bootstrap_file_allow, &key);
	return allowed && allowed->generation == generation;
}

// emit_event writes one decision record to the enforce_events ringbuf.
// path_src may be NULL for network ops.
static __always_inline void emit_event(
	__u64 cgroup_id, __u32 op, __u32 action, __u32 enforce_mode,
	const char *path_src)
{
	struct ardur_enforce_event *ev =
		bpf_ringbuf_reserve(&enforce_events, sizeof(*ev), 0);
	if (!ev) {
		// Ringbuf full — record the drop so it is counted, not silent (#122).
		__u32 zero = 0;
		__u64 *dropped = bpf_map_lookup_elem(&enforce_events_dropped, &zero);
		if (dropped)
			__sync_fetch_and_add(dropped, 1);
		return;
	}
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
// sleepable hook). Identical except its ACT_ALLOWLIST branch calls
// file_path_is_allowed (cgroup_file_allow, a HASH map) instead of
// path_is_allowed (cgroup_path_allow, an LPM_TRIE) — see decide()'s doc
// comment for why sleepable programs can't reach LPM_TRIE maps at all, and
// ardur_file_allow_key's doc comment for how the HASH-map ancestor walk
// restores allowlist enforcement here without needing one. OP_NET_CONNECT
// never reaches this function (guard_file_open only fires OP_FILE_READ /
// OP_FILE_WRITE), so unlike decide() there is no net_is_allowed branch to
// worry about.
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
		int ok = 0;
		if (path_src && ctx->path_len > 0)
			ok = file_path_is_allowed(cgroup_id, path_src, ctx->path_len);

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
	observe_bootstrap_file(file);

	struct ardur_file_allow_scratch *scratch = current_file_allow_scratch();
	char *path_buf = 0;
	if (scratch) {
		path_buf = scratch->path_copy;
		__builtin_memset(path_buf, 0, ARDUR_PATH_LEN);
	}
	long pret = path_buf ? bpf_d_path(&file->f_path, path_buf, ARDUR_PATH_LEN) : 0;
	int path_len = pret > 0 ? (int)pret : 0;
	if (op == ARDUR_OP_FILE_READ) {
		struct ardur_managed_value *mv = lookup_managed(cgroup_id);
		if (mv) {
			struct ardur_trusted_root_value *trusted =
				lookup_trusted_root(cgroup_id, mv->generation);
			if (trusted) {
				if (bootstrap_initial_file_allowed(file, cgroup_id, mv->generation))
					return 0;
				if (path_len > 0 && bootstrap_runtime_path_allowed(
						path_buf, path_len, trusted->allow_mask))
					return 0;
			}
		}
	}

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

	struct ardur_managed_value *mv = lookup_managed(cgroup_id);
	if (mv && control_plane_is_allowed(cgroup_id, mv->generation, sa_family,
					   (const __u8 *)address + 2, addr_buf, addr_len))
		return 0;

	struct decide_ctx dctx = {
		.cgroup_id = cgroup_id,
		.op = ARDUR_OP_NET_CONNECT,
		.addr_bytes = addr_buf,
		.addr_len = addr_len,
	};
	return decide(&dctx);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
