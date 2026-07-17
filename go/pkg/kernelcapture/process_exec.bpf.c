//go:build ignore

// This source is compiled by bpf2go into embedded eBPF object files.
// It intentionally captures process exec/exit lifecycle metadata for the
// Phase 2 local MVP; it does not collect argv, env, file contents, or network
// destinations.

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define ARDUR_EVENT_EXEC 1
#define ARDUR_EVENT_EXIT 2
#define ARDUR_FILTER_CONTROL_KEY 0
#define ARDUR_FILTER_DISABLED 0
#define ARDUR_FILTER_ENABLED 1
#define ARDUR_ALLOWED_CGROUPS_MAX 4096
#define ARDUR_RECOGNITION_COMMS_MAX 64
#define ARDUR_RECOGNITION_BASENAMES_MAX 64
#define ARDUR_EXECUTABLE_BASENAME_LEN 64
#define ARDUR_EXEC_FILENAME_READ_LEN 256
#define ARDUR_LAUNCHER_EXEC_STATE_MAX 4096
#define ARDUR_LAUNCHER_KIND_NONE 0
#define ARDUR_LAUNCHER_KIND_SCRIPT 1
#define ARDUR_LAUNCHER_KIND_INTERPRETER_BACKED 2

struct ns_common {
    unsigned int inum;
} __attribute__((preserve_access_index));

struct pid_namespace {
    struct ns_common ns;
} __attribute__((preserve_access_index));

struct nsproxy {
    struct pid_namespace *pid_ns_for_children;
} __attribute__((preserve_access_index));

struct task_struct {
    struct task_struct *real_parent;
    struct nsproxy *nsproxy;
    unsigned int tgid;
    int exit_code;
} __attribute__((preserve_access_index));

struct linux_binprm {
    struct file *file;
    const char *filename;
    const char *interp;
} __attribute__((preserve_access_index));

struct ardur_launcher_exec_state {
    __u64 inode;
    __u64 mount_id;
    __u32 device_major;
    __u32 device_minor;
    __u32 link_count;
    __u32 _pad;
};

struct ardur_process_event {
    __u8 event_type;
    __u8 launcher_kind;
    __u8 launcher_identity_present;
    __u8 _pad0[5];
    __u64 monotonic_ns;
    __u32 pid;
    __u32 ppid;
    __u32 tid;
    __u32 pid_namespace_id;
    __u64 cgroup_id;
    __s32 exit_code;
    __u32 launcher_link_count;
    __u64 launcher_inode;
    __u64 launcher_mount_id;
    __u32 launcher_device_major;
    __u32 launcher_device_minor;
    char comm[16];
    char executable_basename[ARDUR_EXECUTABLE_BASENAME_LEN];
    char interpreter_basename[ARDUR_EXECUTABLE_BASENAME_LEN];
};

struct ardur_comm_key {
    char comm[16];
};

struct ardur_executable_basename_key {
    char name[ARDUR_EXECUTABLE_BASENAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} events SEC(".maps");

// lifecycle_events_dropped counts process exec/exit records that could not be
// reserved in the ringbuf. Ringbuf readers do not receive a lost-samples signal,
// so userspace must read this monotonic counter to report producer-side gaps.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} lifecycle_events_dropped SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} filter_control SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, ARDUR_ALLOWED_CGROUPS_MAX);
    __type(key, __u64);
    __type(value, __u8);
} allowed_cgroups SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} recognition_control SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, ARDUR_RECOGNITION_COMMS_MAX);
    __type(key, struct ardur_comm_key);
    __type(value, __u8);
} recognition_comms SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, ARDUR_RECOGNITION_BASENAMES_MAX);
    __type(key, struct ardur_executable_basename_key);
    __type(value, __u8);
} recognition_executable_basenames SEC(".maps");

// The separately loaded launcher_identity BPF-LSM program writes the first
// object seen for one exec attempt into this shared map. The successful-exec
// and exit tracepoints consume/delete it, so failed attempts cannot turn a
// stale PID into authority and completed attempts do not accumulate state.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, ARDUR_LAUNCHER_EXEC_STATE_MAX);
    __type(key, __u64);
    __type(value, struct ardur_launcher_exec_state);
} launcher_exec_state SEC(".maps");

static __always_inline int cgroup_allowed(__u64 cgroup_id) {
    __u32 control_key = ARDUR_FILTER_CONTROL_KEY;
    __u8 *filter_enabled;
    __u8 *allowed;

    filter_enabled = bpf_map_lookup_elem(&filter_control, &control_key);
    if (!filter_enabled || *filter_enabled == ARDUR_FILTER_DISABLED) {
        return 1;
    }
    if (*filter_enabled != ARDUR_FILTER_ENABLED) {
        return 0;
    }

    allowed = bpf_map_lookup_elem(&allowed_cgroups, &cgroup_id);
    return allowed != 0;
}

static __always_inline int recognition_enabled(void) {
    __u32 control_key = ARDUR_FILTER_CONTROL_KEY;
    __u8 *recognition_enabled;

    recognition_enabled = bpf_map_lookup_elem(&recognition_control, &control_key);
    return recognition_enabled && *recognition_enabled == ARDUR_FILTER_ENABLED;
}

static __always_inline int comm_recognition_allowed(struct ardur_comm_key *comm) {
    return bpf_map_lookup_elem(&recognition_comms, comm) != 0;
}

static __always_inline int basename_recognition_allowed(struct ardur_executable_basename_key *basename) {
    return basename && bpf_map_lookup_elem(&recognition_executable_basenames, basename) != 0;
}

static __always_inline int read_bounded_basename(
    const char *filename,
    struct ardur_executable_basename_key *basename,
    char path[ARDUR_EXEC_FILENAME_READ_LEN]) {
    long path_len;
    int basename_start = 0;
    int scan_start = 0;

    if (!filename || !basename || !path) {
        return 0;
    }
    __builtin_memset(path, 0, ARDUR_EXEC_FILENAME_READ_LEN);
    path_len = bpf_probe_read_kernel_str(
        path, ARDUR_EXEC_FILENAME_READ_LEN, filename);
    if (path_len <= 1 || path_len >= ARDUR_EXEC_FILENAME_READ_LEN) {
        return 0;
    }
    if (path_len > ARDUR_EXECUTABLE_BASENAME_LEN) {
        scan_start = path_len - ARDUR_EXECUTABLE_BASENAME_LEN;
    }
#pragma unroll
    for (int i = 0; i < ARDUR_EXECUTABLE_BASENAME_LEN; i++) {
        int path_index = scan_start + i;
        if (path_index >= path_len - 1) {
            break;
        }
        if (path[path_index] == '/') {
            basename_start = path_index + 1;
        }
    }
    if (basename_start >= path_len - 1) {
        return 0;
    }
    long basename_len = bpf_probe_read_kernel_str(
        basename->name,
        sizeof(basename->name),
        filename + basename_start);
    return basename_len > 1 && basename_len < sizeof(basename->name);
}

static __always_inline int read_executable_basename(
    struct linux_binprm *bprm,
    struct ardur_executable_basename_key *basename,
    char path[ARDUR_EXEC_FILENAME_READ_LEN]) {
    if (!bprm) {
        return 0;
    }
    return read_bounded_basename(BPF_CORE_READ(bprm, filename), basename, path);
}

static __always_inline int submit_process_event(
    __u8 event_type,
    struct ardur_executable_basename_key *executable_basename,
    struct ardur_executable_basename_key *interpreter_basename,
    struct ardur_launcher_exec_state *launcher_state,
    __u8 launcher_kind) {
    struct ardur_process_event *event;
    struct ardur_comm_key comm = {};
    __u32 zero = 0;
    __u64 *dropped;
    __u64 pid_tgid;
    __u64 cgroup_id;
    struct task_struct *task;
    struct task_struct *parent;
    struct nsproxy *nsproxy;
    struct pid_namespace *pidns;

    cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&comm.comm, sizeof(comm.comm));
    if (!cgroup_allowed(cgroup_id) &&
        (event_type != ARDUR_EVENT_EXEC || !recognition_enabled() ||
         (!comm_recognition_allowed(&comm) &&
          !basename_recognition_allowed(executable_basename)))) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        dropped = bpf_map_lookup_elem(&lifecycle_events_dropped, &zero);
        if (dropped) {
            __sync_fetch_and_add(dropped, 1);
        }
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));

    pid_tgid = bpf_get_current_pid_tgid();
    event->event_type = event_type;
    event->launcher_kind = launcher_kind;
    event->monotonic_ns = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->cgroup_id = cgroup_id;
    __builtin_memcpy(event->comm, comm.comm, sizeof(event->comm));
    if (executable_basename) {
        __builtin_memcpy(event->executable_basename,
                         executable_basename->name,
                         sizeof(event->executable_basename));
    }

    task = (struct task_struct *)bpf_get_current_task_btf();
    if (task) {
        parent = BPF_CORE_READ(task, real_parent);
        if (parent) {
            event->ppid = BPF_CORE_READ(parent, tgid);
        }
        nsproxy = BPF_CORE_READ(task, nsproxy);
        if (nsproxy) {
            pidns = BPF_CORE_READ(nsproxy, pid_ns_for_children);
            if (pidns) {
                event->pid_namespace_id = BPF_CORE_READ(pidns, ns.inum);
            }
        }
        if (event_type == ARDUR_EVENT_EXIT) {
            event->exit_code = BPF_CORE_READ(task, exit_code);
        }
    }

    if (launcher_kind == ARDUR_LAUNCHER_KIND_SCRIPT && launcher_state) {
        event->launcher_identity_present = 1;
        event->launcher_inode = launcher_state->inode;
        event->launcher_mount_id = launcher_state->mount_id;
        event->launcher_device_major = launcher_state->device_major;
        event->launcher_device_minor = launcher_state->device_minor;
        event->launcher_link_count = launcher_state->link_count;
    }
    if (interpreter_basename) {
        __builtin_memcpy(event->interpreter_basename,
                         interpreter_basename->name,
                         sizeof(event->interpreter_basename));
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("raw_tracepoint/sched_process_exec")
int handle_sched_process_exec(struct bpf_raw_tracepoint_args *ctx) {
    struct ardur_executable_basename_key basename = {};
    struct ardur_executable_basename_key interpreter_basename = {};
    struct ardur_executable_basename_key *basename_ptr = 0;
    struct ardur_executable_basename_key *interpreter_basename_ptr = 0;
    struct ardur_launcher_exec_state *launcher_state = 0;
    char path[ARDUR_EXEC_FILENAME_READ_LEN] = {};
    __u64 task_key = (__u64)bpf_get_current_task_btf();
    __u8 launcher_kind = ARDUR_LAUNCHER_KIND_NONE;
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];

    if (bprm) {
        const char *filename = BPF_CORE_READ(bprm, filename);
        const char *interp = BPF_CORE_READ(bprm, interp);
        if (filename && interp && filename != interp) {
            // filename != interp includes binfmt_misc and other interpreter
            // handlers. Only state written after an explicit #! observation
            // may strengthen a candidate as a script; every other interpreted
            // shape stays marked so userspace cannot hash the interpreter as
            // a native fallback.
            launcher_kind = ARDUR_LAUNCHER_KIND_INTERPRETER_BACKED;
            launcher_state = bpf_map_lookup_elem(&launcher_exec_state, &task_key);
            if (launcher_state) {
                launcher_kind = ARDUR_LAUNCHER_KIND_SCRIPT;
            }
            if (read_bounded_basename(interp, &interpreter_basename, path)) {
                interpreter_basename_ptr = &interpreter_basename;
            }
        }
    }

    if (recognition_enabled()) {
        if (read_executable_basename(bprm, &basename, path)) {
            basename_ptr = &basename;
        }
    }
    int result = submit_process_event(
        ARDUR_EVENT_EXEC,
        basename_ptr,
        interpreter_basename_ptr,
        launcher_state,
        launcher_kind);
    bpf_map_delete_elem(&launcher_exec_state, &task_key);
    return result;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(void *ctx) {
    __u64 task_key = (__u64)bpf_get_current_task_btf();
    bpf_map_delete_elem(&launcher_exec_state, &task_key);
    return submit_process_event(ARDUR_EVENT_EXIT, 0, 0, 0, ARDUR_LAUNCHER_KIND_NONE);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
