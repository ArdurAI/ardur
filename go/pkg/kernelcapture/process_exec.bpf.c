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
    const char *filename;
} __attribute__((preserve_access_index));

struct ardur_process_event {
    __u8 event_type;
    __u8 _pad0[7];
    __u64 monotonic_ns;
    __u32 pid;
    __u32 ppid;
    __u32 tid;
    __u32 pid_namespace_id;
    __u64 cgroup_id;
    __s32 exit_code;
    char comm[16];
    char executable_basename[ARDUR_EXECUTABLE_BASENAME_LEN];
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

static __always_inline int read_executable_basename(struct linux_binprm *bprm,
                                                     struct ardur_executable_basename_key *basename) {
    const char *filename;
    char path[ARDUR_EXEC_FILENAME_READ_LEN] = {};
    long path_len;
    int basename_start = 0;
    int scan_start = 0;

    if (!bprm || !basename) {
        return 0;
    }
    filename = BPF_CORE_READ(bprm, filename);
    if (!filename) {
        return 0;
    }
    path_len = bpf_probe_read_kernel_str(path, sizeof(path), filename);
    if (path_len <= 1 || path_len >= sizeof(path)) {
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

static __always_inline int submit_process_event(
    __u8 event_type,
    struct ardur_executable_basename_key *executable_basename) {
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

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("raw_tracepoint/sched_process_exec")
int handle_sched_process_exec(struct bpf_raw_tracepoint_args *ctx) {
    struct ardur_executable_basename_key basename = {};
    struct ardur_executable_basename_key *basename_ptr = 0;

    if (recognition_enabled()) {
        struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];
        if (read_executable_basename(bprm, &basename)) {
            basename_ptr = &basename;
        }
    }
    return submit_process_event(ARDUR_EVENT_EXEC, basename_ptr);
}

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(void *ctx) {
    return submit_process_event(ARDUR_EVENT_EXIT, 0);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
