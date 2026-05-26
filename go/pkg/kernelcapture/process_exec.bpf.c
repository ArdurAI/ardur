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
#define ARDUR_ALLOWED_CGROUPS_MAX 1024

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
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} events SEC(".maps");

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

static __always_inline int submit_process_event(__u8 event_type) {
    struct ardur_process_event *event;
    __u64 pid_tgid;
    __u64 cgroup_id;
    struct task_struct *task;
    struct task_struct *parent;
    struct nsproxy *nsproxy;
    struct pid_namespace *pidns;

    cgroup_id = bpf_get_current_cgroup_id();
    if (!cgroup_allowed(cgroup_id)) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));

    pid_tgid = bpf_get_current_pid_tgid();
    event->event_type = event_type;
    event->monotonic_ns = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->cgroup_id = cgroup_id;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

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

SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(void *ctx) {
    return submit_process_event(ARDUR_EVENT_EXEC);
}

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(void *ctx) {
    return submit_process_event(ARDUR_EVENT_EXIT);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
