//go:build ignore

// This optional BPF-LSM observer records only the non-path identity of the
// original object at the first bprm security pass. It never denies execution.
// process_exec.bpf.c consumes the shared entry only at successful exec and
// deletes it at exec/exit. Keeping this in a separate object prevents hosts
// without an active BPF LSM from losing ordinary lifecycle capture.

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define ARDUR_LAUNCHER_EXEC_STATE_MAX 4096
#define ARDUR_DEVICE_MINOR_BITS 20
#define ARDUR_DEVICE_MINOR_MASK ((1U << ARDUR_DEVICE_MINOR_BITS) - 1)

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
    unsigned int i_nlink;
    struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct file {
    struct path f_path;
    struct inode *f_inode;
} __attribute__((preserve_access_index));

struct linux_binprm {
    struct file *file;
    const char *filename;
    const char *interp;
    char buf[2];
} __attribute__((preserve_access_index));

struct mount {
    struct vfsmount mnt;
    int mnt_id;
} __attribute__((preserve_access_index));

struct ardur_launcher_exec_state {
    __u64 inode;
    __u64 mount_id;
    __u32 device_major;
    __u32 device_minor;
    __u32 link_count;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, ARDUR_LAUNCHER_EXEC_STATE_MAX);
    __type(key, __u64);
    __type(value, struct ardur_launcher_exec_state);
} launcher_exec_state SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(observe_launcher_identity, struct linux_binprm *bprm, int ret) {
    if (ret != 0 || !bprm) {
        return ret;
    }

    // alloc_bprm initializes interp == filename. Script/binfmt passes change
    // interp before the next security check, so only equality identifies the
    // original object and also overwrites stale state from a failed prior exec.
    const char *filename = BPF_CORE_READ(bprm, filename);
    const char *interp = BPF_CORE_READ(bprm, interp);
    if (!filename || !interp || filename != interp) {
        return ret;
    }

    // The first binary-handler pass is also the stale-state boundary. Clear
    // any failed prior exec before deciding whether this object is an actual
    // shebang script. filename != interp alone at success is broader and also
    // includes binfmt_misc, which must not enter the script trust domain.
    __u64 task_key = (__u64)bpf_get_current_task_btf();
    bpf_map_delete_elem(&launcher_exec_state, &task_key);
    char header[2] = {};
    if (bpf_core_read(header, sizeof(header), &bprm->buf[0]) != 0 ||
        header[0] != '#' || header[1] != '!') {
        return ret;
    }

    struct file *file = BPF_CORE_READ(bprm, file);
    struct inode *inode = file ? BPF_CORE_READ(file, f_inode) : 0;
    struct vfsmount *vfsmount = file ? BPF_CORE_READ(file, f_path.mnt) : 0;
    struct super_block *super = inode ? BPF_CORE_READ(inode, i_sb) : 0;
    if (!file || !inode || !vfsmount || !super) {
        return ret;
    }

    __u64 inode_number = BPF_CORE_READ(inode, i_ino);
    __u32 device = BPF_CORE_READ(super, s_dev);
    struct mount *mount = (struct mount *)((char *)vfsmount -
        bpf_core_field_offset(struct mount, mnt));
    int mount_id = BPF_CORE_READ(mount, mnt_id);

    struct ardur_launcher_exec_state state = {
        .inode = inode_number,
        .mount_id = (__u64)mount_id,
        .device_major = device >> ARDUR_DEVICE_MINOR_BITS,
        .device_minor = device & ARDUR_DEVICE_MINOR_MASK,
        .link_count = BPF_CORE_READ(inode, i_nlink),
    };
    bpf_map_update_elem(&launcher_exec_state, &task_key, &state, BPF_ANY);
    return ret;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
