//go:build linux

package kernelcapture

// bpf_policy_apply_pinned_linux_test.go — tests for the issue #124 pinning
// paths that don't require a real BPF-LSM-enabled kernel: PinnedGuardPaths'
// pure path logic, and tryLoadPinnedGuardState's "no pins exist yet" fallback
// path, which fails at the bpf_obj_get(2)/ENOENT level before ever touching
// BPF-LSM verification -- this runs in the bpf-generate CI job (plain
// ubuntu-24.04, real generated bindings, no privileged VM needed), unlike
// go/cmd/ardur-guard-smoke's end-to-end restart-survival scenario, which
// needs the kernel-smoke job's virtme-ng VM to prove actual enforcement
// (see that scenario's doc comment for what only a real kernel can prove).

import (
	"testing"
)

func TestDefaultPinnedGuardPaths_AllTenPathsDistinctAndNonEmpty(t *testing.T) {
	paths := DefaultPinnedGuardPaths()
	all := paths.allPaths()
	if len(all) != 10 {
		t.Fatalf("allPaths() returned %d paths, want 10", len(all))
	}
	seen := make(map[string]bool, len(all))
	for _, p := range all {
		if p == "" {
			t.Error("a pin path is empty")
		}
		if seen[p] {
			t.Errorf("duplicate pin path %q -- two fields would collide on bpffs", p)
		}
		seen[p] = true
	}
}

func TestDefaultPinnedGuardPaths_UnderArdurBpffsNamespace(t *testing.T) {
	paths := DefaultPinnedGuardPaths()
	const prefix = "/sys/fs/bpf/ardur/"
	for _, p := range paths.allPaths() {
		if len(p) <= len(prefix) || p[:len(prefix)] != prefix {
			t.Errorf("pin path %q is not under the ardur-owned bpffs namespace %q", p, prefix)
		}
	}
}

// TestTryLoadPinnedGuardState_FalseWhenNoPinsExist proves the "first start,
// nothing pinned yet" fallback path: every LoadPinnedLink/LoadPinnedMap call
// fails against paths that don't exist, so the function must report ok=false
// (triggering LoadAndAttachProcessGuardEBPFPinned's fresh-load fallback)
// rather than panicking or returning a partially-populated handle.
func TestTryLoadPinnedGuardState_FalseWhenNoPinsExist(t *testing.T) {
	base := t.TempDir() + "/does-not-exist/"
	paths := PinnedGuardPaths{
		BprmLinkPath:        base + "bprm_link",
		FileOpenLinkPath:    base + "file_open_link",
		SocketConnLinkPath:  base + "socket_connect_link",
		CgroupOpPolicyPath:  base + "cgroup_op_policy",
		CgroupPathAllowPath: base + "cgroup_path_allow",
		CgroupFileAllowPath: base + "cgroup_file_allow",
		CgroupNetAllowPath:  base + "cgroup_net_allow",
		CgroupManagedPath:   base + "cgroup_managed",
		KillSwitchPath:      base + "kill_switch",
		EnforceEventsPath:   base + "enforce_events",
	}

	h, ok := tryLoadPinnedGuardState(paths)
	if ok {
		t.Fatal("tryLoadPinnedGuardState reported ok=true against nonexistent pin paths")
	}
	if h != nil {
		t.Fatal("tryLoadPinnedGuardState returned a non-nil handle alongside ok=false")
	}
}

// TestRemovePinnedGuardState_NeverErrorsOnMissingPins confirms the cleanup
// helper is safe to call unconditionally (e.g. from a test's defer) even when
// nothing was ever pinned.
func TestRemovePinnedGuardState_NeverErrorsOnMissingPins(t *testing.T) {
	base := t.TempDir() + "/never-pinned/"
	paths := PinnedGuardPaths{
		BprmLinkPath:        base + "bprm_link",
		FileOpenLinkPath:    base + "file_open_link",
		SocketConnLinkPath:  base + "socket_connect_link",
		CgroupOpPolicyPath:  base + "cgroup_op_policy",
		CgroupPathAllowPath: base + "cgroup_path_allow",
		CgroupFileAllowPath: base + "cgroup_file_allow",
		CgroupNetAllowPath:  base + "cgroup_net_allow",
		CgroupManagedPath:   base + "cgroup_managed",
		KillSwitchPath:      base + "kill_switch",
		EnforceEventsPath:   base + "enforce_events",
	}
	// Must not panic.
	RemovePinnedGuardState(paths)
}
