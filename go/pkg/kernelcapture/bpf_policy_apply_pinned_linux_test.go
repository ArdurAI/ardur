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
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestMapSchemaMatchesRejectsPinnedABIDrift(t *testing.T) {
	info := &ebpf.MapInfo{Type: ebpf.Hash, KeySize: 24, ValueSize: 4, MaxEntries: 16384, Flags: 0}
	spec := &ebpf.MapSpec{Type: ebpf.Hash, KeySize: 24, ValueSize: 4, MaxEntries: 16384, Flags: 0}
	if !mapSchemaMatches(info, spec) {
		t.Fatal("identical pinned and embedded map schemas did not match")
	}
	drifted := *info
	drifted.KeySize = 264
	if mapSchemaMatches(&drifted, spec) {
		t.Fatal("old path-key bootstrap map schema was accepted")
	}
}

func TestDefaultPinnedGuardPaths_AllFifteenPathsDistinctAndNonEmpty(t *testing.T) {
	paths := DefaultPinnedGuardPaths()
	all := paths.allPaths()
	// 3 LSM links + 10 policy maps + enforce_events ringbuf + drop counter = 15.
	if len(all) != 15 {
		t.Fatalf("allPaths() returned %d paths, want 15", len(all))
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

func TestCompleteUnreadablePinnedGuardStateIsPreserved(t *testing.T) {
	base := t.TempDir() + "/"
	paths := PinnedGuardPaths{
		BprmLinkPath: base + "bprm", FileOpenLinkPath: base + "file", SocketConnLinkPath: base + "socket",
		CgroupOpPolicyPath: base + "op", CgroupPathAllowPath: base + "path", CgroupFileAllowPath: base + "file_allow",
		CgroupBootstrapFileAllowPath: base + "bootstrap", CgroupControlPlaneAllowPath: base + "control", CgroupTrustedRootPath: base + "root",
		BootstrapFileObservationPath: base + "bootstrap_observation",
		CgroupNetAllowPath:           base + "net", CgroupManagedPath: base + "managed", KillSwitchPath: base + "kill",
		EnforceEventsPath: base + "events", EnforceEventsDroppedPath: base + "drops",
	}
	for _, path := range paths.allPaths() {
		if err := os.WriteFile(path, []byte("not a bpffs object"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadAndAttachProcessGuardEBPFPinned(paths); err == nil || !strings.Contains(err.Error(), "preserving pins") {
		t.Fatalf("complete invalid pin set error = %v, want preservation failure", err)
	}
	for _, path := range paths.allPaths() {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("pin %q was removed after complete-set load failure: %v", path, err)
		}
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

func TestLoadPinnedGuardStateRejectsEmptyAndDuplicatePaths(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*PinnedGuardPaths)
		wantErr string
	}{
		{
			name: "empty",
			mutate: func(paths *PinnedGuardPaths) {
				paths.CgroupTrustedRootPath = ""
			},
			wantErr: "CgroupTrustedRootPath is empty",
		},
		{
			name: "duplicate",
			mutate: func(paths *PinnedGuardPaths) {
				paths.CgroupTrustedRootPath = paths.CgroupControlPlaneAllowPath
			},
			wantErr: "CgroupControlPlaneAllowPath and CgroupTrustedRootPath",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := DefaultPinnedGuardPaths()
			tt.mutate(&paths)
			if _, err := LoadAndAttachProcessGuardEBPFPinned(paths); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("LoadAndAttachProcessGuardEBPFPinned() error = %v, want substring %q", err, tt.wantErr)
			}
		})
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
		BprmLinkPath:                 base + "bprm_link",
		FileOpenLinkPath:             base + "file_open_link",
		SocketConnLinkPath:           base + "socket_connect_link",
		CgroupOpPolicyPath:           base + "cgroup_op_policy",
		CgroupPathAllowPath:          base + "cgroup_path_allow",
		CgroupFileAllowPath:          base + "cgroup_file_allow",
		CgroupBootstrapFileAllowPath: base + "cgroup_bootstrap_file_allow",
		BootstrapFileObservationPath: base + "bootstrap_file_observation",
		CgroupControlPlaneAllowPath:  base + "cgroup_control_plane_allow",
		CgroupTrustedRootPath:        base + "cgroup_trusted_root",
		CgroupNetAllowPath:           base + "cgroup_net_allow",
		CgroupManagedPath:            base + "cgroup_managed",
		KillSwitchPath:               base + "kill_switch",
		EnforceEventsPath:            base + "enforce_events",

		EnforceEventsDroppedPath: base + "enforce_events_dropped",
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
		BprmLinkPath:                 base + "bprm_link",
		FileOpenLinkPath:             base + "file_open_link",
		SocketConnLinkPath:           base + "socket_connect_link",
		CgroupOpPolicyPath:           base + "cgroup_op_policy",
		CgroupPathAllowPath:          base + "cgroup_path_allow",
		CgroupFileAllowPath:          base + "cgroup_file_allow",
		CgroupBootstrapFileAllowPath: base + "cgroup_bootstrap_file_allow",
		BootstrapFileObservationPath: base + "bootstrap_file_observation",
		CgroupControlPlaneAllowPath:  base + "cgroup_control_plane_allow",
		CgroupTrustedRootPath:        base + "cgroup_trusted_root",
		CgroupNetAllowPath:           base + "cgroup_net_allow",
		CgroupManagedPath:            base + "cgroup_managed",
		KillSwitchPath:               base + "kill_switch",
		EnforceEventsPath:            base + "enforce_events",

		EnforceEventsDroppedPath: base + "enforce_events_dropped",
	}
	// Must not panic.
	RemovePinnedGuardState(paths)
}
