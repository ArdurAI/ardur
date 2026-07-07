//go:build linux

package main

// restart_survival_scenario.go — proves issue #124's fix: pinning the
// process_guard BPF-LSM links and policy-state maps means a daemon restart
// re-attaches to already-enforcing kernel state instead of dropping the
// applied policy. A daemon restart is simulated here the same way it happens
// for real: ProcessGuardHandles.Close() releases this process's FDs but,
// by design, never removes the bpffs pins — the three LSM programs and
// every policy map stay exactly as they were in the kernel throughout.

import (
	"fmt"
	"os"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
	"golang.org/x/sys/unix"
)

// runRestartSurvivalScenario applies an OP_EXEC:DENY policy against a fresh
// cgroup through a pinned guard load, confirms EPERM, simulates a daemon
// restart (Close, then load again from the same pins), and asserts execve is
// STILL denied WITHOUT ever calling ApplyPolicyMaps a second time.
//
// This is a meaningful (not vacuous) assertion: if the second load silently
// fell back to a fresh unpinned attach instead of reusing the pinned state,
// the freshly created cgroup_managed map would have no entry at all for this
// cgroup, which process_guard treats as "not managed" — default-allow. A
// regression here shows up as execve unexpectedly *succeeding* post-restart,
// not as an ambiguous error, so this scenario can't pass by accident.
// ensureBpffsMounted makes /sys/fs/bpf a mounted bpf filesystem if it is not
// already one. Idempotent: an already-mounted bpffs is success (detected via
// statfs, with EBUSY from the mount call as a fallback). Needed because BPF
// link/map pins can only be created on a bpf filesystem.
func ensureBpffsMounted() error {
	const bpffs = "/sys/fs/bpf"
	if err := os.MkdirAll(bpffs, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", bpffs, err)
	}
	var st unix.Statfs_t
	if err := unix.Statfs(bpffs, &st); err == nil && uint64(st.Type) == uint64(unix.BPF_FS_MAGIC) {
		return nil // already a bpffs
	}
	if err := unix.Mount("bpf", bpffs, "bpf", 0, ""); err != nil && err != unix.EBUSY {
		return fmt.Errorf("mount bpf at %s: %w", bpffs, err)
	}
	return nil
}

func runRestartSurvivalScenario() error {
	const cgroupDir = "/sys/fs/cgroup/ardur-guard-smoke-restart"

	// BPF pins require a mounted bpf filesystem. A minimal guest (the
	// virtme-ng kernel-smoke VM) may not auto-mount /sys/fs/bpf, so ensure it
	// before pinning — otherwise every pin silently fails and the restart
	// survival this scenario proves is defeated.
	if err := ensureBpffsMounted(); err != nil {
		return fmt.Errorf("ensure bpffs mounted: %w", err)
	}

	// A dedicated, disposable pin directory (not DefaultPinnedGuardPaths'
	// real /sys/fs/bpf/ardur/) so this smoke run never collides with an
	// actual daemon's pins on the same host and cleans up after itself.
	//
	// It MUST live on a bpffs mount, not the tmpfs (/dev/shm) the other
	// scenarios use for their regular file paths: BPF link/map pins can only
	// be created on a bpf filesystem, and pinning to tmpfs fails with "is not
	// on a bpf filesystem" — silently (each pin is non-fatal), which then
	// detaches everything on Close and defeats the very restart survival this
	// scenario exists to prove. Use a subdir under /sys/fs/bpf.
	pinDir := fmt.Sprintf("/sys/fs/bpf/ardur-guard-smoke-pins-%d", os.Getpid())
	if err := os.MkdirAll(pinDir, 0o700); err != nil {
		return fmt.Errorf("create bpffs pin directory %s (is /sys/fs/bpf a mounted bpf filesystem?): %w", pinDir, err)
	}
	defer os.RemoveAll(pinDir)
	paths := kernelcapture.PinnedGuardPaths{
		BprmLinkPath:        pinDir + "/bprm_link",
		FileOpenLinkPath:    pinDir + "/file_open_link",
		SocketConnLinkPath:  pinDir + "/socket_connect_link",
		CgroupOpPolicyPath:  pinDir + "/cgroup_op_policy",
		CgroupPathAllowPath: pinDir + "/cgroup_path_allow",
		CgroupFileAllowPath: pinDir + "/cgroup_file_allow",
		CgroupNetAllowPath:  pinDir + "/cgroup_net_allow",
		CgroupManagedPath:   pinDir + "/cgroup_managed",
		KillSwitchPath:      pinDir + "/kill_switch",
		EnforceEventsPath:   pinDir + "/enforce_events",
	}
	defer kernelcapture.RemovePinnedGuardState(paths)

	cgroupID, cgFile, err := setupSmokeCgroup(cgroupDir)
	if err != nil {
		return fmt.Errorf("set up cgroup: %w", err)
	}
	defer cgFile.Close()
	defer os.Remove(cgroupDir)

	firstHandles, err := kernelcapture.LoadAndAttachProcessGuardEBPFPinned(paths)
	if err != nil {
		return fmt.Errorf("first (pre-restart) pinned load: %w", err)
	}

	maps := kernelcapture.PolicyMapsFromHandles(firstHandles)
	policy := kernelcapture.DaemonApplyPolicyRequest{
		SessionID:   "guard-smoke-restart",
		Generation:  smokeGeneration,
		EnforceMode: kernelcapture.BpfEnforceModeEnforce,
		OpPolicies: []kernelcapture.DaemonOpPolicy{
			// Same OP_FILE_READ:ALLOW rationale as runExecDenyScenario: execve
			// opens the target binary for reading before bprm_check_security
			// runs, so this must be present or the process never reaches the
			// exec hook this scenario is actually testing.
			{Op: kernelcapture.BpfOpFileRead, Action: kernelcapture.BpfActionAllow, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
			{Op: kernelcapture.BpfOpExec, Action: kernelcapture.BpfActionDeny, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
		},
	}
	if err := kernelcapture.ApplyPolicyMaps(maps, cgroupID, policy); err != nil {
		firstHandles.Close()
		return fmt.Errorf("apply OP_EXEC:DENY policy before simulated restart: %w", err)
	}
	fmt.Printf("applied OP_EXEC:DENY (ENFORCE) policy for cgroup_id=%d via pinned load\n", cgroupID)

	if err := execveInCgroupExpectEPERM(cgFile); err != nil {
		firstHandles.Close()
		return fmt.Errorf("pre-restart EPERM check: %w", err)
	}
	fmt.Println("pre-restart: execve denied as expected")

	// Simulate the daemon process exiting and restarting.
	firstHandles.Close()

	secondHandles, err := kernelcapture.LoadAndAttachProcessGuardEBPFPinned(paths)
	if err != nil {
		return fmt.Errorf("second (post-restart) pinned load: %w", err)
	}
	defer secondHandles.Close()

	// Deliberately no ApplyPolicyMaps call here: the whole point is that the
	// pre-restart policy is still enforced without re-applying anything.
	if err := execveInCgroupExpectEPERM(cgFile); err != nil {
		return fmt.Errorf("post-restart EPERM check (policy must survive without re-apply, issue #124): %w", err)
	}
	fmt.Println("post-restart: execve still denied with no re-apply -- pinned policy survived (issue #124)")

	return nil
}
