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
func runRestartSurvivalScenario() error {
	const cgroupDir = "/sys/fs/cgroup/ardur-guard-smoke-restart"

	// A dedicated, disposable pin directory (not DefaultPinnedGuardPaths'
	// real /sys/fs/bpf/ardur/) so this smoke run never collides with an
	// actual daemon's pins on the same host and cleans up after itself.
	pinDir, err := resolvedTempDir("ardur-guard-smoke-pins-*")
	if err != nil {
		return fmt.Errorf("create pin directory: %w", err)
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
