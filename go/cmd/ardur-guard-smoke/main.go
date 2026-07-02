//go:build linux

// Command ardur-guard-smoke is a CI-only kernel-in-loop smoke test for the
// process_guard BPF-LSM program (Slice 4.2). It is driven by the
// kernel-smoke job in .github/workflows/kernel-enforce.yml, which boots a
// kernel with "bpf" in the active LSM list via virtme-ng and runs this
// binary as root inside that VM.
//
// It proves, against a real kernel, what the pure-Go unit tests cannot:
//  1. process_guard loads and attaches its three LSM hooks.
//  2. A cgroup with an OP_EXEC:DENY/ENFORCE policy actually blocks execve
//     with -EPERM for a process placed in that cgroup.
//  3. The blocked attempt produces a matching DENY record on the
//     enforce_events ringbuf.
//
// Not part of `go test ./...`: this mutates real kernel state (loads a
// BPF-LSM program, creates a cgroup) and requires CAP_BPF/CAP_SYS_ADMIN,
// CONFIG_BPF_LSM=y, "bpf" active in /sys/kernel/security/lsm, and cgroup v2 —
// preconditions only the disposable kernel-smoke VM guarantees.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

const (
	cgroupDir       = "/sys/fs/cgroup/ardur-guard-smoke"
	smokeGeneration = 1
	ringbufTimeout  = 10 * time.Second
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: process_guard denied execve with EPERM and emitted a matching DENY event")
}

func run() error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root (loads a BPF-LSM program and creates a cgroup)")
	}

	cgroupID, cgFile, err := setupSmokeCgroup()
	if err != nil {
		return fmt.Errorf("set up cgroup: %w", err)
	}
	defer cgFile.Close()
	defer os.Remove(cgroupDir)

	preflight := kernelcapture.InspectBPFLSMPreflight()
	for _, f := range preflight.Findings {
		fmt.Printf("preflight: %s = %s (%s)\n", f.CheckName, f.Verdict, f.Details)
	}
	if !preflight.CanContinue {
		return errors.New("BPF-LSM preflight failed; is the kernel booted with CONFIG_BPF_LSM=y and lsm=...,bpf?")
	}

	handles, err := kernelcapture.LoadAndAttachProcessGuardEBPF()
	if err != nil {
		return fmt.Errorf("load process_guard: %w", err)
	}
	defer handles.Close()
	fmt.Println("process_guard loaded and attached (bprm_check_security, lsm.s/file_open, socket_connect)")

	maps := kernelcapture.PolicyMapsFromHandles(handles)
	policy := kernelcapture.DaemonApplyPolicyRequest{
		SessionID:   "guard-smoke",
		Generation:  smokeGeneration,
		EnforceMode: kernelcapture.BpfEnforceModeEnforce,
		OpPolicies: []kernelcapture.DaemonOpPolicy{
			{Op: kernelcapture.BpfOpExec, Action: kernelcapture.BpfActionDeny, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
		},
	}
	if err := kernelcapture.ApplyPolicyMaps(maps, cgroupID, policy); err != nil {
		return fmt.Errorf("apply OP_EXEC:DENY policy: %w", err)
	}
	fmt.Printf("applied OP_EXEC:DENY (ENFORCE) policy for cgroup_id=%d\n", cgroupID)

	denyEvent := make(chan error, 1)
	go watchForDenyEvent(handles, cgroupID, denyEvent)

	if err := execveInCgroupExpectEPERM(cgFile); err != nil {
		return err
	}
	fmt.Println("execve in the managed cgroup failed with EPERM, as expected")

	select {
	case err := <-denyEvent:
		if err != nil {
			return fmt.Errorf("enforce_events ringbuf: %w", err)
		}
	case <-time.After(ringbufTimeout):
		return fmt.Errorf("no matching DENY event observed on enforce_events within %s", ringbufTimeout)
	}
	return nil
}

// setupSmokeCgroup creates a fresh leaf cgroup and returns its kernel
// cgroup_id (the cgroup directory's inode number — what
// bpf_get_current_cgroup_id() returns) plus an open fd on the directory for
// use with SysProcAttr.CgroupFD.
func setupSmokeCgroup() (uint64, *os.File, error) {
	if err := os.RemoveAll(cgroupDir); err != nil && !os.IsNotExist(err) {
		return 0, nil, fmt.Errorf("clear stale cgroup: %w", err)
	}
	if err := os.Mkdir(cgroupDir, 0o755); err != nil {
		return 0, nil, fmt.Errorf("mkdir %s: %w", cgroupDir, err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(cgroupDir, &st); err != nil {
		return 0, nil, fmt.Errorf("stat %s: %w", cgroupDir, err)
	}
	f, err := os.Open(cgroupDir)
	if err != nil {
		return 0, nil, fmt.Errorf("open %s: %w", cgroupDir, err)
	}
	return st.Ino, f, nil
}

// execveInCgroupExpectEPERM spawns /bin/true directly into the smoke cgroup
// via clone3(CLONE_INTO_CGROUP) (Go's SysProcAttr.UseCgroupFD) so the child
// is already scoped to cgroupID at the moment guard_bprm_check runs during
// its execve — no race window where it briefly runs ungoverned.
func execveInCgroupExpectEPERM(cgFile *os.File) error {
	target, err := exec.LookPath("true")
	if err != nil {
		target = "/bin/true"
	}
	cmd := exec.Command(target)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    int(cgFile.Fd()),
	}
	err = cmd.Run()
	if err == nil {
		return fmt.Errorf("expected execve(%s) to fail with EPERM under the DENY policy, but it succeeded", target)
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) || errno != syscall.EPERM {
		return fmt.Errorf("expected EPERM, got: %w", err)
	}
	return nil
}

// watchForDenyEvent reads enforce_events until it sees a DENY record for
// cgroupID + OP_EXEC, or the reader is closed / times out.
func watchForDenyEvent(handles *kernelcapture.ProcessGuardHandles, cgroupID uint64, result chan<- error) {
	reader := handles.Reader()
	reader.SetDeadline(time.Now().Add(ringbufTimeout))
	for {
		record, err := reader.Read()
		if err != nil {
			result <- fmt.Errorf("read enforce_events: %w", err)
			return
		}
		ev, ok := decodeSmokeEvent(record.RawSample)
		if !ok {
			continue
		}
		if ev.cgroupID == cgroupID && ev.op == uint32(kernelcapture.BpfOpExec) && ev.actionTaken == uint32(kernelcapture.BpfActionDeny) {
			result <- nil
			return
		}
	}
}

// smokeEvent holds only the leading scalar fields of struct
// ardur_enforce_event (process_guard.bpf.c) that this smoke test needs to
// assert on — see decodeEnforceEvent in
// go/cmd/ardur-kernelcaptured/daemon_guard_common.go for the full,
// production decode of every field (comm, path, etc).
type smokeEvent struct {
	cgroupID    uint64
	pid         uint32
	op          uint32
	actionTaken uint32
	enforceMode uint32
}

func decodeSmokeEvent(raw []byte) (smokeEvent, bool) {
	const headerSize = 8 + 4 + 4 + 4 + 4 // cgroup_id, pid, op, action_taken, enforce_mode
	if len(raw) < headerSize {
		return smokeEvent{}, false
	}
	return smokeEvent{
		cgroupID:    binary.NativeEndian.Uint64(raw[0:8]),
		pid:         binary.NativeEndian.Uint32(raw[8:12]),
		op:          binary.NativeEndian.Uint32(raw[12:16]),
		actionTaken: binary.NativeEndian.Uint32(raw[16:20]),
		enforceMode: binary.NativeEndian.Uint32(raw[20:24]),
	}, true
}
