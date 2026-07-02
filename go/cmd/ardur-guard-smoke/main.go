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
			// EnforceMode: Enforce sets cgroup_managed's STRICT flag, so any
			// op with no rule in the active slot fails closed. execve(2)
			// opens the target binary for reading (guard_file_open,
			// OP_FILE_READ) *before* the kernel calls bprm_check_security
			// (guard_bprm_check, OP_EXEC) — confirmed on a real kernel: the
			// first version of this test denied at the file-open step with
			// no OP_FILE_READ rule present, and the process never reached
			// exec at all. Without this ALLOW, EPERM would still occur (both
			// hooks fail closed), but for the wrong reason, and no OP_EXEC
			// DENY event would ever land on enforce_events.
			{Op: kernelcapture.BpfOpFileRead, Action: kernelcapture.BpfActionAllow, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
			{Op: kernelcapture.BpfOpExec, Action: kernelcapture.BpfActionDeny, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
		},
	}
	if err := kernelcapture.ApplyPolicyMaps(maps, cgroupID, policy); err != nil {
		return fmt.Errorf("apply OP_FILE_READ:ALLOW + OP_EXEC:DENY policy: %w", err)
	}
	fmt.Printf("applied OP_FILE_READ:ALLOW + OP_EXEC:DENY (ENFORCE) policy for cgroup_id=%d\n", cgroupID)

	denyEvent := make(chan error, 1)
	watcherReady := make(chan struct{})
	go watchForDenyEvent(handles, cgroupID, watcherReady, denyEvent)
	<-watcherReady // watcher is blocked in reader.Read() before we trigger the exec

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
// cgroupID + OP_EXEC, or the reader is closed / times out. Closes ready right
// before its first blocking Read() call so the caller can be certain the
// watcher is actually listening before triggering the exec that should
// produce the event — belt-and-suspenders on top of the ring buffer itself
// preserving unconsumed entries regardless of when Read() is first called.
//
// Every record seen (matching or not) is logged: if this test ever fails
// again, that log distinguishes "zero records — decide() never called
// emit_event, e.g. another LSM earlier in the lsm= chain denied the exec
// first and guard_bprm_check's `if (ret != 0) return ret;` short-circuited
// before evaluating our policy at all" from "records arrived but didn't
// match — a decode or field-value bug in this harness" or "matched a
// different op/action than expected."
func watchForDenyEvent(handles *kernelcapture.ProcessGuardHandles, cgroupID uint64, ready chan<- struct{}, result chan<- error) {
	reader := handles.Reader()
	reader.SetDeadline(time.Now().Add(ringbufTimeout))
	close(ready)
	seen := 0
	for {
		record, err := reader.Read()
		if err != nil {
			result <- fmt.Errorf("read enforce_events: %w (saw %d unrelated record(s) first)", err, seen)
			return
		}
		ev, ok := decodeSmokeEvent(record.RawSample)
		if !ok {
			fmt.Printf("enforce_events: record too short to decode (%d bytes)\n", len(record.RawSample))
			continue
		}
		seen++
		fmt.Printf("enforce_events[%d]: cgroup_id=%d op=%d action=%d mode=%d pid=%d\n",
			seen, ev.cgroupID, ev.op, ev.actionTaken, ev.enforceMode, ev.pid)
		if ev.cgroupID == cgroupID && ev.op == uint32(kernelcapture.BpfOpExec) && ev.actionTaken == uint32(kernelcapture.BpfActionDeny) {
			result <- nil
			return
		}
	}
}

// smokeEvent holds only the leading scalar fields of struct
// ardur_enforce_event (process_guard.bpf.c) that this smoke test needs to
// assert on — see decodeEnforceEvent in
// go/cmd/ardur-kernelcaptured/daemon_enforce.go for the full, production
// decode of every field (comm, path, etc).
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
