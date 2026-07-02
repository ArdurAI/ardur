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
//     with -EPERM for a process placed in that cgroup (runExecDenyScenario).
//  3. A cgroup with an OP_FILE_WRITE:ALLOWLIST/ENFORCE policy actually
//     permits opens under the allowlisted directory and denies opens
//     outside it (runFileAllowlistScenario) — the Slice 4.1/4.2
//     reconciliation this file exists to prove: guard_file_open is
//     sleepable and cannot use the cgroup_path_allow LPM trie the other
//     hooks use, so this exercises the cgroup_file_allow HASH-map ancestor
//     walk that replaces it for file ops (see ardur_file_allow_key's doc
//     comment in process_guard.bpf.c).
//  4. Both cases produce a matching record on the enforce_events ringbuf.
//
// Not part of `go test ./...`: this mutates real kernel state (loads a
// BPF-LSM program, creates cgroups) and requires CAP_BPF/CAP_SYS_ADMIN,
// CONFIG_BPF_LSM=y, "bpf" active in /sys/kernel/security/lsm, and cgroup v2 —
// preconditions only the disposable kernel-smoke VM guarantees.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

const (
	smokeGeneration = 1
	ringbufTimeout  = 10 * time.Second
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: process_guard enforced both the exec-deny and file-allowlist scenarios with matching enforce_events")
}

func run() error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root (loads a BPF-LSM program and creates cgroups)")
	}

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

	if err := runExecDenyScenario(handles); err != nil {
		return fmt.Errorf("exec-deny scenario: %w", err)
	}
	fmt.Println("exec-deny scenario: PASS")

	if err := runFileAllowlistScenario(handles); err != nil {
		return fmt.Errorf("file-allowlist scenario: %w", err)
	}
	fmt.Println("file-allowlist scenario: PASS")

	return nil
}

// runExecDenyScenario proves an OP_EXEC:DENY/ENFORCE policy blocks execve
// with -EPERM and emits a matching DENY event.
func runExecDenyScenario(handles *kernelcapture.ProcessGuardHandles) error {
	const cgroupDir = "/sys/fs/cgroup/ardur-guard-smoke-exec"

	cgroupID, cgFile, err := setupSmokeCgroup(cgroupDir)
	if err != nil {
		return fmt.Errorf("set up cgroup: %w", err)
	}
	defer cgFile.Close()
	defer os.Remove(cgroupDir)

	maps := kernelcapture.PolicyMapsFromHandles(handles)
	policy := kernelcapture.DaemonApplyPolicyRequest{
		SessionID:   "guard-smoke-exec",
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
	go watchForEnforceEvent(handles, cgroupID, kernelcapture.BpfOpExec, kernelcapture.BpfActionDeny, watcherReady, denyEvent)
	<-watcherReady // watcher is blocked in reader.Read() before we trigger the exec

	if err := execveInCgroupExpectEPERM(cgFile); err != nil {
		return err
	}
	fmt.Println("execve in the managed cgroup failed with EPERM, as expected")

	return waitForEvent(denyEvent)
}

// runFileAllowlistScenario proves an OP_FILE_WRITE:ALLOWLIST/ENFORCE policy
// (as produced by bpf_lower.py's SubpathPolicy/resource_scope lowering)
// actually permits writes under the allowlisted directory and denies writes
// outside it — the reconciliation this file was added for. OP_EXEC and
// OP_FILE_READ are set to unconditional ALLOW so /bin/sh's own execve
// (which opens the sh binary for reading before this scenario's target path
// is ever written to) isn't itself denied by the STRICT no-rule
// fail-closed, for a reason unrelated to what this scenario tests.
func runFileAllowlistScenario(handles *kernelcapture.ProcessGuardHandles) error {
	const cgroupDir = "/sys/fs/cgroup/ardur-guard-smoke-fileallow"

	cgroupID, cgFile, err := setupSmokeCgroup(cgroupDir)
	if err != nil {
		return fmt.Errorf("set up cgroup: %w", err)
	}
	defer cgFile.Close()
	defer os.Remove(cgroupDir)

	allowedDir, err := resolvedTempDir("ardur-guard-smoke-allowed")
	if err != nil {
		return fmt.Errorf("create allowed dir: %w", err)
	}
	defer os.RemoveAll(allowedDir)

	deniedDir, err := resolvedTempDir("ardur-guard-smoke-denied")
	if err != nil {
		return fmt.Errorf("create denied dir: %w", err)
	}
	defer os.RemoveAll(deniedDir)

	// nestedAllowedDir is two directory levels below an UNREGISTERED parent
	// (deniedDir/nested-parent), with only nestedAllowedDir itself in
	// path_allow. A write under it can only succeed if file_path_is_allowed's
	// ancestor walk correctly (a) does NOT match on the first, shallower
	// ancestor boundary it reaches (deniedDir/nested-parent, unregistered)
	// and (b) keeps walking to find the second, deeper one that IS
	// registered — proving the loop's "keep checking up to
	// ARDUR_FILE_ALLOW_MAX_ANCESTORS matches" behavior, not just the
	// single-ancestor case allowedDir/ok.txt below already covers.
	nestedAllowedDir := filepath.Join(deniedDir, "nested-parent", "nested-allowed")
	if err := os.MkdirAll(nestedAllowedDir, 0o755); err != nil {
		return fmt.Errorf("create nested allowed dir: %w", err)
	}

	maps := kernelcapture.PolicyMapsFromHandles(handles)
	policy := kernelcapture.DaemonApplyPolicyRequest{
		SessionID:   "guard-smoke-fileallow",
		Generation:  smokeGeneration,
		EnforceMode: kernelcapture.BpfEnforceModeEnforce,
		PathAllow:   []string{allowedDir, nestedAllowedDir},
		OpPolicies: []kernelcapture.DaemonOpPolicy{
			{Op: kernelcapture.BpfOpExec, Action: kernelcapture.BpfActionAllow, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
			{Op: kernelcapture.BpfOpFileRead, Action: kernelcapture.BpfActionAllow, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
			{Op: kernelcapture.BpfOpFileWrite, Action: kernelcapture.BpfActionAllowlist, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
		},
	}
	if err := kernelcapture.ApplyPolicyMaps(maps, cgroupID, policy); err != nil {
		return fmt.Errorf("apply OP_FILE_WRITE:ALLOWLIST(%s, %s) policy: %w", allowedDir, nestedAllowedDir, err)
	}
	fmt.Printf("applied OP_FILE_WRITE:ALLOWLIST(%s, %s) (ENFORCE) policy for cgroup_id=%d\n", allowedDir, nestedAllowedDir, cgroupID)

	allowedPath := filepath.Join(allowedDir, "ok.txt")
	if err := writeExpectSuccess(handles, cgroupID, cgFile, allowedPath); err != nil {
		return fmt.Errorf("write under allowlisted dir: %w", err)
	}
	fmt.Printf("write to %s succeeded and produced a matching ALLOW event, as expected\n", allowedPath)

	nestedAllowedPath := filepath.Join(nestedAllowedDir, "ok.txt")
	if err := writeExpectSuccess(handles, cgroupID, cgFile, nestedAllowedPath); err != nil {
		return fmt.Errorf("write under nested allowlisted dir: %w", err)
	}
	fmt.Printf("write to %s succeeded and produced a matching ALLOW event, as expected (multi-level ancestor walk)\n", nestedAllowedPath)

	deniedPath := filepath.Join(deniedDir, "blocked.txt")
	if err := writeExpectBlocked(handles, cgroupID, cgFile, deniedPath); err != nil {
		return fmt.Errorf("write outside allowlisted dir: %w", err)
	}
	fmt.Printf("write to %s was blocked and produced a matching DENY event, as expected\n", deniedPath)

	// deniedDir/nested-parent itself (the unregistered ancestor between
	// deniedDir and nestedAllowedDir) must still be denied — otherwise the
	// walk would be matching too broadly (allowing everything under
	// deniedDir once ANY of its descendants is allowlisted) rather than
	// only the exact registered directory and its own descendants.
	deniedParentPath := filepath.Join(deniedDir, "nested-parent", "blocked-here.txt")
	if err := writeExpectBlocked(handles, cgroupID, cgFile, deniedParentPath); err != nil {
		return fmt.Errorf("write in the unregistered ancestor between deniedDir and nestedAllowedDir: %w", err)
	}
	fmt.Printf("write to %s was blocked and produced a matching DENY event, as expected (unregistered ancestor of an allowlisted descendant stays denied)\n", deniedParentPath)

	return nil
}

// setupSmokeCgroup creates a fresh leaf cgroup at cgroupDir and returns its
// kernel cgroup_id (the cgroup directory's inode number — what
// bpf_get_current_cgroup_id() returns) plus an open fd on the directory for
// use with SysProcAttr.CgroupFD.
func setupSmokeCgroup(cgroupDir string) (uint64, *os.File, error) {
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

// tempDirBase is /dev/shm, not the OS default (os.MkdirTemp("", ...), which
// resolves to /tmp). Confirmed on a real kernel-smoke run: virtme-ng's guest
// mounts /tmp (along with /etc, /lib, /home, /opt, /srv, /usr, /var) as an
// overlayfs so the runner's read-only host root can be written to at all —
// and EVM (Extended Verification Module, one of several LSMs active
// alongside "bpf" in this guest regardless of what --append requests; see
// this file's own history in kernel-enforce.yml for that precedent) logs
// "evm: overlay not supported" at boot and then independently vetoes
// file_open on writes under that overlay with EPERM. This is a completely
// separate LSM decision from process_guard's — confirmed by the
// enforce_events log on the failing run, which showed process_guard
// correctly returning ALLOW (action=0) for the exact same open() that still
// failed. /dev/shm is a plain tmpfs, outside virtme-ng's overlay set and not
// subject to this EVM interaction, so it exercises this scenario's actual
// subject (process_guard's ACT_ALLOWLIST decision) without an unrelated LSM
// getting in the way.
const tempDirBase = "/dev/shm"

// resolvedTempDir creates a fresh temp directory under tempDirBase and
// resolves any symlinks in its path. guard_file_open resolves the path it
// checks via bpf_d_path (the kernel's canonical view, symlinks and all
// already followed), so a path_allow entry must be given in the same
// resolved form or an environment where the temp dir's parent happens to be
// a symlink would make an intentionally-allowed write look like a false
// DENY.
func resolvedTempDir(pattern string) (string, error) {
	dir, err := os.MkdirTemp(tempDirBase, pattern)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("resolve symlinks in %s: %w", dir, err)
	}
	return resolved, nil
}

// runInCgroup spawns name(args...) directly into the cgroup behind cgFile
// via clone3(CLONE_INTO_CGROUP) (Go's SysProcAttr.UseCgroupFD), so the child
// is already scoped to that cgroup at the moment any LSM hook runs during
// its execve/open — no race window where it briefly runs ungoverned.
func runInCgroup(cgFile *os.File, name string, args ...string) error {
	target, err := exec.LookPath(name)
	if err != nil {
		target = name
	}
	cmd := exec.Command(target, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    int(cgFile.Fd()),
	}
	// Captured (not just discarded to /dev/null, exec.Cmd's default for a
	// nil Stderr) so a failure's error message includes *why* — an opaque
	// exit code alone isn't enough to tell an ENFORCE-caused denial apart
	// from an unrelated shell/environment error, and this test needs that
	// distinction to be trustworthy.
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("%w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
		}
		return err
	}
	return nil
}

// probeContent is written by writeExpectSuccess/writeExpectBlocked via a
// shell redirect. Its exact bytes are asserted on the allowed side and used
// to detect an enforcement bypass on the denied side (see
// writeExpectBlocked's doc comment).
const probeContent = "ardur-guard-smoke-file-allowlist-probe"

// writeExpectSuccess writes probeContent to path (via `sh -c "printf ... >
// path"` in the cgroup) and asserts the write succeeds, the file's content
// matches, and a matching OP_FILE_WRITE ALLOW event landed on
// enforce_events.
func writeExpectSuccess(handles *kernelcapture.ProcessGuardHandles, cgroupID uint64, cgFile *os.File, path string) error {
	allowEvent := make(chan error, 1)
	ready := make(chan struct{})
	go watchForEnforceEvent(handles, cgroupID, kernelcapture.BpfOpFileWrite, kernelcapture.BpfActionAllow, ready, allowEvent)
	<-ready

	if err := writeViaShellRedirect(cgFile, path); err != nil {
		return fmt.Errorf("write %s: expected success, got: %w", path, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("write %s exited 0 but the file is not readable: %w", path, err)
	}
	if string(got) != probeContent {
		return fmt.Errorf("write %s exited 0 but content = %q, want %q", path, got, probeContent)
	}
	return waitForEvent(allowEvent)
}

// writeExpectBlocked writes probeContent to path (via `sh -c "printf ... >
// path"` in the cgroup) and asserts the write is blocked, then confirms a
// matching OP_FILE_WRITE DENY event landed on enforce_events.
//
// "Blocked" here means "probeContent never landed on disk", not "the file
// does not exist" and not "sh exited nonzero" — neither of those is a
// reliable signal on their own:
//
//   - The file MAY exist afterward with size 0. security_file_open (the
//     guard_file_open hook point) runs in do_dentry_open, which is AFTER
//     the VFS has already resolved/created the O_CREAT dentry in
//     path_openat — an LSM denial at that point fails the open() call
//     (sh gets EPERM, no fd, no write happens) but does not undo the
//     dentry the earlier lookup step already created. This is a real
//     kernel/LSM characteristic, not a gap in this policy or a bug in
//     process_guard.bpf.c: nothing this program does at the LSM hook can
//     prevent that empty dentry from existing, only prevent it from ever
//     being written to.
//   - sh's own exit code is not load-bearing either way: confirmed
//     unreliable with touch(1) in an earlier version of this test — touch
//     fell back to utimensat(2) after its own O_CREAT|O_WRONLY open got
//     EPERM, and utimensat is a path-based syscall this policy does not
//     gate (only file_open is hooked), so it silently succeeded and touch
//     exited 0 despite the write itself having been correctly denied. A
//     shell redirect (`> path`) has no such fallback — a failed open()
//     is a hard failure for the shell — but this test does not depend on
//     that exit code regardless, precisely because the underlying
//     ambiguity (does "the tool reported success" mean "content landed"?)
//     is exactly what caused the touch-based version to give a false
//     failure signal.
//
// So the only assertion that actually distinguishes "write correctly
// blocked" from "a real ACT_ALLOWLIST bypass" is content: absent or empty
// is fine (nothing was ever written), any occurrence of probeContent is a
// hard failure (the write reached disk despite the policy).
func writeExpectBlocked(handles *kernelcapture.ProcessGuardHandles, cgroupID uint64, cgFile *os.File, path string) error {
	denyEvent := make(chan error, 1)
	ready := make(chan struct{})
	go watchForEnforceEvent(handles, cgroupID, kernelcapture.BpfOpFileWrite, kernelcapture.BpfActionDeny, ready, denyEvent)
	<-ready

	_ = writeViaShellRedirect(cgFile, path) // exit code intentionally ignored — see doc comment

	if got, err := os.ReadFile(path); err == nil && string(got) == probeContent {
		return fmt.Errorf("write %s: policy denied this path, but probeContent landed on disk anyway (ACT_ALLOWLIST bypass)", path)
	}
	return waitForEvent(denyEvent)
}

// writeViaShellRedirect runs `sh -c "printf '%s' '<content>' > path"` in the
// cgroup. Shell redirection (not touch(1), see writeExpectBlocked's doc
// comment) so a failed open() has no fallback path that could mask a
// correctly-enforced denial as a false failure — or, in the touch(1) case
// this replaced, mask it as a false SUCCESS. probeContent is passed as
// printf's ARGUMENT, not its format string (`printf '%s' content`, not
// `printf content`) — printf treats its first operand as a format string,
// so passing arbitrary content there directly is a latent bug waiting for
// content that happens to contain a `%`.
func writeViaShellRedirect(cgFile *os.File, path string) error {
	return runInCgroup(cgFile, "sh", "-c", fmt.Sprintf("printf '%%s' %q > %q", probeContent, path))
}

// waitForEvent blocks until the watcher goroutine reports a match or times
// out. Factored out of both scenarios so the timeout message is consistent.
func waitForEvent(result <-chan error) error {
	select {
	case err := <-result:
		if err != nil {
			return fmt.Errorf("enforce_events ringbuf: %w", err)
		}
		return nil
	case <-time.After(ringbufTimeout):
		return fmt.Errorf("no matching event observed on enforce_events within %s", ringbufTimeout)
	}
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

// watchForEnforceEvent reads enforce_events until it sees a record matching
// cgroupID+op+action, or the reader is closed / times out. Closes ready
// right before its first blocking Read() call so the caller can be certain
// the watcher is actually listening before triggering the action that
// should produce the event — belt-and-suspenders on top of the ring buffer
// itself preserving unconsumed entries regardless of when Read() is first
// called.
//
// Every record seen (matching or not) is logged: if this test ever fails
// again, that log distinguishes "zero records — decide()/decide_file_open()
// never called emit_event, e.g. another LSM earlier in the lsm= chain denied
// first and the hook's `if (ret != 0) return ret;` short-circuited before
// evaluating our policy at all" from "records arrived but didn't match — a
// decode or field-value bug in this harness" or "matched a different op/
// action than expected."
func watchForEnforceEvent(
	handles *kernelcapture.ProcessGuardHandles,
	cgroupID uint64,
	op kernelcapture.BpfOp,
	action kernelcapture.BpfAction,
	ready chan<- struct{},
	result chan<- error,
) {
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
		if ev.cgroupID == cgroupID && ev.op == uint32(op) && ev.actionTaken == uint32(action) {
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
