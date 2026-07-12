//go:build linux

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// hsWithPID builds a NON-root peer handshake so the register-time ancestry
// and cgroup-ownership checks actually run (both are skipped for uid-0 peers,
// which are already fully privileged — see verifyRegisterSessionCgroup).
func hsWithPID(pid uint32) kernelcapture.DaemonProtocolPeerHandshake {
	return kernelcapture.DaemonProtocolPeerHandshake{
		Authorization: kernelcapture.DaemonPeerAuthorization{PID: pid, UID: 501},
	}
}

func hsRootWithPID(pid uint32) kernelcapture.DaemonProtocolPeerHandshake {
	return kernelcapture.DaemonProtocolPeerHandshake{
		Authorization: kernelcapture.DaemonPeerAuthorization{PID: pid, UID: 0},
	}
}

func regReq(rootPID uint32, cgroupID uint64) *kernelcapture.DaemonRegisterSessionRequest {
	return &kernelcapture.DaemonRegisterSessionRequest{SessionID: "s", RootPID: rootPID, CgroupID: cgroupID}
}

func verifyRegisterSessionCgroupErr(handshake kernelcapture.DaemonProtocolPeerHandshake, reg *kernelcapture.DaemonRegisterSessionRequest) error {
	_, err := verifyRegisterSessionCgroup(handshake, reg, quietLogger())
	return err
}

// spawnTestChild starts a real, short-lived child of the current test process
// (guaranteeing genuine PID ancestry, the same relationship a launcher has to
// the agent it Popen()s) and returns its PID. Killed and reaped on cleanup.
func spawnTestChild(t *testing.T) uint32 {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn test child: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return uint32(cmd.Process.Pid)
}

// selfCgroupID resolves the test process's own real cgroup_id via the same
// code path verifyRegisterSessionCgroup uses, so tests assert against ground
// truth rather than a value the test guessed independently.
func selfCgroupID(t *testing.T) uint64 {
	t.Helper()
	id, err := resolveCgroupID(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("resolveCgroupID(self): %v", err)
	}
	return id
}

func TestProcParentPID_Self(t *testing.T) {
	got, err := procParentPID(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("procParentPID(self): %v", err)
	}
	if want := uint32(os.Getppid()); got != want {
		t.Fatalf("procParentPID(self) = %d, want %d", got, want)
	}
}

func TestResolveCgroupID_SelfIsNonZeroAndStable(t *testing.T) {
	self := uint32(os.Getpid())
	first, err := resolveCgroupID(self)
	if err != nil {
		t.Fatalf("resolveCgroupID(self): %v", err)
	}
	if first == 0 {
		t.Fatal("resolveCgroupID(self) = 0, want a real cgroup inode")
	}
	second, err := resolveCgroupID(self)
	if err != nil {
		t.Fatalf("resolveCgroupID(self) second call: %v", err)
	}
	if second != first {
		t.Fatalf("resolveCgroupID(self) is not stable across calls: %d != %d", first, second)
	}
}

func TestResolveCgroupID_UnknownPidErrors(t *testing.T) {
	if _, err := resolveCgroupID(1 << 30); err == nil {
		t.Fatal("resolveCgroupID for a non-existent pid should error")
	}
}

// TestVerifyRegisterSessionCgroup_SelfIsOwned proves the still-supported
// happy path: a peer registering its own pid with its OWN real cgroup_id is
// accepted. Before #119 this test used an arbitrary, unverified cgroup_id
// (12345) because nothing checked it; it now must supply the real value.
func TestVerifyRegisterSessionCgroup_SelfIsOwned(t *testing.T) {
	self := uint32(os.Getpid())
	if err := verifyRegisterSessionCgroupErr(hsWithPID(self), regReq(self, selfCgroupID(t))); err != nil {
		t.Fatalf("self-registration with the real cgroup_id should be owned, got: %v", err)
	}
}

// TestVerifyRegisterSessionCgroup_SelfWithWrongCgroupRejected is the #119 gap
// in its simplest form — no child process needed at all: a peer claiming its
// OWN pid as root_pid (trivially "owned" by the old ancestry-only check) but
// a cgroup_id that is NOT the pid's real cgroup must be rejected.
func TestVerifyRegisterSessionCgroup_SelfWithWrongCgroupRejected(t *testing.T) {
	self := uint32(os.Getpid())
	wrong := selfCgroupID(t) + 1 // guaranteed != the real value by construction
	err := verifyRegisterSessionCgroupErr(hsWithPID(self), regReq(self, wrong))
	if err == nil {
		t.Fatal("self-registration claiming a cgroup_id that is not the pid's real cgroup should be rejected")
	}
}

func TestVerifyRegisterSessionCgroup_NonDescendantRejected(t *testing.T) {
	self := uint32(os.Getpid())
	// pid 1 (init) exists but is not a descendant of the test process — a peer
	// naming a process it did not spawn must be rejected, before cgroup
	// ownership is even considered.
	if err := verifyRegisterSessionCgroupErr(hsWithPID(self), regReq(1, 12345)); err == nil {
		t.Fatal("registering pid 1 (not a descendant of the peer) should be rejected")
	}
}

func TestVerifyRegisterSessionCgroup_BogusRootRejected(t *testing.T) {
	self := uint32(os.Getpid())
	// A pid that is not a live process cannot be verified — reject.
	if err := verifyRegisterSessionCgroupErr(hsWithPID(self), regReq(1<<30, 12345)); err == nil {
		t.Fatal("registering a non-existent root_pid should be rejected")
	}
}

func TestVerifyRegisterSessionCgroup_PeerNotVisibleRejected(t *testing.T) {
	// If the peer itself is not visible in /proc, neither ancestry nor cgroup
	// ownership can be established. Accepting the registration would restore
	// the cross-workload enforcement path closed by issue #119, so fail closed.
	err := verifyRegisterSessionCgroupErr(hsWithPID(1<<30), regReq(1, 12345))
	if err == nil {
		t.Fatal("unresolvable non-root peer should be rejected, not granted enforce rights")
	}
	if !strings.Contains(err.Error(), "not visible in the daemon /proc view") {
		t.Fatalf("unresolvable peer error = %q, want explicit daemon /proc visibility failure", err)
	}
}

func TestVerifyRegisterSessionCgroup_PeerPIDUnavailableRejected(t *testing.T) {
	// Cross-namespace peer-credential translation can yield no usable PID in
	// the receiver's namespace. UID authorization alone cannot bind that peer
	// to root_pid or cgroup_id, so an unavailable PID must also fail closed.
	err := verifyRegisterSessionCgroupErr(hsWithPID(0), regReq(1, 12345))
	if err == nil {
		t.Fatal("non-root peer without a usable peer pid should be rejected")
	}
	if !strings.Contains(err.Error(), "peer pid is unavailable") {
		t.Fatalf("missing peer pid error = %q, want explicit unavailable-pid failure", err)
	}
}

func TestHandleAuthorizedRequest_PeerNotVisibleDoesNotRegisterSession(t *testing.T) {
	d := newTestDaemon(t)
	d.cgroupVerifier = verifyRegisterSessionCgroup
	const sessionID = "proc-invisible-peer"
	req := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodRegisterSession,
		RegisterSession: &kernelcapture.DaemonRegisterSessionRequest{
			SessionID:    sessionID,
			RootPID:      1,
			CgroupID:     12345,
			EventClasses: []string{kernelcapture.DaemonProtocolEventProcessLifecycle},
			TTLSeconds:   60,
		},
	}

	resp := d.handleAuthorizedRequest(context.Background(), req, hsWithPID(1<<30))
	if resp.OK {
		t.Fatalf("register_session for an unresolvable non-root peer succeeded: %+v", resp)
	}
	if !strings.Contains(resp.Error, "peer pid") || !strings.Contains(resp.Error, "not visible") {
		t.Fatalf("register_session error = %q, want explicit peer-pid visibility failure", resp.Error)
	}
	if _, registered := d.registry.Session(sessionID); registered {
		t.Fatal("rejected unresolvable peer was persisted in the session registry")
	}
}

func TestVerifyRegisterSessionCgroup_RootPeerSkips(t *testing.T) {
	// A root peer is already fully privileged; both checks are skipped for it
	// (a non-root peer with the same args is rejected — see above).
	if err := verifyRegisterSessionCgroupErr(hsRootWithPID(uint32(os.Getpid())), regReq(1, 12345)); err != nil {
		t.Fatalf("root peer should skip both checks, got: %v", err)
	}
}

// ── issue #119: live PoC reproduction ───────────────────────────────────────
//
// The reported exploit: a non-root allowed peer calls
//
//	register_session{root_pid: <peer's own child>, cgroup_id: <victim's cgroup>}
//
// Ancestry passes (root_pid really is the peer's child), so the pre-#119
// check (which never looked at cgroup_id at all) accepted this and returned
// OK=true. The peer could then apply_policy against a cgroup — and workload —
// it does not own. These two tests are that exact reproduction: a genuine
// spawned child (real ancestry, not simulated) claiming a cgroup_id that is
// NOT the child's real cgroup.

func TestVerifyRegisterSessionCgroup_Issue119PocRejected(t *testing.T) {
	self := uint32(os.Getpid())
	child := spawnTestChild(t)

	realCgroup, err := resolveCgroupID(child)
	if err != nil {
		t.Fatalf("resolveCgroupID(child): %v", err)
	}
	victimCgroupID := realCgroup + 1 // "another workload's" cgroup: anything != the child's real one

	// This is the exact call shape from the #119 report: ancestry passes
	// (child really was spawned by self), cgroup_id does not match reality.
	err = verifyRegisterSessionCgroupErr(hsWithPID(self), regReq(child, victimCgroupID))
	if err == nil {
		t.Fatal("#119 PoC: register_session{root_pid: own child, cgroup_id: victim} " +
			"was accepted (OK=true) — the cgroup-ownership gap is NOT closed")
	}
	t.Logf("#119 PoC correctly rejected: %v", err)
}

func TestVerifyRegisterSessionCgroup_Issue119PocAcceptedWithCorrectCgroup(t *testing.T) {
	// Companion to the rejection test above: proves the check is a real
	// ownership comparison, not a blanket rejection of any child-cgroup
	// registration. Same ancestry (spawned child), but the TRUE cgroup_id —
	// this is exactly the shape of a legitimate `ardur run` registration
	// before the launcher has moved the child anywhere (the common case: no
	// cgroup adoption happened, the child stayed in the parent's cgroup).
	self := uint32(os.Getpid())
	child := spawnTestChild(t)

	realCgroup, err := resolveCgroupID(child)
	if err != nil {
		t.Fatalf("resolveCgroupID(child): %v", err)
	}

	if err := verifyRegisterSessionCgroupErr(hsWithPID(self), regReq(child, realCgroup)); err != nil {
		t.Fatalf("registering a spawned child with its REAL cgroup_id should be accepted, got: %v", err)
	}
}

// ── legit `ardur run` adoption flow ─────────────────────────────────────────

// cgroupV2SelfDir resolves the test process's own cgroupfs directory, or
// skips the test if it cannot be resolved (no cgroup v2, or otherwise
// unavailable in this environment).
func cgroupV2SelfDir(t *testing.T) string {
	t.Helper()
	path, err := resolveCgroupPath(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("cannot resolve own cgroup path (%v); skipping real-adoption reproduction", err)
	}
	return path
}

// TestVerifyRegisterSessionCgroup_LegitAdoptFlowAccepted reproduces the real
// `ardur run` sequence end to end: create a dedicated cgroup (as
// kernel_correlation.create_run_cgroup does), spawn a child, move it into
// that cgroup via cgroup.procs (as CgroupHandle.adopt_pid does), then
// register with the new cgroup's real inode. Must be accepted — the fix must
// not break the legitimate flow it exists to protect.
//
// Skips gracefully (not a failure) if this environment does not grant write
// access to a cgroup v2 subtree under the test process's own cgroup — that
// needs either root or a delegated slice (most systemd-managed CI runners,
// including GitHub Actions' default ubuntu images, delegate one to the login
// session; environments that don't still exercise the rest of this file's
// coverage via the two Issue119Poc tests above, which don't need a real
// cgroup move).
func TestVerifyRegisterSessionCgroup_LegitAdoptFlowAccepted(t *testing.T) {
	parent := cgroupV2SelfDir(t)
	target := filepath.Join(parent, "ardur-test-119-"+strconv.Itoa(os.Getpid()))

	if err := os.Mkdir(target, 0o755); err != nil {
		t.Skipf("cannot create cgroup subtree at %s (%v); need cgroup v2 delegation to run this reproduction", target, err)
	}
	t.Cleanup(func() { _ = os.Remove(target) })

	child := spawnTestChild(t)

	procs := filepath.Join(target, "cgroup.procs")
	if err := os.WriteFile(procs, []byte(strconv.Itoa(int(child))), 0o644); err != nil {
		t.Skipf("cannot move child into new cgroup via %s (%v); need cgroup v2 delegation to run this reproduction", procs, err)
	}

	resolvedCgroupID, err := resolveCgroupID(child)
	if err != nil {
		t.Fatalf("resolveCgroupID(child) after adoption: %v", err)
	}

	self := uint32(os.Getpid())
	if err := verifyRegisterSessionCgroupErr(hsWithPID(self), regReq(child, resolvedCgroupID)); err != nil {
		t.Fatalf("legit adopt-then-register flow should be accepted, got: %v", err)
	}
}
