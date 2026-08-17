package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

// Ensure the fs interface is satisfied by osEvidenceFS (compile-time check).
var _ evidenceFS = osEvidenceFS{}

// stubEvidenceFS captures AppendFile calls for inspection in tests.
type stubEvidenceFS struct {
	mu      sync.Mutex
	dirs    []string
	appends map[string][]byte
	err     error
}

func newStubFS() *stubEvidenceFS { return &stubEvidenceFS{appends: map[string][]byte{}} }

func (s *stubEvidenceFS) Lstat(_ string) (fs.FileInfo, error) {
	return nil, fs.ErrNotExist
}

func (s *stubEvidenceFS) MkdirAll(path string, _ fs.FileMode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirs = append(s.dirs, path)
	return s.err
}

func (s *stubEvidenceFS) AppendFile(path string, data []byte, _ fs.FileMode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.appends[path] = append(s.appends[path], data...)
	return nil
}

type blockingEvidenceFS struct {
	*stubEvidenceFS
	appendCalls   atomic.Int32
	firstEntered  chan struct{}
	secondEntered chan struct{}
	releaseFirst  chan struct{}
}

func newBlockingEvidenceFS() *blockingEvidenceFS {
	return &blockingEvidenceFS{
		stubEvidenceFS: newStubFS(),
		firstEntered:   make(chan struct{}),
		secondEntered:  make(chan struct{}),
		releaseFirst:   make(chan struct{}),
	}
}

func (s *blockingEvidenceFS) AppendFile(path string, data []byte, perm fs.FileMode) error {
	switch s.appendCalls.Add(1) {
	case 1:
		close(s.firstEntered)
		<-s.releaseFirst
	case 2:
		close(s.secondEntered)
	}
	return s.stubEvidenceFS.AppendFile(path, data, perm)
}

// newTestDaemon returns a daemon wired with an in-memory (stub) filesystem.
// It bypasses BuildDaemonCustodyPlan path validation so tests can run without
// privileged filesystem access.
func newTestDaemon(t *testing.T) *daemon {
	t.Helper()
	tmpDir := t.TempDir()
	d := &daemon{
		log:                       testLogger(t),
		registry:                  kernelcapture.NewDaemonSessionRegistry(),
		evidenceDir:               filepath.Join(tmpDir, "evidence"),
		cgroupIndex:               make(map[uint64]string),
		treeScopes:                make(map[string]*kernelcapture.ProcessTreeScope),
		correlators:               make(map[string]*kernelcapture.Correlator),
		routeIndex:                make(map[string]*sessionRoute),
		enforceChains:             make(map[string]*kernelcapture.EnforceReceiptChain),
		enforceSummaries:          make(map[string]*kernelcapture.EnforceEventSummaryAccumulator),
		enforceOrphanChain:        kernelcapture.NewEnforceReceiptChain(),
		enforceOrphanSummary:      kernelcapture.NewEnforceEventSummaryAccumulator(),
		lifecycleCaptureSummaries: make(map[string]*kernelcapture.LifecycleCaptureSummaryAccumulator),
		observabilityGaps:         make(map[string]*kernelcapture.ObservabilityGapAccumulator),
		lifecycleFilter:           newLifecycleFilterManager(),
		fs:                        osEvidenceFS{},
		tamperChain:               kernelcapture.NewTamperReceiptChain(),
		seccompPolicy:             kernelcapture.NewSeccompPolicyStore(),
		seccompListeners:          make(map[string]seccompListenerRegistration),
		activeTier:                daemonTierNone,
		appliedAllow:              make(map[string]*appliedAllowRecord),
		// No-op cgroup verifier: daemon-flow tests register synthetic PIDs that
		// aren't real /proc descendants. The real check is covered directly by
		// daemon_cgroup_verify_linux_test.go.
		cgroupVerifier: func(kernelcapture.DaemonProtocolPeerHandshake, *kernelcapture.DaemonRegisterSessionRequest, *slog.Logger) (uint64, error) {
			return 1, nil
		},
	}
	d.lifecycleFilter.markUnavailable(errors.New("lifecycle filter unavailable in unit test"))
	return d
}

// testLogger returns a logger that writes to t.Log.
func testLogger(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(testLogWriter{t}, nil))
}

// testLogWriter bridges io.Writer to t.Log.
type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

func TestSanitizeSessionID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"abc-123_XYZ", "abc-123_XYZ"},
		{"ses/path/../etc", "ses_path____etc"},
		{"uuid-0123456789abcdef", "uuid-0123456789abcdef"},
		{"", ""},
	}
	for _, c := range cases {
		got := sanitizeSessionID(c.in)
		if got != c.want {
			t.Errorf("sanitizeSessionID(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestOnSessionRegisteredAndEnded(t *testing.T) {
	d := newTestDaemon(t)

	reg := &kernelcapture.DaemonRegisterSessionRequest{
		SessionID:    "test-session-001",
		RootPID:      12345,
		CgroupID:     999,
		EventClasses: []string{kernelcapture.DaemonProtocolEventProcessLifecycle},
		TTLSeconds:   60,
	}
	d.onSessionRegistered(reg, "test-session-001")

	d.mu.RLock()
	cgroupSID, ok := d.cgroupIndex[999]
	scope := d.treeScopes["test-session-001"]
	corr := d.correlators["test-session-001"]
	d.mu.RUnlock()

	if !ok || cgroupSID != "test-session-001" {
		t.Errorf("cgroup index: got %q, want %q", cgroupSID, "test-session-001")
	}
	if scope == nil {
		t.Error("process tree scope not created")
	}
	if corr == nil {
		t.Error("correlator not created")
	}

	d.onSessionEnded("test-session-001")

	d.mu.RLock()
	_, inCgroup := d.cgroupIndex[999]
	_, inTree := d.treeScopes["test-session-001"]
	_, inCorr := d.correlators["test-session-001"]
	d.mu.RUnlock()

	if inCgroup {
		t.Error("cgroup index entry not removed after end_session")
	}
	if inTree {
		t.Error("tree scope entry not removed after end_session")
	}
	if inCorr {
		t.Error("correlator entry not removed after end_session")
	}
}

// ── issue #119: cgroup collision guard ──────────────────────────────────────
//
// checkCgroupCollision is the second, platform-neutral half of #119's fix:
// even a register_session that independently passes cgroupVerifier's
// ownership check must not be allowed to bind a cgroup_id another live
// session already holds.

func TestCheckCgroupCollision_RejectsCgroupAlreadyBoundToAnotherSession(t *testing.T) {
	d := newTestDaemon(t)
	d.mu.Lock()
	d.cgroupIndex[42] = "existing-session"
	d.mu.Unlock()

	err := d.checkCgroupCollision(&kernelcapture.DaemonRegisterSessionRequest{
		SessionID: "attacker-session",
		RootPID:   1,
		CgroupID:  42,
	})
	if err == nil {
		t.Fatal("registering a cgroup_id already bound to a different session should be rejected")
	}
}

func TestCheckCgroupCollision_AllowsSameSessionReRegistering(t *testing.T) {
	d := newTestDaemon(t)
	d.mu.Lock()
	d.cgroupIndex[42] = "same-session"
	d.mu.Unlock()

	// A session re-registering against the cgroup_id it already owns is not a
	// collision — it's a legitimate retry of its own registration.
	err := d.checkCgroupCollision(&kernelcapture.DaemonRegisterSessionRequest{
		SessionID: "same-session",
		RootPID:   1,
		CgroupID:  42,
	})
	if err != nil {
		t.Fatalf("a session re-registering its own cgroup_id should be allowed, got: %v", err)
	}
}

func TestCheckCgroupCollision_AllowsUnclaimedCgroup(t *testing.T) {
	d := newTestDaemon(t)
	err := d.checkCgroupCollision(&kernelcapture.DaemonRegisterSessionRequest{
		SessionID: "fresh-session",
		RootPID:   1,
		CgroupID:  777,
	})
	if err != nil {
		t.Fatalf("registering an unclaimed cgroup_id should be allowed, got: %v", err)
	}
}

func TestCheckCgroupCollision_ZeroCgroupIsNoop(t *testing.T) {
	d := newTestDaemon(t)
	// cgroup_id=0 is rejected by protocol validation before this check ever
	// matters in practice, but the guard itself must not panic or misbehave
	// on it (e.g. by treating "0: unbound" as some kind of universal match).
	if err := d.checkCgroupCollision(&kernelcapture.DaemonRegisterSessionRequest{SessionID: "s", RootPID: 1, CgroupID: 0}); err != nil {
		t.Fatalf("cgroup_id=0 should be a no-op, got: %v", err)
	}
}

func TestCheckCgroupCollision_NilRequestIsNoop(t *testing.T) {
	d := newTestDaemon(t)
	if err := d.checkCgroupCollision(nil); err != nil {
		t.Fatalf("nil request should be a no-op, got: %v", err)
	}
}

// TestHandleAuthorizedRequest_RejectsCgroupCollisionEvenWithNoOpVerifier
// proves the collision guard is wired into the real request path
// (handleAuthorizedRequest), not just unit-testable in isolation: even with
// cgroupVerifier stubbed to always-allow (as newTestDaemon does, and as
// production's verifyRegisterSessionCgroup would for a root peer or a
// same-cgroup claim), a second session cannot register the same cgroup_id
// an existing live session already holds.
func TestHandleAuthorizedRequest_RejectsCgroupCollisionEvenWithNoOpVerifier(t *testing.T) {
	d := newTestDaemon(t)
	d.mu.Lock()
	d.cgroupIndex[555] = "first-session"
	d.mu.Unlock()

	req := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodRegisterSession,
		RegisterSession: &kernelcapture.DaemonRegisterSessionRequest{
			SessionID:    "second-session",
			RootPID:      1,
			CgroupID:     555,
			EventClasses: []string{kernelcapture.DaemonProtocolEventProcessLifecycle},
			TTLSeconds:   60,
		},
	}
	resp := d.handleAuthorizedRequest(context.Background(), req, kernelcapture.DaemonProtocolPeerHandshake{})
	if resp.OK {
		t.Fatal("register_session for a cgroup_id already bound to another session should not be OK")
	}
}

// TestOnSessionEnded_ClearsSeccompState guards the E4 cleanup wiring:
// onSessionEnded must clear the session's seccomp policy and cancel (and
// forget) its seccomp listener supervisor, mirroring the existing
// RemovePolicyMaps/cgroupIndex cleanup this test's sibling
// (TestOnSessionRegisteredAndEnded) already covers for the BPF tier.
func TestOnSessionEnded_ClearsSeccompState(t *testing.T) {
	d := newTestDaemon(t)
	d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{
		SessionID:    "sec-session-001",
		RootPID:      222,
		CgroupID:     555,
		EventClasses: []string{kernelcapture.DaemonProtocolEventProcessLifecycle},
		TTLSeconds:   60,
	}, "sec-session-001")

	if err := kernelcapture.ApplySeccompPolicy(d.seccompPolicy, "sec-session-001",
		kernelcapture.DaemonApplyPolicyRequest{
			SessionID: "sec-session-001",
			OpPolicies: []kernelcapture.DaemonOpPolicy{
				{Op: kernelcapture.BpfOpNetConnect, Action: kernelcapture.BpfActionAllow, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
			},
		}); err != nil {
		t.Fatalf("ApplySeccompPolicy: %v", err)
	}

	cancelled := false
	if !d.registerSeccompListener("sec-session-001", 1, func() { cancelled = true }) {
		t.Fatal("registerSeccompListener: expected first registration to succeed")
	}

	d.onSessionEnded("sec-session-001")

	if !cancelled {
		t.Error("onSessionEnded did not cancel the session's seccomp listener")
	}
	d.mu.RLock()
	_, stillRegistered := d.seccompListeners["sec-session-001"]
	d.mu.RUnlock()
	if stillRegistered {
		t.Error("onSessionEnded left the seccomp listener registered")
	}
	decision := kernelcapture.EvaluateSeccompConnect(d.seccompPolicy, "sec-session-001", net.ParseIP("1.2.3.4"))
	if decision.HasPolicy {
		t.Errorf("onSessionEnded did not clear the session's seccomp policy: %+v", decision)
	}
}

// TestPruneExpiredSessions_ClearsSeccompState is TestPruneExpiredSessions'
// seccomp-tier counterpart.
func TestPruneExpiredSessions_ClearsSeccompState(t *testing.T) {
	d := newTestDaemon(t)

	d.mu.Lock()
	scope := kernelcapture.NewProcessTreeScope(1, 89)
	scope.SessionID = "phantom-seccomp-session"
	d.treeScopes["phantom-seccomp-session"] = &scope
	d.cgroupIndex[89] = "phantom-seccomp-session"
	d.correlators["phantom-seccomp-session"] = kernelcapture.NewCorrelator(kernelcapture.CorrelatorOptions{})
	d.mu.Unlock()

	if err := kernelcapture.ApplySeccompPolicy(d.seccompPolicy, "phantom-seccomp-session",
		kernelcapture.DaemonApplyPolicyRequest{
			SessionID: "phantom-seccomp-session",
			OpPolicies: []kernelcapture.DaemonOpPolicy{
				{Op: kernelcapture.BpfOpNetConnect, Action: kernelcapture.BpfActionDeny, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
			},
		}); err != nil {
		t.Fatalf("ApplySeccompPolicy: %v", err)
	}
	cancelled := false
	if !d.registerSeccompListener("phantom-seccomp-session", 1, func() { cancelled = true }) {
		t.Fatal("registerSeccompListener: expected first registration to succeed")
	}

	d.pruneExpiredSessions()

	if !cancelled {
		t.Error("pruneExpiredSessions did not cancel the phantom session's seccomp listener")
	}
	d.mu.RLock()
	_, stillRegistered := d.seccompListeners["phantom-seccomp-session"]
	d.mu.RUnlock()
	if stillRegistered {
		t.Error("pruneExpiredSessions left the phantom session's seccomp listener registered")
	}
	decision := kernelcapture.EvaluateSeccompConnect(d.seccompPolicy, "phantom-seccomp-session", net.ParseIP("1.2.3.4"))
	if decision.HasPolicy {
		t.Errorf("pruneExpiredSessions did not clear the phantom session's seccomp policy: %+v", decision)
	}
}

// TestRegisterSeccompListener_RejectsDuplicate guards against two
// supervisor goroutines racing to answer the same session's notifications —
// see daemon_seccomp_linux.go's handleSeccompHandoffConnection, which relies
// on this to refuse a retried/duplicate handoff.
func TestRegisterSeccompListener_RejectsDuplicate(t *testing.T) {
	d := newTestDaemon(t)
	if !d.registerSeccompListener("dup-session", 1, func() {}) {
		t.Fatal("first registerSeccompListener call: expected success")
	}
	if d.registerSeccompListener("dup-session", 2, func() {}) {
		t.Error("second registerSeccompListener call for the same session: expected rejection")
	}
}

func TestUnregisterSeccompListener_DoesNotRemoveReplacementGeneration(t *testing.T) {
	d := newTestDaemon(t)
	firstCancelled := false
	if !d.registerSeccompListener("reused-session", 1, func() { firstCancelled = true }) {
		t.Fatal("register generation 1 listener")
	}
	d.unregisterSeccompListener("reused-session", 1)
	if !firstCancelled {
		t.Fatal("generation 1 listener was not cancelled")
	}

	secondCancelled := false
	if !d.registerSeccompListener("reused-session", 2, func() { secondCancelled = true }) {
		t.Fatal("register generation 2 listener")
	}
	// Model generation 1's supervisor defer arriving after generation 2 has
	// attached. It must be a compare-and-delete no-op.
	d.unregisterSeccompListener("reused-session", 1)
	if secondCancelled {
		t.Fatal("stale generation 1 cleanup cancelled generation 2 listener")
	}
	d.mu.RLock()
	listener, ok := d.seccompListeners["reused-session"]
	d.mu.RUnlock()
	if !ok || listener.registrationGeneration != 2 {
		t.Fatalf("replacement listener = %+v, present=%t; want generation 2", listener, ok)
	}
}

func TestRegisterSessionRetiresPriorGenerationSeccompListener(t *testing.T) {
	d := newTestDaemon(t)
	oldCancelled := false
	if !d.registerSeccompListener("replacement-registration", 99, func() { oldCancelled = true }) {
		t.Fatal("register prior-generation listener")
	}
	if err := kernelcapture.ApplySeccompPolicy(d.seccompPolicy, "replacement-registration", kernelcapture.DaemonApplyPolicyRequest{
		SessionID: "replacement-registration",
		OpPolicies: []kernelcapture.DaemonOpPolicy{{
			Op: kernelcapture.BpfOpNetConnect, Action: kernelcapture.BpfActionDeny, EnforceMode: kernelcapture.BpfEnforceModeEnforce,
		}},
	}); err != nil {
		t.Fatalf("seed prior-generation seccomp policy: %v", err)
	}
	const peerStartTicks = 12345678
	handshake := kernelcapture.DaemonProtocolPeerHandshake{
		ProtocolVersion:       kernelcapture.DaemonProtocolVersion,
		Method:                kernelcapture.DaemonProtocolMethodRegisterSession,
		CredentialSource:      kernelcapture.DaemonPeerCredentialSourceLinuxSOPeerCred,
		ProcessStartTimeTicks: peerStartTicks,
		Authorization: kernelcapture.DaemonPeerAuthorization{
			Verdict:               kernelcapture.DaemonPeerAuthorizationVerdictAllow,
			UID:                   uint32(os.Getuid()),
			PID:                   uint32(os.Getpid()),
			ProcessStartTimeTicks: peerStartTicks,
		},
	}
	request := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodRegisterSession,
		RegisterSession: &kernelcapture.DaemonRegisterSessionRequest{
			SessionID:    "replacement-registration",
			RootPID:      50,
			CgroupID:     17,
			EventClasses: []string{kernelcapture.DaemonProtocolEventProcessLifecycle},
			TTLSeconds:   120,
		},
	}
	response := d.handleAuthorizedRequest(context.Background(), request, handshake)
	if !response.OK {
		t.Fatalf("replacement registration response = %+v", response)
	}
	if !oldCancelled {
		t.Fatal("accepted replacement registration did not cancel prior-generation listener")
	}
	if d.seccompListenerAttached(request.RegisterSession.SessionID) {
		t.Fatal("accepted replacement registration retained prior-generation listener")
	}
	if decision := kernelcapture.EvaluateSeccompConnect(d.seccompPolicy, request.RegisterSession.SessionID, net.ParseIP("192.0.2.10")); decision.HasPolicy {
		t.Fatalf("accepted replacement registration inherited prior-generation policy: %+v", decision)
	}
}

func TestApplyPolicyLifecycleLeasePreventsPublicationAcrossReplacement(t *testing.T) {
	d := newTestDaemon(t)
	d.activeTier = daemonTierSeccomp
	const peerStartTicks = 12345678
	handshake := kernelcapture.DaemonProtocolPeerHandshake{
		ProtocolVersion:       kernelcapture.DaemonProtocolVersion,
		Method:                kernelcapture.DaemonProtocolMethodRegisterSession,
		CredentialSource:      kernelcapture.DaemonPeerCredentialSourceLinuxSOPeerCred,
		ProcessStartTimeTicks: peerStartTicks,
		Authorization: kernelcapture.DaemonPeerAuthorization{
			Verdict:               kernelcapture.DaemonPeerAuthorizationVerdictAllow,
			UID:                   uint32(os.Getuid()),
			PID:                   uint32(os.Getpid()),
			ProcessStartTimeTicks: peerStartTicks,
		},
	}
	register := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodRegisterSession,
		RegisterSession: &kernelcapture.DaemonRegisterSessionRequest{
			SessionID:    "apply-replacement-barrier",
			RootPID:      50,
			CgroupID:     17,
			EventClasses: []string{kernelcapture.DaemonProtocolEventProcessLifecycle},
			TTLSeconds:   120,
		},
	}
	if response := d.handleAuthorizedRequest(context.Background(), register, handshake); !response.OK {
		t.Fatalf("initial register response = %+v", response)
	}
	apply := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodApplyPolicy,
		ApplyPolicy: &kernelcapture.DaemonApplyPolicyRequest{
			SessionID:   register.RegisterSession.SessionID,
			Generation:  1,
			EnforceMode: kernelcapture.BpfEnforceModeEnforce,
			OpPolicies: []kernelcapture.DaemonOpPolicy{{
				Op: kernelcapture.BpfOpNetConnect, Action: kernelcapture.BpfActionDeny, EnforceMode: kernelcapture.BpfEnforceModeEnforce,
			}},
		},
	}

	d.applyMu.Lock()
	applyDone := make(chan kernelcapture.DaemonProtocolResponse, 1)
	go func() { applyDone <- d.handleAuthorizedRequest(context.Background(), apply, handshake) }()
	deadline := time.Now().Add(5 * time.Second)
	for d.seccompSessionMu.TryLock() {
		d.seccompSessionMu.Unlock()
		if time.Now().After(deadline) {
			d.applyMu.Unlock()
			t.Fatal("apply_policy did not acquire lifecycle read lease")
		}
		runtime.Gosched()
	}
	end := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodEndSession,
		EndSession:      &kernelcapture.DaemonEndSessionRequest{SessionID: register.RegisterSession.SessionID},
	}
	endDone := make(chan kernelcapture.DaemonProtocolResponse, 1)
	go func() { endDone <- d.handleAuthorizedRequest(context.Background(), end, handshake) }()
	select {
	case response := <-endDone:
		d.applyMu.Unlock()
		t.Fatalf("end/replacement lifecycle crossed stalled apply: %+v", response)
	case <-time.After(50 * time.Millisecond):
	}
	d.applyMu.Unlock()

	if response := <-applyDone; !response.OK {
		t.Fatalf("stalled apply response = %+v", response)
	}
	if response := <-endDone; !response.OK {
		t.Fatalf("end response = %+v", response)
	}
	if decision := kernelcapture.EvaluateSeccompConnect(d.seccompPolicy, register.RegisterSession.SessionID, net.ParseIP("192.0.2.10")); decision.HasPolicy {
		t.Fatalf("ended generation retained stalled apply policy: %+v", decision)
	}
	if response := d.handleAuthorizedRequest(context.Background(), register, handshake); !response.OK {
		t.Fatalf("replacement register response = %+v", response)
	}
	if decision := kernelcapture.EvaluateSeccompConnect(d.seccompPolicy, register.RegisterSession.SessionID, net.ParseIP("192.0.2.10")); decision.HasPolicy {
		t.Fatalf("replacement registration inherited prior policy: %+v", decision)
	}
}

// TestHandleAuthorizedRequest_HealthAdvertisesActiveTier guards "advertise
// which tier is live in the daemon status" from the E4 plan.
func TestHandleAuthorizedRequest_HealthAdvertisesActiveTier(t *testing.T) {
	for _, tier := range []string{daemonTierNone, daemonTierBPFLSM, daemonTierSeccomp} {
		t.Run(tier, func(t *testing.T) {
			d := newTestDaemon(t)
			d.activeTier = tier
			req := kernelcapture.DaemonProtocolRequest{
				ProtocolVersion: kernelcapture.DaemonProtocolVersion,
				Method:          kernelcapture.DaemonProtocolMethodHealth,
				Health:          &kernelcapture.DaemonHealthRequest{},
			}
			handshake := kernelcapture.DaemonProtocolPeerHandshake{
				ProtocolVersion:       kernelcapture.DaemonProtocolVersion,
				Method:                kernelcapture.DaemonProtocolMethodHealth,
				SocketPath:            "/run/ardur/kernelcapture/control.sock",
				CredentialSource:      kernelcapture.DaemonPeerCredentialSourceLinuxSOPeerCred,
				ProcessStartTimeTicks: 1,
				Authorization: kernelcapture.DaemonPeerAuthorization{
					Verdict:               kernelcapture.DaemonPeerAuthorizationVerdictAllow,
					Reason:                "test",
					UID:                   501,
					PID:                   4242,
					ProcessStartTimeTicks: 1,
					Matched:               "uid",
				},
			}
			resp := d.handleAuthorizedRequest(context.Background(), req, handshake)
			if !resp.OK {
				t.Fatalf("health request failed: %+v", resp)
			}
			if resp.EnforcementTier != tier {
				t.Errorf("EnforcementTier = %q, want %q", resp.EnforcementTier, tier)
			}
		})
	}
}

func TestRouteEvent_CgroupMatch(t *testing.T) {
	d := newTestDaemon(t)

	d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{
		SessionID:    "route-test-001",
		RootPID:      100,
		CgroupID:     42,
		EventClasses: []string{kernelcapture.DaemonProtocolEventProcessLifecycle},
		TTLSeconds:   300,
	}, "route-test-001")

	evt := kernelcapture.ProcessEvent{
		PID:      100,
		CgroupID: 42,
		Type:     kernelcapture.ProcessEventExec,
	}
	sid, corr := d.routeEvent(&evt)
	if sid != "route-test-001" {
		t.Errorf("routeEvent cgroup match: got %q, want %q", sid, "route-test-001")
	}
	if corr == nil {
		t.Error("routeEvent: expected non-nil correlator")
	}
}

func TestRouteEvent_NoMatch(t *testing.T) {
	d := newTestDaemon(t)

	evt := kernelcapture.ProcessEvent{PID: 9999, CgroupID: 77}
	sid, corr := d.routeEvent(&evt)
	if sid != "" {
		t.Errorf("routeEvent no-match: got non-empty session %q", sid)
	}
	if corr != nil {
		t.Error("routeEvent no-match: expected nil correlator")
	}
}

func TestRouteEventFallbackIndexContainsOnlyZeroCgroupScopes(t *testing.T) {
	d := newTestDaemon(t)
	d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{
		SessionID: "registered-cgroup", RootPID: 100, CgroupID: 42,
	}, "registered-cgroup")
	d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{
		SessionID: "fallback-scope", RootPID: 200,
	}, "fallback-scope")

	d.mu.RLock()
	fallbackCount := len(d.fallbackRoutes)
	routeCount := len(d.routeIndex)
	d.mu.RUnlock()
	if fallbackCount != 1 || routeCount != 2 {
		t.Fatalf("route indexes = fallback:%d all:%d, want fallback:1 all:2", fallbackCount, routeCount)
	}

	evt := kernelcapture.ProcessEvent{PID: 200, CgroupID: 999, Type: kernelcapture.ProcessEventExec}
	if sid, correlator := d.routeEvent(&evt); sid != "fallback-scope" || correlator == nil {
		t.Fatalf("zero-cgroup fallback = (%q, %v), want (fallback-scope, non-nil)", sid, correlator)
	}
}

func TestSessionRouteRetirementWaitsForMatchedEvent(t *testing.T) {
	d := newTestDaemon(t)
	d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{
		SessionID: "retirement-session", RootPID: 100, CgroupID: 42,
	}, "retirement-session")

	evt := kernelcapture.ProcessEvent{PID: 100, CgroupID: 42, Type: kernelcapture.ProcessEventExec}
	route := d.lockRouteEvent(&evt)
	if route == nil {
		t.Fatal("lockRouteEvent returned nil for registered session")
	}
	ended := make(chan struct{})
	go func() {
		d.onSessionEnded("retirement-session")
		close(ended)
	}()

	deadline := time.Now().Add(time.Second)
	for d.mu.TryRLock() {
		d.mu.RUnlock()
		if time.Now().After(deadline) {
			route.unlock()
			t.Fatal("session retirement did not reach the route lease")
		}
		runtime.Gosched()
	}
	select {
	case <-ended:
		route.unlock()
		t.Fatal("session retirement completed while a matched route lease was held")
	default:
	}
	route.unlock()
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("session retirement did not complete after route lease release")
	}

	probe := kernelcapture.ProcessEvent{PID: 100, CgroupID: 42, Type: kernelcapture.ProcessEventExec}
	if sid, correlator := d.routeEvent(&probe); sid != "" || correlator != nil {
		t.Fatalf("retired route matched as (%q, %v)", sid, correlator)
	}
}

func TestProcessKernelEventReleasesRouteBeforeEvidenceAppendAndPreservesGenerationOrder(t *testing.T) {
	d := newTestDaemon(t)
	fsys := newBlockingEvidenceFS()
	d.fs = fsys
	const sessionID = "slow-evidence-session"
	d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{
		SessionID: sessionID, RootPID: 100, CgroupID: 42,
	}, sessionID)

	firstDone := make(chan struct{})
	go func() {
		d.processKernelEvent(kernelcapture.ProcessEvent{PID: 100, CgroupID: 42, Type: kernelcapture.ProcessEventExec})
		close(firstDone)
	}()
	select {
	case <-fsys.firstEntered:
	case <-time.After(time.Second):
		t.Fatal("first event did not reach the evidence append boundary")
	}

	var releaseOnce sync.Once
	releaseFirst := func() { releaseOnce.Do(func() { close(fsys.releaseFirst) }) }
	defer releaseFirst()

	ended := make(chan struct{})
	go func() {
		d.onSessionEnded(sessionID)
		close(ended)
	}()
	select {
	case <-ended:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("session retirement remained blocked by the in-flight evidence append")
	}

	// A replacement generation may publish while the old generation's append is
	// still blocked, but it must not overtake that already-correlated evidence.
	d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{
		SessionID: sessionID, RootPID: 200, CgroupID: 42,
	}, sessionID)
	secondDone := make(chan struct{})
	go func() {
		d.processKernelEvent(kernelcapture.ProcessEvent{PID: 200, CgroupID: 42, Type: kernelcapture.ProcessEventExec})
		close(secondDone)
	}()
	select {
	case <-fsys.secondEntered:
		t.Fatal("replacement generation overtook the prior generation's evidence append")
	case <-time.After(50 * time.Millisecond):
	}

	releaseFirst()
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first event did not finish after releasing evidence append")
	}
	select {
	case <-fsys.secondEntered:
	case <-time.After(time.Second):
		t.Fatal("replacement event did not reach evidence append after prior generation finished")
	}
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("replacement event did not finish")
	}

	path := filepath.Join(d.evidenceDir, sessionID, "kernel_receipts.jsonl")
	fsys.mu.Lock()
	data := append([]byte(nil), fsys.appends[path]...)
	fsys.mu.Unlock()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var first, second KernelReceiptEntry
	if err := decoder.Decode(&first); err != nil {
		t.Fatalf("decode first receipt: %v", err)
	}
	if err := decoder.Decode(&second); err != nil {
		t.Fatalf("decode second receipt: %v", err)
	}
	if first.Event.PID != 100 || second.Event.PID != 200 {
		t.Fatalf("receipt order = [%d, %d], want [100, 200]", first.Event.PID, second.Event.PID)
	}
}

func TestControlHandlerDrainGatesPolicyTeardown(t *testing.T) {
	t.Run("actual drain permits teardown", func(t *testing.T) {
		d := newTestDaemon(t)
		drained := make(chan struct{})
		serveDone := make(chan struct{})
		d.setControlHandlerDrain(drained, serveDone)
		close(drained)
		close(serveDone)
		if !d.waitForControlHandlerDrain() {
			t.Fatal("completed handler drain was not accepted")
		}
	})

	t.Run("server timeout rejects explicit teardown", func(t *testing.T) {
		d := newTestDaemon(t)
		drained := make(chan struct{})
		serveDone := make(chan struct{})
		d.setControlHandlerDrain(drained, serveDone)
		close(serveDone)
		if d.waitForControlHandlerDrain() {
			t.Fatal("server return without a completed handler drain permitted teardown")
		}
	})
}

func TestProcessKernelEventReleasesRouteWithNilCorrelator(t *testing.T) {
	d := newTestDaemon(t)
	scope := kernelcapture.NewProcessTreeScope(100, 42)
	scope.SessionID = "nil-correlator-session"
	route := newSessionRoute("nil-correlator-session", &scope, nil, nil)
	d.mu.Lock()
	d.cgroupIndex[42] = route.sessionID
	d.treeScopes[route.sessionID] = &scope
	d.publishSessionRouteLocked(route)
	d.mu.Unlock()

	d.processKernelEvent(kernelcapture.ProcessEvent{PID: 100, CgroupID: 42, Type: kernelcapture.ProcessEventExec})
	if !route.mu.TryLock() {
		t.Fatal("nil-correlator event leaked its route lease")
	}
	route.mu.Unlock()
}

func TestAgentRecognitionObservesUnroutedExecOnlyWhenEnabled(t *testing.T) {
	tests := []struct {
		name    string
		enable  bool
		event   kernelcapture.ProcessEvent
		wantHit bool
	}{
		{name: "disabled", event: kernelcapture.ProcessEvent{PID: 41, Type: kernelcapture.ProcessEventExec, Comm: "claude"}},
		{name: "recognized exec", enable: true, event: kernelcapture.ProcessEvent{PID: 42, Type: kernelcapture.ProcessEventExec, Comm: "claude"}, wantHit: true},
		{name: "unknown exec", enable: true, event: kernelcapture.ProcessEvent{PID: 43, Type: kernelcapture.ProcessEventExec, Comm: "python3"}},
		{name: "recognized name on exit", enable: true, event: kernelcapture.ProcessEvent{PID: 44, Type: kernelcapture.ProcessEventExit, Comm: "claude"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newTestDaemon(t)
			if tt.enable {
				if err := d.enableAgentRecognition(kernelcapture.AgentRecognizerOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			var got kernelcapture.AgentRecognitionResult
			d.agentRecognitionObserver = func(_ kernelcapture.ProcessEvent, result kernelcapture.AgentRecognitionResult) {
				got = result
			}
			d.processKernelEvent(tt.event)
			if hit := got.Status != ""; hit != tt.wantHit {
				t.Fatalf("observer hit=%t result=%+v, want %t", hit, got, tt.wantHit)
			}
			if tt.wantHit && (got.AgentType != "claude_code" || got.GovernanceAction != "observe_only") {
				t.Fatalf("unsafe or incorrect recognition result: %+v", got)
			}
		})
	}
}

func TestAgentFingerprintingObservesNativeMatchAndReportsHealth(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native executable fingerprint resolution requires Linux pidfds and procfs")
	}
	d := newTestDaemon(t)
	if err := d.enableAgentRecognition(kernelcapture.AgentRecognizerOptions{}); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	registry, err := kernelcapture.NewAgentFingerprintRegistry(kernelcapture.AgentFingerprintRegistryDocument{
		SchemaVersion:   kernelcapture.AgentFingerprintRegistrySchema,
		RegistryVersion: "test.native.v1",
		Rules: []kernelcapture.AgentFingerprintRule{{
			RuleID: "native.codex", AgentType: "codex_cli", ExpectedSHA256: []string{hex.EncodeToString(hasher.Sum(nil))},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.enableAgentFingerprinting(registry); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.disableAgentRecognition)

	observed := make(chan kernelcapture.AgentFingerprintObservation, 1)
	d.agentRecognitionMu.Lock()
	d.agentFingerprintObserver = func(_ kernelcapture.ProcessEvent, _ kernelcapture.AgentRecognitionResult, observation kernelcapture.AgentFingerprintObservation) {
		observed <- observation
	}
	d.agentRecognitionMu.Unlock()
	d.processKernelEvent(kernelcapture.ProcessEvent{
		PID: uint32(os.Getpid()), Type: kernelcapture.ProcessEventExec, Comm: "codex", ExecutableBasename: "codex",
	})
	select {
	case observation := <-observed:
		if observation.Outcome != kernelcapture.AgentFingerprintOutcomeSuccess || observation.Confidence != kernelcapture.AgentRecognitionConfidenceMedium {
			t.Fatalf("fingerprint observation = %+v", observation)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for native fingerprint observation")
	}
	// Observer publication precedes terminal accounting so an observer panic
	// cannot be recorded as a success. Wait for the worker to complete that
	// final accounting step instead of racing it after receiving the callback.
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(time.Millisecond)
	defer poll.Stop()
	for {
		response := d.handleAuthorizedRequest(context.Background(), healthReq(), validHealthHandshake())
		if !response.OK || response.AgentFingerprint == nil {
			t.Fatalf("health response = %+v", response)
		}
		switch success := response.AgentFingerprint.Counters.Success; {
		case success == 1:
			return
		case success > 1:
			t.Fatalf("health response = %+v", response)
		}
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for fingerprint success accounting; health response = %+v", response)
		case <-poll.C:
		}
	}
}

func TestEnableAgentFingerprintingRejectsInactiveAgentType(t *testing.T) {
	d := newTestDaemon(t)
	if err := d.enableAgentRecognition(kernelcapture.AgentRecognizerOptions{AllowAgentTypes: []string{"claude_code"}}); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("trusted"))
	registry, err := kernelcapture.NewAgentFingerprintRegistry(kernelcapture.AgentFingerprintRegistryDocument{
		SchemaVersion: kernelcapture.AgentFingerprintRegistrySchema, RegistryVersion: "test.native.v1",
		Rules: []kernelcapture.AgentFingerprintRule{{RuleID: "native.codex", AgentType: "codex_cli", ExpectedSHA256: []string{hex.EncodeToString(digest[:])}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.enableAgentFingerprinting(registry); err == nil {
		t.Fatal("fingerprint registry for inactive agent type was accepted")
	}
}

func TestSplitCommaSeparatedValues(t *testing.T) {
	if got, want := splitCommaSeparatedValues(" claude_code, codex_cli ,,"), []string{"claude_code", "codex_cli"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("split values = %v, want %v", got, want)
	}
}

func TestRouteEventConcurrentRoutingAndRetirement(t *testing.T) {
	d := newTestDaemon(t)
	const sessionCount = 32
	for index := 0; index < sessionCount; index++ {
		sessionID := benchmarkRouteSessionID(index)
		evt := benchmarkRouteEvent(index)
		d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{
			SessionID: sessionID, RootPID: evt.PID, CgroupID: evt.CgroupID,
		}, sessionID)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for index := 0; index < sessionCount; index++ {
		index := index
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 500 {
				evt := benchmarkRouteEvent(index)
				d.routeEvent(&evt)
			}
		}()
		if index%2 == 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				d.onSessionEnded(benchmarkRouteSessionID(index))
			}()
		}
	}
	close(start)
	wg.Wait()

	for index := 0; index < sessionCount; index++ {
		evt := benchmarkRouteEvent(index)
		sid, correlator := d.routeEvent(&evt)
		if index%2 == 0 {
			if sid != "" || correlator != nil {
				t.Fatalf("retired session %d still routed as %q", index, sid)
			}
			continue
		}
		if want := benchmarkRouteSessionID(index); sid != want || correlator == nil {
			t.Fatalf("active session %d routed as (%q, %v), want (%q, non-nil)", index, sid, correlator, want)
		}
	}
}

func TestLifecycleCaptureLossIsSessionWindowedAndNotEventAttributed(t *testing.T) {
	d := newTestDaemon(t)
	stub := newStubFS()
	d.fs = evidenceFS(stub)

	register := func(sessionID string, rootPID uint32, cgroupID uint64) {
		d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{
			SessionID: sessionID, RootPID: rootPID, CgroupID: cgroupID,
		}, sessionID)
	}
	register("session-a", 100, 10)
	register("session-b", 200, 20)

	if epoch := d.recordMalformedLifecycleRecord(); epoch != 1 {
		t.Fatalf("first loss epoch = %d, want 1", epoch)
	}
	// A valid event outside every registered scope must not erase the gap.
	d.processKernelEvent(kernelcapture.ProcessEvent{PID: 999, CgroupID: 99, Type: kernelcapture.ProcessEventExec})

	for _, sessionID := range []string{"session-a", "session-b"} {
		summary, ok := d.lifecycleCaptureSummaryForSession(sessionID)
		if !ok {
			t.Fatalf("missing lifecycle capture summary for %s", sessionID)
		}
		if summary.CoverageStatus != kernelcapture.LifecycleCaptureCoverageDegraded || summary.RingbufDropped != 1 {
			t.Fatalf("%s summary after uncorrelated event = %+v", sessionID, summary)
		}
		if summary.LossEpochStart != 1 || summary.LossEpochEnd != 1 {
			t.Fatalf("%s loss epoch = %d..%d, want 1..1", sessionID, summary.LossEpochStart, summary.LossEpochEnd)
		}
	}

	// A later correlated event is written without being arbitrarily charged the
	// host-global gap; the session-level summary remains degraded instead.
	d.processKernelEvent(kernelcapture.ProcessEvent{PID: 100, CgroupID: 10, Type: kernelcapture.ProcessEventExec})
	stub.mu.Lock()
	data := append([]byte(nil), stub.appends[filepath.Join(d.evidenceDir, "session-a", "kernel_receipts.jsonl")]...)
	stub.mu.Unlock()
	if len(data) == 0 {
		t.Fatal("correlated event did not write a kernel receipt")
	}
	var entry KernelReceiptEntry
	if err := json.Unmarshal(data[:len(data)-1], &entry); err != nil {
		t.Fatalf("decode kernel receipt: %v", err)
	}
	if entry.Receipt.CaptureLoss != (kernelcapture.CaptureLoss{}) {
		t.Fatalf("correlated receipt was arbitrarily charged global loss: %+v", entry.Receipt.CaptureLoss)
	}

	// A session registered after epoch 1 starts complete, then joins all other
	// active sessions in epoch 2.
	register("session-c", 300, 30)
	if got, _ := d.lifecycleCaptureSummaryForSession("session-c"); got.CoverageStatus != kernelcapture.LifecycleCaptureCoverageComplete || got.RingbufDropped != 0 {
		t.Fatalf("new session inherited an old capture gap: %+v", got)
	}
	d.recordLifecycleCaptureLoss(kernelcapture.CaptureLoss{RingbufDropped: 1})

	for _, tc := range []struct {
		sessionID string
		drops     uint64
		start     uint64
	}{{"session-a", 2, 1}, {"session-b", 2, 1}, {"session-c", 1, 2}} {
		got, _ := d.lifecycleCaptureSummaryForSession(tc.sessionID)
		if got.RingbufDropped != tc.drops || got.LossEpochStart != tc.start || got.LossEpochEnd != 2 {
			t.Fatalf("%s final summary = %+v", tc.sessionID, got)
		}
	}
}

type lifecycleDropSample struct {
	total uint64
	ok    bool
}

func scriptedLifecycleDropTotal(samples ...lifecycleDropSample) func() (uint64, bool) {
	i := 0
	return func() (uint64, bool) {
		sample := samples[i]
		if i < len(samples)-1 {
			i++
		}
		return sample.total, sample.ok
	}
}

func TestLifecycleProducerDropCounterBaselinesAndRebaselines(t *testing.T) {
	d := newTestDaemon(t)
	for _, sessionID := range []string{"session-a", "session-b"} {
		d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{SessionID: sessionID}, sessionID)
	}
	d.setLifecycleDropCounter(scriptedLifecycleDropTotal(
		lifecycleDropSample{total: 5, ok: true},
		lifecycleDropSample{total: 5, ok: true},
		lifecycleDropSample{total: 8, ok: true},
		lifecycleDropSample{total: 4, ok: true},
		lifecycleDropSample{total: 9, ok: true},
	))
	if got := d.sampleLifecycleProducerLoss(); got != 0 {
		t.Fatalf("unchanged inherited baseline delta = %d, want 0", got)
	}
	if got := d.sampleLifecycleProducerLoss(); got != 3 {
		t.Fatalf("first producer delta = %d, want 3", got)
	}
	if got := d.sampleLifecycleProducerLoss(); got != 0 {
		t.Fatalf("backwards counter delta = %d, want 0", got)
	}
	if got := d.sampleLifecycleProducerLoss(); got != 5 {
		t.Fatalf("post-reset producer delta = %d, want 5", got)
	}
	for _, sessionID := range []string{"session-a", "session-b"} {
		summary, _ := d.lifecycleCaptureSummaryForSession(sessionID)
		if summary.RingbufDropped != 8 || summary.LossEpochStart != 1 || summary.LossEpochEnd != 2 {
			t.Fatalf("%s producer summary = %+v", sessionID, summary)
		}
		if summary.ProducerRingbufDropped != 8 || summary.MalformedRecords != 0 {
			t.Fatalf("%s producer source counters = %+v", sessionID, summary)
		}
		if !summary.ProducerCounterEvidenceGap {
			t.Fatalf("%s backwards counter did not leave evidence gap: %+v", sessionID, summary)
		}
	}
}

func TestLifecycleProducerDropCounterWaitsForFirstAvailableBaseline(t *testing.T) {
	d := newTestDaemon(t)
	d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{SessionID: "session-a"}, "session-a")
	d.setLifecycleDropCounter(scriptedLifecycleDropTotal(
		lifecycleDropSample{ok: false},
		lifecycleDropSample{total: 7, ok: true},
		lifecycleDropSample{total: 9, ok: true},
	))
	d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{SessionID: "session-b"}, "session-b")
	if got := d.sampleLifecycleProducerLoss(); got != 0 {
		t.Fatalf("first available total was replayed as delta %d", got)
	}
	if got := d.sampleLifecycleProducerLoss(); got != 2 {
		t.Fatalf("delta after delayed baseline = %d, want 2", got)
	}
	for _, sessionID := range []string{"session-a", "session-b"} {
		summary, _ := d.lifecycleCaptureSummaryForSession(sessionID)
		if summary.RingbufDropped != 2 {
			t.Fatalf("%s producer summary = %+v", sessionID, summary)
		}
		if summary.ProducerRingbufDropped != 2 || summary.MalformedRecords != 0 {
			t.Fatalf("%s producer source counters = %+v", sessionID, summary)
		}
		if !summary.ProducerCounterEvidenceGap {
			t.Fatalf("%s initial counter unavailability did not leave evidence gap: %+v", sessionID, summary)
		}
	}
}

func TestLifecycleProducerDropCounterRemovalMarksActiveSessions(t *testing.T) {
	d := newTestDaemon(t)
	d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{SessionID: "session-a"}, "session-a")
	d.setLifecycleDropCounter(scriptedLifecycleDropTotal(lifecycleDropSample{total: 4, ok: true}))
	d.setLifecycleDropCounter(nil)
	d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{SessionID: "session-b"}, "session-b")

	for _, sessionID := range []string{"session-a", "session-b"} {
		summary, _ := d.lifecycleCaptureSummaryForSession(sessionID)
		if !summary.ProducerCounterEvidenceGap || summary.CoverageStatus != kernelcapture.LifecycleCaptureCoverageDegraded {
			t.Fatalf("%s removed producer counter did not leave evidence gap: %+v", sessionID, summary)
		}
	}
}

func TestLifecycleCaptureSummaryIsExposedUntilSessionEnd(t *testing.T) {
	d := newTestDaemon(t)
	d.setLifecycleDropCounter(scriptedLifecycleDropTotal(
		lifecycleDropSample{total: 0, ok: true},
		lifecycleDropSample{total: 0, ok: true},
		lifecycleDropSample{total: 0, ok: true},
		lifecycleDropSample{total: 2, ok: true},
		lifecycleDropSample{total: 3, ok: true},
	))
	const startTicks uint64 = 987654
	handshake := kernelcapture.DaemonProtocolPeerHandshake{
		ProtocolVersion:       kernelcapture.DaemonProtocolVersion,
		CredentialSource:      kernelcapture.DaemonPeerCredentialSourceLinuxSOPeerCred,
		ProcessStartTimeTicks: startTicks,
		Authorization: kernelcapture.DaemonPeerAuthorization{
			Verdict:               kernelcapture.DaemonPeerAuthorizationVerdictAllow,
			UID:                   uint32(os.Getuid()),
			PID:                   uint32(os.Getpid()),
			ProcessStartTimeTicks: startTicks,
		},
	}

	register := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodRegisterSession,
		RegisterSession: &kernelcapture.DaemonRegisterSessionRequest{
			SessionID:    "capture-status-session",
			RootPID:      123,
			CgroupID:     456,
			EventClasses: []string{kernelcapture.DaemonProtocolEventProcessLifecycle},
			TTLSeconds:   60,
		},
	}
	handshake.Method = register.Method
	if resp := d.handleAuthorizedRequest(context.Background(), register, handshake); !resp.OK {
		t.Fatalf("register_session failed: %+v", resp)
	}
	d.recordMalformedLifecycleRecord()

	status := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodSessionStatus,
		SessionStatus:   &kernelcapture.DaemonSessionStatusRequest{SessionID: "capture-status-session"},
	}
	handshake.Method = status.Method
	statusResp := d.handleAuthorizedRequest(context.Background(), status, handshake)
	if !statusResp.OK || statusResp.LifecycleCapture == nil {
		t.Fatalf("session_status lifecycle capture = %+v", statusResp)
	}
	if got := statusResp.LifecycleCapture; got.CoverageStatus != kernelcapture.LifecycleCaptureCoverageDegraded || got.RingbufDropped != 3 {
		t.Fatalf("session_status lifecycle capture = %+v", got)
	}
	if got := statusResp.LifecycleCapture; got.ProducerRingbufDropped != 2 || got.MalformedRecords != 1 {
		t.Fatalf("session_status lifecycle source counters = %+v", got)
	}

	end := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodEndSession,
		EndSession:      &kernelcapture.DaemonEndSessionRequest{SessionID: "capture-status-session"},
	}
	handshake.Method = end.Method
	endResp := d.handleAuthorizedRequest(context.Background(), end, handshake)
	if !endResp.OK || endResp.LifecycleCapture == nil || endResp.LifecycleCapture.RingbufDropped != 4 {
		t.Fatalf("end_session lifecycle capture = %+v", endResp)
	}
	if _, ok := d.lifecycleCaptureSummaryForSession("capture-status-session"); ok {
		t.Fatal("ended session retained lifecycle capture state")
	}
}

// TestRouteEvent_SlowPathPIDTreeMatch exercises the slow-path PID-tree scan.
// The session is registered with CgroupID=0 (no cgroup guard) so it does not
// appear in cgroupIndex. The event carries CgroupID=99 which misses the fast
// path (cgroupIndex[99] is empty), falling through to the PID-tree scan where
// PID=100 matches the root PID.
func TestRouteEvent_SlowPathPIDTreeMatch(t *testing.T) {
	d := newTestDaemon(t)

	d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{
		SessionID:    "slow-path-test",
		RootPID:      100,
		CgroupID:     0,
		EventClasses: []string{kernelcapture.DaemonProtocolEventProcessLifecycle},
		TTLSeconds:   300,
	}, "slow-path-test")

	// CgroupID=99: fast path checks cgroupIndex[99], finds nothing, falls through.
	// scope.CgroupID=0 disables the cgroup guard inside MatchesAndTrack.
	// PID=100 matches the registered root PID.
	evt := kernelcapture.ProcessEvent{
		PID:      100,
		CgroupID: 99,
		Type:     kernelcapture.ProcessEventExec,
	}
	sid, corr := d.routeEvent(&evt)
	if sid != "slow-path-test" {
		t.Errorf("routeEvent slow-path PID-tree match: got %q, want %q", sid, "slow-path-test")
	}
	if corr == nil {
		t.Error("routeEvent slow-path: expected non-nil correlator")
	}
}

func TestAppendKernelReceipt(t *testing.T) {
	d := newTestDaemon(t)
	stub := newStubFS()
	d.fs = evidenceFS(stub)

	sessionID := "evidence-test-001"
	evt := kernelcapture.ProcessEvent{PID: 200, CgroupID: 55, Type: kernelcapture.ProcessEventExec}
	receipt := kernelcapture.SyntheticKernelReceipt{
		EventID:               "evt-001",
		EventClass:            "process_exec",
		CoverageStatus:        "not_claimed",
		CorrelationMethod:     "cgroup_time_window",
		CorrelationConfidence: "medium",
		Verdict:               "not_claimed",
	}

	d.appendKernelReceipt(sessionID, evt, receipt)

	stub.mu.Lock()
	data := stub.appends[filepath.Join(d.evidenceDir, sanitizeSessionID(sessionID), "kernel_receipts.jsonl")]
	stub.mu.Unlock()

	if len(data) == 0 {
		t.Fatal("appendKernelReceipt: no data written")
	}

	var entry KernelReceiptEntry
	if err := json.Unmarshal(data[:len(data)-1], &entry); err != nil {
		t.Fatalf("unmarshal receipt entry: %v\n%s", err, data)
	}
	if entry.SessionID != sessionID {
		t.Errorf("receipt entry session_id: got %q, want %q", entry.SessionID, sessionID)
	}
	if entry.SchemaVersion != KernelReceiptSchema {
		t.Errorf("receipt entry schema_version: got %q, want %q", entry.SchemaVersion, KernelReceiptSchema)
	}
}

func TestAppendKernelReceiptRejectsSymlinkSessionDirBeforeAppend(t *testing.T) {
	d := newTestDaemon(t)
	d.evidenceDir = filepath.Join(t.TempDir(), "evidence")

	sessionID := "symlink-session-dir"
	sessionDir := filepath.Join(d.evidenceDir, sanitizeSessionID(sessionID))
	escapeDir := filepath.Join(t.TempDir(), "escape")
	if err := os.MkdirAll(d.evidenceDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(evidenceDir): %v", err)
	}
	if err := os.MkdirAll(escapeDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(escapeDir): %v", err)
	}
	if err := os.Symlink(escapeDir, sessionDir); err != nil {
		t.Fatalf("Symlink(sessionDir): %v", err)
	}

	evt, receipt := kernelReceiptFixture()
	d.appendKernelReceipt(sessionID, evt, receipt)

	info, err := os.Lstat(sessionDir)
	if err != nil {
		t.Fatalf("Lstat(sessionDir): %v", err)
	}
	if info.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("session dir should remain a symlink, mode=%v", info.Mode())
	}
	if _, err := os.Stat(filepath.Join(escapeDir, "kernel_receipts.jsonl")); err == nil || !os.IsNotExist(err) {
		t.Fatalf("symlink target was modified or unexpected stat error: %v", err)
	}
}

func TestAppendKernelReceiptRejectsSymlinkReceiptFileBeforeAppend(t *testing.T) {
	d := newTestDaemon(t)
	d.evidenceDir = filepath.Join(t.TempDir(), "evidence")

	sessionID := "symlink-receipt-file"
	sessionDir := filepath.Join(d.evidenceDir, sanitizeSessionID(sessionID))
	receiptPath := filepath.Join(sessionDir, "kernel_receipts.jsonl")
	escapePath := filepath.Join(t.TempDir(), "escape.jsonl")
	original := []byte("preexisting\n")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(sessionDir): %v", err)
	}
	if err := os.WriteFile(escapePath, original, 0o600); err != nil {
		t.Fatalf("WriteFile(escapePath): %v", err)
	}
	if err := os.Symlink(escapePath, receiptPath); err != nil {
		t.Fatalf("Symlink(receiptPath): %v", err)
	}

	evt, receipt := kernelReceiptFixture()
	d.appendKernelReceipt(sessionID, evt, receipt)

	info, err := os.Lstat(receiptPath)
	if err != nil {
		t.Fatalf("Lstat(receiptPath): %v", err)
	}
	if info.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("receipt path should remain a symlink, mode=%v", info.Mode())
	}
	data, err := os.ReadFile(escapePath)
	if err != nil {
		t.Fatalf("ReadFile(escapePath): %v", err)
	}
	if string(data) != string(original) {
		t.Fatalf("symlink target was modified: got %q want %q", data, original)
	}
}

func TestAppendKernelReceiptRejectsNonDirectorySessionPathBeforeAppend(t *testing.T) {
	d := newTestDaemon(t)
	d.evidenceDir = filepath.Join(t.TempDir(), "evidence")

	sessionID := "non-directory-session"
	sessionPath := filepath.Join(d.evidenceDir, sanitizeSessionID(sessionID))
	original := []byte("not a directory")
	if err := os.MkdirAll(d.evidenceDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(evidenceDir): %v", err)
	}
	if err := os.WriteFile(sessionPath, original, 0o600); err != nil {
		t.Fatalf("WriteFile(sessionPath): %v", err)
	}

	evt, receipt := kernelReceiptFixture()
	d.appendKernelReceipt(sessionID, evt, receipt)

	data, err := os.ReadFile(sessionPath)
	if err != nil {
		t.Fatalf("ReadFile(sessionPath): %v", err)
	}
	if string(data) != string(original) {
		t.Fatalf("non-directory parent was modified: got %q want %q", data, original)
	}
	if _, err := os.Lstat(filepath.Join(sessionPath, "kernel_receipts.jsonl")); err == nil {
		t.Fatal("receipt path unexpectedly exists under non-directory parent")
	}
}

func kernelReceiptFixture() (kernelcapture.ProcessEvent, kernelcapture.SyntheticKernelReceipt) {
	return kernelcapture.ProcessEvent{PID: 200, CgroupID: 55, Type: kernelcapture.ProcessEventExec}, kernelcapture.SyntheticKernelReceipt{
		EventID:               "evt-001",
		EventClass:            "process_exec",
		CoverageStatus:        "not_claimed",
		CorrelationMethod:     "cgroup_time_window",
		CorrelationConfidence: "medium",
		Verdict:               "not_claimed",
	}
}

func TestHandleAuthorizedRequest_RegisterUpdatesIndex(t *testing.T) {
	d := newTestDaemon(t)
	filter := newFakeLifecycleCgroupFilter()
	d.lifecycleFilter = newLifecycleFilterManager()
	if err := d.lifecycleFilter.install(filter); err != nil {
		t.Fatalf("install lifecycle filter: %v", err)
	}

	const fakeStartTicks uint64 = 12345678
	handshake := kernelcapture.DaemonProtocolPeerHandshake{
		ProtocolVersion:       kernelcapture.DaemonProtocolVersion,
		Method:                kernelcapture.DaemonProtocolMethodRegisterSession,
		CredentialSource:      kernelcapture.DaemonPeerCredentialSourceLinuxSOPeerCred,
		ProcessStartTimeTicks: fakeStartTicks,
		Authorization: kernelcapture.DaemonPeerAuthorization{
			Verdict:               kernelcapture.DaemonPeerAuthorizationVerdictAllow,
			UID:                   uint32(os.Getuid()),
			PID:                   uint32(os.Getpid()),
			ProcessStartTimeTicks: fakeStartTicks,
		},
	}
	req := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodRegisterSession,
		RegisterSession: &kernelcapture.DaemonRegisterSessionRequest{
			SessionID:    "dispatch-test-001",
			RootPID:      50,
			CgroupID:     17,
			EventClasses: []string{kernelcapture.DaemonProtocolEventProcessLifecycle},
			TTLSeconds:   120,
		},
	}

	resp := d.handleAuthorizedRequest(context.Background(), req, handshake)
	if !resp.OK {
		t.Fatalf("handleAuthorizedRequest: not OK: %s", resp.Error)
	}

	d.mu.RLock()
	_, hasIndex := d.cgroupIndex[17]
	d.mu.RUnlock()

	if !hasIndex {
		t.Error("cgroup index not populated after handleAuthorizedRequest register_session")
	}
	if _, ok := filter.allowed[17]; !ok {
		t.Fatal("register_session returned success before allowing its lifecycle cgroup")
	}

	duplicate := d.handleAuthorizedRequest(context.Background(), req, handshake)
	if duplicate.OK {
		t.Fatal("duplicate active registration unexpectedly succeeded")
	}
	if _, ok := filter.allowed[17]; !ok {
		t.Fatal("rejected duplicate registration removed the active session's lifecycle cgroup")
	}

	d.onSessionEnded(req.RegisterSession.SessionID)
	if _, ok := filter.allowed[17]; ok {
		t.Fatal("session teardown left its lifecycle cgroup allowed")
	}
}

func TestPruneExpiredSessions(t *testing.T) {
	d := newTestDaemon(t)
	filter := newFakeLifecycleCgroupFilter()
	d.lifecycleFilter = newLifecycleFilterManager()
	if err := d.lifecycleFilter.install(filter); err != nil {
		t.Fatalf("install lifecycle filter: %v", err)
	}
	if added, err := d.lifecycleFilter.prepare(context.Background(), "phantom-session", 88); err != nil || !added {
		t.Fatalf("prepare phantom lifecycle cgroup added=%t err=%v", added, err)
	}

	// Insert a session directly into the routing index without going through
	// the registry, so we can test pruning of an unknown session.
	d.mu.Lock()
	scope := kernelcapture.NewProcessTreeScope(1, 88)
	scope.SessionID = "phantom-session"
	d.treeScopes["phantom-session"] = &scope
	d.cgroupIndex[88] = "phantom-session"
	d.correlators["phantom-session"] = kernelcapture.NewCorrelator(kernelcapture.CorrelatorOptions{})
	d.lifecycleCaptureSummaries["phantom-session"] = kernelcapture.NewLifecycleCaptureSummaryAccumulator()
	d.mu.Unlock()

	// pruneExpiredSessions should remove the phantom session because the
	// registry has no record of it (ActiveSession returns an error).
	d.pruneExpiredSessions()

	d.mu.RLock()
	_, stillInCgroup := d.cgroupIndex[88]
	_, stillInTree := d.treeScopes["phantom-session"]
	_, stillInCapture := d.lifecycleCaptureSummaries["phantom-session"]
	d.mu.RUnlock()

	if stillInCgroup {
		t.Error("phantom session cgroup entry not pruned")
	}
	if stillInTree {
		t.Error("phantom session tree scope not pruned")
	}
	if stillInCapture {
		t.Error("phantom session lifecycle capture summary not pruned")
	}
	if _, ok := filter.allowed[88]; ok {
		t.Fatal("expired session left its lifecycle cgroup allowed")
	}
}

func TestOsEvidenceFS_AppendFile(t *testing.T) {
	dir := t.TempDir()
	fsys := osEvidenceFS{}
	path := filepath.Join(dir, "receipts.jsonl")

	if err := fsys.AppendFile(path, []byte("line1\n"), 0o600); err != nil {
		t.Fatalf("first append: %v", err)
	}
	if err := fsys.AppendFile(path, []byte("line2\n"), 0o600); err != nil {
		t.Fatalf("second append: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(data) != "line1\nline2\n" {
		t.Errorf("file contents: got %q, want %q", data, "line1\nline2\n")
	}
}

// TestOsEvidenceFS_AppendFileRejectsTrailingSymlink verifies that the OS-level
// OpenFile call rejects a trailing symlink via O_NOFOLLOW. This is a
// defense-in-depth regression test: prevalidation (Lstat) already rejects
// symlinks, but O_NOFOLLOW closes the Lstat→OpenFile TOCTOU window at the
// kernel level. Without O_NOFOLLOW, AppendFile would follow the symlink and
// write to the target.
func TestOsEvidenceFS_AppendFileRejectsTrailingSymlink(t *testing.T) {
	dir := t.TempDir()
	fsys := osEvidenceFS{}
	target := filepath.Join(dir, "target.jsonl")
	linkPath := filepath.Join(dir, "link.jsonl")

	if err := os.WriteFile(target, []byte("original\n"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	err := fsys.AppendFile(linkPath, []byte("injected\n"), 0o600)
	if err == nil {
		t.Fatal("AppendFile via trailing symlink should fail with O_NOFOLLOW")
	}

	// The symlink target must not be modified.
	data, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("read target: %v", readErr)
	}
	if string(data) != "original\n" {
		t.Fatalf("symlink target was modified: got %q want %q", data, "original\n")
	}
}
