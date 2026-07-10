package main

import (
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

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

// newTestDaemon returns a daemon wired with an in-memory (stub) filesystem.
// It bypasses BuildDaemonCustodyPlan path validation so tests can run without
// privileged filesystem access.
func newTestDaemon(t *testing.T) *daemon {
	t.Helper()
	tmpDir := t.TempDir()
	return &daemon{
		log:                       testLogger(t),
		registry:                  kernelcapture.NewDaemonSessionRegistry(),
		evidenceDir:               filepath.Join(tmpDir, "evidence"),
		cgroupIndex:               make(map[uint64]string),
		treeScopes:                make(map[string]*kernelcapture.ProcessTreeScope),
		correlators:               make(map[string]*kernelcapture.Correlator),
		enforceChains:             make(map[string]*kernelcapture.EnforceReceiptChain),
		enforceSummaries:          make(map[string]*kernelcapture.EnforceEventSummaryAccumulator),
		enforceOrphanChain:        kernelcapture.NewEnforceReceiptChain(),
		enforceOrphanSummary:      kernelcapture.NewEnforceEventSummaryAccumulator(),
		lifecycleCaptureSummaries: make(map[string]*kernelcapture.LifecycleCaptureSummaryAccumulator),
		fs:                        osEvidenceFS{},
		tamperChain:               kernelcapture.NewTamperReceiptChain(),
		seccompPolicy:             kernelcapture.NewSeccompPolicyStore(),
		seccompListeners:          make(map[string]context.CancelFunc),
		activeTier:                daemonTierNone,
		appliedAllow:              make(map[string]*appliedAllowRecord),
		// No-op cgroup verifier: daemon-flow tests register synthetic PIDs that
		// aren't real /proc descendants. The real check is covered directly by
		// daemon_cgroup_verify_linux_test.go.
		cgroupVerifier: func(kernelcapture.DaemonProtocolPeerHandshake, *kernelcapture.DaemonRegisterSessionRequest, *slog.Logger) error {
			return nil
		},
	}
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
	if !d.registerSeccompListener("sec-session-001", func() { cancelled = true }) {
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
	if !d.registerSeccompListener("phantom-seccomp-session", func() { cancelled = true }) {
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
	if !d.registerSeccompListener("dup-session", func() {}) {
		t.Fatal("first registerSeccompListener call: expected success")
	}
	if d.registerSeccompListener("dup-session", func() {}) {
		t.Error("second registerSeccompListener call for the same session: expected rejection")
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

func TestLifecycleCaptureSummaryIsExposedUntilSessionEnd(t *testing.T) {
	d := newTestDaemon(t)
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
	if got := statusResp.LifecycleCapture; got.CoverageStatus != kernelcapture.LifecycleCaptureCoverageDegraded || got.RingbufDropped != 1 {
		t.Fatalf("session_status lifecycle capture = %+v", got)
	}

	end := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodEndSession,
		EndSession:      &kernelcapture.DaemonEndSessionRequest{SessionID: "capture-status-session"},
	}
	handshake.Method = end.Method
	endResp := d.handleAuthorizedRequest(context.Background(), end, handshake)
	if !endResp.OK || endResp.LifecycleCapture == nil || endResp.LifecycleCapture.RingbufDropped != 1 {
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
}

func TestPruneExpiredSessions(t *testing.T) {
	d := newTestDaemon(t)

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
