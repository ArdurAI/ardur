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
		log:                  testLogger(t),
		registry:             kernelcapture.NewDaemonSessionRegistry(),
		evidenceDir:          filepath.Join(tmpDir, "evidence"),
		cgroupIndex:          make(map[uint64]string),
		treeScopes:           make(map[string]*kernelcapture.ProcessTreeScope),
		correlators:          make(map[string]*kernelcapture.Correlator),
		enforceChains:        make(map[string]*kernelcapture.EnforceReceiptChain),
		enforceSummaries:     make(map[string]*kernelcapture.EnforceEventSummaryAccumulator),
		enforceOrphanChain:   kernelcapture.NewEnforceReceiptChain(),
		enforceOrphanSummary: kernelcapture.NewEnforceEventSummaryAccumulator(),
		fs:                   osEvidenceFS{},
		tamperChain:          kernelcapture.NewTamperReceiptChain(),
		seccompPolicy:        kernelcapture.NewSeccompPolicyStore(),
		seccompListeners:     make(map[string]context.CancelFunc),
		activeTier:           daemonTierNone,
		appliedAllow:         make(map[string]*appliedAllowRecord),
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
	d.mu.Unlock()

	// pruneExpiredSessions should remove the phantom session because the
	// registry has no record of it (ActiveSession returns an error).
	d.pruneExpiredSessions()

	d.mu.RLock()
	_, stillInCgroup := d.cgroupIndex[88]
	_, stillInTree := d.treeScopes["phantom-session"]
	d.mu.RUnlock()

	if stillInCgroup {
		t.Error("phantom session cgroup entry not pruned")
	}
	if stillInTree {
		t.Error("phantom session tree scope not pruned")
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
