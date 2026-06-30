package main

import (
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
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
		log:         testLogger(t),
		registry:    kernelcapture.NewDaemonSessionRegistry(),
		evidenceDir: filepath.Join(tmpDir, "evidence"),
		cgroupIndex: make(map[uint64]string),
		treeScopes:  make(map[string]*kernelcapture.ProcessTreeScope),
		correlators: make(map[string]*kernelcapture.Correlator),
		fs:          osEvidenceFS{},
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
