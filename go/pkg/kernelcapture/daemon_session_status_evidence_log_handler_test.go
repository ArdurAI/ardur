package kernelcapture

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDaemonSessionStatusEvidenceLogHandlerAppendsSuccessfulStatusSnapshots(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 5, 20, 0, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	custody := daemonCustodyPlanForEvidenceLogHandlerTest(t)
	sink := NewDaemonSessionStatusSnapshotSink()
	sessionID := "handler-evidence-session"
	mapped := newMappedEvidenceLogFilesystemForTest(t, evidenceLogPathForHandlerTest(custody, sessionID))
	handler := NewDaemonSessionStatusEvidenceLogHandler(DaemonSessionStatusEvidenceLogHandlerConfig{
		Registry:     registry,
		CustodyPlan:  custody,
		SnapshotSink: sink,
		Filesystem:   mapped,
	})
	handshake := daemonSessionRegistryTestHandshake(sessionID)

	register := daemonRegisterSessionRequest(sessionID, 5151, 60)
	register.RegisterSession.CgroupID = 515100
	register.RegisterSession.MissionID = "mission-handler-evidence"
	if response := handler.HandleAuthorizedRequest(context.Background(), register, handshake); !response.OK {
		t.Fatalf("register response = %#v", response)
	}
	if len(sink.Snapshots()) != 0 || len(mapped.operations()) != 0 {
		t.Fatalf("register should not retain snapshots or touch filesystem: sink=%#v ops=%#v", sink.Snapshots(), mapped.operations())
	}

	first := handler.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest(sessionID), handshake)
	if !first.OK || first.Method != DaemonProtocolMethodSessionStatus || first.Status != DaemonSessionStatusActive {
		t.Fatalf("first status response = %#v", first)
	}
	assertProtocolResponseDoesNotExposeEvidenceLogInternals(t, first)
	if got := sink.Snapshots(); len(got) != 1 || got[0].Session.SessionID != sessionID {
		t.Fatalf("sink snapshots after first status = %#v", got)
	}
	content := string(mapped.readLogicalFile(t, evidenceLogPathForHandlerTest(custody, sessionID)))
	if strings.Count(content, "\n") != 1 {
		t.Fatalf("evidence log line count after first status = %d, content=%q", strings.Count(content, "\n"), content)
	}
	stateSnapshot, ok := handler.EvidenceLogStateSnapshot(sessionID)
	if !ok || stateSnapshot.EntryCount != 1 || stateSnapshot.TotalBytes <= 0 {
		t.Fatalf("state snapshot after first status = %#v ok=%v", stateSnapshot, ok)
	}

	now = now.Add(5 * time.Second)
	second := handler.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest(sessionID), handshake)
	if !second.OK || second.Status != DaemonSessionStatusActive {
		t.Fatalf("second status response = %#v", second)
	}
	assertProtocolResponseDoesNotExposeEvidenceLogInternals(t, second)
	if got := sink.Snapshots(); len(got) != 2 {
		t.Fatalf("sink snapshot count after second status = %d", len(got))
	}
	content = string(mapped.readLogicalFile(t, evidenceLogPathForHandlerTest(custody, sessionID)))
	if strings.Count(content, "\n") != 2 {
		t.Fatalf("evidence log line count after second status = %d, content=%q", strings.Count(content, "\n"), content)
	}
	stateSnapshot, ok = handler.EvidenceLogStateSnapshot(sessionID)
	if !ok || stateSnapshot.EntryCount != 2 || stateSnapshot.TotalBytes <= 0 {
		t.Fatalf("state snapshot after second status = %#v ok=%v", stateSnapshot, ok)
	}
	if !mapped.sawOp("mkdirall", filepath.Dir(evidenceLogPathForHandlerTest(custody, sessionID))) || !mapped.sawOp("append", evidenceLogPathForHandlerTest(custody, sessionID)) {
		t.Fatalf("expected mkdirall+append operations, got %#v", mapped.operations())
	}
}

func TestDaemonSessionStatusEvidenceLogHandlerRejectsStatusFromDifferentPeerWithoutEvidenceSideEffects(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 5, 20, 15, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	custody := daemonCustodyPlanForEvidenceLogHandlerTest(t)
	sink := NewDaemonSessionStatusSnapshotSink()
	sessionID := "handler-evidence-owned-session"
	mapped := newMappedEvidenceLogFilesystemForTest(t, evidenceLogPathForHandlerTest(custody, sessionID))
	handler := NewDaemonSessionStatusEvidenceLogHandler(DaemonSessionStatusEvidenceLogHandlerConfig{
		Registry:     registry,
		CustodyPlan:  custody,
		SnapshotSink: sink,
		Filesystem:   mapped,
	})
	owner := daemonSessionRegistryTestHandshake(sessionID)

	register := daemonRegisterSessionRequest(sessionID, 5151, 60)
	register.RegisterSession.CgroupID = 515100
	if response := handler.HandleAuthorizedRequest(context.Background(), register, owner); !response.OK {
		t.Fatalf("register response = %#v", response)
	}

	other := owner
	other.Authorization.UID = 502
	other.Authorization.GID = 21
	other.Authorization.PID = 9876
	other.Authorization.Reason = "different authorized peer"
	rejected := handler.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest(sessionID), other)
	if rejected.OK || rejected.Status != DaemonSessionStatusActive || !strings.Contains(rejected.Error, "different peer") {
		t.Fatalf("different peer status response = %#v", rejected)
	}
	assertProtocolResponseDoesNotExposeEvidenceLogInternals(t, rejected)
	if got := sink.Snapshots(); len(got) != 0 {
		t.Fatalf("different peer retained snapshot: %#v", got)
	}
	if got := mapped.operations(); len(got) != 0 {
		t.Fatalf("different peer touched evidence filesystem: %#v", got)
	}
	if _, ok := handler.EvidenceLogStateSnapshot(sessionID); ok {
		t.Fatalf("different peer stored append state")
	}

	ownerStatus := handler.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest(sessionID), owner)
	if !ownerStatus.OK || ownerStatus.Status != DaemonSessionStatusActive {
		t.Fatalf("owner status response = %#v", ownerStatus)
	}
}

func TestDaemonSessionStatusEvidenceLogHandlerRotatesThroughInjectedFilesystem(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 5, 20, 30, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	custody := daemonCustodyPlanForEvidenceLogHandlerTest(t)
	sink := NewDaemonSessionStatusSnapshotSink()
	sessionID := "handler-evidence-rotate-session"
	mapped := newMappedEvidenceLogFilesystemForTest(t, evidenceLogPathForHandlerTest(custody, sessionID))
	handler := NewDaemonSessionStatusEvidenceLogHandler(DaemonSessionStatusEvidenceLogHandlerConfig{
		Registry:     registry,
		CustodyPlan:  custody,
		SnapshotSink: sink,
		Filesystem:   mapped,
		EvidenceLogConfig: DaemonSessionStatusEvidenceLogConfig{
			MaxEntryBytes:   8192,
			MaxLogBytes:     8192,
			MaxRotatedFiles: 3,
		},
	})
	handshake := daemonSessionRegistryTestHandshake(sessionID)
	register := daemonRegisterSessionRequest(sessionID, 6161, 60)
	register.RegisterSession.CgroupID = 616100
	if response := handler.HandleAuthorizedRequest(context.Background(), register, handshake); !response.OK {
		t.Fatalf("register response = %#v", response)
	}

	first := handler.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest(sessionID), handshake)
	if !first.OK {
		t.Fatalf("first status response = %#v", first)
	}
	now = now.Add(5 * time.Second)
	second := handler.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest(sessionID), handshake)
	if !second.OK {
		t.Fatalf("second status response = %#v", second)
	}

	stateSnapshot, ok := handler.EvidenceLogStateSnapshot(sessionID)
	if !ok || stateSnapshot.RotationCount != 1 || stateSnapshot.EntryCount != 1 {
		t.Fatalf("state snapshot after rotation = %#v ok=%v", stateSnapshot, ok)
	}
	basePath := evidenceLogPathForHandlerTest(custody, sessionID)
	rotationPath := basePath + ".000001"
	if strings.Count(string(mapped.readLogicalFile(t, rotationPath)), "\n") != 1 {
		t.Fatalf("rotated log did not contain first entry")
	}
	if strings.Count(string(mapped.readLogicalFile(t, basePath)), "\n") != 1 {
		t.Fatalf("fresh log did not contain second entry")
	}
	if !mapped.sawOp("rename", basePath+"->"+rotationPath) {
		t.Fatalf("expected rotation rename, got %#v", mapped.operations())
	}
}

func TestDaemonSessionStatusEvidenceLogHandlerFailsClosedWithoutEvidenceSideEffects(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		mutate     func(*DaemonSessionStatusEvidenceLogHandlerConfig, *mappedEvidenceLogFilesystemForTest)
		want       string
		wantNoFile bool
	}{
		{name: "nil sink", mutate: func(cfg *DaemonSessionStatusEvidenceLogHandlerConfig, _ *mappedEvidenceLogFilesystemForTest) {
			cfg.SnapshotSink = nil
		}, want: "snapshot sink", wantNoFile: true},
		{name: "nil filesystem", mutate: func(cfg *DaemonSessionStatusEvidenceLogHandlerConfig, _ *mappedEvidenceLogFilesystemForTest) {
			cfg.Filesystem = nil
		}, want: "filesystem", wantNoFile: true},
		{name: "append failure", mutate: func(_ *DaemonSessionStatusEvidenceLogHandlerConfig, mapped *mappedEvidenceLogFilesystemForTest) {
			mapped.failAppend = errEvidenceLogHandlerTestAppendFailure{}
		}, want: "evidence-log append", wantNoFile: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			now := time.Date(2026, 6, 5, 21, 0, 0, 0, time.UTC)
			registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
			custody := daemonCustodyPlanForEvidenceLogHandlerTest(t)
			sink := NewDaemonSessionStatusSnapshotSink()
			sessionID := "handler-fail-" + strings.ReplaceAll(tc.name, " ", "-")
			mapped := newMappedEvidenceLogFilesystemForTest(t, evidenceLogPathForHandlerTest(custody, sessionID))
			cfg := DaemonSessionStatusEvidenceLogHandlerConfig{
				Registry:     registry,
				CustodyPlan:  custody,
				SnapshotSink: sink,
				Filesystem:   mapped,
			}
			tc.mutate(&cfg, mapped)
			handler := NewDaemonSessionStatusEvidenceLogHandler(cfg)
			handshake := daemonSessionRegistryTestHandshake(sessionID)
			register := daemonRegisterSessionRequest(sessionID, 7171, 60)
			register.RegisterSession.CgroupID = 717100
			if response := handler.HandleAuthorizedRequest(context.Background(), register, handshake); !response.OK {
				t.Fatalf("register response = %#v", response)
			}

			response := handler.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest(sessionID), handshake)
			if response.OK || !strings.Contains(response.Error, tc.want) {
				t.Fatalf("status response = %#v, want error containing %q", response, tc.want)
			}
			assertProtocolResponseDoesNotExposeEvidenceLogInternals(t, response)
			if strings.Contains(response.Error, custody.StateDir) || strings.Contains(response.Error, ".evlog") {
				t.Fatalf("error leaked evidence-log path: %#v", response)
			}
			if got := sink.Snapshots(); len(got) != 0 {
				t.Fatalf("failure retained snapshot: %#v", got)
			}
			if _, ok := handler.EvidenceLogStateSnapshot(sessionID); ok {
				t.Fatalf("failure stored append state")
			}
			if tc.wantNoFile {
				for _, op := range mapped.operations() {
					if strings.HasPrefix(op, "append:") || strings.HasPrefix(op, "rename:") {
						t.Fatalf("failure performed mutating evidence-log op: %#v", mapped.operations())
					}
				}
			}
		})
	}
}

func TestDaemonSessionStatusEvidenceLogHandlerForwardsNonStatusWithoutEvidenceLog(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 5, 21, 30, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	custody := daemonCustodyPlanForEvidenceLogHandlerTest(t)
	sink := NewDaemonSessionStatusSnapshotSink()
	sessionID := "handler-non-status-session"
	mapped := newMappedEvidenceLogFilesystemForTest(t, evidenceLogPathForHandlerTest(custody, sessionID))
	handler := NewDaemonSessionStatusEvidenceLogHandler(DaemonSessionStatusEvidenceLogHandlerConfig{
		Registry:     registry,
		CustodyPlan:  custody,
		SnapshotSink: sink,
		Filesystem:   mapped,
	})
	handshake := daemonSessionRegistryTestHandshake(sessionID)

	if response := handler.HandleAuthorizedRequest(context.Background(), daemonEvidenceLogHandlerHealthRequest(), handshake); !response.OK {
		t.Fatalf("health response = %#v", response)
	}
	register := daemonRegisterSessionRequest(sessionID, 8181, 60)
	register.RegisterSession.CgroupID = 818100
	if response := handler.HandleAuthorizedRequest(context.Background(), register, handshake); !response.OK {
		t.Fatalf("register response = %#v", response)
	}
	if response := handler.HandleAuthorizedRequest(context.Background(), daemonEndSessionRequest(sessionID), handshake); !response.OK {
		t.Fatalf("end response = %#v", response)
	}
	if len(sink.Snapshots()) != 0 {
		t.Fatalf("non-status requests retained snapshots: %#v", sink.Snapshots())
	}
	if len(mapped.operations()) != 0 {
		t.Fatalf("non-status requests touched evidence filesystem: %#v", mapped.operations())
	}
}

func daemonEvidenceLogHandlerHealthRequest() DaemonProtocolRequest {
	return DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodHealth,
		Health:          &DaemonHealthRequest{},
	}
}

func daemonCustodyPlanForEvidenceLogHandlerTest(t *testing.T) DaemonCustodyPlan {
	t.Helper()
	custody, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	return custody
}

func evidenceLogPathForHandlerTest(custody DaemonCustodyPlan, sessionID string) string {
	return filepath.Join(cleanPath(custody.StateDir), "evidence", "sessions", daemonSessionHandoffSessionKey(sessionID)+".evlog")
}

func assertProtocolResponseDoesNotExposeEvidenceLogInternals(t *testing.T, response DaemonProtocolResponse) {
	t.Helper()
	encoded, err := EncodeDaemonProtocolResponse(response)
	if err != nil {
		t.Fatalf("EncodeDaemonProtocolResponse returned error: %v", err)
	}
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"handoff", "root_pid", "cgroup", "internal", "evidence_log", "entry_digest", "/var/lib/ardur", ".evlog"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("protocol response leaked %q: %s", forbidden, string(encoded))
		}
	}
}

type errEvidenceLogHandlerTestAppendFailure struct{}

func (errEvidenceLogHandlerTestAppendFailure) Error() string { return "simulated append failure" }

// mappedEvidenceLogFilesystemUnion delegates to multiple underlying mapped
// filesystems so tests can use a single handler with multiple per-session
// temp-dir filesystem backends.
type mappedEvidenceLogFilesystemUnion struct {
	t *testing.T
	m []*mappedEvidenceLogFilesystemForTest
}

func newMappedEvidenceLogFilesystemUnion(m ...*mappedEvidenceLogFilesystemForTest) *mappedEvidenceLogFilesystemUnion {
	return &mappedEvidenceLogFilesystemUnion{m: m}
}

func (mu *mappedEvidenceLogFilesystemUnion) Lstat(path string) (fs.FileInfo, error) {
	for _, m := range mu.m {
		if strings.HasPrefix(path+"/", m.logicalRoot+"/") || path == m.logicalRoot {
			return m.Lstat(path)
		}
	}
	mu.t.Fatalf("Lstat path %q not matched by any union member", path)
	return nil, nil
}

func (mu *mappedEvidenceLogFilesystemUnion) MkdirAll(path string, perm fs.FileMode) error {
	for _, m := range mu.m {
		if strings.HasPrefix(path+"/", m.logicalRoot+"/") || path == m.logicalRoot {
			return m.MkdirAll(path, perm)
		}
	}
	mu.t.Fatalf("MkdirAll path %q not matched by any union member", path)
	return nil
}

func (mu *mappedEvidenceLogFilesystemUnion) AppendFile(path string, data []byte, perm fs.FileMode) error {
	for _, m := range mu.m {
		if strings.HasPrefix(path, m.logicalRoot) {
			return m.AppendFile(path, data, perm)
		}
	}
	mu.t.Fatalf("AppendFile path %q not matched by any union member", path)
	return nil
}

func (mu *mappedEvidenceLogFilesystemUnion) Rename(oldPath, newPath string) error {
	for _, m := range mu.m {
		if strings.HasPrefix(oldPath, m.logicalRoot) && strings.HasPrefix(newPath, m.logicalRoot) {
			return m.Rename(oldPath, newPath)
		}
	}
	mu.t.Fatalf("Rename %q -> %q not matched by any union member", oldPath, newPath)
	return nil
}
