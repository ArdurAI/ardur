package kernelcapture

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDaemonSessionStatusEvidenceLogHandlerEndSessionRemovesEvidenceLogAppendState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 5, 22, 0, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	custody := daemonCustodyPlanForEvidenceLogHandlerTest(t)
	sink := NewDaemonSessionStatusSnapshotSink()
	sessionID := "handler-endsession-cleanup"
	mapped := newMappedEvidenceLogFilesystemForTest(t, evidenceLogPathForHandlerTest(custody, sessionID))
	handler := NewDaemonSessionStatusEvidenceLogHandler(DaemonSessionStatusEvidenceLogHandlerConfig{
		Registry:     registry,
		CustodyPlan:  custody,
		SnapshotSink: sink,
		Filesystem:   mapped,
	})
	handshake := daemonSessionRegistryTestHandshake(sessionID)

	register := daemonRegisterSessionRequest(sessionID, 9191, 60)
	register.RegisterSession.CgroupID = 919100
	if response := handler.HandleAuthorizedRequest(context.Background(), register, handshake); !response.OK {
		t.Fatalf("register response = %#v", response)
	}
	status := handler.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest(sessionID), handshake)
	if !status.OK {
		t.Fatalf("status response = %#v", status)
	}
	if len(sink.Snapshots()) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(sink.Snapshots()))
	}
	if _, ok := handler.EvidenceLogStateSnapshot(sessionID); !ok {
		t.Fatal("expected append state to exist after status")
	}

	end := handler.HandleAuthorizedRequest(context.Background(), daemonEndSessionRequest(sessionID), handshake)
	if !end.OK || end.Status != DaemonSessionStatusEnded {
		t.Fatalf("end response = %#v", end)
	}
	assertProtocolResponseDoesNotExposeEvidenceLogInternals(t, end)
	if _, ok := handler.EvidenceLogStateSnapshot(sessionID); ok {
		t.Fatal("end_session should have removed append state")
	}
	if len(sink.Snapshots()) != 1 {
		t.Fatalf("sink snapshot count changed after end: %d", len(sink.Snapshots()))
	}
}

func TestDaemonSessionStatusEvidenceLogHandlerExpiredSessionStatusRemovesEvidenceLogAppendState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 5, 22, 15, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	custody := daemonCustodyPlanForEvidenceLogHandlerTest(t)
	sink := NewDaemonSessionStatusSnapshotSink()
	sessionID := "handler-expired-cleanup"
	mapped := newMappedEvidenceLogFilesystemForTest(t, evidenceLogPathForHandlerTest(custody, sessionID))
	handler := NewDaemonSessionStatusEvidenceLogHandler(DaemonSessionStatusEvidenceLogHandlerConfig{
		Registry:     registry,
		CustodyPlan:  custody,
		SnapshotSink: sink,
		Filesystem:   mapped,
	})
	handshake := daemonSessionRegistryTestHandshake(sessionID)

	register := daemonRegisterSessionRequest(sessionID, 10101, 1)
	register.RegisterSession.CgroupID = 1010100
	if response := handler.HandleAuthorizedRequest(context.Background(), register, handshake); !response.OK {
		t.Fatalf("register response = %#v", response)
	}
	status := handler.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest(sessionID), handshake)
	if !status.OK {
		t.Fatalf("status response = %#v", status)
	}
	if _, ok := handler.EvidenceLogStateSnapshot(sessionID); !ok {
		t.Fatal("expected append state to exist after first status")
	}

	now = now.Add(2 * time.Second)
	expired := handler.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest(sessionID), handshake)
	if expired.OK || expired.Status != DaemonSessionStatusExpired || !strings.Contains(expired.Error, "expired") {
		t.Fatalf("expired status response = %#v", expired)
	}
	assertProtocolResponseDoesNotExposeEvidenceLogInternals(t, expired)
	if _, ok := handler.EvidenceLogStateSnapshot(sessionID); ok {
		t.Fatal("expired session_status should have removed append state")
	}
}

func TestDaemonSessionStatusEvidenceLogHandlerExplicitRemoveEvidenceLogAppendState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 5, 22, 30, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	custody := daemonCustodyPlanForEvidenceLogHandlerTest(t)
	sink := NewDaemonSessionStatusSnapshotSink()
	sessionID := "handler-explicitremove"
	mapped := newMappedEvidenceLogFilesystemForTest(t, evidenceLogPathForHandlerTest(custody, sessionID))
	handler := NewDaemonSessionStatusEvidenceLogHandler(DaemonSessionStatusEvidenceLogHandlerConfig{
		Registry:     registry,
		CustodyPlan:  custody,
		SnapshotSink: sink,
		Filesystem:   mapped,
	})
	handshake := daemonSessionRegistryTestHandshake(sessionID)

	register := daemonRegisterSessionRequest(sessionID, 11111, 60)
	register.RegisterSession.CgroupID = 1111100
	if response := handler.HandleAuthorizedRequest(context.Background(), register, handshake); !response.OK {
		t.Fatalf("register response = %#v", response)
	}
	status := handler.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest(sessionID), handshake)
	if !status.OK {
		t.Fatalf("status response = %#v", status)
	}
	if _, ok := handler.EvidenceLogStateSnapshot(sessionID); !ok {
		t.Fatal("expected append state to exist after status")
	}

	handler.RemoveEvidenceLogAppendState(sessionID)
	if _, ok := handler.EvidenceLogStateSnapshot(sessionID); ok {
		t.Fatal("explicit remove should have removed append state")
	}
}

func TestDaemonSessionStatusEvidenceLogHandlerRemoveEvidenceLogAppendStateIdempotent(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 5, 22, 45, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	custody := daemonCustodyPlanForEvidenceLogHandlerTest(t)
	sink := NewDaemonSessionStatusSnapshotSink()
	sessionID := "handler-remove-idempotent"
	mapped := newMappedEvidenceLogFilesystemForTest(t, evidenceLogPathForHandlerTest(custody, sessionID))
	handler := NewDaemonSessionStatusEvidenceLogHandler(DaemonSessionStatusEvidenceLogHandlerConfig{
		Registry:     registry,
		CustodyPlan:  custody,
		SnapshotSink: sink,
		Filesystem:   mapped,
	})

	if _, ok := handler.EvidenceLogStateSnapshot(sessionID); ok {
		t.Fatal("no state should exist for unknown session")
	}
	handler.RemoveEvidenceLogAppendState(sessionID)
	if _, ok := handler.EvidenceLogStateSnapshot(sessionID); ok {
		t.Fatal("remove should be idempotent")
	}
}

func TestDaemonSessionStatusEvidenceLogHandlerSessionsDoNotStaleOtherEvidenceLogState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 5, 23, 0, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	custody := daemonCustodyPlanForEvidenceLogHandlerTest(t)
	sink := NewDaemonSessionStatusSnapshotSink()
	sessionA := "handler-isolated-a"
	sessionB := "handler-isolated-b"
	mappedA := newMappedEvidenceLogFilesystemForTest(t, evidenceLogPathForHandlerTest(custody, sessionA))
	mappedB := newMappedEvidenceLogFilesystemForTest(t, evidenceLogPathForHandlerTest(custody, sessionB))
	mapped := newMappedEvidenceLogFilesystemUnion(mappedA, mappedB)
	handler := NewDaemonSessionStatusEvidenceLogHandler(DaemonSessionStatusEvidenceLogHandlerConfig{
		Registry:     registry,
		CustodyPlan:  custody,
		SnapshotSink: sink,
		Filesystem:   mapped,
	})
	handshakeA := daemonSessionRegistryTestHandshake(sessionA)
	handshakeB := daemonSessionRegistryTestHandshake(sessionB)

	registerA := daemonRegisterSessionRequest(sessionA, 12121, 60)
	registerA.RegisterSession.CgroupID = 1212100
	if response := handler.HandleAuthorizedRequest(context.Background(), registerA, handshakeA); !response.OK {
		t.Fatalf("register A response = %#v", response)
	}
	registerB := daemonRegisterSessionRequest(sessionB, 13131, 60)
	registerB.RegisterSession.CgroupID = 1313100
	if response := handler.HandleAuthorizedRequest(context.Background(), registerB, handshakeB); !response.OK {
		t.Fatalf("register B response = %#v", response)
	}

	if response := handler.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest(sessionA), handshakeA); !response.OK {
		t.Fatalf("status A response = %#v", response)
	}
	if response := handler.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest(sessionB), handshakeB); !response.OK {
		t.Fatalf("status B response = %#v", response)
	}

	if response := handler.HandleAuthorizedRequest(context.Background(), daemonEndSessionRequest(sessionA), handshakeA); !response.OK {
		t.Fatalf("end A response = %#v", response)
	}
	if _, ok := handler.EvidenceLogStateSnapshot(sessionA); ok {
		t.Fatal("session A append state should be removed")
	}
	if _, ok := handler.EvidenceLogStateSnapshot(sessionB); !ok {
		t.Fatal("session B append state should still exist")
	}
	if got := sink.Snapshots(); len(got) != 2 {
		t.Fatalf("sink snapshot count = %d, want 2", len(got))
	}
}
