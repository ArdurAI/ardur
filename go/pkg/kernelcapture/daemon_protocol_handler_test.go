package kernelcapture

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func testHandshake(method, sessionID string) DaemonProtocolPeerHandshake {
	return DaemonProtocolPeerHandshake{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          method,
		SessionID:       sessionID,
	}
}

func TestSessionAwareHandlerHealth(t *testing.T) {
	t.Parallel()

	registry := NewSessionRegistry()
	handler := NewSessionAwareHandler(registry, nil)
	now := time.Now()

	_ = registry.Register(DaemonRegisterSessionRequest{
		SessionID:    "sess-1",
		RootPID:      100,
		TTLSeconds:   3600,
		EventClasses: []string{"exec", "exit"},
	}, now)

	resp := handler(context.Background(), DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodHealth,
		Health:          &DaemonHealthRequest{},
	}, testHandshake(DaemonProtocolMethodHealth, ""))

	if !resp.OK {
		t.Fatalf("expected OK, got error: %s", resp.Error)
	}
	if !strings.Contains(resp.Status, "1 active sessions") {
		t.Fatalf("expected status to contain active count, got %q", resp.Status)
	}
}

func TestSessionAwareHandlerRegisterSession(t *testing.T) {
	t.Parallel()

	registry := NewSessionRegistry()
	handler := NewSessionAwareHandler(registry, nil)

	resp := handler(context.Background(), DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodRegisterSession,
		RegisterSession: &DaemonRegisterSessionRequest{
			SessionID:    "sess-1",
			MissionID:    "mission-abc",
			RootPID:      12345,
			TTLSeconds:   3600,
			EventClasses: []string{"exec", "exit"},
		},
	}, testHandshake(DaemonProtocolMethodRegisterSession, "sess-1"))

	if !resp.OK {
		t.Fatalf("expected OK, got error: %s", resp.Error)
	}
	if resp.Status != "registered" {
		t.Fatalf("expected status 'registered', got %q", resp.Status)
	}
	if resp.SessionID != "sess-1" {
		t.Fatalf("expected session_id sess-1, got %s", resp.SessionID)
	}

	session, err := registry.Lookup("sess-1")
	if err != nil {
		t.Fatalf("expected session to exist, got %v", err)
	}
	if session.MissionID != "mission-abc" {
		t.Fatalf("expected mission-abc, got %s", session.MissionID)
	}
}

func TestSessionAwareHandlerRegisterSessionNilPayload(t *testing.T) {
	t.Parallel()

	registry := NewSessionRegistry()
	handler := NewSessionAwareHandler(registry, nil)

	resp := handler(context.Background(), DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodRegisterSession,
	}, testHandshake(DaemonProtocolMethodRegisterSession, ""))

	if resp.OK {
		t.Fatal("expected error for nil register_session payload")
	}
	if !strings.Contains(resp.Error, "payload is required") {
		t.Fatalf("expected payload required error, got %q", resp.Error)
	}
}

func TestSessionAwareHandlerRegisterSessionInvalidTTL(t *testing.T) {
	t.Parallel()

	registry := NewSessionRegistry()
	handler := NewSessionAwareHandler(registry, nil)

	resp := handler(context.Background(), DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodRegisterSession,
		RegisterSession: &DaemonRegisterSessionRequest{
			SessionID:    "sess-1",
			RootPID:      100,
			TTLSeconds:   -1,
			EventClasses: []string{"exec", "exit"},
		},
	}, testHandshake(DaemonProtocolMethodRegisterSession, "sess-1"))

	if resp.OK {
		t.Fatal("expected error for invalid TTL")
	}
	if !strings.Contains(resp.Error, ErrInvalidTTL.Error()) {
		t.Fatalf("expected ErrInvalidTTL, got %q", resp.Error)
	}
}

func TestSessionAwareHandlerRegisterSessionRegistersCorrelatorReceipt(t *testing.T) {
	t.Parallel()

	registry := NewSessionRegistry()
	correlator := NewCorrelator(CorrelatorOptions{})
	handler := NewSessionAwareHandler(registry, correlator)

	handler(context.Background(), DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodRegisterSession,
		RegisterSession: &DaemonRegisterSessionRequest{
			SessionID:      "sess-1",
			RootPID:        12345,
			PIDNamespaceID: 4026531836,
			CgroupID:       99,
			TTLSeconds:     3600,
			EventClasses:   []string{"exec", "exit"},
		},
	}, testHandshake(DaemonProtocolMethodRegisterSession, "sess-1"))

	// Verify the correlator got the receipt by checking that a matching
	// process event correlates with high confidence.
	receipt := correlator.Correlate(ProcessEvent{
		SessionID:      "sess-1",
		PID:            12345,
		PIDNamespaceID: 4026531836,
		CgroupID:       99,
		ObservedAt:     time.Now(),
	}, EventContext{})
	if receipt.CorrelationMethod != "explicit_pid" {
		t.Fatalf("expected explicit_pid correlation, got %s", receipt.CorrelationMethod)
	}
}

func TestSessionAwareHandlerEndSession(t *testing.T) {
	t.Parallel()

	registry := NewSessionRegistry()
	handler := NewSessionAwareHandler(registry, nil)
	now := time.Now()

	_ = registry.Register(DaemonRegisterSessionRequest{
		SessionID:    "sess-1",
		RootPID:      100,
		TTLSeconds:   3600,
		EventClasses: []string{"exec", "exit"},
	}, now)

	resp := handler(context.Background(), DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodEndSession,
		EndSession:      &DaemonEndSessionRequest{SessionID: "sess-1"},
	}, testHandshake(DaemonProtocolMethodEndSession, "sess-1"))

	if !resp.OK {
		t.Fatalf("expected OK, got error: %s", resp.Error)
	}
	if resp.Status != "ended" {
		t.Fatalf("expected status 'ended', got %q", resp.Status)
	}

	_, err := registry.Lookup("sess-1")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestSessionAwareHandlerEndSessionNilPayload(t *testing.T) {
	t.Parallel()

	registry := NewSessionRegistry()
	handler := NewSessionAwareHandler(registry, nil)

	resp := handler(context.Background(), DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodEndSession,
	}, testHandshake(DaemonProtocolMethodEndSession, ""))

	if resp.OK {
		t.Fatal("expected error for nil end_session payload")
	}
	if !strings.Contains(resp.Error, "payload is required") {
		t.Fatalf("expected payload required error, got %q", resp.Error)
	}
}

func TestSessionAwareHandlerSessionStatusFound(t *testing.T) {
	t.Parallel()

	registry := NewSessionRegistry()
	handler := NewSessionAwareHandler(registry, nil)
	now := time.Now()

	_ = registry.Register(DaemonRegisterSessionRequest{
		SessionID:    "sess-1",
		RootPID:      12345,
		TTLSeconds:   7200,
		EventClasses: []string{"exec", "exit"},
	}, now)

	resp := handler(context.Background(), DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodSessionStatus,
		SessionStatus:   &DaemonSessionStatusRequest{SessionID: "sess-1"},
	}, testHandshake(DaemonProtocolMethodSessionStatus, "sess-1"))

	if !resp.OK {
		t.Fatalf("expected OK, got error: %s", resp.Error)
	}
	if !strings.Contains(resp.Status, "root_pid=12345") {
		t.Fatalf("expected root_pid in status, got %q", resp.Status)
	}
	if !strings.Contains(resp.Status, "ttl=7200s") {
		t.Fatalf("expected ttl in status, got %q", resp.Status)
	}
}

func TestSessionAwareHandlerSessionStatusNotFound(t *testing.T) {
	t.Parallel()

	registry := NewSessionRegistry()
	handler := NewSessionAwareHandler(registry, nil)

	resp := handler(context.Background(), DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodSessionStatus,
		SessionStatus:   &DaemonSessionStatusRequest{SessionID: "nonexistent"},
	}, testHandshake(DaemonProtocolMethodSessionStatus, "nonexistent"))

	if resp.OK {
		t.Fatal("expected error for non-existent session")
	}
	if !strings.Contains(resp.Error, ErrSessionNotFound.Error()) {
		t.Fatalf("expected ErrSessionNotFound, got %q", resp.Error)
	}
}

func TestSessionAwareHandlerSessionStatusNilPayload(t *testing.T) {
	t.Parallel()

	registry := NewSessionRegistry()
	handler := NewSessionAwareHandler(registry, nil)

	resp := handler(context.Background(), DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodSessionStatus,
	}, testHandshake(DaemonProtocolMethodSessionStatus, ""))

	if resp.OK {
		t.Fatal("expected error for nil session_status payload")
	}
	if !strings.Contains(resp.Error, "payload is required") {
		t.Fatalf("expected payload required error, got %q", resp.Error)
	}
}

func TestSessionAwareHandlerUnknownMethod(t *testing.T) {
	t.Parallel()

	registry := NewSessionRegistry()
	handler := NewSessionAwareHandler(registry, nil)

	resp := handler(context.Background(), DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          "nonexistent_method",
	}, testHandshake("nonexistent_method", ""))

	if resp.OK {
		t.Fatal("expected error for unknown method")
	}
	if !strings.Contains(resp.Error, "unknown method") {
		t.Fatalf("expected 'unknown method' error, got %q", resp.Error)
	}
}

func TestSessionAwareHandlerConcurrentAccess(t *testing.T) {
	t.Parallel()

	registry := NewSessionRegistry()
	handler := NewSessionAwareHandler(registry, nil)
	const workers = 4
	const perWorker = 50

	// Register all sessions concurrently.
	var regWg sync.WaitGroup
	regWg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(offset int) {
			defer regWg.Done()
			for i := 0; i < perWorker; i++ {
				id := fmt.Sprintf("sess-%d-%d", offset, i)
				handler(context.Background(), DaemonProtocolRequest{
					ProtocolVersion: DaemonProtocolVersion,
					Method:          DaemonProtocolMethodRegisterSession,
					RegisterSession: &DaemonRegisterSessionRequest{
						SessionID:    id,
						RootPID:      uint32(offset*perWorker + i + 1),
						TTLSeconds:   3600,
						EventClasses: []string{"exec", "exit"},
					},
				}, testHandshake(DaemonProtocolMethodRegisterSession, id))
			}
		}(w)
	}
	regWg.Wait()

	// Then query all sessions concurrently.
	var qWg sync.WaitGroup
	qWg.Add(workers)
	errs := make(chan error, workers*perWorker)
	for w := 0; w < workers; w++ {
		go func(offset int) {
			defer qWg.Done()
			for i := 0; i < perWorker; i++ {
				id := fmt.Sprintf("sess-%d-%d", offset, i)
				resp := handler(context.Background(), DaemonProtocolRequest{
					ProtocolVersion: DaemonProtocolVersion,
					Method:          DaemonProtocolMethodSessionStatus,
					SessionStatus:   &DaemonSessionStatusRequest{SessionID: id},
				}, testHandshake(DaemonProtocolMethodSessionStatus, id))
				if !resp.OK {
					errs <- fmt.Errorf("expected OK for %s, got %s", id, resp.Error)
				}
			}
		}(w)
	}
	qWg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	if registry.ActiveCount() != workers*perWorker {
		t.Fatalf("expected %d sessions, got %d", workers*perWorker, registry.ActiveCount())
	}
}

func TestSessionAwareHandlerEndSessionNonExistent(t *testing.T) {
	t.Parallel()

	registry := NewSessionRegistry()
	handler := NewSessionAwareHandler(registry, nil)

	resp := handler(context.Background(), DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodEndSession,
		EndSession:      &DaemonEndSessionRequest{SessionID: "nonexistent"},
	}, testHandshake(DaemonProtocolMethodEndSession, "nonexistent"))

	if !resp.OK {
		t.Fatalf("end_session for non-existent session should succeed, got error: %s", resp.Error)
	}
}

func TestSessionAwareHandlerSessionStatusExpired(t *testing.T) {
	t.Parallel()

	registry := NewSessionRegistry()
	handler := NewSessionAwareHandler(registry, nil)
	past := time.Now().Add(-2 * time.Hour)

	_ = registry.Register(DaemonRegisterSessionRequest{
		SessionID:    "expired-sess",
		RootPID:      100,
		TTLSeconds:   1,
		EventClasses: []string{"exec", "exit"},
	}, past)

	resp := handler(context.Background(), DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodSessionStatus,
		SessionStatus:   &DaemonSessionStatusRequest{SessionID: "expired-sess"},
	}, testHandshake(DaemonProtocolMethodSessionStatus, "expired-sess"))

	if resp.OK {
		t.Fatal("expected error for expired session")
	}
	if !strings.Contains(resp.Error, ErrSessionExpired.Error()) {
		t.Fatalf("expected ErrSessionExpired, got %q", resp.Error)
	}
}
