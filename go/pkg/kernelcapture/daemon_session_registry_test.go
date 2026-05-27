package kernelcapture

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestSessionRegistryRegisterValid(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry()
	now := time.Now().UTC()

	err := r.Register(DaemonRegisterSessionRequest{
		SessionID:    "sess-1",
		MissionID:    "mission-abc",
		RootPID:      12345,
		TTLSeconds:   3600,
		EventClasses: []string{"exec", "exit"},
	}, now)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	session, err := r.Lookup("sess-1")
	if err != nil {
		t.Fatalf("expected to find session, got %v", err)
	}
	if session.SessionID != "sess-1" {
		t.Fatalf("expected sess-1, got %s", session.SessionID)
	}
	if session.MissionID != "mission-abc" {
		t.Fatalf("expected mission-abc, got %s", session.MissionID)
	}
	if session.RootPID != 12345 {
		t.Fatalf("expected pid 12345, got %d", session.RootPID)
	}
	if session.TTLSeconds != 3600 {
		t.Fatalf("expected ttl 3600, got %d", session.TTLSeconds)
	}
	if session.ExpiresAt.Before(now) {
		t.Fatal("expires_at should be in the future")
	}
}

func TestSessionRegistryRegisterEmptySessionID(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry()
	err := r.Register(DaemonRegisterSessionRequest{
		SessionID:  "",
		TTLSeconds: 3600,
	}, time.Now())
	if err == nil {
		t.Fatal("expected error for empty session id")
	}
	if !errors.Is(err, ErrInvalidSessionID) {
		t.Fatalf("expected ErrInvalidSessionID, got %v", err)
	}
}

func TestSessionRegistryRegisterNegativeTTL(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry()
	err := r.Register(DaemonRegisterSessionRequest{
		SessionID:  "sess-1",
		TTLSeconds: -1,
	}, time.Now())
	if err == nil {
		t.Fatal("expected error for negative ttl")
	}
	if !errors.Is(err, ErrInvalidTTL) {
		t.Fatalf("expected ErrInvalidTTL, got %v", err)
	}
}

func TestSessionRegistryRegisterExceedsMaxTTL(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry()
	err := r.Register(DaemonRegisterSessionRequest{
		SessionID:  "sess-1",
		TTLSeconds: MaxDaemonProtocolTTLSeconds + 1,
	}, time.Now())
	if err == nil {
		t.Fatal("expected error for excessive ttl")
	}
	if !errors.Is(err, ErrInvalidTTL) {
		t.Fatalf("expected ErrInvalidTTL, got %v", err)
	}
}

func TestSessionRegistryDuplicateOverwrites(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry()
	now := time.Now().UTC()

	_ = r.Register(DaemonRegisterSessionRequest{
		SessionID:  "sess-1",
		RootPID:    100,
		TTLSeconds: 3600,
	}, now)

	_ = r.Register(DaemonRegisterSessionRequest{
		SessionID:  "sess-1",
		RootPID:    200,
		TTLSeconds: 7200,
	}, now)

	session, err := r.Lookup("sess-1")
	if err != nil {
		t.Fatalf("expected to find session, got %v", err)
	}
	if session.RootPID != 200 {
		t.Fatalf("expected updated pid 200, got %d", session.RootPID)
	}
}

func TestSessionRegistryUnregister(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry()
	now := time.Now().UTC()

	_ = r.Register(DaemonRegisterSessionRequest{
		SessionID:  "sess-1",
		TTLSeconds: 3600,
	}, now)

	_ = r.Unregister("sess-1")

	_, err := r.Lookup("sess-1")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestSessionRegistryUnregisterNonExistent(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry()
	err := r.Unregister("nonexistent")
	if err != nil {
		t.Fatalf("unregister nonexistent should not error, got %v", err)
	}
}

func TestSessionRegistryLookupNotFound(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry()
	_, err := r.Lookup("nonexistent")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestSessionRegistryExpireRemovesExpired(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry()
	past := time.Now().Add(-2 * time.Hour)

	_ = r.Register(DaemonRegisterSessionRequest{
		SessionID:  "expired-sess",
		TTLSeconds: 1,
	}, past)

	_ = r.Register(DaemonRegisterSessionRequest{
		SessionID:  "valid-sess",
		TTLSeconds: 3600,
	}, time.Now())

	expired := r.ExpireSessions(time.Now())
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired, got %d: %v", len(expired), expired)
	}
	if expired[0] != "expired-sess" {
		t.Fatalf("expected expired-sess, got %s", expired[0])
	}

	_, err := r.Lookup("valid-sess")
	if err != nil {
		t.Fatalf("valid session should still exist, got %v", err)
	}
}

func TestSessionRegistryActiveCount(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry()
	now := time.Now().UTC()

	if r.ActiveCount() != 0 {
		t.Fatalf("expected 0 active, got %d", r.ActiveCount())
	}

	_ = r.Register(DaemonRegisterSessionRequest{SessionID: "a", TTLSeconds: 3600}, now)
	_ = r.Register(DaemonRegisterSessionRequest{SessionID: "b", TTLSeconds: 3600}, now)

	if r.ActiveCount() != 2 {
		t.Fatalf("expected 2 active, got %d", r.ActiveCount())
	}
}

func TestSessionRegistryList(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry()
	now := time.Now().UTC()

	_ = r.Register(DaemonRegisterSessionRequest{SessionID: "b", TTLSeconds: 3600}, now)
	_ = r.Register(DaemonRegisterSessionRequest{SessionID: "a", TTLSeconds: 3600}, now)

	ids := r.List()
	if len(ids) != 2 {
		t.Fatalf("expected 2 ids, got %d", len(ids))
	}
}

func TestSessionRegistryConcurrentAccess(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry()
	now := time.Now().UTC()
	const workers = 6
	const perWorker = 100

	var wg sync.WaitGroup
	wg.Add(workers * 2)

	for w := 0; w < workers; w++ {
		go func(offset int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				id := fmt.Sprintf("sess-%d-%d", offset, i)
				_ = r.Register(DaemonRegisterSessionRequest{
					SessionID:  id,
					TTLSeconds: 3600,
				}, now)
			}
		}(w)
	}

	for w := 0; w < workers; w++ {
		go func(offset int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				id := fmt.Sprintf("sess-%d-%d", offset, i)
				_, _ = r.Lookup(id)
			}
		}(w)
	}

	wg.Wait()

	if r.ActiveCount() != workers*perWorker {
		t.Fatalf("expected %d sessions, got %d", workers*perWorker, r.ActiveCount())
	}
}
