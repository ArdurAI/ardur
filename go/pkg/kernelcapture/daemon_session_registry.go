package kernelcapture

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrSessionNotFound    = errors.New("kernelcapture: session not found")
	ErrSessionExpired     = errors.New("kernelcapture: session expired")
	ErrSessionDuplicate   = errors.New("kernelcapture: duplicate session id")
	ErrInvalidSessionID   = errors.New("kernelcapture: invalid session id")
	ErrInvalidTTL         = errors.New("kernelcapture: invalid ttl")
)

// ActiveSession tracks one kernel-capture session's lifecycle state.
type ActiveSession struct {
	SessionID   string
	MissionID   string
	TraceID     string
	RootPID     uint32
	CgroupID    uint64
	StartedAt   time.Time
	ExpiresAt   time.Time
	TTLSeconds  int64
	EventClasses []string
}

// SessionRegistry manages active kernel-capture sessions with thread-safe
// concurrent access. It pairs with a Correlator for process-lifecycle matching.
type SessionRegistry struct {
	mu       sync.RWMutex
	sessions map[string]*ActiveSession
}

// NewSessionRegistry creates a session registry.
func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{
		sessions: make(map[string]*ActiveSession),
	}
}

// Register adds or replaces a session. Returns error for invalid input.
func (r *SessionRegistry) Register(req DaemonRegisterSessionRequest, now time.Time) error {
	if req.SessionID == "" {
		return fmt.Errorf("%w: session id is required", ErrInvalidSessionID)
	}
	if req.TTLSeconds <= 0 {
		return fmt.Errorf("%w: ttl_seconds must be positive, got %d", ErrInvalidTTL, req.TTLSeconds)
	}
	if req.TTLSeconds > MaxDaemonProtocolTTLSeconds {
		return fmt.Errorf("%w: ttl_seconds %d exceeds max %d", ErrInvalidTTL, req.TTLSeconds, MaxDaemonProtocolTTLSeconds)
	}

	session := &ActiveSession{
		SessionID:    req.SessionID,
		MissionID:    req.MissionID,
		TraceID:      req.TraceID,
		RootPID:      req.RootPID,
		CgroupID:     req.CgroupID,
		StartedAt:    now,
		ExpiresAt:    now.Add(time.Duration(req.TTLSeconds) * time.Second),
		TTLSeconds:   req.TTLSeconds,
		EventClasses: append([]string(nil), req.EventClasses...),
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[req.SessionID] = session
	return nil
}

// Unregister removes a session. Returns nil even if the session didn't exist.
func (r *SessionRegistry) Unregister(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("%w: session id is required", ErrInvalidSessionID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, sessionID)
	return nil
}

// Lookup finds an active session. Returns ErrSessionNotFound if not present
// and ErrSessionExpired if the session has passed its TTL.
func (r *SessionRegistry) Lookup(sessionID string) (*ActiveSession, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	session, ok := r.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}
	return session, nil
}

// ExpireSessions removes and returns IDs of sessions past their TTL.
func (r *SessionRegistry) ExpireSessions(now time.Time) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var expired []string
	for id, session := range r.sessions {
		if now.After(session.ExpiresAt) {
			expired = append(expired, id)
			delete(r.sessions, id)
		}
	}
	return expired
}

// ActiveCount returns the number of currently registered sessions.
func (r *SessionRegistry) ActiveCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

// List returns a snapshot of active session IDs.
func (r *SessionRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.sessions))
	for id := range r.sessions {
		ids = append(ids, id)
	}
	return ids
}
