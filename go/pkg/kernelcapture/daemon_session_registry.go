package kernelcapture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	DaemonSessionStatusRegistered       = "registered"
	DaemonSessionStatusActive           = "active"
	DaemonSessionStatusEnded            = "ended"
	DaemonSessionStatusExpired          = "expired"
	DaemonSessionStatusNotFound         = "not_found"
	DaemonSessionStatusCapacityExceeded = "capacity_exceeded"

	DefaultDaemonSessionRegistryMaxSessions = 4096
)

var ErrDaemonSessionRegistry = errors.New("kernelcapture: daemon session registry failed")

type DaemonSessionClock func() time.Time

// DaemonSessionRecord is daemon-owned in-memory session state derived only after
// a valid protocol request has been joined to daemon-observed peer credentials.
// It is intentionally metadata-only: it does not claim cgroup creation, BPF map
// mutation, process execution, or live kernel enforcement.
type DaemonSessionRecord struct {
	SessionID string
	MissionID string
	TraceID   string
	// RegistrationGeneration is a daemon-local monotonic identity for this
	// specific registration lifetime. Session IDs may be reused after end or
	// expiry, so the string alone cannot prove two lookups saw the same record.
	RegistrationGeneration uint64
	RootPID                uint32
	// RootProcessStartTimeTicks binds RootPID to the process lifetime the
	// daemon observed while accepting register_session. It is distinct from
	// PeerProcessStartTimeTicks because the launcher registers its child.
	RootProcessStartTimeTicks uint64
	PIDNamespaceID            uint32
	CgroupID                  uint64
	EventClasses              []string
	HandoffMetadata           map[string]any

	RegisteredAt time.Time
	ExpiresAt    time.Time
	EndedAt      time.Time

	PeerUID                   uint32
	PeerGID                   uint32
	PeerPID                   uint32
	PeerProcessStartTimeTicks uint64
	CredentialSource          string
	SocketPath                string
}

func (r DaemonSessionRecord) Status(now time.Time) string {
	if !r.EndedAt.IsZero() {
		return DaemonSessionStatusEnded
	}
	if !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt) {
		return DaemonSessionStatusExpired
	}
	return DaemonSessionStatusActive
}

// DaemonSessionRegistry is a bounded in-memory daemon session lifecycle seam for
// authorized daemon protocol requests. It deliberately performs no privileged
// filesystem, cgroup, BPF, service-lifecycle, or process-management work.
type DaemonSessionRegistry struct {
	mu                         sync.RWMutex
	sessions                   map[string]DaemonSessionRecord
	now                        DaemonSessionClock
	maxSessions                int
	nextRegistrationGeneration uint64
}

func NewDaemonSessionRegistry() *DaemonSessionRegistry {
	return NewDaemonSessionRegistryWithClock(time.Now)
}

func NewDaemonSessionRegistryWithClock(clock DaemonSessionClock) *DaemonSessionRegistry {
	if clock == nil {
		clock = time.Now
	}
	return &DaemonSessionRegistry{
		sessions:    make(map[string]DaemonSessionRecord),
		now:         clock,
		maxSessions: DefaultDaemonSessionRegistryMaxSessions,
	}
}

func (r *DaemonSessionRegistry) Session(sessionID string) (DaemonSessionRecord, bool) {
	if r == nil {
		return DaemonSessionRecord{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, ok := r.sessions[strings.TrimSpace(sessionID)]
	if !ok {
		return DaemonSessionRecord{}, false
	}
	return copyDaemonSessionRecord(record), true
}

// ActiveSession returns a copy of a currently active daemon-owned session record.
// It is the safe internal lookup seam for daemon status/handoff code: callers get
// metadata-only state and cannot mutate the registry's in-memory record.
func (r *DaemonSessionRegistry) ActiveSession(sessionID string) (DaemonSessionRecord, error) {
	record, _, err := r.lookupActiveSession(sessionID, r.currentTime())
	if err != nil {
		return DaemonSessionRecord{}, fmt.Errorf("%w: %v", ErrDaemonSessionRegistry, err)
	}
	return record, nil
}

// ActiveSessionForPeer is like ActiveSession but additionally requires that the
// supplied peer handshake OWNS the session — i.e. it matches the UID/GID/PID/
// process-start-time/credential-source recorded at register_session. This is the
// same ownership gate handleEndSession/handleSessionStatus already enforce; it is
// exported so out-of-package daemon handlers that resolve a session by
// client-supplied session_id (apply_policy, set_kill_switch) can enforce it too,
// instead of letting any authorized-UID peer mutate a session another peer
// registered (see the missing-authorization finding these callers close).
func (r *DaemonSessionRegistry) ActiveSessionForPeer(sessionID string, handshake DaemonProtocolPeerHandshake) (DaemonSessionRecord, error) {
	record, _, err := r.lookupActiveSession(sessionID, r.currentTime())
	if err != nil {
		return DaemonSessionRecord{}, fmt.Errorf("%w: %v", ErrDaemonSessionRegistry, err)
	}
	if !daemonSessionRegistryPeerOwnsRecord(record, handshake) {
		return DaemonSessionRecord{}, fmt.Errorf("%w: session %q is owned by a different peer", ErrDaemonSessionRegistry, sessionID)
	}
	return record, nil
}

// ActiveSessionForDelegatedRootPeer resolves an active session only when an
// independently authorized socket peer is the exact root process the session
// owner registered. The launcher owns the control-plane session, while its
// exec shim is a different process that legitimately transfers the seccomp
// listener; this delegated gate preserves that split without reducing it to
// daemon-wide UID/GID authorization.
func (r *DaemonSessionRegistry) ActiveSessionForDelegatedRootPeer(sessionID string, observation DaemonSocketPeerObservation, authorization DaemonPeerAuthorization) (DaemonSessionRecord, error) {
	record, _, err := r.lookupActiveSession(sessionID, r.currentTime())
	if err != nil {
		return DaemonSessionRecord{}, fmt.Errorf("%w: %v", ErrDaemonSessionRegistry, err)
	}
	if !daemonSessionRegistryDelegatedRootPeerOwnsRecord(record, observation, authorization) {
		return DaemonSessionRecord{}, fmt.Errorf("%w: session %q root process is owned by a different peer", ErrDaemonSessionRegistry, sessionID)
	}
	return record, nil
}

// ActiveSessionForDelegatedRootPeerGeneration revalidates that the delegated
// root still owns the same registration lifetime observed earlier. Session IDs
// are reusable after end or expiry; accepting a replacement record here could
// attach an in-flight listener using metadata from the prior registration.
func (r *DaemonSessionRegistry) ActiveSessionForDelegatedRootPeerGeneration(sessionID string, observation DaemonSocketPeerObservation, authorization DaemonPeerAuthorization, registrationGeneration uint64) (DaemonSessionRecord, error) {
	if registrationGeneration == 0 {
		return DaemonSessionRecord{}, fmt.Errorf("%w: session %q registration generation is required", ErrDaemonSessionRegistry, sessionID)
	}
	record, err := r.ActiveSessionForDelegatedRootPeer(sessionID, observation, authorization)
	if err != nil {
		return DaemonSessionRecord{}, err
	}
	if record.RegistrationGeneration != registrationGeneration {
		return DaemonSessionRecord{}, fmt.Errorf("%w: session %q registration was replaced", ErrDaemonSessionRegistry, sessionID)
	}
	return record, nil
}

// ActiveSessionGeneration resolves an active session only if it is still the
// same registration lifetime. Long-lived daemon work uses this to fail closed
// after a session ID is ended or expired and then reused.
func (r *DaemonSessionRegistry) ActiveSessionGeneration(sessionID string, registrationGeneration uint64) (DaemonSessionRecord, error) {
	if registrationGeneration == 0 {
		return DaemonSessionRecord{}, fmt.Errorf("%w: session %q registration generation is required", ErrDaemonSessionRegistry, sessionID)
	}
	record, err := r.ActiveSession(sessionID)
	if err != nil {
		return DaemonSessionRecord{}, err
	}
	if record.RegistrationGeneration != registrationGeneration {
		return DaemonSessionRecord{}, fmt.Errorf("%w: session %q registration was replaced", ErrDaemonSessionRegistry, sessionID)
	}
	return record, nil
}

// BuildActiveSessionHandoffPlan projects an active registered session into the
// existing no-mutation handoff plan using daemon-owned custody paths. It performs
// no filesystem writes, cgroup assignment, BPF map mutation, or live enforcement.
func (r *DaemonSessionRegistry) BuildActiveSessionHandoffPlan(sessionID string, custodyPlan DaemonCustodyPlan) (DaemonSessionHandoffPlan, error) {
	asOf := r.currentTime()
	record, _, err := r.lookupActiveSession(sessionID, asOf)
	if err != nil {
		return DaemonSessionHandoffPlan{}, fmt.Errorf("%w: %v", ErrDaemonSessionRegistry, err)
	}
	return BuildDaemonSessionHandoffPlan(DaemonSessionHandoffConfig{
		CustodyPlan: custodyPlan,
		Session:     record,
		AsOf:        asOf,
	})
}

func (r *DaemonSessionRegistry) HandleAuthorizedRequest(ctx context.Context, req DaemonProtocolRequest, handshake DaemonProtocolPeerHandshake) DaemonProtocolResponse {
	if r == nil {
		return daemonSessionRegistryErrorResponse(req, "", "registry is required")
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			return daemonSessionRegistryErrorResponse(req, "", "request context canceled: %v", ctx.Err())
		default:
		}
	}
	if err := ValidateDaemonProtocolRequest(req); err != nil {
		return daemonSessionRegistryErrorResponse(req, "", "invalid authorized request: %v", err)
	}
	if err := validateDaemonSessionRegistryHandshake(handshake); err != nil {
		return daemonSessionRegistryErrorResponse(req, "", "%v", err)
	}

	switch req.Method {
	case DaemonProtocolMethodHealth:
		return DefaultDaemonAuthorizedProtocolResponse(req, handshake)
	case DaemonProtocolMethodRegisterSession:
		return r.handleRegisterSession(req, handshake)
	case DaemonProtocolMethodSessionStatus:
		return r.handleSessionStatus(req, handshake)
	case DaemonProtocolMethodEndSession:
		return r.handleEndSession(req, handshake)
	default:
		return daemonSessionRegistryErrorResponse(req, "", "unsupported method %q", req.Method)
	}
}

func (r *DaemonSessionRegistry) handleRegisterSession(req DaemonProtocolRequest, handshake DaemonProtocolPeerHandshake) DaemonProtocolResponse {
	register := req.RegisterSession
	if register == nil {
		return daemonSessionRegistryErrorResponse(req, "", "register_session payload is required")
	}
	now := r.currentTime()
	sessionID := strings.TrimSpace(register.SessionID)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions == nil {
		r.sessions = make(map[string]DaemonSessionRecord)
	}
	if existing, ok := r.sessions[sessionID]; ok {
		status := existing.Status(now)
		if status == DaemonSessionStatusActive {
			return daemonSessionRegistryErrorResponse(req, status, "session %q is already active", sessionID)
		}
	} else {
		r.pruneInactiveSessionsLocked(now)
		if len(r.sessions) >= r.effectiveMaxSessions() {
			return daemonSessionRegistryErrorResponse(req, DaemonSessionStatusCapacityExceeded, "session registry capacity exceeded: max active sessions is %d", r.effectiveMaxSessions())
		}
	}
	if r.nextRegistrationGeneration == ^uint64(0) {
		return daemonSessionRegistryErrorResponse(req, DaemonSessionStatusCapacityExceeded, "session registration generation space exhausted")
	}
	r.nextRegistrationGeneration++

	record := DaemonSessionRecord{
		SessionID:                 sessionID,
		MissionID:                 strings.TrimSpace(register.MissionID),
		TraceID:                   strings.TrimSpace(register.TraceID),
		RegistrationGeneration:    r.nextRegistrationGeneration,
		RootPID:                   register.RootPID,
		RootProcessStartTimeTicks: register.RootProcessStartTimeTicks,
		PIDNamespaceID:            register.PIDNamespaceID,
		CgroupID:                  register.CgroupID,
		EventClasses:              append([]string(nil), register.EventClasses...),
		HandoffMetadata:           copyDaemonSessionHandoffMetadata(register.HandoffMetadata),
		RegisteredAt:              now,
		ExpiresAt:                 now.Add(time.Duration(register.TTLSeconds) * time.Second),
		PeerUID:                   handshake.Authorization.UID,
		PeerGID:                   handshake.Authorization.GID,
		PeerPID:                   handshake.Authorization.PID,
		PeerProcessStartTimeTicks: handshake.ProcessStartTimeTicks,
		CredentialSource:          handshake.CredentialSource,
		SocketPath:                cleanPath(handshake.SocketPath),
	}
	r.sessions[sessionID] = record
	return DaemonProtocolResponse{
		ProtocolVersion: DaemonProtocolVersion,
		OK:              true,
		Method:          req.Method,
		SessionID:       sessionID,
		Status:          DaemonSessionStatusRegistered,
	}
}

func (r *DaemonSessionRegistry) handleSessionStatus(req DaemonProtocolRequest, handshake DaemonProtocolPeerHandshake) DaemonProtocolResponse {
	sessionID := daemonProtocolRequestSessionID(req)
	record, status, err := r.lookupActiveSession(sessionID, r.currentTime())
	if err != nil {
		return daemonSessionRegistryErrorResponse(req, status, "%v", err)
	}
	if !daemonSessionRegistryPeerOwnsRecord(record, handshake) {
		return daemonSessionRegistryErrorResponse(req, status, "session %q is owned by a different peer", sessionID)
	}
	return DaemonProtocolResponse{
		ProtocolVersion: DaemonProtocolVersion,
		OK:              true,
		Method:          req.Method,
		SessionID:       record.SessionID,
		Status:          status,
	}
}

func (r *DaemonSessionRegistry) handleEndSession(req DaemonProtocolRequest, handshake DaemonProtocolPeerHandshake) DaemonProtocolResponse {
	sessionID := daemonProtocolRequestSessionID(req)
	now := r.currentTime()
	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.sessions[strings.TrimSpace(sessionID)]
	if !ok {
		return daemonSessionRegistryErrorResponse(req, DaemonSessionStatusNotFound, "session %q not found", sessionID)
	}
	status := record.Status(now)
	if status != DaemonSessionStatusActive {
		return daemonSessionRegistryErrorResponse(req, status, "session %q is not active: %s", sessionID, status)
	}
	if !daemonSessionRegistryPeerOwnsRecord(record, handshake) {
		return daemonSessionRegistryErrorResponse(req, status, "session %q is owned by a different peer", sessionID)
	}
	record.EndedAt = now
	r.sessions[record.SessionID] = record
	return DaemonProtocolResponse{
		ProtocolVersion: DaemonProtocolVersion,
		OK:              true,
		Method:          req.Method,
		SessionID:       record.SessionID,
		Status:          DaemonSessionStatusEnded,
	}
}

func daemonSessionRegistryPeerOwnsRecord(record DaemonSessionRecord, handshake DaemonProtocolPeerHandshake) bool {
	if record.PeerProcessStartTimeTicks == 0 || handshake.ProcessStartTimeTicks == 0 || handshake.Authorization.ProcessStartTimeTicks == 0 {
		return false
	}
	return record.PeerUID == handshake.Authorization.UID &&
		record.PeerGID == handshake.Authorization.GID &&
		record.PeerPID == handshake.Authorization.PID &&
		record.PeerProcessStartTimeTicks == handshake.ProcessStartTimeTicks &&
		record.PeerProcessStartTimeTicks == handshake.Authorization.ProcessStartTimeTicks &&
		record.CredentialSource == handshake.CredentialSource
}

func daemonSessionRegistryDelegatedRootPeerOwnsRecord(record DaemonSessionRecord, observation DaemonSocketPeerObservation, authorization DaemonPeerAuthorization) bool {
	credentials := observation.Credentials
	if authorization.Verdict != DaemonPeerAuthorizationVerdictAllow ||
		record.RootProcessStartTimeTicks == 0 ||
		credentials.ProcessStartTimeTicks == 0 ||
		authorization.ProcessStartTimeTicks == 0 {
		return false
	}
	if credentials.UID != authorization.UID ||
		credentials.GID != authorization.GID ||
		credentials.PID != authorization.PID ||
		credentials.ProcessStartTimeTicks != authorization.ProcessStartTimeTicks {
		return false
	}
	return record.RootPID == authorization.PID &&
		record.RootProcessStartTimeTicks == authorization.ProcessStartTimeTicks &&
		record.CredentialSource == observation.CredentialSource
}

func (r *DaemonSessionRegistry) currentTime() time.Time {
	if r == nil || r.now == nil {
		return time.Now()
	}
	return r.now()
}

func (r *DaemonSessionRegistry) effectiveMaxSessions() int {
	if r == nil || r.maxSessions <= 0 {
		return DefaultDaemonSessionRegistryMaxSessions
	}
	return r.maxSessions
}

func (r *DaemonSessionRegistry) pruneInactiveSessionsLocked(now time.Time) {
	for sessionID, record := range r.sessions {
		if record.Status(now) != DaemonSessionStatusActive {
			delete(r.sessions, sessionID)
		}
	}
}

func (r *DaemonSessionRegistry) lookupActiveSession(sessionID string, now time.Time) (DaemonSessionRecord, string, error) {
	if r == nil {
		return DaemonSessionRecord{}, "", fmt.Errorf("registry is required")
	}
	normalizedSessionID := strings.TrimSpace(sessionID)
	if normalizedSessionID == "" {
		return DaemonSessionRecord{}, "", fmt.Errorf("session_id is required")
	}
	r.mu.RLock()
	record, ok := r.sessions[normalizedSessionID]
	r.mu.RUnlock()
	if !ok {
		return DaemonSessionRecord{}, DaemonSessionStatusNotFound, fmt.Errorf("session %q not found", normalizedSessionID)
	}
	status := record.Status(now)
	if status != DaemonSessionStatusActive {
		return DaemonSessionRecord{}, status, fmt.Errorf("session %q is not active: %s", normalizedSessionID, status)
	}
	return copyDaemonSessionRecord(record), status, nil
}

func validateDaemonSessionRegistryHandshake(handshake DaemonProtocolPeerHandshake) error {
	if handshake.ProtocolVersion != DaemonProtocolVersion {
		return fmt.Errorf("%w: peer handshake protocol version is required", ErrDaemonSessionRegistry)
	}
	if handshake.Authorization.Verdict != DaemonPeerAuthorizationVerdictAllow {
		return fmt.Errorf("%w: peer handshake must have allow verdict before session handling", ErrDaemonSessionRegistry)
	}
	if handshake.Authorization.PID == 0 {
		return fmt.Errorf("%w: peer handshake must include observed peer pid", ErrDaemonSessionRegistry)
	}
	if handshake.ProcessStartTimeTicks == 0 || handshake.Authorization.ProcessStartTimeTicks == 0 {
		return fmt.Errorf("%w: peer handshake must include observed peer process start time", ErrDaemonSessionRegistry)
	}
	if handshake.ProcessStartTimeTicks != handshake.Authorization.ProcessStartTimeTicks {
		return fmt.Errorf("%w: peer handshake process start time must match authorization evidence", ErrDaemonSessionRegistry)
	}
	if strings.TrimSpace(handshake.CredentialSource) == "" {
		return fmt.Errorf("%w: peer handshake credential source is required", ErrDaemonSessionRegistry)
	}
	return nil
}

func daemonSessionRegistryErrorResponse(req DaemonProtocolRequest, status string, format string, args ...any) DaemonProtocolResponse {
	return DaemonProtocolResponse{
		ProtocolVersion: DaemonProtocolVersion,
		OK:              false,
		Method:          req.Method,
		SessionID:       strings.TrimSpace(daemonProtocolRequestSessionID(req)),
		Status:          status,
		Error:           fmt.Errorf("%w: "+format, append([]any{ErrDaemonSessionRegistry}, args...)...).Error(),
	}
}

func copyDaemonSessionRecord(record DaemonSessionRecord) DaemonSessionRecord {
	record.EventClasses = append([]string(nil), record.EventClasses...)
	record.HandoffMetadata = copyDaemonSessionHandoffMetadata(record.HandoffMetadata)
	return record
}

func copyDaemonSessionHandoffMetadata(metadata map[string]any) map[string]any {
	if len(metadata) == 0 {
		return map[string]any{}
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		copy := make(map[string]any, len(metadata))
		for key, value := range metadata {
			copy[key] = value
		}
		return copy
	}
	var copy map[string]any
	if err := json.Unmarshal(data, &copy); err != nil {
		copy = make(map[string]any, len(metadata))
		for key, value := range metadata {
			copy[key] = value
		}
	}
	return copy
}
