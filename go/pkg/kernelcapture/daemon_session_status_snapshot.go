package kernelcapture

import (
	"context"
	"fmt"
	"time"
)

// DaemonSessionStatusSnapshot is internal daemon status/handoff data built from
// authorized registry state. It is deliberately not a daemon protocol payload:
// clients still receive only the narrow DaemonProtocolResponse.
type DaemonSessionStatusSnapshot struct {
	ProtocolResponse DaemonProtocolResponse
	Status           string
	Session          DaemonSessionRecord
	HandoffPlan      DaemonSessionHandoffPlan
	AsOf             time.Time
	ClaimBoundary    []string
	NotClaimed       []string
}

// BuildSessionStatusSnapshot projects an active session into a daemon-internal
// status snapshot plus the existing no-mutation handoff plan. It performs no
// filesystem writes, cgroup assignment, BPF map mutation, protocol expansion, or
// live enforcement.
func (r *DaemonSessionRegistry) BuildSessionStatusSnapshot(sessionID string, custodyPlan DaemonCustodyPlan) (DaemonSessionStatusSnapshot, error) {
	asOf := r.currentTime()
	record, status, err := r.lookupActiveSession(sessionID, asOf)
	if err != nil {
		return DaemonSessionStatusSnapshot{}, fmt.Errorf("%w: %v", ErrDaemonSessionRegistry, err)
	}
	return buildDaemonSessionStatusSnapshot(record, status, asOf, custodyPlan)
}

// HandleAuthorizedSessionStatusSnapshot validates the same authorized
// session_status boundary as HandleAuthorizedRequest, then returns a narrow
// client response plus daemon-internal snapshot data for local handler code. It
// does not handle register/end requests and never serializes the snapshot into
// the daemon protocol response.
func (r *DaemonSessionRegistry) HandleAuthorizedSessionStatusSnapshot(ctx context.Context, req DaemonProtocolRequest, handshake DaemonProtocolPeerHandshake, custodyPlan DaemonCustodyPlan) (DaemonSessionStatusSnapshot, DaemonProtocolResponse) {
	if r == nil {
		return DaemonSessionStatusSnapshot{}, daemonSessionRegistryErrorResponse(req, "", "registry is required")
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			return DaemonSessionStatusSnapshot{}, daemonSessionRegistryErrorResponse(req, "", "request context canceled: %v", ctx.Err())
		default:
		}
	}
	if err := ValidateDaemonProtocolRequest(req); err != nil {
		return DaemonSessionStatusSnapshot{}, daemonSessionRegistryErrorResponse(req, "", "invalid authorized request: %v", err)
	}
	if req.Method != DaemonProtocolMethodSessionStatus {
		return DaemonSessionStatusSnapshot{}, daemonSessionRegistryErrorResponse(req, "", "status snapshot requires a session_status request, got %q", req.Method)
	}
	if err := validateDaemonSessionRegistryHandshake(handshake); err != nil {
		return DaemonSessionStatusSnapshot{}, daemonSessionRegistryErrorResponse(req, "", "%v", err)
	}

	asOf := r.currentTime()
	record, status, err := r.lookupActiveSession(daemonProtocolRequestSessionID(req), asOf)
	if err != nil {
		return DaemonSessionStatusSnapshot{}, daemonSessionRegistryErrorResponse(req, status, "%v", err)
	}
	if !daemonSessionRegistryPeerOwnsRecord(record, handshake) {
		return DaemonSessionStatusSnapshot{}, daemonSessionRegistryErrorResponse(req, status, "session %q is owned by a different peer", daemonProtocolRequestSessionID(req))
	}
	snapshot, err := buildDaemonSessionStatusSnapshot(record, status, asOf, custodyPlan)
	if err != nil {
		return DaemonSessionStatusSnapshot{}, daemonSessionRegistryErrorResponse(req, status, "status snapshot handoff plan failed: %v", err)
	}
	return snapshot, snapshot.ProtocolResponse
}

func buildDaemonSessionStatusSnapshot(record DaemonSessionRecord, status string, asOf time.Time, custodyPlan DaemonCustodyPlan) (DaemonSessionStatusSnapshot, error) {
	record = copyDaemonSessionRecord(record)
	plan, err := BuildDaemonSessionHandoffPlan(DaemonSessionHandoffConfig{
		CustodyPlan: custodyPlan,
		Session:     record,
		AsOf:        asOf,
	})
	if err != nil {
		return DaemonSessionStatusSnapshot{}, err
	}
	response := DaemonProtocolResponse{
		ProtocolVersion: DaemonProtocolVersion,
		OK:              true,
		Method:          DaemonProtocolMethodSessionStatus,
		SessionID:       record.SessionID,
		Status:          status,
	}
	return DaemonSessionStatusSnapshot{
		ProtocolResponse: response,
		Status:           status,
		Session:          record,
		HandoffPlan:      plan,
		AsOf:             asOf,
		ClaimBoundary: []string{
			"internal daemon status snapshot combines active registry metadata with no-mutation handoff plan data",
			"client-visible daemon protocol response remains the narrow session_status status envelope",
			"snapshot data is derived from daemon-owned registry state and daemon custody paths",
		},
		NotClaimed: []string{
			"client-visible protocol expansion",
			"persistent daemon session-state management",
			"filesystem writes, cgroup assignment, BPF map mutation, or live enforcement",
			"production daemon readiness",
		},
	}, nil
}
