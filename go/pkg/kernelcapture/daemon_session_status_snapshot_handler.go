package kernelcapture

import (
	"context"
)

// DaemonSessionStatusSnapshotHandler is a DaemonAuthorizedProtocolHandler that routes
// register_session, end_session, and health requests to the underlying
// DaemonSessionRegistry, and routes session_status requests through
// HandleAuthorizedSessionStatusSnapshot so that a daemon-internal snapshot is
// built and retained in the sink while the client receives only the narrow
// DaemonProtocolResponse.
type DaemonSessionStatusSnapshotHandler struct {
	registry *DaemonSessionRegistry
	custody  DaemonCustodyPlan
	sink     *DaemonSessionStatusSnapshotSink
}

// NewDaemonSessionStatusSnapshotHandler returns a handler that wraps the given registry
// and custody plan. Every successful session_status request is retained in sink.
// Register/end/health are forwarded directly to the registry and never produce
// snapshots. A nil sink fails closed for session_status because this handler's
// contract is daemon-side snapshot retention, not best-effort observation.
func NewDaemonSessionStatusSnapshotHandler(
	registry *DaemonSessionRegistry,
	custody DaemonCustodyPlan,
	sink *DaemonSessionStatusSnapshotSink,
) *DaemonSessionStatusSnapshotHandler {
	return &DaemonSessionStatusSnapshotHandler{
		registry: registry,
		custody:  custody,
		sink:     sink,
	}
}

// HandleAuthorizedRequest satisfies the DaemonAuthorizedProtocolHandler
// signature. For session_status, it builds a daemon-internal snapshot, retains
// it in the sink on success, and returns only the narrow DaemonProtocolResponse.
// For all other methods, it forwards to registry.HandleAuthorizedRequest and
// never produces snapshot side-effects.
func (h *DaemonSessionStatusSnapshotHandler) HandleAuthorizedRequest(
	ctx context.Context,
	req DaemonProtocolRequest,
	handshake DaemonProtocolPeerHandshake,
) DaemonProtocolResponse {
	if h == nil {
		return daemonSessionRegistryErrorResponse(req, "", "session status snapshot handler is required")
	}
	if req.Method != DaemonProtocolMethodSessionStatus {
		return h.registry.HandleAuthorizedRequest(ctx, req, handshake)
	}
	if h.sink == nil {
		return daemonSessionRegistryErrorResponse(req, "", "session status snapshot sink is required")
	}

	snapshot, response := h.registry.HandleAuthorizedSessionStatusSnapshot(
		ctx, req, handshake, h.custody,
	)
	if response.OK {
		h.sink.Retain(snapshot)
	}
	return response
}
