package kernelcapture

import (
	"context"
	"fmt"
	"time"
)

// NewSessionAwareHandler returns a DaemonAuthorizedProtocolHandler that
// dispatches health, register_session, end_session, and session_status to the
// provided SessionRegistry and Correlator.
func NewSessionAwareHandler(registry *SessionRegistry, correlator *Correlator) DaemonAuthorizedProtocolHandler {
	return func(_ context.Context, req DaemonProtocolRequest, handshake DaemonProtocolPeerHandshake) DaemonProtocolResponse {
		switch req.Method {
		case DaemonProtocolMethodHealth:
			return DaemonProtocolResponse{
				ProtocolVersion: DaemonProtocolVersion,
				OK:              true,
				Method:          req.Method,
				SessionID:       handshake.SessionID,
				Status:          fmt.Sprintf("healthy, %d active sessions", registry.ActiveCount()),
			}

		case DaemonProtocolMethodRegisterSession:
			if req.RegisterSession == nil {
				return DaemonProtocolResponse{
					ProtocolVersion: DaemonProtocolVersion,
					OK:              false,
					Method:          req.Method,
					SessionID:       handshake.SessionID,
					Error:           "register_session payload is required",
				}
			}
			now := time.Now()
			if err := registry.Register(*req.RegisterSession, now); err != nil {
				return DaemonProtocolResponse{
					ProtocolVersion: DaemonProtocolVersion,
					OK:              false,
					Method:          req.Method,
					SessionID:       req.RegisterSession.SessionID,
					Error:           err.Error(),
				}
			}
			if correlator != nil {
				correlator.RegisterReceipt(ToolReceipt{
					ReceiptID:               req.RegisterSession.SessionID,
					SessionID:               req.RegisterSession.SessionID,
					PID:                     req.RegisterSession.RootPID,
					PIDNamespaceID:          uint64(req.RegisterSession.PIDNamespaceID),
					CgroupID:                req.RegisterSession.CgroupID,
					ObservedAt:              now,
				})
			}
			return DaemonProtocolResponse{
				ProtocolVersion: DaemonProtocolVersion,
				OK:              true,
				Method:          req.Method,
				SessionID:       req.RegisterSession.SessionID,
				Status:          "registered",
			}

		case DaemonProtocolMethodEndSession:
			if req.EndSession == nil {
				return DaemonProtocolResponse{
					ProtocolVersion: DaemonProtocolVersion,
					OK:              false,
					Method:          req.Method,
					SessionID:       handshake.SessionID,
					Error:           "end_session payload is required",
				}
			}
			_ = registry.Unregister(req.EndSession.SessionID)
			return DaemonProtocolResponse{
				ProtocolVersion: DaemonProtocolVersion,
				OK:              true,
				Method:          req.Method,
				SessionID:       req.EndSession.SessionID,
				Status:          "ended",
			}

		case DaemonProtocolMethodSessionStatus:
			if req.SessionStatus == nil {
				return DaemonProtocolResponse{
					ProtocolVersion: DaemonProtocolVersion,
					OK:              false,
					Method:          req.Method,
					SessionID:       handshake.SessionID,
					Error:           "session_status payload is required",
				}
			}
			session, err := registry.Lookup(req.SessionStatus.SessionID)
			if err != nil {
				return DaemonProtocolResponse{
					ProtocolVersion: DaemonProtocolVersion,
					OK:              false,
					Method:          req.Method,
					SessionID:       req.SessionStatus.SessionID,
					Error:           err.Error(),
				}
			}
			return DaemonProtocolResponse{
				ProtocolVersion: DaemonProtocolVersion,
				OK:              true,
				Method:          req.Method,
				SessionID:       session.SessionID,
				Status:          fmt.Sprintf("active, root_pid=%d, ttl=%ds", session.RootPID, session.TTLSeconds),
			}

		default:
			return DaemonProtocolResponse{
				ProtocolVersion: DaemonProtocolVersion,
				OK:              false,
				Method:          req.Method,
				SessionID:       handshake.SessionID,
				Error:           fmt.Sprintf("unknown method: %s", req.Method),
			}
		}
	}
}
