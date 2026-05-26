package kernelcapture

import (
	"errors"
	"fmt"
	"time"
)

const (
	DefaultDaemonAcceptLoopMaxRequestBytes          int64 = 64 * 1024
	MaxDaemonAcceptLoopRequestBytes                 int64 = 1024 * 1024
	DefaultDaemonAcceptLoopReadTimeout                    = 2 * time.Second
	MaxDaemonAcceptLoopReadTimeout                        = 30 * time.Second
	DefaultDaemonAcceptLoopMaxConcurrentConnections       = 32
	MaxDaemonAcceptLoopConcurrentConnections              = 1024
)

var ErrDaemonAcceptLoopPlan = errors.New("kernelcapture: invalid daemon accept-loop plan")

// DaemonAcceptLoopConfig is the dry-run contract input for a future daemon
// accept loop. It deliberately contains no listener or handler callbacks: this
// slice validates the invariants a later privileged daemon must satisfy before
// it binds a socket or handles traffic.
type DaemonAcceptLoopConfig struct {
	CustodyPlan              DaemonCustodyPlan
	PeerAuthorizationPolicy  DaemonPeerAuthorizationPolicy
	MaxRequestBytes          int64
	ReadTimeout              time.Duration
	MaxConcurrentConnections int
}

// DaemonAcceptLoopPlan is a structured no-mutation plan for the future local
// daemon accept loop. Every step is descriptive and must remain Executed=false in
// this scaffold; executing these steps belongs to a later reviewed daemon slice.
type DaemonAcceptLoopPlan struct {
	Mode                     string
	SocketPath               string
	CredentialSource         string
	MaxRequestBytes          int64
	ReadTimeout              time.Duration
	MaxConcurrentConnections int
	AllowedUIDs              []uint32
	AllowedGIDs              []uint32
	Steps                    []DaemonAcceptLoopStep
	ClaimBoundary            []string
	NotClaimed               []string
}

// DaemonAcceptLoopStep records one future accept-loop invariant without doing
// any socket, filesystem, daemon, process, or eBPF work.
type DaemonAcceptLoopStep struct {
	Name      string
	Executed  bool
	Rationale string
}

// DefaultDaemonAcceptLoopConfig returns bounded defaults for the future local
// accept loop. Callers still need an explicit peer authorization policy; an
// empty allowlist fails closed in BuildDaemonAcceptLoopPlan.
func DefaultDaemonAcceptLoopConfig(custodyPlan DaemonCustodyPlan, policy DaemonPeerAuthorizationPolicy) DaemonAcceptLoopConfig {
	return DaemonAcceptLoopConfig{
		CustodyPlan:              custodyPlan,
		PeerAuthorizationPolicy:  policy,
		MaxRequestBytes:          DefaultDaemonAcceptLoopMaxRequestBytes,
		ReadTimeout:              DefaultDaemonAcceptLoopReadTimeout,
		MaxConcurrentConnections: DefaultDaemonAcceptLoopMaxConcurrentConnections,
	}
}

// BuildDaemonAcceptLoopPlan validates the accept-loop contract and returns a
// dry-run plan only. It does not bind/listen/accept sockets, install/start a
// daemon, perform SO_PEERCRED itself, create directories, pin eBPF maps, or
// expose any service.
func BuildDaemonAcceptLoopPlan(cfg DaemonAcceptLoopConfig) (DaemonAcceptLoopPlan, error) {
	if err := validateDaemonAcceptLoopConfig(cfg); err != nil {
		return DaemonAcceptLoopPlan{}, err
	}

	allowedUIDs := append([]uint32(nil), cfg.PeerAuthorizationPolicy.AllowedUIDs...)
	allowedGIDs := append([]uint32(nil), cfg.PeerAuthorizationPolicy.AllowedGIDs...)
	return DaemonAcceptLoopPlan{
		Mode:                     DaemonCustodyModeLocalOnlyScaffold,
		SocketPath:               cleanPath(cfg.CustodyPlan.SocketPath),
		CredentialSource:         DaemonPeerCredentialSourceLinuxSOPeerCred,
		MaxRequestBytes:          cfg.MaxRequestBytes,
		ReadTimeout:              cfg.ReadTimeout,
		MaxConcurrentConnections: cfg.MaxConcurrentConnections,
		AllowedUIDs:              allowedUIDs,
		AllowedGIDs:              allowedGIDs,
		Steps: []DaemonAcceptLoopStep{
			{
				Name:      "run_read_only_daemon_preflight",
				Rationale: "future daemon bind must be preceded by read-only custody preflight over daemon-owned paths",
			},
			{
				Name:      "bind_validated_local_unix_socket",
				Rationale: "future daemon may bind only the validated custody-plan socket path; this dry-run plan does not bind",
			},
			{
				Name:      "accept_bounded_local_connection",
				Rationale: "future loop must bound concurrency before accepting local clients; this dry-run plan does not accept",
			},
			{
				Name:      "observe_os_peer_credentials",
				Rationale: "each accepted connection must derive peer identity from the OS credential source before request handling",
			},
			{
				Name:      "decode_bounded_json_line_request",
				Rationale: "future loop must enforce max request bytes and read timeout before protocol decoding",
			},
			{
				Name:      "authorize_request_and_peer",
				Rationale: "valid protocol requests are handled only after daemon-observed peer credentials match an explicit allowlist",
			},
			{
				Name:      "dispatch_validated_protocol_method",
				Rationale: "future handlers must preserve protocol validation, custody context, and fail-closed errors",
			},
		},
		ClaimBoundary: []string{
			"dry-run accept-loop contract only; no socket is opened, bound, listened on, or accepted",
			"future bind/listen must use the validated daemon custody plan socket path after read-only preflight",
			"each future accepted connection must be joined to OS-observed peer credentials before handling",
			"request size, read timeout, and concurrency are bounded before runtime implementation",
		},
		NotClaimed: []string{
			"socket server/listener implementation",
			"daemon accept-loop wiring around SO_PEERCRED observations",
			"daemon install/start or service exposure",
			"production daemon readiness",
			"live enforcement or session state management",
		},
	}, nil
}

func validateDaemonAcceptLoopConfig(cfg DaemonAcceptLoopConfig) error {
	if err := validateDaemonPeerHandshakeCustodyPlan(cfg.CustodyPlan); err != nil {
		return acceptLoopPlanError("custody plan is invalid: %v", err)
	}
	if len(cfg.PeerAuthorizationPolicy.AllowedUIDs) == 0 && len(cfg.PeerAuthorizationPolicy.AllowedGIDs) == 0 {
		return acceptLoopPlanError("peer authorization policy requires at least one allowed uid or gid")
	}
	if cfg.MaxRequestBytes <= 0 || cfg.MaxRequestBytes > MaxDaemonAcceptLoopRequestBytes {
		return acceptLoopPlanError("max request bytes must be between 1 and %d", MaxDaemonAcceptLoopRequestBytes)
	}
	if cfg.ReadTimeout <= 0 || cfg.ReadTimeout > MaxDaemonAcceptLoopReadTimeout {
		return acceptLoopPlanError("read timeout must be between 1ns and %s", MaxDaemonAcceptLoopReadTimeout)
	}
	if cfg.MaxConcurrentConnections <= 0 || cfg.MaxConcurrentConnections > MaxDaemonAcceptLoopConcurrentConnections {
		return acceptLoopPlanError("max concurrent connections must be between 1 and %d", MaxDaemonAcceptLoopConcurrentConnections)
	}
	return nil
}

func acceptLoopPlanError(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrDaemonAcceptLoopPlan}, args...)...)
}
