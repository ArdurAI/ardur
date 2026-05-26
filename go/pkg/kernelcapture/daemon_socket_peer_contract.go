package kernelcapture

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	// DaemonPeerCredentialSourceLinuxSOPeerCred names the only local peer
	// credential source currently accepted by the daemon protocol contract. A
	// future socket server must derive it from the kernel, not from client JSON.
	DaemonPeerCredentialSourceLinuxSOPeerCred = "linux_so_peercred"

	// maxDaemonProtocolLineSize caps the number of bytes the daemon will read
	// from a Unix socket before rejecting the request. Unix-domain datagrams
	// are bounded by the kernel, but a malicious or malfunctioning client on a
	// stream-oriented socket could send gigabytes without a newline.
	maxDaemonProtocolLineSize = 64 * 1024

	// daemonUnixSocketReadDeadline is the per-read deadline applied before each
	// bufio read on an accepted Unix socket connection. A client that opens a
	// connection and never sends data (or drips bytes slowly) must not block a
	// daemon goroutine indefinitely.
	daemonUnixSocketReadDeadline = 10 * time.Second
)

var ErrDaemonSocketPeerObservation = errors.New("kernelcapture: invalid daemon socket peer observation")

// DaemonSocketPeerObservation is the daemon-owned evidence that must be paired
// with a decoded protocol request before any future socket server handles it.
//
// This is a contract type only: it does not open, bind, listen on, accept, or
// inspect a Unix socket. Platform-specific code, such as the Linux
// ObserveLinuxUnixPeerCredentials seam, is responsible for populating
// Credentials from an OS peer-credential API such as SO_PEERCRED.
type DaemonSocketPeerObservation struct {
	Credentials      DaemonObservedPeerCredentials
	CredentialSource string
	SocketPath       string
}

// DaemonProtocolPeerHandshake records the deterministic join between a valid
// launch-wrapper request and daemon-observed local peer credentials. It is safe
// to include in review/debug reports because it contains bounded local IDs and
// explicit non-claims, not protocol payloads or secrets.
type DaemonProtocolPeerHandshake struct {
	ProtocolVersion  string
	Method           string
	SessionID        string
	SocketPath       string
	CredentialSource string
	Authorization    DaemonPeerAuthorization
	ClaimBoundary    []string
	NotClaimed       []string
}

// AuthorizeDaemonProtocolPeer validates a protocol request, validates the
// daemon-observed peer observation against the dry-run custody plan, and applies
// the explicit UID/GID allowlist before a future daemon handles the request.
//
// This function is intentionally no-mutation contract code. It does not bind or
// accept a socket, retrieve SO_PEERCRED itself, install/start a daemon, inspect
// process trees, or trust client-supplied peer identity.
func AuthorizeDaemonProtocolPeer(req DaemonProtocolRequest, observation DaemonSocketPeerObservation, policy DaemonPeerAuthorizationPolicy, plan DaemonCustodyPlan) (DaemonProtocolPeerHandshake, error) {
	if err := ValidateDaemonProtocolRequest(req); err != nil {
		return DaemonProtocolPeerHandshake{}, err
	}
	if err := validateDaemonSocketPeerObservation(observation, plan); err != nil {
		return DaemonProtocolPeerHandshake{}, err
	}
	authorization, err := AuthorizeObservedDaemonPeer(observation.Credentials, policy)
	if err != nil {
		return DaemonProtocolPeerHandshake{}, err
	}
	return DaemonProtocolPeerHandshake{
		ProtocolVersion:  req.ProtocolVersion,
		Method:           req.Method,
		SessionID:        daemonProtocolRequestSessionID(req),
		SocketPath:       cleanPath(observation.SocketPath),
		CredentialSource: observation.CredentialSource,
		Authorization:    authorization,
		ClaimBoundary: []string{
			"protocol request is joined to daemon-observed local peer credentials before handling",
			"peer identity must come from an OS credential source such as linux SO_PEERCRED, never client JSON",
			"peer authorization is validated against the daemon custody plan and explicit UID/GID policy before handling",
		},
		NotClaimed: []string{
			"production daemon readiness",
			"daemon install/start or privileged filesystem mutation",
			"privileged eBPF loading, map pinning, or kernel capture",
			"daemon-managed cgroups or session lifecycle enforcement",
		},
	}, nil
}

// AuthorizeDaemonProtocolPeerFromAcceptedUnixConnection is the no-listen bridge
// from an already-accepted Unix socket connection into the peer authorization
// contract. It intentionally does not bind/listen/accept sockets, install/start
// a daemon, or mutate filesystem state.
//
// This helper decodes one protocol request from the accepted connection,
// observes peer credentials from the same connection, and then calls
// AuthorizeDaemonProtocolPeer.
func AuthorizeDaemonProtocolPeerFromAcceptedUnixConnection(conn *net.UnixConn, policy DaemonPeerAuthorizationPolicy, plan DaemonCustodyPlan) (DaemonProtocolPeerHandshake, error) {
	req, err := readDaemonProtocolRequestFromAcceptedUnixConnection(conn)
	if err != nil {
		return DaemonProtocolPeerHandshake{}, err
	}
	observation, err := ObserveLinuxUnixPeerCredentials(conn, plan.SocketPath)
	if err != nil {
		return DaemonProtocolPeerHandshake{}, fmt.Errorf("%w: peer credential retrieval failed: %v", ErrDaemonSocketPeerObservation, err)
	}
	return AuthorizeDaemonProtocolPeer(req, observation, policy, plan)
}

func readDaemonProtocolRequestFromAcceptedUnixConnection(conn *net.UnixConn) (DaemonProtocolRequest, error) {
	return readDaemonProtocolRequestFromAcceptedUnixConnectionWithLimits(conn, maxDaemonProtocolLineSize, daemonUnixSocketReadDeadline)
}

func readDaemonProtocolRequestFromAcceptedUnixConnectionWithLimits(conn *net.UnixConn, maxBytes int64, readTimeout time.Duration) (DaemonProtocolRequest, error) {
	if conn == nil {
		return DaemonProtocolRequest{}, fmt.Errorf("%w: accepted unix connection is required", ErrDaemonProtocol)
	}
	if maxBytes <= 0 {
		return DaemonProtocolRequest{}, fmt.Errorf("%w: max request bytes must be positive", ErrDaemonProtocol)
	}
	if readTimeout <= 0 {
		return DaemonProtocolRequest{}, fmt.Errorf("%w: read timeout must be positive", ErrDaemonProtocol)
	}
	if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return DaemonProtocolRequest{}, fmt.Errorf("%w: set read deadline: %v", ErrDaemonProtocol, err)
	}
	raw, err := readUnixSocketLine(conn, maxBytes)
	if err != nil {
		return DaemonProtocolRequest{}, err
	}
	return DecodeDaemonProtocolRequest(raw)
}

func readUnixSocketLine(conn *net.UnixConn, maxBytes int64) ([]byte, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: accepted unix connection is required", ErrDaemonProtocol)
	}
	limited := io.LimitReader(conn, maxBytes+1)
	reader := bufio.NewReader(limited)
	data, err := reader.ReadString('\n')
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%w: protocol request exceeds %d bytes", ErrDaemonProtocol, maxBytes)
	}
	if err != nil {
		if errors.Is(err, io.EOF) {
			if strings.TrimSpace(data) == "" {
				return nil, fmt.Errorf("%w: protocol request is required", ErrDaemonProtocol)
			}
			return []byte(data), nil
		}
		return nil, fmt.Errorf("%w: read protocol request: %v", ErrDaemonProtocol, err)
	}
	if strings.TrimSpace(data) == "" {
		return nil, fmt.Errorf("%w: protocol request is required", ErrDaemonProtocol)
	}
	return []byte(data), nil
}

func validateDaemonSocketPeerObservation(observation DaemonSocketPeerObservation, plan DaemonCustodyPlan) error {
	if err := validateDaemonPeerHandshakeCustodyPlan(plan); err != nil {
		return err
	}
	if strings.TrimSpace(observation.CredentialSource) == "" {
		return fmt.Errorf("%w: credential source is required", ErrDaemonSocketPeerObservation)
	}
	if observation.CredentialSource != DaemonPeerCredentialSourceLinuxSOPeerCred {
		return fmt.Errorf("%w: unsupported credential source %q", ErrDaemonSocketPeerObservation, observation.CredentialSource)
	}
	observedSocketPath := cleanPath(observation.SocketPath)
	if observedSocketPath == "" {
		return fmt.Errorf("%w: socket path is required", ErrDaemonSocketPeerObservation)
	}
	if observedSocketPath != cleanPath(plan.SocketPath) {
		return fmt.Errorf("%w: socket path must match daemon custody plan", ErrDaemonSocketPeerObservation)
	}
	return nil
}

func validateDaemonPeerHandshakeCustodyPlan(plan DaemonCustodyPlan) error {
	if plan.Mode != DaemonCustodyModeLocalOnlyScaffold {
		return fmt.Errorf("%w: daemon custody plan must be the local-only scaffold", ErrDaemonSocketPeerObservation)
	}
	for _, item := range []struct {
		field string
		value string
	}{
		{field: "config_path", value: plan.ConfigPath},
		{field: "state_dir", value: plan.StateDir},
		{field: "run_dir", value: plan.RunDir},
		{field: "socket_path", value: plan.SocketPath},
		{field: "bpffs_dir", value: plan.BPFFSDir},
		{field: "ringbuf_map_path", value: plan.RingbufMapPath},
		{field: "producer_name", value: plan.ProducerName},
		{field: "producer_version", value: plan.ProducerVersion},
	} {
		if strings.TrimSpace(item.value) == "" {
			return fmt.Errorf("%w: daemon custody plan %s is required", ErrDaemonSocketPeerObservation, item.field)
		}
	}
	cfg := DaemonCustodyConfig{
		ConfigPath:      plan.ConfigPath,
		StateDir:        plan.StateDir,
		RunDir:          plan.RunDir,
		SocketPath:      plan.SocketPath,
		BPFFSDir:        plan.BPFFSDir,
		RingbufMapPath:  plan.RingbufMapPath,
		OwnerUID:        plan.OwnerUID,
		OwnerGID:        plan.OwnerGID,
		ConfigMode:      0o600,
		StateDirMode:    0o700,
		RunDirMode:      0o700,
		BPFFSDirMode:    0o700,
		SocketMode:      0o660,
		ProducerName:    plan.ProducerName,
		ProducerVersion: plan.ProducerVersion,
	}
	if err := validateDaemonCustodyConfig(normalizeDaemonCustodyConfig(cfg)); err != nil {
		return fmt.Errorf("%w: daemon custody plan is not valid: %v", ErrDaemonSocketPeerObservation, err)
	}
	return nil
}

func daemonProtocolRequestSessionID(req DaemonProtocolRequest) string {
	switch req.Method {
	case DaemonProtocolMethodRegisterSession:
		if req.RegisterSession != nil {
			return req.RegisterSession.SessionID
		}
	case DaemonProtocolMethodEndSession:
		if req.EndSession != nil {
			return req.EndSession.SessionID
		}
	case DaemonProtocolMethodSessionStatus:
		if req.SessionStatus != nil {
			return req.SessionStatus.SessionID
		}
	}
	return ""
}
