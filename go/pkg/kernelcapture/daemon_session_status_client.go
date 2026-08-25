package kernelcapture

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const DefaultDaemonSessionStatusClientMaxResponseBytes = DefaultDaemonAcceptLoopMaxRequestBytes

// SendDaemonSessionStatusRequest is a local Unix-socket client helper for the
// session_status daemon protocol method. It builds a validated JSON-line request,
// sends it to the daemon control socket, and decodes only the narrow
// DaemonProtocolResponse. It never expands the client-visible protocol and never
// exposes internal daemon snapshot data.
//
// The helper validates socketPath and sessionID before dialing: empty or
// whitespace-only values are rejected before any I/O.
func SendDaemonSessionStatusRequest(socketPath string, sessionID string) (DaemonProtocolResponse, error) {
	if strings.TrimSpace(socketPath) == "" {
		return DaemonProtocolResponse{}, fmt.Errorf("%w: daemon socket path is required", ErrDaemonProtocol)
	}
	if strings.TrimSpace(sessionID) == "" {
		return DaemonProtocolResponse{}, fmt.Errorf("%w: session_status session_id is required", ErrDaemonProtocol)
	}

	req := DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodSessionStatus,
		SessionStatus:   &DaemonSessionStatusRequest{SessionID: sessionID},
	}
	encoded, err := EncodeDaemonProtocolRequest(req)
	if err != nil {
		return DaemonProtocolResponse{}, fmt.Errorf("kernelcapture: session_status client encode request: %w", err)
	}

	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return DaemonProtocolResponse{}, fmt.Errorf("kernelcapture: session_status client dial unix socket: %w", err)
	}
	defer conn.Close()

	if err := conn.SetWriteDeadline(time.Now().Add(daemonUnixSocketReadDeadline)); err != nil {
		return DaemonProtocolResponse{}, fmt.Errorf("kernelcapture: session_status client set write deadline: %w", err)
	}
	if _, err := conn.Write(encoded); err != nil {
		return DaemonProtocolResponse{}, fmt.Errorf("kernelcapture: session_status client write request: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(daemonUnixSocketReadDeadline)); err != nil {
		return DaemonProtocolResponse{}, fmt.Errorf("kernelcapture: session_status client set read deadline: %w", err)
	}
	line, err := bufio.NewReader(io.LimitReader(conn, DefaultDaemonSessionStatusClientMaxResponseBytes+1)).ReadBytes('\n')
	if int64(len(line)) > DefaultDaemonSessionStatusClientMaxResponseBytes {
		return DaemonProtocolResponse{}, fmt.Errorf("kernelcapture: session_status client response exceeds %d bytes", DefaultDaemonSessionStatusClientMaxResponseBytes)
	}
	if err != nil {
		return DaemonProtocolResponse{}, fmt.Errorf("kernelcapture: session_status client read response: %w", err)
	}

	response, err := DecodeDaemonProtocolResponse(line)
	if err != nil {
		return DaemonProtocolResponse{}, fmt.Errorf("kernelcapture: session_status client decode response: %w", err)
	}
	if !response.OK {
		return response, fmt.Errorf("kernelcapture: session_status request failed: %s", response.Error)
	}
	return response, nil
}
