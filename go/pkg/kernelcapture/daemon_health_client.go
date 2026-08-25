package kernelcapture

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const DefaultDaemonHealthClientMaxResponseBytes = DefaultDaemonAcceptLoopMaxRequestBytes

// SendDaemonHealthRequest is a local Unix-socket client helper for the health
// daemon protocol method. It mirrors SendDaemonSessionStatusRequest: build a
// validated JSON-line request, send it to the daemon control socket, and
// decode only the narrow DaemonProtocolResponse.
//
// ardur-sensor status uses this to report which enforcement tier is live
// (DaemonProtocolResponse.EnforcementTier) without needing any privilege
// beyond what the socket's peer-authorization policy already grants.
func SendDaemonHealthRequest(socketPath string) (DaemonProtocolResponse, error) {
	if strings.TrimSpace(socketPath) == "" {
		return DaemonProtocolResponse{}, fmt.Errorf("%w: daemon socket path is required", ErrDaemonProtocol)
	}

	req := DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodHealth,
		Health:          &DaemonHealthRequest{},
	}
	encoded, err := EncodeDaemonProtocolRequest(req)
	if err != nil {
		return DaemonProtocolResponse{}, fmt.Errorf("kernelcapture: health client encode request: %w", err)
	}

	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return DaemonProtocolResponse{}, fmt.Errorf("kernelcapture: health client dial unix socket: %w", err)
	}
	defer conn.Close()

	if err := conn.SetWriteDeadline(time.Now().Add(daemonUnixSocketReadDeadline)); err != nil {
		return DaemonProtocolResponse{}, fmt.Errorf("kernelcapture: health client set write deadline: %w", err)
	}
	if _, err := conn.Write(encoded); err != nil {
		return DaemonProtocolResponse{}, fmt.Errorf("kernelcapture: health client write request: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(daemonUnixSocketReadDeadline)); err != nil {
		return DaemonProtocolResponse{}, fmt.Errorf("kernelcapture: health client set read deadline: %w", err)
	}
	line, err := bufio.NewReader(io.LimitReader(conn, DefaultDaemonHealthClientMaxResponseBytes+1)).ReadBytes('\n')
	if int64(len(line)) > DefaultDaemonHealthClientMaxResponseBytes {
		return DaemonProtocolResponse{}, fmt.Errorf("kernelcapture: health client response exceeds %d bytes", DefaultDaemonHealthClientMaxResponseBytes)
	}
	if err != nil {
		return DaemonProtocolResponse{}, fmt.Errorf("kernelcapture: health client read response: %w", err)
	}

	response, err := DecodeDaemonProtocolResponse(line)
	if err != nil {
		return DaemonProtocolResponse{}, fmt.Errorf("kernelcapture: health client decode response: %w", err)
	}
	if !response.OK {
		return response, fmt.Errorf("kernelcapture: health request failed: %s", response.Error)
	}
	return response, nil
}
