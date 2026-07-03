package kernelcapture

import (
	"context"
	"net"
	"testing"
)

func TestSendDaemonHealthRequest_RoundTrips(t *testing.T) {
	t.Parallel()

	server, cancel := startDaemonUnixSocketServerForTest(t, daemonSocketServerTestOptions{
		policy: DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
		observePeer: func(_ *net.UnixConn, socketPath string) (DaemonSocketPeerObservation, error) {
			return DaemonSocketPeerObservation{
				Credentials:      DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 4321, ProcessStartTimeTicks: 800004},
				CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
				SocketPath:       socketPath,
			}, nil
		},
		handleAuthorizedRequest: func(_ context.Context, req DaemonProtocolRequest, handshake DaemonProtocolPeerHandshake) DaemonProtocolResponse {
			return DefaultDaemonAuthorizedProtocolResponse(req, handshake)
		},
	})
	defer cancel()

	resp, err := SendDaemonHealthRequest(server.SocketPath())
	if err != nil {
		t.Fatalf("SendDaemonHealthRequest returned error: %v", err)
	}
	if !resp.OK || resp.Method != DaemonProtocolMethodHealth {
		t.Fatalf("health client response = %#v", resp)
	}
}

func TestSendDaemonHealthRequest_RejectsEmptySocketPath(t *testing.T) {
	t.Parallel()
	_, err := SendDaemonHealthRequest("  ")
	if err == nil {
		t.Fatal("SendDaemonHealthRequest with empty socket path returned no error")
	}
}

func TestSendDaemonHealthRequest_UnavailableWhenSocketMissing(t *testing.T) {
	t.Parallel()
	_, err := SendDaemonHealthRequest("/nonexistent/path/to/socket.sock")
	if err == nil {
		t.Fatal("SendDaemonHealthRequest against a missing socket returned no error")
	}
}
