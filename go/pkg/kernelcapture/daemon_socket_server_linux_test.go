//go:build linux

package kernelcapture

import (
	"context"
	"os"
	"testing"
)

func TestDaemonUnixSocketServerDefaultLinuxPeerCredentialsAuthorizeCurrentUID(t *testing.T) {
	t.Parallel()

	handshakes := make(chan DaemonProtocolPeerHandshake, 1)
	server, cancel := startDaemonUnixSocketServerForTest(t, daemonSocketServerTestOptions{
		policy: DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{uint32(os.Getuid())}},
		handleAuthorizedRequest: func(_ context.Context, req DaemonProtocolRequest, handshake DaemonProtocolPeerHandshake) DaemonProtocolResponse {
			handshakes <- handshake
			return DefaultDaemonAuthorizedProtocolResponse(req, handshake)
		},
	})
	defer cancel()

	response := sendDaemonUnixSocketRequest(t, server.SocketPath(), daemonHealthRequest(t))
	if !response.OK {
		t.Fatalf("response ok = false, error = %q", response.Error)
	}

	select {
	case handshake := <-handshakes:
		if handshake.CredentialSource != DaemonPeerCredentialSourceLinuxSOPeerCred {
			t.Fatalf("credential source = %q, want %q", handshake.CredentialSource, DaemonPeerCredentialSourceLinuxSOPeerCred)
		}
		if handshake.Authorization.UID != uint32(os.Getuid()) {
			t.Fatalf("authorized uid = %d, want current uid %d", handshake.Authorization.UID, os.Getuid())
		}
		if handshake.Authorization.Verdict != DaemonPeerAuthorizationVerdictAllow {
			t.Fatalf("authorization verdict = %q, want allow", handshake.Authorization.Verdict)
		}
	default:
		t.Fatalf("authorized handler did not record Linux peer handshake")
	}
}
