//go:build linux

package kernelcapture

import (
	"errors"
	"os"
	"testing"
)

func TestAuthorizeDaemonProtocolPeerFromAcceptedUnixConnection(t *testing.T) {
	t.Parallel()

	plan, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}

	request := DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodRegisterSession,
		RegisterSession: &DaemonRegisterSessionRequest{
			SessionID:    "session-1",
			RootPID:      123,
			EventClasses: []string{DaemonProtocolEventProcessLifecycle},
			TTLSeconds:   60,
		},
	}
	encoded, err := EncodeDaemonProtocolRequest(request)
	if err != nil {
		t.Fatalf("EncodeDaemonProtocolRequest returned error: %v", err)
	}

	accepted, client, cleanup := acceptedUnixConnPair(t)
	defer cleanup()
	writeUnixRequestAndClose(t, client, string(encoded))

	handshake, err := AuthorizeDaemonProtocolPeerFromAcceptedUnixConnection(
		accepted,
		DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{uint32(os.Getuid())}},
		plan,
	)
	if err != nil {
		t.Fatalf("AuthorizeDaemonProtocolPeerFromAcceptedUnixConnection returned error: %v", err)
	}
	if handshake.Authorization.Verdict != DaemonPeerAuthorizationVerdictAllow {
		t.Fatalf("authorization verdict = %q, want allow", handshake.Authorization.Verdict)
	}
	if handshake.SessionID != "session-1" {
		t.Fatalf("session id = %q, want session-1", handshake.SessionID)
	}
	if handshake.SocketPath != plan.SocketPath {
		t.Fatalf("socket path = %q, want %q", handshake.SocketPath, plan.SocketPath)
	}
	if handshake.CredentialSource != DaemonPeerCredentialSourceLinuxSOPeerCred {
		t.Fatalf("credential source = %q, want %q", handshake.CredentialSource, DaemonPeerCredentialSourceLinuxSOPeerCred)
	}
}

func TestAuthorizeDaemonProtocolPeerFromAcceptedUnixConnectionFailsClosedForInvalidCustodyPlan(t *testing.T) {
	t.Parallel()

	plan, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	plan.RunDir = "/tmp"

	request := DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodRegisterSession,
		RegisterSession: &DaemonRegisterSessionRequest{
			SessionID:    "session-1",
			RootPID:      123,
			EventClasses: []string{DaemonProtocolEventProcessLifecycle},
			TTLSeconds:   60,
		},
	}
	encoded, err := EncodeDaemonProtocolRequest(request)
	if err != nil {
		t.Fatalf("EncodeDaemonProtocolRequest returned error: %v", err)
	}

	accepted, client, cleanup := acceptedUnixConnPair(t)
	defer cleanup()
	writeUnixRequestAndClose(t, client, string(encoded))

	_, err = AuthorizeDaemonProtocolPeerFromAcceptedUnixConnection(
		accepted,
		DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{uint32(os.Getuid())}},
		plan,
	)
	if err == nil {
		t.Fatalf("expected custody plan failure")
	}
	if !errors.Is(err, ErrDaemonSocketPeerObservation) {
		t.Fatalf("expected ErrDaemonSocketPeerObservation, got %v", err)
	}
}
