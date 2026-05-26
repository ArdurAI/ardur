//go:build !linux

package kernelcapture

import (
	"errors"
	"strings"
	"testing"
)

func TestAuthorizeDaemonProtocolPeerFromAcceptedUnixConnectionUnsupportedOnNonLinux(t *testing.T) {
	t.Parallel()

	plan, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	request := DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodHealth,
		Health:          &DaemonHealthRequest{},
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
		DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{999}},
		plan,
	)
	if err == nil {
		t.Fatalf("expected unsupported-platform peer credential retrieval error")
	}
	if !errors.Is(err, ErrDaemonSocketPeerObservation) {
		t.Fatalf("expected ErrDaemonSocketPeerObservation, got %v", err)
	}
	if !strings.Contains(err.Error(), "peer credential retrieval failed") {
		t.Fatalf("expected peer credential retrieval failure message, got: %v", err)
	}
}
