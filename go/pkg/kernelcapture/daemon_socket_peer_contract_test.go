package kernelcapture

import (
	"errors"
	"strings"
	"testing"
)

func TestAuthorizeDaemonProtocolPeerBindsObservedCredentialsToRequest(t *testing.T) {
	t.Parallel()

	plan, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	req := DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodRegisterSession,
		RegisterSession: &DaemonRegisterSessionRequest{
			SessionID:    "session-1",
			RootPID:      1234,
			EventClasses: []string{DaemonProtocolEventProcessLifecycle},
			TTLSeconds:   60,
		},
	}
	observation := DaemonSocketPeerObservation{
		Credentials:      DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 4321},
		CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
		SocketPath:       plan.SocketPath,
	}
	policy := DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}}

	handshake, err := AuthorizeDaemonProtocolPeer(req, observation, policy, plan)
	if err != nil {
		t.Fatalf("AuthorizeDaemonProtocolPeer returned error: %v", err)
	}
	if handshake.Method != DaemonProtocolMethodRegisterSession {
		t.Fatalf("method = %q, want register_session", handshake.Method)
	}
	if handshake.SessionID != "session-1" {
		t.Fatalf("session id = %q, want session-1", handshake.SessionID)
	}
	if handshake.SocketPath != plan.SocketPath {
		t.Fatalf("socket path = %q, want %q", handshake.SocketPath, plan.SocketPath)
	}
	if handshake.CredentialSource != DaemonPeerCredentialSourceLinuxSOPeerCred {
		t.Fatalf("credential source = %q", handshake.CredentialSource)
	}
	if handshake.Authorization.Verdict != DaemonPeerAuthorizationVerdictAllow {
		t.Fatalf("authorization verdict = %q, want allow", handshake.Authorization.Verdict)
	}
	if !containsText(handshake.ClaimBoundary, "explicit UID/GID policy before handling") {
		t.Fatalf("claim boundary missing peer-policy guardrail: %#v", handshake.ClaimBoundary)
	}
	if !containsText(handshake.NotClaimed, "production daemon readiness") {
		t.Fatalf("not-claimed list missing production daemon boundary: %#v", handshake.NotClaimed)
	}
}

func TestAuthorizeDaemonProtocolPeerHandlesSessionIDsByMethod(t *testing.T) {
	t.Parallel()

	plan, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	observation := DaemonSocketPeerObservation{
		Credentials:      DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 4321},
		CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
		SocketPath:       plan.SocketPath,
	}
	policy := DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}}

	for _, tc := range []struct {
		name          string
		req           DaemonProtocolRequest
		wantSessionID string
	}{
		{
			name: "health has no session id",
			req: DaemonProtocolRequest{
				ProtocolVersion: DaemonProtocolVersion,
				Method:          DaemonProtocolMethodHealth,
				Health:          &DaemonHealthRequest{},
			},
		},
		{
			name: "end session",
			req: DaemonProtocolRequest{
				ProtocolVersion: DaemonProtocolVersion,
				Method:          DaemonProtocolMethodEndSession,
				EndSession:      &DaemonEndSessionRequest{SessionID: "session-end"},
			},
			wantSessionID: "session-end",
		},
		{
			name: "session status",
			req: DaemonProtocolRequest{
				ProtocolVersion: DaemonProtocolVersion,
				Method:          DaemonProtocolMethodSessionStatus,
				SessionStatus:   &DaemonSessionStatusRequest{SessionID: "session-status"},
			},
			wantSessionID: "session-status",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handshake, err := AuthorizeDaemonProtocolPeer(tc.req, observation, policy, plan)
			if err != nil {
				t.Fatalf("AuthorizeDaemonProtocolPeer returned error: %v", err)
			}
			if handshake.SessionID != tc.wantSessionID {
				t.Fatalf("session id = %q, want %q", handshake.SessionID, tc.wantSessionID)
			}
		})
	}
}

func TestAuthorizeDaemonProtocolPeerFailsClosed(t *testing.T) {
	t.Parallel()

	plan, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	validRequest := DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodRegisterSession,
		RegisterSession: &DaemonRegisterSessionRequest{
			SessionID:    "session-1",
			RootPID:      1234,
			EventClasses: []string{DaemonProtocolEventProcessLifecycle},
			TTLSeconds:   60,
		},
	}
	validObservation := DaemonSocketPeerObservation{
		Credentials:      DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 4321},
		CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
		SocketPath:       plan.SocketPath,
	}
	validPolicy := DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}}

	for _, tc := range []struct {
		name    string
		req     DaemonProtocolRequest
		obs     DaemonSocketPeerObservation
		policy  DaemonPeerAuthorizationPolicy
		plan    DaemonCustodyPlan
		wantErr error
	}{
		{
			name:    "invalid request",
			req:     DaemonProtocolRequest{ProtocolVersion: "kernelcapture.daemon.v0"},
			obs:     validObservation,
			policy:  validPolicy,
			plan:    plan,
			wantErr: ErrDaemonProtocol,
		},
		{
			name:    "missing credential source",
			req:     validRequest,
			obs:     DaemonSocketPeerObservation{Credentials: validObservation.Credentials, SocketPath: plan.SocketPath},
			policy:  validPolicy,
			plan:    plan,
			wantErr: ErrDaemonSocketPeerObservation,
		},
		{
			name:    "unsupported credential source",
			req:     validRequest,
			obs:     DaemonSocketPeerObservation{Credentials: validObservation.Credentials, CredentialSource: "client_json", SocketPath: plan.SocketPath},
			policy:  validPolicy,
			plan:    plan,
			wantErr: ErrDaemonSocketPeerObservation,
		},
		{
			name:    "socket path mismatch",
			req:     validRequest,
			obs:     DaemonSocketPeerObservation{Credentials: validObservation.Credentials, CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred, SocketPath: "/tmp/ardur.sock"},
			policy:  validPolicy,
			plan:    plan,
			wantErr: ErrDaemonSocketPeerObservation,
		},
		{
			name:    "invalid custody plan",
			req:     validRequest,
			obs:     validObservation,
			policy:  validPolicy,
			plan:    DaemonCustodyPlan{},
			wantErr: ErrDaemonSocketPeerObservation,
		},
		{
			name:   "fabricated custody plan outside daemon run dir",
			req:    validRequest,
			obs:    DaemonSocketPeerObservation{Credentials: validObservation.Credentials, CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred, SocketPath: "/tmp/fake.sock"},
			policy: validPolicy,
			plan: DaemonCustodyPlan{
				Mode:            DaemonCustodyModeLocalOnlyScaffold,
				ConfigPath:      "/etc/ardur/kernelcapture-daemon.toml",
				StateDir:        "/var/lib/ardur/kernelcapture",
				RunDir:          "/tmp",
				SocketPath:      "/tmp/fake.sock",
				BPFFSDir:        "/sys/fs/bpf/ardur",
				RingbufMapPath:  "/sys/fs/bpf/ardur/process_lifecycle_events",
				OwnerUID:        0,
				OwnerGID:        0,
				ProducerName:    "ardur-process-lifecycle-ebpf",
				ProducerVersion: "phase2-process-lifecycle-v0",
			},
			wantErr: ErrDaemonSocketPeerObservation,
		},
		{
			name:    "unauthorized peer",
			req:     validRequest,
			obs:     validObservation,
			policy:  DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{999}},
			plan:    plan,
			wantErr: ErrDaemonPeerAuthorization,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := AuthorizeDaemonProtocolPeer(tc.req, tc.obs, tc.policy, tc.plan)
			if err == nil {
				t.Fatalf("expected error")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestAuthorizeDaemonProtocolPeerKeepsPeerIdentityOutOfClientJSON(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"register_session","register_session":{"session_id":"session-1","event_classes":["process_lifecycle"],"ttl_seconds":60,"metadata":{"linux_so_peercred":{"uid":501,"gid":20,"pid":4321}}}}` + "\n")
	_, err := DecodeDaemonProtocolRequest(raw)
	if err == nil {
		t.Fatalf("expected client-supplied peer identity rejection")
	}
	if !errors.Is(err, ErrDaemonProtocol) {
		t.Fatalf("expected ErrDaemonProtocol, got %v", err)
	}
	if !strings.Contains(err.Error(), "peer identity") {
		t.Fatalf("error should explain peer identity boundary, got %v", err)
	}
}

func TestAuthorizeDaemonProtocolPeerFromAcceptedUnixConnectionRejectsMalformedPayload(t *testing.T) {
	t.Parallel()

	plan, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}

	accepted, client, cleanup := acceptedUnixConnPair(t)
	defer cleanup()
	writeUnixRequestAndClose(t, client, `{"protocol_version":"kernelcapture.daemon.v1","method":"register_session","register_session"`)

	_, err = AuthorizeDaemonProtocolPeerFromAcceptedUnixConnection(accepted, DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{1}}, plan)
	if err == nil {
		t.Fatalf("expected malformed payload rejection")
	}
	if !errors.Is(err, ErrDaemonProtocol) {
		t.Fatalf("expected ErrDaemonProtocol, got %v", err)
	}
}
