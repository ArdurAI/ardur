package kernelcapture

import (
	"bytes"
	"errors"
	"testing"
)

func TestDaemonProtocolDeterministicEncoding(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		req  DaemonProtocolRequest
		want string
	}{
		{
			name: "health",
			req: DaemonProtocolRequest{
				ProtocolVersion: DaemonProtocolVersion,
				Method:          DaemonProtocolMethodHealth,
				Health:          &DaemonHealthRequest{},
			},
			want: `{"protocol_version":"kernelcapture.daemon.v1","method":"health","health":{}}` + "\n",
		},
		{
			name: "register_session",
			req: DaemonProtocolRequest{
				ProtocolVersion: DaemonProtocolVersion,
				Method:          DaemonProtocolMethodRegisterSession,
				RegisterSession: &DaemonRegisterSessionRequest{
					SessionID:      "session-1",
					MissionID:      "mission-1",
					TraceID:        "trace-1",
					RootPID:        123,
					PIDNamespaceID: 456,
					CgroupID:       789,
					EventClasses:   []string{DaemonProtocolEventProcessLifecycle},
					TTLSeconds:     60,
				},
			},
			want: `{"protocol_version":"kernelcapture.daemon.v1","method":"register_session","register_session":{"session_id":"session-1","mission_id":"mission-1","trace_id":"trace-1","root_pid":123,"pid_namespace_id":456,"cgroup_id":789,"event_classes":["process_lifecycle"],"ttl_seconds":60}}` + "\n",
		},
		{
			name: "end_session",
			req: DaemonProtocolRequest{
				ProtocolVersion: DaemonProtocolVersion,
				Method:          DaemonProtocolMethodEndSession,
				EndSession:      &DaemonEndSessionRequest{SessionID: "session-1", TraceID: "trace-1"},
			},
			want: `{"protocol_version":"kernelcapture.daemon.v1","method":"end_session","end_session":{"session_id":"session-1","trace_id":"trace-1"}}` + "\n",
		},
		{
			name: "session_status",
			req: DaemonProtocolRequest{
				ProtocolVersion: DaemonProtocolVersion,
				Method:          DaemonProtocolMethodSessionStatus,
				SessionStatus:   &DaemonSessionStatusRequest{SessionID: "session-1"},
			},
			want: `{"protocol_version":"kernelcapture.daemon.v1","method":"session_status","session_status":{"session_id":"session-1"}}` + "\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := EncodeDaemonProtocolRequest(tc.req)
			if err != nil {
				t.Fatalf("EncodeDaemonProtocolRequest returned error: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("encoded request:\n got %q\nwant %q", string(got), tc.want)
			}
			decoded, err := DecodeDaemonProtocolRequest(got)
			if err != nil {
				t.Fatalf("DecodeDaemonProtocolRequest returned error: %v", err)
			}
			encodedAgain, err := EncodeDaemonProtocolRequest(decoded)
			if err != nil {
				t.Fatalf("re-encode returned error: %v", err)
			}
			if !bytes.Equal(got, encodedAgain) {
				t.Fatalf("encoding is not deterministic: %q != %q", got, encodedAgain)
			}
		})
	}
}

func TestDaemonProtocolValidationRejectsInvalidRequests(t *testing.T) {
	t.Parallel()

	validRegister := DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodRegisterSession,
		RegisterSession: &DaemonRegisterSessionRequest{
			SessionID:    "session-1",
			RootPID:      123,
			EventClasses: []string{DaemonProtocolEventProcessLifecycle},
			TTLSeconds:   60,
		},
	}

	for _, tc := range []struct {
		name string
		mut  func(*DaemonProtocolRequest)
	}{
		{name: "unknown version", mut: func(req *DaemonProtocolRequest) { req.ProtocolVersion = "kernelcapture.daemon.v0" }},
		{name: "unknown event class", mut: func(req *DaemonProtocolRequest) { req.RegisterSession.EventClasses = []string{"file_io"} }},
		{name: "missing session id", mut: func(req *DaemonProtocolRequest) { req.RegisterSession.SessionID = "" }},
		{name: "missing root pid", mut: func(req *DaemonProtocolRequest) { req.RegisterSession.RootPID = 0 }},
		{name: "zero ttl", mut: func(req *DaemonProtocolRequest) { req.RegisterSession.TTLSeconds = 0 }},
		{name: "unbounded ttl", mut: func(req *DaemonProtocolRequest) { req.RegisterSession.TTLSeconds = MaxDaemonProtocolTTLSeconds + 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := validRegister
			copyPayload := *validRegister.RegisterSession
			req.RegisterSession = &copyPayload
			tc.mut(&req)
			err := ValidateDaemonProtocolRequest(req)
			if err == nil {
				t.Fatalf("expected validation error")
			}
			if !errors.Is(err, ErrDaemonProtocol) {
				t.Fatalf("expected ErrDaemonProtocol, got %v", err)
			}
		})
	}
}

func TestDaemonProtocolDecodeRejectsRegisterSessionWithoutRootPID(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"register_session","register_session":{"session_id":"session-1","event_classes":["process_lifecycle"],"ttl_seconds":60}}` + "\n")
	_, err := DecodeDaemonProtocolRequest(raw)
	if err == nil {
		t.Fatalf("expected missing root_pid to be rejected")
	}
	if !errors.Is(err, ErrDaemonProtocol) {
		t.Fatalf("expected ErrDaemonProtocol, got %v", err)
	}
}

func TestDaemonProtocolValidationRejectsForbiddenHandoffMetadata(t *testing.T) {
	t.Parallel()

	validRegister := DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodRegisterSession,
		RegisterSession: &DaemonRegisterSessionRequest{
			SessionID:    "session-1",
			RootPID:      123,
			EventClasses: []string{DaemonProtocolEventProcessLifecycle},
			TTLSeconds:   60,
		},
	}

	for _, tc := range []struct {
		name     string
		metadata map[string]any
	}{
		{name: "raw command", metadata: map[string]any{"command": "/bin/echo raw"}},
		{name: "secret-like key", metadata: map[string]any{"api_token": "[REDACTED]"}},
		{name: "nested client secret", metadata: map[string]any{"nested": map[string]any{"client-secret": "[REDACTED]"}}},
		{name: "list private key", metadata: map[string]any{"items": []any{map[string]any{"private key": "[REDACTED]"}}}},
		{name: "authorization", metadata: map[string]any{"Authorization": "[REDACTED]"}},
		{name: "auth header", metadata: map[string]any{"nested": map[string]any{"auth header": "[REDACTED]"}}},
		{name: "bearer", metadata: map[string]any{"items": []any{map[string]any{"BEARER": "[REDACTED]"}}}},
		{name: "jwt", metadata: map[string]any{"nested": map[string]any{"j_w-t": "[REDACTED]"}}},
		{name: "key", metadata: map[string]any{"k e_y-": "[REDACTED]"}},
		{name: "typed nested map[string]string", metadata: map[string]any{"nested": map[string]string{"client-secret": "[REDACTED]"}}},
		{name: "typed list []map[string]any", metadata: map[string]any{"items": []map[string]any{{"private key": "[REDACTED]"}}}},
		{name: "typed list []map[string]string", metadata: map[string]any{"items": []map[string]string{{"so-peercred": "[REDACTED]"}}}},
		{name: "socket path separator variant", metadata: map[string]any{"socket-path": "/run/ardur/kernelcapture/control.sock"}},
		{name: "peer uid space variant", metadata: map[string]any{"nested": map[string]any{"peer uid": 501}}},
		{name: "so peercred hyphen variant", metadata: map[string]any{"items": []any{map[string]any{"so-peercred": map[string]any{"uid": 501}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := validRegister
			copyPayload := *validRegister.RegisterSession
			copyPayload.HandoffMetadata = tc.metadata
			req.RegisterSession = &copyPayload
			err := ValidateDaemonProtocolRequest(req)
			if err == nil {
				t.Fatalf("expected forbidden handoff metadata to be rejected")
			}
			if !errors.Is(err, ErrDaemonProtocol) {
				t.Fatalf("expected ErrDaemonProtocol, got %v", err)
			}
		})
	}
}

func TestDaemonProtocolRejectsRawPrivilegedPathFields(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{
			name: "nested bpffs_dir",
			raw:  []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"register_session","register_session":{"session_id":"session-1","event_classes":["process_lifecycle"],"ttl_seconds":60,"bpffs_dir":"/sys/fs/bpf/ardur"}}` + "\n"),
		},
		{
			name: "mixed case map path",
			raw:  []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"register_session","register_session":{"session_id":"session-1","event_classes":["process_lifecycle"],"ttl_seconds":60,"BpFfS_DiR":"/sys/fs/bpf/ardur"}}` + "\n"),
		},
		{
			name: "nested peer identity",
			raw:  []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"register_session","register_session":{"session_id":"session-1","event_classes":["process_lifecycle"],"ttl_seconds":60,"peer_credentials":{"uid":501,"gid":20,"pid":1234}}}` + "\n"),
		},
		{
			name: "explicit peer uid",
			raw:  []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"register_session","register_session":{"session_id":"session-1","event_classes":["process_lifecycle"],"ttl_seconds":60,"peer_uid":501}}` + "\n"),
		},
		{
			name: "socket path separator variant",
			raw:  []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"register_session","register_session":{"session_id":"session-1","event_classes":["process_lifecycle"],"ttl_seconds":60,"socket-path":"/run/ardur/kernelcapture/control.sock"}}` + "\n"),
		},
		{
			name: "peer uid space variant",
			raw:  []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"register_session","register_session":{"session_id":"session-1","event_classes":["process_lifecycle"],"ttl_seconds":60,"peer uid":501}}` + "\n"),
		},
		{
			name: "so peercred hyphen variant",
			raw:  []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"health","health":{},"so-peercred":{"uid":501}}` + "\n"),
		},
		{
			name: "explicit peer gid",
			raw:  []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"register_session","register_session":{"session_id":"session-1","event_classes":["process_lifecycle"],"ttl_seconds":60,"peer_gid":20}}` + "\n"),
		},
		{
			name: "explicit peer pid",
			raw:  []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"register_session","register_session":{"session_id":"session-1","event_classes":["process_lifecycle"],"ttl_seconds":60,"peer_pid":1234}}` + "\n"),
		},
		{
			name: "ucred wrapper",
			raw:  []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"health","health":{},"ucred":{"uid":501}}` + "\n"),
		},
		{
			name: "mixed case so peercred",
			raw:  []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"health","health":{},"So_PeerCred":{"uid":501}}` + "\n"),
		},
		{
			name: "credential source",
			raw:  []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"register_session","register_session":{"session_id":"session-1","event_classes":["process_lifecycle"],"ttl_seconds":60,"credential_source":"linux_so_peercred"}}` + "\n"),
		},
		{
			name: "mixed case credential source",
			raw:  []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"health","health":{},"Credential_Source":"linux_so_peercred"}` + "\n"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeDaemonProtocolRequest(tc.raw)
			if err == nil {
				t.Fatalf("expected privileged path rejection")
			}
			if !errors.Is(err, ErrDaemonProtocol) {
				t.Fatalf("expected ErrDaemonProtocol, got %v", err)
			}
		})
	}
}

func TestDaemonProtocolRejectsUnknownRawFields(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"health","health":{},"extra":true}` + "\n")
	_, err := DecodeDaemonProtocolRequest(raw)
	if err == nil {
		t.Fatalf("expected unknown field rejection")
	}
	if !errors.Is(err, ErrDaemonProtocol) {
		t.Fatalf("expected ErrDaemonProtocol, got %v", err)
	}
}

func TestDaemonProtocolRejectsTrailingJunk(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"health","health":{}}` + "\nnot-json")
	_, err := DecodeDaemonProtocolRequest(raw)
	if err == nil {
		t.Fatalf("expected trailing junk rejection")
	}
	if !errors.Is(err, ErrDaemonProtocol) {
		t.Fatalf("expected ErrDaemonProtocol, got %v", err)
	}
}

func TestValidateCgroupFilterSequenceRequiresAllowlistBeforeEnable(t *testing.T) {
	t.Parallel()

	if err := ValidateCgroupFilterSequence(CgroupFilterSequence{Enable: false}); err != nil {
		t.Fatalf("disabled sequence returned error: %v", err)
	}
	if err := ValidateCgroupFilterSequence(CgroupFilterSequence{Enable: true, AllowlistCgroupIDs: []uint64{123}}); err != nil {
		t.Fatalf("enabled sequence with allowlist returned error: %v", err)
	}
	for _, seq := range []CgroupFilterSequence{
		{Enable: true},
		{Enable: true, AllowlistCgroupIDs: []uint64{0}},
	} {
		if err := ValidateCgroupFilterSequence(seq); err == nil {
			t.Fatalf("expected sequence error for %+v", seq)
		}
	}
}
