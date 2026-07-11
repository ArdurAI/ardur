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

func TestDaemonProtocolResponseDecodeRejectsInternalExpansion(t *testing.T) {
	t.Parallel()

	valid := DaemonProtocolResponse{
		ProtocolVersion: DaemonProtocolVersion,
		OK:              true,
		Method:          DaemonProtocolMethodSessionStatus,
		SessionID:       "session-1",
		Status:          DaemonSessionStatusActive,
	}
	encoded, err := EncodeDaemonProtocolResponse(valid)
	if err != nil {
		t.Fatalf("EncodeDaemonProtocolResponse returned error: %v", err)
	}
	decoded, err := DecodeDaemonProtocolResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeDaemonProtocolResponse returned error: %v", err)
	}
	if decoded != valid {
		t.Fatalf("decoded response = %#v, want %#v", decoded, valid)
	}

	for _, raw := range [][]byte{
		[]byte(`{"protocol_version":"kernelcapture.daemon.v1","ok":true,"method":"session_status","session_id":"session-1","status":"active","handoff":{"session_id":"session-1"}}` + "\n"),
		[]byte(`{"protocol_version":"kernelcapture.daemon.v1","ok":true,"method":"session_status","session_id":"session-1","status":"active","root_pid":123}` + "\n"),
		[]byte(`{"protocol_version":"kernelcapture.daemon.v1","ok":true,"method":"session_status","session_id":"session-1","status":"active"}` + "\n" + `{"protocol_version":"kernelcapture.daemon.v1","ok":true}` + "\n"),
	} {
		if _, err := DecodeDaemonProtocolResponse(raw); err == nil || !errors.Is(err, ErrDaemonProtocol) {
			t.Fatalf("DecodeDaemonProtocolResponse(%q) error = %v, want ErrDaemonProtocol", string(raw), err)
		}
	}
}

func TestDaemonProtocolResponseLifecycleCaptureRoundTrip(t *testing.T) {
	t.Parallel()

	want := LifecycleCaptureSummary{
		CoverageStatus:             LifecycleCaptureCoverageDegraded,
		RingbufDropped:             2,
		ProducerRingbufDropped:     1,
		MalformedRecords:           1,
		ProducerCounterEvidenceGap: true,
		DaemonQueueDropped:         1,
		LossEpochStart:             4,
		LossEpochEnd:               6,
	}
	encoded, err := EncodeDaemonProtocolResponse(DaemonProtocolResponse{
		ProtocolVersion:  DaemonProtocolVersion,
		OK:               true,
		Method:           DaemonProtocolMethodSessionStatus,
		SessionID:        "session-1",
		Status:           DaemonSessionStatusActive,
		LifecycleCapture: &want,
	})
	if err != nil {
		t.Fatalf("EncodeDaemonProtocolResponse returned error: %v", err)
	}
	if !bytes.Contains(encoded, []byte(`"lifecycle_capture":{"coverage_status":"degraded","ringbuf_dropped":2,"producer_ringbuf_dropped":1,"malformed_records":1,"producer_counter_evidence_gap":true,"daemon_queue_dropped":1,"loss_epoch_start":4,"loss_epoch_end":6}`)) {
		t.Fatalf("encoded lifecycle_capture = %s", encoded)
	}

	decoded, err := DecodeDaemonProtocolResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeDaemonProtocolResponse returned error: %v", err)
	}
	if decoded.LifecycleCapture == nil || *decoded.LifecycleCapture != want {
		t.Fatalf("decoded lifecycle_capture = %#v, want %#v", decoded.LifecycleCapture, want)
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
			CgroupID:     789,
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
		{name: "missing cgroup id", mut: func(req *DaemonProtocolRequest) { req.RegisterSession.CgroupID = 0 }},
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

func TestDaemonApplyPolicyControlPlaneEndpointValidation(t *testing.T) {
	t.Parallel()

	valid := DaemonApplyPolicyRequest{
		SessionID: "session-1",
		OpPolicies: []DaemonOpPolicy{{
			Op:          BpfOpNetConnect,
			Action:      BpfActionDeny,
			EnforceMode: BpfEnforceModeEnforce,
		}},
		Generation:  1,
		EnforceMode: BpfEnforceModeEnforce,
		ControlPlaneEndpoint: &DaemonControlPlaneEndpoint{
			IP:   "127.0.0.1",
			Port: 43210,
		},
	}
	if err := validateDaemonApplyPolicy(valid); err != nil {
		t.Fatalf("valid exact loopback endpoint rejected: %v", err)
	}

	for _, tc := range []struct {
		name     string
		endpoint DaemonControlPlaneEndpoint
	}{
		{name: "remote IPv4", endpoint: DaemonControlPlaneEndpoint{IP: "192.0.2.10", Port: 43210}},
		{name: "remote IPv6", endpoint: DaemonControlPlaneEndpoint{IP: "2001:db8::1", Port: 43210}},
		{name: "hostname", endpoint: DaemonControlPlaneEndpoint{IP: "localhost", Port: 43210}},
		{name: "unspecified IPv4", endpoint: DaemonControlPlaneEndpoint{IP: "0.0.0.0", Port: 43210}},
		{name: "zero port", endpoint: DaemonControlPlaneEndpoint{IP: "127.0.0.1", Port: 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := valid
			req.ControlPlaneEndpoint = &tc.endpoint
			if err := validateDaemonApplyPolicy(req); err == nil || !errors.Is(err, ErrDaemonProtocol) {
				t.Fatalf("validate endpoint %#v error = %v, want ErrDaemonProtocol", tc.endpoint, err)
			}
		})
	}

	withoutNetPolicy := valid
	withoutNetPolicy.OpPolicies = []DaemonOpPolicy{{
		Op: BpfOpExec, Action: BpfActionDeny, EnforceMode: BpfEnforceModeEnforce,
	}}
	if err := validateDaemonApplyPolicy(withoutNetPolicy); err == nil || !errors.Is(err, ErrDaemonProtocol) {
		t.Fatalf("endpoint without OP_NET_CONNECT error = %v, want ErrDaemonProtocol", err)
	}
}

func TestDaemonApplyPolicyBootstrapReadAllowIsFixed(t *testing.T) {
	t.Parallel()
	req := DaemonApplyPolicyRequest{
		SessionID: "session-1", Generation: 1, EnforceMode: BpfEnforceModeEnforce,
		BootstrapReadAllow: []string{"/usr", "/lib", "/lib64", "/etc/ld.so.cache", "/etc/ssl/certs", "/dev/urandom"},
	}
	if err := validateDaemonApplyPolicy(req); err != nil {
		t.Fatalf("fixed runtime roots rejected: %v", err)
	}
	for _, paths := range [][]string{{"/home/user"}, {"/usr", "/usr"}, {"relative"}} {
		bad := req
		bad.BootstrapReadAllow = paths
		if err := validateDaemonApplyPolicy(bad); err == nil || !errors.Is(err, ErrDaemonProtocol) {
			t.Fatalf("bootstrap_read_allow %v error = %v, want ErrDaemonProtocol", paths, err)
		}
	}
}

func TestDaemonProtocolRejectsClientSuppliedRootPIDInApplyPolicy(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"apply_policy","apply_policy":{"session_id":"session-1","op_policies":[],"generation":1,"enforce_mode":1,"root_pid":42}}` + "\n")
	if _, err := DecodeDaemonProtocolRequest(raw); err == nil || !errors.Is(err, ErrDaemonProtocol) {
		t.Fatalf("client-supplied apply_policy root_pid error = %v, want ErrDaemonProtocol", err)
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
			CgroupID:     789,
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
			name: "process start time ticks",
			raw:  []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"register_session","register_session":{"session_id":"session-1","event_classes":["process_lifecycle"],"ttl_seconds":60,"process_start_time_ticks":987654321}}` + "\n"),
		},
		{
			name: "peer process start time space variant",
			raw:  []byte(`{"protocol_version":"kernelcapture.daemon.v1","method":"health","health":{},"peer process start time":987654321}` + "\n"),
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

func TestDaemonRegisterReceiptProtocolRoundTripAndValidation(t *testing.T) {
	t.Parallel()
	req := DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodRegisterReceipt,
		RegisterReceipt: &DaemonRegisterReceiptRequest{
			SessionID: "session-1",
			ReceiptID: "receipt:0123456789abcdef",
		},
	}
	encoded, err := EncodeDaemonProtocolRequest(req)
	if err != nil {
		t.Fatalf("EncodeDaemonProtocolRequest: %v", err)
	}
	decoded, err := DecodeDaemonProtocolRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeDaemonProtocolRequest: %v", err)
	}
	if decoded.RegisterReceipt == nil || decoded.RegisterReceipt.ReceiptID != req.RegisterReceipt.ReceiptID {
		t.Fatalf("decoded register_receipt = %#v", decoded.RegisterReceipt)
	}

	for name, receiptID := range map[string]string{
		"empty":      "",
		"whitespace": " receipt:a",
		"control":    "receipt:a\n",
		"unicode":    "receipt:\u00e9",
	} {
		t.Run(name, func(t *testing.T) {
			bad := req
			payload := *req.RegisterReceipt
			payload.ReceiptID = receiptID
			bad.RegisterReceipt = &payload
			if err := ValidateDaemonProtocolRequest(bad); err == nil {
				t.Fatalf("receipt_id %q passed validation", receiptID)
			}
		})
	}
}
