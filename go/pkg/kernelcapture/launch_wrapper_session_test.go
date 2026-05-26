package kernelcapture

import (
	"errors"
	"testing"
	"time"
)

func TestBuildLaunchWrapperSessionProofBuildsDaemonRequestAndCorrelatorSeed(t *testing.T) {
	t.Parallel()

	started := time.Unix(1_778_230_000, 123_000_000).UTC()
	proof, err := BuildLaunchWrapperSessionProof(LaunchWrapperSessionMetadata{
		SessionID:               "cli:session-1",
		MissionID:               "mission-1",
		TraceID:                 "trace-1",
		Command:                 []string{"python3", "-c", "print('ok')"},
		WorkingDirectory:        "/work/repo",
		RootPID:                 4242,
		PIDNamespaceID:          4026531836,
		ProcessStartMonotonicNS: 9_100_000_000,
		CgroupID:                77,
		StartedAt:               started,
		TTLSeconds:              60,
		HandoffMetadata: map[string]any{
			"launcher": "ardur run",
			"reason":   "generic cli boundary",
		},
	})
	if err != nil {
		t.Fatalf("BuildLaunchWrapperSessionProof returned error: %v", err)
	}

	req := proof.RegisterSessionRequest
	if req.ProtocolVersion != DaemonProtocolVersion {
		t.Fatalf("protocol version = %q", req.ProtocolVersion)
	}
	if req.Method != DaemonProtocolMethodRegisterSession {
		t.Fatalf("method = %q, want register_session", req.Method)
	}
	if req.RegisterSession == nil {
		t.Fatalf("register_session payload is nil")
	}
	if req.RegisterSession.SessionID != "cli:session-1" {
		t.Fatalf("session id = %q", req.RegisterSession.SessionID)
	}
	if req.RegisterSession.RootPID != 4242 {
		t.Fatalf("root pid = %d, want 4242", req.RegisterSession.RootPID)
	}
	if req.RegisterSession.PIDNamespaceID != 4026531836 {
		t.Fatalf("pid namespace = %d, want 4026531836", req.RegisterSession.PIDNamespaceID)
	}
	if req.RegisterSession.CgroupID != 77 {
		t.Fatalf("cgroup id = %d, want 77", req.RegisterSession.CgroupID)
	}
	if req.RegisterSession.HandoffMetadata["command_argv_sha256"] == "" {
		t.Fatalf("expected redacted command digest in handoff metadata: %#v", req.RegisterSession.HandoffMetadata)
	}
	if req.RegisterSession.HandoffMetadata["command_argc"] != 3 {
		t.Fatalf("command_argc = %#v, want 3", req.RegisterSession.HandoffMetadata["command_argc"])
	}
	if _, ok := req.RegisterSession.HandoffMetadata["command"]; ok {
		t.Fatalf("handoff metadata must not include raw command argv: %#v", req.RegisterSession.HandoffMetadata)
	}
	if _, err := EncodeDaemonProtocolRequest(req); err != nil {
		t.Fatalf("register_session request should encode after proof build: %v", err)
	}

	seed := proof.CorrelatorSeed
	if seed.ReceiptID != "launch-wrapper:cli:session-1:trace-1" {
		t.Fatalf("receipt id = %q", seed.ReceiptID)
	}
	if seed.SessionID != "cli:session-1" || seed.PID != 4242 || seed.CgroupID != 77 {
		t.Fatalf("unexpected correlator seed: %#v", seed)
	}
	if seed.PIDNamespaceID != 4026531836 {
		t.Fatalf("seed pid namespace = %d, want 4026531836", seed.PIDNamespaceID)
	}
	if seed.ProcessStartMonotonicNS != 9_100_000_000 {
		t.Fatalf("seed process start = %d", seed.ProcessStartMonotonicNS)
	}
	if !seed.ObservedAt.Equal(started) {
		t.Fatalf("seed observed_at = %s, want %s", seed.ObservedAt, started)
	}
	if !containsText(proof.ClaimBoundary, "launch-wrapper session identity is converted into a daemon register_session request") {
		t.Fatalf("claim boundary missing register_session wording: %#v", proof.ClaimBoundary)
	}
	if !containsText(proof.NotClaimed, "subprocess/file/network side-effect capture") {
		t.Fatalf("not-claimed list missing side-effect boundary: %#v", proof.NotClaimed)
	}
}

func TestBuildLaunchWrapperSessionProofUsesExactArgvBytesForDigest(t *testing.T) {
	t.Parallel()

	started := time.Unix(1_778_230_050, 0).UTC()
	base := LaunchWrapperSessionMetadata{
		SessionID:  "cli:session-argv-bytes",
		TraceID:    "trace-argv-bytes",
		Command:    []string{"python3", "-c", "print('ok')"},
		RootPID:    9001,
		StartedAt:  started,
		TTLSeconds: 60,
	}

	proofA, err := BuildLaunchWrapperSessionProof(base)
	if err != nil {
		t.Fatalf("BuildLaunchWrapperSessionProof(base) returned error: %v", err)
	}

	variant := base
	variant.Command = []string{"python3 ", "-c", "print('ok')"}
	proofB, err := BuildLaunchWrapperSessionProof(variant)
	if err != nil {
		t.Fatalf("BuildLaunchWrapperSessionProof(variant) returned error: %v", err)
	}

	digestA, ok := proofA.RegisterSessionRequest.RegisterSession.HandoffMetadata["command_argv_sha256"].(string)
	if !ok || digestA == "" {
		t.Fatalf("base command digest missing or non-string: %#v", proofA.RegisterSessionRequest.RegisterSession.HandoffMetadata["command_argv_sha256"])
	}
	digestB, ok := proofB.RegisterSessionRequest.RegisterSession.HandoffMetadata["command_argv_sha256"].(string)
	if !ok || digestB == "" {
		t.Fatalf("variant command digest missing or non-string: %#v", proofB.RegisterSessionRequest.RegisterSession.HandoffMetadata["command_argv_sha256"])
	}
	if digestA == digestB {
		t.Fatalf("command_argv_sha256 should differ for whitespace-distinct argv bytes: %q", digestA)
	}
}

func TestBuildLaunchWrapperSessionProofUsesExactWorkingDirectoryBytesForDigest(t *testing.T) {
	t.Parallel()

	started := time.Unix(1_778_230_060, 0).UTC()
	base := LaunchWrapperSessionMetadata{
		SessionID:        "cli:session-cwd-bytes",
		TraceID:          "trace-cwd-bytes",
		Command:          []string{"python3"},
		WorkingDirectory: "/work/repo",
		RootPID:          9002,
		StartedAt:        started,
		TTLSeconds:       60,
	}

	proofA, err := BuildLaunchWrapperSessionProof(base)
	if err != nil {
		t.Fatalf("BuildLaunchWrapperSessionProof(base) returned error: %v", err)
	}

	variant := base
	variant.WorkingDirectory = "/work/repo "
	proofB, err := BuildLaunchWrapperSessionProof(variant)
	if err != nil {
		t.Fatalf("BuildLaunchWrapperSessionProof(variant) returned error: %v", err)
	}

	digestA, ok := proofA.RegisterSessionRequest.RegisterSession.HandoffMetadata["working_directory_sha256"].(string)
	if !ok || digestA == "" {
		t.Fatalf("base working-directory digest missing or non-string: %#v", proofA.RegisterSessionRequest.RegisterSession.HandoffMetadata["working_directory_sha256"])
	}
	digestB, ok := proofB.RegisterSessionRequest.RegisterSession.HandoffMetadata["working_directory_sha256"].(string)
	if !ok || digestB == "" {
		t.Fatalf("variant working-directory digest missing or non-string: %#v", proofB.RegisterSessionRequest.RegisterSession.HandoffMetadata["working_directory_sha256"])
	}
	if digestA == digestB {
		t.Fatalf("working_directory_sha256 should differ for whitespace-distinct working_directory bytes: %q", digestA)
	}
}

func TestBuildLaunchWrapperSessionProofFailsClosed(t *testing.T) {
	t.Parallel()

	valid := LaunchWrapperSessionMetadata{
		SessionID:  "cli:session-1",
		TraceID:    "trace-1",
		Command:    []string{"true"},
		RootPID:    1234,
		StartedAt:  time.Unix(1_778_230_100, 0).UTC(),
		TTLSeconds: 60,
	}

	for _, tc := range []struct {
		name string
		mut  func(*LaunchWrapperSessionMetadata)
	}{
		{name: "missing session id", mut: func(m *LaunchWrapperSessionMetadata) { m.SessionID = "" }},
		{name: "missing command", mut: func(m *LaunchWrapperSessionMetadata) { m.Command = nil }},
		{name: "empty command path", mut: func(m *LaunchWrapperSessionMetadata) { m.Command = []string{"   "} }},
		{name: "missing root pid", mut: func(m *LaunchWrapperSessionMetadata) { m.RootPID = 0 }},
		{name: "missing started at", mut: func(m *LaunchWrapperSessionMetadata) { m.StartedAt = time.Time{} }},
		{name: "zero ttl", mut: func(m *LaunchWrapperSessionMetadata) { m.TTLSeconds = 0 }},
		{name: "unbounded ttl", mut: func(m *LaunchWrapperSessionMetadata) { m.TTLSeconds = MaxDaemonProtocolTTLSeconds + 1 }},
		{name: "daemon path in metadata", mut: func(m *LaunchWrapperSessionMetadata) {
			m.HandoffMetadata = map[string]any{"socket_path": "/run/ardur/kernelcapture/control.sock"}
		}},
		{name: "peer identity in nested metadata", mut: func(m *LaunchWrapperSessionMetadata) {
			m.HandoffMetadata = map[string]any{"nested": map[string]any{"peer_uid": 501}}
		}},
		{name: "raw command in handoff metadata", mut: func(m *LaunchWrapperSessionMetadata) {
			m.HandoffMetadata = map[string]any{"command": "/bin/echo raw"}
		}},
		{name: "raw working directory in nested metadata", mut: func(m *LaunchWrapperSessionMetadata) {
			m.HandoffMetadata = map[string]any{"nested": map[string]any{"working_directory": "/secret/path"}}
		}},
		{name: "raw environment in handoff metadata", mut: func(m *LaunchWrapperSessionMetadata) {
			m.HandoffMetadata = map[string]any{"env": map[string]any{"TOKEN": "redacted-but-raw"}}
		}},
		{name: "direct token-like handoff metadata", mut: func(m *LaunchWrapperSessionMetadata) {
			m.HandoffMetadata = map[string]any{"api_token": "redacted-but-still-secret-shaped"}
		}},
		{name: "nested secret-like handoff metadata", mut: func(m *LaunchWrapperSessionMetadata) {
			m.HandoffMetadata = map[string]any{"nested": map[string]any{"client_secret": "redacted-but-still-secret-shaped"}}
		}},
		{name: "listed private-key-like handoff metadata", mut: func(m *LaunchWrapperSessionMetadata) {
			m.HandoffMetadata = map[string]any{"items": []any{map[string]any{"private_key": "redacted-but-still-secret-shaped"}}}
		}},
		{name: "daemon socket path separator variant in handoff metadata", mut: func(m *LaunchWrapperSessionMetadata) {
			m.HandoffMetadata = map[string]any{"socket-path": "/run/ardur/kernelcapture/control.sock"}
		}},
		{name: "peer uid space variant in nested metadata", mut: func(m *LaunchWrapperSessionMetadata) {
			m.HandoffMetadata = map[string]any{"nested": map[string]any{"peer uid": 501}}
		}},
		{name: "so peercred hyphen variant in listed metadata", mut: func(m *LaunchWrapperSessionMetadata) {
			m.HandoffMetadata = map[string]any{"items": []any{map[string]any{"so-peercred": map[string]any{"uid": 501}}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			meta := valid
			tc.mut(&meta)
			_, err := BuildLaunchWrapperSessionProof(meta)
			if err == nil {
				t.Fatalf("expected validation error")
			}
			if !errors.Is(err, ErrLaunchWrapperSessionProof) {
				t.Fatalf("expected ErrLaunchWrapperSessionProof, got %v", err)
			}
		})
	}
}

func TestBuildLaunchWrapperSessionProofRejectsSecretLikeMetadataAtAnyDepth(t *testing.T) {
	t.Parallel()

	valid := LaunchWrapperSessionMetadata{
		SessionID:  "cli:session-1",
		TraceID:    "trace-1",
		Command:    []string{"true"},
		RootPID:    1234,
		StartedAt:  time.Unix(1_778_230_200, 0).UTC(),
		TTLSeconds: 60,
	}

	secretKeys := []struct {
		name string
		key  string
	}{
		{name: "api token", key: "api_token"},
		{name: "access token", key: "ACCESS_TOKEN"},
		{name: "secret", key: "secret"},
		{name: "password", key: "Pass_Word"},
		{name: "private key", key: "private_key"},
		{name: "client secret", key: "client-secret"},
		{name: "api key", key: "api_key"},
		{name: "credential", key: "Credential"},
		{name: "authorization", key: "Authorization"},
		{name: "auth header", key: "auth header"},
		{name: "bearer", key: "BEARER"},
		{name: "jwt", key: "j_w-t"},
		{name: "key", key: "k e_y-"},
	}

	placements := []struct {
		name string
		wrap func(key string) map[string]any
	}{
		{
			name: "direct",
			wrap: func(key string) map[string]any {
				return map[string]any{key: "[REDACTED]"}
			},
		},
		{
			name: "nested map",
			wrap: func(key string) map[string]any {
				return map[string]any{"nested": map[string]any{key: "[REDACTED]"}}
			},
		},
		{
			name: "map in list",
			wrap: func(key string) map[string]any {
				return map[string]any{"items": []any{map[string]any{key: "[REDACTED]"}}}
			},
		},
	}

	for _, secret := range secretKeys {
		secret := secret
		for _, placement := range placements {
			placement := placement
			t.Run(secret.name+"/"+placement.name, func(t *testing.T) {
				t.Parallel()

				meta := valid
				meta.HandoffMetadata = placement.wrap(secret.key)
				_, err := BuildLaunchWrapperSessionProof(meta)
				if err == nil {
					t.Fatalf("expected secret-like key %q to be rejected in %s metadata", secret.key, placement.name)
				}
				if !errors.Is(err, ErrLaunchWrapperSessionProof) {
					t.Fatalf("expected ErrLaunchWrapperSessionProof, got %v", err)
				}
			})
		}
	}
}
