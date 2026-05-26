package kernelcapture

import (
	"errors"
	"testing"
	"time"
)

func TestBuildDaemonAcceptLoopPlanRecordsNoMutationContract(t *testing.T) {
	t.Parallel()

	custodyPlan, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	cfg := DefaultDaemonAcceptLoopConfig(custodyPlan, DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}})

	plan, err := BuildDaemonAcceptLoopPlan(cfg)
	if err != nil {
		t.Fatalf("BuildDaemonAcceptLoopPlan returned error: %v", err)
	}
	if plan.Mode != DaemonCustodyModeLocalOnlyScaffold {
		t.Fatalf("mode = %q, want local-only scaffold", plan.Mode)
	}
	if plan.SocketPath != custodyPlan.SocketPath {
		t.Fatalf("socket path = %q, want %q", plan.SocketPath, custodyPlan.SocketPath)
	}
	if plan.CredentialSource != DaemonPeerCredentialSourceLinuxSOPeerCred {
		t.Fatalf("credential source = %q, want %q", plan.CredentialSource, DaemonPeerCredentialSourceLinuxSOPeerCred)
	}
	if plan.MaxRequestBytes != DefaultDaemonAcceptLoopMaxRequestBytes {
		t.Fatalf("max request bytes = %d, want default", plan.MaxRequestBytes)
	}
	if plan.ReadTimeout != DefaultDaemonAcceptLoopReadTimeout {
		t.Fatalf("read timeout = %s, want default", plan.ReadTimeout)
	}
	if plan.MaxConcurrentConnections != DefaultDaemonAcceptLoopMaxConcurrentConnections {
		t.Fatalf("max concurrent connections = %d, want default", plan.MaxConcurrentConnections)
	}
	if len(plan.AllowedUIDs) != 1 || plan.AllowedUIDs[0] != 501 {
		t.Fatalf("allowed uids = %#v, want [501]", plan.AllowedUIDs)
	}
	wantSteps := []string{
		"run_read_only_daemon_preflight",
		"bind_validated_local_unix_socket",
		"accept_bounded_local_connection",
		"observe_os_peer_credentials",
		"decode_bounded_json_line_request",
		"authorize_request_and_peer",
		"dispatch_validated_protocol_method",
	}
	if len(plan.Steps) != len(wantSteps) {
		t.Fatalf("steps = %#v, want %d ordered steps", plan.Steps, len(wantSteps))
	}
	for i, step := range plan.Steps {
		if step.Name != wantSteps[i] {
			t.Fatalf("step %d name = %q, want %q", i, step.Name, wantSteps[i])
		}
		if step.Executed {
			t.Fatalf("step %q was marked executed in dry-run plan", step.Name)
		}
		if step.Rationale == "" {
			t.Fatalf("step %q missing rationale", step.Name)
		}
	}
	if !containsText(plan.ClaimBoundary, "no socket is opened, bound, listened on, or accepted") {
		t.Fatalf("claim boundary missing no-socket guardrail: %#v", plan.ClaimBoundary)
	}
	if !containsText(plan.ClaimBoundary, "OS-observed peer credentials") {
		t.Fatalf("claim boundary missing peer-credential join guardrail: %#v", plan.ClaimBoundary)
	}
	if !containsText(plan.NotClaimed, "daemon accept-loop wiring around SO_PEERCRED observations") {
		t.Fatalf("not-claimed list missing accept-loop boundary: %#v", plan.NotClaimed)
	}
	if !containsText(plan.NotClaimed, "service exposure") {
		t.Fatalf("not-claimed list missing service-exposure boundary: %#v", plan.NotClaimed)
	}
	if !containsText(plan.NotClaimed, "live enforcement") {
		t.Fatalf("not-claimed list missing live-enforcement boundary: %#v", plan.NotClaimed)
	}
	if !containsText(plan.NotClaimed, "session state management") {
		t.Fatalf("not-claimed list missing session-state boundary: %#v", plan.NotClaimed)
	}
}

func TestBuildDaemonAcceptLoopPlanCopiesPeerPolicy(t *testing.T) {
	t.Parallel()

	custodyPlan, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	cfg := DefaultDaemonAcceptLoopConfig(custodyPlan, DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}, AllowedGIDs: []uint32{20}})

	plan, err := BuildDaemonAcceptLoopPlan(cfg)
	if err != nil {
		t.Fatalf("BuildDaemonAcceptLoopPlan returned error: %v", err)
	}
	cfg.PeerAuthorizationPolicy.AllowedUIDs[0] = 999
	cfg.PeerAuthorizationPolicy.AllowedGIDs[0] = 999
	if plan.AllowedUIDs[0] != 501 || plan.AllowedGIDs[0] != 20 {
		t.Fatalf("plan retained mutable policy slices: uids=%#v gids=%#v", plan.AllowedUIDs, plan.AllowedGIDs)
	}
}

func TestBuildDaemonAcceptLoopPlanAcceptsGIDOnlyPolicyAndInclusiveBounds(t *testing.T) {
	t.Parallel()

	custodyPlan, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	cfg := DaemonAcceptLoopConfig{
		CustodyPlan:              custodyPlan,
		PeerAuthorizationPolicy:  DaemonPeerAuthorizationPolicy{AllowedGIDs: []uint32{20}},
		MaxRequestBytes:          MaxDaemonAcceptLoopRequestBytes,
		ReadTimeout:              MaxDaemonAcceptLoopReadTimeout,
		MaxConcurrentConnections: MaxDaemonAcceptLoopConcurrentConnections,
	}

	plan, err := BuildDaemonAcceptLoopPlan(cfg)
	if err != nil {
		t.Fatalf("BuildDaemonAcceptLoopPlan returned error for inclusive bounds and GID-only policy: %v", err)
	}
	if len(plan.AllowedUIDs) != 0 {
		t.Fatalf("allowed uids = %#v, want none", plan.AllowedUIDs)
	}
	if len(plan.AllowedGIDs) != 1 || plan.AllowedGIDs[0] != 20 {
		t.Fatalf("allowed gids = %#v, want [20]", plan.AllowedGIDs)
	}
	if plan.MaxRequestBytes != MaxDaemonAcceptLoopRequestBytes {
		t.Fatalf("max request bytes = %d, want %d", plan.MaxRequestBytes, MaxDaemonAcceptLoopRequestBytes)
	}
	if plan.ReadTimeout != MaxDaemonAcceptLoopReadTimeout {
		t.Fatalf("read timeout = %s, want %s", plan.ReadTimeout, MaxDaemonAcceptLoopReadTimeout)
	}
	if plan.MaxConcurrentConnections != MaxDaemonAcceptLoopConcurrentConnections {
		t.Fatalf("max concurrent connections = %d, want %d", plan.MaxConcurrentConnections, MaxDaemonAcceptLoopConcurrentConnections)
	}
}

func TestBuildDaemonAcceptLoopPlanFailsClosed(t *testing.T) {
	t.Parallel()

	custodyPlan, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	valid := DefaultDaemonAcceptLoopConfig(custodyPlan, DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}})

	for _, tc := range []struct {
		name string
		mut  func(*DaemonAcceptLoopConfig)
	}{
		{
			name: "invalid custody plan",
			mut: func(cfg *DaemonAcceptLoopConfig) {
				cfg.CustodyPlan = DaemonCustodyPlan{}
			},
		},
		{
			name: "missing peer policy",
			mut: func(cfg *DaemonAcceptLoopConfig) {
				cfg.PeerAuthorizationPolicy = DaemonPeerAuthorizationPolicy{}
			},
		},
		{
			name: "zero max request bytes",
			mut: func(cfg *DaemonAcceptLoopConfig) {
				cfg.MaxRequestBytes = 0
			},
		},
		{
			name: "too many request bytes",
			mut: func(cfg *DaemonAcceptLoopConfig) {
				cfg.MaxRequestBytes = MaxDaemonAcceptLoopRequestBytes + 1
			},
		},
		{
			name: "zero read timeout",
			mut: func(cfg *DaemonAcceptLoopConfig) {
				cfg.ReadTimeout = 0
			},
		},
		{
			name: "too long read timeout",
			mut: func(cfg *DaemonAcceptLoopConfig) {
				cfg.ReadTimeout = MaxDaemonAcceptLoopReadTimeout + time.Nanosecond
			},
		},
		{
			name: "zero concurrent connections",
			mut: func(cfg *DaemonAcceptLoopConfig) {
				cfg.MaxConcurrentConnections = 0
			},
		},
		{
			name: "too many concurrent connections",
			mut: func(cfg *DaemonAcceptLoopConfig) {
				cfg.MaxConcurrentConnections = MaxDaemonAcceptLoopConcurrentConnections + 1
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := valid
			tc.mut(&cfg)
			_, err := BuildDaemonAcceptLoopPlan(cfg)
			if err == nil {
				t.Fatalf("expected fail-closed accept-loop plan error")
			}
			if !errors.Is(err, ErrDaemonAcceptLoopPlan) {
				t.Fatalf("expected ErrDaemonAcceptLoopPlan, got %v", err)
			}
		})
	}
}
