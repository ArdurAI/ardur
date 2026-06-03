package kernelcapture

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestBuildDaemonSessionHandoffPlanFromRegisteredLaunchWrapperSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 3, 16, 0, 0, 0, time.UTC)
	proof, err := BuildLaunchWrapperSessionProof(LaunchWrapperSessionMetadata{
		SessionID:               "cli:unsafe/../session-1",
		MissionID:               "mission-1",
		TraceID:                 "trace-1",
		Command:                 []string{"python3", "-c", "print('ok')"},
		WorkingDirectory:        "/workspace/ardur",
		RootPID:                 4242,
		PIDNamespaceID:          4026531836,
		ProcessStartMonotonicNS: 9_100_000_000,
		CgroupID:                77,
		StartedAt:               now.Add(-1 * time.Second),
		TTLSeconds:              60,
		HandoffMetadata:         map[string]any{"launcher": "ardur run"},
	})
	if err != nil {
		t.Fatalf("BuildLaunchWrapperSessionProof returned error: %v", err)
	}

	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	response := registry.HandleAuthorizedRequest(context.Background(), proof.RegisterSessionRequest, daemonSessionRegistryTestHandshake("cli:unsafe/../session-1"))
	if !response.OK {
		t.Fatalf("register response = %#v", response)
	}
	record, ok := registry.Session("cli:unsafe/../session-1")
	if !ok {
		t.Fatalf("registered session missing")
	}
	custody, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}

	plan, err := BuildDaemonSessionHandoffPlan(DaemonSessionHandoffConfig{
		CustodyPlan: custody,
		Session:     record,
		AsOf:        now,
	})
	if err != nil {
		t.Fatalf("BuildDaemonSessionHandoffPlan returned error: %v", err)
	}
	if plan.Mode != DaemonCustodyModeLocalOnlyScaffold {
		t.Fatalf("mode = %q, want local-only scaffold", plan.Mode)
	}
	if plan.SessionID != "cli:unsafe/../session-1" || plan.MissionID != "mission-1" || plan.TraceID != "trace-1" {
		t.Fatalf("plan identity = %#v", plan)
	}
	if plan.RootPID != 4242 || plan.PIDNamespaceID != 4026531836 || plan.CgroupID != 77 {
		t.Fatalf("plan process identity = %#v", plan)
	}
	if plan.SessionKey == "" || strings.Contains(plan.SessionKey, "/") || strings.Contains(plan.SessionKey, "..") {
		t.Fatalf("unsafe session key = %q", plan.SessionKey)
	}
	for _, path := range []string{plan.SessionStatePath, plan.SessionRuntimeDir} {
		if strings.Contains(path, "unsafe") || strings.Contains(path, "..") {
			t.Fatalf("daemon-owned path includes raw/unsafe session id: %q", path)
		}
	}
	if !lexicalPathWithin(plan.SessionStatePath, custody.StateDir) {
		t.Fatalf("session state path %q is not under state dir %q", plan.SessionStatePath, custody.StateDir)
	}
	if !lexicalPathWithin(plan.SessionRuntimeDir, custody.RunDir) {
		t.Fatalf("session runtime dir %q is not under run dir %q", plan.SessionRuntimeDir, custody.RunDir)
	}
	if !lexicalPathWithin(plan.CgroupAllowlistMapPath, custody.BPFFSDir) {
		t.Fatalf("allowlist map path %q is not under bpffs dir %q", plan.CgroupAllowlistMapPath, custody.BPFFSDir)
	}
	if plan.CgroupFilterSequence.Enable != true || len(plan.CgroupFilterSequence.AllowlistCgroupIDs) != 1 || plan.CgroupFilterSequence.AllowlistCgroupIDs[0] != 77 {
		t.Fatalf("cgroup filter sequence = %#v", plan.CgroupFilterSequence)
	}
	if err := ValidateCgroupFilterSequence(plan.CgroupFilterSequence); err != nil {
		t.Fatalf("planned cgroup filter sequence should validate: %v", err)
	}
	if len(plan.Steps) < 5 {
		t.Fatalf("expected handoff steps, got %d", len(plan.Steps))
	}
	for _, step := range plan.Steps {
		if step.Executed {
			t.Fatalf("step %q executed; handoff plan must be no-mutation", step.Name)
		}
	}
	if !containsText(plan.ClaimBoundary, "registered session metadata is projected into daemon-owned handoff paths") {
		t.Fatalf("claim boundary missing handoff wording: %#v", plan.ClaimBoundary)
	}
	if !containsText(plan.NotClaimed, "daemon-created/assigned cgroups") {
		t.Fatalf("not-claimed list missing cgroup creation boundary: %#v", plan.NotClaimed)
	}
}

func TestBuildDaemonSessionHandoffPlanFailsClosed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 3, 17, 0, 0, 0, time.UTC)
	custody, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	valid := daemonSessionHandoffPlanTestRecord(now)

	for _, tc := range []struct {
		name string
		mut  func(*DaemonSessionHandoffConfig)
	}{
		{name: "missing session id", mut: func(cfg *DaemonSessionHandoffConfig) { cfg.Session.SessionID = "" }},
		{name: "missing root pid", mut: func(cfg *DaemonSessionHandoffConfig) { cfg.Session.RootPID = 0 }},
		{name: "missing cgroup id", mut: func(cfg *DaemonSessionHandoffConfig) { cfg.Session.CgroupID = 0 }},
		{name: "ended session", mut: func(cfg *DaemonSessionHandoffConfig) { cfg.Session.EndedAt = now.Add(-1 * time.Second) }},
		{name: "expired session", mut: func(cfg *DaemonSessionHandoffConfig) { cfg.Session.ExpiresAt = now.Add(-1 * time.Second) }},
		{name: "missing process lifecycle event", mut: func(cfg *DaemonSessionHandoffConfig) { cfg.Session.EventClasses = []string{"future_file_events"} }},
		{name: "invalid custody plan", mut: func(cfg *DaemonSessionHandoffConfig) { cfg.CustodyPlan.StateDir = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := DaemonSessionHandoffConfig{CustodyPlan: custody, Session: valid, AsOf: now}
			tc.mut(&cfg)
			_, err := BuildDaemonSessionHandoffPlan(cfg)
			if err == nil {
				t.Fatalf("expected validation error")
			}
			if !errors.Is(err, ErrDaemonSessionHandoffPlan) {
				t.Fatalf("expected ErrDaemonSessionHandoffPlan, got %v", err)
			}
		})
	}
}

func daemonSessionHandoffPlanTestRecord(now time.Time) DaemonSessionRecord {
	return DaemonSessionRecord{
		SessionID:        "session-handoff",
		MissionID:        "mission-handoff",
		TraceID:          "trace-handoff",
		RootPID:          1111,
		PIDNamespaceID:   4026531836,
		CgroupID:         99,
		EventClasses:     []string{DaemonProtocolEventProcessLifecycle},
		HandoffMetadata:  map[string]any{"handoff_source": "launch_wrapper"},
		RegisteredAt:     now.Add(-1 * time.Second),
		ExpiresAt:        now.Add(60 * time.Second),
		PeerUID:          501,
		PeerGID:          20,
		PeerPID:          4321,
		CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
		SocketPath:       "/run/ardur/kernelcapture/control.sock",
	}
}
