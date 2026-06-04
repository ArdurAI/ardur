package kernelcapture

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildDaemonSessionStatusEvidenceLogPlanRecordsNoWritePlan(t *testing.T) {
	t.Parallel()

	cfg := daemonSessionStatusEvidenceLogConfigForTest(t, "evidence-session")
	plan, err := BuildDaemonSessionStatusEvidenceLogPlan(cfg)
	if err != nil {
		t.Fatalf("BuildDaemonSessionStatusEvidenceLogPlan returned error: %v", err)
	}

	wantPath := filepath.Join(
		cfg.CustodyPlan.StateDir,
		"evidence",
		"sessions",
		daemonSessionHandoffSessionKey("evidence-session")+".evlog",
	)
	if plan.Mode != DaemonCustodyModeLocalOnlyScaffold {
		t.Fatalf("mode = %q, want %q", plan.Mode, DaemonCustodyModeLocalOnlyScaffold)
	}
	if plan.SessionID != "evidence-session" {
		t.Fatalf("session id = %q", plan.SessionID)
	}
	if plan.EvidenceLogPath != wantPath {
		t.Fatalf("evidence log path = %q, want %q", plan.EvidenceLogPath, wantPath)
	}
	if !lexicalPathWithin(plan.EvidenceLogPath, cfg.CustodyPlan.StateDir) {
		t.Fatalf("evidence log path escaped state dir: %q not within %q", plan.EvidenceLogPath, cfg.CustodyPlan.StateDir)
	}
	if plan.SchemaVersion != DaemonSessionStatusEvidenceLogSchemaVersion || plan.EntryKind != DaemonSessionStatusEvidenceLogEntryKind {
		t.Fatalf("schema/kind = %q/%q", plan.SchemaVersion, plan.EntryKind)
	}
	if len(plan.EntryDigest) != 64 {
		t.Fatalf("entry digest = %q, want sha256 hex", plan.EntryDigest)
	}
	if plan.MaxEntryBytes != DefaultDaemonSessionStatusEvidenceLogMaxEntryBytes || plan.MaxLogBytes != DefaultDaemonSessionStatusEvidenceLogMaxLogBytes || plan.MaxRotatedFiles != DefaultDaemonSessionStatusEvidenceLogMaxRotatedFiles {
		t.Fatalf("retention bounds = %d/%d/%d", plan.MaxEntryBytes, plan.MaxLogBytes, plan.MaxRotatedFiles)
	}
	if len(plan.Steps) == 0 {
		t.Fatalf("expected evidence-log plan steps")
	}
	for _, step := range plan.Steps {
		if step.Executed {
			t.Fatalf("evidence-log step %q executed; plan must remain no-mutation", step.Name)
		}
	}
	if !containsText(plan.ClaimBoundary, "performs no filesystem writes") {
		t.Fatalf("claim boundary missing no-write statement: %#v", plan.ClaimBoundary)
	}
	if !containsText(plan.NotClaimed, "evidence-log creation") {
		t.Fatalf("not-claimed list missing evidence-log creation boundary: %#v", plan.NotClaimed)
	}

	again, err := BuildDaemonSessionStatusEvidenceLogPlan(cfg)
	if err != nil {
		t.Fatalf("second BuildDaemonSessionStatusEvidenceLogPlan returned error: %v", err)
	}
	if again.EntryDigest != plan.EntryDigest {
		t.Fatalf("entry digest was not stable: %q != %q", again.EntryDigest, plan.EntryDigest)
	}

	// Mutating the returned plan must not mutate future plans built from the same snapshot.
	plan.Steps[0].Executed = true
	plan.ClaimBoundary[0] = "mutated"
	plan.NotClaimed[0] = "mutated"
	fresh, err := BuildDaemonSessionStatusEvidenceLogPlan(cfg)
	if err != nil {
		t.Fatalf("fresh BuildDaemonSessionStatusEvidenceLogPlan returned error: %v", err)
	}
	if fresh.Steps[0].Executed || fresh.ClaimBoundary[0] == "mutated" || fresh.NotClaimed[0] == "mutated" {
		t.Fatalf("caller mutation leaked into fresh plan: %#v", fresh)
	}
}

func TestBuildDaemonSessionStatusEvidenceLogPlanDigestTracksSnapshotContents(t *testing.T) {
	t.Parallel()

	cfg := daemonSessionStatusEvidenceLogConfigForTest(t, "digest-session")
	plan, err := BuildDaemonSessionStatusEvidenceLogPlan(cfg)
	if err != nil {
		t.Fatalf("BuildDaemonSessionStatusEvidenceLogPlan returned error: %v", err)
	}

	changed := cfg
	changed.Snapshot.Session.HandoffMetadata["handoff_source"] = "changed"
	changed.Snapshot.HandoffPlan.ClaimBoundary[0] = "changed claim boundary"
	changedPlan, err := BuildDaemonSessionStatusEvidenceLogPlan(changed)
	if err != nil {
		t.Fatalf("changed BuildDaemonSessionStatusEvidenceLogPlan returned error: %v", err)
	}
	if changedPlan.EntryDigest == plan.EntryDigest {
		t.Fatalf("entry digest did not change after snapshot content changed: %q", plan.EntryDigest)
	}
}

func TestBuildDaemonSessionStatusEvidenceLogPlanFailsClosed(t *testing.T) {
	t.Parallel()

	valid := daemonSessionStatusEvidenceLogConfigForTest(t, "fail-evidence-session")

	for _, tc := range []struct {
		name string
		mut  func(*DaemonSessionStatusEvidenceLogConfig)
		want string
	}{
		{name: "zero config", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) { *cfg = DaemonSessionStatusEvidenceLogConfig{} }, want: "custody"},
		{name: "invalid custody", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) { cfg.CustodyPlan.StateDir = "" }, want: "custody"},
		{name: "unsupported protocol version", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) {
			cfg.Snapshot.ProtocolResponse.ProtocolVersion = "kernelcapture.daemon.v0"
		}, want: "version"},
		{name: "non status response", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) {
			cfg.Snapshot.ProtocolResponse.Method = DaemonProtocolMethodHealth
		}, want: "session_status"},
		{name: "non ok response", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) {
			cfg.Snapshot.ProtocolResponse.OK = false
			cfg.Snapshot.ProtocolResponse.Error = "not ok"
		}, want: "not OK"},
		{name: "protocol response inactive", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) {
			cfg.Snapshot.ProtocolResponse.Status = DaemonSessionStatusEnded
		}, want: "status"},
		{name: "snapshot inactive", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) { cfg.Snapshot.Status = DaemonSessionStatusEnded }, want: "snapshot status"},
		{name: "empty session id", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) { cfg.Snapshot.Session.SessionID = "" }, want: "session id"},
		{name: "response session mismatch", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) {
			cfg.Snapshot.ProtocolResponse.SessionID = "other-session"
		}, want: "does not match"},
		{name: "handoff session mismatch", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) { cfg.Snapshot.HandoffPlan.SessionID = "other-session" }, want: "does not match"},
		{name: "zero AsOf", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) { cfg.Snapshot.AsOf = time.Time{} }, want: "AsOf"},
		{name: "missing handoff plan", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) {
			cfg.Snapshot.HandoffPlan = DaemonSessionHandoffPlan{SessionID: cfg.Snapshot.Session.SessionID}
		}, want: "handoff"},
		{name: "executed handoff step", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) { cfg.Snapshot.HandoffPlan.Steps[0].Executed = true }, want: "executed"},
		{name: "zero handoff cgroup", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) { cfg.Snapshot.HandoffPlan.CgroupID = 0 }, want: "cgroup"},
		{name: "handoff root pid mismatch", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) {
			cfg.Snapshot.HandoffPlan.RootPID = cfg.Snapshot.Session.RootPID + 1
		}, want: "root pid"},
		{name: "handoff state path escapes custody", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) {
			cfg.Snapshot.HandoffPlan.SessionStatePath = "/tmp/escape.json"
		}, want: "escaped"},
		{name: "handoff runtime dir escapes custody", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) {
			cfg.Snapshot.HandoffPlan.SessionRuntimeDir = "/tmp/escape-runtime"
		}, want: "escaped"},
		{name: "handoff bpffs path escapes custody", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) {
			cfg.Snapshot.HandoffPlan.CgroupAllowlistMapPath = "/tmp/escape-map"
		}, want: "escaped"},
		{name: "forbidden metadata", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) {
			cfg.Snapshot.Session.HandoffMetadata["raw_command"] = "rm -rf /"
		}, want: "forbidden"},
		{name: "zero max entry", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) { cfg.MaxEntryBytes = 0 }, want: "max entry"},
		{name: "too large max entry", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) {
			cfg.MaxEntryBytes = MaxDaemonSessionStatusEvidenceLogMaxEntryBytes + 1
		}, want: "max entry"},
		{name: "max log smaller than entry", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) { cfg.MaxEntryBytes = 1024; cfg.MaxLogBytes = 512 }, want: "less than max entry"},
		{name: "zero rotated files", mut: func(cfg *DaemonSessionStatusEvidenceLogConfig) { cfg.MaxRotatedFiles = 0 }, want: "rotated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := valid
			cfg.Snapshot = copyDaemonSessionStatusSnapshot(valid.Snapshot)
			tc.mut(&cfg)
			_, err := BuildDaemonSessionStatusEvidenceLogPlan(cfg)
			if err == nil {
				t.Fatalf("expected evidence-log plan failure")
			}
			if !errors.Is(err, ErrDaemonSessionStatusEvidenceLogPlan) {
				t.Fatalf("expected ErrDaemonSessionStatusEvidenceLogPlan, got %v", err)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func daemonSessionStatusEvidenceLogConfigForTest(t *testing.T, sessionID string) DaemonSessionStatusEvidenceLogConfig {
	t.Helper()

	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	handshake := daemonSessionRegistryTestHandshake(sessionID)
	custody, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}

	register := daemonRegisterSessionRequest(sessionID, 2468, 60)
	register.RegisterSession.CgroupID = 4242
	register.RegisterSession.MissionID = "mission-" + sessionID
	register.RegisterSession.TraceID = "trace-" + sessionID
	register.RegisterSession.HandoffMetadata = map[string]any{"handoff_source": "evidence_log_plan_test"}
	if response := registry.HandleAuthorizedRequest(t.Context(), register, handshake); !response.OK {
		t.Fatalf("register response = %#v", response)
	}

	snapshot, response := registry.HandleAuthorizedSessionStatusSnapshot(t.Context(), daemonSessionStatusRequest(sessionID), handshake, custody)
	if !response.OK {
		t.Fatalf("status snapshot response = %#v", response)
	}

	cfg := DefaultDaemonSessionStatusEvidenceLogConfig()
	cfg.CustodyPlan = custody
	cfg.Snapshot = snapshot
	return cfg
}
