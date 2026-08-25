package kernelcapture

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDaemonSessionRegistryBuildsAuthorizedStatusSnapshot(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 3, 18, 0, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	handshake := daemonSessionRegistryTestHandshake("session-snapshot")
	register := daemonRegisterSessionRequest("session-snapshot", 888, 60)
	register.RegisterSession.MissionID = "mission-snapshot"
	register.RegisterSession.TraceID = "trace-snapshot"
	register.RegisterSession.PIDNamespaceID = 4026531836
	register.RegisterSession.CgroupID = 8800
	register.RegisterSession.HandoffMetadata = map[string]any{"handoff_source": "launch_wrapper"}

	if response := registry.HandleAuthorizedRequest(context.Background(), register, handshake); !response.OK {
		t.Fatalf("register response = %#v", response)
	}
	custody, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}

	snapshot, response := registry.HandleAuthorizedSessionStatusSnapshot(context.Background(), daemonSessionStatusRequest(" session-snapshot "), handshake, custody)
	if !response.OK || response.Method != DaemonProtocolMethodSessionStatus || response.SessionID != "session-snapshot" || response.Status != DaemonSessionStatusActive {
		t.Fatalf("snapshot response = %#v", response)
	}
	if snapshot.ProtocolResponse != response {
		t.Fatalf("snapshot protocol response = %#v, want %#v", snapshot.ProtocolResponse, response)
	}
	if snapshot.AsOf != now || snapshot.Status != DaemonSessionStatusActive {
		t.Fatalf("snapshot time/status = %s/%q", snapshot.AsOf, snapshot.Status)
	}
	if snapshot.Session.SessionID != "session-snapshot" || snapshot.Session.RootPID != 888 || snapshot.Session.CgroupID != 8800 {
		t.Fatalf("snapshot session = %#v", snapshot.Session)
	}
	if snapshot.Session.MissionID != "mission-snapshot" || snapshot.Session.TraceID != "trace-snapshot" {
		t.Fatalf("snapshot identity = %#v", snapshot.Session)
	}
	if snapshot.HandoffPlan.SessionID != "session-snapshot" || snapshot.HandoffPlan.CgroupID != 8800 {
		t.Fatalf("snapshot handoff plan = %#v", snapshot.HandoffPlan)
	}
	if !containsText(snapshot.ClaimBoundary, "internal daemon status snapshot") {
		t.Fatalf("claim boundary missing status snapshot wording: %#v", snapshot.ClaimBoundary)
	}
	if !containsText(snapshot.NotClaimed, "client-visible protocol expansion") {
		t.Fatalf("not-claimed list missing protocol expansion boundary: %#v", snapshot.NotClaimed)
	}
	for _, step := range snapshot.HandoffPlan.Steps {
		if step.Executed {
			t.Fatalf("snapshot handoff step %q executed; snapshot must remain no-mutation", step.Name)
		}
	}
	encoded, err := EncodeDaemonProtocolResponse(response)
	if err != nil {
		t.Fatalf("EncodeDaemonProtocolResponse returned error: %v", err)
	}
	if strings.Contains(string(encoded), "handoff") || strings.Contains(string(encoded), "root_pid") || strings.Contains(string(encoded), "cgroup") {
		t.Fatalf("client protocol response leaked internal snapshot fields: %s", string(encoded))
	}

	// The snapshot must be detached from registry-owned state.
	snapshot.Session.EventClasses[0] = "mutated"
	snapshot.Session.HandoffMetadata["handoff_source"] = "mutated"
	fresh, err := registry.BuildSessionStatusSnapshot("session-snapshot", custody)
	if err != nil {
		t.Fatalf("BuildSessionStatusSnapshot returned error: %v", err)
	}
	if fresh.Session.EventClasses[0] != DaemonProtocolEventProcessLifecycle || fresh.Session.HandoffMetadata["handoff_source"] != "launch_wrapper" {
		t.Fatalf("snapshot mutation leaked into registry state: %#v", fresh.Session)
	}
}

func TestDaemonSessionRegistryStatusSnapshotRejectsDifferentPeer(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 3, 18, 30, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	owner := daemonSessionRegistryTestHandshake("session-snapshot-owned")
	register := daemonRegisterSessionRequest("session-snapshot-owned", 888, 60)
	register.RegisterSession.CgroupID = 8800

	if response := registry.HandleAuthorizedRequest(context.Background(), register, owner); !response.OK {
		t.Fatalf("register response = %#v", response)
	}
	custody, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}

	other := owner
	other.Authorization.UID = 502
	other.Authorization.GID = 21
	other.Authorization.PID = 9876
	other.Authorization.Reason = "different authorized peer"

	snapshot, response := registry.HandleAuthorizedSessionStatusSnapshot(context.Background(), daemonSessionStatusRequest("session-snapshot-owned"), other, custody)
	if response.OK || response.Status != DaemonSessionStatusActive || !strings.Contains(response.Error, "different peer") {
		t.Fatalf("different peer snapshot response = %#v", response)
	}
	if snapshot.Status != "" || snapshot.Session.SessionID != "" || snapshot.HandoffPlan.SessionID != "" {
		t.Fatalf("different peer produced snapshot = %#v", snapshot)
	}
}

func TestDaemonSessionRegistryStatusSnapshotFailsClosedWithoutProtocolExpansion(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 3, 19, 0, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	handshake := daemonSessionRegistryTestHandshake("session-fail-snapshot")
	register := daemonRegisterSessionRequest("session-fail-snapshot", 999, 60)
	register.RegisterSession.CgroupID = 9900
	if response := registry.HandleAuthorizedRequest(context.Background(), register, handshake); !response.OK {
		t.Fatalf("register response = %#v", response)
	}
	custody, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}

	invalidCustody := custody
	invalidCustody.StateDir = ""
	if _, err := registry.BuildSessionStatusSnapshot("session-fail-snapshot", invalidCustody); !errors.Is(err, ErrDaemonSessionHandoffPlan) {
		t.Fatalf("invalid custody snapshot error = %v", err)
	}

	snapshot, response := registry.HandleAuthorizedSessionStatusSnapshot(context.Background(), daemonRegisterSessionRequest("client-register", 111, 60), handshake, custody)
	if response.OK || !strings.Contains(response.Error, "session_status") {
		t.Fatalf("non-status snapshot response = %#v", response)
	}
	if snapshot.Status != "" || snapshot.Session.SessionID != "" || snapshot.HandoffPlan.SessionID != "" {
		t.Fatalf("non-status request produced snapshot = %#v", snapshot)
	}
	if _, ok := registry.Session("client-register"); ok {
		t.Fatalf("snapshot wrapper mutated registry by handling register_session")
	}

	denied := handshake
	denied.Authorization.Verdict = DaemonPeerAuthorizationVerdictDeny
	snapshot, response = registry.HandleAuthorizedSessionStatusSnapshot(context.Background(), daemonSessionStatusRequest("session-fail-snapshot"), denied, custody)
	if response.OK || !strings.Contains(response.Error, "allow verdict") {
		t.Fatalf("denied peer snapshot response = %#v", response)
	}
	if snapshot.Status != "" || snapshot.Session.SessionID != "" || snapshot.HandoffPlan.SessionID != "" {
		t.Fatalf("denied peer produced snapshot = %#v", snapshot)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	snapshot, response = registry.HandleAuthorizedSessionStatusSnapshot(ctx, daemonSessionStatusRequest("session-fail-snapshot"), handshake, custody)
	if response.OK || !strings.Contains(response.Error, "context canceled") {
		t.Fatalf("canceled context snapshot response = %#v", response)
	}
	if snapshot.Status != "" || snapshot.Session.SessionID != "" || snapshot.HandoffPlan.SessionID != "" {
		t.Fatalf("canceled context produced snapshot = %#v", snapshot)
	}

	now = now.Add(61 * time.Second)
	snapshot, response = registry.HandleAuthorizedSessionStatusSnapshot(context.Background(), daemonSessionStatusRequest("session-fail-snapshot"), handshake, custody)
	if response.OK || response.Status != DaemonSessionStatusExpired || !strings.Contains(response.Error, "expired") {
		t.Fatalf("expired snapshot response = %#v", response)
	}
	if snapshot.Status != "" || snapshot.Session.SessionID != "" || snapshot.HandoffPlan.SessionID != "" {
		t.Fatalf("expired session produced snapshot = %#v", snapshot)
	}
}
