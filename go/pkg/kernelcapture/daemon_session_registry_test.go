package kernelcapture

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDaemonSessionRegistryRegistersStatusesAndEndsSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	handshake := daemonSessionRegistryTestHandshake("session-1")
	register := daemonRegisterSessionRequest("session-1", 1234, 60)
	register.RegisterSession.MissionID = "mission-1"
	register.RegisterSession.TraceID = "trace-1"
	register.RegisterSession.PIDNamespaceID = 42
	register.RegisterSession.CgroupID = 99
	register.RegisterSession.HandoffMetadata = map[string]any{"command_argc": float64(2), "handoff_source": "launch_wrapper"}

	response := registry.HandleAuthorizedRequest(context.Background(), register, handshake)
	if !response.OK {
		t.Fatalf("register response ok=false, error=%q", response.Error)
	}
	if response.Method != DaemonProtocolMethodRegisterSession || response.SessionID != "session-1" || response.Status != DaemonSessionStatusRegistered {
		t.Fatalf("register response = %#v", response)
	}

	record, ok := registry.Session("session-1")
	if !ok {
		t.Fatalf("registered session missing from registry")
	}
	if record.SessionID != "session-1" || record.MissionID != "mission-1" || record.TraceID != "trace-1" {
		t.Fatalf("record identity = %#v", record)
	}
	if record.RootPID != 1234 || record.PIDNamespaceID != 42 || record.CgroupID != 99 {
		t.Fatalf("record process identity = %#v", record)
	}
	if len(record.EventClasses) != 1 || record.EventClasses[0] != DaemonProtocolEventProcessLifecycle {
		t.Fatalf("event classes = %#v", record.EventClasses)
	}
	if !record.RegisteredAt.Equal(now) || !record.ExpiresAt.Equal(now.Add(60*time.Second)) || !record.EndedAt.IsZero() {
		t.Fatalf("record times registered=%s expires=%s ended=%s", record.RegisteredAt, record.ExpiresAt, record.EndedAt)
	}
	if record.PeerUID != 501 || record.PeerGID != 20 || record.PeerPID != 4321 || record.CredentialSource != DaemonPeerCredentialSourceLinuxSOPeerCred {
		t.Fatalf("record peer evidence = %#v", record)
	}
	if record.SocketPath != "/run/ardur/kernelcapture/control.sock" {
		t.Fatalf("socket path = %q", record.SocketPath)
	}
	if record.Status(now) != DaemonSessionStatusActive {
		t.Fatalf("record status = %q, want active", record.Status(now))
	}

	// The registry must not retain mutable caller-owned slices/maps.
	register.RegisterSession.EventClasses[0] = "mutated"
	register.RegisterSession.HandoffMetadata["handoff_source"] = "mutated"
	record, ok = registry.Session("session-1")
	if !ok {
		t.Fatalf("registered session missing after mutation check")
	}
	if record.EventClasses[0] != DaemonProtocolEventProcessLifecycle {
		t.Fatalf("registry retained mutable event class slice: %#v", record.EventClasses)
	}
	if record.HandoffMetadata["handoff_source"] != "launch_wrapper" {
		t.Fatalf("registry retained mutable handoff metadata: %#v", record.HandoffMetadata)
	}

	status := registry.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest("session-1"), handshake)
	if !status.OK || status.Status != DaemonSessionStatusActive {
		t.Fatalf("active status response = %#v", status)
	}

	now = now.Add(5 * time.Second)
	ended := registry.HandleAuthorizedRequest(context.Background(), daemonEndSessionRequest("session-1"), handshake)
	if !ended.OK || ended.Status != DaemonSessionStatusEnded {
		t.Fatalf("end response = %#v", ended)
	}
	record, ok = registry.Session("session-1")
	if !ok || !record.EndedAt.Equal(now) || record.Status(now) != DaemonSessionStatusEnded {
		t.Fatalf("ended record = %#v ok=%t", record, ok)
	}

	endedStatus := registry.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest("session-1"), handshake)
	if endedStatus.OK || endedStatus.Status != DaemonSessionStatusEnded || !strings.Contains(endedStatus.Error, "not active") {
		t.Fatalf("ended status response = %#v", endedStatus)
	}
}

func TestDaemonSessionRegistryRejectsDuplicateActiveSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 2, 12, 30, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	handshake := daemonSessionRegistryTestHandshake("session-dup")
	first := daemonRegisterSessionRequest("session-dup", 111, 60)
	second := daemonRegisterSessionRequest("session-dup", 222, 60)

	if response := registry.HandleAuthorizedRequest(context.Background(), first, handshake); !response.OK {
		t.Fatalf("first register response = %#v", response)
	}
	duplicate := registry.HandleAuthorizedRequest(context.Background(), second, handshake)
	if duplicate.OK || duplicate.Status != DaemonSessionStatusActive || !strings.Contains(duplicate.Error, "already active") {
		t.Fatalf("duplicate response = %#v", duplicate)
	}
	record, ok := registry.Session("session-dup")
	if !ok || record.RootPID != 111 {
		t.Fatalf("duplicate register mutated active record = %#v ok=%t", record, ok)
	}
}

func TestDaemonSessionRegistryRejectsEndSessionByDifferentPeer(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 2, 12, 40, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	owner := daemonSessionRegistryTestHandshake("session-owned")
	register := daemonRegisterSessionRequest("session-owned", 1234, 60)

	if response := registry.HandleAuthorizedRequest(context.Background(), register, owner); !response.OK {
		t.Fatalf("register response = %#v", response)
	}

	other := owner
	other.Authorization.UID = 502
	other.Authorization.GID = 21
	other.Authorization.PID = 9876
	other.Authorization.Reason = "different authorized peer"
	now = now.Add(5 * time.Second)

	rejected := registry.HandleAuthorizedRequest(context.Background(), daemonEndSessionRequest("session-owned"), other)
	if rejected.OK || rejected.Status != DaemonSessionStatusActive || !strings.Contains(rejected.Error, "different peer") {
		t.Fatalf("different peer end response = %#v", rejected)
	}
	record, ok := registry.Session("session-owned")
	if !ok || record.Status(now) != DaemonSessionStatusActive || !record.EndedAt.IsZero() {
		t.Fatalf("different peer mutated session = %#v ok=%t", record, ok)
	}

	ended := registry.HandleAuthorizedRequest(context.Background(), daemonEndSessionRequest("session-owned"), owner)
	if !ended.OK || ended.Status != DaemonSessionStatusEnded {
		t.Fatalf("owner end response = %#v", ended)
	}
}

func TestDaemonSessionRegistryRejectsStatusByDifferentPeer(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 2, 12, 42, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	owner := daemonSessionRegistryTestHandshake("session-status-owned")
	register := daemonRegisterSessionRequest("session-status-owned", 1234, 60)

	if response := registry.HandleAuthorizedRequest(context.Background(), register, owner); !response.OK {
		t.Fatalf("register response = %#v", response)
	}

	other := owner
	other.Authorization.UID = 502
	other.Authorization.GID = 21
	other.Authorization.PID = 9876
	other.Authorization.Reason = "different authorized peer"
	now = now.Add(5 * time.Second)

	rejected := registry.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest("session-status-owned"), other)
	if rejected.OK || rejected.Status != DaemonSessionStatusActive || !strings.Contains(rejected.Error, "different peer") {
		t.Fatalf("different peer status response = %#v", rejected)
	}

	ownerStatus := registry.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest("session-status-owned"), owner)
	if !ownerStatus.OK || ownerStatus.Status != DaemonSessionStatusActive {
		t.Fatalf("owner status response = %#v", ownerStatus)
	}
}

func TestDaemonSessionRegistryRejectsNonAllowPeerHandshake(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 2, 12, 45, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	handshake := daemonSessionRegistryTestHandshake("session-denied")
	handshake.Authorization.Verdict = DaemonPeerAuthorizationVerdictDeny
	handshake.Authorization.Reason = "test denied peer"

	response := registry.HandleAuthorizedRequest(context.Background(), daemonRegisterSessionRequest("session-denied", 222, 60), handshake)
	if response.OK || !strings.Contains(response.Error, "allow verdict") {
		t.Fatalf("non-allow handshake response = %#v", response)
	}
	if _, ok := registry.Session("session-denied"); ok {
		t.Fatalf("non-allow handshake registered a session")
	}
}

func TestDaemonSessionRegistryEnforcesMaxActiveSessions(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 2, 12, 55, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	registry.maxSessions = 1
	handshake := daemonSessionRegistryTestHandshake("session-cap")

	if response := registry.HandleAuthorizedRequest(context.Background(), daemonRegisterSessionRequest("session-a", 111, 60), handshake); !response.OK {
		t.Fatalf("first register response = %#v", response)
	}
	capacity := registry.HandleAuthorizedRequest(context.Background(), daemonRegisterSessionRequest("session-b", 222, 60), handshake)
	if capacity.OK || capacity.Status != DaemonSessionStatusCapacityExceeded || !strings.Contains(capacity.Error, "capacity exceeded") {
		t.Fatalf("capacity response = %#v", capacity)
	}

	if response := registry.HandleAuthorizedRequest(context.Background(), daemonEndSessionRequest("session-a"), handshake); !response.OK {
		t.Fatalf("end session-a response = %#v", response)
	}
	reused := registry.HandleAuthorizedRequest(context.Background(), daemonRegisterSessionRequest("session-b", 222, 60), handshake)
	if !reused.OK || reused.Status != DaemonSessionStatusRegistered {
		t.Fatalf("register after ended session prune response = %#v", reused)
	}
	if _, ok := registry.Session("session-a"); ok {
		t.Fatalf("inactive session-a was not pruned before admitting replacement")
	}
}

func TestDaemonSessionRegistryExpiresAndRejectsUnknownSessions(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 2, 13, 0, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	handshake := daemonSessionRegistryTestHandshake("session-expire")

	missing := registry.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest("missing"), handshake)
	if missing.OK || missing.Status != DaemonSessionStatusNotFound || !strings.Contains(missing.Error, "not found") {
		t.Fatalf("missing status response = %#v", missing)
	}

	if response := registry.HandleAuthorizedRequest(context.Background(), daemonRegisterSessionRequest("session-expire", 333, 1), handshake); !response.OK {
		t.Fatalf("register response = %#v", response)
	}
	now = now.Add(2 * time.Second)
	expired := registry.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest("session-expire"), handshake)
	if expired.OK || expired.Status != DaemonSessionStatusExpired || !strings.Contains(expired.Error, "expired") {
		t.Fatalf("expired status response = %#v", expired)
	}
	endedExpired := registry.HandleAuthorizedRequest(context.Background(), daemonEndSessionRequest("session-expire"), handshake)
	if endedExpired.OK || endedExpired.Status != DaemonSessionStatusExpired || !strings.Contains(endedExpired.Error, "expired") {
		t.Fatalf("end expired response = %#v", endedExpired)
	}
}

func TestDaemonSessionRegistryBuildsHandoffPlanForActiveStatusSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 2, 13, 30, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	handshake := daemonSessionRegistryTestHandshake("session-plan")
	register := daemonRegisterSessionRequest("session-plan", 555, 60)
	register.RegisterSession.MissionID = "mission-plan"
	register.RegisterSession.TraceID = "trace-plan"
	register.RegisterSession.PIDNamespaceID = 4026531836
	register.RegisterSession.CgroupID = 12345
	register.RegisterSession.HandoffMetadata = map[string]any{"handoff_source": "launch_wrapper"}

	if response := registry.HandleAuthorizedRequest(context.Background(), register, handshake); !response.OK {
		t.Fatalf("register response = %#v", response)
	}
	status := registry.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest("session-plan"), handshake)
	if !status.OK || status.Method != DaemonProtocolMethodSessionStatus || status.Status != DaemonSessionStatusActive {
		t.Fatalf("active status response = %#v", status)
	}

	record, err := registry.ActiveSession(" session-plan ")
	if err != nil {
		t.Fatalf("ActiveSession returned error: %v", err)
	}
	if record.SessionID != "session-plan" || record.CgroupID != 12345 || record.RootPID != 555 {
		t.Fatalf("active session record = %#v", record)
	}
	record.CgroupID = 0 // returned records must be copies, not mutable registry state.

	custody, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	plan, err := registry.BuildActiveSessionHandoffPlan(" session-plan ", custody)
	if err != nil {
		t.Fatalf("BuildActiveSessionHandoffPlan returned error: %v", err)
	}
	if plan.SessionID != "session-plan" || plan.MissionID != "mission-plan" || plan.TraceID != "trace-plan" {
		t.Fatalf("plan identity = %#v", plan)
	}
	if plan.RootPID != 555 || plan.PIDNamespaceID != 4026531836 || plan.CgroupID != 12345 {
		t.Fatalf("plan process identity = %#v", plan)
	}
	if !lexicalPathWithin(plan.SessionStatePath, custody.StateDir) || !lexicalPathWithin(plan.SessionRuntimeDir, custody.RunDir) {
		t.Fatalf("planned session paths escaped daemon custody roots: %#v", plan)
	}
	if plan.CgroupFilterSequence.Enable != true || len(plan.CgroupFilterSequence.AllowlistCgroupIDs) != 1 || plan.CgroupFilterSequence.AllowlistCgroupIDs[0] != 12345 {
		t.Fatalf("cgroup filter sequence = %#v", plan.CgroupFilterSequence)
	}
	for _, step := range plan.Steps {
		if step.Executed {
			t.Fatalf("step %q executed; registry handoff plan must remain no-mutation", step.Name)
		}
	}
}

func TestDaemonSessionRegistryHandoffPlanFailsClosedForInactiveMissingAndInvalidCustody(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 2, 13, 45, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	handshake := daemonSessionRegistryTestHandshake("session-fail-closed")
	register := daemonRegisterSessionRequest("session-fail-closed", 777, 60)
	register.RegisterSession.CgroupID = 7007
	if response := registry.HandleAuthorizedRequest(context.Background(), register, handshake); !response.OK {
		t.Fatalf("register response = %#v", response)
	}
	custody, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}

	if _, err := registry.ActiveSession("missing-session"); !errors.Is(err, ErrDaemonSessionRegistry) || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing ActiveSession error = %v", err)
	}
	if _, err := registry.BuildActiveSessionHandoffPlan("missing-session", custody); !errors.Is(err, ErrDaemonSessionRegistry) || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing BuildActiveSessionHandoffPlan error = %v", err)
	}

	invalidCustody := custody
	invalidCustody.StateDir = ""
	if _, err := registry.BuildActiveSessionHandoffPlan("session-fail-closed", invalidCustody); !errors.Is(err, ErrDaemonSessionHandoffPlan) {
		t.Fatalf("invalid custody handoff error = %v", err)
	}

	now = now.Add(61 * time.Second)
	if _, err := registry.ActiveSession("session-fail-closed"); !errors.Is(err, ErrDaemonSessionRegistry) || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired ActiveSession error = %v", err)
	}
	if _, err := registry.BuildActiveSessionHandoffPlan("session-fail-closed", custody); !errors.Is(err, ErrDaemonSessionRegistry) || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired BuildActiveSessionHandoffPlan error = %v", err)
	}
}

func TestDaemonUnixSocketServerHandlesSessionLifecycleWithRegistry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 2, 14, 0, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	server, cancel := startDaemonUnixSocketServerForTest(t, daemonSocketServerTestOptions{
		policy: DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
		observePeer: func(_ *net.UnixConn, socketPath string) (DaemonSocketPeerObservation, error) {
			return DaemonSocketPeerObservation{
				Credentials:      DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 4321},
				CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
				SocketPath:       socketPath,
			}, nil
		},
		handleAuthorizedRequest: registry.HandleAuthorizedRequest,
	})
	defer cancel()

	registered := sendDaemonUnixSocketRequest(t, server.SocketPath(), daemonEncodeProtocolRequest(t, daemonRegisterSessionRequest("socket-session", 444, 60)))
	if !registered.OK || registered.Method != DaemonProtocolMethodRegisterSession || registered.SessionID != "socket-session" || registered.Status != DaemonSessionStatusRegistered {
		t.Fatalf("socket register response = %#v", registered)
	}
	active := sendDaemonUnixSocketRequest(t, server.SocketPath(), daemonEncodeProtocolRequest(t, daemonSessionStatusRequest("socket-session")))
	if !active.OK || active.Status != DaemonSessionStatusActive {
		t.Fatalf("socket active response = %#v", active)
	}
	now = now.Add(10 * time.Second)
	ended := sendDaemonUnixSocketRequest(t, server.SocketPath(), daemonEncodeProtocolRequest(t, daemonEndSessionRequest("socket-session")))
	if !ended.OK || ended.Status != DaemonSessionStatusEnded {
		t.Fatalf("socket end response = %#v", ended)
	}
	inactive := sendDaemonUnixSocketRequest(t, server.SocketPath(), daemonEncodeProtocolRequest(t, daemonSessionStatusRequest("socket-session")))
	if inactive.OK || inactive.Status != DaemonSessionStatusEnded || !strings.Contains(inactive.Error, "not active") {
		t.Fatalf("socket ended status response = %#v", inactive)
	}
}

func daemonSessionRegistryTestHandshake(sessionID string) DaemonProtocolPeerHandshake {
	return DaemonProtocolPeerHandshake{
		ProtocolVersion:  DaemonProtocolVersion,
		Method:           DaemonProtocolMethodRegisterSession,
		SessionID:        sessionID,
		SocketPath:       "/run/ardur/kernelcapture/control.sock",
		CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
		Authorization: DaemonPeerAuthorization{
			Verdict: DaemonPeerAuthorizationVerdictAllow,
			Reason:  "observed peer uid is explicitly allowed",
			UID:     501,
			GID:     20,
			PID:     4321,
			Matched: "uid",
		},
	}
}

func daemonRegisterSessionRequest(sessionID string, rootPID uint32, ttlSeconds int64) DaemonProtocolRequest {
	return DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodRegisterSession,
		RegisterSession: &DaemonRegisterSessionRequest{
			SessionID:    sessionID,
			RootPID:      rootPID,
			EventClasses: []string{DaemonProtocolEventProcessLifecycle},
			TTLSeconds:   ttlSeconds,
		},
	}
}

func daemonSessionStatusRequest(sessionID string) DaemonProtocolRequest {
	return DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodSessionStatus,
		SessionStatus:   &DaemonSessionStatusRequest{SessionID: sessionID},
	}
}

func daemonEndSessionRequest(sessionID string) DaemonProtocolRequest {
	return DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodEndSession,
		EndSession:      &DaemonEndSessionRequest{SessionID: sessionID},
	}
}

func daemonEncodeProtocolRequest(t *testing.T, req DaemonProtocolRequest) []byte {
	t.Helper()
	encoded, err := EncodeDaemonProtocolRequest(req)
	if err != nil {
		t.Fatalf("EncodeDaemonProtocolRequest returned error: %v", err)
	}
	return encoded
}
