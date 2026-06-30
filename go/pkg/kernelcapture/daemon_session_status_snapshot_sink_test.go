package kernelcapture

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDaemonSessionStatusSnapshotSinkRetainsDetachedSessionStatusSnapshot(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 3, 20, 0, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	custody, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	sink := NewDaemonSessionStatusSnapshotSink()
	handler := NewDaemonSessionStatusSnapshotHandler(registry, custody, sink)

	server, cancel := startDaemonUnixSocketServerForTest(t, daemonSocketServerTestOptions{
		policy: DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
		observePeer: func(_ *net.UnixConn, socketPath string) (DaemonSocketPeerObservation, error) {
			return DaemonSocketPeerObservation{
				Credentials:      DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 4321, ProcessStartTimeTicks: 800004},
				CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
				SocketPath:       socketPath,
			}, nil
		},
		handleAuthorizedRequest: handler.HandleAuthorizedRequest,
	})
	defer cancel()

	// Register a session first.
	registerReq := daemonRegisterSessionRequest("sink-session", 777, 60)
	registerReq.RegisterSession.MissionID = "mission-sink"
	registerReq.RegisterSession.CgroupID = 7700
	registered := sendDaemonUnixSocketRequest(t, server.SocketPath(), daemonEncodeProtocolRequest(t, registerReq))
	if !registered.OK || registered.SessionID != "sink-session" || registered.Status != DaemonSessionStatusRegistered {
		t.Fatalf("register response = %#v", registered)
	}

	// Request session_status through the Unix socket and inspect the actual wire bytes.
	wireResponse, response := sendDaemonUnixSocketRawRequest(t, server.SocketPath(), daemonEncodeProtocolRequest(t, daemonSessionStatusRequest("sink-session")))
	if !response.OK || response.Method != DaemonProtocolMethodSessionStatus || response.Status != DaemonSessionStatusActive {
		t.Fatalf("session_status response = %#v", response)
	}

	// Wire protocol response must remain narrow: no handoff, root_pid, cgroup,
	// or internal fields leaked.
	for _, forbidden := range []string{"handoff", "root_pid", "cgroup", "internal"} {
		if strings.Contains(strings.ToLower(string(wireResponse)), forbidden) {
			t.Fatalf("wire response leaked internal field %q: %s", forbidden, string(wireResponse))
		}
	}

	// Daemon-side sink must retain a detached internal snapshot.
	snapshots := sink.Snapshots()
	if len(snapshots) != 1 {
		t.Fatalf("sink snapshot count = %d, want 1", len(snapshots))
	}
	snapshot := snapshots[0]
	if snapshot.Session.SessionID != "sink-session" || snapshot.Status != DaemonSessionStatusActive {
		t.Fatalf("sink snapshot identity/status = %#v", snapshot)
	}
	if snapshot.HandoffPlan.SessionID != "sink-session" || snapshot.HandoffPlan.CgroupID != 7700 {
		t.Fatalf("sink handoff plan = %#v", snapshot.HandoffPlan)
	}
	if snapshot.Session.RootPID != 777 {
		t.Fatalf("sink snapshot root_pid = %d, want 777", snapshot.Session.RootPID)
	}

	// All handoff plan steps must remain Executed=false.
	for i, step := range snapshot.HandoffPlan.Steps {
		if step.Executed {
			t.Fatalf("sink handoff step %d %q executed; snapshot must remain no-mutation", i, step.Name)
		}
	}

	// Sink copy must be detached from registry state.
	snapshot.Session.RootPID = 999
	fresh, err := registry.BuildSessionStatusSnapshot("sink-session", custody)
	if err != nil {
		t.Fatalf("BuildSessionStatusSnapshot returned error: %v", err)
	}
	if fresh.Session.RootPID != 777 {
		t.Fatalf("sink mutation leaked to registry: root_pid = %d, want 777", fresh.Session.RootPID)
	}

	// Snapshot copies returned by Snapshots must not mutate the sink log.
	snapshots[0].Session.CgroupID = 0
	snapshotsAfter := sink.Snapshots()
	if len(snapshotsAfter) != 1 {
		t.Fatalf("snapshot count after mutation = %d, want 1", len(snapshotsAfter))
	}
	if snapshotsAfter[0].Session.CgroupID == 0 {
		t.Fatalf("caller mutation leaked back into sink snapshot state")
	}
}

func TestDaemonSessionStatusSnapshotSinkFailsClosedForMissingOrExpiredSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 3, 21, 0, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	custody, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	sink := NewDaemonSessionStatusSnapshotSink()
	handler := NewDaemonSessionStatusSnapshotHandler(registry, custody, sink)

	server, cancel := startDaemonUnixSocketServerForTest(t, daemonSocketServerTestOptions{
		policy: DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
		observePeer: func(_ *net.UnixConn, socketPath string) (DaemonSocketPeerObservation, error) {
			return DaemonSocketPeerObservation{
				Credentials:      DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 4321, ProcessStartTimeTicks: 800004},
				CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
				SocketPath:       socketPath,
			}, nil
		},
		handleAuthorizedRequest: handler.HandleAuthorizedRequest,
	})
	defer cancel()

	// Missing session: wire response must fail, sink must not retain.
	missing := sendDaemonUnixSocketRequest(t, server.SocketPath(), daemonEncodeProtocolRequest(t, daemonSessionStatusRequest("missing-session")))
	if missing.OK || missing.Status != DaemonSessionStatusNotFound || !strings.Contains(missing.Error, "not found") {
		t.Fatalf("missing session_status response = %#v", missing)
	}
	if len(sink.Snapshots()) != 0 {
		t.Fatalf("sink retained snapshot for missing session: %#v", sink.Snapshots())
	}

	// Register then expire a session; snapshot sink must fail closed.
	registerReq := daemonRegisterSessionRequest("sink-expire", 888, 1)
	if response := sendDaemonUnixSocketRequest(t, server.SocketPath(), daemonEncodeProtocolRequest(t, registerReq)); !response.OK {
		t.Fatalf("register response = %#v", response)
	}
	now = now.Add(2 * time.Second)
	expired := sendDaemonUnixSocketRequest(t, server.SocketPath(), daemonEncodeProtocolRequest(t, daemonSessionStatusRequest("sink-expire")))
	if expired.OK || expired.Status != DaemonSessionStatusExpired || !strings.Contains(expired.Error, "expired") {
		t.Fatalf("expired session_status response = %#v", expired)
	}
	if len(sink.Snapshots()) != 0 {
		t.Fatalf("sink retained snapshot for expired session: %#v", sink.Snapshots())
	}
}

func TestDaemonSessionStatusSnapshotSinkFailsClosedForInvalidCustodyPlan(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 3, 22, 0, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	custody, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	// Break custody: empty StateDir invalidates handoff planning.
	invalidCustody := custody
	invalidCustody.StateDir = ""

	sink := NewDaemonSessionStatusSnapshotSink()
	handler := NewDaemonSessionStatusSnapshotHandler(registry, invalidCustody, sink)

	server, cancel := startDaemonUnixSocketServerForTest(t, daemonSocketServerTestOptions{
		policy: DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
		observePeer: func(_ *net.UnixConn, socketPath string) (DaemonSocketPeerObservation, error) {
			return DaemonSocketPeerObservation{
				Credentials:      DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 4321, ProcessStartTimeTicks: 800004},
				CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
				SocketPath:       socketPath,
			}, nil
		},
		handleAuthorizedRequest: handler.HandleAuthorizedRequest,
	})
	defer cancel()

	registerReq := daemonRegisterSessionRequest("sink-invalid-custody", 999, 60)
	registerReq.RegisterSession.CgroupID = 9999
	if response := sendDaemonUnixSocketRequest(t, server.SocketPath(), daemonEncodeProtocolRequest(t, registerReq)); !response.OK {
		t.Fatalf("register response = %#v", response)
	}

	// Snapshot should fail closed: wire response error, sink empty.
	failClosed := sendDaemonUnixSocketRequest(t, server.SocketPath(), daemonEncodeProtocolRequest(t, daemonSessionStatusRequest("sink-invalid-custody")))
	if failClosed.OK {
		t.Fatalf("snapshot with invalid custody returned ok=true, want fail closed")
	}
	if !strings.Contains(failClosed.Error, "custody") && !strings.Contains(failClosed.Error, "handoff") {
		t.Fatalf("invalid custody snapshot error = %q, want custody/handoff error", failClosed.Error)
	}
	if len(sink.Snapshots()) != 0 {
		t.Fatalf("sink retained snapshot for invalid custody: %#v", sink.Snapshots())
	}
}

func TestDaemonSessionStatusSnapshotSinkRejectsNonSessionStatusMethod(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 3, 23, 0, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	custody, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	sink := NewDaemonSessionStatusSnapshotSink()
	handler := NewDaemonSessionStatusSnapshotHandler(registry, custody, sink)

	server, cancel := startDaemonUnixSocketServerForTest(t, daemonSocketServerTestOptions{
		policy: DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
		observePeer: func(_ *net.UnixConn, socketPath string) (DaemonSocketPeerObservation, error) {
			return DaemonSocketPeerObservation{
				Credentials:      DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 4321, ProcessStartTimeTicks: 800004},
				CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
				SocketPath:       socketPath,
			}, nil
		},
		handleAuthorizedRequest: handler.HandleAuthorizedRequest,
	})
	defer cancel()

	// Health and register/end must not produce snapshots in the sink.
	healthResp := sendDaemonUnixSocketRequest(t, server.SocketPath(), daemonHealthRequest(t))
	if !healthResp.OK {
		t.Fatalf("health response = %#v", healthResp)
	}
	if len(sink.Snapshots()) != 0 {
		t.Fatalf("sink retained snapshot for health request: %#v", sink.Snapshots())
	}

	registerReq := daemonRegisterSessionRequest("sink-reg", 444, 60)
	regResp := sendDaemonUnixSocketRequest(t, server.SocketPath(), daemonEncodeProtocolRequest(t, registerReq))
	if !regResp.OK {
		t.Fatalf("register response = %#v", regResp)
	}
	if len(sink.Snapshots()) != 0 {
		t.Fatalf("sink retained snapshot for register request: %#v", sink.Snapshots())
	}

	endResp := sendDaemonUnixSocketRequest(t, server.SocketPath(), daemonEncodeProtocolRequest(t, daemonEndSessionRequest("sink-reg")))
	if !endResp.OK {
		t.Fatalf("end response = %#v", endResp)
	}
	if len(sink.Snapshots()) != 0 {
		t.Fatalf("sink retained snapshot for end request: %#v", sink.Snapshots())
	}
}

func TestDaemonSessionStatusSnapshotSinkRejectsNilRegistryOrSink(t *testing.T) {
	t.Parallel()

	custody, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}

	// Nil registry must fail closed.
	handler := NewDaemonSessionStatusSnapshotHandler(nil, custody, NewDaemonSessionStatusSnapshotSink())
	resp := handler.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest("any"), daemonSessionRegistryTestHandshake("any"))
	if resp.OK || !strings.Contains(resp.Error, "registry is required") {
		t.Fatalf("nil registry response = %#v", resp)
	}

	// Nil sink must fail closed for session_status because this handler's contract is retention.
	now := time.Date(2026, 6, 4, 0, 0, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	handlerNilSink := NewDaemonSessionStatusSnapshotHandler(registry, custody, nil)
	reg := daemonRegisterSessionRequest("nil-sink", 555, 60)
	reg.RegisterSession.CgroupID = 5555
	if resp := handlerNilSink.HandleAuthorizedRequest(context.Background(), reg, daemonSessionRegistryTestHandshake("nil-sink")); !resp.OK {
		t.Fatalf("register with nil sink response = %#v", resp)
	}
	sessResp := handlerNilSink.HandleAuthorizedRequest(context.Background(), daemonSessionStatusRequest("nil-sink"), daemonSessionRegistryTestHandshake("nil-sink"))
	if sessResp.OK || !strings.Contains(sessResp.Error, "snapshot sink is required") {
		t.Fatalf("session_status with nil sink response = %#v", sessResp)
	}
	encoded, err := EncodeDaemonProtocolResponse(sessResp)
	if err != nil {
		t.Fatalf("EncodeDaemonProtocolResponse returned error: %v", err)
	}
	if strings.Contains(strings.ToLower(string(encoded)), "handoff") || strings.Contains(strings.ToLower(string(encoded)), "cgroup") {
		t.Fatalf("nil-sink wire response leaked internal fields: %s", string(encoded))
	}
}

func TestSessionStatusSocketClientSendsAndDecodesOnlyProtocolResponse(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 4, 1, 0, 0, 0, time.UTC)
	registry := NewDaemonSessionRegistryWithClock(func() time.Time { return now })
	custody, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	sink := NewDaemonSessionStatusSnapshotSink()
	handler := NewDaemonSessionStatusSnapshotHandler(registry, custody, sink)

	server, cancel := startDaemonUnixSocketServerForTest(t, daemonSocketServerTestOptions{
		policy: DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
		observePeer: func(_ *net.UnixConn, socketPath string) (DaemonSocketPeerObservation, error) {
			return DaemonSocketPeerObservation{
				Credentials:      DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 4321, ProcessStartTimeTicks: 800004},
				CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
				SocketPath:       socketPath,
			}, nil
		},
		handleAuthorizedRequest: handler.HandleAuthorizedRequest,
	})
	defer cancel()

	// Register a session.
	registerReq := daemonRegisterSessionRequest("client-session", 333, 60)
	registerReq.RegisterSession.CgroupID = 3300
	registerReq.RegisterSession.MissionID = "mission-client"
	if response := sendDaemonUnixSocketRequest(t, server.SocketPath(), daemonEncodeProtocolRequest(t, registerReq)); !response.OK {
		t.Fatalf("register response = %#v", response)
	}

	// Use the session_status client helper.
	clientResponse, clientErr := SendDaemonSessionStatusRequest(server.SocketPath(), "client-session")
	if clientErr != nil {
		t.Fatalf("SendDaemonSessionStatusRequest returned error: %v", clientErr)
	}
	if !clientResponse.OK || clientResponse.Method != DaemonProtocolMethodSessionStatus || clientResponse.Status != DaemonSessionStatusActive {
		t.Fatalf("client helper response = %#v", clientResponse)
	}

	// Client response must not contain internal fields.
	encoded, err := EncodeDaemonProtocolResponse(clientResponse)
	if err != nil {
		t.Fatalf("EncodeDaemonProtocolResponse returned error: %v", err)
	}
	for _, forbidden := range []string{"handoff", "root_pid", "cgroup", "internal"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("client helper wire response leaked internal field %q: %s", forbidden, string(encoded))
		}
	}

	// Sink must have been populated server-side.
	if len(sink.Snapshots()) != 1 {
		t.Fatalf("sink snapshot count = %d, want 1", len(sink.Snapshots()))
	}

	// Client helper must fail for missing session.
	_, clientErr = SendDaemonSessionStatusRequest(server.SocketPath(), "missing-session")
	if clientErr == nil {
		t.Fatalf("SendDaemonSessionStatusRequest for missing session returned no error")
	}
	if !strings.Contains(clientErr.Error(), "not found") {
		t.Fatalf("missing session client error = %v, want not found", clientErr)
	}

	// Client helper must reject empty socket path before I/O.
	_, clientErr = SendDaemonSessionStatusRequest("  ", "client-session")
	if clientErr == nil {
		t.Fatalf("SendDaemonSessionStatusRequest for empty socket path returned no error")
	}
	if !strings.Contains(clientErr.Error(), "socket path") {
		t.Fatalf("empty socket path client error = %v", clientErr)
	}

	// Client helper must reject empty session_id.
	_, clientErr = SendDaemonSessionStatusRequest(server.SocketPath(), "  ")
	if clientErr == nil {
		t.Fatalf("SendDaemonSessionStatusRequest for empty session_id returned no error")
	}
	if !strings.Contains(clientErr.Error(), "session_id") {
		t.Fatalf("empty session_id client error = %v", clientErr)
	}
}

func sendDaemonUnixSocketRawRequest(t *testing.T, socketPath string, request []byte) ([]byte, DaemonProtocolResponse) {
	t.Helper()
	conn := dialDaemonUnixSocket(t, socketPath)
	defer conn.Close()
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline returned error: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("ReadBytes returned error: %v", err)
	}
	response, err := DecodeDaemonProtocolResponse(line)
	if err != nil {
		t.Fatalf("DecodeDaemonProtocolResponse returned error: %v", err)
	}
	return line, response
}
