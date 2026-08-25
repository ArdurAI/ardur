package kernelcapture

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDaemonUnixSocketServerBindsAcceptsAndAuthorizesWithObservedPeer(t *testing.T) {
	t.Parallel()

	server, cancel := startDaemonUnixSocketServerForTest(t, daemonSocketServerTestOptions{
		policy: DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
		observePeer: func(_ *net.UnixConn, socketPath string) (DaemonSocketPeerObservation, error) {
			return DaemonSocketPeerObservation{
				Credentials:      DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 4321, ProcessStartTimeTicks: 800001},
				CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
				SocketPath:       socketPath,
			}, nil
		},
	})
	defer cancel()

	response := sendDaemonUnixSocketRequest(t, server.SocketPath(), daemonHealthRequest(t))
	if !response.OK {
		t.Fatalf("response ok = false, error = %q", response.Error)
	}
	if response.Method != DaemonProtocolMethodHealth {
		t.Fatalf("response method = %q, want health", response.Method)
	}
	if response.Status != "authorized" {
		t.Fatalf("response status = %q, want authorized", response.Status)
	}
}

func TestDaemonUnixSocketServerRejectsUnauthorizedPeerFailClosed(t *testing.T) {
	t.Parallel()

	server, cancel := startDaemonUnixSocketServerForTest(t, daemonSocketServerTestOptions{
		policy: DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
		observePeer: func(_ *net.UnixConn, socketPath string) (DaemonSocketPeerObservation, error) {
			return DaemonSocketPeerObservation{
				Credentials:      DaemonObservedPeerCredentials{UID: 999, GID: 20, PID: 4321, ProcessStartTimeTicks: 800002},
				CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
				SocketPath:       socketPath,
			}, nil
		},
	})
	defer cancel()

	response := sendDaemonUnixSocketRequest(t, server.SocketPath(), daemonHealthRequest(t))
	if response.OK {
		t.Fatalf("response ok = true, want fail-closed unauthorized response")
	}
	if !strings.Contains(response.Error, ErrDaemonPeerAuthorization.Error()) {
		t.Fatalf("response error = %q, want authorization error", response.Error)
	}
}

func TestDaemonUnixSocketServerFailsClosedWhenPeerCredentialObservationFails(t *testing.T) {
	t.Parallel()

	var handled atomic.Int32
	server, cancel := startDaemonUnixSocketServerForTest(t, daemonSocketServerTestOptions{
		policy: DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
		observePeer: func(_ *net.UnixConn, _ string) (DaemonSocketPeerObservation, error) {
			return DaemonSocketPeerObservation{}, errors.New("test peer credential observer unavailable")
		},
		handleAuthorizedRequest: func(_ context.Context, req DaemonProtocolRequest, handshake DaemonProtocolPeerHandshake) DaemonProtocolResponse {
			handled.Add(1)
			return DefaultDaemonAuthorizedProtocolResponse(req, handshake)
		},
	})
	defer cancel()

	response := sendDaemonUnixSocketRequest(t, server.SocketPath(), daemonHealthRequest(t))
	if response.OK {
		t.Fatalf("response ok = true, want fail-closed peer observation failure")
	}
	if !strings.Contains(response.Error, ErrDaemonSocketPeerObservation.Error()) {
		t.Fatalf("response error = %q, want peer observation error", response.Error)
	}
	if handled.Load() != 0 {
		t.Fatalf("authorized handler calls = %d, want 0 after peer observation failure", handled.Load())
	}
}

func TestDaemonUnixSocketServerEnforcesBoundedConcurrency(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var handled atomic.Int32

	server, cancel := startDaemonUnixSocketServerForTest(t, daemonSocketServerTestOptions{
		maxConcurrentConnections: 1,
		policy:                   DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
		observePeer: func(_ *net.UnixConn, socketPath string) (DaemonSocketPeerObservation, error) {
			return DaemonSocketPeerObservation{
				Credentials:      DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 4321, ProcessStartTimeTicks: 800001},
				CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
				SocketPath:       socketPath,
			}, nil
		},
		handleAuthorizedRequest: func(_ context.Context, req DaemonProtocolRequest, handshake DaemonProtocolPeerHandshake) DaemonProtocolResponse {
			handled.Add(1)
			entered <- struct{}{}
			<-release
			return DefaultDaemonAuthorizedProtocolResponse(req, handshake)
		},
	})
	defer cancel()

	firstConn := dialDaemonUnixSocket(t, server.SocketPath())
	defer firstConn.Close()
	if _, err := firstConn.Write(daemonHealthRequest(t)); err != nil {
		t.Fatalf("write first request: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("first connection did not enter authorized handler")
	}

	secondConn := dialDaemonUnixSocket(t, server.SocketPath())
	defer secondConn.Close()
	if _, err := secondConn.Write(daemonHealthRequest(t)); err != nil && !isConnectionAlreadyClosed(err) {
		t.Fatalf("write second request: %v", err)
	}
	secondResponse := readDaemonUnixSocketResponse(t, secondConn)
	if secondResponse.OK {
		t.Fatalf("second response ok = true, want concurrency rejection")
	}
	if !strings.Contains(secondResponse.Error, "too many concurrent") {
		t.Fatalf("second response error = %q, want concurrency rejection", secondResponse.Error)
	}
	if handled.Load() != 1 {
		t.Fatalf("handled count = %d, want only first connection handled", handled.Load())
	}

	close(release)
	firstResponse := readDaemonUnixSocketResponse(t, firstConn)
	if !firstResponse.OK {
		t.Fatalf("first response ok = false after release: %q", firstResponse.Error)
	}
}

func TestDaemonUnixSocketServerCancellationDrainsInFlightHandlerBeforeServeReturns(t *testing.T) {
	entered := make(chan struct{})
	observedCancel := make(chan struct{})
	allowReturn := make(chan struct{})
	var releaseOnce sync.Once
	releaseHandler := func() { releaseOnce.Do(func() { close(allowReturn) }) }
	defer releaseHandler()

	server := listenDaemonUnixSocketServerForTest(t, daemonSocketServerTestOptions{
		policy: DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
		observePeer: func(_ *net.UnixConn, socketPath string) (DaemonSocketPeerObservation, error) {
			return DaemonSocketPeerObservation{
				Credentials:      DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 4321, ProcessStartTimeTicks: 800001},
				CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
				SocketPath:       socketPath,
			}, nil
		},
		handleAuthorizedRequest: func(ctx context.Context, req DaemonProtocolRequest, handshake DaemonProtocolPeerHandshake) DaemonProtocolResponse {
			close(entered)
			<-ctx.Done()
			close(observedCancel)
			<-allowReturn
			return DefaultDaemonAuthorizedProtocolResponse(req, handshake)
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ctx) }()

	conn := dialDaemonUnixSocket(t, server.SocketPath())
	defer conn.Close()
	if _, err := conn.Write(daemonHealthRequest(t)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("authorized handler did not start")
	}
	cancel()
	select {
	case <-observedCancel:
	case <-time.After(time.Second):
		t.Fatal("authorized handler did not observe context cancellation")
	}
	select {
	case err := <-serveErr:
		t.Fatalf("Serve returned before the in-flight handler drained: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	releaseHandler()
	select {
	case err := <-serveErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve error = %v, want context cancellation after drain", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not return after the in-flight handler drained")
	}
}

func TestDaemonUnixSocketServerCancellationUnblocksAndDrainsPartialRequest(t *testing.T) {
	server := listenDaemonUnixSocketServerForTest(t, daemonSocketServerTestOptions{
		policy: DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
		observePeer: func(_ *net.UnixConn, socketPath string) (DaemonSocketPeerObservation, error) {
			return DaemonSocketPeerObservation{
				Credentials:      DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 4321, ProcessStartTimeTicks: 800001},
				CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
				SocketPath:       socketPath,
			}, nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ctx) }()

	conn := dialDaemonUnixSocket(t, server.SocketPath())
	defer conn.Close()
	deadline := time.Now().Add(time.Second)
	for len(server.semaphore) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("partial request handler did not acquire its concurrency slot")
		}
		runtime.Gosched()
	}
	cancel()
	select {
	case err := <-serveErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not return after cancellation")
	}
	if got := len(server.semaphore); got != 0 {
		t.Fatalf("active handler slots after Serve returned = %d, want 0", got)
	}
}

func TestDaemonUnixSocketServerCancellationBeforeDispatchSkipsAuthorizedMutation(t *testing.T) {
	observerEntered := make(chan struct{})
	releaseObserver := make(chan struct{})
	var handled atomic.Int32
	server := listenDaemonUnixSocketServerForTest(t, daemonSocketServerTestOptions{
		policy: DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
		observePeer: func(_ *net.UnixConn, socketPath string) (DaemonSocketPeerObservation, error) {
			close(observerEntered)
			<-releaseObserver
			return DaemonSocketPeerObservation{
				Credentials:      DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 4321, ProcessStartTimeTicks: 800001},
				CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
				SocketPath:       socketPath,
			}, nil
		},
		handleAuthorizedRequest: func(_ context.Context, req DaemonProtocolRequest, handshake DaemonProtocolPeerHandshake) DaemonProtocolResponse {
			handled.Add(1)
			return DefaultDaemonAuthorizedProtocolResponse(req, handshake)
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ctx) }()
	conn := dialDaemonUnixSocket(t, server.SocketPath())
	defer conn.Close()
	if _, err := conn.Write(daemonHealthRequest(t)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	select {
	case <-observerEntered:
	case <-time.After(time.Second):
		t.Fatal("peer observer did not start")
	}
	cancel()
	close(releaseObserver)
	select {
	case err := <-serveErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not drain after cancellation")
	}
	if got := handled.Load(); got != 0 {
		t.Fatalf("authorized mutations after cancellation = %d, want 0", got)
	}
}

func TestDaemonUnixSocketServerReportsBoundedDrainTimeout(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseHandler := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseHandler()

	server := listenDaemonUnixSocketServerForTest(t, daemonSocketServerTestOptions{
		shutdownTimeout: 50 * time.Millisecond,
		policy:          DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
		observePeer: func(_ *net.UnixConn, socketPath string) (DaemonSocketPeerObservation, error) {
			return DaemonSocketPeerObservation{
				Credentials:      DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 4321, ProcessStartTimeTicks: 800001},
				CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
				SocketPath:       socketPath,
			}, nil
		},
		handleAuthorizedRequest: func(_ context.Context, req DaemonProtocolRequest, handshake DaemonProtocolPeerHandshake) DaemonProtocolResponse {
			close(entered)
			<-release // Deliberately ignore cancellation to exercise the hard deadline.
			return DefaultDaemonAuthorizedProtocolResponse(req, handshake)
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ctx) }()
	conn := dialDaemonUnixSocket(t, server.SocketPath())
	defer conn.Close()
	if _, err := conn.Write(daemonHealthRequest(t)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("authorized handler did not start")
	}
	cancel()
	select {
	case err := <-serveErr:
		if !errors.Is(err, ErrDaemonSocketServerShutdownTimeout) {
			t.Fatalf("Serve error = %v, want handler-drain timeout", err)
		}
		if !errors.Is(err, ErrDaemonSocketServer) {
			t.Fatalf("Serve error = %v, want generic socket-server classification", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not honor its bounded drain timeout")
	}
	select {
	case <-server.HandlersDrained():
		t.Fatal("HandlersDrained closed while the non-cooperative handler was still running")
	default:
	}
	releaseHandler()
	select {
	case <-server.HandlersDrained():
	case <-time.After(time.Second):
		t.Fatal("HandlersDrained did not close after the handler eventually returned")
	}
}

func TestDaemonUnixSocketServerRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	plan, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	cfg := DefaultDaemonUnixSocketServerConfig(plan, DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}})
	cfg.bindSocketPath = shortDaemonSocketPathForTest(t)
	cfg.MaxConcurrentConnections = -1

	_, err = ListenDaemonUnixSocketServer(cfg)
	if err == nil {
		t.Fatalf("expected invalid socket server config error")
	}
	if !errors.Is(err, ErrDaemonSocketServer) {
		t.Fatalf("expected ErrDaemonSocketServer, got %v", err)
	}
}

func TestDaemonUnixSocketServerServeIsSingleUse(t *testing.T) {
	server, cancel := startDaemonUnixSocketServerForTest(t, daemonSocketServerTestOptions{
		policy: DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
		observePeer: func(_ *net.UnixConn, socketPath string) (DaemonSocketPeerObservation, error) {
			return DaemonSocketPeerObservation{
				Credentials:      DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 4321, ProcessStartTimeTicks: 800001},
				CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
				SocketPath:       socketPath,
			}, nil
		},
	})
	cancel()
	if err := server.Serve(context.Background()); err == nil || !strings.Contains(err.Error(), "only once") {
		t.Fatalf("second Serve error = %v, want single-use rejection", err)
	}
}

type daemonSocketServerTestOptions struct {
	policy                   DaemonPeerAuthorizationPolicy
	observePeer              DaemonPeerCredentialObserver
	handleAuthorizedRequest  DaemonAuthorizedProtocolHandler
	maxConcurrentConnections int
	shutdownTimeout          time.Duration
}

func listenDaemonUnixSocketServerForTest(t *testing.T, opts daemonSocketServerTestOptions) *DaemonUnixSocketServer {
	t.Helper()

	plan, err := BuildDaemonCustodyPlan(DefaultDaemonCustodyConfig())
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	if len(opts.policy.AllowedUIDs) == 0 && len(opts.policy.AllowedGIDs) == 0 {
		opts.policy = DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}}
	}
	cfg := DefaultDaemonUnixSocketServerConfig(plan, opts.policy)
	cfg.bindSocketPath = shortDaemonSocketPathForTest(t)
	cfg.ObservePeerCredentials = opts.observePeer
	cfg.HandleAuthorizedRequest = opts.handleAuthorizedRequest
	if opts.maxConcurrentConnections != 0 {
		cfg.MaxConcurrentConnections = opts.maxConcurrentConnections
	}
	if opts.shutdownTimeout != 0 {
		cfg.ShutdownTimeout = opts.shutdownTimeout
	}

	server, err := ListenDaemonUnixSocketServer(cfg)
	if err != nil {
		t.Fatalf("ListenDaemonUnixSocketServer returned error: %v", err)
	}
	return server
}

func shortDaemonSocketPathForTest(t *testing.T) string {
	t.Helper()

	// Darwin's sockaddr_un path budget is small and t.TempDir includes the full
	// test name, so keep the bound path intentionally short. Local agents may set
	// ARDUR_TEST_SOCKET_TMPDIR to a short external-volume path; CI keeps /tmp.
	baseDir := os.Getenv("ARDUR_TEST_SOCKET_TMPDIR")
	if baseDir == "" {
		baseDir = "/tmp"
	}
	dir, err := os.MkdirTemp(baseDir, "ardur-sock-*")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return filepath.Join(dir, "s.sock")
}

func startDaemonUnixSocketServerForTest(t *testing.T, opts daemonSocketServerTestOptions) (*DaemonUnixSocketServer, func()) {
	t.Helper()
	server := listenDaemonUnixSocketServerForTest(t, opts)
	ctx, cancelContext := context.WithCancel(context.Background())
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- server.Serve(ctx)
	}()

	cancel := func() {
		cancelContext()
		if err := server.Close(); err != nil && !isConnectionAlreadyClosed(err) {
			t.Logf("server close: %v", err)
		}
		select {
		case err := <-serveErrCh:
			if err != nil && !errors.Is(err, context.Canceled) && !isConnectionAlreadyClosed(err) {
				t.Logf("server serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Logf("timed out waiting for daemon socket server shutdown")
		}
	}
	return server, cancel
}

func daemonHealthRequest(t *testing.T) []byte {
	t.Helper()
	req, err := EncodeDaemonProtocolRequest(DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodHealth,
		Health:          &DaemonHealthRequest{},
	})
	if err != nil {
		t.Fatalf("EncodeDaemonProtocolRequest returned error: %v", err)
	}
	return req
}

func dialDaemonUnixSocket(t *testing.T, socketPath string) *net.UnixConn {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("DialUnix returned error: %v", err)
	}
	return conn
}

func sendDaemonUnixSocketRequest(t *testing.T, socketPath string, request []byte) DaemonProtocolResponse {
	t.Helper()
	conn := dialDaemonUnixSocket(t, socketPath)
	defer conn.Close()
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	return readDaemonUnixSocketResponse(t, conn)
}

func readDaemonUnixSocketResponse(t *testing.T, conn *net.UnixConn) DaemonProtocolResponse {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline returned error: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("ReadBytes returned error: %v", err)
	}
	var response DaemonProtocolResponse
	if err := json.Unmarshal(line, &response); err != nil {
		t.Fatalf("json.Unmarshal response returned error: %v", err)
	}
	return response
}

func TestDaemonUnixSocketServerRemovesSocketOnClose(t *testing.T) {
	t.Parallel()

	server, cancel := startDaemonUnixSocketServerForTest(t, daemonSocketServerTestOptions{
		policy: DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
		observePeer: func(_ *net.UnixConn, socketPath string) (DaemonSocketPeerObservation, error) {
			return DaemonSocketPeerObservation{
				Credentials:      DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 4321, ProcessStartTimeTicks: 800001},
				CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
				SocketPath:       socketPath,
			}, nil
		},
	})
	socketPath := server.SocketPath()
	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatalf("socket path was not created: %v", err)
	}
	if got := info.Mode().Perm(); got != DefaultDaemonUnixSocketMode {
		t.Fatalf("socket mode = %#o, want %#o", got, DefaultDaemonUnixSocketMode)
	}
	cancel()
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket path still exists after close, err=%v", err)
	}
}
