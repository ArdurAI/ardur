//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
	"golang.org/x/sys/unix"
)

const seccompHandoffChildModeEnv = "ARDUR_SECCOMP_HANDOFF_TEST_CHILD"

// TestSeccompHandoffChildProcess is re-executed by the ownership tests below
// as a real sibling or delegated root process. The ordinary parent test run
// leaves it inert.
func TestSeccompHandoffChildProcess(t *testing.T) {
	mode := os.Getenv(seccompHandoffChildModeEnv)
	if mode == "" {
		return
	}
	if mode == "victim" {
		time.Sleep(30 * time.Second)
		return
	}
	if mode != "handoff" {
		t.Fatalf("unknown child mode %q", mode)
	}

	socketPath := os.Getenv("ARDUR_SECCOMP_HANDOFF_TEST_SOCKET")
	sessionID := os.Getenv("ARDUR_SECCOMP_HANDOFF_TEST_SESSION")
	readyFile := os.Getenv("ARDUR_SECCOMP_HANDOFF_TEST_READY")
	expectedOK, err := strconv.ParseBool(os.Getenv("ARDUR_SECCOMP_HANDOFF_TEST_EXPECT_OK"))
	if err != nil {
		t.Fatalf("parse expected response: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(readyFile); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ready file %s did not appear", readyFile)
		}
		time.Sleep(10 * time.Millisecond)
	}

	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("dial handoff socket: %v", err)
	}
	defer conn.Close()

	// Match the real shim's ordering: connect before installing the filter so
	// its own AF_UNIX dial cannot be trapped by the listener it is transferring.
	runtime.LockOSThread()
	listenerFD, err := kernelcapture.InstallConnectUserNotifyFilter()
	if err != nil {
		t.Fatalf("install real seccomp user-notify filter: %v", err)
	}
	defer unix.Close(listenerFD)
	rightsFDs := []int{listenerFD}
	var extraRead, extraWrite *os.File
	if extra, _ := strconv.ParseBool(os.Getenv("ARDUR_SECCOMP_HANDOFF_TEST_EXTRA_FD")); extra {
		extraRead, extraWrite, err = os.Pipe()
		if err != nil {
			t.Fatalf("create extra SCM_RIGHTS descriptor: %v", err)
		}
		defer extraRead.Close()
		defer extraWrite.Close()
		rightsFDs = append(rightsFDs, int(extraRead.Fd()))
	}

	header, err := json.Marshal(seccompHandoffRequest{SessionID: sessionID})
	if err != nil {
		t.Fatalf("encode handoff header: %v", err)
	}
	if _, _, err := conn.WriteMsgUnix(header, unix.UnixRights(rightsFDs...), nil); err != nil {
		t.Fatalf("send real SCM_RIGHTS handoff: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set response deadline: %v", err)
	}
	responseBytes := make([]byte, 4096)
	n, err := conn.Read(responseBytes)
	if err != nil {
		t.Fatalf("read handoff response: %v", err)
	}
	var response seccompHandoffResponse
	if err := json.Unmarshal(responseBytes[:n], &response); err != nil {
		t.Fatalf("decode handoff response: %v", err)
	}
	if response.OK != expectedOK {
		t.Fatalf("handoff response = %+v, want ok=%t", response, expectedOK)
	}
	connectReady := os.Getenv("ARDUR_SECCOMP_HANDOFF_TEST_CONNECT_READY")
	connectDone := os.Getenv("ARDUR_SECCOMP_HANDOFF_TEST_CONNECT_DONE")
	if connectReady != "" {
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(connectReady); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("connect-ready file %s did not appear", connectReady)
			}
			time.Sleep(10 * time.Millisecond)
		}
		conn, _ := net.DialTimeout("tcp", "127.0.0.3:19999", time.Second)
		if conn != nil {
			_ = conn.Close()
		}
		if err := os.WriteFile(connectDone, []byte("connect returned\n"), 0o600); err != nil {
			t.Fatalf("write connect-done file: %v", err)
		}
	}
}

func TestHandleSeccompHandoffConnectionRejectsAuthorizedSiblingPeer(t *testing.T) {
	d := newTestDaemon(t)
	d.peerPolicy = kernelcapture.DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	d.cgroupVerifier = verifyRegisterSessionCgroup

	const sessionID = "seccomp-owned-by-another-root"
	victim := startSeccompHandoffTestChild(t, "victim", "", sessionID, false, false)
	registerRealDelegatedRootSession(t, d, sessionID, uint32(victim.cmd.Process.Pid))

	listener, socketPath := listenForTestSeccompHandoff(t)
	sibling := startSeccompHandoffTestChild(t, "handoff", socketPath, sessionID, false, false)
	serveTestSeccompHandoff(t, d, listener, sibling, sessionID)
}

func TestHandleSeccompHandoffConnectionAcceptsRegisteredRootPeer(t *testing.T) {
	d := newTestDaemon(t)
	d.peerPolicy = kernelcapture.DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	d.cgroupVerifier = verifyRegisterSessionCgroup

	const sessionID = "seccomp-delegated-root-peer"
	listener, socketPath := listenForTestSeccompHandoff(t)
	root := startSeccompHandoffTestChild(t, "handoff", socketPath, sessionID, true, false)
	registerRealDelegatedRootSession(t, d, sessionID, uint32(root.cmd.Process.Pid))
	serveTestSeccompHandoff(t, d, listener, root, sessionID)
}

func TestHandleSeccompHandoffConnectionRejectsMultipleDescriptors(t *testing.T) {
	d := newTestDaemon(t)
	d.peerPolicy = kernelcapture.DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	d.cgroupVerifier = verifyRegisterSessionCgroup

	const sessionID = "seccomp-multiple-descriptors"
	listener, socketPath := listenForTestSeccompHandoff(t)
	root := startSeccompHandoffTestChild(t, "handoff", socketPath, sessionID, false, true)
	registerRealDelegatedRootSession(t, d, sessionID, uint32(root.cmd.Process.Pid))
	serveTestSeccompHandoff(t, d, listener, root, sessionID)
}

func TestSeccompHandoffLifecycleBarrierBlocksReplacementDuringReceive(t *testing.T) {
	d := newTestDaemon(t)
	d.peerPolicy = kernelcapture.DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	listener, socketPath := listenForTestSeccompHandoff(t)
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("dial handoff socket: %v", err)
	}
	defer client.Close()
	accepted, err := listener.AcceptUnix()
	if err != nil {
		t.Fatalf("accept handoff socket: %v", err)
	}
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		d.handleSeccompHandoffConnection(context.Background(), accepted, socketPath, testLogger(t))
	}()

	deadline := time.Now().Add(5 * time.Second)
	for d.seccompSessionMu.TryLock() {
		d.seccompSessionMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("handoff handler did not acquire lifecycle read lease")
		}
		runtime.Gosched()
	}
	writerAcquired := make(chan struct{})
	go func() {
		d.seccompSessionMu.Lock()
		close(writerAcquired)
		d.seccompSessionMu.Unlock()
	}()
	select {
	case <-writerAcquired:
		t.Fatal("replacement lifecycle writer entered during in-flight handoff")
	case <-time.After(50 * time.Millisecond):
	}

	// Complete the real socket read with a malformed no-FD handoff. The handler
	// rejects it, releases the lease, and only then may the lifecycle writer run.
	if _, err := client.Write([]byte(`{"session_id":"barrier-probe"}`)); err != nil {
		t.Fatalf("write no-FD handoff: %v", err)
	}
	response := make([]byte, 4096)
	if _, err := client.Read(response); err != nil {
		t.Fatalf("read rejected handoff response: %v", err)
	}
	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handoff handler did not release lifecycle lease")
	}
	select {
	case <-writerAcquired:
	case <-time.After(5 * time.Second):
		t.Fatal("replacement lifecycle writer remained blocked after handoff")
	}
}

func TestSeccompNotificationLifecycleBarrierBlocksEndUntilEvidenceCompletes(t *testing.T) {
	d := newTestDaemon(t)
	d.peerPolicy = kernelcapture.DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	d.cgroupVerifier = verifyRegisterSessionCgroup
	const sessionID = "seccomp-notification-lifecycle-barrier"
	listener, socketPath := listenForTestSeccompHandoff(t)
	connectDir := t.TempDir()
	connectReady := filepath.Join(connectDir, "connect-ready")
	connectDone := filepath.Join(connectDir, "connect-done")
	t.Setenv("ARDUR_SECCOMP_HANDOFF_TEST_CONNECT_READY", connectReady)
	t.Setenv("ARDUR_SECCOMP_HANDOFF_TEST_CONNECT_DONE", connectDone)
	root := startSeccompHandoffTestChild(t, "handoff", socketPath, sessionID, true, false)
	ownerHandshake := registerRealDelegatedRootSession(t, d, sessionID, uint32(root.cmd.Process.Pid))
	if err := kernelcapture.ApplySeccompPolicy(d.seccompPolicy, sessionID, kernelcapture.DaemonApplyPolicyRequest{
		SessionID: sessionID,
		OpPolicies: []kernelcapture.DaemonOpPolicy{{
			Op: kernelcapture.BpfOpNetConnect, Action: kernelcapture.BpfActionDeny, EnforceMode: kernelcapture.BpfEnforceModeEnforce,
		}},
	}); err != nil {
		t.Fatalf("apply notification test policy: %v", err)
	}
	if err := os.WriteFile(root.readyFile, []byte("ready\n"), 0o600); err != nil {
		t.Fatalf("release handoff child: %v", err)
	}
	accepted, err := listener.AcceptUnix()
	if err != nil {
		t.Fatalf("accept handoff child: %v", err)
	}
	peerObservation, err := kernelcapture.ObserveLinuxUnixPeerCredentials(accepted, socketPath)
	if err != nil {
		t.Fatalf("observe notification child peer: %v", err)
	}
	record, ok := d.registry.Session(sessionID)
	if !ok || record.RootPID != peerObservation.Credentials.PID || record.RootProcessStartTimeTicks != peerObservation.Credentials.ProcessStartTimeTicks {
		t.Fatalf("notification child identity = pid:%d start:%d; registered = %+v, present=%t", peerObservation.Credentials.PID, peerObservation.Credentials.ProcessStartTimeTicks, record, ok)
	}
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		d.handleSeccompHandoffConnection(context.Background(), accepted, socketPath, testLogger(t))
	}()
	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handoff handler did not acknowledge listener")
	}

	d.mu.Lock()
	locked := true
	defer func() {
		if locked {
			d.mu.Unlock()
		}
	}()
	if err := os.WriteFile(connectReady, []byte("connect\n"), 0o600); err != nil {
		d.mu.Unlock()
		locked = false
		t.Fatalf("release connect probe: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(connectDone); err == nil {
			break
		}
		if time.Now().After(deadline) {
			d.mu.Unlock()
			locked = false
			t.Fatal("real seccomp notification did not return a response")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for d.seccompSessionMu.TryLock() {
		d.seccompSessionMu.Unlock()
		if time.Now().After(deadline) {
			d.mu.Unlock()
			locked = false
			t.Fatal("notification handler did not retain lifecycle read lease through evidence")
		}
		runtime.Gosched()
	}
	endDone := make(chan kernelcapture.DaemonProtocolResponse, 1)
	go func() {
		endDone <- d.handleAuthorizedRequest(context.Background(), kernelcapture.DaemonProtocolRequest{
			ProtocolVersion: kernelcapture.DaemonProtocolVersion,
			Method:          kernelcapture.DaemonProtocolMethodEndSession,
			EndSession:      &kernelcapture.DaemonEndSessionRequest{SessionID: sessionID},
		}, ownerHandshake)
	}()
	select {
	case response := <-endDone:
		d.mu.Unlock()
		locked = false
		t.Fatalf("end_session crossed in-flight notification evidence: %+v", response)
	case <-time.After(50 * time.Millisecond):
	}
	d.mu.Unlock()
	locked = false
	select {
	case response := <-endDone:
		if !response.OK {
			t.Fatalf("end_session after notification = %+v", response)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("end_session remained blocked after notification evidence completed")
	}
	if err := root.cmd.Wait(); err != nil {
		t.Fatalf("notification child failed: %v\n%s", err, root.output.String())
	}
}

type seccompHandoffTestChild struct {
	cmd       *exec.Cmd
	output    *bytes.Buffer
	readyFile string
}

func startSeccompHandoffTestChild(t *testing.T, mode, socketPath, sessionID string, expectedOK, extraFD bool) *seccompHandoffTestChild {
	t.Helper()
	readyFile := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(os.Args[0], "-test.run=^TestSeccompHandoffChildProcess$")
	cmd.Env = append(os.Environ(),
		seccompHandoffChildModeEnv+"="+mode,
		"ARDUR_SECCOMP_HANDOFF_TEST_SOCKET="+socketPath,
		"ARDUR_SECCOMP_HANDOFF_TEST_SESSION="+sessionID,
		"ARDUR_SECCOMP_HANDOFF_TEST_READY="+readyFile,
		"ARDUR_SECCOMP_HANDOFF_TEST_EXPECT_OK="+strconv.FormatBool(expectedOK),
		"ARDUR_SECCOMP_HANDOFF_TEST_EXTRA_FD="+strconv.FormatBool(extraFD),
	)
	output := &bytes.Buffer{}
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s child process: %v", mode, err)
	}
	child := &seccompHandoffTestChild{cmd: cmd, output: output, readyFile: readyFile}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	return child
}

func listenForTestSeccompHandoff(t *testing.T) (*net.UnixListener, string) {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "seccomp-handoff.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("listen on handoff socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, socketPath
}

func serveTestSeccompHandoff(t *testing.T, d *daemon, listener *net.UnixListener, child *seccompHandoffTestChild, sessionID string) {
	t.Helper()
	if err := os.WriteFile(child.readyFile, []byte("ready\n"), 0o600); err != nil {
		t.Fatalf("release handoff child: %v", err)
	}
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set accept deadline: %v", err)
	}
	accepted, err := listener.AcceptUnix()
	if err != nil {
		t.Fatalf("accept handoff child: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.handleSeccompHandoffConnection(context.Background(), accepted, listener.Addr().String(), testLogger(t))
	}()
	if err := child.cmd.Wait(); err != nil {
		t.Fatalf("handoff child failed: %v\n%s", err, child.output.String())
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("handoff handler did not return\nchild output: %s", child.output.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for d.seccompListenerAttached(sessionID) {
		if time.Now().After(deadline) {
			t.Fatalf("seccomp listener supervisor did not exit\nchild output: %s", child.output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func registerRealDelegatedRootSession(t *testing.T, d *daemon, sessionID string, rootPID uint32) kernelcapture.DaemonProtocolPeerHandshake {
	t.Helper()
	launcherObservation, launcherAuthorization := observeRealTestLauncher(t)
	handshake := kernelcapture.DaemonProtocolPeerHandshake{
		ProtocolVersion:       kernelcapture.DaemonProtocolVersion,
		Method:                kernelcapture.DaemonProtocolMethodRegisterSession,
		SessionID:             sessionID,
		SocketPath:            launcherObservation.SocketPath,
		CredentialSource:      launcherObservation.CredentialSource,
		ProcessStartTimeTicks: launcherAuthorization.ProcessStartTimeTicks,
		Authorization:         launcherAuthorization,
	}
	cgroupID, err := resolveCgroupID(rootPID)
	if err != nil {
		t.Fatalf("resolve real root child cgroup: %v", err)
	}
	request := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodRegisterSession,
		RegisterSession: &kernelcapture.DaemonRegisterSessionRequest{
			SessionID:    sessionID,
			RootPID:      rootPID,
			CgroupID:     cgroupID,
			EventClasses: []string{kernelcapture.DaemonProtocolEventProcessLifecycle},
			TTLSeconds:   60,
		},
	}
	if response := d.handleAuthorizedRequest(context.Background(), request, handshake); !response.OK {
		t.Fatalf("register real delegated root session: %+v", response)
	}
	record, ok := d.registry.Session(sessionID)
	if !ok || record.RootPID != rootPID || record.RootProcessStartTimeTicks == 0 {
		t.Fatalf("registered root identity = %+v, present=%t", record, ok)
	}
	return handshake
}

func observeRealTestLauncher(t *testing.T) (kernelcapture.DaemonSocketPeerObservation, kernelcapture.DaemonPeerAuthorization) {
	t.Helper()
	listener, socketPath := listenForTestSeccompHandoff(t)
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("dial launcher observation socket: %v", err)
	}
	defer client.Close()
	accepted, err := listener.AcceptUnix()
	if err != nil {
		t.Fatalf("accept launcher observation socket: %v", err)
	}
	defer accepted.Close()
	observation, err := kernelcapture.ObserveLinuxUnixPeerCredentials(accepted, socketPath)
	if err != nil {
		t.Fatalf("observe real launcher credentials: %v", err)
	}
	authorization, err := kernelcapture.AuthorizeObservedDaemonPeer(
		observation.Credentials,
		kernelcapture.DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{uint32(os.Getuid())}},
	)
	if err != nil {
		t.Fatalf("authorize real launcher credentials: %v", err)
	}
	return observation, authorization
}
