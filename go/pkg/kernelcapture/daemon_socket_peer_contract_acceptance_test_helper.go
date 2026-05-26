package kernelcapture

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func acceptedUnixConnPair(t *testing.T) (*net.UnixConn, *net.UnixConn, func()) {
	t.Helper()

	socketDir, err := os.MkdirTemp("/tmp", "ardur-kp-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	socketPath := filepath.Join(socketDir, "control.sock")
	addr := &net.UnixAddr{Name: socketPath, Net: "unix"}

	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatalf("ListenUnix returned error: %v", err)
	}

	acceptedConnCh := make(chan *net.UnixConn, 1)
	acceptErrCh := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			acceptErrCh <- acceptErr
			return
		}
		acceptedConnCh <- conn
	}()

	clientConn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		listener.Close()
		t.Fatalf("DialUnix returned error: %v", err)
	}

	var serverConn *net.UnixConn
	select {
	case serverConn = <-acceptedConnCh:
	case err = <-acceptErrCh:
		clientConn.Close()
		listener.Close()
		t.Fatalf("AcceptUnix returned error: %v", err)
	case <-time.After(5 * time.Second):
		clientConn.Close()
		listener.Close()
		t.Fatalf("timed out waiting for accepted unix connection")
	}

	cleanup := func() {
		if err := serverConn.Close(); err != nil && !isConnectionAlreadyClosed(err) {
			t.Logf("server conn close: %v", err)
		}
		if err := clientConn.Close(); err != nil && !isConnectionAlreadyClosed(err) {
			t.Logf("client conn close: %v", err)
		}
		if err := listener.Close(); err != nil {
			t.Logf("listener close: %v", err)
		}
		if err := removeUnixSocket(socketDir); err != nil {
			t.Logf("socket dir remove: %v", err)
		}
	}

	return serverConn, clientConn, cleanup
}

func isConnectionAlreadyClosed(err error) bool {
	return strings.Contains(err.Error(), "closed network connection")
}

func writeUnixRequestAndClose(t *testing.T, conn *net.UnixConn, request string) {
	t.Helper()
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

func removeUnixSocket(socketPath string) error {
	return os.RemoveAll(socketPath)
}
