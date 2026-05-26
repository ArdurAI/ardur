//go:build linux

package kernelcapture

import (
	"errors"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestObserveLinuxUnixPeerCredentialsFromSocketpair(t *testing.T) {
	t.Parallel()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair returned error: %v", err)
	}
	serverFile := os.NewFile(uintptr(fds[0]), "ardur-peercred-server")
	clientFile := os.NewFile(uintptr(fds[1]), "ardur-peercred-client")
	defer serverFile.Close()
	defer clientFile.Close()

	serverConn, err := net.FileConn(serverFile)
	if err != nil {
		t.Fatalf("FileConn(server) returned error: %v", err)
	}
	defer serverConn.Close()
	clientConn, err := net.FileConn(clientFile)
	if err != nil {
		t.Fatalf("FileConn(client) returned error: %v", err)
	}
	defer clientConn.Close()

	serverUnix, ok := serverConn.(*net.UnixConn)
	if !ok {
		t.Fatalf("server connection type = %T, want *net.UnixConn", serverConn)
	}

	observation, err := ObserveLinuxUnixPeerCredentials(serverUnix, " /run/ardur/kernelcapture/control.sock ")
	if err != nil {
		t.Fatalf("ObserveLinuxUnixPeerCredentials returned error: %v", err)
	}
	if observation.CredentialSource != DaemonPeerCredentialSourceLinuxSOPeerCred {
		t.Fatalf("credential source = %q, want %q", observation.CredentialSource, DaemonPeerCredentialSourceLinuxSOPeerCred)
	}
	if observation.SocketPath != "/run/ardur/kernelcapture/control.sock" {
		t.Fatalf("socket path = %q", observation.SocketPath)
	}
	if observation.Credentials.UID != uint32(os.Getuid()) {
		t.Fatalf("uid = %d, want %d", observation.Credentials.UID, os.Getuid())
	}
	if observation.Credentials.GID != uint32(os.Getgid()) {
		t.Fatalf("gid = %d, want %d", observation.Credentials.GID, os.Getgid())
	}
	if observation.Credentials.PID == 0 {
		t.Fatalf("pid must be daemon-observed and non-zero")
	}
}

func TestObserveLinuxUnixPeerCredentialsFailsClosed(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		conn       *net.UnixConn
		socketPath string
	}{
		{name: "nil connection", socketPath: "/run/ardur/kernelcapture/control.sock"},
		{name: "missing socket path", conn: &net.UnixConn{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ObserveLinuxUnixPeerCredentials(tc.conn, tc.socketPath)
			if err == nil {
				t.Fatalf("expected error")
			}
			if !errors.Is(err, ErrDaemonPeerCredentialRetrieval) {
				t.Fatalf("expected ErrDaemonPeerCredentialRetrieval, got %v", err)
			}
		})
	}
}
