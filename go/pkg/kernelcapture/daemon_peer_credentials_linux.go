//go:build linux

package kernelcapture

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/sys/unix"
)

// ObserveLinuxUnixPeerCredentials reads Linux SO_PEERCRED from an already-open
// Unix connection and returns the daemon-owned peer observation used by the
// protocol handshake contract.
//
// The caller must supply the daemon-owned socket path it accepted this
// connection on. This function does not open, bind, listen on, accept, install,
// start, or expose a daemon; it is only the Linux credential retrieval seam for
// a connection the future daemon already owns.
func ObserveLinuxUnixPeerCredentials(conn *net.UnixConn, socketPath string) (DaemonSocketPeerObservation, error) {
	cleanedSocketPath := cleanPath(strings.TrimSpace(socketPath))
	if cleanedSocketPath == "" {
		return DaemonSocketPeerObservation{}, fmt.Errorf("%w: socket path is required", ErrDaemonPeerCredentialRetrieval)
	}
	if conn == nil {
		return DaemonSocketPeerObservation{}, fmt.Errorf("%w: unix connection is required", ErrDaemonPeerCredentialRetrieval)
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return DaemonSocketPeerObservation{}, fmt.Errorf("%w: access unix connection fd: %v", ErrDaemonPeerCredentialRetrieval, err)
	}

	var ucred *unix.Ucred
	var controlErr error
	if err := rawConn.Control(func(fd uintptr) {
		ucred, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return DaemonSocketPeerObservation{}, fmt.Errorf("%w: control unix connection fd: %v", ErrDaemonPeerCredentialRetrieval, err)
	}
	if controlErr != nil {
		return DaemonSocketPeerObservation{}, fmt.Errorf("%w: getsockopt SO_PEERCRED: %v", ErrDaemonPeerCredentialRetrieval, controlErr)
	}
	if ucred == nil {
		return DaemonSocketPeerObservation{}, fmt.Errorf("%w: getsockopt SO_PEERCRED returned no credentials", ErrDaemonPeerCredentialRetrieval)
	}
	if ucred.Pid <= 0 {
		return DaemonSocketPeerObservation{}, fmt.Errorf("%w: observed peer pid is required", ErrDaemonPeerCredentialRetrieval)
	}

	return DaemonSocketPeerObservation{
		Credentials: DaemonObservedPeerCredentials{
			UID: ucred.Uid,
			GID: ucred.Gid,
			PID: uint32(ucred.Pid),
		},
		CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
		SocketPath:       cleanedSocketPath,
	}, nil
}
