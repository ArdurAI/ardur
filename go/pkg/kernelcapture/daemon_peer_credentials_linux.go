//go:build linux

package kernelcapture

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const maxLinuxProcStatBytes = 4096

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
	startTimeTicks, err := readLinuxProcProcessStartTimeTicks(uint32(ucred.Pid))
	if err != nil {
		return DaemonSocketPeerObservation{}, err
	}

	return DaemonSocketPeerObservation{
		Credentials: DaemonObservedPeerCredentials{
			UID:                   ucred.Uid,
			GID:                   ucred.Gid,
			PID:                   uint32(ucred.Pid),
			ProcessStartTimeTicks: startTimeTicks,
		},
		CredentialSource: DaemonPeerCredentialSourceLinuxSOPeerCred,
		SocketPath:       cleanedSocketPath,
	}, nil
}

func readLinuxProcProcessStartTimeTicks(pid uint32) (uint64, error) {
	if pid == 0 {
		return 0, fmt.Errorf("%w: observed peer pid is required", ErrDaemonPeerCredentialRetrieval)
	}
	file, err := os.Open(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, fmt.Errorf("%w: peer /proc stat unavailable: %v", ErrDaemonPeerCredentialRetrieval, pathlessOSError(err))
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxLinuxProcStatBytes+1))
	if err != nil {
		return 0, fmt.Errorf("%w: read peer /proc stat: %v", ErrDaemonPeerCredentialRetrieval, err)
	}
	if len(data) > maxLinuxProcStatBytes {
		return 0, fmt.Errorf("%w: peer /proc stat exceeds %d bytes", ErrDaemonPeerCredentialRetrieval, maxLinuxProcStatBytes)
	}
	startTimeTicks, err := parseLinuxProcStatStartTimeTicks(string(data))
	if err != nil {
		return 0, fmt.Errorf("%w: parse peer /proc stat start time: %v", ErrDaemonPeerCredentialRetrieval, err)
	}
	return startTimeTicks, nil
}

func pathlessOSError(err error) error {
	if pathErr, ok := err.(*os.PathError); ok {
		return pathErr.Err
	}
	return err
}

func parseLinuxProcStatStartTimeTicks(raw string) (uint64, error) {
	trimmed := strings.TrimSpace(raw)
	closeIndex := strings.LastIndex(trimmed, ") ")
	if closeIndex < 0 {
		return 0, fmt.Errorf("missing process name terminator")
	}
	fields := strings.Fields(trimmed[closeIndex+2:])
	if len(fields) <= 19 {
		return 0, fmt.Errorf("expected at least 22 proc stat fields, got %d", len(fields)+2)
	}
	startTimeTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid start time ticks %q: %v", fields[19], err)
	}
	if startTimeTicks == 0 {
		return 0, fmt.Errorf("start time ticks is zero")
	}
	return startTimeTicks, nil
}
