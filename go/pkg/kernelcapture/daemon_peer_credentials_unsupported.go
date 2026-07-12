//go:build !linux

package kernelcapture

import (
	"fmt"
	"net"
	"runtime"
)

// ObserveLinuxUnixPeerCredentials is unavailable outside Linux because the
// future daemon peer-credential boundary depends on SO_PEERCRED.
func ObserveLinuxUnixPeerCredentials(_ *net.UnixConn, _ string) (DaemonSocketPeerObservation, error) {
	return DaemonSocketPeerObservation{}, fmt.Errorf("%w: linux SO_PEERCRED is not supported on %s", ErrDaemonPeerCredentialRetrieval, runtime.GOOS)
}

// ObserveLinuxProcessStartTimeTicks is unavailable outside Linux because the
// process lifetime identity is read from Linux /proc/<pid>/stat.
func ObserveLinuxProcessStartTimeTicks(_ uint32) (uint64, error) {
	return 0, fmt.Errorf("%w: linux proc process identity is not supported on %s", ErrDaemonPeerCredentialRetrieval, runtime.GOOS)
}
