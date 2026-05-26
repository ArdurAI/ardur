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
