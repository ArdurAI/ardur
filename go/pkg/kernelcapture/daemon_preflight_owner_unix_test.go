//go:build unix

package kernelcapture

import (
	"os"
	"testing"
)

func TestDaemonPreflightFileOwnerExtractsUnixOwnership(t *testing.T) {
	t.Parallel()

	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatalf("stat temporary directory: %v", err)
	}
	uid, gid := daemonPreflightFileOwner(info.Sys())
	if uid != os.Getuid() || gid != os.Getgid() {
		t.Fatalf("owner = %d:%d, want current process owner %d:%d", uid, gid, os.Getuid(), os.Getgid())
	}
}
