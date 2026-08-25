//go:build unix

package kernelcapture

import "syscall"

func daemonPreflightFileOwner(systemInfo any) (int, int) {
	if stat, ok := systemInfo.(*syscall.Stat_t); ok {
		return int(stat.Uid), int(stat.Gid)
	}
	return -1, -1
}
