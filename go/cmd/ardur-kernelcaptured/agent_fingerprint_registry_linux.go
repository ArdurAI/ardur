//go:build linux

package main

import (
	"fmt"
	"os"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
	"golang.org/x/sys/unix"
)

func loadAgentFingerprintRegistry(path string, daemonUID uint32) (*kernelcapture.AgentFingerprintRegistry, error) {
	if path == "" {
		return nil, fmt.Errorf("agent fingerprint registry path is required")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open agent fingerprint registry: %w", err)
	}
	file := os.NewFile(uintptr(fd), "agent-fingerprint-registry")
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open agent fingerprint registry: invalid file descriptor")
	}
	defer file.Close()

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, fmt.Errorf("inspect agent fingerprint registry: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("agent fingerprint registry must be a regular file")
	}
	if stat.Uid != daemonUID {
		return nil, fmt.Errorf("agent fingerprint registry must be owned by the daemon uid")
	}
	if stat.Mode&0o022 != 0 {
		return nil, fmt.Errorf("agent fingerprint registry must not be writable by group or other")
	}
	if stat.Size < 0 || stat.Size > kernelcapture.MaxAgentFingerprintRegistryBytes {
		return nil, fmt.Errorf("agent fingerprint registry exceeds the maximum size")
	}
	registry, err := kernelcapture.ParseAgentFingerprintRegistry(file)
	if err != nil {
		return nil, err
	}
	return registry, nil
}
