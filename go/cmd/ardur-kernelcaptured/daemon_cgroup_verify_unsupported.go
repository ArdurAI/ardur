//go:build !linux

package main

// daemon_cgroup_verify_unsupported.go — non-Linux stub for the register_session
// cgroup-ownership check. There is no /proc process-ancestry model to consult
// here (and no BPF-LSM cgroup enforcement to protect either), so registration
// proceeds unverified. See daemon_cgroup_verify_linux.go for the real check.

import (
	"log/slog"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

func verifyRegisterSessionCgroup(_ kernelcapture.DaemonProtocolPeerHandshake, _ *kernelcapture.DaemonRegisterSessionRequest, _ *slog.Logger) error {
	return nil
}
