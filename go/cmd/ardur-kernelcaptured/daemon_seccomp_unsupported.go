//go:build !linux

package main

// daemon_seccomp_unsupported.go — non-Linux stub for the seccomp user-notify
// enforcement tier (Epic A #63, plan E4). seccomp is a Linux-only kernel
// facility; on any other platform the handoff server simply refuses to
// start, the same graceful-degrade shape runGuardConsumer/runEBPFConsumer
// already use for the BPF-LSM and exec/exit tracepoint tiers.

import (
	"context"
	"fmt"
	"log/slog"
)

func runSeccompHandoffServer(_ context.Context, _ string, _ *daemon, _ *slog.Logger) error {
	return fmt.Errorf("seccomp user-notify enforcement is Linux-only; unavailable on this platform")
}
