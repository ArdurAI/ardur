//go:build !linux

package main

import (
	"context"
	"fmt"
	"log/slog"
)

func platformName() string { return "unsupported" }

// runEBPFConsumer is a no-op stub on non-Linux platforms. The eBPF ringbuf
// consumer requires a Linux kernel; the daemon runs control-plane only.
func runEBPFConsumer(_ context.Context, _ *daemon, log *slog.Logger) error {
	log.Warn("eBPF ringbuf consumer is Linux-only; running control plane only")
	return fmt.Errorf("eBPF consumer unavailable on this platform")
}
