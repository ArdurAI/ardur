//go:build !linux

package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

func platformName() string { return "unsupported" }

// runEBPFConsumer is a no-op stub on non-Linux platforms.
func runEBPFConsumer(_ context.Context, _ *daemon, log *slog.Logger) error {
	log.Warn("eBPF ringbuf consumer is Linux-only; running control plane only")
	return fmt.Errorf("eBPF consumer unavailable on this platform")
}

// sdNotify is a no-op on non-Linux platforms.
func sdNotify(_ string) error { return nil }

// runWatchdog is a no-op on non-Linux platforms.
func runWatchdog(_ context.Context, _ time.Duration, _ *slog.Logger) {}

// runGuardConsumer is a no-op stub on non-Linux platforms.
func runGuardConsumer(_ context.Context, _ *daemon, log *slog.Logger) error {
	log.Warn("BPF-LSM guard is Linux-only; enforcement unavailable on this platform")
	return fmt.Errorf("BPF-LSM guard unavailable on this platform")
}
