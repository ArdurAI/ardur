//go:build !linux && !darwin

// daemon_unsupported.go covers platforms with no host-sensor backend at all
// (i.e. anything that is neither Linux/eBPF nor Darwin/Endpoint-Security).
// Darwin gets its own file, daemon_darwin.go, which wires the Endpoint
// Security client scaffold (kernelcapture.NewESClient) in place of the
// generic "unsupported" message below.

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
func runGuardConsumer(_ context.Context, _ *daemon, log *slog.Logger, ready chan<- error) error {
	log.Warn("BPF-LSM guard is Linux-only; enforcement unavailable on this platform")
	err := fmt.Errorf("BPF-LSM guard unavailable on this platform")
	ready <- err
	return err
}
