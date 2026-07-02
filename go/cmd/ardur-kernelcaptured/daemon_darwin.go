//go:build darwin

package main

// daemon_darwin.go — macOS entry points for the daemon's platform-specific
// hooks (Epic A #63, Slice 2 remainder).
//
// Today this runs control-plane-only, same outcome as the generic
// "unsupported" platform (daemon_unsupported.go): the socket control plane,
// session registry, and evidence-log writer all work; there is no kernel
// event source. The difference from the generic file is that
// runEBPFConsumer's error comes from kernelcapture.NewESClient — the single
// call site where a real Endpoint Security binding plugs in once Apple
// grants EndpointSecurityEntitlement (see es_client_darwin.go). BPF-LSM
// enforcement has no macOS analogue in this slice, so runGuardConsumer keeps
// the same "unavailable on this platform" shape as the generic file.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

func platformName() string { return "darwin" }

// runEBPFConsumer attempts to obtain an Endpoint Security client. It always
// fails today — see kernelcapture.NewESClient's doc comment — so the daemon
// degrades to control-plane-only, the same outcome as every other non-Linux
// platform, but with a diagnostic that names the actual blocker (missing
// entitlement) instead of a generic "Linux-only" message.
func runEBPFConsumer(_ context.Context, _ *daemon, log *slog.Logger) error {
	client, err := kernelcapture.NewESClient()
	if err != nil {
		log.Warn("Endpoint Security client unavailable; running control plane only",
			"error", err,
			"remediation", "run 'ardur-sensor preflight' to check the code-signing entitlement",
		)
		return fmt.Errorf("endpoint security consumer unavailable: %w", err)
	}
	// Unreachable until NewESClient can succeed, kept for the day it does:
	// mirrors runGuardConsumer's defer-based cleanup on the Linux side.
	defer client.Close()
	return fmt.Errorf("endpoint security consumer not implemented")
}

// sdNotify is a no-op on macOS (no systemd).
func sdNotify(_ string) error { return nil }

// runWatchdog is a no-op on macOS (no systemd watchdog).
func runWatchdog(_ context.Context, _ time.Duration, _ *slog.Logger) {}

// runGuardConsumer: BPF-LSM has no macOS equivalent in this slice.
func runGuardConsumer(_ context.Context, _ *daemon, log *slog.Logger) error {
	log.Warn("BPF-LSM guard is Linux-only; enforcement unavailable on this platform")
	return fmt.Errorf("BPF-LSM guard unavailable on this platform")
}
