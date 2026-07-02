//go:build linux

package main

// daemon_guard_linux.go — BPF-LSM guard program integration for the daemon (Linux only).
//
// Slice 4.2: loads process_guard.bpf.c (BPF-LSM), populates d.policyMaps so
// that handleApplyPolicy can write to the BPF enforcement maps, and consumes
// the enforce_events ringbuf to produce BpfEnforceEvent records that are
// correlated against registered sessions and appended to evidence logs.
//
// Graceful degrade: if BPF-LSM is unavailable (BTF missing, "bpf" not in the
// active LSM list, or capability failure), the guard is skipped with a warning.
// The exec tracepoint consumer (daemon_linux.go/runEBPFConsumer) and the socket
// control plane continue to operate normally.
//
// See daemon_guard_common.go for the platform-independent decode/routing
// logic (decodeEnforceEvent, processEnforceEvent, enforceEventVerdict).

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
	"github.com/cilium/ebpf/ringbuf"
)

// runGuardConsumer loads the process_guard BPF-LSM program and streams
// enforce_events to registered sessions until ctx is cancelled.
//
// Returns nil on graceful context cancellation; returns a non-nil error if
// the guard fails to load (in which case the daemon degrades gracefully —
// enforcement is unavailable but the exec tracepoint consumer still runs).
func runGuardConsumer(ctx context.Context, d *daemon, log *slog.Logger) error {
	// Preflight: check BTF and BPF-LSM availability.
	preflightReport := kernelcapture.InspectBPFLSMPreflight()
	for _, f := range preflightReport.Findings {
		switch f.Verdict {
		case kernelcapture.DaemonPreflightVerdictFail:
			return fmt.Errorf("BPF-LSM preflight failed (%s): %s; %s", f.CheckName, f.Details, f.Remediation)
		case kernelcapture.DaemonPreflightVerdictWarn:
			log.Warn("BPF-LSM preflight warning",
				"check", f.CheckName, "detail", f.Details, "remediation", f.Remediation)
		}
	}

	handles, err := kernelcapture.LoadAndAttachProcessGuardEBPF()
	if err != nil {
		return fmt.Errorf("load process_guard BPF-LSM: %w", err)
	}
	defer func() {
		// Clear policy maps reference so subsequent apply_policy calls fail safely.
		d.policyMaps = kernelcapture.PolicyMaps{}
		handles.Close()
	}()

	// Expose maps to the daemon for apply_policy calls.
	d.policyMaps = kernelcapture.PolicyMapsFromHandles(handles)

	log.Info("BPF-LSM process_guard loaded",
		"hooks", "bprm_check_security, lsm.s/file_open, socket_connect",
	)

	return consumeEnforceEvents(ctx, handles.Reader(), d, log)
}

// consumeEnforceEvents reads raw BPfEnforceEvent structs from the ringbuf,
// decodes them, correlates them to registered sessions, and appends evidence.
//
// Note: unlike perf.Record, cilium/ebpf's ringbuf.Record carries no lost-sample
// counter — BPF_MAP_TYPE_RINGBUF reservation failures happen inside the BPF
// program (emit_event's bpf_ringbuf_reserve returning NULL) and are not
// surfaced to the userspace reader, so there is nothing to count here.
func consumeEnforceEvents(ctx context.Context, reader *ringbuf.Reader, d *daemon, log *slog.Logger) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		record, err := reader.Read()
		if err != nil {
			if err == io.EOF || err == ringbuf.ErrClosed {
				return nil
			}
			if strings.Contains(err.Error(), "context canceled") || strings.Contains(err.Error(), "deadline exceeded") {
				return ctx.Err()
			}
			return fmt.Errorf("enforce_events ringbuf read: %w", err)
		}

		ev, err := decodeEnforceEvent(record.RawSample)
		if err != nil {
			log.Warn("decode enforce_event failed", "error", err)
			continue
		}

		d.processEnforceEvent(ev, log)
	}
}
