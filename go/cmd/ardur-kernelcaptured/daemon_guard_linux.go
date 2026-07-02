//go:build linux

package main

// daemon_guard_linux.go — BPF-LSM guard program integration for the daemon (Linux only).
//
// Slice 4.2: loads process_guard.bpf.c (BPF-LSM), populates d.policyMaps so
// that handleApplyPolicy can write to the BPF enforcement maps, and feeds the
// enforce_events ringbuf into the platform-independent processing pipeline in
// daemon_enforce.go (decode, sequence, hash-chain, correlate — added in #100
// ahead of this file landing, exactly for this to plug into: see that file's
// header comment).
//
// Graceful degrade: if BPF-LSM is unavailable (BTF missing, "bpf" not in the
// active LSM list, or capability failure), the guard is skipped with a warning.
// The exec tracepoint consumer (daemon_linux.go/runEBPFConsumer) and the socket
// control plane continue to operate normally.

import (
	"context"
	"fmt"
	"io"
	"log/slog"

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

	// ringbuf.Reader.Read() blocks with no context awareness of its own; close
	// it on ctx cancellation to unblock a pending read, the same pattern
	// DaemonUnixSocketServer.Serve uses for its accept loop.
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = handles.Reader().Close()
		case <-stop:
		}
	}()
	defer close(stop)

	return consumeEnforceEvents(ctx, ringbufEnforceEventReader{handles.Reader()}, d, log)
}

// ringbufEnforceEventReader adapts *ringbuf.Reader to the enforceEventReader
// interface consumeEnforceEvents (daemon_enforce.go) expects, so that
// platform-independent pipeline can be built and tested without depending on
// cilium/ebpf/ringbuf directly.
//
// ringbuf.ErrClosed (the reader closed under it, e.g. by the ctx.Done()
// watcher in runGuardConsumer) maps to io.EOF, consumeEnforceEvents' signal
// to stop cleanly. Any other error is wrapped and returned as-is;
// consumeEnforceEvents itself re-checks ctx.Err() after a read failure and
// prefers that as the returned error when it's set, so there's no need to
// pattern-match cancellation-flavored error text here too.
//
// LostSamples is always 0: unlike perf.Record, cilium/ebpf's ringbuf.Record
// carries no lost-sample counter at any version — BPF_MAP_TYPE_RINGBUF
// reservation failures happen inside the BPF program itself (emit_event's
// bpf_ringbuf_reserve returning NULL) and are never surfaced to the
// userspace reader. There is nothing this adapter can report here; the field
// exists in enforceEventRecord for a future producer that can supply it
// (e.g. a perf-buffer-backed transport), not for this one.
type ringbufEnforceEventReader struct {
	r *ringbuf.Reader
}

func (a ringbufEnforceEventReader) Read() (enforceEventRecord, error) {
	record, err := a.r.Read()
	if err != nil {
		if err == ringbuf.ErrClosed {
			return enforceEventRecord{}, io.EOF
		}
		return enforceEventRecord{}, fmt.Errorf("enforce_events ringbuf read: %w", err)
	}
	return enforceEventRecord{RawSample: record.RawSample}, nil
}
