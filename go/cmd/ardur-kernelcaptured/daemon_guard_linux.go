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
//
// Slice 2 remainder: once the guard is loaded, runGuardConsumer also starts a
// tamper self-audit ticker (tamperAuditInterval, kept in lockstep with the
// systemd watchdog cadence in daemon_linux.go) that re-verifies the loaded
// links and kill-switch state each tick via kernelcapture.RunTamperAudit and
// records the result through d.recordTamperAudit — see tamper_audit.go for
// what this can and cannot detect.
//
// Restart survival (issue #124): loads via LoadAndAttachProcessGuardEBPFPinned,
// which pins the three LSM links and every policy-state map under
// /sys/fs/bpf/ardur/ so a daemon restart re-attaches to the still-enforcing
// kernel state instead of dropping it — see that function's doc comment.
//
// Fail-open on mid-run death (issue #121): if this function returns while the
// daemon is still running (main()'s ctx not yet cancelled) — whether from a
// real error or a clean ringbuf close caused by something other than our own
// shutdown watcher below — the caller in main() calls d.degradeGuardTier so
// activeTier (and therefore every health response) stops claiming bpf_lsm the
// moment nothing is actually attached anymore.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// tamperAuditInterval is the cadence for re-verifying the loaded guard's
// links and kill-switch state. Matches runWatchdog's interval (daemon_linux.go)
// intentionally: both exist to catch problems within half of the systemd
// WatchdogSec window, and reusing the constant keeps them from drifting apart.
const tamperAuditInterval = 15 * time.Second

// runGuardConsumer loads the process_guard BPF-LSM program and streams
// enforce_events to registered sessions until ctx is cancelled.
//
// Returns nil on graceful context cancellation; returns a non-nil error if
// the guard fails to load (in which case the daemon degrades gracefully —
// enforcement is unavailable but the exec tracepoint consumer still runs).
//
// ready receives exactly one value — nil once the guard has loaded and
// d.policyMaps is live, or the load error otherwise — before this function
// does anything that can block for the rest of the daemon's lifetime. main()
// blocks on it (with a timeout) to make the BPF-LSM-vs-seccomp tier decision
// (plan E4) without guessing from preflight alone, since preflight can pass
// while the actual load still fails for reasons preflight doesn't check.
func runGuardConsumer(ctx context.Context, d *daemon, log *slog.Logger, ready chan<- error) error {
	// Preflight: check BTF and BPF-LSM availability.
	preflightReport := kernelcapture.InspectBPFLSMPreflight()
	for _, f := range preflightReport.Findings {
		switch f.Verdict {
		case kernelcapture.DaemonPreflightVerdictFail:
			err := fmt.Errorf("BPF-LSM preflight failed (%s): %s; %s", f.CheckName, f.Details, f.Remediation)
			ready <- err
			return err
		case kernelcapture.DaemonPreflightVerdictWarn:
			log.Warn("BPF-LSM preflight warning",
				"check", f.CheckName, "detail", f.Details, "remediation", f.Remediation)
		}
	}

	handles, err := kernelcapture.LoadAndAttachProcessGuardEBPFPinned(kernelcapture.DefaultPinnedGuardPaths())
	if err != nil {
		err = fmt.Errorf("load process_guard BPF-LSM: %w", err)
		ready <- err
		return err
	}
	defer func() {
		// Clear policy maps reference so subsequent apply_policy calls fail safely.
		d.policyMaps = kernelcapture.PolicyMaps{}
		handles.Close()
	}()
	if err := kernelcapture.ClearBootstrapFileObservations(handles); err != nil {
		err = fmt.Errorf("clear stale bootstrap registration requests: %w", err)
		ready <- err
		return err
	}

	// Expose maps to the daemon for apply_policy calls.
	d.policyMaps = kernelcapture.PolicyMapsFromHandles(handles)

	log.Info("BPF-LSM process_guard loaded",
		"hooks", "bprm_check_security, lsm.s/file_open, socket_connect",
	)
	ready <- nil

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

	go runTamperAuditTicker(ctx, handles, d, log)

	return consumeEnforceEvents(ctx, newRingbufEnforceEventReader(handles.Reader(), handles.DroppedEventsMap(), log), d, log)
}

// runTamperAuditTicker re-verifies the loaded guard's links and kill-switch
// state every tamperAuditInterval until ctx is cancelled. Each tick's result
// is hash-chained and written to evidence via d.recordTamperAudit, drift or
// not — see that method's doc comment for why a clean tick is still recorded.
func runTamperAuditTicker(ctx context.Context, handles *kernelcapture.ProcessGuardHandles, d *daemon, log *slog.Logger) {
	ticker := time.NewTicker(tamperAuditInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.recordCurrentTamperAudit(handles, log)
		}
	}
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
// LostSamples reporting (issue #122): cilium/ebpf's ringbuf.Record carries no
// lost-sample counter — BPF_MAP_TYPE_RINGBUF reservation failures happen inside
// the BPF program itself (emit_event's bpf_ringbuf_reserve returning NULL) and
// are never surfaced to the userspace reader, so this adapter historically
// reported a hardcoded 0 and the daemon's "no gaps" accounting was silently
// blind to every kernel-side drop. To make that accounting honest,
// process_guard.bpf.c now increments a dedicated enforce_events_dropped counter
// map (atomic add) on each reserve failure, and this adapter reads that counter
// once per delivered event, reporting the increase since the previous event as
// that record's LostSamples. That routes kernel-side drops into the exact same
// per-session summary path perf-style lost samples would use
// (consumeEnforceEvents -> enforceOrphanSummary.RecordLostSamples). If the
// counter is unavailable — nil map (an older pin set without it) or a transient
// lookup failure — LostSamples falls back to 0; a missing drop count must never
// stall enforcement-event delivery.
//
// Drops are observed lazily, matching perf's "attach the lost count to the next
// good sample" contract: a reserve failure is only reported on the NEXT
// successfully-delivered event. The startup baseline is snapshotted from the
// (pinned, #124) counter so this daemon reports only drops during its own run,
// not the monotonic total inherited from a prior lifetime — see
// newRingbufEnforceEventReader.
type ringbufEnforceEventReader struct {
	r *ringbuf.Reader
	// dropTotal returns the current monotonic kernel drop total from
	// enforce_events_dropped and true, or (0, false) when the counter is
	// unavailable. Held as a func (rather than the *ebpf.Map directly) so the
	// delta accounting in droppedSinceLast is unit-testable without a live map.
	dropTotal     func() (uint64, bool)
	lastDropCount uint64
}

// newRingbufEnforceEventReader builds the adapter over the enforce_events
// ringbuf reader and its enforce_events_dropped counter map (either may drive
// its behaviour independently; dropped may be nil). It snapshots the counter's
// current value as the baseline so only drops occurring during THIS daemon's
// run are reported as LostSamples — the counter is pinned and monotonic across
// restarts (#124), so without this snapshot a restart would re-report every
// historical drop the previous daemon already accounted for. A nonzero baseline
// is logged once, since those pre-restart drops won't appear in this daemon's
// live stream.
func newRingbufEnforceEventReader(r *ringbuf.Reader, dropped *ebpf.Map, log *slog.Logger) *ringbufEnforceEventReader {
	dropTotal := func() (uint64, bool) {
		if dropped == nil {
			return 0, false
		}
		var zero uint32
		var total uint64
		if err := dropped.Lookup(&zero, &total); err != nil {
			return 0, false
		}
		return total, true
	}
	return newRingbufEnforceEventReaderFromSource(r, dropTotal, log)
}

// newRingbufEnforceEventReaderFromSource is the map-agnostic core of
// newRingbufEnforceEventReader: it takes the counter source directly so the
// baseline-snapshot and delta accounting can be exercised in tests without a
// live BPF map. dropTotal may be nil (drop reporting disabled).
func newRingbufEnforceEventReaderFromSource(r *ringbuf.Reader, dropTotal func() (uint64, bool), log *slog.Logger) *ringbufEnforceEventReader {
	a := &ringbufEnforceEventReader{r: r, dropTotal: dropTotal}
	if dropTotal != nil {
		if total, ok := dropTotal(); ok {
			a.lastDropCount = total
			if total > 0 && log != nil {
				log.Warn("enforce_events drop counter nonzero at guard load (drops from a prior daemon lifetime; not replayed into this run's stream)",
					"kernel_dropped_total", total)
			}
		}
	}
	return a
}

func (a *ringbufEnforceEventReader) Read() (enforceEventRecord, error) {
	record, err := a.r.Read()
	if err != nil {
		if err == ringbuf.ErrClosed {
			return enforceEventRecord{}, io.EOF
		}
		return enforceEventRecord{}, fmt.Errorf("enforce_events ringbuf read: %w", err)
	}
	return enforceEventRecord{
		RawSample:   record.RawSample,
		LostSamples: a.droppedSinceLast(),
	}, nil
}

// droppedSinceLast returns how far the kernel drop counter has advanced since
// the previous call, updating the running baseline. Returns 0 when the counter
// is unavailable. If the counter appears to have gone backwards it re-baselines
// and returns 0 rather than a spurious huge delta: the kernel value is a
// monotonic __sync_fetch_and_add total, but a fresh (unpinned) map after a
// restart could reset our frame of reference, and a lost count must never be
// reported as a negative-turned-enormous unsigned spike.
func (a *ringbufEnforceEventReader) droppedSinceLast() uint64 {
	if a.dropTotal == nil {
		return 0
	}
	total, ok := a.dropTotal()
	if !ok {
		return 0
	}
	if total <= a.lastDropCount {
		a.lastDropCount = total
		return 0
	}
	delta := total - a.lastDropCount
	a.lastDropCount = total
	return delta
}
