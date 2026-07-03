package main

// daemon_enforce.go — enforce_events processing (Epic A #63, plan E3).
//
// This file processes BpfEnforceEvent records once they have been decoded
// from the enforce_events ringbuf. It does NOT load the BPF-LSM program or
// open that ringbuf itself: that loader lives behind the Slice 4.2 BPF-LSM
// bridge, which does not build cleanly yet (blocked pending #92). Once it
// lands, wiring the data-plane goroutine is a single adapter that satisfies
// enforceEventReader over *ringbuf.Reader and a call to consumeEnforceEvents
// from main()'s run loop — exactly how runEBPFConsumer wires the exec/exit
// tracepoint consumer today.
//
// Claim boundary for this file:
//   - Decodes raw enforce_events ringbuf records into BpfEnforceEvent.
//   - Routes events through the same per-session Correlator used for
//     exec/exit events (via d.correlators), so kernel-enforcement denials get
//     the same PID/cgroup/time-window attribution confidence grading, rather
//     than a bare cgroup-index lookup.
//   - Sequences and hash-chains every processed event, including orphans, so
//     the evidence log can be verified for gaps or tampering
//     (EnforceReceiptChain).
//   - Orphaned events — enforce_events for a cgroup with no registered
//     session — are never dropped: they are appended to a dedicated
//     hash-chained log (enforceOrphanChain) and counted, not discarded.
//   - Accounts for ringbuf LostSamples and exposes a per-session enforcement
//     summary over the session_status daemon protocol response
//     (DaemonProtocolResponse.Enforcement).
//
// NOT in this file:
//   - Loading process_guard.bpf.c, attaching LSM hooks, or opening the
//     enforce_events ringbuf (blocked; see #92).
//   - Writing BPF policy maps (apply_policy).

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

// enforceOrphanScope is the pseudo-session-id used for the evidence-log
// directory and in-memory chain/summary that hold enforce_events which could
// not be attributed to any registered session.
const enforceOrphanScope = "_orphan"

// enforceEventRecord is the platform-independent projection of one raw
// ringbuf record: the decoded bytes plus how many prior samples the kernel
// ring buffer dropped before this one was read. Keeping this decoupled from
// github.com/cilium/ebpf/ringbuf.Record lets the processing pipeline below
// build and be tested on every platform, not just Linux.
type enforceEventRecord struct {
	RawSample   []byte
	LostSamples uint64
}

// enforceEventReader is satisfied by a thin adapter over *ringbuf.Reader
// (Linux-only, added when the BPF-LSM loader lands) and by fakes in tests.
type enforceEventReader interface {
	Read() (enforceEventRecord, error)
}

// consumeEnforceEvents reads raw enforce_event records from reader, decodes
// them, and routes each to processEnforceEvent until ctx is cancelled or the
// reader is exhausted (io.EOF, signalling a closed reader).
func consumeEnforceEvents(ctx context.Context, reader enforceEventReader, d *daemon, log *slog.Logger) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		rec, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("enforce_events read: %w", err)
		}

		if rec.LostSamples > 0 {
			d.enforceOrphanSummary.RecordLostSamples(rec.LostSamples)
			log.Warn("enforce_events ringbuf lost samples", "lost", rec.LostSamples)
		}

		ev, err := decodeEnforceEvent(rec.RawSample)
		if err != nil {
			log.Warn("decode enforce_event failed", "error", err)
			continue
		}

		d.processEnforceEvent(ev, enforceEventTier(ev), log)
	}
}

// decodeEnforceEvent deserializes the raw bytes from the BPF ringbuf into a
// BpfEnforceEvent. The layout must exactly match struct ardur_enforce_event
// in process_guard.bpf.c:
//
//	cgroup_id  u64     (8)
//	pid        u32     (4)
//	op         u32     (4)
//	action     u32     (4)
//	mode       u32     (4)
//	observed   u64     (8)
//	comm       [16]u8  (16)
//	path       [256]u8 (256)
//
// Total: 304 bytes. Uses native byte order because the ringbuf memory is
// written directly by the (same-host, CO-RE) BPF program.
func decodeEnforceEvent(raw []byte) (kernelcapture.BpfEnforceEvent, error) {
	const fixedSize = 8 + 4 + 4 + 4 + 4 + 8 + 16 + 256 // 304 bytes
	if len(raw) < fixedSize {
		return kernelcapture.BpfEnforceEvent{}, fmt.Errorf("enforce_event too short: %d < %d", len(raw), fixedSize)
	}

	r := bytes.NewReader(raw)
	var ev kernelcapture.BpfEnforceEvent

	var cgroupID uint64
	var pid, op, action, mode uint32
	var observedNS uint64
	var comm [16]byte
	var path [256]byte

	for _, field := range []any{&cgroupID, &pid, &op, &action, &mode, &observedNS, &comm, &path} {
		if err := binary.Read(r, binary.NativeEndian, field); err != nil {
			return kernelcapture.BpfEnforceEvent{}, fmt.Errorf("decode enforce_event: %w", err)
		}
	}

	ev.CgroupID = cgroupID
	ev.PID = pid
	ev.Op = kernelcapture.BpfOp(op)
	ev.ActionTaken = kernelcapture.BpfAction(action)
	ev.EnforceMode = kernelcapture.BpfEnforceMode(mode)
	ev.ObservedNS = observedNS
	ev.Comm = strings.TrimRight(string(comm[:]), "\x00")
	ev.Path = strings.TrimRight(string(path[:]), "\x00")

	return ev, nil
}

// routeEnforceEvent finds the session (and its Correlator) that owns
// cgroupID. Returns ("", nil) if no registered session claims this cgroup.
//
// Unlike routeEvent (used for exec/exit tracepoint events), this only does
// the cgroup-index fast-path lookup: the BPF-LSM maps are keyed directly by
// the governed cgroup_id, so there is no subtree-escape ambiguity to resolve
// with a process-tree walk the way there is for arbitrary tracepoint events.
func (d *daemon) routeEnforceEvent(cgroupID uint64) (string, *kernelcapture.Correlator) {
	if cgroupID == 0 {
		return "", nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	sid, ok := d.cgroupIndex[cgroupID]
	if !ok {
		return "", nil
	}
	return sid, d.correlators[sid]
}

// bpfEnforceEventToProcessEvent projects a BpfEnforceEvent into the generic
// ProcessEvent shape the Correlator matches against.
//
// ObservedAt is set to the wall-clock time of processing rather than derived
// from ev.ObservedNS: the BPF program only supplies a monotonic kernel
// timestamp, and without a monotonic-to-wall-clock anchor point (the daemon
// does not currently record one) there is no principled way to convert it.
// Ringbuf consumption latency is sub-millisecond in practice, well inside the
// multi-second CorrelationGrace window the Correlator uses, so this
// approximation does not materially affect correlation quality.
// ObservedMonotonicNS is set from the true kernel value, since restart-gap
// detection (isWithinRestartGap) compares monotonic clocks directly.
func bpfEnforceEventToProcessEvent(ev kernelcapture.BpfEnforceEvent, sessionID string) kernelcapture.ProcessEvent {
	return kernelcapture.ProcessEvent{
		SessionID:           sessionID,
		Type:                kernelcapture.ProcessEventEnforce,
		PID:                 ev.PID,
		CgroupID:            ev.CgroupID,
		Comm:                ev.Comm,
		ObservedAt:          time.Now().UTC(),
		ObservedMonotonicNS: ev.ObservedNS,
	}
}

// enforceEventVerdict maps a BpfEnforceEvent's kernel-observed action to a
// SyntheticKernelReceipt-style verdict string. This is authoritative — it
// reflects what the kernel actually did — and is not overridden by
// correlation ambiguity the way exec/exit verdicts are.
func enforceEventVerdict(ev kernelcapture.BpfEnforceEvent) string {
	switch ev.ActionTaken {
	case kernelcapture.BpfActionDeny, kernelcapture.BpfActionAllowlist:
		// ACT_ALLOWLIST only reaches userspace as an enforce_event when the
		// target missed the allowlist, i.e. it is enforced the same as
		// ACT_DENY.
		if ev.EnforceMode == kernelcapture.BpfEnforceModeEnforce {
			return "denied"
		}
		return "blocked" // permissive mode: logged, syscall not killed
	default:
		return "compliant"
	}
}

// enforceEventTier identifies the enforcement backend + mode that produced
// an event, for the summary's TierCoverage breakdown. Forward-compatible with
// future tiers (seccomp unotify, plan E4): a non-BPF-LSM tier would key its
// own events here (e.g. "seccomp:enforce").
func enforceEventTier(ev kernelcapture.BpfEnforceEvent) string {
	if ev.EnforceMode == kernelcapture.BpfEnforceModeEnforce {
		return "bpf_lsm:enforce"
	}
	return "bpf_lsm:permissive"
}

// processEnforceEvent routes one decoded enforce_event to its session's
// Correlator, sequences and hash-chains a receipt, updates the session's
// enforcement summary, and appends the receipt to evidence. Events that
// cannot be attributed to a registered session are routed to the orphan
// scope instead of being dropped.
//
// tier identifies the enforcement backend + mode that produced ev (e.g.
// "bpf_lsm:enforce", "seccomp:enforce") for the summary's TierCoverage
// breakdown. Callers supply it explicitly rather than this function deriving
// it from ev alone: ev's shape (BpfOp/BpfAction/BpfEnforceMode) is shared
// across every enforcement tier by design, so which tier actually produced a
// given event is knowledge only the caller has — consumeEnforceEvents (the
// BPF-LSM ringbuf consumer) always saw bpf_lsm:*, but a future or concurrent
// tier's events must not be mislabeled as bpf_lsm just because they use the
// same event shape.
func (d *daemon) processEnforceEvent(ev kernelcapture.BpfEnforceEvent, tier string, log *slog.Logger) {
	verdict := enforceEventVerdict(ev)

	sid, correlator := d.routeEnforceEvent(ev.CgroupID)
	if sid == "" || correlator == nil {
		d.appendOrphanEnforceReceipt(ev, verdict, tier, log)
		return
	}

	procEvt := bpfEnforceEventToProcessEvent(ev, sid)
	receipt := correlator.Correlate(procEvt, kernelcapture.EventContext{})
	// The kernel's enforcement action is authoritative and is recorded via
	// the local verdict variable below; receipt's CorrelationMethod and
	// CorrelationConfidence are still read for attribution confidence.

	entry := kernelcapture.EnforceReceiptEntry{
		SchemaVersion:         kernelcapture.EnforceReceiptSchema,
		SessionID:             sid,
		RecordedAt:            time.Now().UTC(),
		Event:                 ev,
		Verdict:               verdict,
		CorrelationMethod:     receipt.CorrelationMethod,
		CorrelationConfidence: receipt.CorrelationConfidence,
		Orphan:                false,
	}

	d.mu.Lock()
	chain := d.enforceChains[sid]
	summary := d.enforceSummaries[sid]
	d.mu.Unlock()
	if chain == nil || summary == nil {
		// Session ended between routing and append; preserve the event
		// rather than dropping it now that we know it belongs nowhere live.
		d.appendOrphanEnforceReceipt(ev, verdict, tier, log)
		return
	}

	finalized, err := chain.Append(entry)
	if err != nil {
		log.Warn("hash-chain enforce receipt", "session_id", sid, "error", err)
		return
	}
	summary.RecordReceipt(finalized, tier)

	log.Debug("enforce event",
		"session_id", sid,
		"seq", finalized.Seq,
		"op", ev.Op,
		"action", ev.ActionTaken,
		"mode", ev.EnforceMode,
		"comm", ev.Comm,
		"verdict", verdict,
		"correlation", receipt.CorrelationMethod+"/"+receipt.CorrelationConfidence,
	)
	d.appendEnforceReceiptLine(sid, finalized, log)
}

// appendOrphanEnforceReceipt hash-chains and appends an enforce_event that
// could not be attributed to any registered session to the shared orphan
// evidence log, and counts it in the orphan summary. This is the "don't
// silently drop orphans" path: the event is preserved for forensic review
// even though it cannot be tied to a governed session.
func (d *daemon) appendOrphanEnforceReceipt(ev kernelcapture.BpfEnforceEvent, verdict, tier string, log *slog.Logger) {
	entry := kernelcapture.EnforceReceiptEntry{
		SchemaVersion: kernelcapture.EnforceReceiptSchema,
		RecordedAt:    time.Now().UTC(),
		Event:         ev,
		Verdict:       verdict,
		Orphan:        true,
	}
	finalized, err := d.enforceOrphanChain.Append(entry)
	if err != nil {
		log.Warn("hash-chain orphan enforce receipt", "cgroup_id", ev.CgroupID, "error", err)
		return
	}
	d.enforceOrphanSummary.RecordReceipt(finalized, tier)

	log.Warn("enforce event for unregistered cgroup",
		"cgroup_id", ev.CgroupID,
		"pid", ev.PID,
		"op", ev.Op,
		"verdict", verdict,
		"seq", finalized.Seq,
	)
	d.appendEnforceReceiptLine(enforceOrphanScope, finalized, log)
}

// appendEnforceReceiptLine writes one finalized EnforceReceiptEntry as a
// JSONL line to <evidenceDir>/<scope>/enforce_events.jsonl, where scope is
// either a sanitized session id or enforceOrphanScope.
func (d *daemon) appendEnforceReceiptLine(scope string, entry kernelcapture.EnforceReceiptEntry, log *slog.Logger) {
	line, err := json.Marshal(entry)
	if err != nil {
		log.Warn("marshal enforce receipt", "scope", scope, "error", err)
		return
	}
	line = append(line, '\n')

	dir := filepath.Join(d.evidenceDir, sanitizeSessionID(scope))
	path := filepath.Join(dir, "enforce_events.jsonl")
	if err := prevalidateKernelReceiptAppendPath(d.fs, d.evidenceDir, dir, path); err != nil {
		log.Warn("prevalidate enforce receipt path", "path", path, "error", err)
		return
	}
	if err := d.fs.MkdirAll(dir, 0o700); err != nil {
		log.Warn("create evidence dir for enforce receipt", "path", dir, "error", err)
		return
	}
	if err := d.fs.AppendFile(path, line, 0o600); err != nil {
		log.Warn("append enforce receipt", "path", path, "error", err)
	}
}

// enforceSummaryForScope returns a detached snapshot of the enforcement
// summary for a session id (or enforceOrphanScope), and whether one exists.
// The per-session summary's LostSamples is stamped from the shared
// (session-agnostic) ringbuf loss counter at read time: sample loss happens
// before any cgroup attribution is possible, so it cannot be charged to one
// session's accumulator and is reported as pipeline-wide context instead.
func (d *daemon) enforceSummaryForScope(scope string) (kernelcapture.EnforceEventSummary, bool) {
	d.mu.RLock()
	acc, ok := d.enforceSummaries[scope]
	d.mu.RUnlock()
	if scope == enforceOrphanScope {
		acc, ok = d.enforceOrphanSummary, d.enforceOrphanSummary != nil
	}
	if !ok || acc == nil {
		return kernelcapture.EnforceEventSummary{}, false
	}
	snap := acc.Snapshot()
	if scope != enforceOrphanScope && d.enforceOrphanSummary != nil {
		snap.LostSamples = d.enforceOrphanSummary.Snapshot().LostSamples
	}
	return snap, true
}
