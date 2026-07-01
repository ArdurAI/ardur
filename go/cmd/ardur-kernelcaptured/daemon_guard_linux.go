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
	"github.com/cilium/ebpf/ringbuf"
)

// EnforceReceiptSchema is the schema version tag written into per-session
// enforce_events JSONL files.
const EnforceReceiptSchema = "ardur.enforce.receipt.v1"

// EnforceReceiptEntry is the JSONL record appended to
// <evidenceDir>/<sessionID>/enforce_events.jsonl for each enforcement event.
type EnforceReceiptEntry struct {
	SchemaVersion string                          `json:"schema_version"`
	SessionID     string                          `json:"session_id"`
	RecordedAt    time.Time                       `json:"recorded_at"`
	Event         kernelcapture.BpfEnforceEvent   `json:"event"`
	Verdict       string                          `json:"verdict"`
}

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
func consumeEnforceEvents(ctx context.Context, reader *ringbuf.Reader, d *daemon, log *slog.Logger) error {
	var dropped uint64
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

		if record.LostSamples > 0 {
			dropped += record.LostSamples
			log.Warn("enforce_events ringbuf lost samples", "lost", record.LostSamples, "total_dropped", dropped)
		}

		ev, err := decodeEnforceEvent(record.RawSample)
		if err != nil {
			log.Warn("decode enforce_event failed", "error", err)
			continue
		}

		d.processEnforceEvent(ev, log)
	}
}

// decodeEnforceEvent deserialises the raw bytes from the BPF ringbuf into a
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
// Total: 304 bytes.
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

	if err := binary.Read(r, binary.NativeEndian, &cgroupID); err != nil {
		return ev, err
	}
	if err := binary.Read(r, binary.NativeEndian, &pid); err != nil {
		return ev, err
	}
	if err := binary.Read(r, binary.NativeEndian, &op); err != nil {
		return ev, err
	}
	if err := binary.Read(r, binary.NativeEndian, &action); err != nil {
		return ev, err
	}
	if err := binary.Read(r, binary.NativeEndian, &mode); err != nil {
		return ev, err
	}
	if err := binary.Read(r, binary.NativeEndian, &observedNS); err != nil {
		return ev, err
	}
	if err := binary.Read(r, binary.NativeEndian, &comm); err != nil {
		return ev, err
	}
	if err := binary.Read(r, binary.NativeEndian, &path); err != nil {
		return ev, err
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

// processEnforceEvent routes one enforce_event to the appropriate registered
// session and appends an EnforceReceiptEntry to the evidence log.
func (d *daemon) processEnforceEvent(ev kernelcapture.BpfEnforceEvent, log *slog.Logger) {
	d.mu.RLock()
	sid, ok := d.cgroupIndex[ev.CgroupID]
	d.mu.RUnlock()
	if !ok {
		return // event for a non-registered cgroup; ignore
	}

	verdict := enforceEventVerdict(ev)
	log.Debug("enforce event",
		"session_id", sid,
		"cgroup_id", ev.CgroupID,
		"pid", ev.PID,
		"op", ev.Op,
		"action", ev.ActionTaken,
		"mode", ev.EnforceMode,
		"comm", ev.Comm,
		"verdict", verdict,
	)

	entry := EnforceReceiptEntry{
		SchemaVersion: EnforceReceiptSchema,
		SessionID:     sid,
		RecordedAt:    time.Now().UTC(),
		Event:         ev,
		Verdict:       verdict,
	}
	line, err := json.Marshal(entry)
	if err != nil {
		log.Warn("marshal enforce receipt", "error", err)
		return
	}
	line = append(line, '\n')

	dir := filepath.Join(d.evidenceDir, sanitizeSessionID(sid))
	path := filepath.Join(dir, "enforce_events.jsonl")
	if err := d.fs.MkdirAll(dir, 0o700); err != nil {
		log.Warn("create evidence dir for enforce receipt", "path", dir, "error", err)
		return
	}
	if err := d.fs.AppendFile(path, line, 0o600); err != nil {
		log.Warn("append enforce receipt", "path", path, "error", err)
	}
}

// enforceEventVerdict maps a BpfEnforceEvent to a SyntheticKernelReceipt verdict.
func enforceEventVerdict(ev kernelcapture.BpfEnforceEvent) string {
	switch ev.ActionTaken {
	case kernelcapture.BpfActionDeny:
		if ev.EnforceMode == kernelcapture.BpfEnforceModeEnforce {
			return kernelcapture.SyntheticKernelReceiptVerdictDenied
		}
		return kernelcapture.SyntheticKernelReceiptVerdictBlocked
	case kernelcapture.BpfActionAllowlist:
		// ACT_ALLOWLIST in an event means "target not in allowlist, logged only"
		return kernelcapture.SyntheticKernelReceiptVerdictBlocked
	default:
		return kernelcapture.SyntheticKernelReceiptVerdictCompliant
	}
}
