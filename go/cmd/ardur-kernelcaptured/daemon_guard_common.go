package main

// daemon_guard_common.go — platform-independent parts of BPF-LSM guard event
// handling: decoding raw ringbuf bytes, evidence-log routing, and verdict
// mapping. None of this touches BPF maps or loads kernel state, so it has no
// build tag and is unit-testable on darwin/CI (unlike runGuardConsumer /
// consumeEnforceEvents in daemon_guard_linux.go, which need a real ringbuf
// reader and are Linux-only).

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

// EnforceReceiptSchema is the schema version tag written into per-session
// enforce_events JSONL files.
const EnforceReceiptSchema = "ardur.enforce.receipt.v1"

// EnforceReceiptEntry is the JSONL record appended to
// <evidenceDir>/<sessionID>/enforce_events.jsonl for each enforcement event.
type EnforceReceiptEntry struct {
	SchemaVersion string                        `json:"schema_version"`
	SessionID     string                        `json:"session_id"`
	RecordedAt    time.Time                     `json:"recorded_at"`
	Event         kernelcapture.BpfEnforceEvent `json:"event"`
	Verdict       string                        `json:"verdict"`
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
