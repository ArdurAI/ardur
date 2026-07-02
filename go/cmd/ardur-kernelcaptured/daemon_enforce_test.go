package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

// encodeTestEnforceEvent serializes ev into the exact 304-byte layout
// decodeEnforceEvent expects, mirroring struct ardur_enforce_event.
func encodeTestEnforceEvent(t *testing.T, ev kernelcapture.BpfEnforceEvent) []byte {
	t.Helper()
	var buf bytes.Buffer

	var comm [16]byte
	copy(comm[:], ev.Comm)
	var path [256]byte
	copy(path[:], ev.Path)

	fields := []any{
		ev.CgroupID,
		ev.PID,
		uint32(ev.Op),
		uint32(ev.ActionTaken),
		uint32(ev.EnforceMode),
		ev.ObservedNS,
		comm,
		path,
	}
	for _, f := range fields {
		if err := binary.Write(&buf, binary.NativeEndian, f); err != nil {
			t.Fatalf("encode test enforce event: %v", err)
		}
	}
	return buf.Bytes()
}

// fakeEnforceEventReader replays a fixed sequence of records, then returns
// io.EOF.
type fakeEnforceEventReader struct {
	records []enforceEventRecord
	i       int
}

func (f *fakeEnforceEventReader) Read() (enforceEventRecord, error) {
	if f.i >= len(f.records) {
		return enforceEventRecord{}, io.EOF
	}
	rec := f.records[f.i]
	f.i++
	return rec, nil
}

func readEnforceReceiptLines(t *testing.T, stub *stubEvidenceFS, path string) []kernelcapture.EnforceReceiptEntry {
	t.Helper()
	stub.mu.Lock()
	data := append([]byte(nil), stub.appends[path]...)
	stub.mu.Unlock()

	var out []kernelcapture.EnforceReceiptEntry
	for _, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var entry kernelcapture.EnforceReceiptEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("unmarshal enforce receipt line: %v\n%s", err, line)
		}
		out = append(out, entry)
	}
	return out
}

func TestProcessEnforceEvent_DeniedEventRoutesThroughCorrelator(t *testing.T) {
	d := newTestDaemon(t)
	stub := newStubFS()
	d.fs = stub

	d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{
		SessionID:    "enforce-session-1",
		RootPID:      100,
		CgroupID:     42,
		EventClasses: []string{kernelcapture.DaemonProtocolEventProcessLifecycle},
		TTLSeconds:   300,
	}, "enforce-session-1")

	ev := kernelcapture.BpfEnforceEvent{
		CgroupID:    42,
		PID:         100,
		Op:          kernelcapture.BpfOpFileWrite,
		ActionTaken: kernelcapture.BpfActionDeny,
		EnforceMode: kernelcapture.BpfEnforceModeEnforce,
		ObservedNS:  123456789,
		Comm:        "agent",
		Path:        "/etc/shadow",
	}
	d.processEnforceEvent(ev, d.log)

	path := filepath.Join(d.evidenceDir, sanitizeSessionID("enforce-session-1"), "enforce_events.jsonl")
	entries := readEnforceReceiptLines(t, stub, path)
	if len(entries) != 1 {
		t.Fatalf("expected 1 enforce receipt, got %d", len(entries))
	}
	entry := entries[0]
	if entry.Verdict != "denied" {
		t.Errorf("verdict = %q, want %q", entry.Verdict, "denied")
	}
	if entry.Orphan {
		t.Error("registered session's event was marked orphan")
	}
	if entry.SessionID != "enforce-session-1" {
		t.Errorf("session_id = %q, want %q", entry.SessionID, "enforce-session-1")
	}
	// The event routed through the real per-session Correlator (cgroup+PID
	// match, no registered ToolReceipt) rather than a bare cgroup lookup, so
	// it must carry a correlation grading, not an empty/bypassed one.
	if entry.CorrelationMethod == "" || entry.CorrelationConfidence == "" {
		t.Errorf("expected correlation metadata from the Correlator, got method=%q confidence=%q",
			entry.CorrelationMethod, entry.CorrelationConfidence)
	}
	if entry.Seq != 1 || entry.PrevHash != "" || entry.Hash == "" {
		t.Errorf("expected first chain entry (seq=1, empty prev_hash, non-empty hash); got %+v", entry)
	}

	summary, ok := d.enforceSummaryForScope("enforce-session-1")
	if !ok {
		t.Fatal("expected an enforcement summary for the registered session")
	}
	if summary.TotalEvents != 1 || summary.VerdictCounts["denied"] != 1 {
		t.Errorf("session summary = %+v, want 1 total denied event", summary)
	}
	if summary.TierCoverage["bpf_lsm:enforce"] != 1 {
		t.Errorf("session summary tier coverage = %+v, want bpf_lsm:enforce=1", summary.TierCoverage)
	}
	if summary.OrphanCount != 0 {
		t.Errorf("registered session's summary should have zero orphans, got %d", summary.OrphanCount)
	}
}

func TestProcessEnforceEvent_OrphanEventNotDropped(t *testing.T) {
	d := newTestDaemon(t)
	stub := newStubFS()
	d.fs = stub

	// No session registered for cgroup 7777: this event cannot be attributed.
	ev := kernelcapture.BpfEnforceEvent{
		CgroupID:    7777,
		PID:         555,
		Op:          kernelcapture.BpfOpNetConnect,
		ActionTaken: kernelcapture.BpfActionDeny,
		EnforceMode: kernelcapture.BpfEnforceModeEnforce,
		Comm:        "orphan-proc",
	}
	d.processEnforceEvent(ev, d.log)

	orphanPath := filepath.Join(d.evidenceDir, sanitizeSessionID(enforceOrphanScope), "enforce_events.jsonl")
	entries := readEnforceReceiptLines(t, stub, orphanPath)
	if len(entries) != 1 {
		t.Fatalf("expected the orphan event to be preserved in the orphan log, got %d entries", len(entries))
	}
	if !entries[0].Orphan {
		t.Error("orphan log entry should have Orphan=true")
	}
	if entries[0].SessionID != "" {
		t.Errorf("orphan entry should carry no session_id, got %q", entries[0].SessionID)
	}

	summary, ok := d.enforceSummaryForScope(enforceOrphanScope)
	if !ok {
		t.Fatal("expected an orphan enforcement summary to exist")
	}
	if summary.OrphanCount != 1 || summary.TotalEvents != 1 {
		t.Errorf("orphan summary = %+v, want 1 orphan/1 total", summary)
	}
}

func TestConsumeEnforceEvents_SequencingAndHashChainContinuity(t *testing.T) {
	d := newTestDaemon(t)
	stub := newStubFS()
	d.fs = stub

	d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{
		SessionID:    "chain-session",
		RootPID:      1,
		CgroupID:     10,
		EventClasses: []string{kernelcapture.DaemonProtocolEventProcessLifecycle},
		TTLSeconds:   300,
	}, "chain-session")

	base := kernelcapture.BpfEnforceEvent{CgroupID: 10, PID: 1, ActionTaken: kernelcapture.BpfActionDeny, EnforceMode: kernelcapture.BpfEnforceModeEnforce}
	reader := &fakeEnforceEventReader{records: []enforceEventRecord{
		{RawSample: encodeTestEnforceEvent(t, base)},
		{RawSample: encodeTestEnforceEvent(t, base)},
		{RawSample: encodeTestEnforceEvent(t, base)},
	}}

	if err := consumeEnforceEvents(context.Background(), reader, d, d.log); err != nil {
		t.Fatalf("consumeEnforceEvents: %v", err)
	}

	path := filepath.Join(d.evidenceDir, sanitizeSessionID("chain-session"), "enforce_events.jsonl")
	entries := readEnforceReceiptLines(t, stub, path)
	if len(entries) != 3 {
		t.Fatalf("expected 3 chained entries, got %d", len(entries))
	}
	for i, e := range entries {
		if e.Seq != uint64(i+1) {
			t.Errorf("entry %d: seq = %d, want %d", i, e.Seq, i+1)
		}
	}
	if entries[1].PrevHash != entries[0].Hash {
		t.Errorf("entry 1 prev_hash %q does not chain to entry 0 hash %q", entries[1].PrevHash, entries[0].Hash)
	}
	if entries[2].PrevHash != entries[1].Hash {
		t.Errorf("entry 2 prev_hash %q does not chain to entry 1 hash %q", entries[2].PrevHash, entries[1].Hash)
	}

	ok, brokenAt, err := kernelcapture.VerifyEnforceReceiptChain(entries)
	if err != nil {
		t.Fatalf("VerifyEnforceReceiptChain: %v", err)
	}
	if !ok {
		t.Fatalf("expected intact chain, broke at index %d", brokenAt)
	}

	// Tamper with the middle entry's verdict and confirm verification catches it.
	tampered := append([]kernelcapture.EnforceReceiptEntry(nil), entries...)
	tampered[1].Verdict = "compliant"
	ok, brokenAt, err = kernelcapture.VerifyEnforceReceiptChain(tampered)
	if err != nil {
		t.Fatalf("VerifyEnforceReceiptChain (tampered): %v", err)
	}
	if ok || brokenAt != 1 {
		t.Errorf("expected tamper detection at index 1, got ok=%v brokenAt=%d", ok, brokenAt)
	}
}

func TestConsumeEnforceEvents_LostSamplesAccounted(t *testing.T) {
	d := newTestDaemon(t)
	stub := newStubFS()
	d.fs = stub

	reader := &fakeEnforceEventReader{records: []enforceEventRecord{
		{LostSamples: 5, RawSample: encodeTestEnforceEvent(t, kernelcapture.BpfEnforceEvent{CgroupID: 999, PID: 1})},
	}}
	if err := consumeEnforceEvents(context.Background(), reader, d, d.log); err != nil {
		t.Fatalf("consumeEnforceEvents: %v", err)
	}

	summary, ok := d.enforceSummaryForScope(enforceOrphanScope)
	if !ok {
		t.Fatal("expected orphan summary to exist")
	}
	if summary.LostSamples != 5 {
		t.Errorf("lost samples = %d, want 5", summary.LostSamples)
	}
}

func TestConsumeEnforceEvents_StopsOnContextCancellation(t *testing.T) {
	d := newTestDaemon(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	reader := &fakeEnforceEventReader{records: []enforceEventRecord{
		{RawSample: encodeTestEnforceEvent(t, kernelcapture.BpfEnforceEvent{})},
	}}
	err := consumeEnforceEvents(ctx, reader, d, d.log)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestHandleAuthorizedRequest_SessionStatusIncludesEnforcementSummary(t *testing.T) {
	d := newTestDaemon(t)
	stub := newStubFS()
	d.fs = stub

	handshake := kernelcapture.DaemonProtocolPeerHandshake{
		ProtocolVersion:       kernelcapture.DaemonProtocolVersion,
		Method:                kernelcapture.DaemonProtocolMethodRegisterSession,
		SessionID:             "status-session",
		SocketPath:            "/run/ardur/kernelcapture/control.sock",
		CredentialSource:      kernelcapture.DaemonPeerCredentialSourceLinuxSOPeerCred,
		ProcessStartTimeTicks: 1,
		Authorization: kernelcapture.DaemonPeerAuthorization{
			Verdict:               kernelcapture.DaemonPeerAuthorizationVerdictAllow,
			Reason:                "test",
			UID:                   501,
			PID:                   4242,
			ProcessStartTimeTicks: 1,
			Matched:               "uid",
		},
	}

	registerResp := d.handleAuthorizedRequest(context.Background(), kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodRegisterSession,
		RegisterSession: &kernelcapture.DaemonRegisterSessionRequest{
			SessionID:    "status-session",
			RootPID:      100,
			CgroupID:     55,
			EventClasses: []string{kernelcapture.DaemonProtocolEventProcessLifecycle},
			TTLSeconds:   300,
		},
	}, handshake)
	if !registerResp.OK {
		t.Fatalf("register_session failed: %+v", registerResp)
	}

	d.processEnforceEvent(kernelcapture.BpfEnforceEvent{
		CgroupID:    55,
		PID:         100,
		ActionTaken: kernelcapture.BpfActionDeny,
		EnforceMode: kernelcapture.BpfEnforceModeEnforce,
	}, d.log)

	statusResp := d.handleAuthorizedRequest(context.Background(), kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodSessionStatus,
		SessionStatus:   &kernelcapture.DaemonSessionStatusRequest{SessionID: "status-session"},
	}, handshake)
	if !statusResp.OK {
		t.Fatalf("session_status failed: %+v", statusResp)
	}
	if statusResp.Enforcement == nil {
		t.Fatal("expected session_status response to carry an Enforcement summary")
	}
	if statusResp.Enforcement.TotalEvents != 1 || statusResp.Enforcement.VerdictCounts["denied"] != 1 {
		t.Errorf("enforcement summary = %+v, want 1 total denied event", statusResp.Enforcement)
	}
}
