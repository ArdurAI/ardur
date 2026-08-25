package main

// daemon_kill_switch_receipt_test.go — tests for issue #123: every
// set_kill_switch state change must land in the hash-chained, offline-
// verifiable tamper-evidence stream, attributed to the peer that made it, not
// only in a stderr line the next audit tick can't even see. These are
// platform-neutral (fake policy maps + real osEvidenceFS on a temp dir), so
// they run on every OS, matching the other daemon-dispatch tests.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

// readTamperEntries parses every JSONL line the daemon wrote to its tamper
// evidence file, in on-disk order. It intentionally does NOT sort by Seq: the
// on-disk order is exactly what VerifyTamperReceiptChain consumes, so returning
// it verbatim lets a test assert file order == Seq order.
func readTamperEntries(t *testing.T, d *daemon) []kernelcapture.TamperReceiptEntry {
	t.Helper()
	path := filepath.Join(d.evidenceDir, "_tamper", "tamper_audit.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read tamper file %s: %v", path, err)
	}
	var entries []kernelcapture.TamperReceiptEntry
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var e kernelcapture.TamperReceiptEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("unmarshal tamper line %q: %v", line, err)
		}
		entries = append(entries, e)
	}
	return entries
}

func setKillSwitchReq(engaged bool) kernelcapture.DaemonProtocolRequest {
	return kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodSetKillSwitch,
		SetKillSwitch:   &kernelcapture.DaemonSetKillSwitchRequest{Engaged: engaged},
	}
}

func TestHandleSetKillSwitch_WritesAttributedHashChainedReceipt(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	maps, _ := countingPolicyMaps()
	d.activatePolicyMaps(maps)

	// Admin (uid 0) peer; testPeerHandshakeUID pins PID 4321.
	root := testPeerHandshakeUID("", kernelcapture.DaemonProtocolMethodSetKillSwitch, 0)

	// Engage, then disengage — two transitions.
	if resp := d.handleSetKillSwitch(setKillSwitchReq(true), root); !resp.OK {
		t.Fatalf("engage: OK=false: %+v", resp)
	}
	if resp := d.handleSetKillSwitch(setKillSwitchReq(false), root); !resp.OK {
		t.Fatalf("disengage: OK=false: %+v", resp)
	}

	entries := readTamperEntries(t, d)
	var ksEntries []kernelcapture.TamperReceiptEntry
	for _, e := range entries {
		if e.KillSwitch != nil {
			ksEntries = append(ksEntries, e)
		}
	}
	if len(ksEntries) != 2 {
		t.Fatalf("want 2 kill-switch receipts, got %d (of %d total entries)", len(ksEntries), len(entries))
	}

	// First receipt: false -> true, attributed to the admin peer.
	e1 := ksEntries[0].KillSwitch
	if e1.PriorEngaged != false || e1.Engaged != true {
		t.Errorf("first receipt transition = %v->%v, want false->true", e1.PriorEngaged, e1.Engaged)
	}
	if e1.ActorUID != 0 || e1.ActorPID != 4321 {
		t.Errorf("first receipt actor = uid %d pid %d, want uid 0 pid 4321", e1.ActorUID, e1.ActorPID)
	}
	if e1.ChangedAt.IsZero() {
		t.Error("first receipt ChangedAt is zero")
	}

	// Second receipt: true -> false — the prior state must reflect the first
	// change, proving the daemon tracks the transition, not just the new value.
	e2 := ksEntries[1].KillSwitch
	if e2.PriorEngaged != true || e2.Engaged != false {
		t.Errorf("second receipt transition = %v->%v, want true->false", e2.PriorEngaged, e2.Engaged)
	}

	// The whole on-disk chain (kill-switch receipts included) must verify.
	ok, brokenAt, err := kernelcapture.VerifyTamperReceiptChain(entries)
	if err != nil {
		t.Fatalf("verify tamper chain: %v", err)
	}
	if !ok {
		t.Fatalf("tamper chain with kill-switch receipts failed to verify, broke at %d", brokenAt)
	}
}

func TestHandleSetKillSwitch_EvidenceFailureRollsBackWithoutAdvancingChain(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	maps, observed := countingPolicyMaps()
	d.activatePolicyMaps(maps)
	stub := newStubFS()
	stub.err = errors.New("evidence volume unavailable")
	d.fs = stub
	d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{
		SessionID: "rollback-session", RootPID: 4321, CgroupID: 41,
	}, "rollback-session")

	root := testPeerHandshakeUID("", kernelcapture.DaemonProtocolMethodSetKillSwitch, 0)
	resp := d.handleSetKillSwitch(setKillSwitchReq(true), root)
	if resp.OK {
		t.Fatalf("evidence failure returned OK: %+v", resp)
	}
	if observed["kill"].puts != 2 {
		t.Fatalf("kill-switch map writes = %d, want set + rollback", observed["kill"].puts)
	}
	if d.expectedKillSwitch() {
		t.Fatal("expected kill-switch state stayed engaged after successful rollback")
	}
	if seq, digest := d.tamperChain.Head(); seq != 0 || digest != "" {
		t.Fatalf("failed evidence advanced tamper chain: seq=%d digest=%q", seq, digest)
	}
	summary, ok := d.enforceSummaryForScope("rollback-session")
	if !ok || !summary.KillSwitchEvidenceGap || summary.KillSwitchEngagedDuringSession {
		t.Fatalf("rolled-back session evidence summary = %+v, ok=%v", summary, ok)
	}
}

type rollbackFailKillSwitchMap struct {
	puts int
}

func (m *rollbackFailKillSwitchMap) Put(_, _ interface{}) error {
	m.puts++
	if m.puts == 2 {
		return errors.New("simulated rollback failure")
	}
	return nil
}

func (m *rollbackFailKillSwitchMap) Delete(_ interface{}) error { return nil }

func TestHandleSetKillSwitch_RollbackFailureSurfacesSessionEvidenceGap(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	maps, _ := countingPolicyMaps()
	kill := &rollbackFailKillSwitchMap{}
	maps.KillSwitch = kill
	d.activatePolicyMaps(maps)
	stub := newStubFS()
	stub.err = errors.New("evidence volume unavailable")
	d.fs = stub
	d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{
		SessionID: "gap-session", RootPID: 4321, CgroupID: 42,
	}, "gap-session")

	root := testPeerHandshakeUID("", kernelcapture.DaemonProtocolMethodSetKillSwitch, 0)
	resp := d.handleSetKillSwitch(setKillSwitchReq(true), root)
	if resp.OK {
		t.Fatalf("evidence and rollback failure returned OK: %+v", resp)
	}
	if kill.puts != 2 {
		t.Fatalf("kill-switch map writes = %d, want set + failed rollback", kill.puts)
	}
	if !d.expectedKillSwitch() {
		t.Fatal("expected state must reflect the successful set when rollback fails")
	}
	summary, ok := d.enforceSummaryForScope("gap-session")
	if !ok || !summary.KillSwitchEvidenceGap || !summary.KillSwitchEngagedDuringSession {
		t.Fatalf("session evidence gap summary = %+v, ok=%v", summary, ok)
	}
}

func TestHandleSetKillSwitch_SessionStatusBindsTamperHeadAndImpact(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	maps, _ := countingPolicyMaps()
	d.activatePolicyMaps(maps)
	d.onSessionRegistered(&kernelcapture.DaemonRegisterSessionRequest{
		SessionID: "attested-session", RootPID: 4321, CgroupID: 43,
	}, "attested-session")
	root := testPeerHandshakeUID("", kernelcapture.DaemonProtocolMethodSetKillSwitch, 0)

	if resp := d.handleSetKillSwitch(setKillSwitchReq(true), root); !resp.OK {
		t.Fatalf("engage: %+v", resp)
	}
	if resp := d.handleSetKillSwitch(setKillSwitchReq(false), root); !resp.OK {
		t.Fatalf("disengage: %+v", resp)
	}

	summary, ok := d.enforceSummaryForScope("attested-session")
	if !ok {
		t.Fatal("missing enforcement summary")
	}
	seq, digest := d.tamperChain.Head()
	if summary.TamperChainStartSeq != 1 || summary.TamperChainLastSeq != seq || summary.TamperChainDigest != digest {
		t.Fatalf("tamper window/head = %+v, chain head=(%d, %q)", summary, seq, digest)
	}
	if summary.KillSwitchChangeCount != 2 || !summary.KillSwitchEngagedDuringSession || summary.KillSwitchEvidenceGap {
		t.Fatalf("kill-switch session impact = %+v", summary)
	}
}

func TestHandleSetKillSwitch_DeniedNonRootWritesNoReceipt(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	maps, _ := countingPolicyMaps()
	d.activatePolicyMaps(maps)

	nonRoot := testPeerHandshakeUID("", kernelcapture.DaemonProtocolMethodSetKillSwitch, 501)
	if resp := d.handleSetKillSwitch(setKillSwitchReq(true), nonRoot); resp.OK {
		t.Fatalf("non-root set_kill_switch unexpectedly OK: %+v", resp)
	}

	// A denied change must leave NO receipt — the evidence stream must not imply
	// enforcement was disabled when the admin gate refused the request.
	path := filepath.Join(d.evidenceDir, "_tamper", "tamper_audit.jsonl")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		entries := readTamperEntries(t, d)
		for _, e := range entries {
			if e.KillSwitch != nil {
				t.Fatalf("denied non-root request still wrote a kill-switch receipt: %+v", e.KillSwitch)
			}
		}
	}
}

// TestHandleSetKillSwitch_ReceiptOrderingUnderConcurrentAuditTicks proves the
// tamperWriteMu guarantee: with the audit ticker and set_kill_switch both
// appending to the one chain concurrently, the on-disk line order still matches
// Seq order, so VerifyTamperReceiptChain (which reads lines in file order)
// passes. Without holding a lock across chain-append + file-write, two
// goroutines could take Seq N, N+1 and flush their lines reversed — this test,
// under -race, is what catches a regression that drops that serialization.
func TestHandleSetKillSwitch_ReceiptOrderingUnderConcurrentAuditTicks(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	maps, _ := countingPolicyMaps()
	d.activatePolicyMaps(maps)
	root := testPeerHandshakeUID("", kernelcapture.DaemonProtocolMethodSetKillSwitch, 0)

	const iterations = 40
	var wg sync.WaitGroup
	wg.Add(2)

	// Writer A: audit ticks (no applyMu — the real concurrency hazard).
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			d.recordTamperAudit(kernelcapture.TamperAuditResult{CheckedAt: time.Now().UTC()}, d.log)
		}
	}()
	// Writer B: kill-switch toggles.
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			d.handleSetKillSwitch(setKillSwitchReq(i%2 == 0), root)
		}
	}()
	wg.Wait()

	entries := readTamperEntries(t, d)
	if len(entries) != 2*iterations {
		t.Fatalf("wrote %d entries, want %d", len(entries), 2*iterations)
	}
	ok, brokenAt, err := kernelcapture.VerifyTamperReceiptChain(entries)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatalf("concurrent writers produced an out-of-order/broken chain at index %d "+
			"(file order != Seq order — tamperWriteMu not serializing append+write)", brokenAt)
	}
}

// TestTamperAuditTickHashUnchangedByKillSwitchField is a backward-compatibility
// guard: an audit-tick entry (KillSwitch nil) must marshal — and therefore
// hash — exactly as it did before #123 added the omitempty field, so existing
// tamper_audit.jsonl chains still verify. We assert the marshaled tick carries
// no kill_switch key at all.
func TestTamperAuditTickHashUnchangedByKillSwitchField(t *testing.T) {
	t.Parallel()
	entry := kernelcapture.TamperReceiptEntry{
		SchemaVersion: kernelcapture.TamperReceiptSchema,
		Result:        kernelcapture.TamperAuditResult{CheckedAt: time.Now().UTC()},
	}
	blob, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(blob, []byte("kill_switch")) {
		t.Fatalf("audit-tick entry marshaled with a kill_switch key, breaking prior-hash compatibility: %s", blob)
	}
}
