package kernelcapture

import (
	"testing"
	"time"
)

func testEnforceReceiptEntry(seq int) EnforceReceiptEntry {
	return EnforceReceiptEntry{
		SchemaVersion: EnforceReceiptSchema,
		SessionID:     "session-a",
		RecordedAt:    time.Unix(1_800_000_000, 0).UTC(),
		Event: BpfEnforceEvent{
			CgroupID:    42,
			PID:         uint32(1000 + seq),
			Op:          BpfOpFileWrite,
			ActionTaken: BpfActionDeny,
			EnforceMode: BpfEnforceModeEnforce,
		},
		Verdict: "denied",
	}
}

func TestEnforceReceiptChain_AssignsMonotonicSeq(t *testing.T) {
	t.Parallel()
	c := NewEnforceReceiptChain()

	for i := 1; i <= 5; i++ {
		entry, err := c.Append(testEnforceReceiptEntry(i))
		if err != nil {
			t.Fatalf("Append(%d): %v", i, err)
		}
		if entry.Seq != uint64(i) {
			t.Errorf("entry %d: seq = %d, want %d", i, entry.Seq, i)
		}
	}
	if c.Len() != 5 {
		t.Errorf("Len() = %d, want 5", c.Len())
	}
}

func TestEnforceReceiptChain_HashChainsToPrevious(t *testing.T) {
	t.Parallel()
	c := NewEnforceReceiptChain()

	first, err := c.Append(testEnforceReceiptEntry(1))
	if err != nil {
		t.Fatalf("Append(1): %v", err)
	}
	if first.PrevHash != "" {
		t.Errorf("genesis entry PrevHash = %q, want empty", first.PrevHash)
	}
	if first.Hash == "" {
		t.Error("genesis entry Hash is empty")
	}

	second, err := c.Append(testEnforceReceiptEntry(2))
	if err != nil {
		t.Fatalf("Append(2): %v", err)
	}
	if second.PrevHash != first.Hash {
		t.Errorf("second.PrevHash = %q, want %q", second.PrevHash, first.Hash)
	}
	if c.LastHash() != second.Hash {
		t.Errorf("LastHash() = %q, want %q", c.LastHash(), second.Hash)
	}

	// Same logical content appended again must still produce a different hash
	// because Seq/PrevHash differ — the chain, not just the payload, is hashed.
	third, err := c.Append(testEnforceReceiptEntry(1))
	if err != nil {
		t.Fatalf("Append(1 again): %v", err)
	}
	if third.Hash == first.Hash {
		t.Error("re-appending identical entry content produced the same hash as the genesis entry")
	}
}

func TestEnforceReceiptChain_DifferentContentDifferentHash(t *testing.T) {
	t.Parallel()
	c1, c2 := NewEnforceReceiptChain(), NewEnforceReceiptChain()

	e1 := testEnforceReceiptEntry(1)
	e2 := testEnforceReceiptEntry(1)
	e2.Verdict = "compliant"

	r1, err := c1.Append(e1)
	if err != nil {
		t.Fatalf("Append e1: %v", err)
	}
	r2, err := c2.Append(e2)
	if err != nil {
		t.Fatalf("Append e2: %v", err)
	}
	if r1.Hash == r2.Hash {
		t.Error("entries with different verdicts produced the same hash")
	}
}

func TestVerifyEnforceReceiptChain_IntactChainPasses(t *testing.T) {
	t.Parallel()
	c := NewEnforceReceiptChain()
	var entries []EnforceReceiptEntry
	for i := 1; i <= 4; i++ {
		entry, err := c.Append(testEnforceReceiptEntry(i))
		if err != nil {
			t.Fatalf("Append(%d): %v", i, err)
		}
		entries = append(entries, entry)
	}

	ok, brokenAt, err := VerifyEnforceReceiptChain(entries)
	if err != nil {
		t.Fatalf("VerifyEnforceReceiptChain: %v", err)
	}
	if !ok || brokenAt != -1 {
		t.Errorf("expected intact chain, got ok=%v brokenAt=%d", ok, brokenAt)
	}
}

func TestVerifyEnforceReceiptChain_DetectsTamperedField(t *testing.T) {
	t.Parallel()
	c := NewEnforceReceiptChain()
	var entries []EnforceReceiptEntry
	for i := 1; i <= 3; i++ {
		entry, err := c.Append(testEnforceReceiptEntry(i))
		if err != nil {
			t.Fatalf("Append(%d): %v", i, err)
		}
		entries = append(entries, entry)
	}

	entries[1].Event.Path = "/tampered/path"

	ok, brokenAt, err := VerifyEnforceReceiptChain(entries)
	if err != nil {
		t.Fatalf("VerifyEnforceReceiptChain: %v", err)
	}
	if ok || brokenAt != 1 {
		t.Errorf("expected tamper detected at index 1, got ok=%v brokenAt=%d", ok, brokenAt)
	}
}

func TestVerifyEnforceReceiptChain_DetectsDeletedEntry(t *testing.T) {
	t.Parallel()
	c := NewEnforceReceiptChain()
	var entries []EnforceReceiptEntry
	for i := 1; i <= 3; i++ {
		entry, err := c.Append(testEnforceReceiptEntry(i))
		if err != nil {
			t.Fatalf("Append(%d): %v", i, err)
		}
		entries = append(entries, entry)
	}

	// Remove the middle entry: the seq sequence now has a gap (1, 3) and the
	// third entry's PrevHash no longer matches the (now second) entry's hash.
	spliced := []EnforceReceiptEntry{entries[0], entries[2]}

	ok, brokenAt, err := VerifyEnforceReceiptChain(spliced)
	if err != nil {
		t.Fatalf("VerifyEnforceReceiptChain: %v", err)
	}
	if ok || brokenAt != 1 {
		t.Errorf("expected deletion detected at index 1, got ok=%v brokenAt=%d", ok, brokenAt)
	}
}

func TestVerifyEnforceReceiptChain_DetectsReorderedEntries(t *testing.T) {
	t.Parallel()
	c := NewEnforceReceiptChain()
	var entries []EnforceReceiptEntry
	for i := 1; i <= 3; i++ {
		entry, err := c.Append(testEnforceReceiptEntry(i))
		if err != nil {
			t.Fatalf("Append(%d): %v", i, err)
		}
		entries = append(entries, entry)
	}

	reordered := []EnforceReceiptEntry{entries[0], entries[2], entries[1]}

	ok, brokenAt, err := VerifyEnforceReceiptChain(reordered)
	if err != nil {
		t.Fatalf("VerifyEnforceReceiptChain: %v", err)
	}
	if ok || brokenAt != 1 {
		t.Errorf("expected reorder detected at index 1, got ok=%v brokenAt=%d", ok, brokenAt)
	}
}

func TestVerifyEnforceReceiptChain_EmptyChainIsTriviallyIntact(t *testing.T) {
	t.Parallel()
	ok, brokenAt, err := VerifyEnforceReceiptChain(nil)
	if err != nil {
		t.Fatalf("VerifyEnforceReceiptChain(nil): %v", err)
	}
	if !ok || brokenAt != -1 {
		t.Errorf("expected empty chain to verify as intact, got ok=%v brokenAt=%d", ok, brokenAt)
	}
}

func TestEnforceEventSummaryAccumulator_RecordsCountsAndDigest(t *testing.T) {
	t.Parallel()
	chain := NewEnforceReceiptChain()
	acc := NewEnforceEventSummaryAccumulator()

	e1, _ := chain.Append(testEnforceReceiptEntry(1))
	acc.RecordReceipt(e1, "bpf_lsm:enforce")

	permissive := testEnforceReceiptEntry(2)
	permissive.Verdict = "blocked"
	e2, _ := chain.Append(permissive)
	acc.RecordReceipt(e2, "bpf_lsm:permissive")

	acc.RecordLostSamples(3)

	snap := acc.Snapshot()
	if snap.TotalEvents != 2 {
		t.Errorf("TotalEvents = %d, want 2", snap.TotalEvents)
	}
	if snap.VerdictCounts["denied"] != 1 || snap.VerdictCounts["blocked"] != 1 {
		t.Errorf("VerdictCounts = %+v, want denied=1 blocked=1", snap.VerdictCounts)
	}
	if snap.TierCoverage["bpf_lsm:enforce"] != 1 || snap.TierCoverage["bpf_lsm:permissive"] != 1 {
		t.Errorf("TierCoverage = %+v, want one of each tier", snap.TierCoverage)
	}
	if snap.LostSamples != 3 {
		t.Errorf("LostSamples = %d, want 3", snap.LostSamples)
	}
	if snap.LastSeq != 2 {
		t.Errorf("LastSeq = %d, want 2", snap.LastSeq)
	}
	if snap.ChainDigest != e2.Hash {
		t.Errorf("ChainDigest = %q, want chain head %q", snap.ChainDigest, e2.Hash)
	}
}
