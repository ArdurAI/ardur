package kernelcapture_test

import (
	"errors"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

// fakeGuardLinkAuditor is a test double for GuardLinkAuditor.
type fakeGuardLinkAuditor struct {
	links      []kernelcapture.TamperCheckResult
	killSwitch kernelcapture.TamperCheckResult
}

func (f fakeGuardLinkAuditor) AuditLinks() []kernelcapture.TamperCheckResult {
	return f.links
}

func (f fakeGuardLinkAuditor) AuditKillSwitch(_ bool) kernelcapture.TamperCheckResult {
	return f.killSwitch
}

func okLinks() []kernelcapture.TamperCheckResult {
	return []kernelcapture.TamperCheckResult{
		{Name: "link:bprm_check_security", OK: true, Detail: "program id unchanged"},
		{Name: "link:file_open", OK: true, Detail: "program id unchanged"},
		{Name: "link:socket_connect", OK: true, Detail: "program id unchanged"},
	}
}

func okKillSwitch() kernelcapture.TamperCheckResult {
	return kernelcapture.TamperCheckResult{Name: "kill_switch", OK: true, Detail: "matches expected state"}
}

func TestRunTamperAudit_NoDriftWhenAllChecksOK(t *testing.T) {
	t.Parallel()
	auditor := fakeGuardLinkAuditor{links: okLinks(), killSwitch: okKillSwitch()}
	result := kernelcapture.RunTamperAudit(auditor, false)
	if result.Drift {
		t.Fatalf("expected no drift, got drift with checks=%+v", result.Checks)
	}
	if len(result.Checks) != 4 {
		t.Fatalf("expected 4 checks (3 links + kill switch), got %d", len(result.Checks))
	}
	if result.CheckedAt.IsZero() {
		t.Fatal("expected CheckedAt to be set")
	}
}

func TestRunTamperAudit_DriftWhenLinkFails(t *testing.T) {
	t.Parallel()
	links := okLinks()
	links[1] = kernelcapture.TamperCheckResult{
		Name: "link:file_open", OK: false, Detail: "program id mismatch: attached=42 now=0",
	}
	auditor := fakeGuardLinkAuditor{links: links, killSwitch: okKillSwitch()}
	result := kernelcapture.RunTamperAudit(auditor, false)
	if !result.Drift {
		t.Fatal("expected drift when a link check fails")
	}
}

func TestRunTamperAudit_DriftWhenKillSwitchMismatch(t *testing.T) {
	t.Parallel()
	auditor := fakeGuardLinkAuditor{
		links:      okLinks(),
		killSwitch: kernelcapture.TamperCheckResult{Name: "kill_switch", OK: false, Detail: "expected disengaged, found engaged"},
	}
	result := kernelcapture.RunTamperAudit(auditor, false)
	if !result.Drift {
		t.Fatal("expected drift when kill switch check fails")
	}
}

func TestTamperReceiptChain_AppendSequencesAndHashChains(t *testing.T) {
	t.Parallel()
	chain := kernelcapture.NewTamperReceiptChain()

	e1, err := chain.Append(kernelcapture.TamperReceiptEntry{
		SchemaVersion: kernelcapture.TamperReceiptSchema,
		Result:        kernelcapture.RunTamperAudit(fakeGuardLinkAuditor{links: okLinks(), killSwitch: okKillSwitch()}, false),
	})
	if err != nil {
		t.Fatalf("append 1: %v", err)
	}
	if e1.Seq != 1 || e1.PrevHash != "" || e1.Hash == "" {
		t.Fatalf("unexpected first entry: %+v", e1)
	}

	e2, err := chain.Append(kernelcapture.TamperReceiptEntry{
		SchemaVersion: kernelcapture.TamperReceiptSchema,
		Result:        kernelcapture.RunTamperAudit(fakeGuardLinkAuditor{links: okLinks(), killSwitch: okKillSwitch()}, false),
	})
	if err != nil {
		t.Fatalf("append 2: %v", err)
	}
	if e2.Seq != 2 || e2.PrevHash != e1.Hash {
		t.Fatalf("unexpected second entry: %+v (want prev_hash=%s)", e2, e1.Hash)
	}
	if chain.LastHash() != e2.Hash {
		t.Fatalf("LastHash() = %q, want %q", chain.LastHash(), e2.Hash)
	}
	if chain.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", chain.Len())
	}

	ok, brokenAt, err := kernelcapture.VerifyTamperReceiptChain([]kernelcapture.TamperReceiptEntry{e1, e2})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatalf("expected chain to verify intact, broke at %d", brokenAt)
	}
}

func TestTamperReceiptChain_AppendPersistedFailureDoesNotAdvance(t *testing.T) {
	t.Parallel()
	chain := kernelcapture.NewTamperReceiptChain()
	sentinel := errors.New("disk unavailable")

	_, err := chain.AppendPersisted(
		kernelcapture.TamperReceiptEntry{SchemaVersion: kernelcapture.TamperReceiptSchema},
		func(kernelcapture.TamperReceiptEntry) error { return sentinel },
	)
	if !errors.Is(err, sentinel) {
		t.Fatalf("AppendPersisted error = %v, want %v", err, sentinel)
	}
	seq, digest := chain.Head()
	if seq != 0 || digest != "" || chain.Len() != 0 {
		t.Fatalf("failed persistence advanced chain: seq=%d digest=%q len=%d", seq, digest, chain.Len())
	}

	var persisted kernelcapture.TamperReceiptEntry
	finalized, err := chain.AppendPersisted(
		kernelcapture.TamperReceiptEntry{SchemaVersion: kernelcapture.TamperReceiptSchema},
		func(entry kernelcapture.TamperReceiptEntry) error {
			persisted = entry
			return nil
		},
	)
	if err != nil {
		t.Fatalf("successful AppendPersisted: %v", err)
	}
	if finalized.Seq != 1 || finalized.PrevHash != "" || finalized.Hash == "" {
		t.Fatalf("first committed entry after failure = %+v", finalized)
	}
	if persisted.Seq != finalized.Seq || persisted.PrevHash != finalized.PrevHash || persisted.Hash != finalized.Hash {
		t.Fatalf("persisted entry = %+v, finalized = %+v", persisted, finalized)
	}
	seq, digest = chain.Head()
	if seq != 1 || digest != finalized.Hash {
		t.Fatalf("committed head = (%d, %q), want (1, %q)", seq, digest, finalized.Hash)
	}
}

func TestVerifyTamperReceiptChain_DetectsTamperedEntry(t *testing.T) {
	t.Parallel()
	chain := kernelcapture.NewTamperReceiptChain()
	e1, err := chain.Append(kernelcapture.TamperReceiptEntry{SchemaVersion: kernelcapture.TamperReceiptSchema})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	e2, err := chain.Append(kernelcapture.TamperReceiptEntry{SchemaVersion: kernelcapture.TamperReceiptSchema})
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	tampered := e2
	tampered.Result.Drift = !tampered.Result.Drift // mutate content without recomputing the hash

	ok, brokenAt, err := kernelcapture.VerifyTamperReceiptChain([]kernelcapture.TamperReceiptEntry{e1, tampered})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("expected tampered entry to break chain verification")
	}
	if brokenAt != 1 {
		t.Fatalf("brokenAt = %d, want 1", brokenAt)
	}
}

func TestVerifyTamperReceiptChain_DetectsGapInSeq(t *testing.T) {
	t.Parallel()
	chain := kernelcapture.NewTamperReceiptChain()
	e1, _ := chain.Append(kernelcapture.TamperReceiptEntry{SchemaVersion: kernelcapture.TamperReceiptSchema})
	e2, _ := chain.Append(kernelcapture.TamperReceiptEntry{SchemaVersion: kernelcapture.TamperReceiptSchema})
	_ = e2

	e3, _ := chain.Append(kernelcapture.TamperReceiptEntry{SchemaVersion: kernelcapture.TamperReceiptSchema})

	// Skip e2 entirely — a dropped entry must be detectable via the seq gap.
	ok, brokenAt, err := kernelcapture.VerifyTamperReceiptChain([]kernelcapture.TamperReceiptEntry{e1, e3})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("expected gap in seq to break chain verification")
	}
	if brokenAt != 1 {
		t.Fatalf("brokenAt = %d, want 1", brokenAt)
	}
}
