package kernelcapture

// tamper_audit.go — periodic self-audit of the loaded BPF-LSM enforcement
// state (Epic A #63, Slice 2 remainder).
//
// The daemon holds open handles to the process_guard BPF-LSM links and maps
// for as long as it runs, but holding a handle does not guarantee the kernel
// state behind it is unchanged: a sufficiently privileged external actor can
// force-detach a link (e.g. `bpftool link detach`) or overwrite the
// kill-switch map directly, and the daemon's own FDs would not notice unless
// it goes and checks. RunTamperAudit is that check: it re-verifies the
// program a link is still associated with (BPF_OBJ_GET_INFO_BY_FD reports a
// link's current attachment; a detached link's reported program diverges from
// what was attached) and that the kill-switch map still reads back the value
// the daemon itself last wrote.
//
// Claim boundary — what this DOES verify:
//   - Each held BPF-LSM link still reports the program ID it was attached
//     with (link.Info().Program unchanged since LoadAndAttachProcessGuardEBPF).
//   - The kill_switch map value matches what the daemon believes it last set.
//
// What this does NOT verify (out of scope for this slice):
//   - Whether the BPF program's bytecode/logic was modified (verifier-signed
//     bytecode makes this hard to tamper with in the first place).
//   - cgroup_op_policy / cgroup_path_allow / cgroup_net_allow / cgroup_managed
//     map contents beyond what apply_policy itself already asserts on write.
//   - Any tampering that also compromises the daemon process itself (a
//     root-equivalent attacker who controls this process can make any check
//     here report whatever it wants).
//
// This file has no build tag: the types and orchestration are pure Go and
// unit-testable everywhere via the GuardLinkAuditor interface. The real
// Linux-backed auditor lives behind ProcessGuardHandles.AuditLinks/
// AuditKillSwitch in bpf_policy_apply_linux.go — the same split used for
// enforce_events (enforceEventReader / ringbufEnforceEventReader).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// TamperReceiptSchema is the schema version tag written into
// <evidenceDir>/_tamper/tamper_audit.jsonl.
const TamperReceiptSchema = "ardur.tamper.receipt.v1"

// TamperCheckResult is the outcome of one individual drift check.
type TamperCheckResult struct {
	// Name identifies the check, e.g. "link:bprm_check_security" or
	// "kill_switch".
	Name string `json:"name"`
	// OK is true when the check found no drift.
	OK bool `json:"ok"`
	// Detail is a human-readable explanation, always populated.
	Detail string `json:"detail"`
}

// TamperAuditResult is one audit tick's full set of check outcomes.
type TamperAuditResult struct {
	CheckedAt time.Time           `json:"checked_at"`
	Checks    []TamperCheckResult `json:"checks"`
	Drift     bool                `json:"drift"`
}

// GuardLinkAuditor is satisfied by the loaded BPF-LSM guard handles (Linux)
// and by fakes in tests. It never mutates kernel state — every method is a
// read-only re-verification of state established at load/apply time.
type GuardLinkAuditor interface {
	// AuditLinks re-verifies every held LSM link still reports the program it
	// was attached with.
	AuditLinks() []TamperCheckResult
	// AuditKillSwitch re-verifies the kill_switch map still reads back
	// expectedEngaged, the value the daemon itself last set (default false).
	AuditKillSwitch(expectedEngaged bool) TamperCheckResult
}

// RunTamperAudit runs every check in auditor and folds the results into one
// TamperAuditResult. auditor must not be nil — callers only invoke this once
// a guard is loaded (see runGuardConsumer), matching the existing pattern
// where enforce_events processing is only wired up once the guard is present.
func RunTamperAudit(auditor GuardLinkAuditor, expectedKillSwitchEngaged bool) TamperAuditResult {
	result := TamperAuditResult{CheckedAt: time.Now().UTC()}
	result.Checks = append(result.Checks, auditor.AuditLinks()...)
	result.Checks = append(result.Checks, auditor.AuditKillSwitch(expectedKillSwitchEngaged))
	for _, c := range result.Checks {
		if !c.OK {
			result.Drift = true
			break
		}
	}
	return result
}

// TamperReceiptEntry is one hash-chained, sequenced tamper-audit record.
type TamperReceiptEntry struct {
	SchemaVersion string            `json:"schema_version"`
	Seq           uint64            `json:"seq"`
	PrevHash      string            `json:"prev_hash"`
	Hash          string            `json:"hash"`
	RecordedAt    time.Time         `json:"recorded_at"`
	Result        TamperAuditResult `json:"result"`
}

// TamperReceiptChain maintains a monotonic seq + SHA-256 hash chain of tamper
// audit ticks, the same construction EnforceReceiptChain uses for
// enforce_events — see that file for the rationale. Kept as a separate type
// rather than a shared generic because the entry payload (TamperAuditResult
// vs BpfEnforceEvent) differs and the two evidence streams have independent
// lifecycles (one chain per daemon process, not one per session).
//
// TamperReceiptChain is safe for concurrent use by multiple goroutines.
type TamperReceiptChain struct {
	mu       sync.Mutex
	nextSeq  uint64
	lastHash string
}

// NewTamperReceiptChain returns a chain starting at Seq 1 with an empty
// genesis PrevHash.
func NewTamperReceiptChain() *TamperReceiptChain {
	return &TamperReceiptChain{nextSeq: 1}
}

// Append assigns the next Seq and Hash to entry (its Seq/PrevHash/Hash fields
// are overwritten) and returns the finalized entry.
func (c *TamperReceiptChain) Append(entry TamperReceiptEntry) (TamperReceiptEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry.Seq = c.nextSeq
	entry.PrevHash = c.lastHash
	entry.Hash = ""
	hash, err := hashTamperReceiptEntry(entry)
	if err != nil {
		return TamperReceiptEntry{}, fmt.Errorf("kernelcapture: hash tamper receipt entry: %w", err)
	}
	entry.Hash = hash

	c.nextSeq++
	c.lastHash = entry.Hash
	return entry, nil
}

// LastHash returns the hash of the most recently appended entry, or "" if the
// chain is empty.
func (c *TamperReceiptChain) LastHash() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastHash
}

// Len returns the number of entries appended to the chain so far.
func (c *TamperReceiptChain) Len() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nextSeq - 1
}

func hashTamperReceiptEntry(entry TamperReceiptEntry) (string, error) {
	entry.Hash = ""
	canonical, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyTamperReceiptChain re-derives hashes over entries (which must already
// be ordered by Seq) and reports whether the chain is intact, mirroring
// VerifyEnforceReceiptChain.
func VerifyTamperReceiptChain(entries []TamperReceiptEntry) (ok bool, brokenAt int, err error) {
	var expectedSeq uint64 = 1
	prevHash := ""
	for i, entry := range entries {
		if entry.Seq != expectedSeq {
			return false, i, nil
		}
		if entry.PrevHash != prevHash {
			return false, i, nil
		}
		claimedHash := entry.Hash
		recomputed, hashErr := hashTamperReceiptEntry(entry)
		if hashErr != nil {
			return false, i, fmt.Errorf("kernelcapture: recompute hash for entry %d: %w", i, hashErr)
		}
		if claimedHash != recomputed {
			return false, i, nil
		}
		expectedSeq++
		prevHash = claimedHash
	}
	return true, -1, nil
}
