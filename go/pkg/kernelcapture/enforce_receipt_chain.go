package kernelcapture

// enforce_receipt_chain.go — sequencing and hash-chaining for enforce_events
// evidence (Epic A #63, plan E3).
//
// enforce_events.jsonl records were previously unsequenced and unsigned: an
// entry could be dropped, reordered, or edited after the fact with no way to
// detect it. EnforceReceiptChain assigns each entry a monotonic Seq and a
// SHA-256 hash over its own content plus the previous entry's hash, so a
// verifier can walk the chain from Seq 1 forward and prove nothing was
// removed, reordered, or altered.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// EnforceReceiptSchema is the schema version tag written into per-session
// (and orphan) enforce_events JSONL files.
const EnforceReceiptSchema = "ardur.enforce.receipt.v1"

// EnforceReceiptEntry is one hash-chained, sequenced enforcement-event record.
// SessionID is empty and Orphan is true for events that could not be
// attributed to any registered session.
type EnforceReceiptEntry struct {
	SchemaVersion         string          `json:"schema_version"`
	SessionID             string          `json:"session_id,omitempty"`
	Seq                   uint64          `json:"seq"`
	PrevHash              string          `json:"prev_hash"`
	Hash                  string          `json:"hash"`
	RecordedAt            time.Time       `json:"recorded_at"`
	Event                 BpfEnforceEvent `json:"event"`
	Verdict               string          `json:"verdict"`
	CorrelationMethod     string          `json:"correlation_method,omitempty"`
	CorrelationConfidence string          `json:"correlation_confidence,omitempty"`
	Orphan                bool            `json:"orphan"`
}

// EnforceReceiptChain maintains a monotonic seq + SHA-256 hash chain of
// enforcement receipts for one routing scope: either a single session, or the
// shared scope used for events that could not be attributed to any session.
//
// EnforceReceiptChain is safe for concurrent use by multiple goroutines.
type EnforceReceiptChain struct {
	mu       sync.Mutex
	nextSeq  uint64
	lastHash string
}

// NewEnforceReceiptChain returns a chain starting at Seq 1 with an empty
// genesis PrevHash.
func NewEnforceReceiptChain() *EnforceReceiptChain {
	return &EnforceReceiptChain{nextSeq: 1}
}

// Append assigns the next Seq and Hash to entry (its Seq/PrevHash/Hash fields
// are overwritten) and returns the finalized entry. The entry is not
// considered committed to the chain's running state until Append returns
// successfully.
func (c *EnforceReceiptChain) Append(entry EnforceReceiptEntry) (EnforceReceiptEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry.Seq = c.nextSeq
	entry.PrevHash = c.lastHash
	entry.Hash = ""
	hash, err := hashEnforceReceiptEntry(entry)
	if err != nil {
		return EnforceReceiptEntry{}, fmt.Errorf("kernelcapture: hash enforce receipt entry: %w", err)
	}
	entry.Hash = hash

	c.nextSeq++
	c.lastHash = entry.Hash
	return entry, nil
}

// LastHash returns the hash of the most recently appended entry, or "" if the
// chain is empty.
func (c *EnforceReceiptChain) LastHash() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastHash
}

// Len returns the number of entries appended to the chain so far.
func (c *EnforceReceiptChain) Len() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nextSeq - 1
}

// hashEnforceReceiptEntry computes the chain hash for entry: SHA-256 over a
// canonical JSON encoding of every field except Hash itself (which is what's
// being computed). PrevHash is included, which is what makes this a chain
// rather than an independent per-entry digest.
func hashEnforceReceiptEntry(entry EnforceReceiptEntry) (string, error) {
	entry.Hash = ""
	canonical, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyEnforceReceiptChain re-derives hashes over entries (which must already
// be ordered by Seq) and reports whether the chain is intact. ok is false and
// brokenAt is the index of the first entry (0-based, into entries) whose Seq,
// PrevHash, or Hash does not match what Append would have produced given the
// preceding entry — this catches gaps in Seq, tampering with any entry's
// content, reordering, and deletion.
func VerifyEnforceReceiptChain(entries []EnforceReceiptEntry) (ok bool, brokenAt int, err error) {
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
		recomputed, hashErr := hashEnforceReceiptEntry(entry)
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
