package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

// writeChainLog builds an n-entry hash-chained enforce_events.jsonl using the
// same producer the daemon uses (NewEnforceReceiptChain/Append) and returns the
// file path plus the chain head hash.
func writeChainLog(t *testing.T, dir string, n int) (string, string) {
	t.Helper()
	chain := kernelcapture.NewEnforceReceiptChain()
	path := filepath.Join(dir, "enforce_events.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	var head string
	enc := json.NewEncoder(f)
	for i := 1; i <= n; i++ {
		entry := kernelcapture.EnforceReceiptEntry{
			SchemaVersion: kernelcapture.EnforceReceiptSchema,
			SessionID:     "sess-verify",
			RecordedAt:    time.Unix(1_800_000_000, int64(i)).UTC(),
			Event: kernelcapture.BpfEnforceEvent{
				CgroupID: 99, PID: uint32(1000 + i), Op: kernelcapture.BpfOpExec,
				ActionTaken: kernelcapture.BpfActionDeny, EnforceMode: kernelcapture.BpfEnforceModeEnforce,
			},
			Verdict: "denied",
		}
		final, err := chain.Append(entry)
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		if err := enc.Encode(final); err != nil {
			t.Fatalf("encode: %v", err)
		}
		head = final.Hash
	}
	return path, head
}

func TestVerifyLog_IntactChainAndDigestMatch(t *testing.T) {
	path, head := writeChainLog(t, t.TempDir(), 3)

	res, err := verifyLog(path, head)
	if err != nil {
		t.Fatalf("verifyLog: %v", err)
	}
	if !res.ChainIntact || res.BrokenAt != -1 {
		t.Errorf("expected intact chain, got intact=%v brokenAt=%d", res.ChainIntact, res.BrokenAt)
	}
	if res.Entries != 3 || res.Denied != 3 {
		t.Errorf("entries=%d denied=%d, want 3/3", res.Entries, res.Denied)
	}
	if res.HeadHash != head || !res.DigestMatch {
		t.Errorf("digest match failed: head=%q match=%v", res.HeadHash, res.DigestMatch)
	}
}

func TestVerifyLog_DetectsTamperAndDigestMismatch(t *testing.T) {
	dir := t.TempDir()
	path, head := writeChainLog(t, dir, 3)

	// Tamper: rewrite the first record's event content, leaving its hash as-is.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := splitLines(raw)
	var first kernelcapture.EnforceReceiptEntry
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	first.Event.Path = "/tampered/path"
	edited, _ := json.Marshal(first)
	lines[0] = string(edited)
	if err := os.WriteFile(path, []byte(joinLines(lines)), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := verifyLog(path, head)
	if err != nil {
		t.Fatalf("verifyLog: %v", err)
	}
	if res.ChainIntact {
		t.Error("expected tamper to break the chain")
	}
	if res.BrokenAt != 0 {
		t.Errorf("brokenAt = %d, want 0", res.BrokenAt)
	}
	// Head hash is unchanged (we tampered entry 0), but a broken chain must not
	// be reported as a trustworthy digest match: DigestMatch reflects the head
	// string equality only; ChainIntact is the gate. Assert the CLI would fail.
	if res.ChainIntact && res.DigestMatch {
		t.Error("tampered log must not verify")
	}
}

func splitLines(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == '\n' {
			if i > start {
				out = append(out, string(b[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out
}

func joinLines(lines []string) string {
	s := ""
	for _, l := range lines {
		s += l + "\n"
	}
	return s
}
