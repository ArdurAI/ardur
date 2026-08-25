package main

import (
	"bufio"
	"encoding/json"
	"os"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

// verifyResult is the outcome of verifying one enforce_events.jsonl log.
type verifyResult struct {
	Entries     int
	Denied      int
	ChainIntact bool
	BrokenAt    int
	HeadHash    string
	DigestMatch bool
}

// verifyLog parses an enforce_events.jsonl file, verifies its hash chain via the
// shipped kernelcapture verifier, and (when expectDigest != "") reports whether
// the chain head equals that digest.
func verifyLog(path, expectDigest string) (verifyResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return verifyResult{}, err
	}
	defer f.Close()

	var entries []kernelcapture.EnforceReceiptEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e kernelcapture.EnforceReceiptEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return verifyResult{}, err
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return verifyResult{}, err
	}

	ok, brokenAt, err := kernelcapture.VerifyEnforceReceiptChain(entries)
	if err != nil {
		return verifyResult{}, err
	}

	res := verifyResult{Entries: len(entries), ChainIntact: ok, BrokenAt: brokenAt}
	for _, e := range entries {
		if e.Verdict == "denied" {
			res.Denied++
		}
	}
	if len(entries) > 0 {
		res.HeadHash = entries[len(entries)-1].Hash
	}
	res.DigestMatch = expectDigest != "" && expectDigest == res.HeadHash
	return res, nil
}
