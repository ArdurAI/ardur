// Command enforce-verify validates an ardur kernelcapture enforce_events.jsonl
// evidence log offline — no kernel, no daemon, no root required.
//
// It re-derives the SHA-256 hash chain with the same
// kernelcapture.VerifyEnforceReceiptChain the daemon ships, so it detects any
// gap, reorder, deletion, or content tampering in the log. Optionally, given
// the kernel_enforcement.chain_digest from a session attestation, it asserts
// that the attestation commits to this exact log (digest == chain head hash).
//
// Usage:
//
//	enforce-verify <enforce_events.jsonl> [expected_chain_digest]
//
// Exit status: 0 = chain intact (and, if a digest was supplied, it matches);
// 1 = chain broken or digest mismatch; 2 = usage/IO error.
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: enforce-verify <enforce_events.jsonl> [expected_chain_digest]")
		os.Exit(2)
	}

	logPath := os.Args[1]
	if strings.TrimSpace(logPath) == "" {
		fmt.Fprintln(os.Stderr, "enforce-verify: the enforce_events.jsonl path must be a non-empty path after trimming whitespace")
		os.Exit(2)
	}

	expectDigest := ""
	if len(os.Args) == 3 {
		expectDigest = os.Args[2]
	}

	res, err := verifyLog(logPath, expectDigest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "enforce-verify:", err)
		os.Exit(2)
	}

	fmt.Printf("entries         = %d\n", res.Entries)
	fmt.Printf("denied verdicts = %d\n", res.Denied)
	fmt.Printf("chain intact    = %v", res.ChainIntact)
	if !res.ChainIntact {
		fmt.Printf(" (first break at index %d)", res.BrokenAt)
	}
	fmt.Println()
	fmt.Printf("chain head hash = %s\n", res.HeadHash)
	if expectDigest != "" {
		fmt.Printf("attestation digest match = %v\n", res.DigestMatch)
		fmt.Printf("  attestation: %s\n  log head   : %s\n", expectDigest, res.HeadHash)
	}

	if !res.ChainIntact || (expectDigest != "" && !res.DigestMatch) {
		os.Exit(1)
	}
}
