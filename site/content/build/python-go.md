---
title: "Python And Go Runtime Surfaces"
description: "Curated runtime imports are public; dedicated Python and Go CI run on every push and pull request."
weight: 41
maturity: ["public-now"]
claim_types: ["runtime-boundary"]
surfaces: ["python", "go"]
frameworks: ["framework-agnostic"]
evidence_levels: ["code-and-doc"]
---

{{< claim "mission-boundary" >}}

The Python and Go directories are public runtime surfaces. Dedicated Python
(3.10 + 3.13) and Go test jobs run on every push and pull request via
`.github/workflows/tests.yml`, alongside CodeQL, link-check, secret-scan,
format validation, and the Hugo site build.

## Go AAT Engine

The `go/pkg/aat` package is a complete implementation of the Attenuating
Authorization Token specification:

- **13 constraint types** with full check and subsumption semantics
- **IssueRoot / DeriveChild** with holder binding, depth tracking, and
  cryptographic parent-chain linking
- **BuildPoPJWT / VerifyPoPJWT** with deterministic HTA canonicalization
- **VerifyChain** — the 8-step offline verification algorithm per AAT §7
- **49 tests** covering constraint checks, cross-type subsumption,
  issuance, derivation, PoP round-trips, and full chain scenarios

## Cloud Model Governance Tests

`python/tests/test-results/` contains real-world governance test results
proving the Ardur proxy enforces policy correctly with live cloud LLMs:

- **Cloud Model (1T params):** 18/20 files created, 35 tool calls, zero denials
- **Local Model (8B):** 4/20 files, 4 tool calls, zero denials
- Every tool call flows through evaluate → attest → receipt
- Average proxy overhead: ~4ms per call

Sources: {{< repo-link "python/README.md" >}}, {{< repo-link "go/README.md" >}}, {{< repo-link "python/tests/test-results/SUMMARY.md" "Cloud model test results" >}}, and {{< repo-link ".github/workflows/tests.yml" "tests workflow" >}}.
