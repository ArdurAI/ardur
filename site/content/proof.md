---
title: "Verification & Evidence"
description: "Current rerunnable proofs, CI gates, and the boundaries they do not cross."
weight: 55
maturity: ["public-now"]
claim_types: ["proof-media", "runtime-boundary"]
surfaces: ["python", "tests"]
frameworks: ["ollama", "framework-agnostic"]
evidence_levels: ["code-and-doc"]
---

The evidence below is tied to rerunnable paths in the current public tree.

## Fast Local Proofs

| Proof | What it establishes | Source |
|---|---|---|
| No-key governance loop | A temporary loopback proxy returns PERMIT and DENY and produces a locally verified signed attestation | {{< repo-link "scripts/run-no-key-mvp-demo.py" >}} |
| Claude Code deny proof | The installed local hook path returns a human-readable deny, verifies exactly one signed/hash-linked Bash violation receipt, checks post-deny file state, and removes temporary material | {{< repo-link "scripts/run-claude-deny-demo.py" >}} |
| Phase 1 evidence bundle | A redacted bundle covers setup, profile creation, simulated hook receipts, report verification, and claim mapping | {{< repo-link "scripts/run-rwt-phase1-fresh-user.py" >}} |

These are configured-boundary proofs. The file-state checks are not
independent process/kernel observation, and the no-key harness does not execute
a live provider.

## Current Verification Snapshot

At the reviewed `dev` tree on 2026-07-11:

| Gate | Result |
|---|---|
| Python local run with CI coverage flags | 1,665 passed, 33 skipped; CI separately enforces its coverage threshold |
| Python CI | Python 3.10 and 3.13, lint, and wheel smoke passed |
| Go CI | Tests, vet, lint, and vulnerability scan passed |
| Static/security | Python and Go CodeQL, secret scans, and format checks passed |
| Linux enforcement | BPF generation plus Go build/vet/race tests, live BPF-LSM kernel smoke, seccomp smoke, and full `ardur run --enforce` seccomp E2E passed |
| Docs/release contracts | Hugo, links, package build, and OCI smoke passed |

The workflow files under {{< repo-link ".github/workflows/" >}} are the
current source of truth; numeric results here are a dated snapshot.

## AAT JWT Path

The Go AAT package tests 13 constraint types, issuance, child derivation,
proof-of-possession JWTs, and chain verification. CWT integer claim-key mapping
remains pending, so this is not a complete claim for every AAT serialization
profile. See {{< repo-link "go/README.md" >}}.

## Historical Model Harness

{{< repo-link "python/tests/run_cloud_model_test.py" >}} is an opt-in
live-provider harness, and the redacted tree retains historical aggregates.
Raw per-model fixtures are not shipped, so those aggregates are context rather
than current-tree proof and are not used to claim zero false denials, universal
provider support, or a fixed latency ceiling.

## Claim Boundary

The checks above do not establish:

- visibility into calls that bypass an Ardur adapter or proxy;
- provider-hidden actions or reasoning;
- independent third-party witnessing of self-issued receipts;
- every subprocess, file, network, or kernel effect below a permitted call;
- production kernel enforcement on Linux, macOS, or Windows.

The [configured tool-boundary claim]({{< relref "/claims/configured-tool-boundary/" >}}),
[coverage map]({{< relref "/source/docs/coverage-map/" >}}), and
[known limitations]({{< relref "/source/docs/known-limitations/" >}}) keep the
trust boundary explicit.
