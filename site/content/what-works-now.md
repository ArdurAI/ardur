---
title: "What Works Now"
description: "Current public Ardur capability, separated from roadmap ambition."
weight: 20
maturity: ["public-now", "in-progress"]
claim_types: ["status", "runtime-boundary", "integration", "protocol-spec"]
surfaces: ["docs", "python", "go", "examples", "media", "github"]
frameworks: ["framework-agnostic", "claude-code", "langchain", "langgraph", "autogen"]
evidence_levels: ["code-and-doc", "spec", "archival-media"]
---

Ardur is pre-release, but the public repo is code-bearing today.

## Public Now

| Surface | Current state | Primary source |
|---|---|---|
| Runtime governance | Configured Python proxy and adapter paths for mission passport issuance, policy decisions, and issuer-signed/hash-linked receipts; Go JWT AAT constraints, derivation, PoP, and chain verification with CWT mapping still pending | {{< repo-link "python/README.md" "Python" >}}, {{< repo-link "go/README.md" "Go" >}} |
| CLI | Protocol and Personal commands including `issue`, full offline `verify`, `anchor`, `receiver-attestation-fixture`, `offline-verification-fixture`, `attest`, `start`, `hub`, `setup`, `status`, `doctor`, `doctor-claude-code`, `run`, `profile init`, `protect claude-code`, `claude-code-hook`, and `claude-code-report`; the wheel also ships `ardur-verify` | {{< repo-link "docs/reference/cli.md" "CLI reference" >}} |
| Ardur Personal | Local Hub service, browser extension, desktop observe adapter, native messaging host | {{< repo-link "docs/guides/ardur-personal-hub.md" "Personal Hub guide" >}} |
| Claude Code | Plugin and hooks for `PreToolUse`, `PostToolUse`, `SubagentStart`, `SubagentStop`; source-checkout MVP quickstart with no-key harness, demo packet, evidence-bundle reader, and live-Claude path | {{< repo-link "docs/guides/claude-code-mvp-quickstart.md" "MVP quickstart" >}}, {{< repo-link "docs/guides/phase1-demo-packet.md" "Demo packet" >}}, {{< repo-link "docs/guides/read-phase1-evidence-bundle.md" "Evidence bundle guide" >}}, {{< repo-link "plugins/claude-code/README.md" "Plugin README" >}} |
| Runnable examples | Mission JSON, LangChain, LangGraph, AutoGen, browser extension, desktop observe, native host | {{< repo-link "examples/README.md" "Examples index" >}} |
| Protocol docs | Mission Declaration, Delegation Grant, Execution Receipt, EAT profile, Transparency Anchor, Receiver Attestation, Offline Verification Bundle, Verifier Contract, conformance profiles, IDM extension, revocation | {{< repo-link "docs/specs/README.md" "Specs index" >}} |
| Cloud model tests | Real-world governance harnesses for live LLM tool calls through the Ardur proxy; raw per-model fixtures are not shipped in the redacted public tree. Aggregate report path: `python/tests/comprehensive_test_report.json` | {{< repo-link "python/tests/run_cloud_model_test.py" "Run harness" >}} |
| CI and public hygiene | Python 3.10 and 3.13, Go, CodeQL, link-check, secret-scan, format validation, Hugo build | {{< repo-link ".github/workflows/tests.yml" "Tests workflow" >}} |

These are configured-boundary claims. They do not imply visibility into calls
that bypass an adapter, provider-hidden behavior, or side effects below a tool
request. Receipt verification proves the configured issuer signature and hash
linkage. Optional transparency and receiver-attestation profiles add separately
keyed evidence for configured paths, and the packaged offline verifier composes
them into a redacted timeline. These checks still do not prove universal
observation, online revocation freshness, or action-set completeness.

## Bounded Or In Progress

{{< proof-status state="archival" label="Archival media only" source="MEDIA.md" >}}
The current recordings are asciinema `.cast` files. They are useful
product-direction media, but they are not rerunnable public proof until stable
verifier commands and artifact paths land. The current rerunnable Phase 1
evidence path is the no-key JSON bundle, not these archival casts.
{{< /proof-status >}}

{{< proof-status state="hold" label="Not a packaged production release" source="STATUS.md" >}}
PyPI/Homebrew/OCI distribution, broader cluster deployment material, and
rerunnable public proof media are still being hardened.
{{< /proof-status >}}

{{< proof-status state="hold" label="Linux enforcement is a gated development surface" source="docs/coverage-map.md" >}}
The repository contains privileged Linux BPF-LSM and seccomp proof harnesses
with live CI. They are not the cross-platform first-run claim, a production
kernel agent, or evidence that macOS and Windows have equivalent enforcement.
{{< /proof-status >}}

Primary status source: {{< repo-link "STATUS.md" >}}.
