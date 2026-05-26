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
| Runtime governance | Python and Go runtime imports, mission passport issuance, verification, receipt paths, governance checks, AAT credential-attenuation engine (constraints, derivation, PoP, chain verification) | {{< repo-link "python/README.md" "Python" >}}, {{< repo-link "go/README.md" "Go" >}} |
| CLI | Protocol and Personal commands including `issue`, `verify`, `attest`, `start`, `hub`, `setup`, `status`, `doctor`, `doctor-claude-code`, `run`, `profile init`, `protect claude-code`, `claude-code-hook`, and `claude-code-report` | {{< repo-link "docs/reference/cli.md" "CLI reference" >}} |
| Ardur Personal | Local Hub service, browser extension, desktop observe adapter, native messaging host | {{< repo-link "docs/guides/ardur-personal-hub.md" "Personal Hub guide" >}} |
| Claude Code | Plugin and hooks for `PreToolUse`, `PostToolUse`, `SubagentStart`, `SubagentStop`; source-checkout MVP quickstart with no-key harness, demo packet, evidence-bundle reader, and live-Claude path | {{< repo-link "docs/guides/claude-code-mvp-quickstart.md" "MVP quickstart" >}}, {{< repo-link "docs/guides/phase1-demo-packet.md" "Demo packet" >}}, {{< repo-link "docs/guides/read-phase1-evidence-bundle.md" "Evidence bundle guide" >}}, {{< repo-link "plugins/claude-code/README.md" "Plugin README" >}} |
| Runnable examples | Mission JSON, LangChain, LangGraph, AutoGen, browser extension, desktop observe, native host | {{< repo-link "examples/README.md" "Examples index" >}} |
| Protocol docs | Mission Declaration, Delegation Grant, Execution Receipt, EAT profile, Verifier Contract, conformance profiles, IDM extension, revocation | {{< repo-link "docs/specs/README.md" "Specs index" >}} |
| Cloud model tests | Real-world governance proof: live LLM tool calls through Ardur proxy with zero denials | {{< repo-link "python/tests/test-results/SUMMARY.md" "Test results" >}} |
| CI and public hygiene | Python 3.10 and 3.13, Go, CodeQL, link-check, secret-scan, format validation, Hugo build | {{< repo-link ".github/workflows/tests.yml" "Tests workflow" >}} |

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

Primary status source: {{< repo-link "STATUS.md" >}}.
