---
title: "Work In Progress"
description: "Active work, ambitions, audiences, and boundaries without presenting future work as shipped."
weight: 80
maturity: ["in-progress"]
claim_types: ["roadmap", "status", "integration", "proof-media", "deployment"]
surfaces: ["docs", "examples", "media", "deploy"]
frameworks: ["framework-agnostic", "openai-agents-sdk", "google-adk", "kubernetes", "spire"]
evidence_levels: ["limitation-backed", "doc-and-manifest"]
---

Ardur's ambition is to make runtime governance for AI agents inspectable,
composable, and hard to misrepresent. The public repo is moving toward that in
phases.

## Active Work

No row below is a shipped production claim. The status label says how the public
site should treat that work today.

| Workstream | Why it matters | Public status |
|---|---|---|
| OpenAI Agents SDK adapter | Expands coverage beyond current runnable examples | {{< status-pill state="planned" label="planned" >}} |
| Google ADK adapter | Expands framework coverage | {{< status-pill state="planned" label="planned" >}} |
| Codex hooks | Brings the Claude Code-style lifecycle idea to another coding-agent surface | {{< status-pill state="planned" label="planned" >}} |
| Claude Desktop MCP packaging | Gives local users a cleaner install path | {{< status-pill state="planned" label="planned" >}} |
| Rerunnable proof media | Replaces archival casts with public-runtime recordings | {{< status-pill state="in-progress" label="in progress" >}} |
| Conformance vectors | Lets spec readers verify expected behavior from checked-in fixtures | {{< status-pill state="not-public-yet" label="not public yet" >}} |
| Packaged release | Makes Ardur Personal usable without a source checkout | {{< status-pill state="in-progress" label="in progress" >}} |
| Deployment hardening | Moves beyond SPIRE design surface toward complete cluster walkthroughs | {{< status-pill state="in-progress" label="in progress" >}} |

## Audience

- **Framework builders:** integration patterns and adapter specs.
- **Coding-agent users:** local Hub, Claude Code plugin, browser, desktop, and
  native-host paths.
- **Security reviewers:** claim ledger, denial semantics, specs, and media
  limitations.
- **Platform engineers:** deployment manifests, SPIRE work, and hardening gaps.
- **Contributors:** tests, docs, examples, and source-backed site generation.

## Ambition

- Give agent builders a mission boundary that can be enforced before tool calls.
- Give security reviewers signed evidence rather than narrative claims.
- Give local users a Personal Hub that can govern coding agents, browser
  observations, desktop observations, and CLI commands through one authority.
- Keep integrations thin so policy and receipts stay centralized.

## Boundaries

Ardur does not currently claim production packaging, full deployment maturity,
general hardware-rooted TEE attestation, or rerunnable public proof media.
Those are roadmap items until the repo contains the evidence and commands.
