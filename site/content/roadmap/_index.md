---
title: "Roadmap"
description: "A staged view of what works now, what is coming soon, and what is not public yet."
weight: 70
maturity: ["public-now", "in-progress"]
claim_types: ["status", "roadmap", "deployment", "integration", "proof-media"]
surfaces: ["docs", "examples", "media", "deploy", "python"]
frameworks: ["framework-agnostic", "claude-code", "kubernetes", "spire", "openai-agents-sdk", "google-adk"]
evidence_levels: ["code-and-doc", "doc-and-manifest", "archival-media", "limitation-backed"]
---

## Public Now

- Runtime governance core in Python and Go.
- Ardur Personal Hub, CLI, Claude Code plugin, and local adapter surfaces.
- Claude Code `PreToolUse` / `PostToolUse` / subagent hooks with signed
  receipt chains and `ardur claude-code-report`.
- Low-latency Claude Code `PreToolUse` daemon-client path when the local
  compiler and daemon are available, with Python fallback.
- Runnable LangChain, LangGraph, AutoGen, browser extension, desktop observe,
  and native-host examples.
- Public v0.1 specs, ADRs, CI workflows, agent instructions, articles, and
  source-backed Hugo site.

## Coming Soon

These are planned or in-progress items, not shipped claims:

| Workstream | Current public status | Evidence boundary |
|---|---|---|
| Tool-agnostic CLI capture / Linux eBPF | Coming soon | Current public capture is Claude Code tool calls, not kernel-level process or network events. |
| Filesystem snapshots | Coming soon | Current public capture does not see file changes caused below a shell command or MCP server. |
| Codex hooks | Coming soon | Not first-class in the current public release candidate. |
| Claude Desktop MCP packaging | Coming soon | Not first-class in the current public release candidate. |
| Tagged packaging | Coming soon | PyPI, Homebrew, or OCI distribution suitable for regular users is not public yet. |
| Rerunnable proof media | In progress | Current casts are archival until stable verifier commands and artifact paths land. |
| OpenAI Agents SDK and Google ADK adapter lifts | In progress | Current directories are deferred adapter specs rather than runnable examples. |
| Broader deployment material | In progress | Current deployment evidence is useful SPIRE/Helm material, not a production-complete walkthrough. |

## Not Public Yet

- PyPI, Homebrew, or OCI distribution suitable for non-technical users.
- Production-complete cluster, identity, and receipt-storage walkthroughs.
- Hardware-rooted TEE production claims.
- Benchmark-heavy material and internal session artifacts.

Primary sources: {{< repo-link "ROADMAP.md" >}}, {{< repo-link "STATUS.md" >}},
and {{< repo-link "docs/coverage-map.md" >}}.
