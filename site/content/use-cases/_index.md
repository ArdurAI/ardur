---
title: "Use Cases"
description: "Concrete Ardur use cases, current proof links, and the work that is still coming soon."
weight: 25
maturity: ["public-now", "in-progress", "not-public-yet"]
claim_types: ["runtime-boundary", "integration", "roadmap", "proof-media"]
surfaces: ["docs", "python", "examples", "media"]
frameworks: ["claude-code", "framework-agnostic"]
evidence_levels: ["code-and-doc", "limitation-backed", "archival-media"]
---

Ardur is most useful today for terminal-based coding-agent sessions where a
human wants the agent to stay inside a declared mission and leave behind
verifiable evidence. The first-class public path is Claude Code at the local
tool-call boundary.

## Claude Code With A Mission Profile

**User pain:** a terminal coding assistant can read, search, edit, run shell
commands, and call MCP tools. A plain prompt is not enough when you need a
repeatable boundary like "read this folder, do not edit files, and do not run
commands."

**How Ardur helps today:** `ardur profile init` writes an `ARDUR.md` mission
profile, and `ardur protect claude-code` compiles it into a Mission Passport
for the Claude Code plugin. The plugin checks each `PreToolUse` event against
allowed tools, forbidden tools, resource scope, cwd, and policy backends before
the tool runs.

**Proof links:**

- {{< repo-link "plugins/claude-code/README.md" "Claude Code plugin README" >}}
- {{< repo-link "docs/guides/claude-code-mvp-quickstart.md" "Claude Code MVP quickstart" >}}
- {{< repo-link "docs/guides/read-phase1-evidence-bundle.md" "Phase 1 evidence-bundle guide" >}}
- {{< repo-link "docs/reference/cli.md" "CLI reference" >}}
- {{< repo-link "docs/reference/ardur-md-profile.md" "ARDUR.md profile reference" >}}

**Coming soon:** packaged installation so this path does not require a source
checkout.

## Deny Dangerous Local Tool Calls

**User pain:** when an agent tries to step outside the mission, the useful
behavior is a clear denial before the local action happens, not a note after
the fact.

**How Ardur helps today:** the Claude Code `PreToolUse` hook can return
Claude Code's deny response for disallowed local tool calls. On allowed calls,
Ardur records evidence and leaves Claude Code's normal permission prompts in
charge.

**Proof links:**

- {{< repo-link "plugins/claude-code/README.md" "PreToolUse deny path" >}}
- {{< repo-link "plugins/claude-code/scripts/smoke.py" "Claude Code smoke test" >}}
- {{< repo-link "python/vibap/claude_code_hook.py" "Hook adapter" >}}
- {{< repo-link "python/tests/test_claude_code_hook.py" "Hook tests" >}}

**Coming soon:** filesystem snapshots and deeper operating-system capture so
Ardur can close more of the gap between a tool call and the side effects below
that tool call.

## Keep A Signed Receipt Chain

**User pain:** after a coding-agent session, a reviewer needs more than a chat
transcript. They need to know what tool calls happened, whether they were
permitted or denied, and whether the evidence chain was altered.

**How Ardur helps today:** Claude Code tool events produce signed Execution
Receipts. Each receipt links to the prior receipt by hash, and
`ardur claude-code-report` reads the chain to summarize allow, deny, and
verification outcomes. The current public capture boundary is tool calls, not
provider-side reasoning or every kernel-level side effect.

**Proof links:**

- {{< repo-link "python/vibap/receipt.py" "Receipt chain implementation" >}}
- {{< repo-link "python/vibap/claude_code_report.py" "Claude Code report implementation" >}}
- {{< repo-link "docs/guides/read-phase1-evidence-bundle.md" "How to read a redacted evidence bundle" >}}
- {{< repo-link "docs/coverage-map.md" "Coverage map" >}}
- {{< repo-link "docs/security-model.md" "Security model" >}}

**Available now:** a rerunnable no-key JSON evidence bundle for the Claude Code
MVP path. **Coming soon:** rerunnable public proof media with stable verifier
commands and artifact paths. The current walkthrough media is useful, but it
remains archival.

## Report And Replay A Session

**User pain:** a team wants to review a terminal session after it ends: which
tools ran, where a deny happened, and whether the receipt sequence still
verifies.

**How Ardur helps today:** `ardur claude-code-report` can read the saved
Claude Code receipt chain and emit a human or JSON summary. The demo page shows
the intended review loop: protect a session, let hooks record receipts, then
inspect and verify the chain.

**Proof links:**

- {{< repo-link "docs/reference/cli.md" "ardur claude-code-report" >}}
- {{< repo-link "docs/guides/claude-code-mvp-quickstart.md" "Claude Code quickstart and live demo" >}}
- {{< repo-link "docs/guides/read-phase1-evidence-bundle.md" "Phase 1 no-key evidence reader" >}}
- {{< repo-link "python/tests/test_receipt_hardening.py" "Receipt hardening tests" >}}
- {{< repo-link "python/tests/test_claude_code_hook.py" "Claude Code hook tests" >}}

**Available now:** report and replay verification through the source checkout
and no-key harness. **Coming soon:** public proof recordings that can be
regenerated from the public tree, not just replayed as archived media.

## Keep The Hook Path Fast Enough For Interactive Use

**User pain:** if governance makes every terminal tool call feel slow, users
will turn it off.

**How Ardur helps today:** `ardur protect claude-code` tries to install a
native `PreToolUse` daemon client when a local C compiler is available. The
hook wrapper attempts the daemon path first and falls back to Python handling
when the daemon path is unavailable or invalid.

**Proof links:**

- {{< repo-link "plugins/claude-code/README.md" "Low-latency PreToolUse path" >}}
- {{< repo-link "plugins/claude-code/hooks/pre_tool_use" "PreToolUse wrapper" >}}
- {{< repo-link "python/vibap/claude_code_daemon.py" "Daemon implementation" >}}
- {{< repo-link "python/tests/test_claude_code_hook_latency.py" "Latency tests" >}}

**Coming soon:** clearer packaged defaults for regular users. Benchmark-heavy
claims should stay tied to the relevant tests and release artifacts.

## Coming Soon, Not Shipped Claims

These are roadmap items, not current product claims:

- **Tool-agnostic CLI capture / Linux eBPF:** broader process and kernel-event
  evidence beyond the current Claude Code tool-call boundary.
- **Codex hooks:** a separate coding-agent integration with the same mission
  and receipt discipline, once implemented and tested.
- **Claude Desktop MCP:** packaging for local desktop users through MCP, once
  the public integration is present.
- **Filesystem snapshots:** scoped file-delta evidence to reduce blind spots
  around shell-command and MCP-server side effects.
- **Packaging:** tagged PyPI, Homebrew, or OCI distribution suitable for users
  who should not need to clone the repo.

The honest boundary is intentional: Ardur is not a sandbox, does not see
provider-side reasoning, and does not yet capture every subprocess or
kernel-level side effect. See {{< repo-link "STATUS.md" "Status" >}} and
{{< repo-link "docs/coverage-map.md" "Coverage Map" >}} for the current line.
