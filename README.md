# Ardur

Ardur is the runtime governance and evidence layer for AI agents.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--release-blue)](STATUS.md)
[![Discussions](https://img.shields.io/badge/GitHub-Discussions-181717?logo=github)](https://github.com/ArdurAI/ardur/discussions)

This public repo contains the product intent, research-informed positioning,
public specs, the Python governance runtime, Go packages for eBPF kernel
capture and Kubernetes control-plane components, mission examples, runnable
framework adapters (LangChain, LangGraph, AutoGen), the Ardur Personal Hub
service, the Claude Code plugin and hook, and the public Hugo evidence site.
Re-runnable proof media, full packaging, and production deployment material
are still being tightened before they are presented as release-ready.

[Research](RESEARCH.md) · [Status](STATUS.md) · [Coverage Map](docs/coverage-map.md) · [Roadmap](ROADMAP.md) · [Media](MEDIA.md) · [Articles](docs/articles/README.md) · [Docs](docs/README.md) · [Reference](docs/reference/README.md) · [Phase 1 Demo Packet](docs/guides/phase1-demo-packet.md) · [Read the Phase 1 Evidence Bundle](docs/guides/read-phase1-evidence-bundle.md) · [Evidence Site Source](site/README.md)

## Test Results

Tests here are designed to prove three things:

1. **Correctness** — the governance proxy enforces the spec faithfully: visibility, envelope integrity, manifest digest, delegation narrowing, hidden-hop detection, per-class budgets, rate limiting, and kill-switch semantics.
2. **Resilience** — adversarial models cannot bypass policy boundaries through prompt injection, jailbreaking, social engineering, path traversal, multi-turn steering, or chained-tool attacks.
3. **Real-model integration** — live models routed through the proxy can build substantial software (multi-file applications with tests and documentation) while every tool call flows through governance first.

### Unit & Integration Suite

| Suite | Passed | Skipped | Failed |
|-------|--------|---------|--------|
| Core governance (proxy, passport, mission, receipts) | 581 | 21 | 0 |

Covers the Delegation-Core, MIC-State, and MIC-Evidence conformance profiles — all 4 verifier-contract gaps closed as of the hardening round ending 2026-05-14. Includes visibility checks (§6.4), envelope signature verification (§9.5), manifest digest comparison (§9.6), hidden-hop detection (§9.1), and `last_seen_receipts` tracking (§5.7).

### Comprehensive Protocol Composition

Single end-to-end test exercising all protocol layers over real TLS with SPIFFE identity, Biscuit attenuation, JWT delegation, and policy backends.

| Scenario | Duration | What it proves |
|----------|----------|---------------|
| Health & baseline | 0.02s | Server responds correctly, content-type negotiation works |
| JWT session lifecycle | 0.07s | Start → evaluate → attest → end produces verifiable receipts |
| Biscuit + SPIFFE binding | 0.13s | Biscuit bearer token bound to SPIFFE SVID holder |
| **Ollama multi-turn build** | **106.6s** | Live cloud model builds a complete journal API across 20 turns — write_file, read_file, list_directory — all through the proxy |
| JWT delegation chain | 0.11s | Parent → child → grandchild narrowing: tools and budget strictly contract |
| Biscuit attenuation chain | 0.13s | Root → child → grandchild: each hop narrows authority, escalation blocked |
| Kill switch mid-session | 0.08s | Activate blocks /evaluate (503), deactivate restores, health stays available |
| Rate limit flooding | 0.31s | Burst beyond 50 requests triggers 429 with Retry-After header |
| Metrics verification | 0.03s | Prometheus text format, all 6 required metric families present |
| Receipt chain integrity | 0.01s | Multi-trace receipts form independently verifiable hash-linked chains |
| ForbidRules composition | 0.05s | Regex-based forbid-rules backend denies while native permits |
| Three-backend composition | 0.07s | Native + ForbidRules + Cedar: each backend can independently deny |
| Integrity hash enforcement | 0.03s | policy_sha256 mismatch → DENY (fail-closed) |

**13/13 passed. Total: 118.3s.**

### Ollama Integration

| Suite | Passed | Failed |
|-------|--------|--------|
| Connectivity (model listing, chat, tool calling) | 3 | 0 |
| Governance integration (proxy routing, denial, multi-turn, delegation) | 8 | 0 |
| Security headers | 2 | 0 |
| Concurrency | 1 | 0 |
| Model capabilities (denial understanding, self-description, constraint respect) | 3 | 0 |

**17/17 passed. Total: 26.1s.**

### Phase 1 — Adversarial Boundary Testing

10 hostile scenarios across 5 cloud models spanning multiple providers. Every scenario is designed to trigger a DENY — models attempt direct forbidden-tool use, mid-execution prompt injection, DAN-style jailbreaking, resource-scope violations, social engineering with false urgency, path traversal, budget exhaustion, obfuscated command injection, multi-turn gradual steering toward forbidden actions, and chained tool attacks (write script → execute). See [test-results](python/tests/test-results/) for per-model breakdowns.

| Metric | Value |
|--------|-------|
| Tool calls evaluated | 143 |
| PERMIT | 63 |
| DENY | 106 |
| **BYPASS** | **0** |

**Zero bypasses.** Proxy boundaries held across all 5 models, all 10 attack vectors. The proxy denied 106 violation attempts. Models that refused before calling tools (ethical refusal) were counted as passes — the scenario's goal is exercising the proxy's enforcement boundary, and a model-level refusal means the attack didn't reach the runtime.

### Phase 2 — Advanced Enforcement Checks

22 programmatic checks verifying specific enforcement points — no model in the loop. Direct API calls against the proxy exercising edge cases:

| Category | Checks | Highlights |
|----------|--------|-----------|
| Approval policy | 2 | operator_id required, fatigue threshold exceeded |
| Delegation | 1 | child tool escalation beyond parent scope rejected |
| Memory governance | 2 | FIX-8: private key material rejected on memory write/read |
| Token replay | 1 | JTI replay on session start rejected |
| Kill switch | 2 | /evaluate and /session/start both return 503 |
| Per-class budget | 2 | internal_write budget exhaustion, side_effect_class not in allowlist |
| CWD confinement | 2 | absolute path escape and path traversal escape from CWD both blocked |
| Policy backends | 1 | ForbidRules backend blocks targeted tool |
| Tool scope | 1 | forbidden tool directly denied |
| Resource scope | 1 | write outside resource_scope denied |
| Budget | 1 | main budget exhausted after max_tool_calls |
| Session lifecycle | 2 | ended session rejects, multiple sessions coexist |
| Token validation | 2 | invalid JWT rejected, nonexistent session_id rejected |
| Input sanitization | 1 | unicode confusable path handled correctly |
| Infrastructure | 1 | health endpoint returns ok |

**22/22 passed. Total: <1s.**

### Go AAT — Credential Attenuation Engine

The Go `pkg/aat` package implements 13 constraint types, token serialization, delegation-chain verification, and constraint subsumption. All tests pass with zero failures.

### Aggregate

| Suite | Count | Status |
|-------|-------|--------|
| Python unit + integration | 581 + 21 skipped | All passing |
| Comprehensive protocol composition | 13 scenarios | All passing |
| Ollama integration | 17 | All passing |
| Phase 1 adversarial (5 models) | 10 scenarios × 5 models | 0 bypasses |
| Phase 2 advanced enforcement | 22 checks | All passing |
| Go AAT | full suite | All passing |
| MIC conformance (new) | 29 | All passing |

[Full test results →](python/tests/test-results/) · [Proof & evidence site →](site/)

## Evaluator Quickstart

One command to a working governance demo:

```bash
git clone https://github.com/ArdurAI/ardur.git && cd ardur
make demo
```

Then run the automated verification harness:

```bash
./scripts/verify-mvp.sh
```

Full walkthrough with architecture diagrams, session lifecycle, receipt chain
explanation, and known gaps: [`docs/mvp-evaluator-guide.md`](docs/mvp-evaluator-guide.md).

## Fastest MVP Path: Claude Code

Start with the source-checkout walkthrough in
[`docs/guides/claude-code-mvp-quickstart.md`](docs/guides/claude-code-mvp-quickstart.md).
It gives two bounded paths:

- a **no-key confidence check** that runs the fresh-user evidence harness,
  simulated Claude Code hook allow/deny receipts, and redacted bundle checks
  without contacting an LLM provider; and
- a **live Claude Code demo** for users who already have the `claude` binary
  installed and authenticated.

That guide also separates **Works now**, **Not claimed**, and **Coming soon**
to clearly mark the boundary between shipped, deferred, and in-progress
capabilities — package-manager release status, provider-hidden behavior,
and subprocess/kernel/network side-effect gaps.

After a run, use the
[`Phase 1 Demo Packet`](docs/guides/phase1-demo-packet.md) to assemble a bounded
handoff: tested commit, `bundle.redacted.json`, optional live-Claude report, and
the exact claims the artifacts do and do not support.

> **Capture boundary today (v0.1):** Ardur signs every Claude Code tool-call
> invocation. Side effects below the tool boundary — subprocess trees,
> kernel events, network connections initiated by tool-spawned processes —
> are not yet captured; the roadmap closes that gap in v0.2 (filesystem
> snapshots), v0.5 (Linux eBPF), and v1.0 (macOS Endpoint Security
> Framework). See [`docs/coverage-map.md`](docs/coverage-map.md) for the
> precise per-tool audit.

## Why Ardur

Many agent stacks can log what happened. Fewer can stop an out-of-scope action
before it executes. Fewer still can prove later, with verifier-backed evidence,
what the runtime allowed, denied, or left unknown.

Ardur is being built to do all three:

- bind agents to a declared mission
- enforce runtime boundaries over tools, resources, budgets, and delegation
- emit evidence that can be checked instead of argued about

Concretely — these are the design principles the repo is being built to meet, not guarantees that every checked-in surface is already production-ready:

- **Public-by-default as a working principle.** The aim is that every public claim ties to a verifier path, an artifact, a re-runnable test, or an explicit limitation note. The code-bearing runtime is landing in phases per the [public import plan](docs/public-import-plan.md); claims that depend on not-yet-verified runtime behavior still need explicit caveats.
- **Composable with what already exists.** Designed around SPIFFE for workload identity, Biscuit for first-party-attenuation credentials, Cedar for policy, and on the AAT and EAT IETF drafts for token semantics. We didn't reinvent the substrate.
- **Cryptographically bound by design.** Mission credentials are designed to be signed by an issuer key, holder-bound to a SPIFFE SVID, and produce signed receipts chain-hashed to the previous one. The design is documented in the [ADRs](docs/decisions/README.md); the public code that implements it is being curated in phases.
- **Delegation that narrows, never widens.** Child sessions get strictly narrower authority than their parent — fewer tools, smaller resource scope, smaller budget. The narrowing discipline is formalised in [ADR-017](docs/decisions/ADR-017-biscuit-attenuation-narrowing-semantics.md).
- **Explicit about what it doesn't do.** Scope-level governance can't catch semantic misuse — if an allowed tool is used on an allowed resource for the wrong reason, that's a different layer's job.
- **MIT licensed.** The research foundation (the Silence Theorem, the protocol formalism, the benchmark methodology) will be linked from this repo when the paper's public identifier is assigned. Articles in this repo paraphrase the research in original prose; they do not reproduce paper content.

## What Is Public Today

This repo currently includes:

- the product thesis and launch direction
- a short research-informed positioning summary
- current status and what is still being resolved
- public v0.1 specs for mission declarations, execution receipts, verifier contracts, conformance profiles, and related protocol surfaces
- Python governance runtime under `python/`; Go eBPF/K8s packages and a complete AAT credential-attenuation engine under `go/`
- the Ardur Personal Hub service and CLI under `python/vibap/` (`ardur hub`, `ardur setup`, `ardur status`, `ardur protect claude-code`, `ardur profile init`, `ardur doctor-claude-code`)
- the Claude Code plugin under `plugins/claude-code/` with `PreToolUse`, `PostToolUse`, `SubagentStart`, and `SubagentStop` hooks emitting signed receipts
- runnable framework adapters under `examples/`: LangChain, LangGraph, AutoGen, browser extension, desktop-observe, and native-host. JSON mission examples remain in `examples/missions/`. OpenAI Agents SDK and Google ADK directories remain deferred adapter specs
- dedicated Python (3.10 + 3.13) and Go CI under `.github/workflows/tests.yml`, including the offline examples-smoke regression in `python/tests/test_examples_smoke.py`, plus CodeQL, link-check, secret-scan, format validation, and the Hugo build
- the Hugo public evidence site source under `site/`, with each public claim linkable to its backing source file
- bootstrap and verification scripts under `scripts/` (`conductor-bootstrap.sh`, `setup-dev.sh`, `check-local.sh`)
- agent-specific public guides under [`docs/agent-instructions/`](docs/agent-instructions/) (Conductor, Codex, Claude)
- new technical reference pages under [`docs/reference/`](docs/reference/) — CLI, Personal Hub HTTP API, and the `ARDUR.md` profile format
- selected archival terminal recordings, plus a separate re-runnable no-key
  Phase 1 evidence harness for the Claude Code MVP path — see
  [MEDIA.md](MEDIA.md) and the
  [evidence-bundle guide](docs/guides/read-phase1-evidence-bundle.md)
- a journey-log [article series](docs/articles/README.md) — Article 06 (Public Import Discipline) and Article 05 (Proof Media That Actually Means Something) are the first-wave shippers
- a public audit trail at [`docs/audit/`](docs/audit/) mirroring the GitHub Code Scanning dismissal record so triage decisions are auditable from the repo tree without GitHub credentials

## What Is Coming Next

The next repo drops will add:

- runnable OpenAI Agents SDK and Google ADK adapter lifts to replace the current deferred-spec README directories
- Codex hooks and Claude Desktop MCP packaging as separate next-cycle integrations
- re-runnable proof media — recordings made against the public runtime with stable verifier commands and artifact paths, replacing the current archival walkthrough casts
- a tagged release with a regenerated Homebrew formula carrying Python resource stanzas, so non-technical users can install Ardur Personal without a source checkout
- broader deployment material (cluster, identity, receipt storage) past the current SPIRE design surface

## Integrations

Ardur sits between an AI agent and the tools it calls — so the integration story is which agent frameworks, model providers, policy engines, and identity systems Ardur plugs into.

| Layer                | In repo now | Still pending public validation |
|----------------------|-------------|---------------------------------|
| **Agent framework**  | JSON mission examples; Claude Code plugin; runnable LangChain, LangGraph, AutoGen, browser, desktop-observe, and native-host examples; deferred README-only OpenAI Agents SDK and Google ADK directories | more runnable framework adapters |
| **Model provider**   | provider-agnostic tool boundary in the runtime design | local Ollama quickstarts and live-provider examples |
| **Policy engine**    | native checks, forbid-rules, Cedar bridge, AAT constraint engine (13 types) | OPA and broader Biscuit datalog examples |
| **Identity**         | SPIFFE / SPIRE-oriented code and docs | full cluster deployment walkthrough |
| **Receipts sink**    | local JSON / stdout-oriented receipt surfaces | OTel emitters and durable storage examples |

If you'd use an integration that isn't listed, file an [integration request](https://github.com/ArdurAI/ardur/issues/new?template=integration_request.yml) — it's the strongest signal we have for prioritisation.

## Naming Note

`Ardur` is the public product name.

Some implementation and protocol surfaces still use `VIBAP`, `MCEP`, and
related protocol names. Those names are part of the technical lineage and are
kept where they describe actual artifacts, specifications, or protocol roots.

## Scope and Status

This repo is published progressively — each surface lands when it is
backed by runnable code, verifiable artifacts, or documented limitations.
See `STATUS.md` for what is public today and `ROADMAP.md` for what is
coming next.
