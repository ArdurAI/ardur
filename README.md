# Ardur

Ardur governs AI-agent tool calls that pass through a configured adapter or
proxy. It checks mission, resource, budget, and delegation constraints before
that integration dispatches the call, then emits an issuer-signed,
hash-linked receipt for the decision.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--release-blue)](STATUS.md)
[![Discussions](https://img.shields.io/badge/GitHub-Discussions-181717?logo=github)](https://github.com/ArdurAI/ardur/discussions)

This public repo contains the product intent, research-informed positioning,
public specs, the Python governance runtime, Go packages for eBPF kernel
capture and Kubernetes control-plane components, mission examples, runnable
framework adapters (LangChain, LangGraph, AutoGen), the Ardur Personal Hub
service, the Claude Code plugin and hook, and the public Hugo evidence site.
The current public proof is strongest at those configured tool boundaries. It
does not establish universal agent capture, third-party witnessing,
provider-hidden behavior, or cross-platform kernel enforcement. Re-runnable
proof media, full packaging, and production deployment material are still
being tightened before they are presented as release-ready.

[Research](RESEARCH.md) · [Status](STATUS.md) · [Coverage Map](docs/coverage-map.md) · [Roadmap](ROADMAP.md) · [Media](MEDIA.md) · [Articles](docs/articles/README.md) · [Docs](docs/README.md) · [Reference](docs/reference/README.md) · [Phase 1 Demo Packet](docs/guides/phase1-demo-packet.md) · [Read the Phase 1 Evidence Bundle](docs/guides/read-phase1-evidence-bundle.md) · [Evidence Site Source](site/README.md)

## Verification Snapshot

At the reviewed `dev` tree on 2026-07-09, the current gates were:

| Gate | Verified result |
|---|---|
| Python local matrix with the CI coverage flags (Python 3.13) | 1,363 passed, 32 skipped, 85% coverage |
| Python CI | Python 3.10 and 3.13 passed; lint and wheel smoke passed |
| Go CI | Tests, vet, lint, and vulnerability scan passed |
| Linux enforcement CI | BPF generation plus Go build/vet/race tests, live BPF-LSM kernel smoke, seccomp smoke, and full `ardur run --enforce` seccomp E2E passed |
| Security and release hygiene | CodeQL for Python and Go, secret scanning, formats, links, Hugo, package build, and OCI smoke passed |

These gates verify the checked-in runtime and its configured integration
paths: policy evaluation, fail-closed error handling, signed/hash-linked
receipts, delegation, package contracts, and the explicitly gated Linux
enforcement harnesses. They do **not** prove that Ardur observes calls that
bypass an adapter, provider-hidden actions, every effect below a tool call, or
production readiness on every platform.

The numeric Python result is a dated snapshot, not a permanent badge; the
workflow files under [`.github/workflows/`](.github/workflows/) are the current
source of truth. Historical model/adversarial aggregates remain at
`python/tests/comprehensive_test_report.json`, but they are not presented here
as evidence for the current tree.

## First-Run Paths

Start with one of these source-checkout paths. All three avoid a provider API
key; the local demo additionally avoids manual bearer-token and Docker setup.

### Local governance loop

```bash
git clone https://github.com/ArdurAI/ardur.git && cd ardur
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e python/
python scripts/run-no-key-mvp-demo.py
```

This temporary loopback-only demo reaches a `PERMIT`, a `DENY`, and a locally
verified signed attestation. It disables TLS and bearer auth only for the child
process; do not use it as a production launch command. See the
[no-key MVP guide](docs/guides/no-key-mvp-demo.md) for the boundary and timing.

### Fresh-user evidence bundle

```bash
python3 scripts/run-rwt-phase1-fresh-user.py \
  --expected-origin-dev "$(git rev-parse --short=12 origin/dev)" \
  --output-dir /tmp/ardur-rwt-phase1
```

This runs the repeatable no-key install, profile, hook allow/deny, receipt-chain,
and redaction checks. Read the [Claude Code MVP quickstart](docs/guides/claude-code-mvp-quickstart.md)
for the expected bundle result and the optional live-Claude path.

### Authenticated Docker evaluator

`make demo` plus [`scripts/verify-mvp.sh`](scripts/verify-mvp.sh) is the
authenticated Docker path. Configure `ARDUR_API_TOKEN` before starting it; the
[MVP evaluator guide](docs/mvp-evaluator-guide.md) contains the tested,
copy-paste authenticated lifecycle. CI starts this full stack from fresh named
volumes and requires the health, `PERMIT`, `DENY`, and signed-attestation
lifecycle to pass before the aggregate test gate succeeds.

## Fastest MVP Path: Claude Code

Start with the source-checkout walkthrough in
[`docs/guides/claude-code-mvp-quickstart.md`](docs/guides/claude-code-mvp-quickstart.md).
It gives three bounded paths:

- a **60-second deliberate deny proof** using
  `python3 scripts/run-claude-deny-demo.py`; it exercises the real local hook
  adapter, verifies a signed violation receipt, checks an unchanged canary, and
  removes all temporary state without contacting an LLM provider;
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

> **Capture boundary today (v0.1):** Ardur signs the Claude Code tool-call
> events delivered to its installed hooks. Side effects below the tool
> boundary — subprocess trees,
> kernel events, network connections initiated by tool-spawned processes —
> are not yet captured; the roadmap closes that gap in v0.2 (filesystem
> snapshots), v0.5 (Linux eBPF), and v1.0 (macOS Endpoint Security
> Framework). See [`docs/coverage-map.md`](docs/coverage-map.md) for the
> precise per-tool audit.

## Why Ardur

Many agent stacks can log what happened. A configured Ardur adapter can stop an
out-of-scope tool request before that adapter dispatches it. Its receipts let a
reviewer verify the issuer signature and hash linkage later, including what the
runtime allowed, denied, or left unknown.

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
- public v0.1 specs for mission declarations, execution receipts, verifier contracts, conformance profiles, and related protocol surfaces, plus the v0.2 Execution Receipt hardening profile with versioned RFC 8785 payloads and legacy verification
- Python governance runtime under `python/`; Go eBPF/K8s packages and a JWT AAT credential-attenuation implementation under `go/` (CWT integer-key mapping remains incomplete)
- the Ardur Personal Hub service and CLI under `python/vibap/` (`ardur hub`, `ardur setup`, `ardur status`, `ardur protect claude-code`, `ardur profile init`, `ardur doctor-claude-code`)
- the Claude Code plugin under `plugins/claude-code/` with `PreToolUse`, `PostToolUse`, `SubagentStart`, and `SubagentStop` hooks emitting signed receipts
- runnable framework adapters under `examples/`: LangChain, LangGraph, AutoGen, browser extension, desktop-observe, native-host, and offline/no-key OpenAI Agents SDK and Google ADK fixtures. JSON mission examples remain in `examples/missions/`
- dedicated Python (3.10 + 3.13) and Go CI under `.github/workflows/tests.yml`, including the offline examples-smoke regression in `python/tests/test_examples_smoke.py` and a required fresh-volume Compose demo lifecycle, plus CodeQL, link-check, secret-scan, format validation, and the Hugo build
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

- live-provider OpenAI Agents SDK and Google ADK wrapper evidence as a separate, opt-in path beyond the current no-key fixture examples
- Codex hooks and Claude Desktop MCP packaging as separate next-cycle integrations
- re-runnable proof media — recordings made against the public runtime with stable verifier commands and artifact paths, replacing the current archival walkthrough casts
- a tagged release with a regenerated Homebrew formula carrying Python resource stanzas, so non-technical users can install Ardur Personal without a source checkout
- broader deployment material (cluster, identity, receipt storage) past the current SPIRE design surface

## Integrations

Ardur sits between an AI agent and the tools it calls — so the integration story is which agent frameworks, model providers, policy engines, and identity systems Ardur plugs into.

| Layer                | In repo now | Still pending public validation |
|----------------------|-------------|---------------------------------|
| **Agent framework**  | JSON mission examples; Claude Code plugin; runnable LangChain, LangGraph, AutoGen, browser, desktop-observe, native-host, and offline/no-key OpenAI Agents SDK and Google ADK fixture examples | live-provider wrappers and more runnable framework adapters |
| **Model provider**   | provider-agnostic tool boundary in the runtime design | local Ollama quickstarts and live-provider examples |
| **Policy engine**    | native checks, forbid-rules, Cedar bridge, JWT AAT constraint engine (13 types) | AAT CWT integer-key mapping, OPA, and broader Biscuit datalog examples |
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
