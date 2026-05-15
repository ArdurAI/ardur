# Status

## Capture Boundary

Today, Ardur captures every Claude Code tool-call invocation — file reads
(`Read`), file writes (`Edit`/`Write`), shell command invocations (`Bash`),
web access (`WebFetch`/`WebSearch`), and subagent dispatches (`Task`). Each
invocation is signed (ES256) and chained (SHA-256).

What we do **not** yet capture:

- **Side effects of shell commands.** A `Bash("rm foo")` is recorded as the
  command string; the actual `unlink` syscall is invisible.
- **Subprocess trees** spawned by a tool call (e.g. by `Bash("./run.sh")`).
- **Network connections** initiated by tool-spawned processes.
- **Filesystem changes** outside the typed file tools.
- **Provider-side reasoning, hidden state, server-side tool calls** — out
  of scope by definition for any local tool.

This boundary is intentional and disclosed. The roadmap closes the gap in
phases: v0.2 adds filesystem snapshots within the protected scope; v0.5
adds Linux eBPF kernel-level capture; v1.0 adds macOS Endpoint Security
Framework. See [`docs/coverage-map.md`](docs/coverage-map.md) for the full
audit, [`docs/known-limitations.md`](docs/known-limitations.md) for the
caveat list, and [`ROADMAP.md`](ROADMAP.md) for the phase plan.

## Public Now

- the product category and public intent are defined
- the main repo wedge is narrowed to runtime governance plus verifiable evidence
- the public-facing brand has moved to `Ardur`
- public v0.1 specs are present under `docs/specs/` (Mission Declaration, Delegation Grant, Execution Receipt and EAT profile, Verifier Contract, Conformance Profiles, IDM extension, Revocation)
- curated Python runtime files and tests are present under `python/`, including the Ardur Personal Hub service (`personal_hub.py`), Claude Code hook (`claude_code_hook.py`), telemetry (`claude_code_telemetry.py`), reporting (`claude_code_report.py`), native-messaging host (`ardur_personal_native_host.py`), and `ARDUR.md` profile compiler (`ardur_profile.py`)
- the `ardur` CLI ships subcommands for the protocol path (`issue`, `verify`, `attest`, `start`) and the Personal path (`hub`, `setup`, `status`, `doctor`, `doctor-claude-code`, `uninstall`, `run`, `desktop-observe`, `personal-native-host`, `personal-native-manifest`, `profile init`, `protect claude-code`, `claude-code-hook`, `claude-code-report`)
- the Claude Code plugin is present under `plugins/claude-code/` with `PreToolUse`, `PostToolUse`, `SubagentStart`, and `SubagentStop` hooks plus a smoke script
- curated Go runtime, governance, and operator files are present under `go/`, including a complete AAT credential-attenuation engine with constraint checks, subsumption, JWT issuance/derivation, PoP binding, and full §7 chain verification (49 tests)
- runnable framework examples are present under `examples/`: LangChain, LangGraph, and AutoGen quickstarts; the Ardur Personal browser extension; the Ardur Personal desktop-observe adapter; the Ardur Personal native-messaging host; and the Claude Code plugin pointer. JSON mission examples remain in `examples/missions/`. OpenAI Agents SDK and Google ADK directories are deferred adapter specs
- dedicated Python (3.10 + 3.13) and Go CI workflows run on every push and PR (`.github/workflows/tests.yml`), alongside CodeQL, link-check, secret-scan, format validation, and the Hugo site build
- the Hugo public evidence-site source tree is present under `site/`, with start-here / build / evidence sections that link each public claim back to the source file backing it
- bootstrap and local-validation scripts ship under `scripts/` (`conductor-bootstrap.sh`, `setup-dev.sh`, `check-local.sh`)
- agent-specific public guides live under `docs/agent-instructions/` (Conductor, Codex, Claude, plus a shared contract)
- new technical reference pages live under `docs/reference/` (CLI, Personal Hub HTTP API, `ARDUR.md` profile format)
- selected archival walkthrough recordings are public starter media; a re-runnable proof path lands with the next media drop — see `MEDIA.md`
- a public audit trail is maintained under `docs/audit/`, mirroring the GitHub Code Scanning dismissal record
- cloud model governance tests (`python/tests/test-results/`) prove real-world proxy enforcement with live LLMs across 5 cloud models — 143 tool calls evaluated, 106 adversarial denials, **zero bypasses** (Phase 1) plus 22 programmatic enforcement checks (Phase 2)
- the reference proxy implements all three conformance profiles: Delegation-Core, MIC-State, and MIC-Evidence — all 4 verifier-contract gaps closed (visibility, envelope signature, manifest digest, hidden-hop detection, last_seen_receipts tracking)
- the first tagged release (`v0.1.0`) is published
- the journey-log article series (`docs/articles/`) ships Article 05 (Proof Media That Actually Means Something) and Article 06 (Public Import Discipline) as first-wave entries

## In Progress

- runnable OpenAI Agents SDK and Google ADK adapter lifts to replace the current deferred-spec READMEs
- Codex hooks and Claude Desktop MCP packaging as separate next-cycle integrations
- re-runnable public proof media — recordings made against the public runtime with stable verifier commands and artifact paths
- a regenerated Homebrew formula carrying Python resource stanzas, so non-technical users can install Ardur Personal without a source checkout (tag v0.1.0 exists; the formula and PyPI distribution are next)
- conformance test vectors (`docs/specs/conformance/`) — the v0.1 specs reference them by private layout; they are not yet imported into the public tree
- broader deployment material beyond the SPIRE design surface

## What We Still Need To Resolve

- close the remaining "private layout" notes in the v0.1 specs as their fixtures and companion files land publicly
- replace or re-render any legacy media that still carries internal path or repo-layout assumptions
- keep `VIBAP`, `MCEP`, and related protocol names only where they describe real artifacts, specifications, or protocol lineage
- decide which framework surfaces stay first-screen and which stay secondary as more adapters land

## Not Public Yet

- a packaged distribution on PyPI / Homebrew / OCI suitable for non-technical users (v0.1.0 tag exists; packaging is next)
- full deployment material for cluster, identity, and receipt storage paths
- the full public docs spine (the current set is the public-safe subset)
- benchmark-heavy material
- internal planning, lane, and session artifacts
- Trusted Execution Environment (TEE) attestation as a general hardware-rooted production claim — see `docs/known-limitations.md`

## Honest Launch Rule

Until every imported v0.1 spec has its companion fixtures and the Personal
release candidate has a tagged, packaged installer, the repo continues to say
"opening in phases" rather than implying a complete production distribution is
already present.
