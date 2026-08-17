# Status

## Capture Boundary

Today, an installed Ardur Claude Code hook records the tool-call events Claude
Code delivers to that hook — file reads (`Read`), file writes (`Edit`/`Write`),
shell command invocations (`Bash`), web access (`WebFetch`/`WebSearch`), and
subagent dispatches (`Task`). Each observed invocation is signed (ES256) and
chained (SHA-256). Ardur does not claim visibility into calls that bypass the
hook or provider-hidden actions.

`ardur run -- <cli>` additionally captures zero-privilege host-observer
process-lifecycle evidence for any CLI launch: the root process's PID, command,
`run_command` (the actual argv when adapter wrapping transforms it before
launch, omitted when identical), `cwd` (absolute working directory),
`duration_budget_s` (the caller-set time budget, omitted when not set),
started-at timestamp, wall-clock duration, exit code, exit signal, and CPU/memory
usage (`cpu_user_s`/`cpu_system_s` user/system CPU time and `peak_rss_bytes` peak
resident set size, all via POSIX `getrusage(RUSAGE_CHILDREN)` delta around
`proc.wait()`, platform-normalised to bytes). It also enumerates descendant
processes recursively (direct children, grandchildren, etc. — PID, command,
started-at, wall-clock duration, depth, parent_pid; child exit codes are
best-effort and may be null when a child exits between snapshot and inspection).
This is recorded as `capture_tier=host-observer` and works on macOS and Linux
without any host plugin API dependency or kernel daemon. It captures a
point-in-time snapshot of the root process and its descendant tree — not
real-time exec/fork event streams, syscalls, file/network effects, or
provider-side actions — so consumers never mistake it for full process-tree
lifecycle capture (which requires eBPF daemon correlation).

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

Each observed tool call results in a five-state Decision: `PERMIT`,
`DENY`, `VIOLATION`, `INSUFFICIENT_EVIDENCE`, or `UNKNOWN`. Only `PERMIT`
allows execution; all others block the call (fail-closed discipline).
`INSUFFICIENT_EVIDENCE` records a transient operational failure (state file
corrupted, approval operator unreachable) — might be retried. `UNKNOWN`
records a structural observation gap where the activity is outside Ardur's
capture boundary — the honest "I cannot know what happened" outcome. Both
fail-closed as `DENY` on the receipt. See [`docs/security-model.md`](docs/security-model.md) for the
full taxonomy.

An opt-in Linux `ardur-kernelcaptured --agent-recognition` preview now admits
exec events whose exact 15-byte-or-shorter Linux `comm` or bounded
successful-exec basename matches the embedded `claude`, `codex`, `gemini`, or
`kimi` registry. It reports low-confidence, observe-only candidates and never
writes an unrouted candidate into governed session evidence. It emits the
basename but not its parent path and does not emit argv, hashes, uid,
environment, or file content. It does not attest or enforce. A versioned,
sanitized v0.2 corpus keeps 28 exact-name samples separate from eight synthetic
native/launcher content transitions. The gate requires at least 0.90
name-only supported-shape recall, zero name-only hard-negative false positives,
8/8 reviewed content transitions, independent launcher-interpreter inputs, and
zero mismatch confidence promotions.
Its deterministic report includes sample counts, Wilson intervals, stable error
IDs, and exact corpus/name-registry/content-registry digests; these are
maintained-corpus results, not population accuracy, provenance, or identity
assurance.

Operators can now add a daemon-owned executable fingerprint registry to that
opt-in preview. A fixed worker pool binds recognized PIDs with pidfds. Native
candidates hash bounded regular files opened through `/proc/<pid>/exe`.
Script-backed candidates use a separately loaded, non-enforcing BPF-LSM hook to
capture the original object's device, inode, mount ID, and link state; mutable
cmdline is only a bounded locator, opened below the process root and accepted
only after exact object-identity equality. Unsupported launcher observation
fails low without breaking native matching or lifecycle capture. Saturation,
denial, exit, unsupported kernel/filesystem, missing identity/locator, locator
mismatch, interpreter denial, argv/size/deadline limits, digest mismatch, and
success remain explicit health outcomes; contained worker or observer failures
are counted as worker unavailability, never success. A match raises the
observation only to `medium` heuristic content evidence; it is not provenance,
attestation, or authorization. No computed digest, full host path, argv,
environment, or file content is exposed, and no fingerprint cache is used.

The opt-in recognition preview now also has a bounded real-Linux AB/BA overhead
harness. It records raw paired wall observations, daemon thread-group CPU,
peak RSS, authenticated health, and exclusive lifecycle/classification/
fingerprint ledgers for low, sustained, and storm profiles. The required CI
profile uses at least 20 measured pairs after warm-up and fails closed on
missing counters, loss, rejection, unavailable fingerprint work, schema drift,
or digest mismatch once a reviewed target-runner budget is present. Its result
is host-specific observer-effect evidence, not a universal performance claim.

The Linux kernel-capture daemon now publishes its BPF policy-map handle set and
`bpf_lsm` tier as one synchronized lifecycle transition. Every map operation,
health-tier read, withdrawal, and close boundary uses the same mutex; teardown
withdraws the tier and map reachability only after in-flight users drain, then
closes the handles. A readiness timeout commits seccomp under the same lock, so
a late BPF load cannot replace the selected fallback. Mid-run guard loss still
degrades honestly to `none`; automatic BPF-to-seccomp failover is not claimed.

The Python Biscuit session path now accepts JWT-SVID holder binding only from
server-owned Biscuit issuer-key, trust-bundle, and audience configuration. A
configured binding is mandatory for every Biscuit presentation; per-call
issuer keys and caller-supplied JWKS, trust-domain, and audience fields cannot
select the verifier's authority. Only SPIFFE bundle keys marked
`use=jwt-svid` can verify the peer, and `svid_bound=true` is recorded only after
signature, audience, trust-domain, and holder-ID checks. JWT-SVID remains a
replayable bearer credential, so this does not claim complete replay prevention.

The offline `ardur evidence correlate` command can now verify a receipt journal
and compare it with operator-supplied normalized, Tetragon, or Falco JSONL. It
does not deploy a sensor, authenticate imported JSON, or turn missing alerts
into proof of no activity. This improves inspection without changing the
automatic capture boundary above.

The detached `ardur telemetry export` command verifies the signed receipt
chain before projecting redacted governance events to local JSONL or OTLP/HTTP
JSON traces and logs. It exports receipt/parent linkage, signed decisions,
policy source/rule labels, reason codes, budget state, and bounded risk
classifications. It never exports raw prompts, tool arguments, targets, paths,
or policy-reason prose by default. This is a one-shot connector, not a hosted
collector, SIEM, dashboard, delivery guarantee, or vendor-specific integration.
Actor and verifier IDs are signature-covered receipt claims; the exporter does
not validate a SPIFFE SVID or bind the receipt signer to workload identity, and
reports that boundary in JSONL and OTLP.

The Linux governance-overhead harness now provides a schema-validated PR smoke
and manual stress profile. It measures configured governance paths and optional
operator-supplied paired commands; it does not establish universal overhead or
complete sensor coverage.

## Public Now

- the product category and public intent are defined
- the main repo wedge is narrowed to runtime governance plus verifiable evidence
- the public-facing brand has moved to `Ardur`
- public v0.1 specs are present under `docs/specs/` (Mission Declaration, Delegation Grant, Execution Receipt and EAT profile, Verifier Contract, Conformance Profiles, IDM extension, Revocation); the draft-10-pinned DRP profile now emits RFC 8785/P-256 Authorization Objects and fail-closed verifies full transitive chains against external signer, instruction, finite-universe, log, revocation, and optional receipt-chain context while enforcing concrete resource/class/cwd bounds, with a portable seven-scenario implementation self-test bundle and deterministic CI report but no IETF/independent conformance claim; the v0.2 Execution Receipt hardening profile adds versioned RFC 8785 action receipts, legacy verification, and a signed session-final receipt-chain/kernel-integrity binding; the v0.1 transparency-anchor sidecar adds pending-state honesty plus offline Rekor v1 and separately keyed self-hosted inclusion verification; the v0.1 receiver-attestation envelope adds a separately keyed MCP shim, public golden fixture, and two-signature offline verification; the v0.1 Offline Verification Bundle composes full chains and sidecars into redacted CLI/JSON/static HTML reports with separate trust roots
- curated Python runtime files and tests are present under `python/`, including the Ardur Personal Hub service (`personal_hub.py`), Claude Code hook (`claude_code_hook.py`), Claude telemetry/reporting (`claude_code_telemetry.py`, `claude_code_report.py`), Gemini CLI local-only hook fixture/reporting (`gemini_cli_hook.py`), Codex app-server local host-event fixture/reporting (`codex_app_server_fixture.py`), static non-executing tool-server preflight scanner (`tool_preflight.py`), native-messaging host (`ardur_personal_native_host.py`), and `ARDUR.md` profile compiler (`ardur_profile.py`)
- the `ardur` CLI ships subcommands for the protocol path (`issue`, `verify`, `evidence correlate`, `telemetry export`, `anchor`, `drp-profile-fixture`, `receiver-attestation-fixture`, `offline-verification-fixture`, `attest`, `start`) and the Personal path (`hub`, `setup`, `status`, `doctor`, `doctor-claude-code`, `uninstall`, `run`, `desktop-observe`, `personal-native-host`, `personal-native-manifest`, `profile init`, `protect claude-code`, `claude-code-hook`, `claude-code-report`, `gemini-cli-fixture`, `gemini-cli-hook`, `gemini-cli-report`, `codex-app-server-fixture`, `codex-app-server-event`, `codex-app-server-report`, `preflight tool-server`); the wheel also exposes `ardur-verify` as the no-service offline verifier and `ardur-drp-fixtures` as the portable DRP implementation-fixture runner
- the Claude Code plugin is present under `plugins/claude-code/` with `PreToolUse`, `PostToolUse`, `SubagentStart`, and `SubagentStop` hooks plus a smoke script
- curated Go runtime, governance, and operator files are present under `go/`; the AAT package keeps the draft-00 DG v0.1 JWT contract and adds the positively discriminated `ardur.dg.aat-draft-01.v0.2` path with chain-position roles, nine core constraints, mandatory audience-bound proof of possession, fresh per-hop holder keys, append-only approval requirements, mission-reference preservation, and DRP receipt-key separation; its deterministic public fixture is an Ardur self-test, while CWT and independent interoperability remain unclaimed
- runnable framework examples are present under `examples/`: LangChain, LangGraph, and AutoGen quickstarts; the Ardur Personal browser extension; the Ardur Personal desktop-observe adapter; the Ardur Personal native-messaging host; the Claude Code plugin pointer; and offline/no-key OpenAI Agents SDK and Google ADK fixtures. JSON mission examples remain in `examples/missions/`
- dedicated Python (3.10 + 3.13) and Go CI workflows run on every push and PR (`.github/workflows/tests.yml`), including the offline examples-smoke regression in `python/tests/test_examples_smoke.py` and a required fresh-volume Compose demo lifecycle, alongside CodeQL, link-check, secret-scan, format validation, and the Hugo site build
- the Hugo public evidence-site source tree is present under `site/`, with start-here / build / evidence sections that link each public claim back to the source file backing it
- bootstrap and local-validation scripts ship under `scripts/` (`conductor-bootstrap.sh`, `setup-dev.sh`, `check-local.sh`)
- agent-specific public guides live under `docs/agent-instructions/` (Conductor, Codex, Claude, plus a shared contract)
- new technical reference pages live under `docs/reference/` (CLI, Personal Hub HTTP API, `ARDUR.md` profile format)
- runtime delegation uses the file-backed `FileLineageBudgetLedger` for sibling child-budget reservations; mission-declared `lineage_budgets` from the v0.1 spec are not enforced yet and now fail closed at compile/issue time instead of being silently accepted
- selected archival walkthrough recordings are public starter media; the Claude
  Code MVP path also has a re-runnable no-key evidence harness and
  `bundle.redacted.json` reader guide. Re-runnable proof media remains in
  progress — see `MEDIA.md` and `docs/guides/read-phase1-evidence-bundle.md`
- a public audit trail is maintained under `docs/audit/`, mirroring the GitHub Code Scanning dismissal record
- the journey-log article series (`docs/articles/`) ships Article 05 (Proof Media That Actually Means Something) and Article 06 (Public Import Discipline) as first-wave entries

## In Progress

- checkpoint consistency monitoring and independent witness cosignatures for transparency anchors; one valid signed checkpoint proves inclusion but does not by itself detect a malicious log's split view
- live-provider OpenAI Agents SDK and Google ADK wrapper evidence beyond the current no-key fixtures
- live Codex hooks/cloud integration, Claude Desktop MCP packaging, and other non-fixture host integrations as separate next-cycle work
- re-runnable public proof media — recordings made against the public runtime
  with stable verifier commands and artifact paths; this is separate from the
  current no-key JSON evidence harness
- a tagged release with a regenerated Homebrew formula carrying Python resource stanzas, so non-technical users can install Ardur Personal without a source checkout
- broader conformance vectors beyond the public DRP and runtime-evidence implementation fixtures already under `docs/specs/conformance/`
- mission-declared `lineage_budgets` compiler/verifier support — the v0.1 specs define the intended protocol semantics, but the current runtime only supports delegation reservation accounting through `FileLineageBudgetLedger` and rejects non-empty mission-level `lineage_budgets`
- broader deployment material beyond the SPIRE design surface
- macOS and Windows launch sources under #70, #71, and the external Apple
  entitlement track #106; these remain separate from the completed bounded
  Linux classifier and content-fingerprint evidence contract in #67
- cross-host benchmark baselines and independently reproduced sensor-overhead results beyond the current local harness
- externally governed AuditBench annotation collection and headline scoring; the strict capture/blind-label/content-integrity-seal/score pipeline is implemented, but current public scenarios remain deterministic pipeline fixtures

## What We Still Need To Resolve

- close the remaining "private layout" notes in the v0.1 specs as their fixtures and companion files land publicly
- replace or re-render any legacy media that still carries internal path or repo-layout assumptions
- keep `VIBAP`, `MCEP`, and related protocol names only where they describe real artifacts, specifications, or protocol lineage
- decide which framework surfaces stay first-screen and which stay secondary as more adapters land

## Not Public Yet

- a tagged, packaged distribution on PyPI / Homebrew / OCI suitable for non-technical users
- full deployment material for cluster, identity, and receipt storage paths
- the full public docs spine (the current set is the public-safe subset)
- benchmark corpora and independently reproduced cross-host performance claims beyond the public local harness
- externally governed AuditBench human annotations, privacy-approved real-agent traces, external preregistration, and held-out headline results
- internal planning, lane, and session artifacts
- Trusted Execution Environment (TEE) attestation as a general hardware-rooted production claim — see `docs/known-limitations.md`

## Current Posture

The repo is published progressively: v0.1.0 is tagged with runnable code and
tests, while packaging (PyPI, Homebrew) and companion fixtures remain in active
development. Each surface declares its readiness level rather than implying a
complete production distribution is already present.
