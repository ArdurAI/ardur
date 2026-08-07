# Ardur Coverage Map

**The single source of truth for what Ardur captures and what it does not.**

This page is the canonical reference linked from the README, `STATUS.md`,
plugin documentation, and every example. When the capture surface changes,
this page changes; everywhere else just links to it.

Last updated: 2026-08-07. Current shipping version: v0.1 (tool-call boundary). The `ardur run -- <cli>` host-observer lifecycle tier is now also shipping: root-process PID, command, `run_command` (actual argv when adapter wrapping differs), `cwd` (absolute working directory), `duration_budget_s` (caller-set time budget), started-at, wall-clock duration, exit code, and exit signal are captured for any CLI launch on macOS/Linux without any host plugin API dependency (`capture_tier=host-observer`). Descendant processes are now enumerated recursively (direct children, grandchildren, etc. — PID, command, started-at, wall-clock duration, depth, parent_pid; child exit codes best-effort). Full real-time exec/fork event capture remains a layer 2 gap requiring eBPF daemon correlation. Current dev branch additionally contains a bounded Linux eBPF/daemon-control proof harness with a capped in-memory daemon session registry seam, safe active-session lookup/handoff-plan builder ergonomics, daemon-internal status snapshots, in-memory snapshot retention handler/sink proof, narrow local `session_status` client proof, no-write status evidence-log planning seam, in-memory JSONL evidence-log entry builder, injected in-memory append/rotation planner, injected filesystem append/rotation adapter with temp-dir test coverage, daemon-side `session_status` evidence-log append wiring through that injected filesystem, and a no-mutation session handoff plan seam; it is not part of the shipping v0.1 capture claim.
 - The handler also automatically removes in-memory evidence-log append state when sessions end or expire; it does not delete, rotate, archive, or rename evidence-log files.

## What Ardur captures today (v0.1)

| Source | Coverage | Receipt fields |
|---|---|---|
| Claude Code `Read` tool | Full — file path, content digest (SHA-256), size, exit code | `tool=Read`, `target=<path>`, `arguments_hash`, `invocation_digest` |
| Claude Code `Edit` / `MultiEdit` tool | Full — path, old/new strings, exit | `tool=Edit\|MultiEdit`, `target=<path>` |
| Claude Code `Write` tool | Full — path, full content digest | `tool=Write`, `target=<path>`, response digest |
| Claude Code `Glob` / `Grep` tool | Tool-call boundary — pattern/search args and response digest; host-reported result/count metadata can be truncated or incomplete when count metadata is absent or marked incomplete | `tool=Glob\|Grep`, search args, response digest |
| Claude Code `Bash` tool | **Command string only** — *not* the subprocess effects (see "What is *not* captured" below) | `tool=Bash`, `target=<command-string>` |
| Claude Code `WebFetch` / `WebSearch` | Full — URL, response digest | `tool=WebFetch\|WebSearch`, `target=<url>` |
| Claude Code `Task` (subagent dispatch) | Full — parent intent, child trace id, prompt | `tool=Task`, plus `SubagentStart` / `SubagentStop` lifecycle receipts |
| Claude Code MCP tool calls (`mcp__server__tool`) | Full at the call boundary — name, args, response digest. Downstream effects of the MCP server are out of scope. | `tool=mcp__<server>__<name>` |
| Mission Passport | Full — issued JWT with allowed/forbidden tools, resource scope, budgets, biscuit attenuation chain | Signed by issuer; verified at session start |
| Receipt chain integrity | Full — every receipt's `parent_receipt_hash` is SHA-256 of prior receipt's full JWT; ES256-signed | `receipt_id`, `parent_receipt_hash`, `parent_receipt_id`, `trace_id` |
| Posture index | Derived local evidence only — summarizes local receipts/profile/redacted bundle without mutating them | `schema_version=ardur.posture_index.v0`, `positioning=derived_local_evidence`, chain status, verdict/boundary counts, coverage gaps |
| `ardur run -- <cli>` host-observer lifecycle | **Root-process + recursive descendant lifecycle** — root PID, command, `run_command` (actual argv when adapter wrapping differs), `cwd` (absolute working directory), `duration_budget_s` (caller-set time budget), started-at, wall-clock duration, exit code, and exit signal, plus descendant processes recursively (direct children, grandchildren, etc. with PID, command, started-at, wall-clock duration, depth, parent_pid; child exit codes best-effort). Zero-privilege, no kernel daemon, works on macOS/Linux with any CLI. `capture_tier=host-observer`. Lifecycle evidence is cryptographically signed into the session-final attestation token as a `process_lifecycle` claim. | `process_lifecycle` object in governance result and attestation JWT: `root_pid`, `command`, `run_command` (when differing), `cwd` (when captured), `duration_budget_s` (when set), `started_at`, `wall_clock_s`, `exit_code`, `exit_signal`, `capture_tier`, `children` (list of descendant snapshots with depth + parent_pid when descendants exist) |

## What is *not automatically captured* today (v0.1)

| Gap | Why | Roadmap |
|---|---|---|
| **Side effects of `Bash` commands** — when Claude calls `Bash("rm foo")`, we record the command string but not the kernel `unlink` syscall, the inotify event, or the actual file change. | Claude Code hooks fire at the tool-call boundary; subprocess execution happens below in a process tree the hook can't see. | v0.2 (filesystem snapshots) closes this for FS effects within scope. v0.5 (Linux eBPF) closes this completely on Linux. v1.0 (macOS Endpoint Security Framework) closes this on macOS. |
| **Subprocess trees spawned by `Bash`** — `Bash("./run.sh")` is one receipt; everything inside `run.sh` is invisible. | Same reason. | v0.5 / v1.0 |
| **Network connections** initiated by tool-spawned processes (DNS, TCP, HTTP) | Hooks see `WebFetch`/`WebSearch`; they do not see network calls made by, say, `Bash("curl …")` | v0.5 / v1.0 |
| **Filesystem deltas outside the typed file tools** — files changed by a Bash command, by an MCP server, or by a subagent's subprocess | Same boundary | v0.2 (snapshots) partial; v0.5 / v1.0 full |
| **Provider-side reasoning, hidden state, server-side tool calls** | The LLM runs on Anthropic/OpenAI/etc. infrastructure. No local tool can see what happens inside the model or on the provider's servers. | **Out of scope by definition.** Labeled `unknown` on receipts when the verifier observed the call but cannot know what happened inside the provider. |
| **Anything outside the active session** — actions in another terminal, after `claude` exits, or before `ardur start` runs | We instrument a specific process tree. | Cross-session correlation is a separate research question. |
| **Out-of-scope filesystem** — paths outside the Mission Passport's `resource_scope` | Intentional — scope is the user's protected boundary | A user can widen scope in `instructions.md`; not captured by default |
| **Posture index as asset inventory** — `ardur posture scan` does not discover unmanaged apps, credentials, cloud assets, or provider-side state. | It is a report over local Ardur evidence artifacts, not a scanner with new sensors. | Future adapters can feed more evidence; the posture index must continue to label unsupported boundaries as gaps. |

## Imported runtime-evidence correlation

`ardur evidence correlate` is a separate offline inspection path. It first
verifies a signed receipt journal, then correlates operator-supplied normalized,
Tetragon, or Falco JSONL into a detached redacted report. It can make
claim-vs-reality evidence easier to inspect, but it does not change what the
configured hook captures automatically.

The report separates:

- **source assurance** (`imported_unverified` in v0.1);
- **coverage** (`unknown` for Tetragon by default and `alert_only` for Falco);
  and
- **match confidence** (`high`, `medium`, `low`, or `ambiguous`).

A high-confidence match is still unauthenticated corroboration. A missing event
does not prove an action was absent. Raw commands, paths, destinations,
workspaces, credentials, source identifiers, and local paths are removed from
the report. See the
[Runtime Evidence Correlation Profile](specs/runtime-evidence-correlation-v0.1.md)
for the exact contract.

## Posture index positioning

`ardur posture scan` is a read-only derived-evidence report. It can verify local
receipt-chain integrity when `passport_public.pem` is supplied, count allow/deny
policy outcomes, identify unknown boundaries such as Bash subprocess effects,
and attach profile / redacted-bundle digests. It must not be described as live
endpoint monitoring, enterprise discovery, kernel capture, provider-side
visibility, or proof that uncaptured side effects did or did not happen. The
machine-readable marker is `positioning=derived_local_evidence`.

The posture index is safe to share by default: credential-like values are
emitted as `[REDACTED]`, and local absolute paths are replaced with hashed
`<PATH:...>` placeholders.

## Boundary classes

Three layers exist. Configured hooks capture layer 1; imported sensor evidence
can inspect selected layer-2 observations without claiming native sensor
deployment, source authenticity, or complete coverage. Separately, a Linux
`ardur run` that successfully registers its cgroup with the live
`ardur-kernelcaptured` daemon receives native process exec/exit capture for that
session. The proxy registers each receipt before releasing the evaluated
action, and the signed attestation carries captured/correlated/uncorrelated
counts plus an observed-effect gap ratio. Capture loss degrades that metric.
This conditional native path is not host-wide universal CLI capture, persistent
session storage, file/network effect capture, provider-hidden visibility, or a
claim that an authenticated session-owner receipt was independently verified
by the daemon.

```
┌─────────────────────────────────────────────────────┐
│ Layer 3 — Filesystem boundary                       │
│   inotify/fsevents on the working directory         │
│   ↳ planned: v0.2 (working-dir snapshots)           │
├─────────────────────────────────────────────────────┤
│ Layer 2 — Process / kernel boundary                 │
│   Linux cgroup process exec/exit       ← conditional │
│   Other syscalls/network/macOS ESF     ← roadmap     │
├─────────────────────────────────────────────────────┤
│ Layer 1.5 — Host-observer lifecycle                 │
│   ardur run -- <cli> root + descendant tree PID/cmd │
│   ↳ zero-privilege, no daemon — shipping            │
├─────────────────────────────────────────────────────┤
│ Layer 1 — Tool-call boundary           ← shipping   │
│   Every Claude Code tool invocation, signed         │
└─────────────────────────────────────────────────────┘
```

Layer 1.5 (host-observer) captures the root process launched by
`ardur run -- <cli>`: its PID, command, `run_command` (the actual argv when
adapter wrapping transforms it), `cwd` (absolute working directory), started-at
timestamp, wall-clock duration, exit code, and exit signal. It also enumerates
descendant processes recursively (direct children, grandchildren, etc. — PID,
command, started-at, wall-clock duration, depth, parent_pid; child exit codes
are best-effort and may be null when a child exits between snapshot and
inspection). This works on macOS and Linux without any host plugin API
dependency or kernel daemon. It is `capture_tier=host-observer` and records a
point-in-time snapshot of the root process and its descendant tree — not
real-time exec/fork event streams, syscalls, file/network effects, or
provider-side actions. Those remain layer 2 / layer 3 gaps.

## What "cryptographic provenance" precisely claims

Ardur signs:
- **Mission Passport** at issuance (ES256 over the claims).
- **Each Execution Receipt** at capture (ES256 over `tool`, `target`, `arguments_hash`, `verdict`, `parent_receipt_hash`, timestamps, `trace_id`, `step_id`, etc.).
- **Receipt chain integrity** via `parent_receipt_hash` = SHA-256(prior receipt JWT). Tampering with any receipt invalidates the chain from that point forward.

Ardur does **not** sign:
- The kernel's actual response to a syscall (we don't observe it; layer 2 work).
- The remote provider's reasoning or server-side actions (out of scope).
- Anything the operating system did between two tool calls (layer 3 work).

The runtime-evidence correlator also does not sign imported sensor JSON. It
hashes exact input lines as pointers and labels the source
`imported_unverified`; those hashes show which bytes were analyzed, not that a
trusted sensor produced them.

So when we say "cryptographically verifiable record", it's a record of **what tool calls Claude Code made** — not "everything that happened on your machine".

## Evidence levels (per-receipt label)

Each receipt carries an `evidence_level` field. The values:

| Level | Meaning |
|---|---|
| `enforced` | Ardur controlled the local action boundary (deny path fired, action did not execute) |
| `attested` | Ardur signed an observation; the action's intent is captured |
| `observed` | A local adapter saw browser/desktop/CLI state |
| `self_signed` | Ardur signed its own observation (default for tool calls) |
| `insufficient_evidence` | The verifier could not make a confident decision due to a transient operational failure (approval operator unavailable, state file corrupted, network error). Might be retried. |
| `unknown` | The verifier observed the call but the evidence is structurally outside the capture boundary — the honest "I cannot know what happened" outcome, distinct from a retryable transient failure |

Both labels keep claims precise at the receipt level. `insufficient_evidence` records a retryable operational failure; `unknown` records a genuine observation gap where the activity is structurally outside Ardur's capture boundary. Both fail-closed as `DENY`. See [Security Model](security-model.md) for the full five-state Decision taxonomy.

## What v0.5 / v1.0 will add

### v0.5 — Linux eBPF (kernel-capture)

Current dev proof already covers the first process-lifecycle slice: gated Linux load/attach of exec/exit tracepoints, ringbuf sample reading, cgroup allowlist smoke behavior, local daemon-control authorization seams, a capped in-memory daemon session registry seam with safe active-session lookup/handoff-plan builder ergonomics, daemon-internal status snapshots, in-memory snapshot retention handler/sink proof, narrow local `session_status` client proof, no-write status evidence-log planning seam, in-memory JSONL evidence-log entry builder, injected in-memory append/rotation planner, injected filesystem append/rotation adapter with temp-dir test coverage, daemon-side `session_status` evidence-log append wiring through that injected filesystem, and a no-mutation daemon session handoff plan seam. The remaining v0.5 claim is larger than that proof: production daemon lifecycle, persistent daemon-owned session/cgroup management, restart-safe evidence-log persistence, daemon-created/assigned cgroups, broader syscall/file/network capture, and deployable Linux hardening are still future work.

Adds receipts for kernel events: `execve`, `clone`, `openat`, `write`, `unlinkat`, `renameat2`, `connect`, etc. Each kernel-event receipt is correlated to the tool-call receipt that caused it (via process-tree ancestry). Same chain. Same signing. Same disputability.

After v0.5: the gap between "what Claude said it would do" (tool call) and "what actually happened on the system" (kernel events) is closed on Linux.

### v1.0 — macOS Endpoint Security Framework

Same coverage as v0.5, on macOS, via Apple's ESF system extension. Requires Apple Developer entitlement.

### v2.0 — Windows ETW

Same coverage on Windows via Event Tracing for Windows + Windows Filtering Platform.

See [`STATUS.md`](../STATUS.md) and [`ROADMAP.md`](../ROADMAP.md) for current status.

## How this page should be used

- The **README** links here from its first section ("What Ardur is") so any reader gets the boundary up front.
- **`STATUS.md`** links here from its "Capture Boundary" section.
- The **Claude Code plugin README** links here from its "Boundaries" section.
- Any **example README** that demonstrates capture should link here so the scope of the demo is clear.
- **The verifier-contract spec** (`docs/specs/verifier-contract-v0.1.md`) is the formal source of truth for what's signed; this page is the prose explanation.

If you are reading this and notice a claim elsewhere in the repo that contradicts this page, the contradiction is a bug — file an issue. This page is the source of truth.
