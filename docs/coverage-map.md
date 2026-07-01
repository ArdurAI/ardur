# Ardur Coverage Map

**The single source of truth for what Ardur captures and what it does not.**

This page is the canonical reference linked from the README, `STATUS.md`,
plugin documentation, and every example. When the capture surface changes,
this page changes; everywhere else just links to it.

Last updated: 2026-06-25. Current shipping version: v0.1 (tool-call boundary). Current dev branch additionally contains a bounded Linux eBPF/daemon-control proof harness with a capped in-memory daemon session registry seam, safe active-session lookup/handoff-plan builder ergonomics, daemon-internal status snapshots, in-memory snapshot retention handler/sink proof, narrow local `session_status` client proof, no-write status evidence-log planning seam, in-memory JSONL evidence-log entry builder, injected in-memory append/rotation planner, injected filesystem append/rotation adapter with temp-dir test coverage, daemon-side `session_status` evidence-log append wiring through that injected filesystem, and a no-mutation session handoff plan seam; it is not part of the shipping v0.1 capture claim.
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

## What is *not* captured today (v0.1)

| Gap | Why | Roadmap |
|---|---|---|
| **Side effects of `Bash` commands** — when Claude calls `Bash("rm foo")`, we record the command string but not the kernel `unlink` syscall, the inotify event, or the actual file change. | Claude Code hooks fire at the tool-call boundary; subprocess execution happens below in a process tree the hook can't see. | v0.2 (filesystem snapshots) closes this for FS effects within scope. v0.5 (Linux eBPF) closes this completely on Linux. v1.0 (macOS Endpoint Security Framework) closes this on macOS. |
| **Subprocess trees spawned by `Bash`** — `Bash("./run.sh")` is one receipt; everything inside `run.sh` is invisible. | Same reason. | v0.5 / v1.0 |
| **Network connections** initiated by tool-spawned processes (DNS, TCP, HTTP) | Hooks see `WebFetch`/`WebSearch`; they do not see network calls made by, say, `Bash("curl …")` | v0.5 / v1.0 |
| **Filesystem deltas outside the typed file tools** — files changed by a Bash command, by an MCP server, or by a subagent's subprocess | Same boundary | v0.2 (snapshots) partial; v0.5 / v1.0 full |
| **Provider-side reasoning, hidden state, server-side tool calls** | The LLM runs on Anthropic/OpenAI/etc. infrastructure. No local tool can see what happens inside the model or on the provider's servers. | **Out of scope by definition.** Labeled `insufficient_evidence` on receipts when relevant. |
| **Anything outside the active session** — actions in another terminal, after `claude` exits, or before `ardur start` runs | We instrument a specific process tree. | Cross-session correlation is a separate research question. |
| **Out-of-scope filesystem** — paths outside the Mission Passport's `resource_scope` | Intentional — scope is the user's protected boundary | A user can widen scope in `instructions.md`; not captured by default |
| **Posture index as asset inventory** — `ardur posture scan` does not discover unmanaged apps, credentials, cloud assets, or provider-side state. | It is a report over local Ardur evidence artifacts, not a scanner with new sensors. | Future adapters can feed more evidence; the posture index must continue to label unsupported boundaries as gaps. |

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

Three layers exist; we currently capture layer 1.

Development note: `go/pkg/kernelcapture` contains a gated Linux process-lifecycle proof harness that can load/attach `sched/sched_process_exec` and `sched/sched_process_exit` eBPF tracepoint programs in a privileged Linux test environment, read exec/exit samples from a ringbuf, and project them through Ardur's correlation/evidence semantics. It also contains a bounded local Unix-domain daemon-control socket proof seam with fail-closed peer authorization, a capped in-memory session registry for authorized `register_session`/`session_status`/`end_session` requests, safe active-session lookup/handoff-plan builder ergonomics, daemon-internal status snapshots plus in-memory daemon-side snapshot retention for internal status/handoff code, a narrow local `session_status` client proof that rejects response expansion, a no-write status evidence-log planning seam that derives schema/digest/rotation plan data under daemon-owned custody paths, an in-memory JSONL evidence-log entry builder that revalidates digest/session/size before any future write path, an injected in-memory append/rotation planner that computes accept/rotate/reject decisions against a fake sink only, an injected filesystem append/rotation adapter that executes validated logical-path writes through caller-provided filesystem implementations with temp-dir test coverage, daemon-side `session_status` evidence-log wiring that appends successful status snapshots through that injected filesystem before retaining them without expanding the client protocol, and a no-mutation session handoff plan that derives daemon-owned hashed state/runtime paths plus cgroup allowlist preconditions. This is useful development evidence for the v0.5 direction, but it is not a production daemon, not persistent session storage, not production persistent status evidence-log storage, not daemon-owned evidence-log service wiring or restart-safe persistence, not a cgroup assignment mechanism, not a service installer, not client-visible protocol expansion, not live universal CLI capture, and not file/network/syscall coverage beyond process lifecycle metadata.

```
┌─────────────────────────────────────────────────────┐
│ Layer 3 — Filesystem boundary                       │
│   inotify/fsevents on the working directory         │
│   ↳ planned: v0.2 (working-dir snapshots)           │
├─────────────────────────────────────────────────────┤
│ Layer 2 — Process / kernel boundary                 │
│   Process tree, syscalls, network sockets           │
│   ↳ planned: v0.5 (Linux eBPF) / v1.0 (macOS ESF)   │
├─────────────────────────────────────────────────────┤
│ Layer 1 — Tool-call boundary           ← shipping   │
│   Every Claude Code tool invocation, signed         │
└─────────────────────────────────────────────────────┘
```

## What "cryptographic provenance" precisely claims

Ardur signs:
- **Mission Passport** at issuance (ES256 over the claims).
- **Each Execution Receipt** at capture (ES256 over `tool`, `target`, `arguments_hash`, `verdict`, `parent_receipt_hash`, timestamps, `trace_id`, `step_id`, etc.).
- **Receipt chain integrity** via `parent_receipt_hash` = SHA-256(prior receipt JWT). Tampering with any receipt invalidates the chain from that point forward.

Ardur does **not** sign:
- The kernel's actual response to a syscall (we don't observe it; layer 2 work).
- The remote provider's reasoning or server-side actions (out of scope).
- Anything the operating system did between two tool calls (layer 3 work).

So when we say "cryptographically verifiable record", it's a record of **what tool calls Claude Code made** — not "everything that happened on your machine".

## Evidence levels (per-receipt label)

Each receipt carries an `evidence_level` field. The values:

| Level | Meaning |
|---|---|
| `enforced` | Ardur controlled the local action boundary (deny path fired, action did not execute) |
| `attested` | Ardur signed an observation; the action's intent is captured |
| `observed` | A local adapter saw browser/desktop/CLI state |
| `self_signed` | Ardur signed its own observation (default for tool calls) |
| `insufficient_evidence` | The relevant provider-side or kernel-level activity was not locally visible — labeled explicitly rather than implied |

The `insufficient_evidence` label is how we keep claims precise at the receipt level. If something happened that Ardur couldn't verify, the receipt says so.

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
