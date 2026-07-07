# Epic B — Linux Auto-Detection Layer: eBPF Exec-Tracing, Agent Fingerprinting, and the Auto-Attach Trust Model

Status: **research/design document** (2026-07-04). No code changed. This is the
kernel-and-userspace deep-dive behind the Epic B plan
(`docs/roadmap/epic-b-auto-detection-plan.md`, in flight on the
`docs/epic-b-auto-detection-plan` lane), specifically **§2 "Detection"** and
its kickoff open questions on host-wide exec tracing, agent-class inference,
and adopt-and-attach mechanics. It complements the two sibling research docs
with the mechanism-level detail they defer:

- `docs/research/epic-b-policy-selection.md` owns **which mission governs** a
  detected agent (the posture ladder, binding rules, provenance passport). It
  explicitly defers detection mechanics and fingerprinting to *this* document.
- `docs/research/epic-b-performance-fp-budget.md` owns the **cost and
  false-positive budget** (the "CrowdStrike tax"). This document supplies the
  raw signal inventory that budget is spent on.

Scope boundary — what this document covers: (1) reliable eBPF exec-tracing to
catch an agent launch the instant it `execve`s; (2) fingerprinting a launched
process as a specific AI agent, with false-positive and evasion analysis; (3)
the auto-attest / auto-attach flow and its trust model. **Out of scope:** macOS
Endpoint Security Framework and Windows ETW (the `docs/epic-b-macos-windows-detection`
lane); the mission-selection decision (policy-selection doc); behavioral
identity over a running session (`python/vibap/behavioral_fingerprint.py`, B2).

---

## 0. TL;DR — key findings

1. **Ardur already picked the right detection hook.** The Slice-1 daemon
   (`go/cmd/ardur-kernelcaptured/daemon_linux.go`) attaches
   `tracepoint/sched/sched_process_exec` — which fires *after* the new program
   image is installed, so `comm`, `cgroup_id`, and the process's argv/env
   memory are all resident. The common beginner hook,
   `tracepoint/syscalls/sys_enter_execve`, is the wrong one: it runs *before*
   the syscall copies the strings in, and reading `argv`/`filename` there
   returns `EFAULT` because the `.rodata` pages holding them are not yet
   faulted in. Host-wide detection is therefore a *filter change* to existing
   code, not a new mechanism.

2. **Detection is inherently observe-only; enforcement is a different hook.**
   By the time `sched_process_exec` fires, the exec has already succeeded — you
   cannot un-exec the agent. The only clean *pre-execution* block point on
   Linux is the LSM BPF hook `lsm/bprm_check_security` returning `-EPERM`,
   which Ardur *already* built for enforcement in Slice 4.2
   (`go/pkg/kernelcapture/process_guard.bpf.c`). Detection and enforcement are
   two hooks with two different jobs; the auto-detection layer is the former.

3. **`comm` is no longer a reliable agent signal** and got *worse* recently.
   Claude Code and OpenAI Codex both shifted to **native compiled binaries**
   (`comm=claude`, `comm=codex`), while Gemini CLI, Grok CLI, and Kimi remain
   **Node/Python wrappers** (`comm=node`/`python`). No single field
   discriminates them; fingerprinting must fuse executable identity, argv,
   network endpoint, ancestry, and environment.

4. **The strongest positive signal (network endpoint) is defeatable and
   arrives late.** Egress to `api.anthropic.com` / `api.openai.com` /
   `generativelanguage.googleapis.com` / `api.x.ai` / `api.moonshot.ai` is the
   most specific "this is agent X" evidence, but every one of these CLIs
   supports a **custom base URL** (`OPENAI_BASE_URL`, `grok --base-url`, Kimi
   `base_url`, Gemini custom endpoint), so a proxied or self-hosted agent emits
   *no* known-endpoint egress — and the signal only appears *after* the first
   API call, i.e. after the agent has already acted.

5. **Auto-detection is governance-by-cooperation, not a security boundary.**
   Every fingerprint signal is individually spoofable by a motivated adversary
   (rename the binary, proxy the endpoint, strip the env). Auto-detection
   reliably governs the *cooperative/negligent* case (an honestly-built agent
   nobody happened to wrap in `ardur run`); it cannot govern an agent actively
   trying to evade. The trust model and default policy must be built on that
   admission — see §7.

---

## 1. What Epic A already gives us (the substrate)

Auto-detection is not greenfield. Slice 1 shipped a host daemon with an eBPF
exec/exit consumer; Slice 4.2 shipped an LSM-BPF enforcement guard. The
relevant existing pieces:

| Component | File | What it does today | Reuse for Epic B |
|---|---|---|---|
| Exec/exit tracer | `go/pkg/kernelcapture/process_exec.bpf.c` | `sched_process_exec` + `sched_process_exit` → ringbuf; captures `pid/ppid/tid/pid_ns/cgroup_id/comm[16]/exit_code` | The detection probe. Needs argv+path enrichment (§3.3) and host-wide mode (§3.4) |
| cgroup prefilter | same, `allowed_cgroups` + `filter_control` maps | in-kernel allowlist so only a registered session's cgroup subtree emits events | Invert to a **denylist/host-wide** mode for detection; keep the allowlist for post-adoption scoping |
| Daemon consumer | `go/cmd/ardur-kernelcaptured/daemon_linux.go` | ringbuf → correlator → per-session JSONL receipts | The classification + routing point |
| LSM enforcement guard | `go/pkg/kernelcapture/process_guard.bpf.c` | `bprm_check_security` / `lsm.s/file_open` / `socket_connect` → per-cgroup DENY/-EPERM | The *enforce* half after adoption; also the pre-exec block point discussed in §2 |
| Policy apply path | `bpf_policy_apply.go`, `run_bridge.py` | lowers a mission to BPF maps, keyed by `cgroup_id` | Auto-attach writes here with a *default* mission (policy-selection doc) |

The important architectural fact: **detection and enforcement are already
separate BPF programs** in the codebase. This document's job is to make the
detection program (a) run host-wide, (b) capture enough to fingerprint, and (c)
hand a confirmed agent to an adopt-and-attach path that writes the enforcement
program's maps.

---

## 2. Reliable eBPF exec-tracing

### 2.1 The hook decision

There are five candidate attach points for "a process just exec'd." They are
not interchangeable; they differ in *when* they fire, *what memory is readable*,
and *whether they can block*.

| Hook | Type | Fires | argv/path readable? | Can block exec? | Stability |
|---|---|---|---|---|---|
| `syscalls/sys_enter_execve` | tracepoint | **before** copy-in | ❌ `EFAULT` — `.rodata` not faulted in yet | no | stable ABI |
| `syscalls/sys_exit_execve` | tracepoint | after, but new `mm` | ⚠️ partial; return value only | no | stable ABI |
| **`sched/sched_process_exec`** | **tracepoint** | **after** new image installed | ✅ argv via `mm->arg_start/arg_end`; comm set; cgroup valid | no (already exec'd) | **stable ABI** |
| `bprm_execve` / `finalize_exec` | fentry/fexit | during exec | ✅ `bprm->filename`, `bprm->interp` | fexit: no; fentry+override: yes | BTF/CO-RE |
| `do_execveat_common` | kprobe | during exec | ✅ via registers | ✅ `bpf_override_return` (needs `CONFIG_BPF_KPROBE_OVERRIDE`) | unstable symbol |
| **`lsm/bprm_check_security`** | **LSM BPF** | **before** exec commits | ✅ `bprm->filename` | ✅ **return `-EPERM`** | needs `CONFIG_BPF_LSM` + `lsm=…,bpf` |

The classic mistake, documented at length by kernel practitioners, is hooking
`sys_enter_execve` and trying to `bpf_probe_read_user_str(filename)` /
`argv[i]`. It fails with `-EFAULT` because static argument strings live in the
binary's `.rodata` ELF section and are lazily paged in via `mmap`; the eBPF
probe runs *before* `execve`'s internal `strncpy_from_user()` triggers the
fault that would make them resident. `sched_process_exec` fires after the new
image is installed, so the strings are already in memory and are read through
the task's `mm_struct` (`arg_start`/`arg_end`) rather than raw userspace
pointers. **This is why Ardur's existing probe is on `sched_process_exec`, and
why host-wide detection reuses it rather than replacing it.**

For *detection*, `sched_process_exec` is correct: it is a stable tracepoint
(no per-kernel symbol drift like a kprobe on `do_execveat_common`), it needs no
special kernel config beyond `CONFIG_DEBUG_INFO_BTF` (for CO-RE reads of
`task_struct`), and everything needed to fingerprint is resident by the time it
fires. `fentry` on `bprm_execve` is a reasonable alternative with slightly
lower overhead (no perf-tracepoint plumbing) and direct access to `bprm`, but
it costs BTF-availability assumptions and buys nothing detection needs that the
tracepoint lacks.

### 2.2 The observe-only limitation and its (partial) workarounds

By the time detection fires, the agent is running. There is no "catch it
before it does anything" at the detection hook — that is a property of the
mechanism, not a bug. The kernel offers three ways to *act* on an exec, and
understanding which one applies is central to the trust model:

| Want | Mechanism | Where | Catch |
|---|---|---|---|
| Kill the process after the fact | `bpf_send_signal(SIGKILL)` | any hook incl. tracepoint | **racy** — the exec already succeeded; SIGKILL is synchronous to the *task* but does not undo side-effects already in flight (e.g. a `write()` may still land) |
| Fail the syscall so it never runs | `bpf_override_return` | kprobe on the syscall path | needs `CONFIG_BPF_KPROBE_OVERRIDE`; only on error-injectable functions; unstable |
| Deny the exec cleanly, pre-commit | LSM `bprm_check_security` → `-EPERM` | LSM BPF | needs `CONFIG_BPF_LSM` + `bpf` in the active `lsm=` list |

This is exactly the Falco-vs-Tetragon split (§2.4): Falco *observes and alerts*;
Tetragon *observes and enforces* via `Sigkill` (`bpf_send_signal`) and `Override`
(`bpf_override_return`). Ardur's Slice 4.2 chose the cleanest of the three —
LSM `-EPERM` — for enforcement, and it is **per-cgroup**, which is the seam
that makes auto-attach possible: detection runs host-wide and observe-only;
once a process is adopted into an Ardur-governed cgroup, the *already-attached*
LSM guard begins enforcing on it. The auto-detection layer never needs to block
at the detection hook, because blocking is the enforcement guard's job on the
subset of processes that have been adopted.

The consequence for detection: there is an irreducible window between `execve`
and adopt-and-attach during which a detected agent is observed but ungoverned.
That window, and the fact that the disambiguating signal often arrives inside
it, is the hardest open problem (§7).

### 2.3 What to capture, and how

Today's probe captures `comm[16]` — the 15-char-truncated basename of the
exec'd program. That is far too little to fingerprint an agent (§3). The
detection probe must additionally capture:

- **Full executable path.** Read `task->mm->exe_file` and resolve it with
  `bpf_d_path()` (as `process_guard.bpf.c` already does for `file_open`). Note
  `bpf_d_path` is only callable from a **BTF allowlist** of hooks (LSM,
  specific fentry/tracepoint programs); confirm `sched_process_exec` is on that
  allowlist for the target kernels, else fall back to userspace
  `/proc/<pid>/exe` readlink (§2.5 race). Path buffers are 256 bytes and can
  truncate; long paths are a known lossy case.
- **argv (bounded).** Read the contiguous NUL-separated argv block between
  `task->mm->arg_start` and `task->mm->arg_end` with a bounded loop (the
  verifier requires a static upper bound; cap at e.g. 4 KB / 32 args). There is
  no built-in helper for full argv — this is a hand-rolled `mm`-walk, resident
  and reliable only because we are at `sched_process_exec`.
- **env (selected keys only).** The same technique on
  `mm->env_start/env_end`, but env is sensitive (contains API keys). Capture
  *presence of* whitelisted keys (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, …),
  never values — see §3 and the privacy note in §6.
- Already captured and kept: `pid/tgid`, `ppid` (`real_parent->tgid`),
  `pid_namespace_id` (container attribution), `cgroup_id`, `monotonic_ns`.

Cost note: argv/path/env reads are not free per-exec host-wide; the
performance-budget doc owns the ceiling. Two mitigations: (a) a cheap in-kernel
prefilter that only pays for the expensive reads when comm or exe-basename is in
a small candidate set (`node`, `python`, `claude`, `codex`, `bun`, `deno`, …),
accepting that the prefilter itself is a spoofable narrowing; (b) emit a small
"exec seen" event always, and enrich lazily from userspace only for candidates.

### 2.4 How the EDRs do it (web-verified)

| System | Detection mechanism | argv source | Enforcement | Relevance to Ardur |
|---|---|---|---|---|
| **Falco** (modern eBPF probe) | syscall tracepoints (`sys_enter_execve`/`execveat`), CO-RE, probe embedded in the binary (no driver compile) | in-kernel + userspace `/proc` + container metadata enrichment | **none in-kernel** — detection/alert engine only | Confirms the "observe-only" baseline; Ardur wants more (attribution + attach) |
| **Tetragon** | tracepoints (`sched_process_exec`), raw tracepoints, kprobes, uprobes, **LSM BPF** | **in-kernel** argv/cwd/binary read (avoids `/proc` race) | **in-kernel**: `Sigkill` via `bpf_send_signal`, `Override` via `bpf_override_return` (needs `CONFIG_BPF_KPROBE_OVERRIDE`) | Closest architectural analog; Ardur = Tetragon's in-kernel model + LSM `-EPERM`, specialized to *agent identity* + mission attach |
| **CrowdStrike Falcon (Linux)** | eBPF programs loaded from **user space** (user mode; no kernel module) or kernel mode; falls to **Reduced Functionality Mode** (no process-exec events) if user mode unsupported | proprietary sensor → ThreatGraph | proprietary (prevention policies) | Validates the user-mode-eBPF sensor model; the 2024 kernel *panic* (an eBPF **verifier** bug) is the cautionary tale for shipping eBPF host-wide |

The load-bearing takeaway: **no EDR does what Epic B needs.** They detect
generic threats and processes; none of them says "this exec is *Claude Code*,
here is its mission passport, attach it." Ardur's novelty is not the exec
tracing — that is table stakes Tetragon does better today — it is **binding a
detected exec to a known *AI-agent identity* and a governance mission.** That
binding is the fingerprinting problem (§3) and the trust problem (§4–§7), not
the tracing problem.

### 2.5 The `/proc` enrichment race

The userspace fallback for anything not read in-kernel (full path via
`/proc/<pid>/exe`, argv via `/proc/<pid>/cmdline`, env via `/proc/<pid>/environ`)
has a TOCTOU race: between the ringbuf event and the `/proc` read, the process
may have exec'd *again* (so `/proc` now reflects a different image), exited (the
read returns `ESRCH`/empty), or — adversarially — rewritten its own `argv`
in-place. In-kernel reads at `sched_process_exec` are race-free because they see
the exact image being installed; that is the argument for paying the in-kernel
cost for the fingerprint-critical fields (path, argv) and leaving only
best-effort extras to `/proc`.

---

## 3. Agent fingerprinting

The question: given an exec event (path, argv, comm, ppid, cgroup, later
network + env), decide **is this an AI agent, and which one** — with a
calibrated confidence, few false positives, and a documented evasion surface.

### 3.1 The signal inventory

| Signal | How observed | Discriminating power | Spoofability | Latency |
|---|---|---|---|---|
| **comm** (15 chars) | `bpf_get_current_comm` (already) | Low — inconsistent across agents (native vs interpreted), collides with `node`/`python` | Trivial (`prctl(PR_SET_NAME)`, rename) | Immediate |
| **exe path + basename** | `mm->exe_file`+`d_path` / `/proc/<pid>/exe` | Medium — `~/.local/bin/claude`, npm global bin, `~/.bun/bin/…` | Easy (symlink, copy, rename) | Immediate |
| **argv[0..n]** | `mm->arg_start/arg_end` | Medium-High — interpreter agents reveal entrypoint (`node …/@google/gemini-cli/dist/index.js`), subcommands, flags | Easy (`argv[0]` is caller-controlled) | Immediate |
| **binary hash / signature** | hash exe vs known-release DB; npm provenance; macOS codesign (not Linux) | High when it matches | Hard to forge a *match*, easy to *avoid* (rebuild/strip) | Immediate but needs maintained DB, breaks every release |
| **network endpoint (SNI/DNS/IP)** | `socket_connect` LSM hook + DNS; TLS SNI | **Highest positive** — `api.anthropic.com` etc. | **Defeatable** via custom base URL / proxy | **Late** — only after first API call |
| **parent / ancestry** | `ppid`, walk `real_parent` | Medium — attributes subprocesses (MCP servers, tool calls) to an agent session; distinguishes desktop-app-spawned | Medium (re-parent via double-fork) | Immediate |
| **env key presence** | `mm->env_start/env_end` (keys only) | Medium-High — `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `XAI_API_KEY`, `MOONSHOT_API_KEY` | Easy (unset/rename; use a config file instead) | Immediate |
| **cgroup / container** | `cgroup_id`, `pid_ns` | Context, not identity | n/a | Immediate |

### 3.2 Per-agent fingerprint (web-verified, 2026-07)

| Agent | Packaging → `comm` | argv shape | Known endpoint(s) | Env key |
|---|---|---|---|---|
| **Claude Code** (Anthropic) | native binary (`claude.ai/install.sh` or `@anthropic-ai/claude-code-<plat>` optional-dep) → **`claude`** | `claude …` (argv[0] basename `claude`) | `api.anthropic.com`; auth/install via `claude.ai` | `ANTHROPIC_API_KEY`, `CLAUDE_*` |
| **OpenAI Codex CLI** | **native Rust** (`codex-rs`, ~95% Rust; npm/brew/binaries) → **`codex`** | `codex …` | `api.openai.com/v1` (overridable via `OPENAI_BASE_URL`) | `OPENAI_API_KEY` |
| **Gemini CLI** (Google) | **Node** (`@google/gemini-cli`, `npx`) → **`node`** | `node …/@google/gemini-cli/dist/index.js …` | `generativelanguage.googleapis.com`, `cloudcode-pa.googleapis.com`; hdr `x-goog-api-key` | `GEMINI_API_KEY`/`GOOGLE_API_KEY` |
| **Grok CLI** (xAI / community) | **Node** (e.g. `superagent-ai/grok-cli`) → **`node`** | `node …/grok… --base-url?` | `api.x.ai/v1` (overridable `--base-url`) | `XAI_API_KEY` / `GROK_API_KEY` |
| **Kimi** (Moonshot) | **Node/Python** (Kimi Code CLI) → **`node`/`python`** | wrapper entrypoint | `api.moonshot.ai/v1` (intl), `api.moonshot.cn` (CN), `api.kimi.com/coding/v1` (Kimi Code) | `MOONSHOT_API_KEY` |

Two structural facts jump out. First, **`comm` splits the field**: `claude` and
`codex` self-identify by basename, but the three interpreter-based agents all
present as `node`/`python`, so for them the identity lives in `argv[1]` (the
entrypoint script path) and the endpoint. Second, **endpoints are shared and
overridable**: `api.openai.com` is hit by Codex *and* by thousands of unrelated
OpenAI-SDK programs, so an endpoint match proves "an OpenAI client" not "Codex";
and any of these can be pointed at a proxy, erasing the endpoint entirely.

### 3.3 Confidence scoring, not boolean matching

Because no single signal is both specific and unspoofable, classification must
be a **weighted, corroboration-gated score**, not an `if comm == "claude"`.
A workable model:

- **Candidate (weak, ≥1 immediate signal):** exe-basename or argv entrypoint
  matches a known agent, *or* env key present. Cheap, immediate, high recall,
  low precision. → observe only; do **not** attach an enforcing policy.
- **Confirmed (corroborated, ≥2 independent signals):** e.g. argv entrypoint
  *and* a matching known endpoint; or signed-binary hash match; or
  exe-name + env-key + ancestry-from-a-known-launcher. → eligible for
  adopt-and-attach at the configured posture.
- **Attributed subprocess:** ancestry links a `node`/`python`/tool process to
  an already-confirmed agent's process tree (MCP server, shell tool call,
  `ripgrep` the agent spawned). Inherits the parent session's scope rather than
  being classified independently.

The two-tier gate (candidate→observe, confirmed→enforce) is what keeps a
misfire from *breaking* a user's unrelated `node` process by sandboxing it. It
also aligns with the posture ladder in the policy-selection doc: a candidate
maps to the observe rung; a confirmed agent maps to a governed rung.

### 3.4 Host-wide mode

Detection needs the probe to see *every* exec, not just a pre-registered
cgroup's. The existing `filter_control`/`allowed_cgroups` maps invert cleanly:
a `filter_control` value of "host-wide detect" bypasses the allowlist and emits
a (cheap, comm-only) event for every exec, with the expensive enrichment gated
by the §2.3 prefilter. After adoption, the *same* maps go back to their Slice-1
job — scoping the enforcement guard to the adopted cgroup subtree. One map set,
two lifecycle phases.

### 3.5 False-positive analysis

The costly failure is a *confirmed* false positive, because that triggers
attach (and possibly enforcement) on a non-agent. Sources:

1. **Name collisions.** A user's own script named `claude`, or a repo binary
   `codex`. Mitigated by requiring corroboration (a lone matching basename is
   only a *candidate*).
2. **Generic SDK clients.** A data pipeline using the OpenAI SDK hits
   `api.openai.com` — matches Codex's endpoint but is not Codex. Endpoint alone
   never confirms; it must pair with an argv/exe signal specific to the CLI.
3. **`comm=node`/`python` base rate.** These are among the most common execs on
   a dev host. Gating anything on comm alone is a precision disaster; comm is
   only ever a *prefilter*, never a classifier.
4. **Help/version/CI invocations.** `claude --version` in a CI script is an
   agent binary but not an agent *session*. A session gate (did it open a
   long-lived connection / read the project) avoids attaching to a one-shot.
5. **The user's own `ardur run` agent.** A wrapped agent must not be
   double-governed. Adoption must check for an existing Ardur cgroup membership
   / session registration and *skip* — the single most important
   false-positive to suppress, because it corrupts the receipt chain.

### 3.6 Evasion / false-negative analysis (adversarial)

Assume an agent (or a user) that does **not** want to be governed. Each signal
falls:

| Evasion | Defeats | Residual signal |
|---|---|---|
| Rename/symlink binary; spoof `argv[0]` | exe-name, argv | endpoint, env, ancestry |
| Point at custom base URL / corporate proxy | endpoint (the strongest) | argv, exe, env |
| Read key from a config file, unset env | env | argv, exe, endpoint |
| Static-link + strip + self-rebuild | hash/signature | behavior, endpoint |
| Nest in a fresh namespace/container | cgroup attribution, ancestry | in-namespace exec still visible host-wide (pid_ns tags it) |
| Combine all of the above | every static signal | **only behavioral** (§policy-selection B2) or nothing |

The honest conclusion: **a determined adversary defeats static fingerprinting.**
Detection's job is not to beat an adversary — it is to *reliably* govern the
overwhelmingly common non-adversarial case and to make evasion *observable*
(an exec that trips a candidate signal then goes dark on endpoint is itself a
reportable anomaly). This bounds what the trust model may claim (§7).

---

## 4. Auto-attest + auto-attach flow

The sequence for a process nobody launched under `ardur run`:

```
execve ──► sched_process_exec (host-wide, observe)
             │  emit: pid, ppid, cgroup_id, pid_ns, comm
             ▼
        candidate?  (prefilter: comm/exe-basename in agent set OR env key present)
             │ no → drop (cheap path, the 99%+ case)
             │ yes
             ▼
        enrich  (in-kernel argv + exe path; userspace /proc extras)
             ▼
        classify → confidence tier
             │ candidate  → register OBSERVE session, default-permissive, receipts only
             │ confirmed  → adopt-and-attach:
             ▼
        1. skip if already governed (existing Ardur cgroup / ardur run session)
        2. create/assign an Ardur cgroup; move the pid (cgroup.procs)
        3. register a synthetic session with the daemon (cgroup_id ↔ session)
        4. select default mission (policy-selection doc) and apply_policy →
           writes the enforcement guard's BPF maps for this cgroup_id
        5. begin receipts; mark provenance = "auto-detected" (NOT launched-under-governance)
             ▼
        (later) socket_connect to a known endpoint ──► raise confidence / confirm class
```

### 4.1 The cgroup-attach mechanics and their races

Adoption moves an already-running process into an Ardur cgroup by writing its
pid to the new cgroup's `cgroup.procs`. Sharp edges:

- **The move is post-hoc.** Everything the agent did between `execve` and step
  2 happened under its original cgroup and was *not* enforced (it was observed,
  if the enrichment fired). This is the governance gap (§7).
- **`bpf_get_current_cgroup_id()` follows the move.** The enforcement guard
  keys on the process's *current* cgroup, so after the move the LSM hooks see
  the Ardur cgroup and enforce. Good — but children forked *before* the move
  may still be in the old cgroup and escape enforcement until swept. B4's
  descendant sweep (policy-selection doc references it) owns this; detection
  must hand B4 the full process-tree root, not just the leaf pid.
- **Threaded processes / cgroup v2 rules.** cgroup v2 moves are per-process
  (all threads move together) which is what we want, but the write can race a
  concurrent fork; the sweep must be idempotent and re-run.
- **Move authority.** Writing another process's pid into a cgroup requires the
  daemon to have the right (root/delegated). That is a powerful capability
  (§4.2).

### 4.2 Trust model

This is where auto-detection differs most from `ardur run`, and where honesty
matters most in the attestation.

**Two provenance tiers, never conflated.** An `ardur run` session carries a
signed Mission Passport issued *before* the agent ran — a cryptographic proof of
human intent and a launched-into-governance guarantee ("no ungoverned
instruction executed under `--enforce`", per the policy-selection doc's
invariant table). An auto-adopted session has *none of that*: no passport, no
pre-execution consent, and a nonzero ungoverned head-start. The receipt for an
auto-adopted session **must** be stamped `provenance: auto-detected,
launch: unverified, governed-from: T+Δ` so that any downstream verifier can see
it is a weaker claim. Selling an auto-adopted receipt as equivalent to a wrapped
one would be the single most damaging integrity failure in Epic B.

**Default policy = observe, escalate on evidence.** Because detection can false-
positive and because enforcing on a misidentified process breaks legitimate
work, auto-attach defaults to the **observe/permissive** rung. Escalation to
enforce requires either (a) a high-confidence *confirmed* classification **and**
an operator-configured "enforce auto-detected agents" posture, or (b) explicit
per-agent opt-in. The policy-selection doc owns *which* mission; this document's
constraint on it is: **do not auto-enforce on a candidate**, only on a confirmed
agent under an explicit posture. Fail-open for detection (miss → agent runs as
it would have anyway), fail-safe for enforcement (only enforce what you're sure
of).

**Authority to govern is itself a trust boundary.** A daemon that can move
arbitrary pids into cgroups and apply deny policies to them can, if compromised
or misconfigured, sandbox or SIGKILL any user process. Auto-govern must be
gated: only processes matching the configured agent-detection policy, only for
consenting UIDs/namespaces, with the kill-switch and authZ from the Slice-4.2
security audit (`ardur-enforcement-security-audit`) applying to the auto-attach
path exactly as to the manual one. Auto-detection widens the set of processes
the enforcement surface can touch — so it inherits, and must re-clear, that
surface's authZ.

---

## 5. Recommended phasing

| Phase | Deliverable | Risk |
|---|---|---|
| D1 | Host-wide `sched_process_exec` mode (invert `filter_control`) + comm-only emit | Low — filter change to shipped code |
| D2 | In-kernel argv + exe-path enrichment, gated by candidate prefilter | Med — verifier bounds on `mm`-walk; perf budget |
| D3 | Confidence-scored classifier (exe/argv/env fusion), **observe only** | Med — false-positive tuning; needs a labeled corpus (B2) |
| D4 | `socket_connect` endpoint corroboration → confirm tier | Med — endpoint DB, proxy/override blind spots |
| D5 | Adopt-and-attach (cgroup move + synthetic session + default mission), provenance-stamped receipts, **observe posture default** | High — the race + trust model of §4/§7 |
| D6 | Opt-in enforce posture for confirmed agents | High — only after D1–D5 proven, gated by authZ |

D1–D3 are low-to-medium risk and deliver the core value (transparent visibility
into un-wrapped agents) without touching enforcement. D5–D6 are where the hard
problem lives and should not ship until the observe path is trustworthy.

---

## 6. Privacy and safety notes

- **Never capture env *values*.** API keys, tokens, and secrets live in the
  environment. The probe captures *presence of whitelisted keys* for
  fingerprinting, never their values, and never dumps `environ`. This is both a
  privacy requirement and an attack-surface reduction (the daemon must not
  become a secret aggregator).
- **argv can contain secrets too** (a `--api-key=…` flag). argv capture should
  redact known secret-bearing flags before it hits a receipt.
- **Host-wide exec tracing sees every process on the box**, not just agents.
  The prefilter must drop non-candidates *in-kernel* so non-agent execs never
  reach userspace as identifiable records — minimizing what is logged about
  unrelated user activity.
- **Shipping eBPF host-wide is itself a reliability risk.** The 2024 CrowdStrike
  Linux kernel *panic* was an eBPF **verifier** bug, not sensor logic — a
  reminder that a host-wide probe must degrade gracefully (the daemon already
  degrades to observe-only when BPF-LSM is unavailable) and be killable.

---

## 7. The single hardest open problem

**Trustworthy enforce-grade attach is blocked by an irreducible race against a
signal that arrives too late — and detection can never be a hard boundary
anyway.**

Unpack it:

1. **The window exists and cannot be closed by moving detection earlier.**
   Between `execve` and adopt-and-attach, the agent runs ungoverned and does
   its highest-value actions first (read credentials, first file access, first
   exfil). You cannot fingerprint *earlier* than `sched_process_exec`: at
   `sys_enter_execve` the argv/env strings are not yet readable (`EFAULT`,
   §2.1), and the network endpoint — the *most* disambiguating signal — does not
   exist until the agent makes its first API call, which is *inside* the window.
   So the strongest evidence for "confirmed agent, safe to enforce" arrives
   *after* the moment you'd have wanted to start enforcing.

2. **The only way to close the window is a posture nobody wants.** To guarantee
   zero ungoverned instructions you would have to deny-by-default *every* exec
   at `lsm/bprm_check_security` and allow-list, i.e. the opposite of transparent
   host-wide adoption — that is `ardur run`'s launched-into-governance model,
   not detection. Detection's entire premise is catching agents *nobody wrapped*;
   requiring them to be wrapped to be safe is circular.

3. **Every static signal is individually evadable (§3.6),** so even setting the
   race aside, a *confirmed* classification is only confirmed against a
   cooperative agent. An adversary proxies the endpoint, renames the binary, and
   reads its key from a file — and confirmation never fires, or fires wrong.

The unavoidable resolution is a **two-phase, honestly-tiered model**, not a
fix: detect-and-observe immediately and cheaply host-wide (fail-open, capture
the window's actions even though you can't block them), then confirm-and-enforce
once corroborating signals land (fail-safe, enforce only the subset you're sure
of), and **stamp every auto-adopted receipt with its weaker provenance and its
`governed-from: T+Δ` gap** so nobody mistakes captured-but-not-blocked for
prevented. The open research question that remains, and that this document
cannot answer, is: **what is the minimum corroboration that justifies flipping a
detected agent from observe to enforce, given that the flip is both racy and
adversarially defeatable — and can that threshold be set without either
(a) enforcing on false positives or (b) leaving the high-value first-window
actions of true agents ungoverned?** Everything else in the Linux detection
layer is engineering; this is the part that is genuinely unsolved.

---

## References

- eBPF exec-tracing mechanics and the `sys_enter_execve` argv/`EFAULT` gotcha:
  <https://mozillazg.com/2024/03/ebpf-tracepoint-syscalls-sys-enter-execve-can-not-get-filename-argv-values-case-en.html>,
  <https://github.com/bpftrace/bpftrace/discussions/2116>,
  <https://docs.ebpf.io/linux/helper-function/bpf_probe_read_kernel_str/>
- Tetragon hooks (tracepoint / kprobe / raw tracepoint / uprobe / LSM BPF) and
  enforcement actions (`Sigkill` = `bpf_send_signal`, `Override` =
  `bpf_override_return`, `CONFIG_BPF_KPROBE_OVERRIDE`):
  <https://tetragon.io/docs/concepts/tracing-policy/hooks/>,
  <https://tetragon.io/docs/concepts/enforcement/>,
  <https://github.com/cilium/tetragon>,
  <https://yuki-nakamura.com/2024/05/17/tetragon-process-lifecycle-observation-ebpf-part/>
- Falco modern eBPF probe (CO-RE, embedded, syscall `execve`/`execveat` source,
  observe/alert only):
  <https://falco.org/blog/falco-modern-bpf-0-35-0/>,
  <https://falco.org/docs/concepts/event-sources/kernel/>,
  <https://github.com/falcosecurity/libs/blob/master/driver/modern_bpf/programs/tail_called/events/syscall_dispatched_events/execve.bpf.c>
- CrowdStrike Falcon for Linux (user-mode eBPF sensor, Reduced Functionality
  Mode, 2024 kernel-panic root cause = eBPF verifier bug):
  <https://www.crowdstrike.com/tech-hub/endpoint-security/installing-falcon-sensor-for-linux/>,
  <https://christiantaillon.medium.com/no-need-to-panic-the-linux-kernel-panic-crowdstrike-issue-f3ada3386303>,
  <https://www.theregister.com/2024/09/26/grafana_labs_interview/>
- Agent CLIs — packaging, argv, endpoints, env:
  - Claude Code (native binary; `claude.ai/install.sh`; `api.anthropic.com`):
    <https://www.npmjs.com/package/@anthropic-ai/claude-code>,
    <https://github.com/anthropics/claude-code>,
    <https://code.claude.com/docs/en/setup>
  - OpenAI Codex CLI (native Rust; `OPENAI_BASE_URL`; `api.openai.com/v1`):
    <https://developers.openai.com/codex/cli>,
    <https://github.com/openai/codex>,
    <https://developers.openai.com/codex/config-advanced>
  - Gemini CLI (Node; `generativelanguage.googleapis.com`; `x-goog-api-key`):
    <https://github.com/google-gemini/gemini-cli>,
    <https://github.com/google-gemini/gemini-cli/issues/1679>
  - Grok CLI (Node; `api.x.ai/v1`; `--base-url`):
    <https://github.com/superagent-ai/grok-cli>, <https://docs.x.ai/developers/quickstart>
  - Kimi / Moonshot (`api.moonshot.ai/v1`, `api.moonshot.cn`, `api.kimi.com/coding/v1`):
    <https://platform.moonshot.ai/>,
    <https://moonshotai.github.io/kimi-cli/en/configuration/providers.html>
- Ardur substrate (this repo): `go/pkg/kernelcapture/process_exec.bpf.c`
  (`sched_process_exec` probe), `go/pkg/kernelcapture/process_guard.bpf.c`
  (LSM enforcement), `go/cmd/ardur-kernelcaptured/daemon_linux.go` (consumer),
  `docs/roadmap/epic-b-auto-detection-plan.md`,
  `docs/research/epic-b-policy-selection.md`,
  `docs/research/epic-b-performance-fp-budget.md`.
