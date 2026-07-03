# Epic B — Slice B1: Host-Wide Linux Detection (implementation plan)

Status: **planning document only** (2026-07-03). Read-only pass; no code changed.
This is the file-level build plan for the first Epic B *build* slice after the B0
hardening gate. It proposes work; it does not authorize it, and it inherits the
honest enforcement boundary in `docs/security-model.md`.

Parents / inputs:
- Epic B slice plan — `docs/roadmap/epic-b-auto-detection-plan.md` (#114, merged).
  B1 row: "Linux host-wide exec detection + observability-gap metric (#39).
  Ungated `sched_process_exec` path capturing binary path/argv/uid; in-kernel
  basename prefilter; keep the scoped correlator feed intact. Must prove: every
  known-agent exec observed, non-agent execs dropped in-kernel, overhead under CI
  budget, #39 emits. **No attest, no enforce.**"
- Cost/reliability SLOs — `docs/research/epic-b-performance-fp-budget.md` (#117).
  B1 is gated by **SLO-1, SLO-2, SLO-3, SLO-4** (defined there; restated in §7).
- Policy-selection research — `docs/research/epic-b-policy-selection.md` (#116).
  Not exercised by B1 (no policy, no enforce) but sets the observe-only default
  B1 must not violate.
- Issues: **#39** (observability-gap metric), **#67** (classification — *next*
  slice, not B1), Epic A tracker **#63**.

> There is **no** separate "Linux-detection / fingerprinting" research PR open as
> of this writing (`gh pr list`: the only open Epic-B-adjacent PR is #115, the B0
> hardening). If that research lands later, reconcile §3–§4 against it before B1
> kickoff. This plan is built from the two merged research docs + the code.

---

## 0. Hard dependency: B0 (#115) must land first

B1 **must not merge before B0 (#115 — the #108/#109/#110 fixes)**, even though B1
is observe-only and adds no attest/enforce path. Three concrete reasons, not a
formality:

1. **Shared daemon files.** #115 rewrites the daemon control-request routing
   (`go/cmd/ardur-kernelcaptured/main.go` `handleAuthorizedRequest` and the
   per-peer authorization seam in `daemon_session_registry.go`). B1 adds a new
   consumer loop and (optionally) a prefilter-seed control method to the *same*
   files. Landing B1 first guarantees a rebase conflict and risks re-opening the
   exact authz gap #108 closes.
2. **Any new control method inherits B0's authorization model.** If B1 adds a
   control-socket method to seed/update the prefilter basename map at runtime
   (§4.4), that method must route through the per-peer authorization #115
   introduces. Building it against the pre-#115 handler shape bakes in the
   vulnerable pattern.
3. **Epic-B gate discipline.** The roadmap makes B0 the hardening gate: the
   sensor's reach expands from "cgroups an operator registered" to "every process
   on the host" in B1. That expansion must never ship on top of a control plane
   with a known global-kill / IDOR bug (#108) or silent stale-policy bug (#109).
   Observe-only B1 doesn't *touch* those bugs, but it dramatically raises the
   value of the daemon as a target, so the gate stands.

B1 is therefore **branched off B0**, not off `dev`, and its CI must be green only
after #115 is in the base.

---

## 1. What B1 is, and the one architectural change it makes

Today, `process_exec.bpf.c` is **wrapper-scoped**: `submit_process_event()` gates
every event on `cgroup_allowed(cgroup_id)` and emits only `struct
ardur_process_event { …, char comm[16] }` — no path, no argv, no uid — into a
4 KB (`1 << 12`) ringbuf that feeds the Correlator for governed sessions.

B1 adds a **second, parallel, host-wide detection path** and changes nothing
about the scoped one. The scoped `process_exec.bpf.c` program, its `events`
ringbuf, its `allowed_cgroups`/`filter_control` maps, and the Correlator feed are
left **byte-for-byte intact** (regenerated objects must not drift — the
`bpf-generate` CI job enforces this). B1's new path:

- runs on **every** exec system-wide (no cgroup gate),
- captures the **resolved binary path, leading argv, and uid**,
- **prefilters in-kernel** against a known-agent basename set so ~all non-agent
  execs are dropped before any ringbuf reserve or userspace wake,
- emits surviving events to a **new, larger detection ringbuf**,
- maintains **per-CPU counters** (execs seen / prefilter-miss / surfaced /
  ringbuf-drop) that the daemon reads to emit the **#39 observability-gap
  metric**,
- and **stops there** — the daemon consumes detection events into the evidence
  log and counters **only**. No classification (B2), no attestation (B3), no
  adoption (B4), no policy/enforce (B5). The detection stream does **not** feed
  the Correlator or `apply_policy`.

The single load-bearing property: **the detection program is structurally
incapable of blocking or governing anything.** It is a sensor tap, and B1's job
is to prove the tap is cheap, complete on direct-binary agents, and honest about
what it misses.

---

## 2. BPF design

### 2.1 Hook choice — recommended primary + fallback

The detection hook must (a) see every exec host-wide, (b) yield the *resolved*
binary path (not a racy user-pointer — the Phantom Attack / CVE-2021-33505 lesson
in the cost/FP research §2.2), and (c) be **structurally observe-only**.

**Primary: a void BPF-LSM hook — `SEC("lsm/bprm_committed_creds")`.**
- `bprm_committed_creds` is a **void** LSM hook: it returns nothing, so the BPF
  program **cannot deny the exec**. Observe-only is guaranteed by the hook's
  signature, not by convention — exactly the property B1 needs.
- At this hook the `struct linux_binprm *bprm` is fully populated: `bprm->file`
  is the resolved executable, so `bpf_d_path(&bprm->file->f_path, buf, sz)`
  returns the absolute resolved path. `bpf_d_path` is on the BTF allowlist for
  security hooks, so this call is verifier-legal here (it is **not** legal from
  an arbitrary tracepoint — this is the reason to prefer the LSM hook).
- argv: reachable from the new mm's arg pages via `bprm->p` / `bprm->mm`
  (the standard Tetragon approach), read **only on a prefilter hit** (§2.3).
- uid: `bpf_get_current_uid_gid() & 0xffffffff`.
- **Dependency:** requires `CONFIG_BPF_LSM=y` and `bpf` in the kernel `lsm=`
  boot list — the **same** requirement Slice 4.2 already established and the
  `kernel-smoke` CI job already boots with (virtme-ng, BPF-LSM on the cmdline).
  So B1 adds no new kernel-config surface beyond what the enforce stack has.

**Fallback (hosts without BPF-LSM): `SEC("tracepoint/sched/sched_process_exec")`.**
- Mirrors the existing scoped program's attach point but **ungated**.
- The raw tracepoint exposes `__data_loc filename` — the exec filename, which may
  be relative and is *not* the fully-resolved path, and `bpf_d_path` is **not**
  callable here. So the in-kernel prefilter uses the **basename of that filename**
  (adequate for direct-binary agents, which are invoked by absolute or
  PATH-resolved names), and userspace resolves the canonical path as a backstop
  via `/proc/<pid>/exe` off the hot path.
- This matches the daemon's existing tiered posture (BPF-LSM tier with a non-LSM
  fallback), and keeps B1 functional on stock cloud kernels that ship without
  BPF-LSM in the active `lsm=` list.

The daemon selects primary-vs-fallback at load time using the same capability
probe pattern as `daemon_kernel_caps_linux.go` (which already gates BPF-LSM
availability for the enforce path).

### 2.2 Maps (all fixed-size, pre-allocated — SLO-3)

Mirror the guard-map budget discipline (`process_guard.bpf.c`: `cgroup_op_policy`
16384, `cgroup_path_allow` 4096, `enforce_events` 16 KB ring). New maps:

| Map | Type | Size | Purpose |
|---|---|---|---|
| `detect_events` | `BPF_MAP_TYPE_RINGBUF` | **256 KB** (`1 << 18`) | Host-wide detection events. Larger than the scoped feed's 4 KB because it carries host-wide (build-storm) traffic; sized to absorb a burst and **count** overruns rather than grow (research §1.5, SLO-4). |
| `agent_basenames` | `BPF_MAP_TYPE_HASH` | 256 entries, key `struct basename_key{char b[32]}`, value `u8 class_hint` | The in-kernel prefilter set. Seeded by userspace from the known-agent **direct-binary** basename list (§4.4). O(1) lookup = the whole cost model (research §1.3). |
| `detect_counters` | `BPF_MAP_TYPE_PERCPU_ARRAY` | 8 slots `u64` | #39 counters: `[0] execs_seen`, `[1] prefilter_miss`, `[2] surfaced`, `[3] ringbuf_full_drops`, `[4] path_read_fail`, `[5] argv_read_fail`, rest reserved. Per-CPU = no atomics on the hot path. |
| `detect_control` | `BPF_MAP_TYPE_ARRAY` | 1 entry `u8` | Kill switch for the detection path (enable/disable at runtime without unloading), mirroring `filter_control`. Default **enabled**. |

Total pinned: 256 KB ring + ~10 KB maps ≪ the **16 MB** SLO-3 ceiling.

### 2.3 Hot-path shape (this is the SLO)

The miss path — every non-agent exec, ~99.9% of execs — must pay only: hook
dispatch + one path read + one basename-hash lookup + counter bump + return.
Nothing else may touch the miss path.

```
handle_detect(bprm):
    counter[execs_seen]++                       # per-CPU, no atomic
    path = bpf_d_path(bprm->file->f_path)        # primary; or __data_loc filename (fallback)
    if !path: counter[path_read_fail]++; return  # loud-but-cheap
    base = basename(path)                         # in-kernel, bounded scan
    hint = bpf_map_lookup_elem(agent_basenames, base)
    if !hint:                                     # ---- MISS: the 99.9% path ----
        counter[prefilter_miss]++
        return                                    # no reserve, no argv, no wake
    # ---- HIT: the rare path; extra cost is amortized to ~0 over all execs ----
    ev = bpf_ringbuf_reserve(detect_events, sizeof(*ev))
    if !ev: counter[ringbuf_full_drops]++; return # SLO-4: counted, never silent
    ev.uid = bpf_get_current_uid_gid()
    ev.pid/ppid/tid/cgroup_id/pid_ns/monotonic_ns = …   # same identity fields as the scoped path
    copy path -> ev.resolved_path[256]
    read up to N argv bytes from bprm arg pages -> ev.argv[512]   # bounded; argv_read_fail counted
    ev.class_hint = *hint
    counter[surfaced]++
    bpf_ringbuf_submit(ev)
```

Note the deliberate asymmetry: **`sha256` and full argv parsing are NOT here.**
The kernel emits the raw path + bounded argv bytes; the expensive fingerprint
work is B2's, off the hot path in userspace (research §1.3, §4.3). The prefilter
is seeded with **direct-binary** basenames only; interpreter basenames
(`python3`/`node`) are deliberately **excluded** in B1 (§4.4) — matching them
host-wide is the FP-flood/cost blow-up the research calls the structural hole
(§2.2/§5), so B1 *measures* that gap via #39 rather than pretending to close it.

### 2.4 Event struct (new, distinct from the scoped `ardur_process_event`)

```c
struct ardur_detect_event {
    __u8  event_type;        // ARDUR_DETECT_EXEC = 1
    __u8  class_hint;        // prefilter class hint (NOT a classification — B2 owns that)
    __u8  path_truncated;    // resolved_path hit the 256B cap
    __u8  argv_truncated;    // argv hit the 512B cap
    __u64 monotonic_ns;
    __u32 pid; __u32 ppid; __u32 tid;
    __u32 uid;
    __u32 pid_namespace_id; __u64 cgroup_id;
    char  comm[16];          // free, still useful for cross-checking renames
    char  resolved_path[256];
    char  argv[512];         // NUL-separated leading argv bytes, bounded
};
```

Kept separate from `ardur_process_event` on purpose: the detection stream must
not be mistaken for, or routed into, the Correlator's scoped lifecycle feed.

---

## 3. Files to add / change

### 3.1 BPF + generated bindings

| File | Add/Change | What |
|---|---|---|
| `go/pkg/kernelcapture/process_detect.bpf.c` | **add** | The detection program (§2). Primary LSM hook + fallback tracepoint behind a compile guard; maps; hot-path. `//go:build ignore` like the other `.bpf.c`. |
| `go/pkg/kernelcapture/process_detect_generate.go` | **add** | `//go:generate … bpf2go … processDetect process_detect.bpf.c …` mirroring `process_exec_generate.go`. |
| `go/pkg/kernelcapture/processdetect_bpfel.go` | **add (generated, committed)** | bpf2go output — committed like `processexec_bpfel.go` / `processguard_bpfel.go`. |
| `go/pkg/kernelcapture/processdetect_bpfel.o` | **add (generated, committed)** | ditto. |

### 3.2 Userspace (Go) — daemon side

| File | Add/Change | What |
|---|---|---|
| `go/pkg/kernelcapture/types.go` | **change** | Add `DetectEvent` struct (Go mirror of `ardur_detect_event`: `ResolvedPath`, `Argv []string` or raw bytes, `UID`, `ClassHint`, truncation flags, plus the shared identity fields) and a `ProcessEventDetect` type marker. Keep it **out** of the `ProcessEvent`/Correlator types so B1 can't accidentally feed enforcement. |
| `go/pkg/kernelcapture/detect_source_linux.go` | **add** | `RingbufDetectSource` — opens the pinned `detect_events` ring, `Next(ctx)` decodes one `ardur_detect_event`. Modeled on `ringbuf_source_linux.go` + `decodeRingbufRecord` (`ringbuf_common.go`), but decodes the wider struct (little-endian, fixed offsets). |
| `go/pkg/kernelcapture/detect_decode.go` | **add** | Pure decode of the `ardur_detect_event` byte layout (unit-testable off-kernel, exactly how `decodeRingbufRecord` is testable today). |
| `go/pkg/kernelcapture/detect_prefilter_linux.go` | **add** | Seed/update `agent_basenames` from the known-agent basename seed set (§4.4); expose `SeedAgentBasenames([]string)`. This is the only place B1 mutates a BPF map at runtime. |
| `go/pkg/kernelcapture/detect_observability_linux.go` | **add** | Read `detect_counters` (per-CPU, summed), compute the **#39 gap** (`execs_seen − surfaced` = dropped-by-prefilter; plus `ringbuf_full_drops` as the SLO-4 loss signal), expose a snapshot the daemon surfaces in the evidence log + status. |
| `go/pkg/kernelcapture/linux_ebpf_daemon_linux.go` | **change** | Load + attach `processDetect` (LSM primary / tracepoint fallback via the `daemon_kernel_caps_linux.go` probe). Extend `PinnedEBPFPaths` + `DefaultPinnedEBPFPaths()` with `DetectLinkPath` (`/sys/fs/bpf/ardur/detect_link`), `DetectEventsMapPath` (`/sys/fs/bpf/ardur/detect_events`), `DetectCountersMapPath`, `DetectBasenamesMapPath`; add restart-survival (pin/reuse) exactly like `LoadAndAttachProcessExecEBPFPinned`. |
| `go/pkg/kernelcapture/bpf_policy_apply_unsupported.go` / `daemon_kernel_caps_unsupported.go` | **change (parallel stubs)** | Add non-Linux build-tag stubs for the new symbols so the darwin "Go" workflow keeps compiling (the package already uses this `_unsupported.go` pattern). |
| `go/cmd/ardur-kernelcaptured/main.go` | **change** | Start the detection consumer loop: drain `RingbufDetectSource` → append to the evidence JSONL (a new `detect` record kind) + periodically fold `detect_observability` counters into the status snapshot. **Observe-only**: it must not call `apply_policy`, must not touch the Correlator, must not register a session. If B1 adds a runtime prefilter-seed control method, route it through the **post-#115** authorization path (§0). |
| `go/pkg/kernelcapture/README.md` | **change** | Document the two-path model (scoped correlator feed vs host-wide detection tap) and the observe-only boundary. |

### 3.3 Smoke harness + CI

| File | Add/Change | What |
|---|---|---|
| `go/cmd/ardur-detect-smoke/` | **add** | Privileged smoke harness (sibling of `ardur-guard-smoke`): plant a binary named like a known agent, exec it, assert a `detect_events` record with the right resolved path/uid; exec a non-agent (`/bin/true`), assert **no** record and `prefilter_miss` incremented; read `detect_counters` and assert the gap math. |
| `go/cmd/ardur-detect-bench/` | **add** | Exec-storm micro-benchmark for **SLO-1**: fork+exec a trivial non-agent in a tight loop with the detector loaded vs unloaded, report added p50/p99 exec latency on the **miss** path. |
| `.github/workflows/kernel-enforce.yml` | **change** | (a) extend `bpf-generate` to regenerate + drift-check `processDetect` too; (b) add **`detect-smoke`** job (KVM + virtme-ng, BPF-LSM on cmdline — reuse the `kernel-smoke` VM recipe) running `ardur-detect-smoke`; (c) add **`detect-bench`** running `ardur-detect-bench` with a **p99 ceiling gate** (SLO-1). Add the new `go/cmd/ardur-detect-*/**` to the `paths:` triggers. Start `detect-smoke` as `continue-on-error: true` (burn-in), like `kernel-smoke` did. |

### 3.4 Explicitly NOT touched by B1

`process_exec.bpf.c`, `correlator.go`, `bpf_policy_apply*.go`, `apply_policy` /
`set_kill_switch` handlers, `process_guard.bpf.c`, `run_bridge.py`. If a B1 diff
touches any of these beyond additive map-path plumbing, the slice has scope-crept
into B2+/enforcement.

---

## 4. The hard bits, decided for B1

### 4.1 Resolved path without a TOCTOU (research §2.2)
Use the kernel object (`bprm->file->f_path` via `bpf_d_path`), never a user
pointer — this is the correct-by-construction mitigation for the Phantom-Attack
class. The tracepoint fallback reads `__data_loc filename` (still kernel-side)
and resolves canonically in userspace via `/proc/<pid>/exe`; a mismatch between
the two is itself a signal worth counting.

### 4.2 Keeping the miss path honest (SLO-1)
`bpf_d_path` is the one non-trivial cost on the miss path. If `detect-bench`
shows it breaching p99 ≤ 10 µs on the target runner, the documented optimization
is a **two-stage prefilter**: gate first on the free `comm[16]` (already
available via `bpf_get_current_comm`) and only call `bpf_d_path` for
comm-candidates. This is left as a bench-driven option, not a premature
complication — B1 ships the single-stage version and the benchmark decides.

### 4.3 Ringbuf sizing & drops (SLO-4)
256 KB detection ring; every failed reserve bumps `ringbuf_full_drops`. The
daemon surfaces sustained drops as an SLO-4 violation via #39 — a drop is a
**measured coverage gap**, never silent loss. Reuse the lost-sample accounting
posture already established for the enforce ring (#100).

### 4.4 Prefilter seed set — direct binaries only, interpreters excluded
Seed `agent_basenames` from a small **direct-binary** list (e.g. `claude`,
`claude-code`, `codex`, `gemini`, `kimi`, `grok` — the exact set is B2's corpus
input, seeded conservatively in B1). **Interpreter basenames (`python`,
`python3`, `node`) are excluded in B1** because matching them host-wide is the
FP-flood + cost blow-up the research flags as the structural hole (§2.2/§5).
B1's stance: prove the mechanism on direct binaries, and let **#39 measure** the
interpreter-hosted gap (execs seen vs the subset the prefilter can catch) rather
than assert coverage. Closing the interpreter gap is explicitly B2's problem
(argv/fingerprint), not B1's.

### 4.5 The #39 observability-gap metric — what it actually reports
From `detect_counters`: `execs_seen` (every exec the hook saw), `surfaced`
(prefilter hits emitted), `prefilter_miss` (dropped cheap), `ringbuf_full_drops`
(lost under burst). The gap metric = the honest coverage statement: "the sensor
saw N execs this interval; it surfaced S; it dropped D to prefilter and L to ring
overflow." This is the number that keeps the product claim measurable instead of
asserted (research §2.2, §3.5) and it is a **standing** signal, not a one-time
check. Surface it in the daemon status snapshot and evidence log; a
`/metrics`-style export can follow the `vibap/metrics.py` counter/gauge idiom if
a daemon-side endpoint is wanted later (not required for B1).

---

## 5. Test & verification

### 5.1 Off-kernel unit tests (run in the ordinary darwin/linux "Go" workflow)
- `detect_decode_test.go` — decode `ardur_detect_event` fixtures: field offsets,
  little-endian, path/argv truncation flags, NUL handling (the pattern of
  `decodeRingbufRecord`'s existing tests).
- `detect_prefilter_linux_test.go` — basename-key construction, seed set
  round-trips, oversize-basename rejection.
- `detect_observability_linux_test.go` — per-CPU counter summation + gap math
  from synthetic counter snapshots (no kernel needed).
- Non-Linux stub compile is covered by the existing `_unsupported.go` tags.

### 5.2 Privileged Linux CI — the part only a live kernel can prove
Extend `.github/workflows/kernel-enforce.yml`:
- **`bpf-generate`** (existing, extend): regenerate `processDetect`, fail on
  drift vs the committed `processdetect_bpfel.{go,o}`, then build/vet/test the
  module with the real generated symbols — the same guarantee it gives
  `processguard`/`processexec` today.
- **`detect-smoke`** (new, KVM + virtme-ng, BPF-LSM enabled — reuse the
  `kernel-smoke` VM recipe): as root inside the VM, run `ardur-detect-smoke`:
  1. plant `./claude` (a copy of `/bin/true`), exec it → assert one
     `detect_events` record with `resolved_path` ending `/claude`, correct
     `uid`, and `surfaced == 1`;
  2. exec `/bin/true` (non-agent) → assert **no** record and `prefilter_miss`
     incremented — the in-kernel drop proof;
  3. read `detect_counters` → assert `execs_seen ≥ 2`, `surfaced == 1`, gap
     accounting consistent;
  4. (fallback-mode variant) boot **without** BPF-LSM → assert the tracepoint
     fallback still surfaces the planted agent.
  Start `continue-on-error: true` for a burn-in, then promote to required
  (exactly how `kernel-smoke` was introduced).
- **`detect-bench`** (new): run `ardur-detect-bench`; **fail the job if the
  added miss-path exec latency p99 > 10 µs** (SLO-1). This is the gate that keeps
  B1 on the Tetragon side of the cost gap (research §1.4, SLO-2).

### 5.3 What each layer proves
- `bpf-generate`: the program **compiles and loads**, and the committed bindings
  match source.
- `detect-smoke`: the loaded program **actually fires** host-wide, captures the
  resolved path/uid, and **actually drops** non-agents in-kernel — the one thing
  `bpf-generate` cannot show (same rationale the workflow header gives for
  `kernel-smoke`).
- `detect-bench`: the miss path is **within the latency budget** (SLO-1).
- unit tests: the userspace decode/seed/gap math is correct without a kernel.

---

## 6. Acceptance gate — what B1 must prove

B1 is done when, on top of a merged B0 (#115), all of the following hold:

1. **Host-wide capture works.** Every known-agent (direct-binary) exec on the
   host produces a `detect_events` record carrying resolved path + leading argv +
   uid — proven live by `detect-smoke`, in both BPF-LSM and tracepoint-fallback
   modes.
2. **Non-agent execs are dropped in-kernel.** A non-agent exec produces no
   ringbuf record and bumps `prefilter_miss` — proven live by `detect-smoke`.
3. **Overhead is within budget.** Added miss-path exec latency **p50 ≤ 2 µs,
   p99 ≤ 10 µs** (SLO-1), CI-gated by `detect-bench`; aggregate CPU tracked
   against SLO-2.
4. **Maps are bounded.** All detect maps are compile-time fixed-size, ≤ 16 MB
   pinned, zero per-exec allocation (SLO-3) — reviewed in the PR.
5. **Drops are counted, never silent.** Ring overflow bumps `ringbuf_full_drops`
   and surfaces via #39; sustained drop > 0 is a flagged SLO-4 violation.
6. **#39 emits.** The observability-gap metric reports execs-seen / surfaced /
   prefilter-miss / ring-drop from `detect_counters` in the daemon status +
   evidence log.
7. **The scoped path is untouched.** `process_exec.bpf.c`, its ring, its maps,
   and the Correlator feed are byte-identical; `bpf-generate` confirms no drift.
8. **Observe-only is structural.** No classification, attestation, adoption,
   policy, or enforcement exists in the diff; the detection stream never reaches
   the Correlator or `apply_policy`. The LSM hook's void return makes blocking
   impossible by construction.

Explicitly **out of scope / deferred**: classification and the labeled-corpus
precision/recall SLOs (SLO-5/-7) are **B2 (#67)**; confidence-thresholded enforce
(SLO-6) is **B5**; the interpreter-hosted-agent gap is *measured* here (#39) and
*closed* in B2; macOS `NOTIFY`/`AUTH` budget (SLO-8) is **B6**; adoption is **B4**.

---

## 7. SLOs that gate B1 (from #117, restated)

| SLO | Value | B1 enforcement |
|---|---|---|
| **SLO-1** Added exec latency, miss path | p50 ≤ 2 µs, p99 ≤ 10 µs | `detect-bench` CI job, p99 ceiling |
| **SLO-2** Aggregate host CPU | ≤ 1% of a core @ 1,000 execs/s; ≤ 5% @ 5,000/s storm | standing overhead measurement; architected in-kernel-filtered (Tetragon-side, not Falco-side) |
| **SLO-3** Map memory | ≤ 16 MB pinned, fixed-size, zero per-exec alloc | compile-time constants, PR review |
| **SLO-4** Ringbuf drop rate | drops counted + surfaced; sustained > 0 = violation | `detect_counters` + #39, never silent |

SLO-5/-6/-7 (classifier precision/recall/confidence) and SLO-8 (macOS) do **not**
gate B1 — they gate B2/B5/B6. B1 only has to make the interpreter gap *visible*,
not solved.
