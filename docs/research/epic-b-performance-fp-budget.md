# Epic B — The "CrowdStrike Tax": Cost & Reliability Budget of Always-On Host-Wide Agent Detection

Status: **research document only** (2026-07-03). Read-only pass; no code changed.
This proposes SLOs and a fail-safe posture; it does not authorize work. Every
enforcement slice still inherits the security gates and the honest enforcement
boundary in `docs/security-model.md`, and the slice plan in
`docs/roadmap/epic-b-auto-detection-plan.md` (PR #114).

Scope note — this is a **net-new** Epic B lane. It does **not** re-cover:
- **detection mechanism** per OS (that is the roadmap doc §2),
- **fingerprint/classification design** (roadmap §4.2, #67),
- **policy/trust model** (roadmap §3–4.1, #68/#69).

It covers only the thing those docs defer to a one-line budget: **what does it
cost, and how wrong is it allowed to be, to watch every process on the host** —
and it turns that into numeric SLOs the Epic B slices (B1, B2, B5, B8) must be
held to, plus the fail-safe rule for when detection is uncertain.

The framing is deliberate. Epic B's product analogy is "CrowdStrike for AI
agents." The analogy carries a tax: an always-on host sensor that inspects every
process launch is a permanent, system-wide cost centre and a permanent,
system-wide *liability surface*. The two largest IT outages attributable to
endpoint security software — McAfee 2010 and CrowdStrike 2024 — were **not
breaches. They were the sensor itself misfiring** on the whole fleet at once.
Any doc that proposes to put Ardur on that path owes a number for the cost and a
number for the blast radius. That is this doc.

---

## 1. The cost half: overhead of tracing every exec host-wide

### 1.1 What Epic B changes about the cost model

Epic A's `process_exec.bpf.c` gates every event on `cgroup_allowed(cgroup_id)`
(a 1024-entry hash the wrapper populates) and its ringbuf is only `1 << 12`
(4 KB). The BPF program *runs* on every `sched_process_exec` system-wide, but it
returns almost immediately for any exec outside a managed cgroup — no ringbuf
reserve, no userspace wake. **The scoped design already pays the cheap part of
the tax and skips the expensive part.**

Epic B (roadmap §2.1) inverts this: an **ungated** host-wide exec path that, for
*every* exec on the box, must read the resolved binary path (`bpf_d_path` on the
`linux_binprm` file), enough leading argv to fingerprint, and `uid`, then decide
whether to surface the event. The cost that was skipped is now on the hot path
of every `execve` the machine does. This section budgets that cost.

### 1.2 Baseline: what an exec costs, and how often it happens

- **Cost of one `fork+execve`:** system-dependent, but lmbench-class numbers land
  between **~365 µs and ~2,800 µs** per `fork+execve` depending on hardware/kernel
  ([lmbench, USENIX](https://www.usenix.org/legacy/publications/library/proceedings/usenix01/freenix01/full_papers/loscocco/loscocco_html/node16.html)).
  For scale: a bare syscall is ~5 µs and a context switch ~20 µs. **An exec is
  already a hundreds-of-microseconds operation** — that is the denominator any
  added-latency SLO is measured against.
- **How often execs happen:** Brendan Gregg's `execsnoop` documentation states the
  exec rate is "expected to be low" — **< 500/s** (ftrace build), **< 1000/s**
  (bcc/eBPF build)
  ([bcc execsnoop man page](https://github.com/iovisor/bcc/blob/master/man/man8/execsnoop.8);
  [Ubuntu execsnoop-bpfcc](https://manpages.ubuntu.com/manpages/focal/en/man8/execsnoop-bpfcc.8.html)).
  Tetragon in the field reports ~200 process events/s typical, 1,000–2,000/s under
  a synthetic connect-storm
  ([tetragon.io events docs](https://tetragon.io/docs/concepts/events/)).
  **The exception is the case Ardur most cares about:** build hosts, CI runners,
  and shell-heavy dev boxes — exactly where AI coding agents run — can spike far
  above 1,000 execs/s (a `make -j` or a test suite is an exec storm). The SLO must
  hold at the *storm* rate, not the idle rate.

### 1.3 Per-event BPF cost, and why the prefilter is load-bearing

The kernel-side cost of a tracepoint BPF program is dominated by dispatch +
whatever the program does. Reference points:
- A jump-optimized kprobe hit is ~**243 cycles**; the INT3 fallback is ~**1,858
  cycles**
  ([Red Hat Developer, measuring BPF performance](https://developers.redhat.com/articles/2022/06/22/measuring-bpf-performance-tips-tricks-and-best-practices)).
  Raw tracepoints are cheaper than tracepoints, which beat fentry/kprobe/uprobe
  ([iximiuz Labs](https://labs.iximiuz.com/tutorials/ebpf-tracing-46a570d1)).
- The expensive addition Epic B makes is `bpf_d_path` (a path walk) on every
  exec, plus a hash lookup for the basename prefilter.

The prefilter (roadmap §2.1) is therefore not an optimization — it is the whole
cost model. For the ~99.9% of execs that are **not** agents, the program must
pay only: tracepoint dispatch + path read + one O(1) basename-hash lookup +
return — **no ringbuf reserve, no userspace wake, no sha256, no argv parse.**
Those expensive steps happen only on a prefilter *hit*, and even then the sha256
and argv fingerprint run **off the hot path** in userspace (roadmap §4.3). If any
of that leaks onto the miss path, the tax compounds across every exec on the box.

### 1.4 What the incumbents actually cost (web-verified)

| Tool | Reported overhead | Conditions | Source |
|---|---|---|---|
| **Tetragon** | **1.68%** CPU (exec tracking); **2.46%** with JSON-to-disk | *Worst case* — building the 6.1.13 kernel, "substantially higher event volume than standard" (Thomas Graf, Isovalent CTO) | [InfoQ, Nov 2023](https://www.infoq.com/news/2023/11/kubernetes-ebpf-tetragon/) |
| **Tetragon** | typically **< 1%** CPU | production / moderately active systems, in-kernel filtering | [InfoQ](https://www.infoq.com/news/2023/11/kubernetes-ebpf-tetragon/) |
| **Falco** (eBPF driver) | **2–5%** CPU, **< 1%** mem/node; overhead ∝ event volume | community K8s benchmarks | [InfoQ eBPF security observability](https://www.infoq.com/articles/ebpf-for-security-observability/) |
| **Falco vs Tetragon vs Tracee** (RITECH 2025 study, 2 vCPU / 4 GB DO nodes, 20 repeats) | **Baseline CPU:** Falco **431.5** millicores, Tetragon **6.5** mcore, Tracee **91.6** mcore. **Under attack:** Falco 433.5, Tetragon 6.9, Tracee 93.7 mcore. **Baseline mem:** Falco 397 MB, Tetragon 635 MB, Tracee 573 MB. All 100% detection, 0% FPR on their attack set | Kubernetes cluster, container-escape / DoS / cryptomining | [Syairozi & Arizal, RITECH 2025 (SCITEPRESS)](https://www.scitepress.org/Papers/2025/142727/142727.pdf) |
| **CrowdStrike Falcon** | **"1% or less of CPU"** (vendor claim) | endpoint sensor, marketed as lightweight | [CrowdStrike Deployment FAQ](https://www.crowdstrike.com/en-us/products/faq/) |

The single most important row is the RITECH study's **Falco 431 millicore
(≈ 0.43 of a core) baseline vs Tetragon's 6.5 millicore baseline** — a ~66× gap
between two eBPF tools doing comparable work. The difference is *where the
filtering happens*: Tetragon filters and aggregates in-kernel and wakes
userspace only on a match; Falco's cost scales with raw event volume because more
of the work crosses into userspace. **Epic B must be architected like Tetragon,
not like Falco** — the in-kernel basename prefilter (§1.3) is precisely what puts
Ardur on the 6-millicore side of that gap. A design that ships raw exec events to
userspace for classification lands on the 431-millicore side and fails the SLO by
two orders of magnitude.

> Caveat on sources: the vendor figures (CrowdStrike ≤1%, Falco community 2–5%)
> are marketing/community numbers, not controlled measurements, and the Tetragon
> 1.68% is explicitly a worst-case kernel-build. The RITECH study is peer-reviewed
> but on small (2 vCPU) nodes with a specific workload. They agree on the *shape*
> (well-filtered in-kernel eBPF exec tracing is low-single-digit-% CPU) but the
> exact number is workload-bound. Ardur must **measure its own**, which is why the
> SLO below is paired with a CI gate, not a citation.

### 1.5 Map memory

Bound and pre-allocate, mirroring the existing guard maps (`process_guard.bpf.c`:
`cgroup_op_policy` 16384, `cgroup_path_allow` 4096, `cgroup_net_allow` 1024,
`cgroup_file_allow` 4096, `enforce_events` 16 KB ringbuf). The new detect path
adds: a basename prefilter set, a known-binary-hash set, and a host-wide event
ringbuf. All fixed-size, no per-exec allocation, no unbounded growth. The event
ringbuf must be larger than the scoped feed's 4 KB (`1 << 12`) because it now
carries host-wide traffic; size it to absorb a build-storm burst and account for
overruns rather than growing.

---

## 2. The reliability half: false-positive / false-negative budget

Detection is a classifier. Its two error modes have **wildly asymmetric
consequences**, and the asymmetry is the entire argument for the fail-safe
posture in §3.

### 2.1 False positive — a non-agent classified as an agent

- **If it only attests (observe-only):** harmless telemetry noise. The cost is
  analyst attention, and the industry baseline for that cost is brutal: the Vectra
  2023 SOC study found teams face **4,484 alerts/day, 83% of them false positives**,
  and analysts cannot process **67%** of daily alerts
  ([Vectra 2023 State of Threat Detection](https://www.vectra.ai/resources/2023-state-of-threat-detection)).
  A host sensor that mislabels ordinary `python`/`node`/`git` execs as agents
  drowns its own signal. Bad, but recoverable.
- **If a binding rule then *enforces* on the false positive:** you break a
  legitimate process. This is the **McAfee DAT 5958** failure mode: on 2010-04-21
  a signature update false-positived the core Windows `svchost.exe` as
  `W32/Wecorl.a` and quarantined it, sending enterprise fleets into reboot loops
  and killing networking (one school district: 5,000+ PCs)
  ([Krebs on Security](https://krebsonsecurity.com/2010/04/mcafee-false-detection-locks-up-windows-xp/);
  [The Register](https://www.theregister.com/2010/04/21/mcafee_false_positive/)).
  A false positive that only *watched* would have been a non-event. The same false
  positive wired to an *action* was a global outage.

**Budget:** an FP on an observe-only class is bounded by alert-fatigue economics
(keep it low, but it degrades gracefully). An FP on any class an operator has
wired to an **enforce** binding rule is bounded by *outage economics* and must be
driven to near-zero **before** that rule is allowed to reference the class.

### 2.2 False negative — a real agent seen as a non-agent

This is the error that matters most for the **product claim** ("we govern the
agents on your host"). A missed agent is ungoverned, silently. Every practical
evasion is a deliberate false negative:

- **Renamed binary** — `cp $(which claude) ./notes && ./notes`. Defeats a
  basename prefilter outright unless the binary-hash set also matches.
- **Static linking / repacking** — changes the sha256, defeating the hash set;
  a self-built or repacked agent has neither a known basename nor a known hash.
- **Wrapper script** — the agent runs as `bash wrapper.sh` / `python launch.py`;
  the exec the kernel sees is the interpreter, not the agent.
- **Interpreter + script (the structural hole)** — `python`/`node` agents *are*
  the interpreter. The basename `python3` is shared by thousands of legitimate
  non-agent execs, so the prefilter faces an impossible choice: match `python3`
  and over-capture the whole system (cost + FP flood, §2.1), or don't and miss
  every interpreter-hosted agent (FN). Argv inspection helps but is exactly what
  a wrapper renames away.
- **Sandboxed / re-nested subprocess** — an agent that spawns its real work inside
  a fresh namespace or a child it double-forks can outrun the ppid/start-time
  reconciliation window (roadmap §2.4, B4).

And detection can be evaded even when the fingerprint is *right*, via TOCTOU:
**Phantom Attack** (Rex Guo & Junyuan Zeng, DEF CON 29, 2021) showed an
unprivileged process can evade syscall monitors by racing the monitor's read of
userspace arguments — yielding **CVE-2021-33505** against Falco (CVSS 7.3, fixed
in v0.29.1), because it read user-space pointers directly from its tracing
program
([Phantom Attack, DEF CON 29 PDF](https://media.defcon.org/DEF%20CON%2029/DEF%20CON%2029%20presentations/Rex%20Guo%20Junyuan%20Zeng%20-%20Phantom%20Attack%20-%20%20Evading%20System%20Call%20Monitoring.pdf);
[Falco advisory GHSA-6v9j-2vm2-ghf7](https://github.com/falcosecurity/falco/security/advisories/GHSA-6v9j-2vm2-ghf7)).
Ardur reading the path from the `linux_binprm` file at `bprm`-commit (roadmap
§2.1) is the *correct* mitigation — a kernel-object read, not a racy user-pointer
read — but the general lesson stands: **a determined agent can evade
exec-fingerprinting, so the FN rate is never zero and must be measured, not
assumed.**

**Budget:** FN is bounded by (a) multi-signal matching (basename **and** hash
**and** argv, not any one alone), (b) the **observability-gap metric (#39)** that
counts execs the prefilter dropped vs. classified, making coverage measurable
rather than asserted, and (c) a maintained labeled corpus (roadmap §4.2, #67) of
positives (Claude Code, Codex, Gemini CLI, Kimi, Grok) and hard negatives
(`node`/`python`/`git`/`bash`). FN is a **standing metric**, not a one-time gate,
because evasion is adversarial and the corpus ages.

---

## 3. Fail-safe posture when detection is uncertain: **observe, never enforce**

The recommendation is unambiguous and it is the load-bearing decision of this
doc: **when detection or classification is uncertain, or adoption cannot complete
cleanly, fall back to observe-only — loudly (emit a telemetry event) — and never
enforce.** Uncertainty resolves to *watching*, never to *acting*.

The justification is the CrowdStrike tax made literal. On 2024-07-19 CrowdStrike
shipped Channel File 291; the sensor expected 20 input fields and the content
provided 21; reading the 21st caused an out-of-bounds read and an invalid page
fault that bugchecked **~8.5 million Windows hosts** into boot loops — the largest
IT outage in history
([CrowdStrike RCA, Channel File 291](https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf);
[Wikipedia: 2024 CrowdStrike outages](https://en.wikipedia.org/wiki/2024_CrowdStrike-related_IT_outages)).
No adversary was involved. An always-on sensor with kernel-level authority over
every process turned an internal data error into a fleet-wide outage **because it
acted on the whole fleet synchronously.** McAfee 2010 (§2.1) is the same story a
decade earlier. **The dominant risk of an always-on host sensor is the sensor,
not the threat.**

This is *why* the roadmap's "default observe-only, enforce only under an operator
binding rule, fail-safe = observe" (roadmap §4.1) is correct, and this doc makes
it a hard rule with the outage precedent attached:

1. **Default is observe-only** for every newly detected process. Detection alone
   never enforces.
2. **Enforcement is opt-in per operator binding rule** (classification + path/cwd
   + trust-tier → profile + enforce), never implicit from a match.
3. **Low classifier confidence → observe**, even if a binding rule would otherwise
   enforce. The rule fires only above the confidence threshold (§4, SLO-6).
4. **Adoption failure → observe.** If the running tree can't be brought into a
   governable cgroup cleanly (roadmap §2.4, B4), fall back to observe-only rather
   than enforce a wrong-blast-radius policy.
5. **Every fallback is loud** — a fail-safe that silently degrades is
   indistinguishable from coverage. Emit the observability-gap / fallback event so
   an auditor can see where the sensor chose to watch instead of act.

The asymmetry is decisive: a missed enforcement (FN → observe) is a *gap in
coverage the operator can see in telemetry*; a wrong enforcement (FP → block) is
*an outage the operator experiences as their own service going down*. When
uncertain, take the visible gap over the invisible outage.

---

## 4. Proposed SLOs for the Epic B slices

Each SLO names the slice it gates and how it is *enforced* (a measurement, not a
promise). These are proposals for the Epic B kickoff to ratify, sized against the
verified numbers in §1–§2.

| # | SLO | Value | Gates | Enforced by |
|---|---|---|---|---|
| **SLO-1** | **Added exec latency, prefilter-miss path** (the common case — every non-agent exec) | **p50 ≤ 2 µs, p99 ≤ 10 µs** added to `execve` | B1 | Exec-storm micro-benchmark in CI with a p99 ceiling. Rationale: baseline `fork+execve` is ~365–2,800 µs (§1.2), so 10 µs is < 3% of even the cheapest exec, and at ≤1,000 execs/s the aggregate is negligible. |
| **SLO-2** | **Aggregate host CPU** from the detect path | **≤ 1% of one core at 1,000 execs/s; ≤ 5% at a 5,000 execs/s build-storm** | B1, B8 | Standing overhead CI job (roadmap §4.3). Rationale: matches CrowdStrike's own ≤1% bar and Tetragon's <1%/1.68%-worst-case (§1.4). **Explicitly rejects** landing in Falco's 431-millicore (0.43-core) baseline territory. |
| **SLO-3** | **Map memory**, detect path | **≤ 16 MB pinned, fixed-size, zero per-exec allocation** | B1 | Map sizes are compile-time constants reviewed in the PR; a runtime assert rejects unbounded growth. Mirrors the existing guard-map budget (§1.5). |
| **SLO-4** | **Ringbuf drop rate** under a build-storm | **Drops counted and surfaced; sustained drop > 0 is an SLO violation, not silent loss** | B1 | Reuse the lost-sample accounting (#100) + observability-gap metric (#39). A drop is a measured coverage gap, never invisible. |
| **SLO-5** | **Classifier precision on any enforce-wired class** | **≥ 0.99 overall; = 1.00 (zero tolerance) on hard negatives** `node`/`python`/`git`/`bash` **before that class may be referenced by an enforce binding rule** | B2, B5 | Labeled-corpus test fixture as the B2 gate (roadmap §4.2). Observe-only classes may run looser; the zero-tolerance bar applies only where a match can *block*. Bounds the McAfee/§2.1 outage mode. |
| **SLO-6** | **Classifier confidence threshold for enforce** | Enforce binding rules fire **only above a documented confidence threshold**; below → observe-only | B5 | The threshold is a policy input to the binding rule; below-threshold matches emit an observe event, never an enforce. Implements §3.3. |
| **SLO-7** | **Recall on the known-agent corpus** | **≥ 0.95 at the B2 gate**, tracked continuously thereafter via the observability-gap metric | B2, B8 | Corpus recall test at B2; #39 metric as a standing dashboard afterward. FN is adversarial and the corpus ages, so this is a standing metric (§2.2), not a one-time pass. |
| **SLO-8** | **macOS ESF critical-path budget** | **Detection via `NOTIFY` only (0 added critical-path latency). `AUTH` reserved for the enforce tier with p99 response ≤ 5 ms; fail-open-to-observe if the supervisor can't decide in budget** | B6 | ESF client design review. Rationale: missing the ES `AUTH` deadline gets the client **killed by the OS** (`OS_REASON_ENDPOINTSECURITY`); deadlines are per-message Mach-time and effectively 30–60 s hard, but a monitor that holds the process anywhere near that is itself the outage. Detection must never touch AUTH. ([Apple ES deadline discussion](https://developer.apple.com/forums/thread/130083)) |

Two SLOs are the ones that actually protect the product:
- **SLO-2** keeps Ardur on the Tetragon (6-millicore) side of the eBPF cost gap
  rather than the Falco (431-millicore) side — the difference between a sensor an
  operator forgets is running and one they uninstall.
- **SLO-5 + SLO-6 + §3** are the anti-CrowdStrike-tax controls: enforcement only
  on a high-precision, high-confidence, operator-opted-in class, everything else
  observed. This is what keeps a classifier error a *telemetry* event instead of
  an *outage*.

---

## 5. Recommendation summary

**Recommended SLOs (for kickoff ratification):**
- **Exec latency:** p50 ≤ 2 µs / p99 ≤ 10 µs added on the prefilter-miss path,
  CI-gated with an exec-storm benchmark (SLO-1).
- **CPU:** ≤ 1% of a core at 1,000 execs/s (≤ 5% at a 5,000-exec build storm),
  standing CI job — architect in-kernel-filtered like Tetragon, never
  ship-to-userspace like Falco (SLO-2).
- **False positives:** classifier precision ≥ 0.99, and **= 1.00 on
  `node`/`python`/`git`/`bash`** before any enforce binding rule may reference the
  class (SLO-5); enforce only above a confidence threshold (SLO-6).
- **False negatives:** recall ≥ 0.95 at the B2 corpus gate, then a *standing*
  observability-gap metric (#39), because evasion is adversarial (SLO-7).
- **Fail-safe = observe, never enforce, and loudly** when confidence is low or
  adoption is unsafe (§3).
- **macOS:** detect on `NOTIFY` only; reserve `AUTH` for enforce with a p99 ≤ 5 ms
  response and fail-open-to-observe (SLO-8).

**Biggest evasion risk:** the **interpreter-hosted agent** (`python`/`node` CLIs
launched via a wrapper or renamed script). The exec the kernel sees is a generic
interpreter basename shared by thousands of legitimate non-agent processes, so a
basename prefilter is forced to choose between over-capturing the whole system
(cost blow-up + FP flood) and missing the agent entirely (silent FN) — and argv
inspection, the obvious fallback, is exactly what a wrapper renames away. Combined
with trivial renaming and static-linking to defeat the basename/hash sets, this is
the structural hole where the product claim ("we govern the agents on your host")
is most likely to be quietly false. It cannot be closed by fingerprinting alone;
it must be *measured* by the observability-gap metric (#39) and disclosed
honestly, never asserted away. **This is the single most important input to the
B2 classification gate and the reason SLO-7 is a standing metric rather than a
one-time pass.**

---

## 6. What stays honest (claim boundary)

- The cost numbers cited (§1.4) are a mix of vendor claims, community benchmarks,
  and one peer-reviewed study on small nodes; they establish the *shape* (low
  single-digit % CPU for well-filtered in-kernel eBPF) but Ardur must **measure
  its own** under SLO-1/SLO-2, not inherit a citation.
- The FN rate is **never zero**. Exec-fingerprinting is evadable by design
  (renaming, static linking, wrappers, interpreter-hosting, TOCTOU). Epic B must
  report coverage as measured by #39, never claim completeness.
- The fail-safe is **observe, not block.** An always-on host sensor's dominant
  risk is its own misfire (McAfee 2010, CrowdStrike 2024), so uncertainty resolves
  to watching. Enforcement on an un-declared workload is opt-in per operator rule.
- These SLOs bound the *front half* (detect→classify) and the enforce decision
  seam only. They do not alter Epic A's enforcement ceilings or the honest
  per-OS boundaries in the roadmap doc.

---

## Sources

- [InfoQ — Tetragon 1.0 performance (1.68% / 2.46% worst-case)](https://www.infoq.com/news/2023/11/kubernetes-ebpf-tetragon/)
- [InfoQ — eBPF for security observability (Falco 2–5% CPU)](https://www.infoq.com/articles/ebpf-for-security-observability/)
- [Syairozi & Arizal, "Comparative Analysis of eBPF-Based Runtime Security Monitoring Tools," RITECH 2025 (SCITEPRESS)](https://www.scitepress.org/Papers/2025/142727/142727.pdf)
- [CrowdStrike Deployment FAQ (≤1% CPU claim)](https://www.crowdstrike.com/en-us/products/faq/)
- [Brendan Gregg / iovisor — bcc execsnoop man page (exec rate < 1000/s)](https://github.com/iovisor/bcc/blob/master/man/man8/execsnoop.8)
- [Ubuntu — execsnoop-bpfcc man page](https://manpages.ubuntu.com/manpages/focal/en/man8/execsnoop-bpfcc.8.html)
- [lmbench — process creation latency (USENIX)](https://www.usenix.org/legacy/publications/library/proceedings/usenix01/freenix01/full_papers/loscocco/loscocco_html/node16.html)
- [Red Hat Developer — measuring BPF performance (kprobe cycle costs)](https://developers.redhat.com/articles/2022/06/22/measuring-bpf-performance-tips-tricks-and-best-practices)
- [iximiuz Labs — tracepoints vs kprobes vs fprobes](https://labs.iximiuz.com/tutorials/ebpf-tracing-46a570d1)
- [Tetragon events documentation (field event rates)](https://tetragon.io/docs/concepts/events/)
- [Vectra 2023 State of Threat Detection (4,484 alerts/day, 83% FP)](https://www.vectra.ai/resources/2023-state-of-threat-detection)
- [Krebs on Security — McAfee DAT 5958 false positive (2010)](https://krebsonsecurity.com/2010/04/mcafee-false-detection-locks-up-windows-xp/)
- [The Register — McAfee false positive bricks enterprise PCs (2010)](https://www.theregister.com/2010/04/21/mcafee_false_positive/)
- [CrowdStrike — Channel File 291 Root Cause Analysis (2024)](https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf)
- [Wikipedia — 2024 CrowdStrike-related IT outages (8.5M hosts)](https://en.wikipedia.org/wiki/2024_CrowdStrike-related_IT_outages)
- [Phantom Attack — Evading System Call Monitoring, DEF CON 29 (2021)](https://media.defcon.org/DEF%20CON%2029/DEF%20CON%2029%20presentations/Rex%20Guo%20Junyuan%20Zeng%20-%20Phantom%20Attack%20-%20%20Evading%20System%20Call%20Monitoring.pdf)
- [Falco security advisory GHSA-6v9j-2vm2-ghf7 (CVE-2021-33505, TOCTOU)](https://github.com/falcosecurity/falco/security/advisories/GHSA-6v9j-2vm2-ghf7)
- [Apple Developer Forums — Endpoint Security AUTH deadline behavior](https://developer.apple.com/forums/thread/130083)
