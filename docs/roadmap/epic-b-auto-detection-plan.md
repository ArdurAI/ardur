# Epic B — Transparent Auto-Detection & Auto-Governance

Status: **planning document with a completed bounded Linux classification
slice** (updated 2026-07-17). Issue #67 now has exact-name prefiltering,
native and kernel-bound launcher content matching, a two-stratum regression
gate, and measured overhead evidence. Host-wide feeding, attestation,
adoption, governance, and non-Linux sources remain separate slices. This plan
proposes that remaining work, and every enforcement slice inherits the
existing security gates and the honest
enforcement boundary in `docs/security-model.md` ("what the reference proxy
enforces today" is the conservative claim).

Tracker: Epic A #63. Epic B issues: #67 (auto-recognition), #68 (auto-attest),
#69 (auto-govern), #70 (macOS ESF), #71 (Windows), and #39 (Linux
observability-gap metric).

---

## 1. Where Epic A leaves us, and what Epic B must invert

Epic A shipped an always-on, CI-proven Linux enforcement stack, but it is
**wrapper-scoped**: governance only reaches a process that `ardur run` launched.
The launch path (`run_bridge.run_governed`) does, in order: generate a keypair,
issue a **Mission Passport** with a human-supplied mission + allowed/forbidden
tools, start the governance proxy + session, **create a dedicated cgroup**
(`kc.create_run_cgroup(session_id)`), launch the agent *into* that cgroup, adopt
its PID, then `apply_policy` lowered BPF plans onto that cgroup.

The detection eBPF reflects that ordering. `process_exec.bpf.c` gates every
event on `cgroup_allowed(cgroup_id)` (a hash map the wrapper populates) and
emits only `struct ardur_process_event{ pid, ppid, tid, pid_namespace_id,
cgroup_id, comm[16], executable_basename[64] }` — **no argv, full binary path,
or uid**. It is a scoped
correlator feed, not a host sensor.

Epic B inverts the control flow. A CrowdStrike-style sensor must govern agents
**nobody launched under Ardur**: the process already exists, in a cgroup Ardur
did not create, with no passport and no human-declared mission. The pipeline
becomes:

```
   host-wide exec  ──►  classify  ──►  auto-attest      ──►  adopt + attach  ──►  auto-govern
   (all execs,          (#67:         (#68: provenance       (bring a running     (#69: policy from
    ungated,             fingerprint   passport, NOT a        tree into a           a profile registry,
    prefiltered)         → agent-class mission grant)         governable cgroup)    default observe-only)
```

Everything downstream of "attach" is **existing Epic A machinery reused
unchanged** — `apply_policy` (#96), the BPF-LSM tier-1 guard (#101), the
hash-chained `enforce_events` (#100), and the designed seccomp tier-2 (#104).
Epic B builds only the **front half** (detect → classify → attest → adopt) and
one new decision seam (policy without a human). That is the scoping discipline
for the whole epic: **do not re-implement enforcement; feed it.**

The 2026-07-11 implementation pass was reconciled against the current Host
Agent architecture/roadmap and Linux gap-analysis project notes before code
changes began.

### 1.1 Issue #67 completion checkpoint (2026-07-17)

The bounded Linux classification slice now delivers:

- `process_exec.bpf.c` keeps the existing cgroup allowlist and adds separate,
  disabled-by-default exact-`comm` and successful-exec basename hash-map
  admission paths for exec events only.
- The embedded registry recognizes the official command names `claude`,
  `codex`, `gemini`, and `kimi`; hard negatives include generic runtimes and
  shells. Operator allow/deny classes are applied before populating the map.
- Userspace labels every match heuristic, low-confidence, and observe-only. It
  neither persists unrouted candidates as session evidence nor attests, adopts,
  authorizes, or governs the process.
- Each registry signal and BPF map has a 64-name capacity. The successful-exec
  path emits only a bounded basename, never its parent path. The canonical
  registry digest is release metadata, not independent provenance.
- An optional daemon-owned registry privately compares bounded SHA-256 values
  for native `/proc/<pid>/exe` objects and kernel-bound script-launcher objects.
  Launcher matches require an allowlisted final-interpreter profile; mutable
  cmdline is only a locator and cannot establish object identity.
- A fixed asynchronous worker pool reports explicit fail-low outcomes. Resolver
  and observer panic tests prove that the same one-worker pool completes a
  second job after recovery.
- The v0.2 maintained corpus reports 28 name-only cases separately from eight
  synthetic native/launcher content transitions. Name-only precision/recall is
  never inflated by content matches, and a digest mismatch must not promote
  confidence.
- The paired real-Linux benchmark measures the exact candidate against the
  exact target-branch reference on one runner and fails on reviewed latency,
  CPU, RSS, loss, partial-accounting, or fingerprint-work thresholds.

This closes #67's bounded classifier contract, not the whole Epic B pipeline.
Host-wide observability and gap accounting remain #39/B1; provenance
attestation and policy are #68/#69; macOS, Windows, and Apple entitlements are
tracked in #70/#71/#106. The corpus is project-maintained regression evidence,
not population accuracy, provenance, or identity assurance.

---

## 2. Per-OS detection & enforcement mechanism

The three OSes do not share a substrate. Detection *and* the enforcement
ceiling differ per OS; the plan states each honestly rather than implying
Linux-grade enforcement everywhere.

### 2.1 Linux — eBPF exec-trace → auto-attest → cgroup + BPF-LSM/seccomp

- **Detect.** Add a **host-wide** exec path alongside the current scoped one:
  a `sched_process_exec` (or `tracepoint/syscalls/sys_enter_execve` +
  `bprm`-committed CO-RE read) program that runs **ungated** by
  `cgroup_allowed`, and capture what classification needs — `argv[0]`/resolved
  binary path (via `bpf_d_path` on the `linux_binprm` file, the sleepable-hook
  pattern already used by `guard_file_open`), enough leading argv for fingerprint
  patterns, and `uid`. Keep the *scoped* program for the correlator feed
  unchanged.
- **Prefilter in-kernel (performance-critical, §4.3).** Host-wide exec fires on
  *every* exec on the box. Gate ringbuf emission behind an in-kernel hash-map
  lookup of known-agent binary **basenames** (and a small hash-of-binary set) so
  ~all non-agent execs are dropped before they cost a ringbuf slot or a
  userspace wake.
- **Attest.** Daemon issues a *provenance* passport (§3) signed by the host key,
  folded into the existing evidence log + `enforce_receipt_chain`.
- **Attach.** Reuse `apply_policy` → double-buffered `cgroup_op_policy` maps →
  `process_guard.bpf.c` tier-1 (`bprm_check`/`file_open`/`socket_connect`) and
  the tier-2 seccomp user-notify supervisor (#104) for policy dimensions
  BPF-LSM can't decide in-kernel. **No new enforcement mechanism** — only a new
  way to reach it (§2.4).

### 2.2 macOS — Endpoint Security Framework System Extension

- **Detect.** No eBPF/bpffs. Process-launch detection uses ESF
  (`es_new_client`, `ES_EVENT_TYPE_NOTIFY_EXEC`) from a **System Extension** —
  a materially bigger lift than a daemon, requiring the
  `com.apple.developer.endpoint-security.client` entitlement (Apple-approved,
  not self-servable) + notarization. That entitlement filing has external lead
  time and is **already tracked in #106 — file it now, in parallel with B1**,
  regardless of when the extension code lands.
- **Enforce (different ceiling).** macOS has **no cgroups, no BPF-LSM, no
  seccomp**. The enforcement primitives are ESF **AUTH** events
  (`ES_EVENT_TYPE_AUTH_EXEC`, `AUTH_OPEN`, `AUTH_SIGNAL`) answered within the
  ES deadline, plus a **Network Extension** content filter for egress. So the
  macOS tier map is: ESF-NOTIFY = detect; ESF-AUTH = coarse exec/file gating;
  NEFilterDataProvider = egress. There is **no per-cgroup op policy**; policy is
  scoped per audit-token/process. Classification (#67) and attestation (#68)
  reuse the Linux logic; only the attach/enforce layer is macOS-specific.
- **Critical constraint.** AUTH events are **synchronous on the process's
  critical path** — miss the deadline and the OS kills the ES client. Use
  NOTIFY for detection; reserve AUTH strictly for the enforce tier (§4.3).

### 2.3 Windows — ETW (detect + attest only)

- **Detect.** `Microsoft-Windows-Kernel-Process` ETW provider (or a WMI
  `Win32_ProcessStartTrace` fallback) for exec events. ETW is **telemetry, not
  a control point.**
- **Enforce (future/out-of-scope for B7).** Blocking requires a minifilter
  driver, a WFP callout, or WDAC — a driver-signing lift beyond this epic. B7
  ships **detect + classify + attest + telemetry** and documents the enforcement
  gap honestly (Windows governance is observe-only until a driver track is
  funded). #71 already blocks Windows on macOS ESF landing first.

### 2.4 Composition with the existing enforcement tiers

The **adopt-and-attach** step is the only genuinely new enforcement-adjacent
mechanism. Two ways to bring an *already-running* process under governance:

1. **Migrate** the detected PID (and its already-spawned descendants) into an
   ardur-managed cgroup, then `apply_policy` as today. Correct steady-state, but
   racy: the agent may have already forked children into the old cgroup, and
   cgroup migration is per-PID.
2. **Attach in place**: bind a policy plan to the process's **existing** cgroup.
   Zero migration race, but that cgroup may contain unrelated processes, so the
   policy blast radius is wrong.

Recommend **(1) with a bounded reconciliation sweep** (adopt the root, then walk
`/proc` descendants by ppid/start-time within a grace window, same window logic
the `Correlator` already uses), and **fail safe to observe-only** if the tree
can't be adopted cleanly. Everything after attach is unchanged Epic A code.

---

## 3. Trust & attestation for agents nobody launched under Ardur

This is the conceptual core and the place most likely to be over-claimed.

**Today, trust originates from a human.** The wrapper's Mission Passport encodes
an operator's *intent* — the mission, the allowed/forbidden tools, the resource
scope. An auto-detected agent has **none of that**. There is no mission, no
declared scope, no opt-in.

So an auto-issued attestation must be a **provenance attestation, not a mission
grant**, and the schema/verifier must keep the two un-confusable:

| | Mission Passport (wrapper) | Provenance Passport (auto-detect) |
|---|---|---|
| Asserts | operator *intent* (this agent may do X) | daemon *observation* (this binary ran here at T) |
| Fields | mission, allowed/forbidden tools, resource_scope, TTL | binary path + sha256, argv fingerprint, launch ancestry (ppid chain), cgroup id, uid, detection ts, classifier id + **confidence**, host identity |
| Signed by | session key from operator-provided keypair | **daemon host key** |
| Downstream meaning | COMPLIANT/VIOLATION against declared policy | *what was seen* — **intent is `INSUFFICIENT_EVIDENCE`** until an operator binds a mission |

The load-bearing rule, and the one that ties Epic B to the paper lane's
honest-abstention discipline: **absence of a human mission must resolve to
`INSUFFICIENT_EVIDENCE` for intent, never to COMPLIANT.** A provenance passport
proves an agent was observed and governed; it must be structurally unable to
launder "we saw it" into "it was authorized." The verifier must reject any
attempt to present a provenance passport where a mission grant is required, and
the evidence schema must carry a distinct type so an auditor (and AuditBench)
can tell an auto-attested session from an operator-declared one.

Policy therefore cannot come from the agent (it never opted in). It comes from
an **operator-configured profile registry** keyed by agent-class (§5, B5),
defaulting to **observe-only**. This mirrors the CrowdStrike model precisely:
the sensor detects and reports universally; *prevention* is a policy an operator
turns on per group, not a default the sensor imposes on first sight.

---

## 4. The hard problems

### 4.1 Policy selection for an un-wrapped agent

No mission ⇒ what policy? Options, in increasing aggressiveness:

- **Observe-only (default).** Attest + telemetry + correlator, **no
  enforcement.** Safe, always correct, zero outage risk. This is the default
  for every newly detected agent.
- **Inferred scope.** Reuse the wrapper's heuristic — `resource_scope =
  [cwd, cwd/*]` from the process's working directory — as a *suggested* profile
  an operator can promote, never auto-enforced.
- **Profile-registry enforce.** `ardur_profile.py`-style default profile per
  agent-class, applied **only** when an operator has configured a
  classification→profile **binding rule** (e.g. "Claude Code in /repo ⇒
  strict-repo profile, enforce"). Absent a rule, stay observe-only.

Decision: **fail-safe is observe, not block.** Enforcing a guessed policy on an
un-declared workload is how a security sensor causes an outage. Enforcement on
auto-detected agents is opt-in per operator binding rule, never implicit.

### 4.2 False-positive / false-negative detection

- **False positive (non-agent classified as agent).** If it only attests →
  harmless noise. If a binding rule then *enforces* → you can break a legitimate
  process. Bounded by: conservative multi-signal fingerprint with a **confidence
  score**, operator allow/deny **overrides**, and observe-before-enforce so a
  misclassification is visible in telemetry before it can block anything.
- **False negative (agent seen as non-agent).** Missed governance — the failure
  that matters most for the product claim. Bounded by: a maintained fingerprint
  corpus (#67), the observability-gap metric (#39) that *counts* execs the
  prefilter dropped vs. classified so coverage is measurable, and periodic
  audit of "unclassified interpreter+script" execs (python/node agents hide
  behind a generic interpreter basename).
- Set explicit **precision/recall targets** on a labeled corpus (positives:
  Claude Code, Codex, Gemini CLI, Kimi, Grok; hard negatives: plain
  `node`/`python`/`git`/`bash`). Ship the corpus + thresholds as the B2 gate.

### 4.3 Performance / overhead

- **Linux.** Host-wide exec tracing is on **every** exec system-wide. Budget:
  sub-microsecond added exec latency; the in-kernel basename prefilter (§2.1)
  must drop ~99.9% of execs before any ringbuf write. Reuse the existing
  bounded-ringbuf + lost-sample accounting (#100) for backpressure. Ship an
  **overhead CI gate** (exec-storm micro-benchmark, p99 latency ceiling) so
  regressions can't sneak in.
- **macOS.** ESF AUTH is synchronous with a hard OS deadline — **only** the
  enforce tier may use AUTH; detection uses NOTIFY. An over-broad AUTH
  subscription that misses the deadline gets the client killed by the OS.
- **General.** Classification (sha256 of the binary, argv parsing) must run
  **off** the hot path — the kernel/ESF layer emits a cheap event; userspace
  does the expensive fingerprinting asynchronously.

### 4.4 Security-hardening prerequisite (gating)

Auto-detection **expands the daemon's authority** from "cgroups an operator
registered" to "any process on the host," so the in-flight control-socket
authorization bugs become far more dangerous under Epic B:

- **#108** — `apply_policy`/`set_kill_switch` lack per-session peer
  authorization (IDOR / global enforcement kill); `register_session` trusts a
  client-supplied `cgroup_id`.
- **#109** — stale policy state: tightening a policy is silently ineffective;
  allowlists never revoked/pruned.
- **#110** — concurrent `apply_policy` races the double-buffer swap.

If the daemon starts attesting and attaching policy to processes it wasn't told
about, an unfixed #108 means a sandboxed agent could rewrite or kill the
governance applied to it. **#108/#109/#110 are a hard gate on any Epic B slice
that attests or enforces** (B3+). B1/B2 (detect + classify, observe-only) can
proceed in parallel.

---

## 5. Sliced delivery plan (B0…B8)

Each slice states its dependency and **what it must prove** (its acceptance
gate). Slices are sized to land like the Epic A slices — one reviewable PR each,
CI-proven, no silent under-enforcement.

| Slice | Scope | Depends on | Must prove |
|---|---|---|---|
| **B0** (gate) | Land security hardening **#108 / #109 / #110** before the daemon acts on unowned processes | — | Per-session peer authz on `apply_policy`/`set_kill_switch`; verified `cgroup_id` ownership; stale-slot + allowlist revocation; per-cgroup apply serialization. Regression tests from each issue's PoC pass. |
| **B1** | **Linux host-wide exec detection** + observability-gap metric (**#39**). Ungated `sched_process_exec` path capturing binary path/argv/uid; in-kernel basename prefilter; keep the scoped correlator feed intact | — | Every known-agent exec on the host is observed with **near-zero false-negatives** on the corpus; non-agent execs dropped in-kernel; measured exec-latency overhead under the CI budget; observability-gap metric emits (execs dropped vs. surfaced). **No attest, no enforce.** |
| **B2** | **Classification library (#67, bounded Linux contract implemented).** Exact `comm`/successful-exec basename candidate plus optional native or kernel-bound launcher SHA-256 → agent class + low/medium heuristic confidence; operator allow/deny override | B1 for host-wide feeding; current scoped/opt-in path is independently usable | Separate name-only precision/recall and content-transition gates pass on the maintained corpus; generic-runtime hard negatives are not misclassified; mismatches never promote confidence; native and interpreter-bound launcher methods are covered; override lists are tested. |
| **B3** | **Auto-attestation (#68).** Daemon issues a **provenance passport** (§3), schema-distinct from mission passports, host-key signed, folded into evidence log + `enforce_receipt_chain`. Observe-only | B0, B2 | An un-wrapped agent gets a verifiable provenance record; the verifier **rejects** using it as a mission grant; auto- vs. operator-declared sessions are distinguishable in evidence (AuditBench-legible); intent resolves to `INSUFFICIENT_EVIDENCE`. |
| **B4** | **Adopt-and-attach.** Migrate a running process **tree** into an ardur-managed cgroup (bounded ppid/start-time reconciliation sweep), reusing `apply_policy`; fail safe to observe-only if adoption is unsafe | B0, B1 | A running tree is brought under a governable cgroup without losing already-spawned children and without the #110 race; unsafe adoption falls back to observe-only, loudly. |
| **B5** | **Auto-govern (#69).** classification → **profile registry** → policy plan through tier-1 BPF-LSM + tier-2 seccomp; **default observe-only**, enforce only under an operator binding rule. End-to-end auto-detect→enforce demo (analogue of `enforce-e2e`) | B2, B3, B4, **#104** (tier-2), **#105** (file-op allowlist reconcile) | Unmodified agent launched with no wrapper is detected, attested, and — under a configured binding rule — enforced (a forbidden op → `EPERM` + `enforce_event`); with no rule, observed-only; fail-safe = observe. |
| **B6** | **macOS detection (#70 / #106).** ESF System Extension, `NOTIFY_EXEC` → reuse B2 classifier + B3 attest. Enforce tier = ESF `AUTH_EXEC` + Network Extension egress (coarser than Linux) | B2, B3; **#106 Apple entitlement (parallel external track — start at B1)** | Detect + attest parity on macOS; enforcement scoped honestly to ESF/NE capabilities; AUTH deadline respected (no OS-kill of the client). |
| **B7** | **Windows detection (#71).** ETW `Kernel-Process` provider → detect + classify + attest + telemetry. **Enforcement explicitly out-of-scope** (documented driver gap) | B6 (per #71 ordering), B2, B3 | Detect + attest parity on Windows; the enforcement gap is documented, not implied-away; governance is observe-only on Windows until a driver track exists. |
| **B8** | **Hardening & scale (continuous).** False-positive governance UX (override/confidence tuning), overhead CI gate as a standing job, nested/multi-agent launch correlation, revocation of auto-issued provenance passports | B5 | Overhead budget enforced in CI; operator can correct a misclassification without a redeploy; auto-issued passports are revocable; nested agent launches attributed correctly. |

### Dependency graph

```
   #108/#109/#110 ─── B0 ───────────────┐ (gates all attest/enforce)
                                         │
   B1 (detect+#39) ──► B2 (classify) ──► B3 (attest) ─┐
        │                   │                          ├─► B5 (auto-govern) ──► B8
        └────────────► B4 (adopt) ───────────────────┘        ▲
                                          #104 + #105 ─────────┘  (tier-2 + file-op)

   B2 + B3 ──► B6 (macOS ESF) ──► B7 (Windows ETW, detect-only)
                  ▲
        #106 Apple entitlement filing (external lead time — start during B1)
```

Critical path to the first real "no-wrapper enforcement" demo:
**B0 → B1 → B2 → B3 → B4 → B5** (with #104/#105 landing before B5). macOS/Windows
(B6/B7) fork off after B2/B3 and are paced by the Apple entitlement, so **file
#106 at B1 start** even though the extension code lands much later.

---

## 6. What stays honest (claim boundary)

- Epic B **reuses** Epic A's enforcement; it does not add a second enforcement
  engine. The new surface is detect → classify → attest → adopt + one policy
  seam.
- An auto-issued passport attests **provenance, not intent**. No auto-detected
  session may be reported as policy-COMPLIANT on the basis of detection alone.
- Enforcement on un-wrapped agents is **opt-in per operator binding rule**;
  the sensor's default is observe-only, and the fail-safe is observe, not block.
- Per-OS enforcement ceilings differ (Linux BPF-LSM+seccomp > macOS ESF/NE >
  Windows detect-only). State the ceiling per OS; do not imply Linux-grade
  prevention on macOS/Windows.
- No slice past B0 that attests or enforces may land while #108/#109/#110 are
  open. Detection/classification (B1/B2, observe-only) may proceed in parallel.

## 7. Open questions for the Epic B kickoff

1. Adopt-and-attach (B4): migrate-into-managed-cgroup vs. attach-in-place — pick
   the default and the fallback ordering; confirm the descendant-reconciliation
   window against the Correlator's existing grace logic.
2. Provenance-passport schema: extend `MissionPassport` with a type discriminator
   vs. a separate credential type. Verifier changes needed to keep the two
   un-confusable (§3).
3. Profile registry (B5): shape of the operator binding-rule DSL
   (classification + path/cwd + trust-tier → profile + enforce|observe).
4. Reconcile with Notion Epic-B context (not reachable this pass).
5. macOS entitlement (#106): confirm filing is initiated at B1 start given the
   external lead time.
