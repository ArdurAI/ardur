# Epic B — Slice Plans B2–B7 (classify → attest → adopt → govern → macOS → Windows)

Status: **planning document only** (2026-07-03). Read-only pass; no code changed.
File-level build plans for the Epic B slices after B1 (host-wide Linux
detection). Proposes work; authorizes none; inherits the honest enforcement
boundary in `docs/security-model.md`.

Parents / inputs:
- Epic B slice plan — `docs/roadmap/epic-b-auto-detection-plan.md` (#114, merged).
- B1 detail — `docs/roadmap/epic-b-b1-linux-detection-plan.md` (#120, open).
  B2–B5 build directly on B1's seams: `RingbufDetectSource` /
  `detect_source_linux.go`, `detect_decode.go`, `detect_prefilter_linux.go`
  (`SeedAgentBasenames`), `detect_observability_linux.go`, the
  `ardur_detect_event` struct (`resolved_path`/`argv`/`uid`/`class_hint`), and
  `ardur-detect-smoke`.
- Policy-selection research — `docs/research/epic-b-policy-selection.md` (#116).
  Supplies the **AG-0…AG-4 posture ladder**, the **binding registry DSL**, the
  **synthesized-mission (shadow) model**, the **two-claim verifier** semantics,
  and **deltas D1–D7**. B3/B5 implement it.
- Cost/reliability SLOs — `docs/research/epic-b-performance-fp-budget.md` (#117).
  **SLO-5/-6/-7** gate B2/B5; **SLO-8** gates B6.
- B0 hardening (#108/#109/#110) — **merged (#115)**. Every new daemon control
  method below routes through its per-peer authorization.
- Epic A integration gaps — **#104** (seccomp tier-2, B5 hard dep), **#105**
  (file-op allowlist reconcile, B5 hard dep), **#121/#122/#124** (enforce
  reliability — B5 *trustworthiness* leans on these), **#123** (kill-switch
  attestation — B3 completeness). Tracked in the Epic A completion assessment
  (#125).

> **Research-gap note.** No dedicated **Linux-detection/fingerprinting** research
> doc and no **macOS/Windows detection** research doc are merged or open
> (`gh pr list` shows only the two merged research docs + the B1 plan). B2's
> fingerprint design and B6/B7 below are grounded in the roadmap §2.2/§2.3, #117
> §2.2 (evasion taxonomy), the existing `es_client_darwin.go` scaffolding, and
> #106 — **reconcile against those research docs if their PRs land before the
> slice starts.**

---

## Invariants carried through every slice (do not weaken)

1. **Provenance passport ≠ mission grant.** An auto-issued credential attests
   *what was observed* (binary+hash, argv, ancestry, cgroup, uid, classifier +
   confidence, host id), signed by the **daemon host key** — never operator
   intent. Schema-distinct from `MissionPassport`; the verifier must **reject**
   presenting a provenance passport where a mission grant is required.
2. **`INSUFFICIENT_EVIDENCE` for intent, never `COMPLIANT`.** Absence of a human
   mission resolves `mission_compliance` to `INSUFFICIENT_EVIDENCE`. An operator
   binding rule declares intent about a **class**, not a session, so it can only
   satisfy the separate `class_policy_compliance` claim (policy research §8).
   The two claims never merge.
3. **Observe-first; enforce only on a declaration; fail-safe = observe.** Default
   for a detected agent is AG-1 observe; for a *classified* agent AG-2 shadow
   (permissive, cannot block); enforcement exists **only** at AG-3 under an
   operator binding rule. Every uncertainty (low confidence, adoption failure,
   attach failure, hash drift) descends the ladder, **loudly**.
4. **Loud-abort inversion.** Wrapped `--enforce` kills the agent if policy can't
   install. Auto-governance **cannot** kill what it didn't start and nobody
   asked it to kill — so an enforce-binding that can't attach **falls to shadow,
   loudly**, never runs a wrong-blast-radius block.
5. **Every fail-safe is a measured event.** Silent degradation is
   indistinguishable from coverage. Ladder descents, drops, and attach failures
   emit evidence + feed the #39 observability-gap metric.

---

## B2 — Classification (agent-recognition, #67)

### Goal
Turn a B1 `ardur_detect_event` (resolved path + leading argv + uid + comm) into
`{agent_class, confidence}` with an operator override, off the exec hot path.
Detection said "an agent-basename binary ran"; B2 says "it is `claude-code` at
0.97, or it is not an agent." **Still observe-only** — no attest (B3), no adopt
(B4), no policy (B5).

### Files
| File | Add/Change | What |
|---|---|---|
| `python/vibap/agent_classifier.py` | **add** | The classifier: multi-signal static fingerprint over `(resolved_path basename, binary sha256, argv patterns, interpreter+script resolution)` → `AgentClass` + confidence. Pure function of a detect record; no I/O on the hot path. |
| `python/vibap/agent_corpus/` | **add** | The **labeled corpus** as a versioned fixture: positives (`claude`, `claude-code`, `codex`, `gemini`, `kimi`, `grok`) and hard negatives (`node`, `python`, `python3`, `git`, `bash`, `make`, `cc1`, `ld`). Each entry = `{argv, resolved_path, expected_class, expected_conf_band}`. This corpus is the B2 gate and the seed source for B1's `agent_basenames`. |
| `python/vibap/agent_fingerprints.py` | **add** | The fingerprint rule table (basename set, sha256 pins where known, argv regexes, interpreter+script heuristics). Versioned; the “fingerprint library” #67 asks to maintain. |
| `python/vibap/agent_overrides.py` | **add** | Operator allow/deny/reclassify override store (`ardur agents classify <pid|hash> --as <class>` / `ignore <hash>`), hashed into evidence (policy research §7). Registry-adjacent state, root/hub-gated. |
| `go/pkg/kernelcapture/detect_classify_bridge.go` | **add** | Daemon-side seam: hand a decoded `DetectEvent` to the classifier (in-process Go port **or** an out-of-band call to the Python classifier — decision below) and attach `{class, confidence}` to the telemetry record. Off the hot path (consumer loop, not the BPF program). |
| `python/vibap/behavioral_fingerprint.py` | **change (compose, optional)** | The existing session-start **behavioral** canary fingerprint answers "right crypto identity, wrong behavioral identity"; B2's **static exec** fingerprint answers "which agent class." They compose — behavioral requires a proxy in the loop (absent for un-wrapped agents), so B2 is static-only; note the composition seam for post-adoption (B4). |
| `python/vibap/cli.py` | **change** | Add `ardur agents list` / `classify` (read-only slice of the `ardur agents` family; `bind`/`review` land in B5). |
| `.github/workflows/tests.yml` | **change** | Add the corpus precision/recall test as a required check. |

### Key design decisions
- **Static, not behavioral.** No proxy is in the loop for an un-wrapped agent, so
  B2 fingerprints the exec (path/hash/argv), not model behavior. Behavioral
  fingerprinting (`behavioral_fingerprint.py`) re-enters only *after* adoption
  (B4) if the session is wrapped (AG-4).
- **Multi-signal, conservative (the #117 §2.2 evasion taxonomy).** No single
  signal decides: basename **and** hash **and** argv. A renamed binary
  (`cp claude notes && ./notes`) fails the basename signal but may match the
  hash; a repacked binary fails both and lands **unclassified → AG-1**, not a
  false class.
- **The interpreter hole is measured, not closed.** `python3`/`node` agents share
  a basename with thousands of non-agents (#117 §5). B2 attempts argv-based
  disambiguation (`python -m claude_code …`) but **must not** raise confidence
  above the enforce threshold on interpreter-hosted matches unless a strong argv
  or hash signal is present; the residual gap is reported via #39, never asserted
  away. B1 deliberately kept interpreter basenames out of the kernel prefilter —
  B2 is where any interpreter handling lives, in userspace, where argv is cheap.
- **Confidence is first-class and abstention is honest.** The classifier may
  return `unknown` with a confidence — the honest-abstention discipline extended
  into the classifier itself (policy research §7). `unknown` → AG-1.
- **Go port vs Python call (decide at kickoff).** The classifier logic is small
  and pure; a Go port in `detect_classify_bridge.go` keeps the daemon
  dependency-free (no Python at runtime) at the cost of duplicating the rule
  table. Recommendation: **single source of truth = the fingerprint table as
  data** (JSON/TOML), loaded by both the Python classifier (tests, CLI) and a
  thin Go evaluator (daemon). Avoids drift; the corpus tests both.

### Dependencies
B1 (`#120` — consumes `RingbufDetectSource`/`DetectEvent`, seeds `agent_basenames`
from the corpus). No enforcement deps.

### SLOs it must hold (#117)
- **SLO-5** — precision **≥ 0.99** overall, **= 1.00 (zero tolerance) on the hard
  negatives** `node`/`python`/`git`/`bash` — this is the bar a class must clear
  **before** any B5 enforce binding may reference it.
- **SLO-7** — recall **≥ 0.95** on the known-agent corpus at the gate, then a
  **standing** signal via #39 (evasion is adversarial; the corpus ages).
- No exec-latency SLO: B2 runs off the hot path (SLO-1/-2 are B1's and are not
  re-paid here).

### Test / verification
- **Off-kernel (plain CI, `tests.yml`):** corpus precision/recall test —
  the B2 gate. Per-class confusion matrix; **fails if any hard negative is
  classified as an agent** (SLO-5 zero-tolerance) or recall < 0.95 (SLO-7).
- **Privileged Linux (extend B1's `detect-smoke`):** plant a **renamed** agent
  binary and an **interpreter-hosted** agent; assert the live classify path
  produces the expected class/abstention and that the interpreter gap shows up
  in the #39 counters — proving the evasion cases the corpus asserts statically
  actually behave that way on a live kernel.

### Acceptance gate — what B2 must prove
1. A live-detected known agent (direct binary) is classified to the right class
   with confidence in-band.
2. A renamed/ repacked agent that defeats basename **and** hash lands
   `unknown → AG-1`, **not** a wrong class.
3. Hard negatives are **never** classified as agents (SLO-5 = 1.00 on the set).
4. Recall ≥ 0.95 on the corpus; the interpreter-hosted gap is **surfaced by #39**,
   not hidden.
5. Operator override (`classify`/`ignore`) changes the label and is
   evidence-hashed.
6. Still observe-only: no passport, no plan, no cgroup change in the diff.

---

## B3 — Auto-attestation (provenance passport, #68)

### Goal
For a classified agent, the daemon issues a **provenance passport** — a signed,
verifiable record of *what was observed* — folded into the existing evidence /
hash-chain machinery. **Observe-only**; no adopt, no policy. This is where
Invariants 1–2 become code.

### Files
| File | Add/Change | What |
|---|---|---|
| `python/vibap/provenance_passport.py` | **add** | New credential type, **schema-distinct** from `MissionPassport`: fields per roadmap §3 (binary path + sha256, argv fingerprint, launch ancestry/ppid chain, cgroup id, pid+starttime+boot_id, uid, detection ts, classifier `{class, confidence}`, host identity) + `binding_strength: "process"` (policy research §8 — non-cryptographic process binding, weaker than holder-key PoP) + `mission_origin` discriminator (delta **D1**). Signed by the **daemon host key**. |
| `python/vibap/passport.py` | **change** | Thread the `mission_origin` discriminator (`declared / synthesized / class_binding / learned_candidate`) (D1). Add a **verifier guard**: a provenance passport presented where a mission grant is required is a **hard reject** (`ProvenanceNotAMissionError`) — Invariant 1 as an exception with a test, not a convention. Reconcile the side-effect-class vocabulary docstring vs `bpf_types` (delta **D7**). |
| `go/pkg/kernelcapture/provenance_attest.go` | **add** | Daemon-side issuance: on a classified detection, mint the provenance passport (host-key signature), append a `provenance_passport` record to the evidence log, and seed the correlator with an **observation** marker (not a governed-session receipt). |
| `go/pkg/kernelcapture/enforce_receipt_chain.go` | **change** | Accept provenance/attestation records into the existing monotonic + SHA-256 hash chain (#100) so auto-attested observations are tamper-evident and ordered alongside enforce events. |
| `go/cmd/ardur-kernelcaptured/main.go` | **change** | Wire issuance into the detect consumer loop (post-B2 classify). If a control method is added to query/emit attestations, route through the **post-#115** authorization path. |
| `docs/specs/` (provenance profile note) | **add** | A short spec note: provenance passport is observation, not authorization; how it relates to the EAT/receipt profiles and `revocation-v0.1.md` (provenance passports carry `jti` and revoke through the existing path — no new machinery). |

### Key design decisions
- **Host-key signature, not a session key.** There is no operator keypair; the
  daemon signs with its host identity (SPIFFE where deployed, else host key).
  The signature asserts *provenance and integrity of the observation*, nothing
  about correctness or authorization.
- **Process binding, stated honestly (policy research §8).** The passport binds
  to `(boot_id, cgroup_id, pid, starttime)` — non-transferable but
  non-cryptographic. A pid-reuse race or cgroup escape breaks it in a way a
  stolen holder-key can't; `binding_strength: "process"` tells verifiers to
  weight accordingly. **Do not** claim PoP-equivalent strength.
- **Attestation completeness (#122/#123).** Auto-attestation folds into the same
  chain as enforce events; the #122 (silent ringbuf drops) and #123 (kill-switch
  not attested) gaps mean the chain can under-report. B3 should **surface the
  drop counter** in the attestation summary so an auditor sees "N observations,
  M attested, D dropped" — the honest-abstention rule applied to the sensor's own
  completeness.
- **No adoption, no policy.** B3 attests; it does not move the process or apply a
  plan. That is deliberately B4/B5 so attestation can't accidentally enforce.

### Dependencies
B2 (classification) + B0/#115 (merged; any new control method inherits authz).
Reuses `passport.py`, `enforce_receipt_chain.go` (#100). Completeness leans on
#122/#123.

### SLOs
No perf SLO (off hot path). **Integrity invariants are the gate:** every
provenance passport is host-key-verifiable, chain-ordered, and
structurally-non-authorizing.

### Test / verification
- **Off-kernel (plain CI):** issue a provenance passport from a synthetic
  classified detection; verify host-key signature; assert
  `ProvenanceNotAMissionError` when it's presented as a mission grant
  (Invariant 1); assert `mission_compliance == INSUFFICIENT_EVIDENCE`
  (Invariant 2); assert it appears in the hash chain in order.
- **Privileged Linux (extend `detect-smoke`):** plant → detect → classify →
  **attest**; assert a `provenance_passport` record lands in the daemon evidence
  log with the right binary hash/uid/cgroup and chains correctly.
- **Revocation:** revoke the `jti`; assert the passport verifies as revoked
  through `revocation-v0.1.md`.

### Acceptance gate — what B3 must prove
1. A classified un-wrapped agent gets a **verifiable provenance passport** in the
   evidence chain.
2. The verifier **rejects** it as a mission grant (Invariant 1), and intent reads
   `INSUFFICIENT_EVIDENCE` (Invariant 2) — both enforced by exception + test.
3. `binding_strength: "process"` is present and its weakness is documented.
4. Attestation completeness is honest: observations vs attested vs dropped is
   surfaced (rides on #122/#123).
5. Still observe-only: no cgroup change, no plan, no enforcement in the diff.

---

## B4 — Adopt-and-attach

### Goal
Bring an **already-running** detected process **tree** under an Ardur-managed,
governable cgroup so B5 can attach policy — reusing Epic A's cgroup + apply_policy
machinery. **Adoption ≠ enforcement**: B4 makes a tree governable and stops; it
applies **no** policy. Fail-safe: if the tree can't be adopted cleanly, stay
observe-only, loudly.

### Files
| File | Add/Change | What |
|---|---|---|
| `go/pkg/kernelcapture/adopt_cgroup_linux.go` | **add** | Adoption engine: create an Ardur-managed cgroup (reuse the `create_run_cgroup` pattern from `run_bridge`), migrate the detected root PID in, then a **bounded reconciliation sweep** of already-spawned descendants (walk `/proc` by ppid + start-time within the Correlator's existing grace window) and migrate them. Idempotent; records what it moved. |
| `go/pkg/kernelcapture/adopt_reconcile.go` | **add** | The descendant-sweep + race handling: a process may fork after detection but before adoption; the sweep re-runs until stable or a bounded deadline, then declares the adopted set. Uses the same (pid, starttime, ns) identity the Correlator uses to avoid pid-reuse mis-adoption. |
| `go/pkg/kernelcapture/adopt_cgroup_unsupported.go` | **add** | Non-Linux stub (build-tag parity). |
| `go/cmd/ardur-kernelcaptured/main.go` | **change** | On an attest-and-adopt decision (still no policy), invoke adoption; on any failure emit `adoption_failed` + stay observe-only (Invariant 3/5). |
| `go/cmd/ardur-adopt-smoke/` | **add** | Privileged smoke harness: launch a process tree (parent + pre-spawned children + a late fork), adopt it, assert the whole live tree lands in the managed cgroup without losing children and **without** reintroducing the #110 double-buffer race. |
| `.github/workflows/kernel-enforce.yml` | **change** | Add `adopt-smoke` (KVM+virtme-ng; reuse the VM recipe). |

### Key design decisions
- **Migrate-into-managed vs attach-in-place (roadmap §2.4).** Recommend
  **migrate the tree into a fresh managed cgroup** (correct blast radius) with a
  **bounded reconciliation sweep** for descendants; fall back to observe-only if
  migration can't complete (e.g., the process sits in a cgroup Ardur can't move
  it out of, or forks faster than the sweep converges). Attach-in-place (bind
  policy to the *existing* cgroup) is rejected as the default because that cgroup
  may hold unrelated processes → wrong blast radius.
- **The race is the hard part.** A running agent may have already forked children
  into the old cgroup, and may fork again during adoption. The sweep must
  converge or time out **loudly** → observe-only. It must not reintroduce #110
  (per-cgroup apply serialization) — adoption takes the same per-cgroup lock the
  #115/#110 fix established before touching maps.
- **Adoption is reversible and evidence-logged.** Record the adopted PID set + the
  managed cgroup id in a `cgroup_adoption` evidence event so a later audit can see
  exactly which processes came under governance and when.

### Dependencies
B1 (detected PID/cgroup) + B0/#115 (the per-cgroup serialization + authz the
adoption path relies on). Reuses `create_run_cgroup`/`adopt_pid` patterns from
`run_bridge`.

### SLOs
No new #117 SLO, but two hard bounds: **adoption completes within a bounded
deadline or fails to observe-only** (no unbounded sweep), and **no #110 race
reintroduced** (per-cgroup lock held across the adoption map touches).

### Test / verification
- **Privileged Linux (`adopt-smoke`):** parent + N pre-spawned children + a late
  fork → adopt → assert every live member is in the managed cgroup; kill/exit a
  child mid-sweep → assert convergence; force an un-adoptable case → assert
  **observe-only fallback** with an `adoption_failed` event.
- **Off-kernel unit:** reconciliation state machine (converge / timeout / drift)
  over synthetic proc snapshots.

### Acceptance gate — what B4 must prove
1. A running tree (with pre-existing and late-forked children) is adopted into a
   managed cgroup **without losing members**.
2. An un-adoptable tree **falls back to observe-only, loudly** (`adoption_failed`
   evidence) — never a partial/wrong-blast-radius adoption.
3. No #110 race: concurrent adopt + a policy touch on the same cgroup is
   serialized.
4. Adoption is evidence-logged (which PIDs, which cgroup, when) and applies **no
   policy** (that's B5).

---

## B5 — Auto-govern (#69) — the first no-wrapper enforcement

### Goal
Close the loop: classification → **policy selection via the AG ladder** →
`lower_to_bpf_policy_plan` → `apply_policy` on the adopted cgroup → tier-1
BPF-LSM + tier-2 seccomp. **Default observe/shadow; enforce only under an
operator binding rule** (AG-3). This is the slice where an unmodified agent
launched with no `ardur run` is detected, attested, adopted, and — under a
configured rule — actually enforced. It implements policy research deltas D1–D7.

### Files
| File | Add/Change | What |
|---|---|---|
| `python/vibap/agent_bindings.py` | **add** | The **binding registry** (delta D3): TOML loader (`~/.ardur/agent-bindings.toml` personal, `/etc/ardur/agent-bindings.d/*.toml` fleet), schema `ardur.agent-bindings.v0`, unknown-key = load error. **Load-time dry-run lowering** of every `mode="enforce"` binding through `lower_to_bpf_policy_plan(ENFORCE_MODE_ENFORCE)` so unenforceable dimensions raise `MissionPolicyNotImplementedError` **at config time** (research §6.2). Resolution engine: most-specific-wins, **ambiguity-resolves-downward** to the least aggressive mode (§6.3). Registry sha256 recorded in evidence (§6.4). |
| `python/vibap/synthesized_mission.py` | **add** | The **AG-2 shadow baseline** (§5): per-class `baseline_for(agent_class)` table → mission-shaped input → `lower_to_bpf_policy_plan(ENFORCE_MODE_PERMISSIVE)`. Guard `SynthesizedMissionEnforceError` (delta **D2**): a synthesized plan carrying `ENFORCE_MODE_ENFORCE` on any op is a **crash, not an incident**. |
| `python/vibap/mission_compile.py` / `bpf_lower.py` / `bpf_types.py` | **change** | Thread `mission_origin` (D1) into the plan; add `allowed_side_effect_classes` as the primary enforceable dimension for un-wrapped agents (§6.1); keep the STRICT loud-guard authoritative. **No new kernel op.** |
| `go/pkg/kernelcapture/auto_govern.go` | **add** | Daemon-side: resolve binding (or synthesized baseline) for an adopted cgroup, apply the lowered plan via the existing `apply_policy` (#96), manage ladder transitions (AG-2→AG-3, grace expiry, drift disarm) as **plan replacements with incremented generation** (§10.4) — no new kernel mechanism. **Loud-abort inversion (Invariant 4):** enforce-attach failure ⇒ fall to shadow, emit `enforcement_attach_failed`, never kill. |
| `python/vibap/policy_binding_evidence.py` | **add** | The `ardur.policy_binding.v0` evidence block (delta **D5**): provenance jti, mission_origin, posture_tier, binding_id, registry_sha256, profile_sha256, plan_sha256, enforce_mode, tier2_residue, classifier, generation. |
| `python/vibap/receipt.py` / verifier | **change** | **Two-claim verifier** (D5, research §8): `mission_compliance` (always `INSUFFICIENT_EVIDENCE` for un-wrapped — Invariant 2) **and** `class_policy_compliance` (PERMIT/DENY against the bound profile at AG-3; `INSUFFICIENT_EVIDENCE` for AG-2 shadow). Class intent can never launder into session intent. |
| `python/vibap/cli.py` + hub | **change** | The rest of the `ardur agents` family (delta D6): `review` (shadow would-have-denied evidence), `bind` (writes a `[[binding]]`, validates via dry-run lowering), `pause`/`ignore`, and the AG-4 funnel nudge ("relaunch under `ardur run` for tool-level + budget governance"). |
| `go/cmd/ardur-auto-govern-smoke/` | **add** | Privileged e2e harness (the auto analogue of the `enforce-e2e` demo). |
| `.github/workflows/kernel-enforce.yml` | **change** | Add `auto-govern-smoke` (KVM+virtme-ng, BPF-LSM + seccomp — reuses the `kernel-smoke` **and** `seccomp-smoke` infra from #104). |
| `process_guard.bpf.c` + `bpf_types` | **change (deferrable, D4)** | `cgroup_path_deny` LPM trie for the **self-protection floor** (deny governed-agent writes to Ardur's own keys/evidence/registry). Current vocab has `ACT_ALLOWLIST` but no path-scoped deny. **Deferrable:** the floor ships shadow-only until this lands. |

### Key design decisions
- **The pipeline is reused verbatim (research §10).** `lower_to_bpf_policy_plan`
  → `apply_policy` → double-buffer generation swap (#101/#110) → `enforce_events`
  chain (#100) → kill-switch are unchanged. B5 only changes **where inputs come
  from** (binding registry / synthesized baseline instead of operator CLI) and
  adds guards at the seams (D2 synthesized-enforce crash; registry dry-run
  lowering).
- **`mission_compile` (Biscuit) does NOT run on the auto path (§10.1).** No proxy
  authorizer exists for an un-wrapped agent, so tier-2 semantic dimensions (tool
  allowlists, budgets, delegation, `external_send`, flow/effect/lineage) have no
  interposition point. The registry validator **rejects** enforce bindings whose
  profile carries proxy-only dimensions — the exact failure
  `MissionPolicyNotImplementedError` exists to prevent.
- **The honest enforcement ceiling (research §13, the hardest open question).**
  Auto-enforcement caps at **coarse kernel ops** (exec/file/net per cgroup).
  AG-3 "enforced" is a **weaker** statement than wrapped "enforced." Recommended
  posture (a)+(c): accept the ceiling and say so, and make **conversion to
  `ardur run` (AG-4) the product** — auto-governance is the discovery funnel.
  **This choice shapes Epic B's headline claim, AuditBench scoring, and the
  paper-lane narrative → it deserves an explicit ADR before B5 lands.**
- **Enforce trustworthiness leans on Epic A gaps.** #124 (guard unpinned →
  restart drops enforcement) and #121 (fail-open if guard consumer dies) mean an
  AG-3 enforce binding could silently stop enforcing after a daemon restart/crash.
  The fail-safe (Invariant 3/4) covers the *decision* direction, but a
  trustworthy AG-3 wants #124/#121 fixed. **Recommend #124 + #121 land before AG-3
  enforce ships GA**; AG-2 shadow (the default) is unaffected.

### Dependencies
**Hard:** B2 + B3 + B4, **#104** (seccomp tier-2 for policy dims BPF-LSM can't
decide), **#105** (file-op `ACT_ALLOWLIST` reconcile — else `SubpathPolicy`
enforce silently fails closed). **Trustworthiness:** #121/#122/#124. **Deltas:**
D1–D7 (D4 deferrable).

### SLOs
- **SLO-6** — enforce binding rules fire **only above a documented confidence
  threshold**; below → observe (Invariant 3). Implemented as `min_confidence` in
  the binding (§6.1).
- **SLO-5 (from B2)** — a class may be **referenced by an enforce binding only
  after** it clears precision ≥ 0.99 / = 1.00 on hard negatives. Enforced by the
  registry validator refusing to bind an under-precision class to `mode=enforce`.

### Test / verification
- **Off-kernel:** registry load/validate (dry-run lowering rejects unenforceable
  enforce bindings); `SynthesizedMissionEnforceError` on a synthesized-enforce
  plan; resolution semantics (most-specific-wins, ambiguity-down); two-claim
  verifier (`mission_compliance` always IE; `class_policy_compliance` PERMIT/DENY
  at AG-3, IE at AG-2).
- **Privileged Linux (`auto-govern-smoke`):** the headline e2e — launch an
  unmodified agent with **no wrapper**; assert detect → classify → attest → adopt;
  with **no binding**, assert AG-2 shadow (would-have-denied events, **nothing
  blocked**); add an **enforce binding** for the class, assert a forbidden op →
  `EPERM` + matching `enforce_event`; force an attach failure → assert **fall to
  shadow, loudly** (Invariant 4), never a kill.

### Acceptance gate — what B5 must prove
1. **No-wrapper enforcement works:** an unmodified, un-wrapped agent is detected,
   classified, attested, adopted, and — under an operator enforce binding —
   blocked at a forbidden kernel op (EPERM + chained enforce_event).
2. **Default is safe:** with no binding, a known agent runs at AG-2 **shadow**
   (would-have-denied evidence, zero blocking); an unknown agent at AG-1 observe.
3. **Enforcement requires a declaration:** no plan enforces without a matching,
   confidence-thresholded, non-expired operator binding; synthesized plans
   **cannot** enforce (D2 crash-tested).
4. **Two claims stay separate:** `mission_compliance` is `INSUFFICIENT_EVIDENCE`
   for every un-wrapped session; only `class_policy_compliance` can be PERMIT/DENY.
5. **Loud-abort inversion:** attach failure ⇒ shadow + event, never a kill.
6. **Unenforceable dimensions fail at config time** (registry dry-run lowering),
   not silently at runtime.

---

## B6 — macOS detection (ESF System Extension, #70 / #106)

### Goal
Bring **detect + attest** to macOS via an Endpoint Security System Extension,
reusing B2 (classify) + B3 (attest) unchanged. Enforcement on macOS is a
**different, coarser ceiling** (ESF AUTH + Network Extension, no cgroup/BPF-LSM/
seccomp) and is scoped honestly.

### Files
| File | Add/Change | What |
|---|---|---|
| `go/pkg/kernelcapture/es_client_darwin.go` | **change** | Today a cgo-free preflight stub (`ESClient` interface, `NewESClient`, `InspectEndpointSecurityPreflight`, entitlement check via `codesign`). B6 implements the real client: cgo bindings to `EndpointSecurity.framework`, `es_new_client` + `es_subscribe(ES_EVENT_TYPE_NOTIFY_EXEC)`, decode → the **same `DetectEvent` shape** B2 consumes. |
| `packaging/macos/ardur-endpoint-security.systemextension/` | **add** | The System Extension target: Info.plist, `com.apple.developer.endpoint-security.client` entitlement, notarization/signing config. |
| `packaging/macos/launchd/` | **add** | launchd plist + install/uninstall flow (the #106 packaging remainder; the macOS analogue of the Linux `ardur-sensor install`). |
| `go/cmd/ardur-kernelcaptured/daemon_darwin.go` | **change** | Currently stubs `runEBPFConsumer`/`runGuardConsumer` for darwin. Wire the ES NOTIFY consumer → classify (B2) → attest (B3), platform `darwin`. |
| `go/pkg/kernelcapture/es_enforce_darwin.go` | **add (enforce tier, later)** | The macOS enforce tier: `ES_EVENT_TYPE_AUTH_EXEC`/`AUTH_OPEN` answered within the ES deadline + `NEFilterDataProvider` egress. Policy scoped **per audit-token/process**, not per cgroup. Gated behind the same AG-ladder/binding logic (B5) but with the macOS ceiling. |
| `go/pkg/kernelcapture/es_client_darwin_test.go` | **change** | Extend beyond preflight: NOTIFY decode → DetectEvent parity; AUTH deadline/fallback behavior (mocked ES client where hosted CI can't load a real extension). |

### Key design decisions
- **NOTIFY for detect, AUTH only for enforce (SLO-8).** ESF AUTH is **synchronous
  on the process's critical path**; missing the ES deadline gets the client
  **killed by the OS**. Detection uses `NOTIFY_EXEC` (0 added critical-path
  latency). AUTH is reserved for the B5-style enforce tier with a **p99 ≤ 5 ms**
  response and **fail-open-to-observe** if the supervisor can't decide in budget.
- **Classify + attest are reused as-is.** B2/B3 are platform-neutral (they key on
  path/hash/argv/uid, which ESF provides). Only the event *source* and the
  *enforce* layer are macOS-specific. Invariants 1–5 carry unchanged.
- **The entitlement is the critical-path dependency.**
  `com.apple.developer.endpoint-security.client` is **Apple-approved, not
  self-servable**, with external lead time (#106). **File it at B1 start** so it
  is approved by the time B6 code is ready — B6 is otherwise blocked on a process
  outside the team's control.
- **Enforce ceiling stated honestly.** No per-cgroup op policy on macOS; policy is
  per-process/audit-token. macOS AG-3 "enforced" is coarser still than Linux
  AG-3. Document per the roadmap's per-OS-ceiling rule; do not imply Linux-grade
  prevention.

### Dependencies
B2 + B3 (reused). **#106** (Apple ES entitlement — external lead time, start at
B1). Existing `es_client_darwin.go`/`daemon_darwin.go` scaffolding + the
`daemon_preflight` entitlement check.

### SLOs
- **SLO-8** — detect on `NOTIFY` only (0 added critical-path latency); `AUTH`
  (enforce tier) p99 ≤ 5 ms, fail-open-to-observe.

### Test / verification — and its hard CI limit
- **Hosted CI (macOS runner):** the **cgo-free preflight** and compile only —
  entitlement presence check, ES-client interface, NOTIFY-decode unit tests
  against a **mocked** ES client. GitHub-hosted macOS runners **cannot load a
  System Extension** (SIP + the entitlement + user approval), so the live ESF
  path is **not hosted-CI-testable**.
- **Self-hosted / manual (signed Mac):** the real proof — a **notarized, signed**
  build on a Mac with the approved entitlement: launch an agent, assert a NOTIFY
  detect → classify → attest; (enforce tier) assert an AUTH deny within budget
  and a fail-open-to-observe on deadline pressure. **State this CI limitation
  explicitly** in the slice — it is an honest boundary, not a gap to paper over.

### Acceptance gate — what B6 must prove
1. On a signed Mac with the approved entitlement, an agent launch is **detected
   via ESF NOTIFY**, **classified** (B2), and **attested** (B3) — parity with
   Linux detect+attest.
2. Detection adds **0 critical-path latency** (NOTIFY only); AUTH is never used
   for detection (SLO-8).
3. The enforce tier (if shipped in B6) answers AUTH within p99 ≤ 5 ms and
   **fails open to observe** under deadline pressure — never holds the process to
   the OS-kill boundary.
4. Invariants 1–5 hold identically (provenance-not-mission, IE-not-COMPLIANT,
   observe-first, loud fail-safe).
5. The hosted-CI limitation is documented and the self-hosted proof recipe is
   checked in.

---

## B7 — Windows detection (ETW, detect + attest only, #71)

### Goal
Bring **detect + classify + attest + telemetry** to Windows via ETW. **Enforcement
is explicitly out of scope** (needs a signed minifilter/WFP/WDAC driver track —
beyond this epic). Windows governance is **observe-only**, stated honestly.

### Files
| File | Add/Change | What |
|---|---|---|
| `go/pkg/kernelcapture/etw_source_windows.go` | **add** | ETW consumer for `Microsoft-Windows-Kernel-Process` (WMI `Win32_ProcessStartTrace` fallback) → the **same `DetectEvent` shape** (resolved image path, command line, uid/SID, pid/ppid). |
| `go/pkg/kernelcapture/etw_source_unsupported.go` | **add** | Non-Windows stub (build-tag parity). |
| `go/cmd/ardur-kernelcaptured/daemon_windows.go` | **add** | Windows daemon entry: platform `windows`, ETW NOTIFY consumer → classify (B2) → attest (B3). No guard/enforce consumer (none exists on Windows). |
| `packaging/windows/` | **add** | Service install (SCM) + ETW session setup; no driver. |
| `go/pkg/kernelcapture/etw_source_windows_test.go` | **add** | ETW decode → DetectEvent parity (mocked where the provider isn't available). |

### Key design decisions
- **Detect/attest only; no enforcement, said plainly.** ETW is telemetry, not a
  control point. B7 ships the observe half and **documents the enforcement gap**
  (a driver track is future/unfunded). This is the roadmap's per-OS-ceiling honesty
  rule at its sharpest: on Windows, "govern" means "observe + attest," full stop.
- **Classify + attest reused.** Same platform-neutral B2/B3 as macOS.
- **Ordering (#71).** #71 blocks Windows on **macOS ESF landing first** — B7
  starts after B6 so the cross-platform detect→classify→attest seam is proven
  once on macOS before the third OS.

### Dependencies
B6 (per #71 ordering) + B2 + B3. No enforcement deps (there is no enforcement).

### SLOs
- Overhead budget analogous to **SLO-2** but telemetry-only (ETW consumer CPU
  bounded); **no** AUTH/enforce SLO (nothing enforces). Detect coverage feeds #39
  like the other OSes.

### Test / verification
- **Hosted CI (Windows runner):** ETW `Kernel-Process` consumer runs on
  `windows-latest` with elevation (no driver needed) → launch a process, assert a
  DetectEvent → classify → attest. This is **more** hosted-CI-testable than macOS
  (no System Extension approval needed).
- **Off-kernel:** ETW record → DetectEvent decode parity.

### Acceptance gate — what B7 must prove
1. A process launch on Windows is **detected via ETW**, **classified** (B2), and
   **attested** (B3) — detect+attest parity with Linux/macOS.
2. **No enforcement is claimed or shipped;** the enforcement gap is documented
   (observe-only until a driver track exists).
3. Invariants 1–5 hold (provenance-not-mission, IE-not-COMPLIANT, observe,
   loud fail-safe).

---

## Critical path to the first no-wrapper enforcement demo

```
 B0 (#115, MERGED)
        │
        ▼
 B1 (host-wide Linux detect, #120) ──► B2 (classify #67) ──► B3 (attest #68) ─┐
        │                                    │                                 │
        └──────────────────────────► B4 (adopt-and-attach) ───────────────────┤
                                                                               ▼
                          #104 (seccomp tier-2) + #105 (file-op reconcile) ──► B5 (auto-govern #69)
                                                                               │  ← FIRST no-wrapper
                                                                               │    ENFORCEMENT DEMO
                                                                               ▼    (auto-govern-smoke)
                                                        [#121/#124 recommended before AG-3 enforce GA]

 Parallel, off the critical path:
   #106 Apple ES entitlement (FILE AT B1 START) ──────► B6 (macOS ESF detect+attest) ──► B7 (Windows ETW detect-only, #71)
                                                              ▲
                                                    B2 + B3 reused unchanged
```

**The critical path is B1 → B2 → B3 → B4 → B5**, with **#104 + #105** landing
before B5. B4 can proceed in parallel with B2/B3 (it needs only B1's detected
PID/cgroup). B5 is the join point and the **first slice that enforces on a
no-wrapper agent** — proven by `auto-govern-smoke`. Two things sit *beside* the
path rather than on it: **#106** (start the Apple filing at B1 kickoff — its
external lead time, not code, is what would delay B6), and **#121/#124** (Epic A
enforce-reliability fixes recommended before AG-3 *enforce* ships GA, though AG-2
shadow — the default — doesn't need them).

**Before B5 lands:** an ADR on the honest enforcement ceiling of a proxy-less
agent (policy research §13) — because "auto-govern" AG-3 "enforced" is a
deliberately weaker claim than wrapped `--enforce`, and that choice shapes the
Epic B headline, AuditBench scoring, and the paper-lane narrative.

## SLO ownership summary

| SLO (#117) | Owner slice | Meaning |
|---|---|---|
| SLO-1 / -2 / -3 / -4 | **B1** (+ B8) | exec-latency / CPU / map-memory / drop-accounting |
| **SLO-5** | **B2** (gate for B5) | precision ≥ 0.99; = 1.00 on `node`/`python`/`git`/`bash` |
| **SLO-7** | **B2** (+ B8 standing) | recall ≥ 0.95 on the corpus |
| **SLO-6** | **B5** | enforce only above a confidence threshold |
| **SLO-8** | **B6** | macOS NOTIFY-detect (0 latency); AUTH-enforce p99 ≤ 5 ms, fail-open-to-observe |
| (telemetry-only) | **B7** | ETW consumer overhead bounded; no enforce SLO |
