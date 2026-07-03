# Epic B — Policy Selection for Un-Wrapped Agents: Default Missions, Binding Rules, and the Governance Posture Ladder

Status: **research/design document** (2026-07-03). No code changed. This is the
deep-dive on one seam of the Epic B plan
(`docs/roadmap/epic-b-auto-detection-plan.md`, in flight on the
`docs/epic-b-auto-detection-plan` lane): **§4.1 "Policy selection for an
un-wrapped agent"** and kickoff open questions 2 (provenance-passport
schema, policy half) and 3 (profile-registry binding-rule DSL).

Scope boundary — what this document deliberately does **not** cover, because
sibling lanes own it:

- **Detection mechanics** (Linux host-wide eBPF exec tracing, in-kernel
  prefilter, macOS ESF, Windows ETW) — the auto-detection plan §2 and the
  macOS/Windows detection lane.
- **Classification/fingerprinting** (agent-class inference, confidence
  scoring, the labeled corpus) — B2 / issue #67, plus
  `python/vibap/behavioral_fingerprint.py` for behavioral identity.
- **Adopt-and-attach mechanics** (cgroup migration, descendant sweeps) — B4.

This document answers the question that remains once those lanes deliver:
**the host just detected an AI agent nobody launched under `ardur run` — which
mission governs it, who decided that, and how is the decision proven?**

---

## 1. The gap: which `ardur run` invariants survive auto-detection

`ardur run --enforce` (`python/vibap/run_bridge.py:run_governed`) establishes
governance through an ordered launch sequence, and every downstream component
leans on an invariant that sequence creates:

| # | Launch-path step | Invariant it creates | Survives auto-detection? |
|---|---|---|---|
| 1 | Operator types a command, optionally `--mission`, `--allowed-tools`, `--forbidden-tools` | **Human intent exists** before the agent runs | ❌ No mission, no declared tools |
| 2 | `generate_keypair` + `issue_passport` → Mission Passport (ES256 JWT) | A **signed grant** binds intent to a session | ❌ Nothing was issued |
| 3 | `resource_scope=[cwd, cwd/*]`, `cwd` pinned | Scope is **derived from a consented launch context** | ⚠️ cwd observable, but never consented |
| 4 | Embedded `GovernanceProxy` + session start | Every tool call crosses an **interposition point** (tier-2) | ❌ **No proxy in the loop at all** |
| 5 | Fresh cgroup, agent launched *into* it, PID adopted | Policy blast radius = exactly this agent tree | ⚠️ Rebuilt after the fact by B4 adoption |
| 6 | `apply_policy` writes the lowered `BpfPolicyPlan` before work begins | **No ungoverned instruction executes** under `--enforce` | ❌ The agent has been running ungoverned for some time T |

Rows 1, 2, and 4 are the policy problem. Row 4 is the least obvious and the
most consequential: for a wrapped agent, kernel enforcement (tier-1) is the
*backstop* behind a semantically rich proxy (tier-2: tool allowlists, per-class
budgets, delegation narrowing, external_send detection, flow/effect policies).
For an un-wrapped agent **there is no tier-2** — the agent's tool calls never
route through Ardur. Whatever policy we select can only be *enforced* to the
kernel-expressible ceiling of `BpfPolicyPlan`: exec / file-read / file-write /
net-connect, deny or allowlist, per cgroup (`python/vibap/bpf_types.py`).
Section 10 works through what that constraint does to policy design; §13 names
it as the hardest open question of the epic.

## 2. Inputs available at policy-selection time

Everything policy selection may key on is **observation, not declaration**.
From the detection + classification lanes (B1/B2) and the host itself:

- `agent_class` + `confidence` (e.g. `claude-code`, 0.97) — classifier output
- binary path + sha256; argv fingerprint; interpreter+script resolution
- `uid` / user; `cwd`; environment context the sensor is allowed to read
- launch ancestry (ppid chain — was it spawned by a terminal? by cron? by
  another agent?); pid namespace; container/cgroup context
- host identity (SPIFFE ID where deployed; hostname otherwise)
- time of detection; prior observation history for this (class, hash, uid)

Absent, by construction: mission text, allowed/forbidden tools, budgets,
consent, any holder key for proof-of-possession. The design rule that falls
out, consistent with the tri-state verifier discipline (`PERMIT / DENY /
INSUFFICIENT_EVIDENCE`): **observations select policy; only declarations
justify enforcement.** Every mechanism below is a way of getting a
*declaration* (an operator binding rule) attached to an *observation* (a
classified process) without pretending one is the other.

## 3. Prior art: how existing systems assign policy to unmanaged things

Web-verified survey (sources in §14). The exact question — "a security control
plane discovers a workload nobody enrolled; what policy applies?" — is two
decades old in adjacent domains.

| System | Unknown/unmanaged default | Path to enforcement | Identity → policy binding |
|---|---|---|---|
| **CrowdStrike Falcon** | Sensor detects + reports universally; prevention is per-policy | Phased: detection-optimized policy → triage → prevention policy, rolled out via host groups | Host groups → prevention policies (one policy per group per OS) |
| **Microsoft Defender ASR** | Rules start in **Audit mode** (log, don't block), ~30 days baseline | Audit → per-ring Warn/Block, starting with the fewest-triggered rule; exclusions mined from audit data | Device groups / rings |
| **Microsoft Defender device discovery** | Unmanaged devices are *discovered* into inventory, not controlled | Onboarding funnel: discover → inventory → onboard to management | Device inventory |
| **ThreatLocker** | **Learning Mode** on install: catalog everything, auto-create permit policies | Operator reviews learned policies → "Secured" → default-deny for anything unlearned | Per-app policies from learned baseline |
| **Santa (macOS)** | **MONITOR** mode (default): unknown binaries run, logged; only explicit block rules stop anything | Flip to **LOCKDOWN**: unknown = blocked | Per-binary / per-signing-cert rules |
| **SELinux targeted policy** | Processes with no policy run **unconfined**; only targeted daemons are confined | Write a domain policy; per-domain permissive mode as the intermediate step | Domain (type) per executable |
| **AppArmor** | Unprofiled = unconfined; new profiles start in **complain mode** | `aa-logprof` interactively promotes logged violations into profile rules → enforce | Profile per binary path |
| **802.1X / NAC** | Unknown/failed-posture device → **quarantine or guest VLAN** (degraded tier, not binary allow/deny) | Posture assessment pass → production VLAN | Device identity/health → VLAN/ACL enforcement profile |
| **Kubernetes PSA / Gatekeeper** | Per-namespace `audit`/`warn` before `enforce`; Gatekeeper `dryrun` enforcementAction | Graduated flip per namespace/constraint after observing violations | Namespace labels / constraint selectors |
| **Microsoft Entra Conditional Access** | Unmanaged device ≠ blocked by default; operators add policies for block or **limited web-only access** | Compliance signal (Intune) gates full access | Identity + device state → access tier |
| **NIST SP 800-207 (zero trust)** | Default-deny ideal: PEP grants nothing without a PDP decision | N/A (architecture, not migration guidance) | PE/PA decide, PEP enforces — policy decision separated from enforcement point |

Five patterns recur, and all five map onto Ardur surfaces that already exist:

1. **Observe-first, graduated enforcement.** Every mainstream EDR/hardening
   system defaults an unknown or newly-covered workload to audit/monitor/
   complain/dryrun and requires a human to flip enforcement. Default-deny on
   first sight exists only in *mature allowlist estates* (Santa LOCKDOWN,
   ThreatLocker post-learning, NIST ideal) where a baseline was already built.
   Ardur analogue: `ENFORCE_MODE_PERMISSIVE` vs `ENFORCE_MODE_ENFORCE` is
   already the vocabulary of `BpfPolicyPlan`.
2. **Group/identity → policy binding is the operator interface.** Nobody
   writes per-process policy; they bind policy to an identity class
   (host group, device group, namespace, signing cert). Ardur analogue:
   agent-class from B2 is the grouping key; `ARDUR.md` profiles
   (`python/vibap/ardur_profile.py`) are the policy objects.
3. **A degraded middle tier beats allow/deny binarism.** Quarantine VLANs and
   "limited web-only access" show the value of a posture between full trust
   and blocking. Ardur analogue: a shadow (permissive) plan that produces
   would-have-denied evidence without denying.
4. **Learning modes produce candidates, humans promote them.** ThreatLocker
   and `aa-logprof` both auto-generate policy from observed behavior — and
   both gate enforcement on explicit review. Nobody auto-enforces a learned
   baseline.
5. **Discovery is an onboarding funnel.** Defender device discovery doesn't
   try to govern unmanaged endpoints in place; it inventories them and drives
   them toward management. Ardur analogue: auto-detection funnels agents
   toward `ardur run` / `ardur protect`, where the full governance stack
   (including tier-2) applies.

## 4. The default-mission model: three candidates, one recommendation

**Candidate A — deny-by-default.** No mission ⇒ no execution: block (or
freeze) any detected agent until an operator declares policy. Zero-trust-pure,
and structurally wrong here. It converts every false positive into an outage
(§4.2 of the plan), punishes exactly the discovery capability we're shipping,
and — unlike NAC, where the quarantine VLAN still lets the device exist — a
denied exec is indistinguishable from sabotage of a colleague's workflow. Every
surveyed vendor that ships host-wide detection rejected this default. Reserve
deny-by-default for declared *lockdown estates* (a host-level operator flag,
`host_posture = "lockdown"`, meaningful only where the operator has already
bound every expected agent class — the Santa LOCKDOWN analogue).

**Candidate B — observe-first.** No mission ⇒ provenance-attest + telemetry,
never enforcement. Matches the plan's §4.1 decision and every EDR default.
Correct as the *floor*, but insufficient alone: pure observation never
generates the evidence an operator needs to confidently *turn on* enforcement.
The gap between "observed" and "enforced" needs a ladder, not a cliff.

**Candidate C — learned baseline.** Watch the agent for a window, synthesize
the observed behavior into a policy (the wrapper's own
`resource_scope=[cwd, cwd/*]` heuristic generalized), then enforce the
baseline. This is ThreatLocker learning mode for agents — and both surveyed
learning-mode systems gate the enforce flip on human review, for good reason:
a baseline learned from an already-running, possibly-compromised agent
launders the compromise into the policy ("normalization of deviance"). A
learned baseline is a *candidate binding*, never an auto-applied one.

**Recommendation: a graduated posture ladder ("observe-first, identity-bound,
operator-promoted") that composes all three.** Each tier is defined by which
*declaration* backs it, and the automatic tiers cap at shadow enforcement:

```
 AG-0  not an agent            prefilter drop; no Ardur artifact at all
 AG-1  agent-like, unknown     provenance passport + observe (telemetry,
       class or confidence<θ   correlator feed). No plan applied.
 AG-2  known class, no         provenance passport + SHADOW PLAN: synthesized
       binding rule            baseline mission lowered via bpf_lower with
       (DEFAULT for known)     ENFORCE_MODE_PERMISSIVE → would-have-denied
                               events, zero blocking. §5
 AG-3  operator binding rule   declared class-mission (profile) lowered and
       matches                 applied per the rule's mode: shadow | enforce.
                               Enforcement exists ONLY at this tier. §6
 AG-4  wrapped                 the agent is relaunched under ardur run
       (adoption funnel exit)  (full tier-1 + tier-2). Auto-detection's
                               happy ending, not a tier it operates.
```

Plus one deliberate exception that applies at AG-1 and above regardless of
binding: a **self-protection floor** — deny writes by governed-agent cgroups
to Ardur's own key material, evidence logs, and binding registry. Precedent:
every EDR ships tamper protection on by default; a governor that can be
edited by the governed is not a governor. This is the only enforcement
applied without an operator rule, its blast radius is a handful of
Ardur-owned paths, and it requires a small BPF delta (§11, D4) — until that
lands, the floor is shadow-only like everything else.

Escalation between tiers is **evidence-driven in one direction only**:
AG-2 shadow evidence ("in the last 30 days, `claude-code` triggered 0
would-have-denied events under the `safe-coding` baseline") is exactly the
Defender-ASR-style artifact an operator reviews to promote a class to AG-3
enforce. De-escalation is automatic and immediate: classifier confidence drop,
binary-hash drift breaking a pin (§7), registry ambiguity (§6.3), or adoption
failure (B4) all fall back down the ladder, loudly, to AG-1.

## 5. AG-2: the synthesized baseline mission (shadow policy)

The novel piece relative to the plan. When B2 classifies a known agent class
but no operator has bound a profile, the daemon synthesizes a mission-shaped
policy input and lowers it through the **existing, unchanged** compiler:

```python
# Synthesized-mission inputs → lower_to_bpf_policy_plan(...) verbatim
allowed_side_effect_classes = baseline_for(agent_class)   # e.g. coding agents:
                                                          # ["read","write","exec","network"]
                                                          # → OP_EXTERNAL_SEND: ACT_DENY (shadow)
resource_scope   = [observed_cwd]        # → path_allow + ACT_ALLOWLIST (shadow)
forbidden_tools  = ()                    # cannot guess; do not invent
enforce_mode     = ENFORCE_MODE_PERMISSIVE   # HARD-CODED for synthesized origin
```

Design rules, each load-bearing:

- **Synthesized missions are structurally incapable of enforcing.** A guard in
  the auto-governance path (mirror of `MissionPolicyNotImplementedError`'s
  loud-guard philosophy in `python/vibap/mission_compile.py`) raises if a plan
  whose `mission_origin == "synthesized"` carries `ENFORCE_MODE_ENFORCE` on
  any op. Not a convention — an exception type
  (`SynthesizedMissionEnforceError`) with a test, so "the sensor guessed a
  policy and enforced it" is a crash, not an incident.
- **The baseline is per-class and versioned, not per-process-clever.** A small
  static table (`baseline_for`) shipped with the classifier corpus: coding
  agents get `{read, write, exec, network}` with cwd-scoped path allowlist
  (shadow); nothing gets `external_send` (it is proxy-synthetic —
  `OP_EXTERNAL_SEND` has no kernel hook per `bpf_types.py`, so its shadow
  signal is only meaningful post-adoption where the daemon can fold proxy
  signals in; for un-wrapped agents it simply produces no events, which the
  evidence must label as a coverage gap, not compliance).
- **The mission text is honest**: `mission = "SYNTHESIZED BASELINE — no
  operator mission declared; shadow evaluation only"`. It exists so every
  downstream artifact (receipts, posture index, AuditBench) renders something
  that cannot be mistaken for intent.
- **Shadow output is the promotion artifact.** Every would-have-denied
  `enforce_event` (already hash-chained per #100) accumulates into a
  per-(class, uid, cwd-prefix) report surfaced by `ardur agents review`:
  "promote to enforce" is a one-command act *because* the evidence for it was
  produced automatically.

Why not skip AG-2 and leave known classes at observe-only? Because pure
observation produces *activity* evidence but not *policy-fit* evidence. The
single biggest lesson of the ASR/PSA/Gatekeeper pattern is that the artifact
that de-risks enforcement is "here is what WOULD have been blocked" — and
producing it costs us nothing: the plan machinery, permissive mode, and the
event chain all shipped in Epic A (#96, #100, #101).

## 6. AG-3: the operator binding registry

Answers kickoff open question 3 (binding-rule DSL). The registry is the only
source of enforcement authority for un-wrapped agents.

### 6.1 Shape

A root-owned (fleet) or hub-token-guarded (personal) TOML file — structured,
diffable, and loud on typos, in the spirit of `MissionPassport._KNOWN_FIELDS`
(unknown keys are load errors, not silent defaults). One file
`~/.ardur/agent-bindings.toml` for the personal path; `/etc/ardur/
agent-bindings.d/*.toml` for fleets. **Not** `ARDUR.md`: the friendly-markdown
profile format stays the *policy body*; the registry is the *routing layer*
that says which body applies to which observed identity. Mixing routing into
prose markdown is how precedence bugs are born.

```toml
schema = "ardur.agent-bindings.v0"

[defaults]
unknown_agent = "observe"          # AG-1 (the only valid values here:
known_agent   = "shadow"           #        observe | shadow — never enforce)
host_posture  = "open"             # open | lockdown (§4, Candidate A)

[[binding]]
id              = "claude-repos-enforce"
agent_class     = "claude-code"          # B2 classifier label (required)
min_confidence  = 0.90                   # below θ ⇒ rule does not match ⇒ AG-1
match_uid       = ["nutakki"]            # optional predicates; all must pass
match_cwd       = ["/home/nutakki/repos/**"]
pin_binary_sha256 = []                   # optional; non-empty ⇒ hash must match
profile         = "safe-coding"          # ARDUR.md profile name or path
mode            = "enforce"              # observe | shadow | enforce
escalation_grace_s = 300                 # shadow-soak before ENFORCE flips (§9)
expires         = "2026-12-31"           # bindings decay; enforcement must be
                                         # re-affirmed, not archaeological

[[binding]]
id          = "codex-anywhere-shadow"
agent_class = "codex"
profile     = "read-only"
mode        = "shadow"
```

The `profile` body reuses what exists: `ArdurProfile` fields
(`allowed_tools`, `forbidden_tools`, `scope`, `forbid_rules`, `cedar_policy`)
and the `CLAUDE_CODE_PROTECT_MODES` presets (`safe-coding`, `read-only` in
`python/vibap/cli.py`). One addition to the profile vocabulary is needed:
`allowed_side_effect_classes` — the kernel-native dimension
(`{read, write, network, exec, external_send}` per
`mission_compile._VALID_SIDE_EFFECT_CLASSES`) — because for un-wrapped agents
class-level rules are the *primary* enforceable dimension, not tool names
(§10). (Note in passing: `passport.py`'s docstring vocabulary for
side-effect classes — `none/internal_write/external_send/state_change` —
differs from the `mission_compile`/`bpf_types` set; the registry speaks the
`bpf_types` vocabulary and the discrepancy should be reconciled before B5.)

### 6.2 Load-time validation: dry-run lowering

The registry loader **runs `lower_to_bpf_policy_plan` on every
`mode = "enforce"` binding at load time**, with `ENFORCE_MODE_ENFORCE`. The
Epic A loud-guard then does the work it was built for: any policy dimension
that cannot lower to kernel maps (tool names that don't project via
`_tool_to_bpf_op`, hostname URL allowlists, effect/flow/lineage policies)
raises `MissionPolicyNotImplementedError`, and **the registry refuses to
load the binding as enforce** — with the exact remediation list. Operators
learn at config time, not incident time, that "block Slack messages" is not a
promise the kernel tier can keep for an un-wrapped agent. `shadow` bindings
lower permissively and may carry `tier2_ops` residue, which is recorded in
evidence as declared-but-unenforceable (the same honesty rule as receipts'
`insufficient_evidence`).

### 6.3 Resolution semantics

- **Match** = all present predicates pass (`agent_class` equality,
  `confidence ≥ min_confidence`, uid ∈ set, cwd matches any glob, hash ∈ pin
  set, `expires` in the future).
- **Specificity** orders candidates: count of concrete predicates
  (hash pin > cwd > uid > bare class), lexicographic `id` as the final
  deterministic tiebreak.
- **Equal-specificity conflict with different `mode`s ⇒ never escalate.**
  Apply the least aggressive mode among the tied rules
  (`observe < shadow < enforce`) and emit a `binding_conflict` evidence event.
  The loader additionally rejects *statically detectable* same-class
  same-specificity mode conflicts outright. Ambiguity resolving downward is
  the registry-level analogue of deny-wins composition — for un-consented
  workloads, "safe" points at observe, not at block.
- **No match ⇒ `[defaults]`** (`known_agent` for classified,
  `unknown_agent` otherwise). Defaults cannot name `enforce`; the schema
  forbids it, keeping "enforcement requires a specific, expiring, operator-
  authored rule" as a structural property.

### 6.4 Registry trust

The registry is now the highest-value tamper target on the host (rewrite it
and you disarm or weaponize the sensor), so it inherits the daemon-hardening
posture (#108/#109/#110, fixes in flight on PR #115): loaded only from
root-owned paths (fleet) or hub-token-authenticated writes (personal);
`sha256(registry)` recorded in every policy-attachment evidence block (§8) so
an auditor can prove *which* rules were live when a plan applied; changes
appended to the evidence log as first-class events. A signed-registry
extension (operator key, offline-verifiable like receipts) is the natural
v0.2 hardening and needs no schema change beyond a detached signature file.

## 7. Unknown-agent resolution

When the classifier abstains or scores below every binding's threshold:

- **AG-1 is the resting state**: provenance passport (with the classifier's
  abstention and confidence recorded — honest-abstention extends into the
  classifier itself), telemetry, correlator feed. No plan.
- **TOFU pinning without TOFU trust.** First observation of a new
  (agent_class, binary_sha256) pair is recorded as a `first_seen` evidence
  event — like an SSH known-hosts entry, but the recorded fact confers no
  authorization. Subsequent hash drift for a pinned binding (§6.1) makes the
  binding *stop matching* — the session falls to `[defaults]`, an
  `identity_drift` event fires, and enforcement quietly disarms rather than
  enforcing the wrong policy on an updated (or replaced) binary. Bindings
  fail safe on drift by construction, because match-failure ⇒ ladder-descent.
  Operators who want drift to *block* instead configure `host_posture =
  "lockdown"` — at which point they have opted into Santa-LOCKDOWN semantics
  knowingly.
- **Operator quarantine option, not default.** An operator MAY route
  unknown-but-agent-like processes into a shadow baseline
  (`unknown_agent = "shadow"` with a deliberately generic profile) — the
  guest-VLAN analogue. The shipped default stays `observe`: a false positive
  on an unknown process under shadow still costs nothing, but the noise
  budget belongs to the operator, not to us.
- **Reclassification funnel**: `ardur agents classify <pid|hash> --as
  <class>` writes an override entry (B2's operator override list), which is
  itself registry-adjacent state — hashed into evidence the same way.

## 8. Attestation: how an auto-selected policy becomes provable

The plan's §3 established the credential split (Mission Passport = intent;
Provenance Passport = observation; intent absent ⇒ `INSUFFICIENT_EVIDENCE`).
Policy selection adds the third artifact: proof of **which policy attached and
why**. Every plan application on an adopted cgroup appends a policy-binding
block to the evidence chain:

```json
{
  "type": "ardur.policy_binding.v0",
  "provenance_passport_jti": "…",
  "mission_origin": "synthesized | class_binding | learned_candidate",
  "posture_tier": "AG-2",
  "binding_id": "claude-repos-enforce",        // null for synthesized
  "registry_sha256": "…",                      // null for synthesized
  "profile_sha256": "…",
  "plan_sha256": "…",                          // canonical BpfPolicyPlan hash
  "enforce_mode": "permissive | enforce",
  "tier2_residue": ["url_allowlist_hostname:slack.com"],
  "classifier": {"class": "claude-code", "confidence": 0.97},
  "generation": 7                              // BPF map double-buffer gen
}
```

Verifier semantics extend tri-state cleanly with **two distinct compliance
claims** so class-level intent can never launder into session-level intent:

| Claim | Wrapped (mission) | AG-3 (class binding) | AG-2 (synthesized) | AG-1 |
|---|---|---|---|---|
| `mission_compliance` (this session did what its operator asked) | PERMIT/DENY | **INSUFFICIENT_EVIDENCE** — no session mission exists | INSUFFICIENT_EVIDENCE | INSUFFICIENT_EVIDENCE |
| `class_policy_compliance` (this session stayed inside the operator's standing policy for its class) | PERMIT/DENY (subsumed) | PERMIT/DENY against the bound profile | **INSUFFICIENT_EVIDENCE** (shadow evidence is advisory, never a verdict) | INSUFFICIENT_EVIDENCE |

An operator binding rule *is* a real declaration of intent — but intent about
a **class**, standing, coarse; not about a session. Keeping the claims apart
is what lets AuditBench and the paper lane distinguish "governed because
someone decided" from "observed because we happened to see it."

Weaker binding, stated honestly: a wrapped session can carry
proof-of-possession (`holder_key_thumbprint` / KB-JWT); an auto-governed
process holds no key. The provenance passport binds to **process identity**
— (boot_id, cgroup_id, pid, starttime) — which is non-transferable but also
non-cryptographic; a pid-reuse race or cgroup escape breaks it in ways a
stolen PoP token cannot be broken. The passport schema must carry
`binding_strength: "process" | "holder_key"` so verifiers can weight
accordingly. Revocation needs no new machinery: provenance passports carry
`jti` and flow through `docs/specs/revocation-v0.1.md`; revocation of a
*binding* (registry edit) disarms enforcement at the next reconcile, and the
registry-hash chain proves when.

## 9. Consent and override UX

Two distinct consent relationships, one mechanism.

**Personal path (the developer is the operator).** First detection of a
class with no binding raises a hub notification and a CLI surface:

```
$ ardur agents list
  CLASS        CONF  TIER  SESSIONS  SHADOW-DENIES(30d)  BINDING
  claude-code  0.97  AG-2  14        0                   —
  codex        0.91  AG-2  3         2 (exec outside cwd) —
$ ardur agents review codex          # shows the would-have-denied evidence
$ ardur agents bind claude-code --profile safe-coding --mode enforce \
      --cwd '~/repos/**'             # writes a [[binding]], validates via
                                     # dry-run lowering, records evidence
$ ardur agents ignore <binary-sha>   # explicit negative consent, also recorded
```

The funnel deliberately ends at AG-4: the `bind` output nudges
"for tool-level and budget governance, relaunch under `ardur run`" — auto-
governance is the net, `ardur run` is the destination (Defender
discovery→onboard, pattern 5).

**Fleet path.** Silent detection and central policy is the EDR norm; the
consent surface is organizational (the operator owns the host). What Ardur
adds beyond the norm: enforcement transitions are **visible to the governed**.
When an `enforce` binding first matches a *running* session, the daemon
applies the profile in shadow for `escalation_grace_s`, emits a countdown
`enforcement_pending` event (and hub notification), then flips the generation
to ENFORCE via the double-buffered swap. Grace applies only to
already-running sessions; new sessions of a bound class enforce from first
exec. An `--immediate` override exists for incident response and is itself an
evidence event.

**Denial-time UX.** An EPERM from the kernel tier is opaque to the blocked
agent. The daemon pairs every enforced denial with: (a) the `enforce_event`
in the chain (exists today, #100), (b) a hub notification naming the
`binding_id` and profile line that produced the deny, and (c) a one-shot
override path — `ardur agents pause <session> --for 15m` (drops that session
to shadow, evidence-logged, hub-token-gated) — plus the existing global
kill-switch (#108-hardened) as break-glass. A denial the operator can't
attribute to a rule in one command is a denial that gets Ardur uninstalled.

## 10. Composition with `mission_compile → bpf_lower → apply_policy`

The pipeline is reused verbatim; auto-governance only changes **where its
inputs come from** and adds guards at the seams:

```
                       WRAPPED (Epic A)                    AUTO (Epic B)
inputs                 operator CLI flags / mission file   binding registry (AG-3)
                                                           or synthesized baseline (AG-2)
                │                                   │
                ▼                                   ▼
        MissionPassport (issued, signed)     mission-shaped policy input
                │                            + mission_origin discriminator
                ├────────── mission_compile ────────┤   (Biscuit facts/checks —
                │            (proxy tier-2)         │    WRAPPED ONLY; no proxy
                │                                   │    exists on the auto path)
                ▼                                   ▼
        lower_to_bpf_policy_plan(...)  ←── identical call, both paths
                │        enforce_mode: per --enforce │ per binding mode
                │        STRICT loud-guard           │ + SynthesizedMissionEnforceError
                ▼                                   ▼
        BpfPolicyPlan ──► daemon apply_policy ──► cgroup_op_policy /
                          (#96; authz #115)        path_allow / net_allow maps
                          cgroup: created at launch │ adopted post-hoc (B4)
```

Concrete consequences already handled by design choices above, restated as
the contract for B5 implementation:

1. **`mission_compile` (Biscuit emission) does not run on the auto path.**
   There is no proxy authorizer to consume facts/checks. The registry
   validator therefore rejects `enforce` bindings whose profile carries
   proxy-only dimensions (§6.2) instead of letting them silently become
   vaporware — the exact failure `MissionPolicyNotImplementedError` was
   invented to prevent.
2. **Tool-name dimensions degrade explicitly.** `_tool_to_bpf_op` projection
   (best-effort name → op) applies; unmappable names are `tier2_ops` residue
   = load error for enforce bindings, evidence-labeled residue for shadow.
   Registry documentation steers profiles toward `allowed_side_effect_classes`
   and path/net scopes — the dimensions with kernel-true semantics.
3. **`OP_EXTERNAL_SEND` is unenforceable pre-adoption** (proxy-synthetic op).
   Enforce bindings that deny only `external_send` are legal but the loader
   warns they bind nothing until the session is wrapped; evidence carries the
   gap.
4. **Plan lifecycle keys on the adopted cgroup** exactly as Epic A keys on
   the launched cgroup: same double-buffer generation swap (#101/#110), same
   `enforce_events` chain (#100), same kill-switch. Ladder transitions
   (AG-2→AG-3, grace expiry, drift disarm) are plan replacements with
   incremented generation — no new kernel mechanism.
5. **Loud-abort symmetry.** `run_governed`'s contract — if `--enforce`
   can't install kernel policy, kill the agent rather than run unguarded —
   inverts for auto: if an `enforce` binding can't attach (adoption failed,
   maps unavailable, daemon authz refused), the session **falls to shadow,
   loudly** (`enforcement_attach_failed` event + notification). We cannot
   kill what we did not start and nobody asked us to kill; the fail-safe
   direction flips because the consent baseline flips.

## 11. Deltas required to existing machinery

Deliberately small; everything else composes.

| # | Delta | Where | Size |
|---|---|---|---|
| D1 | `mission_origin` discriminator (`declared / synthesized / class_binding / learned_candidate`) threaded from policy input → plan → evidence | passport/plan/evidence schemas | S |
| D2 | `SynthesizedMissionEnforceError` guard + tests | auto-governance path (B5) | S |
| D3 | Binding registry: TOML schema, loader with dry-run-lowering validation, resolution engine, evidence hashing | new module (`agent_bindings.py`) | M |
| D4 | `cgroup_path_deny` LPM trie for the self-protection floor (current vocabulary has `ACT_ALLOWLIST` but no path-scoped deny — `path_allow` cannot express "deny only these paths") | `process_guard.bpf.c` + `bpf_types` + daemon | M, deferrable (floor ships shadow-only until it lands) |
| D5 | `ardur.policy_binding.v0` evidence block + two-claim verifier extension (`class_policy_compliance`) | receipt/verifier/specs | M |
| D6 | `ardur agents` CLI family (`list/review/bind/ignore/classify/pause`) | cli.py + hub | M |
| D7 | Side-effect-class vocabulary reconciliation (passport docstring vs `bpf_types`) | passport.py docs | XS, pre-B5 hygiene |

## 12. Failure modes (red-team pass)

- **Misclassification + enforce binding = broken legit process.** Bounded by:
  binding requires `min_confidence`, optional hash pin, shadow-soak grace,
  and the promotion workflow that puts 30 days of shadow evidence in front
  of the operator first. Residual risk is the operator's explicit rule — the
  same liability line every EDR draws.
- **Registry tamper / malicious binding** ("bind claude-code to a profile
  that allowlists exfil paths"). Root-owned/hub-gated writes, registry hash
  in every attachment block, change events in the chain (§6.4). A binding
  can weaken only what it could have strengthened; it cannot suppress
  provenance attestation or the observe floor, which are not
  registry-controlled.
- **Agent evades classification** (renamed binary, custom fork). False
  negative = AG-0/AG-1 — the observability-gap metric (#39) exists to price
  this; policy design contributes only the guarantee that *nothing* in the
  ladder assumes detection is complete.
- **Policy flapping** (cwd changes, confidence oscillates around θ).
  Hysteresis in the resolver: tier transitions rate-limited per session,
  descents immediate, ascents debounced (`escalation_grace_s` floor).
- **Sub-agent trees.** A bound agent spawning helpers inherits the cgroup ⇒
  the plan governs the tree automatically (cgroup-scoped maps). A *different
  agent class* detected inside a governed tree (Claude spawning codex) fires
  detection normally; its binding resolves independently but its enforcement
  ceiling is the intersection (it cannot escape the parent cgroup's plan) —
  document as emergent, correct behavior.
- **pid-reuse / adoption races** are B4's problem, but policy carries the
  fail-safe: attach failure ⇒ shadow, never a best-guess enforce.

## 13. Recommendation and the hardest open question

**Recommended default-policy model** — *observe-first, identity-bound,
operator-promoted*, concretely:

1. Default for any detected agent: **AG-1 observe** (provenance passport,
   no plan). Default for a *classified* agent: **AG-2 shadow** — a
   synthesized, per-class baseline lowered through the existing
   `lower_to_bpf_policy_plan` in `ENFORCE_MODE_PERMISSIVE`, structurally
   barred from enforcing (D2), existing to manufacture the
   would-have-denied evidence that makes promotion a reviewed, one-command
   act.
2. Enforcement **only** via an operator binding rule (AG-3): registry-
   declared, class-keyed, confidence-thresholded, expiring, validated by
   dry-run lowering at load, resolved most-specific-wins with
   ambiguity-resolves-downward.
3. Two-claim verifier semantics so class-policy compliance never
   impersonates mission compliance; synthesized shadow output is advisory
   evidence, never a verdict.
4. One default-on exception: the self-protection floor, shadow-only until
   the `cgroup_path_deny` delta lands.
5. The ladder's exit is adoption: auto-governance is the discovery funnel
   whose success metric is sessions *leaving* it for `ardur run`.

**The single hardest open question — the enforcement ceiling of a
proxy-less agent.** For un-wrapped agents there is no tool-call boundary,
so everything that makes Ardur's governance *semantic* — tool allowlists,
per-class budgets, delegation narrowing, `external_send`, flow/effect
policies, lineage budgets — has no interposition point, and honest
auto-enforcement caps at coarse kernel ops (exec/file/net per cgroup). The
unresolved fork: **(a)** accept the ceiling and say so (this document's
stance — but then "auto-govern" headline claims must be written carefully,
because AG-3 "enforced" is a much weaker statement than wrapped
"enforced"); **(b)** interpose post-hoc — env-var/API-base steering or
LD_PRELOAD-style injection into an already-running process — which is
invasive, consent-fraught, per-agent brittle, and trivially evadable by
exactly the workloads that matter; or **(c)** make conversion the product:
auto-detection exists to drain un-wrapped sessions into `ardur run`
(restart under governance), accepting that transparent governance of a
*running* agent is intentionally bounded. (a)+(c) is the recommended
posture, but the choice shapes Epic B's headline claim, its AuditBench
scoring, and the paper-lane narrative, and deserves an explicit ADR before
B5 lands. Secondary open questions: promotion-evidence thresholds (what
shadow-clean duration justifies suggesting enforce?), signed-registry
timing, and whether AG-2 baselines ship per-class network scopes (risk:
synthesized net allowlists age badly as providers move endpoints).

## 14. Sources

Repo (verified on `origin/dev` at c73c0b9 unless noted):
`python/vibap/run_bridge.py` (`run_governed`, loud-abort), `python/vibap/
bpf_lower.py` + `bpf_types.py` (plan vocabulary, STRICT guard), `python/
vibap/mission_compile.py` (`MissionPolicyNotImplementedError`), `python/
vibap/passport.py` (`MissionPassport`, `_KNOWN_FIELDS`, PoP), `python/vibap/
ardur_profile.py` + `cli.py` (`ArdurProfile`, `CLAUDE_CODE_PROTECT_MODES`),
`python/vibap/behavioral_fingerprint.py`, `docs/specs/revocation-v0.1.md`,
`docs/security-model.md`; `docs/roadmap/epic-b-auto-detection-plan.md` (lane
branch `docs/epic-b-auto-detection-plan`, in flight).

Web (accessed 2026-07-03):

- CrowdStrike prevention-policy phasing and host groups:
  <https://inventivehq.com/knowledge-base/crowdstrike/how-to-setup-prevention-policies-in-crowdstrike-falcon>,
  <https://medium.com/fmisec/crowdstrike-falcon-series-deployment-to-maximum-protection-5ba791d33270>,
  <https://answers.uillinois.edu/illinois/page.php?id=93996>
- Microsoft Defender ASR audit→block, ring deployment:
  <https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-plan>,
  <https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-implement>
- Defender device discovery (unmanaged → inventory → onboard):
  <https://learn.microsoft.com/en-us/defender-endpoint/device-discovery>
- ThreatLocker Learning Mode → default deny:
  <https://www.threatlocker.com/platform/learning-mode>,
  <https://threatlocker.kb.help/the-threatlocker-default-deny-policy/>,
  <https://threatlocker.kb.help/automatic-policy-creation/>
- Santa MONITOR/LOCKDOWN semantics: <https://santa.dev/concepts/mode.html>,
  <https://github.com/northpolesec/santa>
- SELinux targeted/unconfined; AppArmor complain mode + `aa-logprof`:
  <https://documentation.suse.com/sles/12-SP5/html/SLES-all/cha-apparmor-concept.html>,
  <https://wiki.archlinux.org/title/AppArmor>,
  <https://tuxcare.com/blog/selinux-vs-apparmor/>
- NAC/802.1X quarantine & guest VLAN, posture assessment:
  <https://www.forescout.com/glossary/802-1x-network-access-control/>,
  <https://infohub.delltechnologies.com/static/media/60658f87-85c9-4493-a78a-7871a3e7acbb.pdf>
- Kubernetes PSA enforce/audit/warn; Gatekeeper dryrun/warn:
  <https://cloud.google.com/kubernetes-engine/docs/how-to/pod-security-policies-with-gatekeeper>,
  <https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/>
- Entra Conditional Access, unmanaged-device limited access:
  <https://learn.microsoft.com/en-us/sharepoint/control-access-from-unmanaged-devices>,
  <https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-compliance>
- NIST SP 800-207 (PE/PA/PEP, default-deny posture):
  <https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-207.pdf>
