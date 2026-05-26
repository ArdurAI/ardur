# Verifier Contract v0.1

> **Public-import note.** This document was authored against the private
> research repo's `docs/spec/` layout. In the public ardur tree, migrated specs
> live under `docs/specs/`. Any `docs/spec/...` path reference in the body of
> this document refers to the original private layout; the public-tree mapping
> is in [`docs/specs/README.md`](./README.md). The Mission Declaration and
> Execution Receipt companion specs are now public — see
> [`mission-declaration-v0.1.md`](./mission-declaration-v0.1.md),
> [`execution-receipt-v0.1.md`](./execution-receipt-v0.1.md), and
> [`execution-receipt-eat-profile-v0.1.md`](./execution-receipt-eat-profile-v0.1.md).
> Conformance test vectors (`docs/specs/conformance/`) remain to be imported.

## 1. Scope

This document defines the **stateful tri-state verifier contract** for the
MCEP (Mission-Controlled Execution Protocol) runtime-governance protocol.

The verifier is the component that composes:

- the Mission Declaration (MD), defined by A.1;
- the Delegation Grant (DG), defined by A.2 as an AAT-profiled delegation
  artifact; and
- the Execution Receipt (ER), defined by A.3.

This document standardizes:

1. the verifier interface;
2. the tri-state verdict codomain;
3. the verifier-side lineage state model;
4. the minimum typed projection required for an honest `compliant` verdict;
5. the `enforce` and `attest` execution modes;
6. the fail-closed rule set for missing or inconsistent evidence; and
7. the minimum-information denial-reason policy.

This document does **not** redefine the MD claims set, the DG wire format, or
the ER claims set. It defines how the verifier consumes and produces those
artifacts.

This document uses the key words **MUST**, **MUST NOT**, **REQUIRED**,
**SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**,
**NOT RECOMMENDED**, **MAY**, and **OPTIONAL** as described in BCP 14
(RFC 2119 / RFC 8174).

## 2. Companion Artifacts

This contract composes with the following companion specifications. The
paths below reflect the private research repo's `docs/spec/` layout where
the v0.1 series was authored. In the public ardur repo, migrated specs
live under `docs/specs/`; pending companion specs are listed by name in
[`docs/specs/README.md`](../specs/README.md) until they migrate.

- **A.1 / Mission Declaration**:
  `docs/spec/mission-declaration-v0.1.md` (migrated — see
  [`./mission-declaration-v0.1.md`](./mission-declaration-v0.1.md))
- **A.2 / Delegation Grant profile**:
  `docs/spec/delegation-grant-profile-v0.1.md` (migrated — see
  [`./delegation-grant-profile-v0.1.md`](./delegation-grant-profile-v0.1.md));
  references to `docs/session-2026-04-14/...` source briefs are private
  research material that has not been imported.
- **A.3 / Execution Receipt**:
  `docs/spec/execution-receipt-v0.1.md` (migrated — see
  [`./execution-receipt-v0.1.md`](./execution-receipt-v0.1.md))

The verifier MUST treat those companion documents as authoritative for the
shapes of MD, DG, and ER.

If a local deployment observes a conflict between this contract and a companion
artifact, the verifier MUST fail closed and the deployment MUST resolve the
schema conflict before claiming conformance.

## 3. Interface

### 3.1 Normative Signature

The verifier interface is:

```text
Evaluate(MD, DG, ObservedEvent, LineageState) -> (Verdict, StateDelta, ExecutionReceipt)
```

The function arguments have the following meanings:

- `MD`: the governing Mission Declaration for the current lineage.
- `DG`: the active Delegation Grant authorizing the observed step.
- `ObservedEvent`: the normalized typed projection of the observed step.
- `LineageState`: verifier-local mutable state keyed by `root_mission_id`.

The return tuple has the following meanings:

- `Verdict`: one of `compliant`, `violation`, or `insufficient_evidence`.
- `StateDelta`: the verifier-local mutation to apply to `LineageState`.
- `ExecutionReceipt`: an ER claims set conforming to A.3.

### 3.2 Root Lineage Key

`root_mission_id` MUST equal `MD.mission_id`.

Every invocation of `Evaluate()` MUST resolve the active state bucket by
`root_mission_id`.

Derived DGs MUST NOT fork verifier state into a new root lineage merely because
they have a different grant identifier. A new `LineageState` bucket MAY be
created only when the verifier observes a different `MD.mission_id`.

### 3.3 StateDelta Semantics

`StateDelta` is verifier-local and is not itself a portable wire artifact.

At minimum, a `StateDelta` MAY update:

- `active_grants`;
- `delegation_graph`;
- `consumed_budget`;
- `reserved_budget`;
- `outstanding_revocations`; and
- `last_seen_receipts`.

An empty state delta is represented as `{}`.

An implementation MUST emit an ER even when `StateDelta = {}`.

## 4. Verdict Codomain

`Verdict` is a closed enum:

```text
Verdict in { compliant, violation, insufficient_evidence }
```

The meanings are:

- `compliant`: the verifier had sufficient typed evidence and determined that
  the observed step satisfies the governing MD and DG.
- `violation`: the verifier had sufficient typed evidence and determined that
  the observed step violates policy, integrity, revocation, or budget rules.
- `insufficient_evidence`: the verifier could not honestly determine
  compliance because required evidence was missing, hidden, ablated, revoked
  out from under the observation, or structurally inconsistent.

The verifier MUST NOT collapse `insufficient_evidence` into `compliant`.

The verifier MUST NOT treat `insufficient_evidence` as a synonym for
`violation`. `insufficient_evidence` is an honesty outcome about the
projection, not proof of malicious action.

## 5. LineageState

### 5.1 Required Shape

`LineageState` is keyed by `root_mission_id` and MUST track at least the
following members:

```text
LineageState[root_mission_id] = {
  active_grants: Map<grant_id, ActiveGrantRecord>,
  delegation_graph: {
    nodes: Set<grant_id>,
    edges: Set<(parent_grant_id, child_grant_id)>
  },
  consumed_budget: Map<effect_class, non_negative_integer>,
  reserved_budget: Map<effect_class, non_negative_integer>,
  outstanding_revocations: Set<grant_id | mission_id>,
  last_seen_receipts: Map<grant_id, receipt_id>
}
```

### 5.2 Active Grants

`active_grants` MUST be keyed by DG identifier.

Each `ActiveGrantRecord` SHOULD include enough data to evaluate:

- the grant subject;
- the parent grant link;
- grant expiration;
- mission reference; and
- any reserved-budget share carried by the DG.

The verifier MUST remove or mark inactive any grant whose lifetime has expired
or whose lineage is revoked.

### 5.3 Delegation Graph

`delegation_graph` is authoritative for visible lineage ancestry inside the
verifier.

The verifier MUST maintain a directed acyclic graph over observed grants.

If an observed child grant cannot be linked to its declared parent through
`delegation_graph`, the verifier MUST treat the hop as hidden and MUST return
`insufficient_evidence` under the rules in Section 9.

### 5.4 Budget Buckets

`consumed_budget` and `reserved_budget` MUST use the MD effect-class namespace
from A.1:

- `read`
- `write`
- `network`
- `exec`
- `external_send`

If an observation pipeline exposes a richer or different side-effect taxonomy,
the verifier MUST deterministically normalize it into one of the five budget
effect classes above before mutating state.

The verifier MUST reject ambiguous normalization rules.

### 5.5 Reserved Budget Initialization

On first observation of a lineage, the verifier MUST initialize
`reserved_budget` from `MD.lineage_budgets.per_effect_class.*.reserved`.

The verifier MUST initialize the budget ceiling for comparison from
`MD.lineage_budgets.per_effect_class.*.ceiling`.

The verifier MUST NOT infer ceilings from previously observed traffic.

### 5.6 Outstanding Revocations

`outstanding_revocations` MUST contain:

- any mission-wide revocation affecting `root_mission_id`; and
- any ancestor grant revocation whose descendants remain present in
  `active_grants`.

If a grant or mission appears in `outstanding_revocations`, the verifier MUST
apply cascading invalidation to all descendants of the revoked node.

### 5.7 Last Seen Receipts

`last_seen_receipts[grant_id]` MUST track the latest ER emitted for the grant.

Under MIC-Evidence, the verifier MUST use this mapping to detect missing linked
receipts, replayed receipt chains, and hidden-hop gaps.

## 6. ObservedEvent Typed-Projection Contract

### 6.1 General Rule

`ObservedEvent` is the verifier's typed, normalized view of a runtime action.

The verifier MUST NOT return `compliant` unless:

1. every field named in `MD.required_telemetry` is present, well-typed, and
   non-empty where non-empty values are required; and
2. every additional integrity field required by this section is present and
   successfully verified.

If either condition fails, the verifier MUST return `insufficient_evidence`.

### 6.2 Canonical Field Set

For v0.1, `ObservedEvent` MUST support at least the following canonical members:

| Member | Type | Purpose | Minimum profile |
|---|---|---|---|
| `event_id` | string | Stable identifier for the observed event. | Delegation-Core |
| `session_id` | string | Session or trace identifier. | Delegation-Core |
| `timestamp` | RFC 3339 date-time string | Observation time. | Delegation-Core |
| `actor` | string | Observed principal executing the step. | Delegation-Core |
| `grant_id` | string | Governing DG identifier. MUST identify `DG`. | Delegation-Core |
| `tool_name` | string | Tool or capability invoked. | Delegation-Core |
| `action_class` | string | High-level action family. | Delegation-Core |
| `target` | string | Normalized target. | Delegation-Core |
| `resource_family` | string | Resource namespace used for policy matching. | Delegation-Core |
| `side_effect_class` | string | Observed side-effect class before budget normalization. | Delegation-Core |
| `budget_delta` | object | Claimed budget effect and amount. | MIC-State |
| `visibility` | enum | `full`, `partial`, or `hidden`. | MIC-State |
| `parent_event_id` | string or `null` | Immediate parent event if one exists. | MIC-State |
| `delegation_from` | string or `null` | Parent grant or principal for delegation edges. | MIC-State |
| `delegation_to` | string or `null` | Child grant or principal for delegation edges. | MIC-State |
| `content_class` | string | Content category touched by the step. | MIC-State |
| `content_provenance` | object | Provenance summary used for the decision. | MIC-State |
| `sensitivity` | string | Sensitivity tier of content or target. | MIC-State |
| `instruction_bearing` | boolean | Whether observed content materially instructed the step. | MIC-State |
| `summary` | string | Sanitized summary of the observed action. | MIC-State |
| `confidence_hint` | number or string | Optional observation-confidence signal. | MIC-State |
| `envelope_signature_valid` | boolean | Result of invocation-envelope verification. | MIC-State |
| `observed_manifest_digest` | string | Digest of the runtime tool manifest snapshot. | MIC-State |
| `parent_receipt_id` | string or `null` | Linked parent ER if available. | MIC-Evidence |
| `downstream_receipt_ids` | array | Linked downstream ERs if the step delegated. | MIC-Evidence |

The verifier MAY carry additional local fields, but it MUST NOT rely on those
additional fields when claiming portable conformance unless they are promoted
into a versioned schema.

### 6.3 Minimum Requirements for `compliant`

For a `compliant` verdict, the verifier MUST observe all of the following:

1. every field required by `MD.required_telemetry`;
2. a `grant_id` that resolves to the active DG under the current lineage;
3. a `tool_name`, `action_class`, `target`, and `resource_family` tuple that
   can be matched against the MD and DG without ambiguity;
4. a `budget_delta` whose normalized effect bucket can be applied to the
   lineage ledger;
5. `envelope_signature_valid = true`;
6. `observed_manifest_digest == MD.tool_manifest_digest`; and
7. if the active profile is MIC-Evidence, visible receipt linkage with no
   hidden hop.

If any of the above cannot be established, the verifier MUST return
`insufficient_evidence` or `violation` according to Section 9.

### 6.4 Missing or Partial Visibility

If `ObservedEvent.visibility` is `partial` or `hidden`, the verifier MUST NOT
return `compliant` unless a stronger local evidence model proves that the
missing fields are irrelevant to the mission predicate.

Portable v0.1 conformance MUST assume no such stronger model.

Therefore, portable v0.1 implementations MUST treat `visibility != full` as
`insufficient_evidence`.

### 6.5 Field Normalization

The verifier MUST normalize:

- `ObservedEvent.tool_name` into `ER.tool`;
- `ObservedEvent.parent_receipt_id` into `ER.parent_receipt_id`; and
- `ObservedEvent.side_effect_class` plus `ObservedEvent.budget_delta` into the
  A.1 budget bucket namespace before updating lineage state.

Normalization MUST be deterministic.

If two implementations would map the same observed value to different budget
buckets, neither implementation MAY claim portable MIC-State conformance until
the mapping is fixed.

## 7. Execution Modes

### 7.1 Mode Enum

The verifier MUST support two execution modes:

- `enforce`
- `attest`

The mode affects gating behavior, not the underlying verdict calculation.

Given the same `(MD, DG, ObservedEvent, LineageState)` input tuple, the
verifier MUST compute the same `Verdict` and the same logically corresponding
ER payload regardless of mode.

The enforcement point MAY decide whether and when to apply the returned
`StateDelta` depending on whether the step was blocked before execution or was
merely observed and attested after execution.

### 7.2 `enforce`

In `enforce` mode:

- `violation` MUST block the governed step;
- `compliant` MUST permit the governed step; and
- `insufficient_evidence` MUST follow the MD's
  `insufficient_evidence_policy`.

If the applicable `insufficient_evidence_policy` is fail-closed, the verifier
MUST block the step.

If the applicable `insufficient_evidence_policy` is fail-open-with-attestation,
the verifier MAY permit the step but MUST still emit an ER with verdict
`insufficient_evidence`.

The current A.1 MD schema does not yet publish `insufficient_evidence_policy`
as a first-class claim. Until A.1 is revised, an implementation claiming
conformance to this contract MUST bind that policy through a deployment-local
default or a versioned MD extension and MUST document the binding explicitly.

### 7.3 `attest`

In `attest` mode:

- the verifier MUST NOT block the governed step solely because of its verdict;
- the verifier MUST emit an ER carrying the actual verdict; and
- the verifier SHOULD persist the resulting audit evidence and lineage-state
  update.

`attest` mode is appropriate when the deployment wants portable evidence and
post-hoc accountability without hard blocking at the observation point.

### 7.4 Mode-Independent Receipt Requirement

In both modes, the verifier MUST emit exactly one ER per evaluated event.

Failure to emit an ER for an evaluated event is itself a receipt-completeness
failure under MIC-Evidence.

## 8. Evaluation Procedure

### 8.1 High-Level Algorithm

The verifier MUST evaluate in the following order:

1. verify MD validity and revocation status;
2. verify DG validity, ancestry, and mission binding;
3. resolve `root_mission_id` and load `LineageState[root_mission_id]`;
4. verify the typed projection completeness of `ObservedEvent`;
5. verify envelope binding and tool-manifest integrity;
6. verify revocation and delegation ancestry;
7. verify budget conservation and reservation ceilings;
8. compute `Verdict`;
9. construct `StateDelta`; and
10. emit an ER conforming to A.3.

### 8.2 Normative Pseudocode

```text
function Evaluate(MD, DG, ObservedEvent, LineageState):
    assert MD.mission_id != ""
    root_mission_id = MD.mission_id
    state = LineageState[root_mission_id] or InitializeFromMD(MD)

    if not VerifyMissionBinding(DG, MD):
        return EmitViolation("chain_invalid", {})

    if not VerifyRequiredTelemetry(MD.required_telemetry, ObservedEvent):
        return EmitInsufficientEvidence("telemetry_missing", {})

    if ObservedEvent.visibility != "full":
        return EmitInsufficientEvidence("telemetry_missing", {})

    if not VerifyEnvelopeSignature(ObservedEvent):
        return EmitViolation("envelope_tampered", {})

    if not VerifyManifestDigest(ObservedEvent.observed_manifest_digest,
                                MD.tool_manifest_digest):
        return EmitViolation("manifest_drift", {})

    if IsCascadeRevoked(MD, DG, state.outstanding_revocations):
        delta = { add_revocations: DescendantsOf(DG, state.delegation_graph) }
        return EmitViolation("revoked", delta)

    if HasHiddenHop(ObservedEvent, DG, state.delegation_graph, MD.conformance_profile):
        return EmitInsufficientEvidence("telemetry_missing", {})

    normalized_bucket = NormalizeBudgetBucket(ObservedEvent.side_effect_class,
                                              ObservedEvent.budget_delta)
    if normalized_bucket is INVALID:
        return EmitInsufficientEvidence("telemetry_missing", {})

    if OverReserveOrOverspend(MD, DG, state, normalized_bucket, ObservedEvent.budget_delta):
        return EmitViolation("budget_exhausted", {})

    if not PolicyAllows(MD, DG, ObservedEvent):
        return EmitViolation("policy_denied", {})

    delta = {
        consumed_budget: Add(state.consumed_budget,
                             normalized_bucket,
                             ObservedEvent.budget_delta.delta),
        last_seen_receipts: Set(DG.jti, NextReceiptID())
    }
    return EmitCompliant(delta)
```

The helper functions `EmitCompliant()`, `EmitViolation()`, and
`EmitInsufficientEvidence()` MUST each produce an ER with an A.3-conformant
`verdict`, `public_denial_reason`, and audit-only `internal_denial_code`
policy. Helper arguments such as `"telemetry_missing"` are internal codes
unless they are also present in the public vocabulary.

## 9. Fail-Closed Rule Set

The following fail-closed rules are normative:

| Condition | Required verdict | Public denial reason | Audit-only internal code |
|---|---|---|---|
| Hidden hop | `insufficient_evidence` | `insufficient_evidence` | `telemetry_missing` |
| Missing required telemetry | `insufficient_evidence` | `insufficient_evidence` | `telemetry_missing` |
| Cascading revocation | `violation` | `revoked` | `revoked` |
| Budget over-reserve or overspend | `violation` | `budget_exhausted` | `budget_exhausted` |
| Envelope signature invalid | `violation` | `policy_denied` | `envelope_tampered` |
| Manifest digest mismatch | `violation` | `policy_denied` | `manifest_drift` |

### 9.1 Hidden Hop

A hidden hop exists when:

- the verifier can observe a child or descendant action but cannot link it to
  its parent edge in `delegation_graph`; or
- the verifier requires linked ERs under MIC-Evidence and a required receipt is
  absent.

In either case, the verifier MUST return `insufficient_evidence`.

### 9.2 Missing Required Telemetry

If any field named in `MD.required_telemetry` is missing, structurally invalid,
or unusable for deterministic policy evaluation, the verifier MUST return
`insufficient_evidence`.

The verifier MUST NOT synthesize placeholder values to rescue a `compliant`
verdict.

### 9.3 Cascading Revocation

If the MD is revoked, or if any ancestor grant in the active lineage is
revoked, the verifier MUST return `violation` for descendant actions.

The verifier MUST update `outstanding_revocations` so later descendant actions
remain invalid even if intermediate telemetry arrives out of order.

### 9.4 Budget Over-Reserve

If a child grant reserves more budget than is available under the parent's
remaining reserved share, or if an observed step would push cumulative lineage
consumption above the mission ceiling, the verifier MUST return `violation`.

This rule is load-bearing for the escrow-rights model. The verifier MUST NOT
permit "best effort" over-reserve.

### 9.5 Envelope Signature Invalid

If the normalized invocation envelope fails signature verification, the
verifier MUST return `violation`.

This is an integrity failure, not a telemetry-quality failure.

### 9.6 Manifest Digest Mismatch

If the observed runtime tool manifest digest differs from
`MD.tool_manifest_digest`, the verifier MUST return `violation`.

This applies even if the substituted tool would otherwise appear policy-safe.

## 10. Denial-Reason Policy

### 10.1 Minimum-Information Requirement

Per B.8, user-facing denial strings are an information-leakage surface.

The verifier MUST restrict user-facing reason strings to the closed
`public_denial_reason` vocabulary defined by A.3.

At minimum, every implementation of this contract MUST support:

- `policy_denied`
- `budget_exhausted`
- `insufficient_evidence`
- `revoked`
- `chain_invalid`

Detailed conditions such as `telemetry_missing`, `manifest_drift`, and
`envelope_tampered` MUST be recorded only as audit-channel
`internal_denial_code` values unless a deployment-specific private profile
authorizes their disclosure.

### 10.2 Audit Channel Separation

The verifier MUST NOT emit free-form denial explanations, policy fragments,
stack traces, rule identifiers, or secret-dependent causal detail in the
user-facing ER payload.

Detailed verifier-local explanation MUST go to an audit channel only.
`internal_denial_code` is part of that audit projection and SHOULD be omitted
from public ER views.

The audit channel SHOULD include enough structured detail to support forensic
replay of the decision, including the specific failed predicate, observed field
values, and state bucket touched.

### 10.3 Oracle-Bit Objective

Deployments SHOULD target the B.8 objective that the mutual information leaked
by user-facing denials remains bounded.

This document does not define the measurement algorithm, but implementations
SHOULD track the companion `denial_oracle_bits` metric and SHOULD keep it at or
below the B.8 target.

## 11. Worked Examples

### 11.1 `compliant`

**Setup**

- `MD.mission_id = "urn:mission:acme:pr-142-review"`
- `DG.jti = "urn:grant:leaf-7"`
- `MD.conformance_profile = "MIC-State"`
- `MD.required_telemetry` includes `timestamp`, `actor`, `tool_name`,
  `action_class`, `target`, `resource_family`, `side_effect_class`,
  `budget_delta`, `grant_id`, and `content_class`
- `LineageState["urn:mission:acme:pr-142-review"].consumed_budget.write = 2`
- `LineageState["urn:mission:acme:pr-142-review"].reserved_budget.write = 4`

**ObservedEvent**

```text
tool_name = "github.create_review_comment"
action_class = "write"
target = "github.com/acme/widget-api/pull/142#discussion-19"
resource_family = "pull_request"
side_effect_class = "internal_write"
budget_delta = { bucket = "write", delta = 1 }
envelope_signature_valid = true
observed_manifest_digest = MD.tool_manifest_digest
visibility = "full"
```

**Result**

- all required telemetry is present;
- the envelope is intact;
- the manifest digest matches;
- the normalized budget bucket is `write`; and
- `2 + 1 <= 4`.

The verifier returns:

```text
Verdict    = compliant
StateDelta = { consumed_budget.write += 1, last_seen_receipts["urn:grant:leaf-7"] = <new receipt id> }
ER.verdict = "compliant"
```

### 11.2 `violation`

**Setup**

- same lineage as above;
- `LineageState["urn:mission:acme:pr-142-review"].consumed_budget.external_send = 0`
- `MD.lineage_budgets.per_effect_class.external_send.ceiling = 0`

**ObservedEvent**

```text
tool_name = "slack.send_message"
action_class = "send"
target = "slack://C01SECOPS"
resource_family = "external_comms"
side_effect_class = "external_send"
budget_delta = { bucket = "external_send", delta = 1 }
envelope_signature_valid = true
observed_manifest_digest = MD.tool_manifest_digest
visibility = "full"
```

**Result**

The typed projection is complete, so this is not an evidence problem. The step
would overrun a mission ceiling of zero for `external_send`.

The verifier returns:

```text
Verdict             = violation
StateDelta          = {}
ER.verdict          = "violation"
ER.public_denial_reason = "budget_exhausted"
ER.internal_denial_code = "budget_exhausted"
```

In `enforce` mode the step is blocked. In `attest` mode the step is not blocked
by the verifier, but the same ER is emitted.

### 11.3 `insufficient_evidence`

**Setup**

- `MD.conformance_profile = "MIC-Evidence"`
- `LineageState` contains the parent grant but no linked receipt for the
  delegation edge that led to the observed child action.

**ObservedEvent**

```text
tool_name = "files.read_file"
action_class = "read"
target = "s3://customer-artifacts/2026/q2/export.csv"
resource_family = "report_data"
side_effect_class = "none"
visibility = "partial"
parent_receipt_id = null
downstream_receipt_ids = []
```

**Result**

The verifier cannot reconstruct the visible delegation hop required by the
profile. The action might be benign, but the projection is incomplete.

The verifier returns:

```text
Verdict             = insufficient_evidence
StateDelta          = {}
ER.verdict          = "insufficient_evidence"
ER.public_denial_reason = "insufficient_evidence"
ER.internal_denial_code = "telemetry_missing"
```

In `enforce` mode, the next action depends on the deployment's
`insufficient_evidence_policy`. In `attest` mode, the step is allowed to
proceed while the ER records the evidence gap.

## 12. Security Considerations

### 12.1 Partial Observation Honesty

The main security property of this contract is honesty under partial
observation.

The verifier MUST prefer `insufficient_evidence` over a guessed `compliant`
result when the observation channel loses information needed for MIC.

### 12.2 Integrity Before Policy

The verifier MUST check envelope integrity, mission binding, manifest binding,
and revocation before claiming a policy-based `compliant` result.

Policy evaluation on top of an untrusted envelope is not meaningful.

### 12.3 Stateful Safety

Budget conservation, cascading revocation, and hidden-hop detection all require
verifier-local state.

A stateless implementation MAY still implement Delegation-Core checks, but it
MUST NOT claim MIC-State or MIC-Evidence conformance unless it maintains the
lineage state required by this document.

## 13. Reference-Implementation Conformance Notes

This spec describes the verifier-contract surface every conformant
implementation MUST eventually meet. The reference Python implementation in
this repository (`python/vibap/proxy.py`) is **partially conformant at v0.1**:
some `MUST` clauses are enforced today, others are documented as design-only
and tracked for future hardening rounds.

This section is the honest map between the spec's `MUST` set and what the
reference proxy actually enforces. It exists so consumers can size the gap
between the specification and the reference implementation — and so the
2026-04-28 hostile audit's FIX-4 finding ("verifier missing major mandatory
checks") is closed by either implementing the check or surfacing the gap.

### 13.1 Implemented checks (all three conformance profiles)

The reference proxy implements the full Delegation-Core, MIC-State, and
MIC-Evidence conformance profiles as of the 2026-05-14 hardening round:

- Mission, DG, and AAT verification (signature, audience, expiry,
  revocation through status-list lookup; FIX-3 ensures the loader fails
  closed on missing required v0.1 members);
- Tool / forbidden-tool / resource-scope / max-tool-calls budget gates;
- Per-session jti single-use and replay defenses, KB-JWT nonce store,
  AAT proof-of-possession (FIX-2 default-secure since 2026-04-28);
- Tri-state verdict (`compliant` / `violation` / `insufficient_evidence`)
  on declared-telemetry absence and on policy violations;
- Receipt chain emission with hash-linked entries and JWS signing;
- Approval-rate-limit enforcement when the MD declares approval policy;
- **Visibility check** (§6.4): `visibility != "full"` → `INSUFFICIENT_EVIDENCE`
  (MIC-State and above);
- **Envelope-signature verification** (§9.5): `envelope_signature_valid is not
  True` → `VIOLATION` / `ENVELOPE_TAMPERED` (MIC-State and above);
- **Manifest digest comparison** (§9.6):
  `observed_manifest_digest == MD.tool_manifest_digest`, skipped when the MD
  carries no digest (MIC-State and above);
- **`last_seen_receipts` tracking** (§5.7): per-grant receipt ID map
  maintained in cross-session lineage state;
- **Hidden-hop detection** (§9.1): parent JTI linkable through lineage
  parent cache and receipt presence (MIC-Evidence);
- **Missing parent receipt** (§5.7): child session requires verifiable
  parent receipt (MIC-Evidence).

All new checks are gated on the session's `conformance_profile` for
backwards compatibility — Delegation-Core sessions skip all checks added
after the baseline.

### 13.2 Implications for conformance claims

A deployment of this reference implementation MAY claim Delegation-Core,
MIC-State, or MIC-Evidence conformance. The four design-only gaps
identified by the 2026-04-28 hostile audit are closed. See
`python/tests/test_mic_conformance.py` for the 29-test conformance suite
validating all three profiles.

## 14. References

- `docs/spec/mission-declaration-v0.1.md` - Mission Declaration schema.
- `docs/spec/execution-receipt-v0.1.md` - Execution Receipt schema.
- `docs/spec/execution-receipt-eat-profile-v0.1.md` - EAT-compatible ER
  profile.
- `docs/session-2026-04-14/09-execution-plan/PLAN.md` Section A.4 - authoritative
  plan item.
- `docs/session-2026-04-14/05-cpo-call-prep/unified-steps-final.md` Section 4.4 -
  precursor pseudocode and tri-state rationale.
- `docs/session-2026-04-14/06-briefs-issued/A2-dg-profile-aat.md` - A.2 DG
  profile brief pending publication of the companion spec.
- `docs/session-2026-04-14/09-execution-plan/PLAN.md` Section B.8 - denial-output
  information-leakage policy.
