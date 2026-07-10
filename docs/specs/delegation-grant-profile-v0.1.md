# Delegation Grant (DG) Profile of Attenuating Authorization Tokens (AAT) v0.1

> **Public-import note.** This document was authored against the private
> research repo's `docs/spec/` layout. In the public ardur tree, migrated specs
> live under `docs/specs/`. Any `docs/spec/...` path reference in the body of
> this document refers to the original private layout; the public-tree mapping
> is in [`docs/specs/README.md`](./README.md). Some companion specs have not
> yet been imported. References to private implementation source paths
> (e.g. `vibap-prototype/vibap/passport.py`) point at the private research
> repo; the corresponding public Python package lands with Phase 1 per
> [`docs/public-import-plan.md`](../public-import-plan.md).

## Status

This document defines version `v0.1` of the Delegation Grant (DG) profile for
the MCEP (Mission-Controlled Execution Protocol) mission-and-evidence layer.

The DG wire format is the Attenuating Authorization Token (AAT) defined by
`draft-niyikiza-oauth-attenuating-agent-tokens-00`.

The live Datatracker document advanced to draft-01 on 2026-06-15. Draft-01 is
an individual Internet-Draft with no formal IETF standing and changes material
wire semantics, including removal of the draft-00 `aat_type` token-role
claim. This v0.1 profile remains intentionally pinned to draft-00; a versioned
migration audit is tracked in
[#233](https://github.com/ArdurAI/ardur/issues/233). Implementations MUST NOT
silently interpret draft-00 tokens under draft-01 rules.

This profile is intentionally narrow:

1. it adopts AAT token structure, derivation, and verification unchanged;
2. it adds one top-level JWT claim, `mission_ref`, to bind an AAT chain to a
   Mission Declaration (MD); and
3. it defines how MD lineage-budget semantics align with profiled AAT chains
   without changing AAT's attenuation semantics.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in RFC 2119
and RFC 8174 when, and only when, they appear in all capitals.

## 1. Introduction

The MCEP protocol family separates three artifacts:

1. Mission Declaration (MD) — issuer-signed mission policy envelope
2. Delegation Grant (DG) — the delegated capability artifact
3. Execution Receipt (ER) — per-hop signed execution evidence

This document specifies the DG artifact only.

The DG artifact is an AAT. This profile does not define a parallel delegation
format. Instead, it composes on top of the AAT draft's common claims, token
types, derivation model, six attenuation invariants, proof-of-possession
structure, and chain-verification algorithm (AAT Sections 3 through 7).

This profile exists because AAT Section 8.1.2 explicitly leaves cumulative
budgets, rate-limit and audit controls, and cross-trace behavior outside AAT's
security scope. The MD and ER companion artifacts cover that space. The only
new DG-level binding needed for that composition is a mission pointer.

## 2. Normative Basis and Compatibility

### 2.1. AAT as the DG Wire Format

Every DG that claims conformance to this profile:

1. MUST be a valid AAT under `draft-niyikiza-oauth-attenuating-agent-tokens-00`;
2. MUST satisfy all AAT common-claim requirements from AAT Section 3.2;
3. MUST use AAT token typing from AAT Section 3.1;
4. MUST satisfy AAT derivation rules from AAT Section 6; and
5. MUST pass the unmodified AAT chain-verification algorithm from AAT
   Section 7 before any profile-specific checks are applied.

If a deployment uses the AAT CBOR/CWT profile from AAT Appendix D, this
profile applies unchanged. `mission_ref` remains an additional DG claim and
does not redefine the Appendix D transport mapping.

An implementation claiming this profile MUST NOT fork, weaken, or replace the
AAT Section 7 algorithm. Profile validation is strictly an additional layer
that runs after AAT verification succeeds.

### 2.2. Backward Compatibility

AAT Section 3.4 requires enforcement points to ignore unrecognized top-level
JWT claims. `mission_ref` therefore does not break AAT interoperability.

A deployment that understands AAT but ignores `mission_ref` remains
AAT-conformant. It is, however, less capable than a deployment that enforces
this profile because it cannot bind the AAT chain to an MD or apply mission-
scoped lineage-budget and evidence semantics.

### 2.3. No New Cryptographic Mechanisms

This profile introduces no new signature scheme, proof-of-possession scheme,
or token-binding mechanism.

Implementations MUST reuse AAT's existing JOSE and PoP machinery, including:

1. AAT token signatures per AAT Section 3.2 and Section 8.14;
2. PoP JWT semantics per AAT Section 5; and
3. `par_hash` chain linkage per AAT Section 4.6 and Section 7.

The optional `mission_digest` member defined by this profile reuses SHA-256
and RFC 8785 JSON Canonicalization Scheme (JCS). It does not add a new
cryptographic primitive.

### 2.4. AAT Sections Used by This Profile

This profile normatively depends on the following parts of the AAT draft:

1. Section 3.1 for token types;
2. Section 3.2 for common claims and signing support requirements;
3. Section 3.4 for top-level-claim compatibility and fail-closed constraint
   behavior;
4. Section 3.5 and Section 9.3 for the OPTIONAL `lineage_budget_share`
   extension-constraint path;
5. Section 4 for invariants I1 through I6;
6. Section 5 for PoP semantics;
7. Section 6 for derivation semantics;
8. Section 7 for chain verification;
9. Section 8.1.2 for the threat space AAT explicitly leaves to companion
   controls;
10. Section 8.14 for algorithm-confusion defenses;
11. Section 9.1 for the JWT-claims registration template; and
12. Appendix D for unchanged CWT/CBOR carriage.

## 3. The `mission_ref` Claim

### 3.1. Purpose

`mission_ref` is a top-level JWT claim carried by a profiled DG. It identifies
the governing MD under which the AAT chain was issued.

`mission_ref` is an external cross-reference only. It does not grant
authority, narrow authority, or alter AAT constraint evaluation.

### 3.2. Claim Value Forms

The `mission_ref` claim value MUST use one of the following encodings:

1. String form:
   - a URI; or
   - a JWK Thumbprint URI using the syntax defined by RFC 9278.
2. Object form:
   - `uri` (string, REQUIRED): a URI or JWK Thumbprint URI identifying the
     governing MD; and
   - `mission_digest` (string, OPTIONAL): SHA-256 over the RFC 8785
     canonical form of the MD payload object.

Profile consumers MUST accept both encodings.

Profile producers SHOULD use object form when they need digest binding.
Profile producers MAY use string form when the MD identifier alone is
sufficient.

If object form is used:

1. `uri` MUST be non-empty;
2. `mission_digest`, when present, MUST be encoded as `sha-256:` followed by
   exactly 64 lowercase hexadecimal characters; and
3. `mission_digest` MUST be computed over the JCS-canonical MD payload object,
   not over compact-JWS bytes, detached JSON text, or implementation-specific
   serializer output.

### 3.3. Issuance and Derivation Rules

For this profile:

1. Every root AAT MUST carry `mission_ref`.
2. Every derived AAT MUST preserve the parent's `mission_ref`.
3. A derived AAT MUST NOT remove `mission_ref`.
4. A derived AAT MUST NOT replace `mission_ref` with a different MD reference.
5. A derived AAT MUST NOT widen `mission_ref` by replacing a more specific
   reference with a less specific one.

Preservation is defined as follows:

1. if the parent uses string form, the child MUST carry the identical string;
2. if the parent uses object form, the child MUST carry the identical `uri`
   value and, when present, the identical `mission_digest` value; and
3. a child MUST NOT change between string form and object form.

Changing the governing MD requires issuance of a new root AAT. It MUST NOT be
done by derivation.

### 3.4. Resolution Semantics

`mission_ref` MAY be dereferenceable, cache-resolved, or deployment-mapped.
This profile does not require online lookup during evaluation.

A verifier that operates offline MAY resolve `mission_ref` from local cache.
A verifier that resolves from cache SHOULD verify `mission_digest` when it is
present.

When a JWK Thumbprint URI is used, deployments MUST define how that URI maps
to the cached or retrieved MD object. The thumbprint URI is an identifier, not
an HTTP dereference requirement.

## 4. Processing Model

A verifier enforcing this profile MUST process a DG chain in the following
order:

1. verify the AAT chain exactly as specified by AAT Section 7;
2. only after AAT verification succeeds, parse and validate `mission_ref`;
3. resolve the referenced MD from cache, dereference, or deployment-local
   mapping;
4. if `mission_digest` is present, recompute the MD payload digest and compare
   it; and
5. apply any mission-layer policy, lineage-budget, and evidence rules defined
   by the deployment's conformance profile.

Failure of steps 2 through 5 is a profile-layer failure. It does not alter the
fact that the underlying AAT chain may still be AAT-valid.

## 5. Interaction with AAT Invariants

### 5.1. Preservation of I1 through I6

This profile preserves the AAT attenuation invariants from AAT Section 4:

1. I1 — Delegation Authority
2. I2 — Depth Monotonicity
3. I3 — TTL Monotonicity
4. I4 — Capability Monotonicity
5. I5 — Cryptographic Linkage
6. I6 — Proof of Possession

`mission_ref` is not part of `authorization_details`, is not part of the AAT
constraint algebra, and is not an input to AAT Section 4.5 subsumption.

Accordingly:

1. `mission_ref` does not narrow or widen the tool set;
2. `mission_ref` does not alter closed-world argument semantics from AAT
   Section 3.3;
3. `mission_ref` does not alter `par_hash` semantics;
4. `mission_ref` does not change `del_depth` or `del_max_depth`; and
5. `mission_ref` does not modify PoP JWT construction or verification.

### 5.2. Verification Compatibility Requirement

Any profiled DG chain that is otherwise valid MUST verify successfully under
an AAT verifier that is unaware of `mission_ref`.

Implementations claiming this profile SHOULD include a conformance test that
demonstrates:

1. the same DG chain passes AAT Section 7 verification before and after
   `mission_ref` is added; and
2. profile validation then enforces `mission_ref` consistency as an additional
   check.

## 6. Escrow-Rights Alignment

### 6.1. Scope Boundary

AAT Section 8.1.2 explicitly states that AAT does not constrain which
authorized invocations occur, in what order, or how many times.

This profile preserves that boundary. Mission-scoped lineage budgets are
authorized by the MD, not by native AAT attenuation semantics.

### 6.2. `reserved_budget_share` Claim

Deployments operating at a MIC-State or stronger conformance profile MUST
enforce lineage-wide budget conservation in verifier or application state.
They MAY serialize the reserved child share into a top-level
`reserved_budget_share` claim on a derived AAT for audit, replay, or
interoperability within a deployment profile.

For this profile:

1. `reserved_budget_share`, when present, MUST be a non-negative integer;
2. `reserved_budget_share`, when present, denotes the share reserved for the
   child at derivation time under the verifier ledger;
3. root AATs SHOULD omit `reserved_budget_share`; and
4. derived AATs MUST NOT rely on `reserved_budget_share` to replace AAT
   Section 7 verification.

This document does not register `reserved_budget_share` in the JWT Claims
Registry. In v0.1 it is a profile-private companion claim used for escrow
audits.

### 6.3. Conservation Rule

The MD's `lineage_budgets` claim authorizes the ceiling.
Verifier-side lineage state records per-child reservations and enforces
conservation. `reserved_budget_share`, when carried, is only a signed
serialization of that state for audit or replay.

For a given root mission and budget bucket:

1. the sum of descendant reservations plus consumed budget charged to a root
   authorization MUST NOT exceed the corresponding MD ceiling; and
2. a verifier or auditor claiming MIC-State or stronger conformance MUST
   detect and report a conservation violation from ledger state, even if no
   `reserved_budget_share` claim was serialized.

This conservation check is intentionally outside the AAT chain verifier.
It is a mission-layer audit over otherwise valid AAT chains.

## 7. Optional AAT Extension Constraint Type: `lineage_budget_share`

### 7.1. Status

This section is OPTIONAL and not required for v0.1 DG interoperability.

It exists for deployments that choose to model delegation itself as an
AAT-governed operation with an explicit numeric derivation parameter for the
reserved child budget share.

The default and RECOMMENDED mechanism in this profile remains:

1. MD `lineage_budgets` as the authorization source;
2. verifier/application lineage state as the conservation mechanism; plus
3. optional top-level `reserved_budget_share` as a signed audit carrier.

### 7.2. Applicability Note

AAT Section 3.5 is designed for argument constraints carried in
`authorization_details`.

`lineage_budget_share` therefore fits only when the deployment exposes
delegation as an operation with a numeric argument representing the child's
reserved budget share.

Deployments that do not model delegation that way SHOULD NOT use this
extension type.

### 7.3. Proposed Registration Template

If a stable public specification is later published for this extension, the
following template satisfies the AAT Section 9.3.2 structure.

Type name:
`lineage_budget_share`

Additional members:

1. `bucket` (string, required): identifier of the MD lineage-budget bucket to
   which the reservation applies.
2. `max_share` (integer, required): maximum non-negative share that may be
   reserved into the child grant for the named bucket.
3. `unit` (string, optional, default `"calls"`): accounting unit for the
   bucket. The unit MUST match the governing MD bucket definition.

Check predicate:

Given a candidate reserved-share value `v`:

1. `v` MUST be an integer;
2. `v` MUST be greater than or equal to zero;
3. `v` MUST be less than or equal to `max_share`; and
4. the surrounding delegation context MUST bind the argument position to the
   same MD lineage-budget bucket named by `bucket`.

Subsumes verification procedure:

`subsumes(C_parent, C_child)` is true if and only if:

1. `C_parent.bucket == C_child.bucket`;
2. `C_parent.unit == C_child.unit` after defaulting absent `unit` to
   `"calls"`; and
3. `C_child.max_share <= C_parent.max_share`.

This procedure is decidable, deterministic, and sound because every value
accepted by `C_child` is also accepted by `C_parent`.

Cross-type subsumption rules:

1. `(lineage_budget_share, lineage_budget_share)` is valid under the
   subsumption rule above.
2. `(lineage_budget_share, exact)` is valid if the `exact` value is a
   non-negative integer and `exact <= parent.max_share`.
3. `(exact, lineage_budget_share)` is invalid.
4. All other pairs involving `pattern`, `range`, `one_of`, `not_one_of`,
   `contains`, `subset`, `regex`, `cel`, `wildcard`, `all`, `any`, or `not`
   are invalid.

Security considerations:

1. this constraint limits a requested reservation ceiling; it does not prove
   conservation across sibling branches by itself;
2. deployments using this type MUST still perform lineage-wide conservation
   audit against the governing MD; and
3. enforcement points that do not recognize this type MUST deny authorization,
   per AAT Section 3.5.2.

Reference:
This document, upon stable public publication.

## 8. IANA Considerations

### 8.1. JWT Claims Registry

If published in an appropriate standards-track venue, this document requests
registration of the following claim in the IANA JSON Web Token Claims
Registry, using the same template shape as AAT Section 9.1:

| Claim Name | Claim Description | Change Controller | Reference |
|---|---|---|---|
| `mission_ref` | Reference to the governing Mission Declaration. The claim value is either a URI/JWK Thumbprint URI or an object containing `uri` and optional `mission_digest`. | IETF | This document |

### 8.2. No Required AAT Constraint Registry Action in v0.1

This version does not require IANA registration of `lineage_budget_share`.
Section 7 defines a proposed template only.

## 9. Security Considerations

This profile inherits the security considerations of AAT, especially:

1. threat-model scoping from AAT Section 8.1;
2. replay considerations from AAT Section 8.6;
3. unknown-constraint fail-closed behavior from AAT Section 8.9; and
4. algorithm-confusion defenses from AAT Section 8.14.

The following profile-specific considerations also apply:

1. `mission_ref` is integrity protected only because it is signed as part of
   the AAT JWT. Implementations MUST verify the AAT signature before trusting
   `mission_ref`.
2. `mission_digest` binds the MD payload object, not the JOSE wrapper around
   it. Implementations MUST hash the canonicalized payload object only.
3. A verifier that ignores `mission_ref` is still AAT-conformant but loses the
   ability to bind the chain to a specific mission policy root.
4. `reserved_budget_share` does not by itself stop over-delegation. The
   security property comes from lineage-wide conservation audit against the MD
   ceiling.
5. This profile does not mitigate malicious root issuers, compromised
   enforcement points, or model-layer compromise beyond the protections already
   scoped by AAT Section 8.1.2.

## 10. References

### 10.1. Normative References

1. `draft-niyikiza-oauth-attenuating-agent-tokens-00`
2. RFC 2119
3. RFC 8174
4. RFC 8785
5. RFC 9278

### 10.2. Informative References

1. `docs/spec/mission-declaration-v0.1.md`
2. `docs/spec/execution-receipt-v0.1.md`
3. `docs/session-2026-04-14/05-cpo-call-prep/unified-steps-final.md`
4. `vibap-prototype/vibap/passport.py`
