# Execution Receipt EAT/CWT Profile v0.1

> **Public-import note.** This document was authored against the private research repo's `docs/spec/` layout. In the public ardur tree, migrated specs live under `docs/specs/`. Any `docs/spec/...` path reference in the body refers to the original private layout; the public-tree mapping is in [`docs/specs/README.md`](./README.md).

## 1. Profile Identifier

This document profiles RFC 9711 EAT for Ardur Execution Receipts carried as
CBOR Web Tokens.

- `eat_profile`: `https://ardur.dev/eat/execution-receipt/v1`
- top-level container: CWT carried in `COSE_Sign1`
- signature algorithm: COSE `ES256` (`alg = -7`)

This profile is secondary to the primary JWT profile defined in
`execution-receipt-v0.1.md`.

## 2. RFC 9711 Claims Used

This profile uses the following RFC 9711 claims directly:

| RFC 9711 claim | Section | CBOR label | Use in this profile |
|---|---|---:|---|
| `eat_nonce` | §4.1 | 10 | Freshness binding; populated from ER `receipt_id`. |
| `eat_profile` | §4.3.2 | 265 | Profile discriminator; fixed to the URI above. |
| `submods` | §4.2.18 | 266 | Container for ER `measurements`. |
| `measurements` | §4.2.16 | 273 | Optional, inside a submodule when raw measurement evidence is available. |
| `measres` | §4.2.17 | 274 | Optional, inside a submodule to report comparison results. |
| `iat` | §4.3.1 | inherited from CWT/JWT | Timestamp of token creation. RFC 9711 forbids floating-point `iat` in EAT. |

This profile also uses standard CWT claims from RFC 8392:

- `iss` -> label `1`
- `exp` -> label `4`
- `iat` -> label `6`
- `cti` -> label `7`

`cti` is the CWT analogue of JWT `jti`.

## 3. Mapping Rules

### 3.1 Top-Level Mapping

| ER claim | EAT/CWT representation |
|---|---|
| `receipt_id` | preserved as profile-private text claim `receipt_id`; duplicated into `eat_nonce` |
| `grant_id` | profile-private text claim `grant_id` |
| `parent_receipt_id` | profile-private text claim `parent_receipt_id` (`null` permitted in JSON projection) |
| `parent_receipt_hash` | profile-private text claim `parent_receipt_hash` (`null` permitted in JSON projection) |
| `actor` | profile-private text claim `actor` |
| `verifier_id` | profile-private text claim `verifier_id` |
| `trace_id` | profile-private text claim `trace_id` |
| `run_nonce` | profile-private text claim `run_nonce` |
| `step_id` | profile-private text claim `step_id` |
| `invocation_digest` | profile-private map claim `invocation_digest`, same structure as the base ER schema |
| `tool` | profile-private text claim `tool` |
| `action_class` | profile-private text claim `action_class` |
| `target` | profile-private text claim `target` |
| `resource_family` | profile-private text claim `resource_family` |
| `side_effect_class` | profile-private text claim `side_effect_class` |
| `verdict` | profile-private EAT claim `verdict` |
| `evidence_level` | profile-private text claim `evidence_level` |
| `reason`, `policy_decisions`, `arguments_hash`, `budget_remaining` | profile-private claims with identical names |
| `timestamp` | profile-private text claim `timestamp` |
| `iss` | standard CWT `iss` |
| `iat` | standard CWT `iat` |
| `exp` | standard CWT `exp` |
| `jti` | standard CWT `cti`, encoded as UTF-8 bytes of the JSON `jti` value |
| `content_class`, `content_provenance`, `sensitivity`, `instruction_bearing`, `budget_delta`, `result_hash`, `public_denial_reason`, `internal_denial_code`, `evidence_proof_ref` | profile-private claims with identical names |

### 3.1.1 Claim Key Strategy

RFC-defined EAT and CWT claims use their registered integer labels. ER-specific
claims in v0.1 remain profile-private and are carried with the same **text
claim names** used by the JWT profile. Integer registration for ER-specific
claims is intentionally deferred until the claim set is stable.

Nested ER objects (`invocation_digest`, `result_hash`, `budget_delta`,
`budget_remaining`, `policy_decisions`, `content_provenance`,
`evidence_proof_ref`, and `measurements`) MUST be encoded as deterministic
CBOR maps or arrays with the same member names as the JSON schema. Producers
MUST sort map keys according to deterministic CBOR rules and MUST NOT re-label
nested ER members with local integer keys in v0.1; otherwise independent CWT
implementations will compute different evidence digests for the same receipt.

### 3.2 `eat_nonce` Binding

`eat_nonce` MUST be populated from ER `receipt_id`.

- In JSON EAT form, `eat_nonce` is the same text string as `receipt_id`.
- In CWT form, `eat_nonce` is the UTF-8 byte sequence of `receipt_id`.

Because RFC 9711 constrains CBOR `eat_nonce` to 8..64 bytes, ER producers using
this profile MUST keep `receipt_id` within that bound when encoded as UTF-8.

### 3.3 `eat_profile` Binding

The EAT `eat_profile` claim MUST equal:

`https://ardur.dev/eat/execution-receipt/v1`

Receivers MUST reject an ER EAT whose `eat_profile` differs.

### 3.4 Verdict as a Profile-Specific EAT Claim

RFC 9711 does not define an attestation verdict claim suitable for MIC's
verdict semantics. This profile therefore defines `verdict` as a
profile-specific EAT claim with the same string values as the base ER schema:

- `compliant`
- `violation`
- `insufficient_evidence`
- `unknown` (v0.2 extension: structural observation gap, distinct from
  `insufficient_evidence`)

Receivers MUST preserve the verdict semantics and MUST NOT collapse
`insufficient_evidence` or `unknown` into `compliant`.

## 4. Mapping `measurements` into `submods`

ER `measurements` is projected into RFC 9711 `submods` rather than into the
top-level RFC 9711 `measurements` claim.

Rationale:

- RFC 9711 `submods` (§4.2.18, label 266) is the standards-defined mechanism for
  grouping claims by subsystem or measured component.
- ER measurements are verifier-local integrity observations about individual
  subsystems of the hop context: manifest binding, envelope binding, memory
  integrity, telemetry completeness, or transparency anchoring.

For each ER entry:

`measurements["name"] = measurement_entry`

the EAT producer MUST create:

`submods["name"] = <Claims-Set | Detached-Submodule-Digest>`

### 4.1 In-Place Claims-Set Form

If the measurement is carried inline, `submods["name"]` SHOULD be a Claims-Set.

That Claims-Set MAY contain:

- RFC 9711 `measurements` (label 273) when raw measurement evidence exists in an
  interoperable content format;
- RFC 9711 `measres` (label 274) when only appraisal results are available; and
- profile-private descriptive claims such as `kind`, `description`, or `digest`.

When populating `measres`, producers SHOULD emit one measurement-results group
named `ardur.er`, with the ER measurement entry name used as the result
identifier.

Status mapping:

| ER measurement `status` | RFC 9711 `measres` result |
|---|---:|
| `success` | `1` (`success`) |
| `fail` | `2` (`fail`) |
| `not-run` | `3` (`not-run`) |
| `absent` | `4` (`absent`) |

### 4.2 Detached Digest Form

If the measurement details are too large or too sensitive for the user-facing
payload, `submods["name"]` MAY be a Detached-Submodule-Digest as defined in RFC
9711 §4.2.18.2.

When this form is used:

- the digest input MUST be the JSON or CBOR claims set for that submodule;
- JSON inputs MUST be RFC 8785 JCS canonicalized before hashing; and
- the separately conveyed detailed submodule claims set MUST remain available in
  an audit channel.

## 5. CBOR / COSE Profile Constraints

This section fills in the RFC 9711 profile choices from §6.3.

### 5.1 Encoding

- Senders MUST emit CBOR for the secondary ER profile.
- Receivers MUST accept CBOR.
- Nested submodules expressed as Claims-Sets MUST use the same encoding as the
  enclosing EAT, per RFC 9711 §4.2.18.1.

### 5.2 CBOR Length Encoding

- Senders MUST use definite-length maps, arrays, and strings.
- Receivers MUST accept definite-length encodings.

### 5.3 Preferred Serialization

- Senders MUST use CBOR preferred serialization.
- Receivers SHOULD reject non-preferred serialization in security-sensitive
  deployments.

### 5.4 Tagging

- When serialized as a standalone artifact, senders SHOULD emit a tagged CWT.
- When the carrying protocol already identifies the object as this profile's
  EAT/CWT, senders MAY omit the outer CWT tag.
- Receivers MUST accept both tagged and untagged forms.

### 5.5 Protection Format

- Senders MUST use `COSE_Sign1`.
- Receivers MUST implement and accept `COSE_Sign1`.
- Nested signed EATs MAY be used inside `submods` when a submodule has its own
  attesting environment, per RFC 9711 §4.2.18.3.

### 5.6 Algorithm Set

- The only signing algorithm allowed in v0.1 is COSE `ES256` (`alg = -7`).
- The signing key MUST use curve P-256.

## 6. Freshness and Replay

- Exactly one `eat_nonce` value MUST be present.
- `cti` MUST be present and MUST encode the ER `jti` value as UTF-8 bytes.
- `trace_id`, `run_nonce`, and `invocation_digest` MUST be present after JSON
  projection and MUST be verified exactly as in the base ER JWT profile.
- `iat` MUST be an integer NumericDate. Floating-point `iat` is invalid in EAT
  (RFC 9711 §4.3.1).
- `exp` MUST be present.

## 7. Claim Processing Rules

- Receivers MUST verify the COSE signature before processing private ER claims.
- Receivers MUST reject tokens with a missing or mismatched `eat_profile`.
- Receivers MUST reject tokens that do not carry the required ER claims after
  JSON projection.
- Receivers SHOULD ignore unknown private claims unless local policy requires a
  fail-closed stance.

## 8. Denial Leakage Requirements

If `verdict` is `violation` or `insufficient_evidence`, the only user-facing
reason string permitted in the EAT payload is the ER
`public_denial_reason` vocabulary from the base spec. Detailed audit material,
including `internal_denial_code`, MUST remain out of band unless the receiver
is explicitly authorized for the audit projection.