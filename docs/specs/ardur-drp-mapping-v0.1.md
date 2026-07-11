# Ardur DRP Mapping Profile v0.1

## 1. Status and Proof Boundary

This document maps the current Ardur delegation and action-receipt surfaces to
`draft-nelson-agent-delegation-receipts-10`. The complete field ledger is
[ardur-drp-mapping-v0.1.json](./ardur-drp-mapping-v0.1.json).

The referenced DRP document is an **individual Internet-Draft**. It is not
endorsed by the IETF, has no formal standing in the IETF standards process,
and is not a standard. This document is therefore a draft-pinned mapping
profile. It is not an IETF conformance statement and does not demonstrate
third-party interoperability.

Issue #178 owns this mapping and the target JSON shape. Emit/verify belongs to
issue #179. Interoperability fixtures and any public conformance statement
belong to issue #180.

This document uses **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and
**MAY** as described in BCP 14 (RFC 2119 / RFC 8174).

## 2. Covered Ardur Surfaces

The word "field" in the issue acceptance criteria means every top-level wire
property in these live contracts plus their enumerated nested delegation
members:

1. the formal Go AAT Delegation Grant in `go/pkg/aat/types.go`, including
   `authorization_details`, argument-constraint members, `mission_ref`,
   `reserved_budget_share`, and `lineage_budget_share`;
2. the JWT mission passport emitted by `python/vibap/passport.py`, including
   child-lineage claims added by `derive_child_passport`; and
3. every top-level property in
   `docs/specs/execution-receipt-v0.2.schema.json`.

The formal DG and Go AAT implementation preserve the AAT draft-00 DG v0.1
contract and separately dispatch the explicit `ardur.dg.aat-draft-01.v0.2`
profile. Draft-01 is an individual Internet-Draft with no formal IETF standing
and removes the draft-00 `aat_type` token-role field in favor of chain-position
semantics. The two wire contracts are never inferred from claim absence or
mixed in one chain. The compatibility contract and completed review are
recorded in
[`aat-draft-01-migration-decision.md`](./aat-draft-01-migration-decision.md).

Arbitrary caller-supplied `extra_claims` are not a versioned schema. An
emitter MUST reject an unregistered extra claim instead of silently placing it
in a DRP object.

Each ledger entry has one classification:

| Classification | Meaning |
|---|---|
| `mapped` | DRP draft-10 defines a corresponding Authorization Object or action-log concept. A documented conversion may still be required. |
| `extension` | Ardur must retain the value under `metadata.x-ardur` or action-log metadata because DRP has no equivalent wire field. |
| `out_of_scope` | The value has no safe role in this profile and is not exported. |

A `mapped` action-log path is conceptual. Draft-10 requires action type,
payload hash, destination, previous-entry hash, timestamp, and agent signature,
but does not define a complete action-log JSON Schema.

## 3. Delegation Mapping Summary

The JSON ledger is normative for individual field coverage. The principal
transformations are:

| Ardur source | DRP target | Rule |
|---|---|---|
| AAT/Python `iat`, `nbf`, `exp` | `timeWindow.notBefore`, `timeWindow.notAfter` | Convert NumericDate to RFC 3339 UTC. Use the later of `iat` and `nbf`. |
| `mission` | `operatorInstructions`, `operatorInstructionsHash` | Normalize the instruction to NFC, hash those exact UTF-8 bytes as `sha256:<lowercase-hex>`, and sign the same normalized value. A Mission Declaration reference alone is not plaintext instruction evidence. |
| allowed tools, action classes, resource scope | `scope.allowedActions` | Produce explicit operation/resource descriptors. Wildcards use DRP semantics. |
| forbidden tools and prohibitions | `scope.deniedActions`, `boundaries` | Preserve every inherited denial and add a stable human-auditable boundary string. |
| AAT `authorization_details[].tools` | `scope.allowedActions` | Project only the tool/resource portion that base DRP can enforce. |
| argument constraints | `metadata.x-ardur.argumentConstraints` | Security-critical extension. A verifier without the full constraint algebra must deny. |
| `jti` | `metadata.x-ardur.delegationGrantId` | DRP `receiptId` is content-derived and MUST NOT be copied from the token ID. |
| `par_hash`, `parent_token_hash`, `parent_jti` | `parentReceiptId` plus Ardur audit fields | Resolve the actual profiled parent receipt. Token hashes and token IDs are retained but are not DRP receipt IDs. |
| `cnf.jwk` | `metadata.x-ardur.capabilityTokenRef.holderConfirmation.jwk` | The holder key is not the DRP receipt-signing key. |
| depth and delegation policy | `metadata.x-ardur.redelegation` | DRP describes depth behavior but has no Authorization Object fields for mode, depth, or maximum depth. |
| budgets and policy references | `metadata.x-ardur.budget`, `metadata.x-ardur.policy` | Security-critical extensions that participate in attenuation checks. |
| `mission_ref` | `metadata.x-ardur.missionRef` | DRP instruction commitment does not replace the governing Mission Declaration reference. |

### 3.1. Critical Extension Rule

The extension MUST contain a `critical` array of JSON Pointer-like paths. An
Ardur-profile verifier MUST understand and enforce every listed path. If any
path is unknown, malformed, unsupported, or omitted from verification, the
verifier MUST return DENY and MUST NOT fall back to base DRP authorization.

A generic DRP verifier may ignore private metadata under draft-10. It may
authenticate the base receipt, but it is not authorized to return PERMIT under
the Ardur profile when `metadata.x-ardur.critical` is non-empty.

This rule is necessary because resource containment, argument constraints,
budget conservation, mission binding, policy version, and re-delegation mode
can narrow authority beyond what `scope.allowedActions` expresses.

### 3.2. Closed Scope Universe and Boundaries

Tool identifiers map to `operation = "invoke"` and a normalized
`resource = "tool://<tool-identifier>"`. A deployment MAY use a more specific
registered operation, but parent and child must use the same operation
vocabulary.

Wildcard expansion and strict-subset comparison require a finite,
authenticated tool/resource universe. The emitter MUST include
`toolSchemaHash`, and the verifier MUST resolve it to the exact trusted tool
manifest used for expansion. If the manifest is missing, mismatched,
unbounded, or untrusted, the verifier MUST return DENY with insufficient
evidence. It MUST NOT infer a universe from only the child receipt.

`boundaries` is non-empty in draft-10. The emitter projects explicit
prohibitions into stable `deny:<operation>:<resource>` strings. When the source
has no explicit prohibition, it MUST include
`x-ardur:deny-unlisted-actions`, which records the profile's closed-world
default without inventing a permission.

## 4. Target Authorization Object

Issue #179 MUST target this shape. Placeholder values show types and bindings,
not a golden fixture:

```json
{
  "receiptId": "rec_<64-lowercase-hex>",
  "schemaVersion": "1.0",
  "scope": {
    "allowedActions": [
      {
        "operation": "invoke",
        "resource": "tool://calendar/create"
      }
    ],
    "deniedActions": [
      {
        "operation": "delete",
        "resource": "*"
      }
    ]
  },
  "boundaries": [
    "deny:delete:*",
    "x-ardur:cwd:/workspace/project"
  ],
  "timeWindow": {
    "notBefore": "2026-07-10T12:00:00Z",
    "notAfter": "2026-07-10T12:10:00Z"
  },
  "operatorInstructionsHash": "sha256:<64-lowercase-hex>",
  "operatorInstructions": "Create the approved calendar event.",
  "toolSchemaHash": "sha256:<64-lowercase-hex>",
  "canonicalPayload": "<base64url-no-padding>",
  "publicKey": {
    "kty": "EC",
    "crv": "P-256",
    "x": "<base64url>",
    "y": "<base64url>"
  },
  "signature": "<base64url-raw-rfc7515-es256-signature>",
  "parentReceiptId": "rec_<64-lowercase-hex>",
  "orchestratorSignature": "<base64url-raw-rfc7515-es256-signature>",
  "revocationRequired": true,
  "metadata": {
    "x-ardur": {
      "profile": "ardur.drp.v0.1",
      "critical": [
        "/metadata/x-ardur/missionRef",
        "/metadata/x-ardur/policy",
        "/metadata/x-ardur/capabilityTokenRef",
        "/metadata/x-ardur/resourceBounds",
        "/metadata/x-ardur/argumentConstraints",
        "/metadata/x-ardur/budget",
        "/metadata/x-ardur/redelegation",
        "/metadata/x-ardur/revocation",
        "/metadata/x-ardur/delegationLogAnchor",
        "/metadata/x-ardur/receiptChainAnchor"
      ],
      "issuer": "https://issuer.example",
      "subject": "spiffe://example.test/ns/agents/sa/calendar",
      "audience": "ardur-verifier",
      "delegationGrantId": "urn:uuid:<grant-id>",
      "missionRef": {
        "uri": "https://example.test/missions/123",
        "missionDigest": "sha-256:<64-lowercase-hex>"
      },
      "policy": {
        "version": "policy-2026-07-10",
        "digest": "sha-256:<64-lowercase-hex>"
      },
      "capabilityTokenRef": {
        "mediaType": "application/aat+jwt",
        "sha256": "<64-lowercase-hex>",
        "toolManifestDigest": "sha256:<64-lowercase-hex>",
        "tokenType": "delegation",
        "holderConfirmation": {
          "jwkThumbprint": "<base64url>"
        }
      },
      "resourceBounds": {
        "resources": [
          "tool://calendar/*"
        ],
        "sideEffectClasses": [
          "external_send"
        ],
        "cwd": "/workspace/project"
      },
      "argumentConstraints": {
        "tool://calendar/create": {
          "calendar_id": {
            "constraintType": "exact",
            "value": "team"
          }
        }
      },
      "budget": {
        "maxToolCalls": 4,
        "maxToolCallsPerClass": {
          "external_send": 1
        },
        "reservedShare": 1
      },
      "redelegation": {
        "mode": "bounded",
        "depth": 1,
        "maxDepth": 3,
        "parentTokenHash": "sha-256:<64-lowercase-hex>"
      },
      "revocation": {
        "ref": "https://example.test/revocations/status#idx=17",
        "required": true,
        "cascade": "issuer-policy"
      },
      "delegationLogAnchor": {
        "backend": "rfc3161-log",
        "required": true,
        "subject": "receipt-id"
      },
      "receiptChainAnchor": {
        "state": "present",
        "traceId": "trace-123",
        "headReceiptId": "receipt-456",
        "headReceiptJwtSha256": "<64-lowercase-hex>"
      }
    }
  }
}
```

Root receipts omit `parentReceiptId` and `orchestratorSignature`.
Sub-receipts require both.

`delegationLogAnchor` is a signed evidence policy, not the proof output. The
receipt must be identified and signed before log submission, so actual
inclusion/TSA evidence is necessarily external and binds the final
`receiptId`. Embedding that final ID or proof output in `pre_id_body` would
create a circular hash requirement. Issue #179's verifier requires
independently verified external evidence matching the signed backend and
`receipt-id` subject.

The profile requires all fields listed in
`profile_shape.ardur_required_fields` in the ledger. If the source token does
not carry policy version, capability reference, revocation reference, or
delegation-log/receipt-chain anchor context, the emitter must receive it from
authenticated issuer configuration. A run that has not produced an action
receipt uses `receiptChainAnchor.state = "unstarted"` and null head values; it
MUST NOT fabricate a chain head. The emitter MUST fail closed if any other
required value is unavailable.

When `receiptChainAnchor.state = "present"`, a verifier returning PERMIT MUST
receive independently verified action-chain facts from outside the
Authorization Object and match the signed trace ID, head receipt ID, and head
receipt-JWT digest. The signed anchor is a commitment, not proof of its own
existence. Missing or mismatched facts are insufficient evidence.

## 5. Deterministic ID and Signing Procedure

Draft-10 contains circular or conflicting prose about whether `receiptId` is
inside its own hash input and whether a sub-receipt ID includes the main
signature. This profile removes that ambiguity:

1. Normalize every string to Unicode NFC.
2. Build `pre_id_body` from every present Authorization Object field except
   `receiptId`, `canonicalPayload`, `signature`, and
   `orchestratorSignature`.
3. Serialize `pre_id_body` with RFC 8785 JCS.
4. Set `receiptId = "rec_" + lowercase_hex(SHA-256(pre_id_bytes))`.
5. Build `signed_body` by adding `receiptId` to `pre_id_body`.
6. Serialize `signed_body` with RFC 8785 JCS.
7. Set `canonicalPayload` to unpadded base64url of those exact
   `signed_body` bytes.
8. Sign those exact decoded canonical bytes with ES256. Encode the 64-byte
   `R || S` signature using unpadded base64url.
9. For a sub-receipt, sign the ASCII binding
   `orchestrator-delegation:<parentReceiptId>:<receiptId>` with the
   externally trusted parent orchestrator P-256 key. This signature remains
   outside `signed_body`.

A verifier MUST decode `canonicalPayload`, require byte-for-byte equality with
its own recomputed `signed_body`, recompute `receiptId`, and then verify the
signature. It MUST reject duplicate JSON names, non-NFC strings, non-JCS bytes,
unknown fields outside the permitted extension point, padded base64url, and
non-canonical ES256 signature length.

## 6. Signer Trust and Algorithm Profile

Draft-10 recommends Ed25519 generally, supports P-256, requires a P-256 root in
its multi-agent section, and defines `orchestratorSignature` only for P-256.
For deterministic draft-10 interoperability, Ardur DRP Profile v0.1 selects
P-256/ES256 for both receipt signatures.

The AAT `cnf.jwk` is a holder key. It MUST NOT be copied into DRP
`publicKey` unless external trust configuration independently identifies that
same key as the receipt signer. Possession of an embedded public key does not
establish issuer identity.

A verifier MUST receive a trust-anchor inventory or authenticated key binding
from outside the receipt. It MUST verify that `publicKey` matches the expected
signer before accepting either signature. Key identifiers, certificate chains,
or workload identities may locate that binding but do not replace the
cryptographic comparison.

### 6.1. Delegation Log Evidence

Draft-10 requires the Delegation Receipt to be anchored before agent action and
uses an RFC 3161-backed log timestamp as authoritative time. The Authorization
Object cannot carry proof output that is created only after signing and log
submission. The Ardur profile therefore signs the required backend and
`receipt-id` proof subject in
`metadata.x-ardur.delegationLogAnchor`. The verifier receives the actual
inclusion/TSA evidence alongside the receipt, validates it against external
log/TSA trust, and requires it to bind the final `receiptId`.

Ardur Transparency Anchor v0.1 currently anchors action receipts and supports
multiple backends. It satisfies this delegation-log requirement only when the
selected backend independently proves pre-action inclusion and the required
authoritative RFC 3161 timestamp. A Rekor timestamp, local checkpoint, or
asynchronous post-action inclusion MUST NOT be relabeled as that evidence.

## 7. Re-Delegation Semantics

### 7.1. No Re-Delegation

`metadata.x-ardur.redelegation.mode = "none"` is an explicit terminal policy.
The emitter MUST NOT create a sub-receipt. A verifier presented with a child
under such a parent returns DRP DENY and Ardur reason
`REDELEGATION_DENIED`.

### 7.2. Bounded Re-Delegation

`mode = "bounded"` permits a child only when all of these hold:

1. the parent and child are fully verified against external trust;
2. `child.depth = parent.depth + 1`;
3. `child.depth < parent.maxDepth`;
4. `child.maxDepth <= parent.maxDepth`;
5. the child time window is contained by the parent;
6. every child allowed action is covered by the parent;
7. the child allowed-action set is a strict proper subset under DRP wildcard
   semantics;
8. every parent denial is preserved;
9. every Ardur resource and argument constraint is equal or narrower;
10. every budget ceiling and remaining/reserved budget is conserved and equal
    or lower; and
11. the parent-child signatures and token/receipt bindings are valid.

Draft-10 rejects a child with the same concrete allowed-action set even if its
arguments, budget, or time are narrower. Such an AAT chain is valid under some
AAT attenuation rules but is **not exportable** as a draft-10 sub-receipt.
Issue #179 MUST return an explicit unmappable/deny result instead of weakening
or fabricating an action restriction.

### 7.3. Denied Re-Delegation

Denied re-delegation is the verifier outcome, not a third grant mode. The
verifier returns DENY with `REDELEGATION_DENIED`,
`SCOPE_NOT_STRICT_SUBSET`, or `PARENT_SCOPE_VIOLATION` when a child is
forbidden, depth-exhausted, untrusted, missing an ancestor, or wider on any
dimension.

### 7.4. Full Transitive Verification

Draft-10 Check 14 explicitly re-verifies only the immediate parent while
traversing older ancestors for IDs/depth. That is insufficient for Ardur's
no-silent-widening invariant.

An Ardur-profile verifier MUST retrieve and fully verify every receipt from the
leaf to the externally trusted root. It MUST verify every signature,
revocation/time state, critical extension, parent binding, and adjacent
attenuation edge. A valid immediate parent does not rehabilitate an invalid or
widened ancestor.

## 8. Revocation and Offline Evidence

`revocationRequired=true` maps directly to draft-10. Offline verification MUST
return DENY when it is true.

The Ardur extension also carries the revocation status reference and cascade
policy. When offline verification is permitted, the result MUST report whether
revocation was checked, the observation time, the data source, and its freshness
boundary. It MUST NOT claim current non-revocation from a stale bundle.

Revocation of a parent invalidates a child when the signed Ardur cascade policy
requires it. If the policy is absent, ambiguous, unavailable, or unsupported,
the verifier MUST deny rather than assume a non-cascading interpretation.

## 9. Insufficiency and Decision Projection

DRP returns PERMIT or DENY. Ardur action receipts use
`compliant`, `violation`, and `insufficient_evidence`.

| Ardur verdict | DRP projection | Signed Ardur detail |
|---|---|---|
| `compliant` | PERMIT | `metadata.x-ardur.verdict = "compliant"` |
| `violation` | DENY | Preserve the public denial category and bounded internal code. |
| `insufficient_evidence` | DENY | `metadata.x-ardur.verdict = "insufficient_evidence"`; never treat uncertainty as permission. |

Authority that is too narrow is not missing evidence. It is a scope denial.
Missing ancestor receipts, unverified timestamps, unsupported critical
constraints, unavailable required revocation state, or incomplete trust
bindings are insufficient evidence and still project to DENY.

`INSUFFICIENT_EVIDENCE` and `REDELEGATION_DENIED` are Ardur private-use
reason values in this profile. This document does not claim they are registered
DRP denial codes.

## 10. Execution Receipt to Action Log

The full field mapping is in the ledger. The core relationship is:

| Execution Receipt v0.2 | DRP action-log concept |
|---|---|
| `grant_id` | authorizing delegation receipt hash/ID after profile resolution |
| `action_class`, `tool` | action type |
| `target` | destination |
| `invocation_digest` | primary payload hash |
| `arguments_hash`, `result_hash` | typed additional payload hashes |
| `parent_receipt_hash` | previous action-log entry hash |
| `timestamp` | authoritative log/TSA timestamp only when matching evidence exists |
| `verdict`, `reason`, `public_denial_reason` | decision and denial reason |
| signed receipt JWS | agent/verifier signature over the action entry |

An ordinary Ardur receipt timestamp is not automatically an RFC 3161 timestamp.
A projection that lacks the draft-required log/TSA evidence MUST report
insufficient evidence rather than claiming a complete DRP action-log entry.

Ardur transparency anchors map to the append-only-log evidence relationship
only at an architectural level unless they meet Section 6.1's stricter proof.
Receiver attestations remain separate receiver-side evidence. Offline
verification bundles remain packaging. None is copied into the Authorization
Object or silently represented as a DRP field.

A signed `receiptChainAnchor.state = "present"` similarly requires external
verification of the referenced action-chain head. The Authorization Object
cannot self-authenticate that referenced chain.

## 11. Known Draft-10 Gaps Fixed or Exposed by This Profile

1. The Datatracker status is individual draft with no formal IETF standing.
2. Receipt-ID prose is circular/inconsistent; Section 10 also describes a
   different sub-receipt ID input. Section 5 above defines one deterministic
   profile.
3. Ed25519/P-256 guidance conflicts across general and multi-agent sections.
   This profile selects P-256 for its draft-10 interoperability mode.
4. `timeWindow` is defined as `notBefore`/`notAfter`, while verification
   pseudocode also uses `start`/`end`. This profile accepts only
   `notBefore`/`notAfter`.
5. Embedded `publicKey` does not establish signer identity. External trust
   binding is mandatory.
6. DRP has no no-redelegation field and no serialized depth/max-depth field.
   The signed Ardur critical extension supplies them.
7. Base DRP cannot express AAT argument constraints, budgets, mission binding,
   policy version, resource containment such as `cwd`, or Ardur proof tiers.
8. Generic metadata-ignore behavior is unsafe for critical authorization
   semantics. The critical-extension rule fails closed.
9. Immediate-parent-only Check 14 verification is weaker than full transitive
   no-widening verification. Ardur requires the full chain.
10. DRP's strict allowed-action subset cannot represent AAT attenuation that
    narrows only another dimension. The exporter must identify that gap.
11. Wildcard strict-subset claims are not decidable against an unknown or
    open-ended tool universe. This profile requires a trusted finite manifest.
12. Existing action-receipt transparency evidence is not automatically the
    pre-action Delegation Receipt log/TSA evidence required by draft-10.
13. Embedding the final receipt ID or post-signing log proof in the pre-ID body
    creates a circular construction. The signed body carries the evidence
    policy; external evidence binds the resulting ID.

## 12. B2 Implementation Contract

Issue #179 is complete only when it:

1. emits the exact shape and deterministic signing procedure in this document;
2. verifies external objects without trusting embedded keys;
3. implements every critical extension or denies;
4. verifies every ancestor and attenuation dimension;
5. rejects unexportable equal-action AAT children explicitly;
6. distinguishes scope denial from insufficient evidence;
7. verifies the finite tool universe plus pre-action delegation-log/TSA proof
   through an explicitly trusted evidence-verification boundary;
8. enforces revocation/offline policy;
9. exposes no claim of interoperability until independent fixtures pass; and
10. keeps the existing AAT token and Execution Receipt signatures intact rather
   than rewriting source evidence.

## 13. References

- [Delegation Receipt Protocol draft-10](https://datatracker.ietf.org/doc/draft-nelson-agent-delegation-receipts/10/)
- [Attenuating Authorization Tokens draft-00 implementation baseline](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/00/)
- [Attenuating Authorization Tokens live Datatracker document](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/)
- [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)
- [RFC 7515: JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515.html)
- [RFC 7638: JSON Web Key Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html)
- [Ardur Delegation Grant Profile v0.1](./delegation-grant-profile-v0.1.md)
- [Ardur Execution Receipt v0.2](./execution-receipt-v0.2.md)
- [Ardur Revocation Model v0.1](./revocation-v0.1.md)
