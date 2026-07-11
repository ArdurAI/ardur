# AAT draft-01 Migration Decision

## Status

Ardur's Delegation Grant profile remains pinned to
`draft-niyikiza-oauth-attenuating-agent-tokens-00` for the v0.2.0 release.
Draft-01 tokens are rejected explicitly. This is a time-bounded compatibility
decision, not a claim that draft-00 is current or standardized.

Review this decision no later than 2026-09-15, and earlier if any of these
events occurs:

1. the v0.2.0 release promotion completes;
2. a newer AAT revision is published; or
3. an independent draft-01 implementation fixture becomes available.

[Issue #246](https://github.com/ArdurAI/ardur/issues/246) owns that review and
the versioned draft-01 implementation path after v0.2.0.

The field-level source record is
[`aat-draft-00-to-01-change-ledger.json`](./aat-draft-00-to-01-change-ledger.json).

## Source Standing

The primary sources are the Datatracker copies of
[draft-00](https://datatracker.ietf.org/doc/html/draft-niyikiza-oauth-attenuating-agent-tokens-00)
and
[draft-01](https://datatracker.ietf.org/doc/html/draft-niyikiza-oauth-attenuating-agent-tokens-01).
Draft-01 was published on 2026-06-15. Datatracker identifies it as an active
individual Internet-Draft that is not endorsed by the IETF and has no formal
standing in the IETF standards process.

## Why Ardur Does Not Migrate In Place

Draft-01 changes security-relevant wire and processing rules:

- `aat_type` is removed; roles are determined by chain position;
- type-transition key separation stops being a base invariant;
- `pattern`, `regex`, `cel`, and `not` leave the core constraint vocabulary;
- PoP gains an optional audience claim with profile-defined enforcement;
- root and child validation is clarified and tightened; and
- JWT/JWS becomes the only fully specified encoding.

An in-place switch would make the same DG profile version mean two different
authorization protocols. It would also let generic draft-01 behavior ignore
the old `aat_type` claim while Ardur still relies on that claim to distinguish
delegation from invocation authority.

## Compatibility Contract

DG v0.1 uses this contract:

1. `aat_type` is required and MUST be `delegation` or `execution`.
2. Its absence is reported as unsupported draft-01 wire semantics, not as a
   parser crash or an implicitly compatible token.
3. Existing draft-00 tokens continue through the draft-00 verifier.
4. Draft-01 tokens are not downgraded, rewritten, or interpreted under
   draft-00 rules.
5. Any future draft-01 support requires a new DG profile version and explicit
   cross-version fixtures.

The Go package is the formal root-to-leaf chain verifier. The Python adapter
is a narrow post-signature mapping shim for the existing runtime and is not a
standards-complete AAT chain verifier. It enforces the same revision boundary
before mapping a grant into Mission Passport material. For delegated input it
also verifies `par_hash` against the exact parent JWS signing input and rejects
argument constraints it cannot enforce instead of widening them during the
mapping.

## Draft-00 Hardening Included With This Decision

The revision audit found implementation gaps that are independent of the
draft-01 migration choice. The v0.1 verifier therefore also:

- signs and verifies direct argument-map `hta` values;
- applies RFC 8785 JCS to the complete PoP payload before JWS signing;
- rejects non-canonical PoP payload bytes and missing PoP identifiers;
- rejects private JWK material in holder confirmation claims;
- treats token `iat` skew as a one-sided future tolerance while retaining a
  bilateral PoP replay window;
- validates root issuer URI shape;
- enforces exact closed-world argument-key preservation;
- rejects duplicate JSON member names, malformed constraint objects, and
  non-integral delegation depths without parsing full claims before signature
  verification;
- applies the draft's inclusive/exclusive range attenuation direction and
  bounded one-to-one matching for `all` constraints;
- permits the empty intermediate capability set while preventing descendants
  from reintroducing authority;
- binds child derivation and PoP construction to the parent or leaf
  confirmation key before minting; and
- returns a typed unsupported-revision denial instead of panicking when
  draft-01's missing `aat_type` is observed.

These changes make existing draft-00 behavior match its claimed profile; they
do not add draft-01 compatibility.

## Migration Exit Criteria

A future DG profile may select draft-01 only after it provides:

1. a versioned wire identifier and deterministic draft-00/draft-01 dispatch;
2. role and key-separation rules that replace the removed `aat_type` invariant;
3. handling for every removed draft-00 core constraint;
4. an audience-binding policy for PoP;
5. organic root, child, and grandchild fixtures from at least one independent
   implementation; and
6. explicit proof that AAT holder keys are not confused with DRP receipt
   signer keys.

## Claim Boundary

This decision is an Ardur compatibility profile. It is not IETF conformance,
IETF endorsement, or demonstrated independent interoperability.
