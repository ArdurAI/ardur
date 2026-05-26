# MCEP Specifications (v0.1)

This directory carries the v0.1 specification documents for Ardur's protocol layer, MCEP (Mission-Controlled Execution Protocol). v0.1 is a pre-release series — the specs describe the intended protocol shape; the public code that implements them is being curated in phases per [docs/public-import-plan.md](../public-import-plan.md).

The MCEP acronym was expanded as "Mission-bound Cryptographic Evidence Protocol" in earlier learn-MCEP teaching material; the formal v0.1 specs use "Mission-Controlled Execution Protocol" and that is the canonical expansion going forward. Articles and other public prose follow the spec form.

**Public-surface import caveat.** The migrated specs were authored in a private context and may reference implementation source paths (e.g. `vibap-prototype/vibap/passport.py`), private session artifacts (e.g. `docs/session-2026-04-XX/...`), or internal review trails that have not yet landed in this public repo. Treat such references as pointers to future work — the underlying code lands alongside the Phase 1 import per the [public import plan](../public-import-plan.md). Contributors cannot verify those referenced artifacts from the public tree today. Same caveat as the [decisions index](../decisions/README.md).

**Runtime implementation caveat.** The v0.1 specs define intended protocol semantics for mission-declared `lineage_budgets`, but the current public runtime does not yet compile or verify those mission-level declarations. Today, delegation budget reservations use the file-backed `FileLineageBudgetLedger`, while non-empty mission-level `lineage_budgets` fail closed at compile/issue time instead of being silently accepted.

## Migration status

| Spec | Status | Notes |
|------|--------|-------|
| [Conformance Profiles](./conformance-profiles-v0.1.md) | **migrated** | Public-import annotated |
| [Delegation Grant (DG) Profile of AAT](./delegation-grant-profile-v0.1.md) | **migrated** | Public-import annotated |
| [Verifier Contract](./verifier-contract-v0.1.md) | **migrated** | Public-import annotated |
| [Mission Declaration (MD)](./mission-declaration-v0.1.md) | **migrated** | Public-import annotated; clean-break protocol rename applied (`application/ardur.md+jwt`, `https://ardur.dev/...`) |
| [Execution Receipt (ER)](./execution-receipt-v0.1.md) | **migrated** | Public-import annotated; clean-break rename applied (`application/ardur.er+jwt`) |
| [Execution Receipt EAT/CWT Profile](./execution-receipt-eat-profile-v0.1.md) | **migrated** | Public-import annotated; clean-break rename applied |
| [IDM Extension Profile](./idm-extension-v0.1.md) | **migrated** | Public-import annotated; clean-break rename applied (`application/ardur.idm+jwt`) |
| [Revocation Model](./revocation-v0.1.md) | **migrated** | Public-import annotated; clean-break rename applied |
| [Mission Declaration schema](./mission-declaration-v0.1.schema.json) | **migrated** | JSON Schema; `$id` rebased to ardur.dev |
| [Execution Receipt schema](./execution-receipt-v0.1.schema.json) | **migrated** | JSON Schema; `$id` rebased to ardur.dev |

## Protocol identifier rename (clean break, applied 2026-04-27)

The v0.1 specs originally embedded a legacy product/project name in their JWT media types (`application/<legacy>.er+jwt`) and `$id` URIs (`https://<legacy>.io/...`). The rename decision: **clean break**, no dual-type support. New canonical identifiers in this public series:

| Identifier kind | Old | New |
|---|---|---|
| Mission Declaration JWT type | `application/<legacy>.md+jwt` | `application/ardur.md+jwt` |
| Execution Receipt JWT type | `application/<legacy>.er+jwt` | `application/ardur.er+jwt` |
| IDM Extension JWT type | `application/<legacy>.idm+jwt` | `application/ardur.idm+jwt` |
| Schema `$id` URI base | `https://<legacy>.io/spec/...` | `https://ardur.dev/spec/...` |

The clean-break rationale: there are no v0.1 receipts, passports, or attestations in third-party hands — all empirical artifacts under this series stay private (the paper, internal benchmarks). Backward-compat dual-type would have added implementation complexity for zero observed callers. If receipts in the wild appear later, a v0.2 with dual-type support is the right answer at that point.

## Reading order for first-timers

1. [Mission Declaration (MD)](./mission-declaration-v0.1.md) — the signed scope envelope the agent starts with
2. [Delegation Grant (DG) Profile](./delegation-grant-profile-v0.1.md) — how child agents get strictly narrower authority
3. [Execution Receipt (ER)](./execution-receipt-v0.1.md) — the signed per-tool-call decision record
4. [Execution Receipt EAT/CWT Profile](./execution-receipt-eat-profile-v0.1.md) — RFC 9711 binding for ER carriage
5. [Verifier Contract](./verifier-contract-v0.1.md) — what a conforming verifier must do
6. [Conformance Profiles](./conformance-profiles-v0.1.md) — tiered conformance matrix (Delegation-Core, MIC-State, MIC-Evidence, IDM Extension)
7. [Revocation Model](./revocation-v0.1.md) — layered revocation across delegation, session, credential, and transparency-log layers
8. [IDM Extension Profile](./idm-extension-v0.1.md) — Intent-Declaration-Manifest experimental profile

## Relationship to adjacent standards

- **AAT (Attenuating Authorization Tokens)** — IETF OAuth WG draft; MCEP's Delegation Grant is an AAT profile.
- **EAT (Entity Attestation Token, RFC 9711)** — used by the ER EAT/CWT profile to carry Execution Receipts.
- **SPIFFE** — workload identity substrate; MCEP binds mission credentials to SVIDs.
- **Biscuit** — first-party-attenuation credential format; the DG profile's narrowing semantics rely on Biscuit's append-only block model (see [ADR-017](../decisions/ADR-017-biscuit-attenuation-narrowing-semantics.md)).

These are real artifacts, not codenames. Their names stay in the specs as technical lineage.

## Conventions

- **Versioning:** v0.1 is the pre-release. The next revision (v0.2 or later) lands after the protocol-level rename decision + one round of adversarial review against the migrated public specs.
- **Normative language:** MUST / SHOULD / MAY usage follows RFC 2119 / RFC 8174.
- **Updates:** specs don't mutate in place; a material change opens a new version file and leaves the prior version immutable for citation stability.
