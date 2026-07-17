# Architecture Decision Records

ADRs document load-bearing design decisions behind Ardur's runtime, protocol, and deployment shape. Each record captures the context, the decision, and the trade-offs known at the time of writing.

ADRs are migrated from the private research repo with the two-pass cleanup applied (sensitive-reference scrub, then historical-codename rename). Decision dates reflect when the decision was originally made; the migration preserves chronology even though the public repo is newer.

**Public-surface import caveat.** Each ADR body was written in a private context and may reference implementation symbols (e.g., `passport.verify_passport`, `GovernanceProxy._load_verified_session`), internal review artifacts (e.g., "PR #10", "finding #3 from the 2026-04-21 review"), or helper scripts (`install_hook.sh`) that live in the private research repo and have not yet landed in this public repo. When you see such a reference, treat it as a pointer to future work: the underlying code and the issue/PR history land alongside the Phase 1 code lift per [`docs/public-import-plan.md`](../public-import-plan.md). Contributors cannot verify those referenced artifacts from the public tree today.

## Index

| # | Title | Status | Date |
|---|-------|--------|------|
| 015 | [Production-grade SPIRE deployment design for Kubernetes](./ADR-015-production-spire-deployment.md) | Proposed | 2026-04-19 |
| 016 | [Delegation lineage hash index](./ADR-016-delegation-lineage-hash-index.md) | Accepted | 2026-04-21 |
| 017 | [Biscuit attenuation narrowing semantics](./ADR-017-biscuit-attenuation-narrowing-semantics.md) | Accepted | 2026-04-21 |
| 018 | [Delegation lineage hash domain unification](./ADR-018-delegation-lineage-hash-domain-unification.md) | Proposed | 2026-04-21 |
| 019 | [Parent-token anchors against trusted lineage](./ADR-019-parent-token-anchors-against-trusted-lineage.md) | Proposed | 2026-04-21 |
| 020 | [Persisted-session reverification on load](./ADR-020-persisted-session-reverification-on-load.md) | Proposed | 2026-04-21 |
| 021 | [KB-JWT server-challenged nonce](./ADR-021-kb-jwt-server-challenged-nonce.md) | Proposed | 2026-04-21 |
| 022 | [SPIFFE mTLS identity for operator telemetry](./ADR-022-operator-telemetry-spiffe-mtls.md) | Accepted | 2026-07-11 |
| 023 | [Explicit resource-scope authority](./ADR-023-explicit-resource-scope-authority.md) | Accepted | 2026-07-12 |
| 024 | [Self-asserted owner identity assurance](./ADR-024-self-asserted-owner-identity-assurance.md) | Accepted | 2026-07-12 |

## Conventions

- **Status**: `Proposed`, `Accepted`, `Superseded by ADR-NNN`, `Deprecated`. A `Proposed` status means the design is documented but not yet landed in code; it can still change.
- **Numbering**: sequential, no gaps. The formal ADR-file practice began at ADR-015 in the private research repo; earlier design decisions were captured in running decision logs rather than individual ADR files. Public numbering preserves the original sequence so cross-references stay stable.
- **Scope**: ADRs record decisions about the protocol (MCEP), the runtime (Ardur), and deployment shapes. They do not duplicate spec content — the v0.1 specs live in [`docs/specs/`](../specs/).
