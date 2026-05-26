# Security Model

Ardur security is based on least privilege, explicit declaration, runtime
enforcement, and verifiable evidence.

> **Conformance scope (2026-04-28 narrowing):** This page describes the
> *design intent* of the protocol. The reference proxy in `python/vibap/`
> implements the **Delegation-Core** profile of `verifier-contract-v0.1`,
> not yet the **MIC-State** or **MIC-Evidence** profiles. When closing
> these gaps, update both this document and [`known-limitations.md`](known-limitations.md)
> in the same PR. See `docs/specs/verifier-contract-v0.1.md` Section 13
> ("Reference Implementation Conformance Notes") for the precise gap.
> Deployments needing the stronger profiles MUST add layers beyond the
> reference proxy or wait for the hardening rounds that close 13.2.

## Core security gates (enforced by the reference proxy)

- tool calls must match declared tools
- resource access must match declared scopes
- delegated child authority must be a subset of parent authority
- per-session passport replay defense (jti single-use)
- KB-JWT nonce replay store and AAT proof-of-possession default-on
- per-session and per-mission revocation via signed status lists
- receipt chains emit and verify (hash-linked, JWS-signed)
- declared-telemetry absence yields `insufficient_evidence`, not a
  false `compliant`
- approval-rate-limit when the Mission Declaration declares an approval
  policy

## Design-only gates (NOT yet enforced by the reference proxy)

These appear in `verifier-contract-v0.1.md` as `MUST` clauses but the
reference Python proxy does not yet enforce them. Deployments that need
them MUST layer additional verifiers:

- runtime-observed `observed_manifest_digest == MD.tool_manifest_digest`
- per-grant `last_seen_receipts` tracking and MIC-Evidence hidden-hop
  detection
- explicit invocation-envelope signature beyond the credential JWT

## Threats in scope

- prompt injection causing out-of-scope tool use
- resource-scope abuse
- delegation scope widening
- budget double-spend
- receipt tampering, stripping, replay, and forking
- metadata forgery or laundering
- partial observation causing unsafe overclaims
- authorized tools used for unauthorized purpose

## Hardening direction

The wider hardening roadmap includes:

- deterministic behavioral templates
- streaming reconciliation and active revocation
- manual reconciliation for unresolved `unknown` states
- TEE-bound attestation profiles
- nested multi-agent attestation
- tiered governance with downgrade rejection

Important boundary: those hardening directions must not be marketed as fully
proven protections until their proof entries reach L5 for the claimed scope.

## Network and secrets posture

- SSRF-sensitive destinations should be denied by policy where the capability
  is claimed as release-gated.
- Official artifacts and recordings should be reviewed for secrets before being
  treated as publishable evidence.

## Governance tiers

| Tier | Boundary |
|---|---|
| `fast_hmac` | internal low-risk actions only |
| `standard_jws` | default receipt path for ordinary governed actions |
| `strong_eat_tee` | required for high-risk delegated or side-effecting actions |

## Required posture

When Ardur lacks evidence, it must deny or return `unknown` rather than
claim safe success.

## Enforcement boundary

This document and the comparison docs under `docs/comparisons/` describe
what the protocol guarantees and what the reference proxy enforces today.
"What the protocol guarantees" is wider than "what the reference proxy
enforces today." The latter is the conservative claim — use it whenever
you cite Ardur in a security context against a real adversary. The
former is the design that the hardening roadmap is driving toward.
