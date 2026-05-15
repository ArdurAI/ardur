# Security Model

Ardur security is based on least privilege, explicit declaration, runtime
enforcement, and verifiable evidence.

> **Conformance scope (updated 2026-05-14):** This page describes the
> *design intent* of the protocol. The reference proxy in `python/vibap/`
> implements all three conformance profiles — **Delegation-Core**,
> **MIC-State**, and **MIC-Evidence** — as of the 2026-05-14 hardening
> round. All four design-only gaps identified in the 2026-04-28 audit
> are closed. See `docs/specs/verifier-contract-v0.1.md` Section 13
> ("Reference Implementation Conformance Notes") for the current map.

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

## Additional conformance gates (enforced as of 2026-05-14)

These checks are active under MIC-State and MIC-Evidence profiles:

- visibility check (`visibility != "full"` → `insufficient_evidence`)
- envelope-signature verification (fail-closed: absent or non-True → violation)
- runtime-observed `observed_manifest_digest == MD.tool_manifest_digest`
- per-grant `last_seen_receipts` tracking
- MIC-Evidence hidden-hop detection and missing-parent-receipt detection

See `docs/specs/verifier-contract-v0.1.md` Section 13 for the full conformance
map and `python/tests/test_mic_conformance.py` for the 29-test validation suite.

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

## Honesty boundary

This document and the comparison docs under `docs/comparisons/` describe
what the protocol guarantees and what the reference proxy enforces today.
"What the protocol guarantees" is wider than "what the reference proxy
enforces today." The latter is the conservative claim — use it whenever
you cite Ardur in a security context against a real adversary. The
former is the design that the hardening roadmap is driving toward.
