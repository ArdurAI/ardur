# Security Model

Ardur security is based on least privilege, explicit declaration, runtime
enforcement, and verifiable evidence.

> **Conformance scope (2026-05-19 update):** The reference proxy in
> `python/vibap/` implements all three conformance profiles of
> `verifier-contract-v0.1`: **Delegation-Core**, **MIC-State**, and
> **MIC-Evidence**. The four design-only gaps identified in the 2026-04-28
> hostile audit are closed. See `docs/specs/verifier-contract-v0.1.md`
> Section 13 ("Reference Implementation Conformance Notes") for the
> conformance map and `python/tests/test_mic_conformance.py` for the
> 29-test validation suite.

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

All `MUST` clauses from `verifier-contract-v0.1.md` that were previously
design-only are now enforced as of the 2026-05-19 hardening round
(t_dcbf560b). The reference proxy now implements:

- runtime-observed `observed_manifest_digest == MD.tool_manifest_digest`
- per-grant `last_seen_receipts` tracking with replay across proxy restarts
- MIC-Evidence hidden-hop detection via visible receipt linkage
- explicit invocation-envelope signature verification

No additional verifier layers are required for MIC-State or MIC-Evidence
conformance.

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

Before enablement, `ardur preflight tool-server` can inspect strict JSON MCP and
tool-server configuration for broad filesystem/network grants, shell execution,
secret-like environment exposure, instruction-like metadata, missing content
pins, and ungated side effects. It opens bounded input without following a
final-component symlink and never starts the server, imports its code, reads
referenced secrets, or contacts configured endpoints. Evidence is redacted and
the generated policy skeleton keeps resource/network scopes empty by default.

This scanner is advisory and incomplete by design. Tool annotations and
descriptions are untrusted hints, and a clean static report does not establish
runtime behavior, dependency safety, binary provenance, or endpoint identity.
See [`Tool-Server Preflight v0.1`](specs/tool-server-preflight-v0.1.md).

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
