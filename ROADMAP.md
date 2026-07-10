# Roadmap

## Public Foundation

Already present:

- README and product intent
- research-informed positioning
- current status and known gaps
- public v0.1 specs (Mission Declaration, Delegation Grant, Execution Receipt and EAT profile, Verifier Contract, Conformance Profiles, IDM extension, Revocation)
- versioned RFC 8785 Execution Receipt v0.2 action payloads, legacy v0.1 verification, golden schema fixtures, and signed session-final receipt-chain/kernel-integrity binding
- optional receipt transparency anchors with Rekor v1 and separately keyed self-hosted proof profiles
- optional receiver-attested receipt envelopes with a separately keyed MCP shim, public golden fixture, and offline two-signature verification
- a packaged offline verifier that composes receipt chains, transparency proofs, and conditional receiver evidence into redacted CLI/JSON/static HTML reports without a running service
- curated Python and Go runtime imports
- the Ardur Personal Hub service plus its CLI surface
- the Claude Code plugin and hook with signed receipts
- runnable LangChain, LangGraph, and AutoGen quickstart examples
- the Ardur Personal browser extension, desktop-observe adapter, native-messaging host, and offline/no-key OpenAI Agents SDK and Google ADK fixtures
- dedicated Python and Go CI plus CodeQL, link-check, secret-scan, and Hugo workflows
- the Hugo public evidence-site source tree under `site/`
- the journey-log article series (Articles 05 and 06)
- a public CodeQL dismissal audit trail under `docs/audit/`
- agent-instruction guides for Conductor, Codex, and Claude
- technical reference pages for the CLI, Personal Hub HTTP API, and `ARDUR.md`
- selected archival walkthrough recordings as starter media
- `Ardur` as the public-facing product name with explicit naming boundaries for `VIBAP`, `MCEP`, and related protocol surfaces (see `docs/protocol-roots.md`)
- complete Go AAT package — 13 constraint types, issuance, derivation, PoP binding, full §7 chain verification (49 tests)
- cloud model governance tests proving real-world proxy enforcement with live LLMs

## Runtime Verification

Next hardening work:

- live-provider OpenAI Agents SDK and Google ADK wrapper evidence beyond the current no-key fixtures
- Codex hooks and Claude Desktop MCP packaging
- re-recorded proof media using the packaged offline verifier and stable public fixture paths
- conformance test vectors imported under `docs/specs/conformance/` to retire the "private layout" notes in the v0.1 specs

## Proof Story

Strengthen the public proof story:

- re-runnable proof media replacing the archival-only walkthrough casts
- public artifact paths with stable schemas
- broader proof-backed capability coverage across Mission Passport issuance, verification, attestation, and revocation

## Expansion

Expand the repo carefully:

- more framework examples beyond LangChain / LangGraph / AutoGen
- more deployment and operator material beyond the current SPIRE design surface
- a tagged release with a regenerated Homebrew formula carrying Python resource stanzas
- planned cleanup path for any remaining legacy product naming while preserving protocol names where they remain technically accurate

## What Will Stay Out

The repo should keep excluding:

- internal session machinery
- raw archival noise
- claims that are broader than the exported public surface can support
