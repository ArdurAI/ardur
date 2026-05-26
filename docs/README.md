# Docs

These docs describe the public product direction and the engineering boundaries
that are stable enough to document. Runnable code and proof paths are present
for the Claude Code MVP path; package-manager release readiness and broader host
coverage are in active development.

## Available now

- [Claude Code MVP Quickstart](guides/claude-code-mvp-quickstart.md) — source
  checkout setup, no-key fresh-user evidence harness, live-Claude demo path, and
  claim boundary
- [Read The Phase 1 Evidence Bundle](guides/read-phase1-evidence-bundle.md) —
  how to interpret `bundle.redacted.json`, RWT gate semantics, redaction checks,
  and the claims a no-key run does and does not support
- [Phase 1 Demo Packet](guides/phase1-demo-packet.md) — a compact handoff for
  the current source-checkout Claude Code MVP proof path, including artifacts to
  attach and claims to avoid
- [Security Model](security-model.md)
- [Known Limitations](known-limitations.md)
- [Protocol Roots](protocol-roots.md)
- [Public Import Plan](public-import-plan.md)
- [Testing](TESTING.md)
- [Ardur Personal Hub](guides/ardur-personal-hub.md)
- [Agent Instructions](agent-instructions/README.md)
- [Engineering Standards](engineering-standards.md)
- [Architecture Decision Records](decisions/README.md)
- [MCEP Specifications (v0.1)](specs/README.md)
- [Comparisons and engineering responses](comparisons/README.md)
- [Technical Reference](reference/README.md) — CLI, Personal Hub HTTP API, and `ARDUR.md` profile format
- [Articles](articles/README.md)
- [CodeQL dismissal audit trail](audit/)

## Start here

1. Read the root [README](../README.md).
2. Check [STATUS](../STATUS.md) for what is public now versus still in flight.
3. Run the quickstart harness, then use the
   [evidence-bundle guide](guides/read-phase1-evidence-bundle.md) to read the
   resulting `bundle.redacted.json` honestly.
4. Use the [Phase 1 Demo Packet](guides/phase1-demo-packet.md) when you need a
   concise demo or reviewer handoff from that run.
5. Use [MEDIA](../MEDIA.md) for example recordings and context on the current
   implementation lineage.
