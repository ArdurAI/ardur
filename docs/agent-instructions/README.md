# Agent Instructions

This directory contains public-safe operating instructions for agents working
on Ardur.

The shared contract is intentionally the same for every agent. The per-agent
files only adapt startup behavior, tool expectations, and local state handling
for that runtime.

## Files

- [Shared Contract](shared.md)
- [Conductor](conductor.md)
- [Codex](codex.md)
- [Claude](claude.md)

## Public vs local

Tracked instructions belong here and in root `AGENTS.md`.

Private or machine-specific instructions belong only in ignored local paths:

- `.context/skills/`
- `.agents/`
- `.local-skills/`
- `.ai-context/`
- `.agent-context/`
- `.codex/`
- `.claude/`
- `HANDOFF.md`
- `workdone-so-far.md`

Do not force-add those local-only paths. `scripts/check-local.sh --quick` and
the `secret-scan` workflow fail if they become tracked.
