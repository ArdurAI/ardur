# Codex Agent Instructions

Codex should follow the [Shared Agent Contract](shared.md), plus the
Codex-specific rules below.

## First Action

```bash
./scripts/conductor-bootstrap.sh
```

Then read:

1. `.context/ARDUR_CONTEXT.md`
2. `.context/ardur-graph.md`
3. `AGENTS.md`
4. `docs/engineering-standards.md`

## Codex-Specific Rules

- Use `rg` for search and `apply_patch` for manual edits.
- Do not write files with shell heredocs when `apply_patch` is appropriate.
- Do not revert unrelated user changes.
- Treat `.context/` as generated/local state. Regenerate it with scripts rather
  than editing generated files by hand.
- Keep final responses self-contained: what changed, what was validated, and
  what remains blocked.

## PR Target

- Normal work: `dev`.
- Release-only work: `main`, only when explicitly requested.
