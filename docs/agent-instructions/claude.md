# Claude Agent Instructions

Claude and Claude Code should follow the [Shared Agent Contract](shared.md),
plus the Claude-specific rules below.

## First Action

```bash
./scripts/conductor-bootstrap.sh
```

Then read:

1. `.context/ARDUR_CONTEXT.md`
2. `.context/ardur-graph.md`
3. `AGENTS.md`
4. `docs/engineering-standards.md`

## Claude-Specific Rules

- Keep private Claude runtime state under `.claude/`; that path is ignored and
  must not be committed.
- Do not add a root `CLAUDE.md` unless the user explicitly asks for one. The
  public-safe Claude guide is this file.
- If using Claude Code hooks or plugin surfaces, verify the relevant hook
  behavior with focused tests and receipt-chain checks before claiming success.
- Do not store prompts, transcripts, or handoff notes in tracked docs unless
  they are intentionally public and reviewed.

## PR Target

- Normal work: `dev`.
- Release-only work: `main`, only when explicitly requested.
