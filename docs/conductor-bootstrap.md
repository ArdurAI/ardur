# Conductor Bootstrap

The Conductor bootstrap script (`scripts/conductor-bootstrap.sh`) generates a
machine-readable context map for coding agents that work in this repository.

## Prerequisites

- Python 3.10+ with the repo's virtual environment at `python/.venv/`
- Git (the script checks branch state and remote defaults)
- A clean working tree (the script will warn if there are uncommitted changes)

## Running it

```bash
./scripts/conductor-bootstrap.sh
```

This produces:

- `.context/ARDUR_CONTEXT.md` — human-readable context summary
- `.context/ardur-graph.md` — dependency graph of repo modules
- `.context/ardur-graph.json` — machine-readable graph (JSON)

All `.context/` artifacts are local-only and excluded from version control.
They are regenerated each run, not accumulated.

## What to read after bootstrap

After bootstrap succeeds, read these in order:

1. `.context/ARDUR_CONTEXT.md` — your session context summary
2. `.context/ardur-graph.md` — module dependency graph
3. `AGENTS.md` — mandatory agent instructions (this file lives at the repo root)
4. `docs/engineering-standards.md` — foundation, testing, review, and security rules

## If bootstrap fails

A failed bootstrap usually means one of:

- The Python virtual environment is missing (`./scripts/setup-dev.sh`)
- The knowledge-graph script is not yet implemented (expected — see `scripts/check-local.sh`)
- The working tree has untracked files that conflict with generated paths

Inspect the failure message before editing files. A failed bootstrap means the
local toolchain, branch state, or generated context is not trustworthy yet.

## Agent contract

Agents working in this repo must:

1. Run `./scripts/conductor-bootstrap.sh` at session start
2. Read `.context/ARDUR_CONTEXT.md` and `.context/ardur-graph.md`
3. Follow the workspace contract in `AGENTS.md`
4. Preserve user WIP — do not reset, checkout, or clean unrelated local changes
5. Keep all generated context under `.context/` (gitignored)
