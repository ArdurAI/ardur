# Conductor Bootstrap

The Conductor bootstrap script (`scripts/conductor-bootstrap.sh`) generates a
human-readable context summary for coding agents that work in this repository.
It also generates graph artifacts when the public checkout contains the graph
builder.

## Prerequisites

- Python 3.10+
- Git (the script checks branch state and remote defaults)
- A working tree whose current state should be recorded in the context summary

## Running it

```bash
./scripts/conductor-bootstrap.sh
```

This always produces:

- `.context/ARDUR_CONTEXT.md` — human-readable context summary
- `.context/skills/README.md` — local-only skill-storage guardrails

When `scripts/build-knowledge-graph.py` is present, a successful run also
produces all three graph artifacts:

- `.context/ardur-graph.md` — dependency graph of repo modules
- `.context/ardur-graph.json` — machine-readable graph (JSON)
- `.context/ardur-graph.mmd` — Mermaid graph view

When the builder is absent, bootstrap still succeeds and marks the graph as
`unavailable` in `.context/ARDUR_CONTEXT.md`. The graph files are optional in
that path. If the builder is present but fails to produce any required graph
artifact, bootstrap fails instead of advertising a partial result.

All `.context/` artifacts are local-only and excluded from version control.
They are regenerated each run, not accumulated.

## What to read after bootstrap

After bootstrap succeeds, read these in order:

1. `.context/ARDUR_CONTEXT.md` — your session context summary
2. If its **Generated Graph** status is `available`, read
   `.context/ardur-graph.md` and use `.context/ardur-graph.json` as the
   machine-readable map
3. If its graph status is `unavailable`, use the listed live source and
   workflow files directly
4. `AGENTS.md` — mandatory agent instructions (this file lives at the repo root)
5. `docs/engineering-standards.md` — foundation, testing, review, and security rules

## If bootstrap fails

A failed bootstrap usually means one of:

- A usable Python interpreter or graph-builder dependency is missing when the
  optional builder is present
- A present knowledge-graph builder returned invalid data or omitted a required
  graph artifact
- The working tree has untracked files that conflict with generated paths

Inspect the failure message before editing files. A failed bootstrap means the
local toolchain, branch state, or generated context is not trustworthy yet.

## Agent contract

Agents working in this repo must:

1. Run `./scripts/conductor-bootstrap.sh` at session start
2. Read `.context/ARDUR_CONTEXT.md` and follow its graph-availability status
3. Follow the workspace contract in `AGENTS.md`
4. Preserve user WIP — do not reset, checkout, or clean unrelated local changes
5. Keep all generated context under `.context/` (gitignored)
