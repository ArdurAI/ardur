# Claude Code Instructions

This repository keeps a single, canonical set of agent instructions in
[`AGENTS.md`](AGENTS.md). This file exists only so that Claude Code loads them
automatically; it deliberately holds no rules of its own, so that the two can
never drift apart.

@AGENTS.md

A public, tool-specific guide also lives at `docs/agent-instructions/claude.md`.
It shares the same contract as `AGENTS.md` and only adds startup and
local-state handling notes for this runtime.
