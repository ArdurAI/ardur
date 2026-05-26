# Conductor Agent Instructions

Conductor workspaces are parallel, branch-isolated working areas. Follow the
[Shared Agent Contract](shared.md), plus the Conductor-specific rules below.

## First Action

```bash
./scripts/conductor-bootstrap.sh
```

Then read:

1. `.context/ARDUR_CONTEXT.md`
2. `.context/ardur-graph.md`
3. `AGENTS.md`
4. `docs/engineering-standards.md`

## Conductor-Specific Rules

- Do not rename the current branch.
- Do not assume the workspace branch was created from the correct base. Check
  `.context/ARDUR_CONTEXT.md`; normal development still targets `dev`.
- If another worktree has `dev` checked out, do not force-move it.
- Put local handoff notes and generated context under `.context/`.
- The user may only see the final message by default, so final responses must
  include the essential result, validation, and caveats.

## PR Target

- Normal work: PR to `dev`.
- Release promotion: PR from `dev` to `main` only when explicitly requested and
  verified.
