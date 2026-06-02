#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

BASE_REF="${ARDUR_BASE_REF:-origin/dev}"
RELEASE_REF="${ARDUR_RELEASE_REF:-origin/main}"
CONTEXT_DIR="${ARDUR_CONTEXT_DIR:-.context}"
CONTEXT_FILE="$CONTEXT_DIR/ARDUR_CONTEXT.md"
PYTHON_BIN="${PYTHON_BIN:-}"

if [ -z "$PYTHON_BIN" ]; then
  if command -v python3.13 >/dev/null 2>&1; then
    PYTHON_BIN="python3.13"
  else
    PYTHON_BIN="python3"
  fi
fi

mkdir -p "$CONTEXT_DIR"
mkdir -p "$CONTEXT_DIR/skills"

if [ ! -f "$CONTEXT_DIR/skills/README.md" ]; then
  cat > "$CONTEXT_DIR/skills/README.md" <<'EOF'
# Local Skills

This folder is ignored by git. Use it for Conductor/session-local skills,
private instructions, imported skill packs, and scratch context that must not
ship in the public Ardur repository.

Allowed here:

- local-only SKILL.md files
- tool-specific notes
- private workspace paths
- unpublished planning context

Not allowed here:

- secrets or credentials
- files that should be reviewed as public docs
- generated artifacts that belong under a more specific ignored runtime folder

Before publishing, run:

```bash
./scripts/check-local.sh --quick
```

That check fails if local-only skill/instruction paths have been force-added to
git.
EOF
fi

tool_version() {
  local name="$1"
  shift
  if command -v "$name" >/dev/null 2>&1; then
    "$name" "$@" 2>&1 | head -n 1
  else
    printf '%s not found\n' "$name"
  fi
}

git_value() {
  git "$@" 2>/dev/null || true
}

current_branch="$(git_value branch --show-current)"
head_sha="$(git_value rev-parse --short HEAD)"
base_sha="$(git_value rev-parse --short "$BASE_REF")"
release_sha="$(git_value rev-parse --short "$RELEASE_REF")"
generated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if git merge-base --is-ancestor "$BASE_REF" HEAD >/dev/null 2>&1; then
  ancestry="HEAD contains $BASE_REF"
else
  ancestry="HEAD does not contain $BASE_REF or $BASE_REF is unavailable"
fi

status_short="$(git status --short)"
if [ -z "$status_short" ]; then
  status_short="clean"
fi

committed_diff_names="$(git diff --name-status "$BASE_REF"...HEAD 2>/dev/null | sed -n '1,160p' || true)"
if [ -z "$committed_diff_names" ]; then
  committed_diff_names="no committed diff against $BASE_REF"
fi

worktree_diff_names="$(git diff --name-status 2>/dev/null | sed -n '1,160p' || true)"
untracked_names="$(git ls-files --others --exclude-standard 2>/dev/null | sed -n '1,160p' | sed 's/^/??\t/' || true)"
if [ -z "$worktree_diff_names$untracked_names" ]; then
  worktree_diff_names="no local worktree diff"
else
  worktree_diff_names="$(printf '%s\n%s\n' "$worktree_diff_names" "$untracked_names" | sed '/^$/d')"
fi

"$PYTHON_BIN" scripts/build-knowledge-graph.py --output-dir "$CONTEXT_DIR"

graph_summary="$("$PYTHON_BIN" - "$CONTEXT_DIR/ardur-graph.json" <<'PY'
import json
import sys
from pathlib import Path

graph = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
counts = graph["counts"]
print(f"- Nodes: `{counts['nodes']}`")
print(f"- Edges: `{counts['edges']}`")
print(f"- Indexed files: `{graph['repo']['indexed_file_count']}`")
print(f"- Tracked files: `{graph['repo']['tracked_file_count']}`")
print(f"- Untracked nonignored files: `{graph['repo']['untracked_file_count']}`")
for kind, count in counts["nodes_by_type"].items():
    if kind in {"python-module", "go-package", "workflow", "test", "adr", "spec"}:
        print(f"- {kind}: `{count}`")
PY
)"

workflow_list="$(git ls-files '.github/workflows/*.yml' '.github/workflows/*.yaml' | sed 's/^/- `/; s/$/`/')"
if [ -z "$workflow_list" ]; then
  workflow_list="- no workflows tracked"
fi

cat > "$CONTEXT_FILE" <<EOF
# Ardur Bootstrap Context

Generated: \`$generated_at\`

## Session Contract

- First-read file: \`AGENTS.md\`
- Default diff base: \`$BASE_REF\`
- Release base: \`$RELEASE_REF\`
- Current branch: \`$current_branch\`
- Current HEAD: \`$head_sha\`
- \`$BASE_REF\`: \`$base_sha\`
- \`$RELEASE_REF\`: \`$release_sha\`
- Base ancestry: $ancestry
- Do not rename the branch.
- Do not revert unrelated user work.
- Target \`dev\` for normal implementation work.
- Treat \`main\` as release-only; promote there only after tested, verified
  public-facing work is ready from \`dev\`.

## Working Tree

\`\`\`text
$status_short
\`\`\`

## Committed Diff Against \`$BASE_REF\`

\`\`\`text
$committed_diff_names
\`\`\`

## Local Worktree Diff

\`\`\`text
$worktree_diff_names
\`\`\`

## Tooling

- $(tool_version "$PYTHON_BIN" --version)
- $(tool_version python3 --version)
- $(tool_version go version)
- $(tool_version git --version)
- $(tool_version rg --version)
- $(tool_version gh --version)
- $(tool_version gitleaks version)
- $(tool_version lychee --version)

## Live CI Truth

Read live workflow files before trusting stale prose. Current tracked workflows:

$workflow_list

The repo currently tracks \`.github/workflows/tests.yml\`; if older docs say
dedicated Python or Go CI is pending, treat the workflow as the current source
of truth and update stale docs when touching that area.

## Required Reading Order

1. \`AGENTS.md\`
2. \`.context/ardur-graph.md\`
3. \`README.md\`
4. \`STATUS.md\`
5. \`docs/agent-instructions/README.md\`
6. \`docs/agent-instructions/shared.md\`
7. \`docs/engineering-standards.md\`
8. \`docs/conductor-bootstrap.md\`
9. \`docs/public-import-plan.md\`
10. \`docs/TESTING.md\`
11. \`.github/workflows/tests.yml\`

## Branch Flow

- New improvements start on feature/workspace branches.
- First merge target is \`dev\`.
- \`main\` is release-only and should receive tested, verified public drops
  promoted from \`dev\`.

## Generated Graph

$graph_summary

Files:

- \`.context/ardur-graph.json\`
- \`.context/ardur-graph.md\`
- \`.context/ardur-graph.mmd\`
- \`.context/skills/README.md\`

## Local-Only Skill Guardrail

Private skills and imported agent instructions belong in ignored paths:
\`.context/skills/\`, \`.agents/\`, \`.local-skills/\`, \`.ai-context/\`,
\`.agent-context/\`, \`.codex/\`, \`.claude/\`, \`HANDOFF.md\`, or
\`workdone-so-far.md\`. Do not force-add those paths. Run
\`./scripts/check-local.sh --quick\` before publishing; it fails if any of them
become tracked.

## Bootstrap Rule For Agents

Use the graph to pick a neighborhood, then use \`rg\`, tests, and source files
to verify exact behavior. Do not infer current state from memory or articles
when the repo can answer the question directly.
EOF

printf 'wrote %s\n' "$CONTEXT_FILE"
