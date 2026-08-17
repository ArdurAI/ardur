#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

BASE_REF="${ARDUR_BASE_REF:-origin/dev}"
RELEASE_REF="${ARDUR_RELEASE_REF:-origin/main}"
CONTEXT_DIR="${ARDUR_CONTEXT_DIR:-.context}"
CONTEXT_FILE="$CONTEXT_DIR/ARDUR_CONTEXT.md"
GRAPH_JSON="$CONTEXT_DIR/ardur-graph.json"
GRAPH_MARKDOWN="$CONTEXT_DIR/ardur-graph.md"
GRAPH_MERMAID="$CONTEXT_DIR/ardur-graph.mmd"
PYTHON_BIN="${PYTHON_BIN:-}"

if [ -z "$PYTHON_BIN" ]; then
  if command -v python3.13 >/dev/null 2>&1; then
    PYTHON_BIN="python3.13"
  else
    PYTHON_BIN="python3"
  fi
fi

version_lt() {
  python3 - "$1" "$2" <<'PY'
import sys

def parts(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split(".") if part.isdigit())

sys.exit(0 if parts(sys.argv[1]) < parts(sys.argv[2]) else 1)
PY
}

# Enforce Ardur's Python minimum before running graph-generation Python.
# Mirrors the guard in scripts/setup-dev.sh: a below-minimum PYTHON_BIN (common
# on macOS where python3 is the system 3.9.6) produces confusing tracebacks
# instead of a clear, actionable message. conductor-bootstrap.sh is documented
# as the first command in every new session, so this check must fire here too.
if [ -f python/pyproject.toml ]; then
  required_python_min="$(grep -oE 'requires-python[[:space:]]*=[[:space:]]*"[^"]*' python/pyproject.toml | grep -oE '[0-9]+\.[0-9]+' | head -1)"
else
  required_python_min=""
fi
if [ -z "$required_python_min" ]; then
  required_python_min="3.10"
fi
actual_python="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
if version_lt "$actual_python" "$required_python_min"; then
  echo "ERROR: Python $actual_python is below Ardur's minimum ($required_python_min). Install Python ${required_python_min}+ or set PYTHON_BIN." >&2
  exit 1
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

rm -f -- "$CONTEXT_FILE" "$GRAPH_JSON" "$GRAPH_MARKDOWN" "$GRAPH_MERMAID"

graph_required_reading=""
if [ -f scripts/build-knowledge-graph.py ]; then
  "$PYTHON_BIN" scripts/build-knowledge-graph.py --output-dir "$CONTEXT_DIR"

  for graph_file in "$GRAPH_JSON" "$GRAPH_MARKDOWN" "$GRAPH_MERMAID"; do
    if [ ! -f "$graph_file" ] || [ ! -s "$graph_file" ]; then
      printf 'error: graph builder did not produce required artifact: %s\n' "$graph_file" >&2
      exit 1
    fi
  done

  graph_counts="$("$PYTHON_BIN" - "$GRAPH_JSON" <<'PY'
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
  graph_summary="- Status: available
$graph_counts"
  graph_required_reading="- \`$GRAPH_MARKDOWN\`
- \`$GRAPH_JSON\`"
  generated_files="- \`$CONTEXT_FILE\`
- \`$GRAPH_JSON\`
- \`$GRAPH_MARKDOWN\`
- \`$GRAPH_MERMAID\`
- \`$CONTEXT_DIR/skills/README.md\`"
  graph_rule="The generated graph is available. Use its Markdown view to choose a
neighborhood and its JSON form as the machine-readable map, then verify exact
behavior with \`rg\`, tests, and source files."
else
  graph_summary="- Status: unavailable
- Reason: \`scripts/build-knowledge-graph.py\` is not tracked in this checkout.
- Fallback: use live source files and workflow files directly."
  generated_files="- \`$CONTEXT_FILE\`
- \`$CONTEXT_DIR/skills/README.md\`"
  graph_rule="Graph artifacts are optional and unavailable in this checkout. Use \`rg\`,
tests, live source files, and workflow files directly; do not treat an absent
graph as a bootstrap failure."
fi

required_reading="- \`AGENTS.md\`"
if [ -n "$graph_required_reading" ]; then
  required_reading="$required_reading
$graph_required_reading"
fi
required_reading="$required_reading
- \`README.md\`
- \`STATUS.md\`
- \`docs/agent-instructions/README.md\`
- \`docs/agent-instructions/shared.md\`
- \`docs/engineering-standards.md\`
- \`docs/conductor-bootstrap.md\`
- \`docs/public-import-plan.md\`
- \`docs/TESTING.md\`
- \`.github/workflows/tests.yml\`"

# sed uses an EOL anchor and literal Markdown backticks.
# shellcheck disable=SC2016
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

$required_reading

## Branch Flow

- New improvements start on feature/workspace branches.
- First merge target is \`dev\`.
- \`main\` is release-only and should receive tested, verified public drops
  promoted from \`dev\`.

## Generated Graph

$graph_summary

## Generated Files

$generated_files

## Local-Only Skill Guardrail

Private skills and imported agent instructions belong in ignored paths:
\`.context/skills/\`, \`.agents/\`, \`.local-skills/\`, \`.ai-context/\`,
\`.agent-context/\`, \`.codex/\`, \`.claude/\`, \`HANDOFF.md\`, or
\`workdone-so-far.md\`. Do not force-add those paths. Run
\`./scripts/check-local.sh --quick\` before publishing; it fails if any of them
become tracked.

## Bootstrap Rule For Agents

$graph_rule

Do not infer current state from memory or articles when the repo can
answer the question directly.
EOF

printf 'wrote %s\n' "$CONTEXT_FILE"
