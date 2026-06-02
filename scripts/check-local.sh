#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

MODE="quick"
SKIP_PYTHON=0
SKIP_GO=0
WITH_NETWORK=0
PYTHON_BIN="${PYTHON_BIN:-}"

if [ -z "$PYTHON_BIN" ]; then
  if [ -x python/.venv/bin/python ]; then
    PYTHON_BIN="python/.venv/bin/python"
  elif command -v python3.13 >/dev/null 2>&1; then
    PYTHON_BIN="python3.13"
  else
    PYTHON_BIN="python3"
  fi
fi

usage() {
  cat <<'EOF'
Usage: scripts/check-local.sh [--quick|--full] [options]

Options:
  --quick          Run fast repository hygiene checks (default)
  --full           Run quick checks plus Python and Go tests
  --skip-python    Skip Python tests in --full mode
  --skip-go        Skip Go tests in --full mode
  --with-network   Run optional networked local checks when installed
  --python PATH    Python binary to use for local checks
  -h, --help       Show this help
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --quick) MODE="quick" ;;
    --full) MODE="full" ;;
    --skip-python) SKIP_PYTHON=1 ;;
    --skip-go) SKIP_GO=1 ;;
    --with-network) WITH_NETWORK=1 ;;
    --python)
      shift
      PYTHON_BIN="${1:?missing python path}"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

PYTHON_RUN="$PYTHON_BIN"
if [[ "$PYTHON_RUN" == */* && "$PYTHON_RUN" != /* ]]; then
  PYTHON_RUN="$ROOT/$PYTHON_RUN"
fi

failures=0

run_step() {
  local label="$1"
  shift
  echo
  echo "==> $label"
  if "$@"; then
    echo "ok: $label"
  else
    echo "FAILED: $label" >&2
    failures=$((failures + 1))
  fi
}

validate_json() {
  local fail=0
  while IFS= read -r -d '' file; do
    if ! "$PYTHON_RUN" -c "import json,sys; json.load(open(sys.argv[1], encoding='utf-8'))" "$file" >/dev/null 2>&1; then
      echo "invalid JSON: $file" >&2
      fail=1
    fi
  done < <(git ls-files -z '*.json')
  return "$fail"
}

validate_yaml() {
  local yaml_python=""
  local candidate
  for candidate in "$PYTHON_RUN" python3.13 python3; do
    if "$candidate" -c "import yaml" >/dev/null 2>&1; then
      yaml_python="$candidate"
      break
    fi
  done

  if [ -z "$yaml_python" ]; then
    echo "PyYAML unavailable in $PYTHON_RUN, python3.13, and python3" >&2
    return 1
  fi

  local fail=0
  while IFS= read -r -d '' file; do
    if ! "$yaml_python" -c "import sys,yaml; list(yaml.safe_load_all(open(sys.argv[1], encoding='utf-8')))" "$file" >/dev/null 2>&1; then
      echo "invalid YAML: $file" >&2
      fail=1
    fi
  done < <(git ls-files -z '*.yml' '*.yaml')
  return "$fail"
}

validate_schema_sync() {
  "$PYTHON_RUN" - <<'PY'
import hashlib
import json
import sys
from pathlib import Path

fail = 0
for embedded in sorted(Path("python/vibap/_specs").glob("*.schema.json")):
    base = embedded.name.removesuffix(".schema.json")
    canonical_base = base.replace("_", "-")
    if canonical_base.endswith("-v01"):
        canonical_base = canonical_base[:-3] + "v0.1"
    canonical = Path("docs/specs") / f"{canonical_base}.schema.json"
    if not canonical.exists():
        print(f"missing canonical schema for {embedded}: {canonical}", file=sys.stderr)
        fail = 1
        continue
    def digest(path: Path) -> str:
        payload = json.dumps(json.loads(path.read_text(encoding="utf-8")), sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
    if digest(canonical) != digest(embedded):
        print(f"schema drift: {canonical} != {embedded}", file=sys.stderr)
        fail = 1
sys.exit(fail)
PY
}

extract_pattern() {
  "$PYTHON_RUN" - "$1" <<'PY'
import re
import sys
from pathlib import Path

marker = sys.argv[1]
lines = Path(".github/workflows/secret-scan.yml").read_text(encoding="utf-8").splitlines()
for index, line in enumerate(lines):
    if marker in line:
        for candidate in lines[index:]:
            match = re.search(r"PATTERN='(.*)'", candidate)
            if match:
                print(match.group(1))
                sys.exit(0)
print(f"pattern not found for marker: {marker}", file=sys.stderr)
sys.exit(1)
PY
}

scan_forbidden_terms() {
  local pattern
  pattern="$(extract_pattern "Scan for forbidden internal terms")"
  if grep -RInE --include='*.md' --include='*.yml' --include='*.yaml' \
      --include='*.json' --include='*.cast' --include='*.toml' \
      --include='*.py' --include='*.go' --include='*.sh' \
      --include='.gitignore' --include='.env*' --include='Dockerfile*' \
      --include='Makefile*' \
      --exclude-dir='.git' --exclude-dir='.context' --exclude-dir='.github' \
      --exclude-dir='.venv' --exclude-dir='.agents' --exclude-dir='.ai-context' \
      --exclude-dir='.agent-context' --exclude-dir='.codex' \
      --exclude-dir='.local-skills' --exclude-dir='.claude' \
      --exclude-dir='artifacts' --exclude-dir='node_modules' \
      "$pattern" .; then
    return 1
  fi
}

scan_model_names() {
  local pattern
  pattern="$(extract_pattern "Scan for specific LLM model identifiers")"
  if grep -RInE --include='*.md' --include='*.yml' --include='*.yaml' \
      --include='*.json' --include='*.cast' --include='*.toml' \
      --include='*.py' --include='*.go' --include='*.sh' \
      --include='Dockerfile*' \
      --exclude-dir='.git' --exclude-dir='.context' --exclude-dir='.github' \
      --exclude-dir='.venv' --exclude-dir='.agents' --exclude-dir='.ai-context' \
      --exclude-dir='.agent-context' --exclude-dir='.codex' \
      --exclude-dir='.local-skills' --exclude-dir='.claude' \
      --exclude-dir='artifacts' --exclude-dir='node_modules' \
      -i "$pattern" .; then
    return 1
  fi
}

local_only_paths_untracked() {
  local tracked
  tracked="$(git ls-files .context .agents .ai-context .agent-context .codex .local-skills .claude agent-instructions.local HANDOFF.md workdone-so-far.md 2>/dev/null || true)"
  if [ -n "$tracked" ]; then
    echo "local-only agent/skill paths are tracked:" >&2
    printf '%s\n' "$tracked" >&2
    echo "move them back to ignored local storage before publishing" >&2
    return 1
  fi
}

shell_syntax() {
  local fail=0
  while IFS= read -r -d '' file; do
    bash -n "$file" || fail=1
  done < <(find scripts -type f -name '*.sh' -print0)
  return "$fail"
}

graph_build() {
  "$PYTHON_RUN" scripts/build-knowledge-graph.py --output-dir .context
  "$PYTHON_RUN" -m json.tool .context/ardur-graph.json >/dev/null
}

go_version_ok() {
  local required actual
  required="$(awk '/^go / {print $2; exit}' go/go.mod)"
  if ! command -v go >/dev/null 2>&1; then
    echo "go not found; go/go.mod requires $required" >&2
    return 1
  fi
  actual="$(go version | awk '{print $3}' | sed 's/^go//')"
  python3 - "$actual" "$required" <<'PY'
import sys

def parts(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split(".") if part.isdigit())

actual, required = sys.argv[1], sys.argv[2]
if parts(actual) < parts(required):
    print(f"local Go {actual} is below go/go.mod requirement {required}", file=sys.stderr)
    sys.exit(1)
PY
}

python_tests() {
  (cd python && "$PYTHON_RUN" -m pytest tests/ -q --tb=short)
}

go_tests() {
  go_version_ok
  (cd go && go test -count=1 ./...)
  (cd go && go vet ./...)
}

optional_gitleaks() {
  if ! command -v gitleaks >/dev/null 2>&1; then
    echo "gitleaks not installed; skipping"
    return 0
  fi
  gitleaks detect --source . --no-git --redact
}

optional_lychee() {
  if [ "$WITH_NETWORK" -eq 0 ]; then
    echo "pass --with-network to run lychee locally"
    return 0
  fi
  if ! command -v lychee >/dev/null 2>&1; then
    echo "lychee not installed; skipping"
    return 0
  fi
  lychee --cache --max-cache-age 7d --no-progress --accept 200,206,429 \
    --exclude 'github\.com/.*/security/advisories/new(/.*)?$' './**/*.md'
}

run_step "shell syntax" shell_syntax
run_step "knowledge graph build" graph_build
run_step "Python graph script compiles" "$PYTHON_RUN" -m py_compile scripts/build-knowledge-graph.py
run_step "tracked JSON parses" validate_json
run_step "tracked YAML parses" validate_yaml
run_step "embedded spec schemas match canonical docs" validate_schema_sync
run_step "local-only skill paths are untracked" local_only_paths_untracked
run_step "forbidden public term scan" scan_forbidden_terms
run_step "specific model-name scan" scan_model_names

if [ "$MODE" = "full" ]; then
  if [ "$SKIP_PYTHON" -eq 0 ]; then
    run_step "Python tests" python_tests
  fi
  if [ "$SKIP_GO" -eq 0 ]; then
    run_step "Go tests and vet" go_tests
  fi
  run_step "optional gitleaks" optional_gitleaks
  run_step "optional lychee" optional_lychee
fi

if [ "$failures" -gt 0 ]; then
  echo
  echo "$failures check(s) failed" >&2
  exit 1
fi

echo
echo "all $MODE checks passed"
