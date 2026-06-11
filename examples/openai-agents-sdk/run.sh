#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR=""
MISSION="$REPO_ROOT/examples/missions/provider-adapter-no-key-mission.json"

usage() {
  printf 'Usage: %s [--out-dir DIR] [--mission PATH]\n' "$0" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    --mission)
      MISSION="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ardur-openai-agents-sdk-fixture.XXXXXX")"
fi

select_python() {
  if [[ -n "${PYTHON:-}" ]]; then
    printf '%s\n' "$PYTHON"
    return 0
  fi

  local repo_python="$REPO_ROOT/python/.venv/bin/python"
  if [[ -x "$repo_python" ]]; then
    printf '%s\n' "$repo_python"
    return 0
  fi

  local candidate
  for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
      command -v "$candidate"
      return 0
    fi
  done

  printf 'Ardur fixture requires Python >= 3.10; set PYTHON to a supported interpreter or run ./scripts/setup-dev.sh.\n' >&2
  return 127
}

require_supported_python() {
  local python_bin="$1"
  local status
  if "$python_bin" - "$python_bin" <<'PY'
import sys

selected = sys.argv[1]
version = ".".join(str(part) for part in sys.version_info[:3])
if sys.version_info < (3, 10):
    print(
        f"Ardur fixture requires Python >= 3.10; selected interpreter {selected!r} is Python {version}. "
        "Set PYTHON to python3.10+ or run ./scripts/setup-dev.sh.",
        file=sys.stderr,
    )
    raise SystemExit(66)
PY
  then
    return 0
  else
    status=$?
    exit "$status"
  fi
}

require_fixture_dependencies() {
  local python_bin="$1"
  local status
  if "$python_bin" - "$python_bin" <<'PY'
import importlib.util
import sys

selected = sys.argv[1]
required = {
    "jwt": "PyJWT",
    "cryptography": "cryptography",
    "jsonschema": "jsonschema",
}
missing = [dist for module, dist in required.items() if importlib.util.find_spec(module) is None]
if missing:
    print(
        "Ardur fixture dependencies are not installed for selected interpreter "
        f"{selected!r}: missing {', '.join(missing)}. Run ./scripts/setup-dev.sh "
        "or set PYTHON=python/.venv/bin/python.",
        file=sys.stderr,
    )
    raise SystemExit(65)
PY
  then
    return 0
  else
    status=$?
    exit "$status"
  fi
}

PYTHON_BIN="$(select_python)"
require_supported_python "$PYTHON_BIN"
require_fixture_dependencies "$PYTHON_BIN"
export PYTHONPATH="$REPO_ROOT/python${PYTHONPATH:+:$PYTHONPATH}"
exec "$PYTHON_BIN" "$SCRIPT_DIR/demo.py" --adapter openai-agents-sdk --out-dir "$OUT_DIR" --mission "$MISSION"
