#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

PYTHON_BIN="${PYTHON_BIN:-python3.13}"
SKIP_PYTHON=0
SKIP_GO=0
WARM_GO=0
ALLOW_GO_MISMATCH=0

usage() {
  cat <<'EOF'
Usage: scripts/setup-dev.sh [options]

Options:
  --skip-python          Do not create/update python/.venv
  --skip-go              Do not check the Go toolchain
  --warm-go              Run go mod download after the Go version check
  --allow-go-mismatch    Warn, but exit 0 if local Go is below go/go.mod
  --python PATH          Python binary to use (default: python3.13)
  -h, --help             Show this help
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --skip-python) SKIP_PYTHON=1 ;;
    --skip-go) SKIP_GO=1 ;;
    --warm-go) WARM_GO=1 ;;
    --allow-go-mismatch) ALLOW_GO_MISMATCH=1 ;;
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

version_lt() {
  python3 - "$1" "$2" <<'PY'
import sys

def parts(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split(".") if part.isdigit())

sys.exit(0 if parts(sys.argv[1]) < parts(sys.argv[2]) else 1)
PY
}

failures=0
waived_failures=0

if [ "$SKIP_PYTHON" -eq 0 ]; then
  if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "ERROR: $PYTHON_BIN not found. Install Python 3.13 or pass --python PATH." >&2
    exit 1
  fi

  # Enforce Ardur's Python minimum before creating the venv. python/pyproject.toml
  # pins requires-python; resolve it the same way the Go block resolves go/go.mod
  # so the two toolchain floors stay symmetric. Without this check, a below-minimum
  # PYTHON_BIN (common on macOS where python3 is the system 3.9) creates a broken
  # venv and fails deep inside a pyproject.toml build-dependency traceback instead
  # of a clear, actionable message.
  required_python_min="$(grep -oE 'requires-python[[:space:]]*=[[:space:]]*"[^"]*' python/pyproject.toml | grep -oE '[0-9]+\.[0-9]+' | head -1)"
  if [ -z "$required_python_min" ]; then
    required_python_min="3.10"
  fi
  actual_python="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
  echo "==> Python interpreter: $PYTHON_BIN ($actual_python); Ardur minimum: $required_python_min"
  if version_lt "$actual_python" "$required_python_min"; then
    echo "ERROR: Python $actual_python is below Ardur's minimum ($required_python_min). Install Python ${required_python_min}+ or pass --python PATH." >&2
    exit 1
  fi

  echo "==> Creating/updating python/.venv with $PYTHON_BIN"
  "$PYTHON_BIN" -m venv python/.venv
  python/.venv/bin/python -m pip install --upgrade pip
  (cd python && .venv/bin/python -m pip install -e '.[dev]')
fi

if [ "$SKIP_GO" -eq 0 ]; then
  required_go="$(awk '/^go / {print $2; exit}' go/go.mod)"
  if ! command -v go >/dev/null 2>&1; then
    echo "ERROR: go not found; go/go.mod requires $required_go." >&2
    failures=$((failures + 1))
  else
    actual_go="$(cd go && go env GOVERSION | sed 's/^go//')"
    echo "==> Go module toolchain version: $actual_go; go/go.mod requires: $required_go"
    if version_lt "$actual_go" "$required_go"; then
      if [ "$ALLOW_GO_MISMATCH" -eq 1 ]; then
        echo "WARN: local Go $actual_go is below go/go.mod requirement $required_go; continuing because --allow-go-mismatch was set." >&2
        waived_failures=$((waived_failures + 1))
      else
        echo "ERROR: local Go $actual_go is below go/go.mod requirement $required_go." >&2
        failures=$((failures + 1))
      fi
    elif [ "$WARM_GO" -eq 1 ]; then
      echo "==> Warming Go module cache"
      (cd go && go mod download)
    fi
  fi
fi

if [ "$failures" -gt 0 ]; then
  echo "setup completed with $failures toolchain problem(s)" >&2
  exit 1
fi

if [ "$waived_failures" -gt 0 ]; then
  echo "setup complete with $waived_failures waived toolchain warning(s)"
else
  echo "setup complete"
fi
echo "next: ./scripts/conductor-bootstrap.sh"
echo "next: ./scripts/check-local.sh --quick"
