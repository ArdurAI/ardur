#!/usr/bin/env python3
"""Run the packaged Linux governance benchmark from a source checkout."""

from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON_ROOT = REPO_ROOT / "python"
sys.path.insert(0, str(PYTHON_ROOT))

from vibap.linux_benchmark import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
