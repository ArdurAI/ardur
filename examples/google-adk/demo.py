#!/usr/bin/env python3
# pyright: reportMissingImports=false
"""Run the Google ADK no-key Ardur fixture."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON_DIR = REPO_ROOT / "python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

from vibap.provider_adapter_fixture import main


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:], adapter_id="google-adk"))
