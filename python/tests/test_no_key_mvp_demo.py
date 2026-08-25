from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_SCRIPT = REPO_ROOT / "scripts" / "run-no-key-mvp-demo.py"
README = REPO_ROOT / "README.md"


def test_no_key_mvp_demo_reaches_permit_deny_and_verified_attestation() -> None:
    result = subprocess.run(
        [sys.executable, str(DEMO_SCRIPT), "--timeout-s", "15"],
        cwd=REPO_ROOT,
        env=os.environ | {"VIBAP_API_TOKEN": "ignored-by-no-auth-demo"},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS  local proxy started on loopback without bearer auth" in result.stdout
    assert "PASS  read_file returned PERMIT" in result.stdout
    assert "PASS  delete_file returned DENY" in result.stdout
    assert (
        "PASS  signed attestation verified with the temporary public key"
        in result.stdout
    )
    assert "Temporary keys, state, and audit data were removed." in result.stdout
    assert "ignored-by-no-auth-demo" not in result.stdout


def test_readme_surfaces_the_two_existing_no_key_paths() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "scripts/run-rwt-phase1-fresh-user.py" in readme
    assert "docs/guides/claude-code-mvp-quickstart.md" in readme
