"""Regression coverage for the local repository check driver."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_quick_check_compiles_graph_with_selected_python(tmp_path: Path) -> None:
    """The dormant graph branch must use the explicitly selected Python."""
    repo = tmp_path / "repo"
    scripts_dir = repo / "scripts"
    scripts_dir.mkdir(parents=True)
    check_script = scripts_dir / "check-local.sh"
    shutil.copy2(_REPO_ROOT / "scripts" / "check-local.sh", check_script)

    graph_script = scripts_dir / "build-knowledge-graph.py"
    graph_script.write_text(
        """\
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--output-dir", required=True)
args = parser.parse_args()
output_dir = Path(args.output_dir)
output_dir.mkdir(parents=True, exist_ok=True)
(output_dir / "ardur-graph.json").write_text(
    json.dumps({"status": "ok"}),
    encoding="utf-8",
)
""",
        encoding="utf-8",
    )

    (repo / "python" / "vibap" / "_specs").mkdir(parents=True)
    (repo / "docs" / "specs").mkdir(parents=True)
    workflow_dir = repo / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "secret-scan.yml").write_text(
        """\
# Scan for forbidden internal terms
# PATTERN='a^'
# Scan for specific LLM model identifiers
# PATTERN='a^'
""",
        encoding="utf-8",
    )

    shim_dir = repo / "bin"
    shim_dir.mkdir()
    python_shim = shim_dir / "python shim"
    python_shim.write_text(
        """\
#!/bin/sh
set -eu
printf '%s\\n' "$*" >> "$ARDUR_PYTHON_TRACE"
exec "$ARDUR_TEST_PYTHON" "$@"
""",
        encoding="utf-8",
    )
    python_shim.chmod(0o755)

    subprocess.run(
        ["git", "init", "--quiet"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )

    trace_path = repo / "python-trace.log"
    env = {
        **os.environ,
        "ARDUR_PYTHON_TRACE": str(trace_path),
        "ARDUR_TEST_PYTHON": sys.executable,
    }
    result = subprocess.run(
        [
            str(check_script),
            "--quick",
            "--python",
            str(python_shim.relative_to(repo)),
        ],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "-m py_compile scripts/build-knowledge-graph.py" in trace_path.read_text(
        encoding="utf-8"
    )
