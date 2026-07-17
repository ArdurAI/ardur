"""Focused regressions for proxy default-path materialization."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_proxy_with_explicit_paths_does_not_create_unused_default_home(
    tmp_path: Path,
) -> None:
    """An omitted receipts path derives from the explicit log, not DEFAULT_HOME."""

    unused_home = tmp_path / "unused-home"
    explicit_root = tmp_path / "explicit"
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; "
                "from cryptography.hazmat.primitives.asymmetric import ec; "
                "from vibap.proxy import GovernanceProxy; "
                "key = ec.generate_private_key(ec.SECP256R1()); "
                "GovernanceProxy(log_path=sys.argv[1], state_dir=sys.argv[2], "
                "keys_dir=sys.argv[3], private_key=key, "
                "public_key=key.public_key())"
            ),
            str(explicit_root / "audit.jsonl"),
            str(explicit_root / "state"),
            str(explicit_root / "keys"),
        ],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env={**os.environ, "VIBAP_HOME": str(unused_home)},
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert not unused_home.exists()
