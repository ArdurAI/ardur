"""Local end-to-end smoke for the Ardur Claude Code hook.

Issues a test passport, simulates 3 hook invocations (Read -> Bash -> Read),
and verifies the resulting receipt chain. Does not require a live Claude
Code binary.

Usage:
    PYTHONPATH=python python3 plugins/claude-code/scripts/smoke.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# Wire up sys.path so the script works both when invoked from the repo root
# AND when the plugins/ directory has been copied into a Claude Code plugin
# install location (the python/ tree must be installed via `pip install -e .`).
_REPO_PYTHON = Path(__file__).resolve().parents[3] / "python"
if _REPO_PYTHON.exists():
    sys.path.insert(0, str(_REPO_PYTHON))

from vibap.claude_code_hook import handle_pre_tool_use, handle_post_tool_use
from vibap.passport import MissionPassport, generate_keypair, issue_passport
from vibap.receipt import verify_chain


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ardur-cc-hook-smoke-") as tmp_dir:
        tmp_path = Path(tmp_dir)
        private_key, public_key = generate_keypair(keys_dir=tmp_path)
        mission = MissionPassport(
            agent_id="smoke",
            mission="Claude Code hook smoke session",
            allowed_tools=["Read"],
            forbidden_tools=["Bash"],
            resource_scope=["/tmp/*"],
            max_tool_calls=10,
            max_duration_s=600,
        )
        token = issue_passport(mission, private_key, ttl_s=3600)

        chain_dir = tmp_path / "chain"
        os.environ["ARDUR_MISSION_PASSPORT"] = token
        os.environ["VIBAP_HOME"] = str(tmp_path)
        os.environ["ARDUR_CC_HOOK_DIR"] = str(chain_dir)

        try:
            # Call 1: Read (allowed)
            handle_pre_tool_use(
                {"tool_name": "Read", "tool_input": {"file_path": "/tmp/a.txt"}},
                keys_dir=tmp_path,
            )
            handle_post_tool_use(
                {
                    "tool_name": "Read",
                    "tool_input": {"file_path": "/tmp/a.txt"},
                    "tool_response": {"content": "a", "exit_code": 0},
                },
                keys_dir=tmp_path,
            )
            # Call 2: Bash (denied -- Pre only)
            out = handle_pre_tool_use(
                {"tool_name": "Bash", "tool_input": {"command": "echo hi"}},
                keys_dir=tmp_path,
            )
            hook_output = out.get("hookSpecificOutput") or {}
            if hook_output.get("permissionDecision") != "deny":
                print(f"FAIL: Bash call was not denied; output={out}", file=sys.stderr)
                return 1

            # Call 3: Read (allowed)
            handle_pre_tool_use(
                {"tool_name": "Read", "tool_input": {"file_path": "/tmp/b.txt"}},
                keys_dir=tmp_path,
            )
            handle_post_tool_use(
                {
                    "tool_name": "Read",
                    "tool_input": {"file_path": "/tmp/b.txt"},
                    "tool_response": {"content": "b", "exit_code": 0},
                },
                keys_dir=tmp_path,
            )

            receipts = list(chain_dir.rglob("receipts.jsonl"))
            if len(receipts) != 1:
                print(f"FAIL: expected 1 chain file, found {len(receipts)}", file=sys.stderr)
                return 1

            lines = [
                l.strip()
                for l in receipts[0].read_text(encoding="utf-8").splitlines()
                if l.strip()
            ]
            if len(lines) != 5:
                print(f"FAIL: expected 5 receipts (2 Pre+Post + 1 deny Pre), got {len(lines)}", file=sys.stderr)
                return 1

            try:
                verify_chain(lines, public_key)
            except Exception as exc:
                print(f"FAIL: chain verification raised: {exc}", file=sys.stderr)
                return 1

        finally:
            for var in ("ARDUR_MISSION_PASSPORT", "VIBAP_HOME", "ARDUR_CC_HOOK_DIR"):
                os.environ.pop(var, None)

        print("PASS: 5 receipts (2 pre+post Read, 1 Bash deny pre, 2 pre+post Read), chain verified")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
