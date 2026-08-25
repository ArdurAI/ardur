from __future__ import annotations

import json

import pytest

from vibap.cli import main


@pytest.mark.parametrize("value", ["", "   "])
def test_posture_report_rejects_empty_or_whitespace_input(
    capsys: pytest.CaptureFixture[str],
    value: str,
) -> None:
    """Required --input must fail closed before empty input resolves to CWD."""

    rc = main(["posture", "report", "--input", value])

    captured = capsys.readouterr()
    assert rc == 1
    assert captured.err == ""
    payload = json.loads(captured.out)
    rendered = json.dumps(payload, sort_keys=True)
    assert payload["ok"] is False
    assert payload["error"] == "posture_report_input_empty"
    assert payload["error_code"] == "posture_report_input_empty"
    assert payload["condition"] == "posture_report_input_empty"
    assert "empty" in payload["message"].lower()
    assert "Traceback" not in rendered
    assert all("<" in step["command"] and ">" in step["command"] for step in payload["next_steps"])
