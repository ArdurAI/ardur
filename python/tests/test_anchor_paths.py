from __future__ import annotations

import json

import pytest

from vibap.cli import main


# Common minimum invocation that gets PAST argparse. Backend c2sp-local-v1
# requires --local-log + --log-private-key + --origin at the handler level, so
# we pass valid-looking stand-ins for the args that are NOT under test. The
# stand-ins only need to satisfy argparse shape (non-empty str); path validation
# runs at the very top of cmd_anchor before any filesystem touch.
_BASE = [
    "anchor",
    "--receipt-log",
    "/tmp/ardur-anchor-receipt.jsonl",
    "--backend",
    "c2sp-local-v1",
    "--local-log",
    "/tmp/ardur-anchor-local-log.jsonl",
    "--log-private-key",
    "/tmp/ardur-anchor-local-log.key",
    "--origin",
    "example-origin.example.com",
]


@pytest.mark.parametrize(
    ("option", "value", "arg_flag"),
    [
        ("--receipt-log", "", "receipt-log"),
        ("--receipt-log", "   ", "receipt-log"),
        ("--receipt-log", "\t\n  ", "receipt-log"),
        ("--local-log", "", "local-log"),
        ("--local-log", "   ", "local-log"),
        ("--log-private-key", "", "log-private-key"),
        ("--log-private-key", "   ", "log-private-key"),
    ],
)
def test_anchor_rejects_empty_or_whitespace_path_args(
    capsys: pytest.CaptureFixture[str],
    option: str,
    value: str,
    arg_flag: str,
) -> None:
    """Empty/whitespace anchor path args must fail before any downstream work.

    Previously --receipt-log, --local-log, and --log-private-key were declared
    ``type=Path``, so argparse normalized ``""`` to ``PosixPath('.')`` and
    ``"   "`` to ``PosixPath('   ')`` BEFORE the handler ran. The centralized
    ``_path_arg_invalid_failure`` guard at the top of ``cmd_anchor`` only
    catches ``isinstance(value, str)`` values, so the bad input silently
    bypassed it and produced confusing downstream errors (e.g. ``local
    transparency-log private key not found: .``). All three args are now
    ``type=str`` so the centralized guard fires with the standard
    ``path_arg_invalid`` structured response.
    """

    # Append the option under test at the end. For repeated options argparse
    # uses the LAST value, so this overrides the valid stand-in for the option
    # under test while leaving the other args at their valid base values.
    argv = [*_BASE, option, value]

    rc = main(argv)

    captured = capsys.readouterr()
    assert rc == 1
    assert captured.err == ""
    payload = json.loads(captured.out)
    rendered = json.dumps(payload, sort_keys=True)
    assert payload["ok"] is False
    assert payload["error"] == "path_arg_invalid"
    assert payload["error_code"] == "path_arg_invalid"
    assert payload["condition"] == "path_arg_invalid"
    # Message names the offending flag and describes the empty/whitespace rule.
    assert arg_flag in payload["message"]
    assert "empty" in payload["message"].lower()
    # No raw input value is echoed and no local absolute path leaks.
    assert value.strip() == ""  # sanity: the input really was whitespace-only
    assert "Traceback" not in rendered
    # next_steps use placeholder commands, never the raw input.
    assert all(
        "<" in step["command"] and ">" in step["command"]
        for step in payload["next_steps"]
    )
    # Crucially, the downstream "private key not found" error must NOT appear.
    assert "anchor_submission_failed" not in rendered
    assert "private key not found" not in rendered


def test_anchor_valid_paths_get_past_path_validation(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A structurally-valid invocation must NOT produce ``path_arg_invalid``.

    This is the negative control: it proves the fix does not over-reject valid
    input. The command may still fail downstream (e.g. the local-log private
    key file does not exist at the stand-in path), but it must get PAST the
    centralized path-validation guard.
    """

    rc = main(
        [
            "anchor",
            "--receipt-log",
            "/tmp/ardur-anchor-receipt.jsonl",
            "--backend",
            "c2sp-local-v1",
            "--local-log",
            "/tmp/ardur-anchor-local-log.jsonl",
            "--log-private-key",
            "/tmp/ardur-anchor-local-log.key",
            "--origin",
            "example-origin.example.com",
        ]
    )

    captured = capsys.readouterr()
    assert rc == 1  # downstream failure is expected (missing private key)
    payload = json.loads(captured.out)
    rendered = json.dumps(payload, sort_keys=True)
    # Must NOT be path_arg_invalid — that would mean we over-rejected valid input.
    assert payload["error"] != "path_arg_invalid"
    assert payload.get("condition") != "path_arg_invalid"
    # The expected downstream failure is anchor_submission_failed.
    assert payload["error"] == "anchor_submission_failed"
