from __future__ import annotations

import json
from pathlib import Path

import pytest

from vibap.cli import main


# Minimum invocation that gets PAST argparse for ``preflight tool-server``.
# A structurally-valid config with one server is required so ``--config``
# validation is the only thing under test.
_VALID_CONFIG_BODY = '{"mcpServers": {"echo": {"command": "/bin/echo"}}}'


def _write_valid_config(tmp_path: Path) -> Path:
    cfg = tmp_path / "ts-config.json"
    cfg.write_text(_VALID_CONFIG_BODY, encoding="utf-8")
    return cfg


@pytest.mark.parametrize(
    ("value", "arg_flag"),
    [
        ("", "config"),
        ("   ", "config"),
        ("\t\n  ", "config"),
    ],
)
def test_preflight_tool_server_rejects_empty_or_whitespace_config(
    capsys: pytest.CaptureFixture[str],
    value: str,
    arg_flag: str,
) -> None:
    """Empty/whitespace ``--config`` must fail with ``path_arg_invalid``.

    Previously ``--config`` was declared ``type=Path``, so argparse
    normalized ``""`` to ``PosixPath('.')`` (truthy CWD) BEFORE the handler
    ran. The handler then treated CWD as the config path, producing a
    misleading ``config_not_regular: configuration must be a regular file``
    for empty input, and ``config_missing: configuration file does not
    exist`` for whitespace-only input — two DX-inconsistent errors instead
    of the standard ``path_arg_invalid`` structured response. The arg is
    now ``type=str`` so the centralized guard fires for both cases.
    """

    argv = ["preflight", "tool-server", "--config", value]

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
    assert arg_flag in payload["message"]
    assert "empty" in payload["message"].lower()
    assert "Traceback" not in rendered
    # Crucially, the misleading downstream errors must NOT appear.
    assert "config_not_regular" not in rendered
    assert "config_missing" not in rendered


@pytest.mark.parametrize(
    ("value", "arg_flag"),
    [
        ("", "output"),
        ("   ", "output"),
        ("\t\n  ", "output"),
    ],
)
def test_preflight_tool_server_rejects_empty_or_whitespace_output(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    value: str,
    arg_flag: str,
) -> None:
    """Empty/whitespace ``--output`` must fail with ``path_arg_invalid``.

    Previously ``--output`` was declared ``type=Path``, so argparse
    normalized ``""`` to ``PosixPath('.')`` (truthy) and ``"   "`` to
    ``PosixPath('   ')`` (truthy) BEFORE the handler ran. With a valid
    ``--config``, whitespace ``--output "   "`` silently succeeded (ok:true,
    exit 0) and wrote a real report file literally named ``"   "`` into the
    CWD — the most severe of the three defects, since it silently creates a
    garbage-named file. The centralized guard now fires first with the
    standard ``path_arg_invalid`` structured response for both cases.
    """

    cfg = _write_valid_config(tmp_path)
    argv = [
        "preflight",
        "tool-server",
        "--config",
        str(cfg),
        "--output",
        value,
    ]

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
    assert arg_flag in payload["message"]
    assert "empty" in payload["message"].lower()
    assert "Traceback" not in rendered
    # Crucially, the report must NOT have been written.
    assert "tool_server_preflight_report_written" not in rendered
    assert "report_sha256" not in rendered
    # And no garbage-named file must have been created in CWD.
    assert not Path(value).exists() if value.strip() else True


def test_preflight_tool_server_valid_config_gets_past_path_validation(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """A structurally-valid ``--config`` must NOT produce ``path_arg_invalid``.

    This is the negative control: it proves the fix does not over-reject
    valid input. The command may still report findings downstream, but it
    must get PAST the centralized path-validation guard.
    """

    cfg = _write_valid_config(tmp_path)

    rc = main(["preflight", "tool-server", "--config", str(cfg)])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    rendered = json.dumps(payload, sort_keys=True)
    # Must NOT be path_arg_invalid — that would mean we over-rejected valid input.
    assert payload.get("error") != "path_arg_invalid"
    assert payload.get("condition") != "path_arg_invalid"
    # And the misleading downstream errors must NOT appear for valid input.
    assert "config_not_regular" not in rendered
    assert "config_missing" not in rendered


def test_preflight_tool_server_valid_output_writes_report(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """A structurally-valid ``--output`` must write the report file.

    This proves the fix preserves the happy path: a valid ``--output`` path
    receives the report and returns the ``tool_server_preflight_report_written``
    condition, rather than being rejected by the centralized guard.
    """

    cfg = _write_valid_config(tmp_path)
    out = tmp_path / "report.json"

    rc = main(
        [
            "preflight",
            "tool-server",
            "--config",
            str(cfg),
            "--output",
            str(out),
        ]
    )

    captured = capsys.readouterr()
    assert rc == 0
    payload = json.loads(captured.out)
    assert payload["condition"] == "tool_server_preflight_report_written"
    assert "report_sha256" in payload
    # The report file must actually exist on disk.
    assert out.is_file()
