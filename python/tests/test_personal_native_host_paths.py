from __future__ import annotations

import json

import pytest

from vibap.cli import main


# Minimum invocation that gets PAST argparse for ``personal-native-host``.
# ``--once-json`` is the arg under test.
_BASE = ["personal-native-host"]


@pytest.mark.parametrize(
    ("value", "arg_flag"),
    [
        ("", "once-json"),
        ("   ", "once-json"),
        ("\t\n  ", "once-json"),
    ],
)
def test_personal_native_host_rejects_empty_or_whitespace_once_json(
    capsys: pytest.CaptureFixture[str],
    value: str,
    arg_flag: str,
) -> None:
    """Empty/whitespace ``--once-json`` must fail before any filesystem touch.

    Previously ``--once-json`` was declared ``type=Path``, so argparse
    normalized ``""`` to ``PosixPath('.')`` (truthy CWD) BEFORE the handler
    ran. The handler then tried to read CWD as a JSON file, producing a
    misleading ``personal_native_host_once_json_unreadable: ... IsADirectoryError``
    response instead of the clean ``path_arg_invalid`` structured response
    that whitespace ``"   "`` already produced via the centralized guard.
    The arg is now ``type=str`` so the centralized guard fires with the
    standard ``path_arg_invalid`` structured response for both cases.
    """

    argv = [*_BASE, "--once-json", value]

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
    # Crucially, the misleading IsADirectoryError response must NOT appear.
    assert "personal_native_host_once_json_unreadable" not in rendered
    assert "IsADirectoryError" not in rendered


def test_personal_native_host_valid_once_json_gets_past_path_validation(
    capsys: pytest.CaptureFixture[str],
    tmp_path,
) -> None:
    """A structurally-valid ``--once-json`` must NOT produce ``path_arg_invalid``.

    This is the negative control: it proves the fix does not over-reject
    valid input. The command may still fail downstream (e.g. missing Hub
    fields in the JSON), but it must get PAST the centralized
    path-validation guard.
    """

    payload_file = tmp_path / "native-message.json"
    payload_file.write_text('{"example": "native-message"}', encoding="utf-8")

    main([*_BASE, "--once-json", str(payload_file)])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    rendered = json.dumps(payload, sort_keys=True)
    # Must NOT be path_arg_invalid — that would mean we over-rejected valid input.
    assert payload.get("error") != "path_arg_invalid"
    assert payload.get("condition") != "path_arg_invalid"
    # Crucially, the misleading IsADirectoryError response must NOT appear
    # for a valid file path either.
    assert "IsADirectoryError" not in rendered
