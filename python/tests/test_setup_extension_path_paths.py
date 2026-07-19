from __future__ import annotations

import json
from pathlib import Path

import pytest

from vibap.cli import main


@pytest.mark.parametrize(
    ("value", "arg_flag"),
    [
        ("", "extension-path"),
        ("   ", "extension-path"),
        ("\t\n  ", "extension-path"),
    ],
)
def test_setup_rejects_empty_or_whitespace_extension_path(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    value: str,
    arg_flag: str,
) -> None:
    """Empty/whitespace ``--extension-path`` must fail with ``path_arg_invalid``.

    Previously ``--extension-path`` was declared ``type=Path``, so argparse
    normalized ``""`` to ``PosixPath('.')`` (truthy CWD) and ``"   "`` to
    ``PosixPath('   ')`` (truthy) BEFORE the handler ran. The handler's
    ``if args.extension_path:`` truthiness check then passed and
    ``browser_extension_path=str(Path(...).expanduser())`` wrote ``"."`` or
    ``"   "`` into ``~/.vibap/personal/config.json`` as a persisted config
    value — a data-quality defect. The arg is now ``type=str`` so the
    centralized guard fires first with the standard ``path_arg_invalid``
    structured response for both cases, before any setup work happens.

    ``setup_personal`` is mocked to prove the guard fires BEFORE setup runs
    and to avoid writing a real LaunchAgent plist / Personal home dir.
    """

    setup_called = {"count": 0}

    def _fake_setup_personal(args):  # pragma: no cover - guard must fire first
        setup_called["count"] += 1
        return {"ok": True, "should_not_reach": True}

    monkeypatch.setattr("vibap.cli.setup_personal", _fake_setup_personal)

    rc = main(["setup", "--extension-path", value])

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
    # Crucially, setup_personal must NOT have been called.
    assert setup_called["count"] == 0


def test_setup_valid_extension_path_passes_path_to_setup(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A valid ``--extension-path`` reaches ``setup_personal`` with a Path.

    This proves the fix preserves the happy path AND that the centralized
    guard's str->Path coercion keeps ``args.extension_path`` a ``Path``
    downstream (the ``str(Path(args.extension_path).expanduser())`` line in
    ``personal_hub.setup_personal`` expects a Path-coercible value).

    ``setup_personal`` is mocked to inspect the args it receives and to
    avoid writing a real LaunchAgent plist / Personal home dir.
    """

    captured_args = {}

    def _fake_setup_personal(args):
        captured_args["extension_path"] = args.extension_path
        return {"ok": True, "reached_setup": True}

    monkeypatch.setattr("vibap.cli.setup_personal", _fake_setup_personal)

    valid_dir = tmp_path / "my-extension"

    rc = main(["setup", "--extension-path", str(valid_dir)])

    captured = capsys.readouterr()
    assert rc == 0
    payload = json.loads(captured.out)
    assert payload.get("error") != "path_arg_invalid"
    assert payload.get("reached_setup") is True
    # The centralized guard must have coerced the validated str back to Path.
    assert isinstance(captured_args.get("extension_path"), Path)
    assert captured_args["extension_path"] == valid_dir


def test_setup_default_extension_path_passes_path_to_setup(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Omitting ``--extension-path`` preserves the default and reaches setup.

    The default was ``Path("examples/ardur-personal-extension")``; after the
    ``type=str`` change it is the string ``"examples/ardur-personal-extension"``.
    The centralized guard must NOT fire on this valid non-empty default, and
    must coerce it back to ``Path`` before ``setup_personal`` runs.

    ``setup_personal`` is mocked to avoid writing a real LaunchAgent plist.
    """

    captured_args = {}

    def _fake_setup_personal(args):
        captured_args["extension_path"] = args.extension_path
        return {"ok": True, "reached_setup": True}

    monkeypatch.setattr("vibap.cli.setup_personal", _fake_setup_personal)

    rc = main(["setup"])

    captured = capsys.readouterr()
    assert rc == 0
    payload = json.loads(captured.out)
    assert payload.get("error") != "path_arg_invalid"
    assert payload.get("reached_setup") is True
    # The default must survive as a Path after the guard's coercion.
    assert isinstance(captured_args.get("extension_path"), Path)
    assert captured_args["extension_path"] == Path("examples/ardur-personal-extension")
