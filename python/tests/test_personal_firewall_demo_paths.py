from __future__ import annotations

import json

import pytest

from vibap.cli import main


# Minimum invocation that gets PAST argparse for ``personal-firewall demo``.
# ``--temp-parent`` is the arg under test; ``--json`` keeps output parseable.
_BASE = ["personal-firewall", "demo", "--json"]


@pytest.mark.parametrize(
    ("value", "arg_flag"),
    [
        ("", "temp-parent"),
        ("   ", "temp-parent"),
        ("\t\n  ", "temp-parent"),
    ],
)
def test_personal_firewall_demo_rejects_empty_or_whitespace_temp_parent(
    capsys: pytest.CaptureFixture[str],
    value: str,
    arg_flag: str,
) -> None:
    """Empty/whitespace ``--temp-parent`` must fail before any demo work.

    Previously ``--temp-parent`` was declared ``type=Path``, so argparse
    normalized ``""`` to ``PosixPath('.')`` (truthy CWD) BEFORE the handler
    ran. The centralized ``_path_arg_invalid_failure`` guard only catches
    ``isinstance(value, str)`` values, so empty input silently bypassed it
    and the demo ran with temp files written into CWD. Whitespace ``"   "``
    already rejected (``PosixPath('   ')`` is a non-existent dir), so the
    two empty/whitespace cases behaved inconsistently. The arg is now
    ``type=str`` so the centralized guard fires with the standard
    ``path_arg_invalid`` structured response for both cases.
    """

    argv = [*_BASE, "--temp-parent", value]

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
    # Crucially, the demo must NOT have run. No ok:true demo payload, and
    # no temp-state schema version leaked.
    assert "personal_firewall_demo_failed" not in rendered
    assert "schema_version" not in rendered


def test_personal_firewall_demo_valid_temp_parent_gets_past_path_validation(
    capsys: pytest.CaptureFixture[str],
    tmp_path,
) -> None:
    """A structurally-valid ``--temp-parent`` must NOT produce ``path_arg_invalid``.

    This is the negative control: it proves the fix does not over-reject
    valid input. The command may still run the demo successfully or fail
    downstream (e.g. timeout), but it must get PAST the centralized
    path-validation guard.
    """

    main([*_BASE, "--temp-parent", str(tmp_path)])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    # Must NOT be path_arg_invalid — that would mean we over-rejected valid input.
    assert payload.get("error") != "path_arg_invalid"
    assert payload.get("condition") != "path_arg_invalid"
    # A valid temp-parent should let the demo run; ok:true is expected, but
    # the critical assertion is that path validation did not fire.
    assert "schema_version" in payload or payload.get("ok") is True
