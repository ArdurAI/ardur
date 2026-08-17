"""Test that ``ardur run --json`` help text correctly documents stderr output.

The ``--json`` flag emits governance results to **stderr** (not stdout),
reserving stdout for the child process output. This was initially implemented
to send JSON to stdout, but that was changed to stderr to avoid mixing
governance JSON with child process stdout.

The inline ``--help`` text must match the actual implementation so users
running ``ardur run --help`` get accurate guidance.
"""

from vibap import cli


def test_run_json_help_says_stderr_not_stdout():
    """The --json help text must say 'stderr', not 'stdout'."""
    parser = cli.build_parser()
    # Find the run subparser
    run_action = None
    for action in parser._actions:
        if hasattr(action, "choices") and "run" in (action.choices or {}):
            run_action = action
            break
    assert run_action is not None, "run subparser not found"
    run_parser = run_action.choices["run"]

    # Find the --json argument
    json_action = None
    for action in run_parser._actions:
        if "--json" in (action.option_strings or []):
            json_action = action
            break
    assert json_action is not None, "--json argument not found on run subparser"

    help_text = json_action.help or ""
    # The help text must say "stderr" (actual output target)
    assert "stderr" in help_text.lower(), (
        f"--json help text should mention 'stderr' (the actual output target), "
        f"got: {help_text!r}"
    )
    # The help text must NOT say the JSON goes to stdout
    # (stdout is reserved for the child process output)
    assert "stdout" not in help_text.lower() or "child" in help_text.lower(), (
        f"--json help text should not claim JSON goes to stdout "
        f"(stdout is reserved for child process), got: {help_text!r}"
    )


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v"])
