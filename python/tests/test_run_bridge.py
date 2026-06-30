"""Integration + unit tests for the ``ardur run`` governance bridge.

The headline test (:func:`test_ardur_run_governs_launched_agent_zero_setup`)
proves the bridge's contract end to end: ``ardur run`` of a stand-in agent that
makes a PERMIT-able and a DENY-able tool call results in a started session,
evaluated calls, a verifiable signed receipt chain, and a verifiable behavioral
attestation — with **zero** manual ``ardur protect`` setup and no edit to the
user's ``~/.claude/settings.json``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from vibap import kernel_correlation as kc
from vibap.attestation import verify_attestation
from vibap.passport import load_public_key
from vibap.receipt import verify_chain
from vibap.run_bridge import (
    ClaudeCodeAdapter,
    EnvProxyAdapter,
    RunContext,
    TransparentInterceptAdapter,
    run_governed,
    select_adapter,
)

# A self-contained stand-in agent. It speaks the documented env contract
# (ARDUR_PROXY_URL / ARDUR_API_TOKEN / ARDUR_SESSION_ID) and routes three tool
# calls through the governance proxy: one PERMIT-able (Read), one DENY-able
# (Bash, which the mission forbids), one PERMIT-able (Glob).
STANDIN_AGENT = '''\
import json, os, sys, urllib.request

proxy = os.environ["ARDUR_PROXY_URL"]
token = os.environ["ARDUR_API_TOKEN"]
session = os.environ["ARDUR_SESSION_ID"]


def evaluate(tool, args):
    body = json.dumps({"session_id": session, "tool_name": tool, "arguments": args}).encode()
    req = urllib.request.Request(
        proxy + "/evaluate", data=body, method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


decisions = {}
for tool, args in [
    ("Read", {"file_path": "README.md"}),
    ("Bash", {"command": "rm -rf /"}),
    ("Glob", {"pattern": "*.py"}),
]:
    decisions[tool] = evaluate(tool, args)["decision"]

sys.stdout.write(json.dumps(decisions))
'''


@pytest.fixture
def standin_agent(tmp_path: Path) -> Path:
    path = tmp_path / "standin_agent.py"
    path.write_text(STANDIN_AGENT, encoding="utf-8")
    return path


def _hermetic_kernel_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Force kernel correlation to degrade deterministically on any platform.

    Points the cgroup root at a directory with no ``cgroup.controllers`` (so
    cgroup v2 looks unavailable) and the daemon socket at a path that does not
    exist — so the bridge takes its graceful-degradation path without touching
    the host's real ``/sys/fs/cgroup`` or any live daemon.
    """
    fake_cgroup_root = tmp_path / "fake-cgroup"
    fake_cgroup_root.mkdir()
    monkeypatch.setenv(kc.CGROUP_ROOT_ENV, str(fake_cgroup_root))
    monkeypatch.setenv(kc.DAEMON_SOCKET_ENV, str(tmp_path / "no-such-daemon.sock"))


def test_ardur_run_governs_launched_agent_zero_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, standin_agent: Path
) -> None:
    _hermetic_kernel_env(monkeypatch, tmp_path)
    home = tmp_path / "ardur-home"

    result = run_governed(
        command=[sys.executable, str(standin_agent)],
        mission="Integration: govern a launched stand-in agent.",
        allowed_tools=["Read", "Glob", "Grep"],
        forbidden_tools=["Bash"],
        max_tool_calls=10,
        home=home,
        via="env",
    )

    # — a session started —
    assert result.session_id
    assert result.mission_id
    assert result.exit_code == 0
    assert result.adapter == "env-proxy"

    # — calls were evaluated (PERMIT + DENY) —
    assert result.total_events == 3
    assert result.permits == 2
    assert result.denials == 1

    # — a signed receipt chain was produced and verifies cryptographically —
    public_key = load_public_key(keys_dir=home / "keys")
    receipts_path = Path(result.receipts_path)
    assert receipts_path.is_file()
    entries = [json.loads(line) for line in receipts_path.read_text().splitlines() if line.strip()]
    assert len(entries) == 3
    verified = verify_chain(entries, public_key)
    assert len(verified) == 3
    verdicts = [c.get("verdict") for c in verified]
    # Signed receipts record a compliant (PERMIT) and a violation (DENY) verdict.
    assert "compliant" in verdicts
    assert "violation" in verdicts

    # — a behavioral attestation was issued and verifies —
    assert result.attestation_token
    assert result.attestation_digest.startswith("sha-256:")
    att = verify_attestation(result.attestation_token, public_key)
    assert att["passport_jti"] == result.session_id
    assert int(att["permits"]) == 2
    assert int(att["denials"]) == 1

    # — ZERO manual ardur protect: governance ran from an isolated ephemeral
    #   home with its own passport; nothing was written to ~/.claude/settings.json —
    assert (home / "active_mission.jwt").is_file()
    assert not (home / "settings.json").exists()

    # — kernel correlation degraded gracefully (no daemon on the test host) —
    assert result.correlation["available"] is False
    assert "governing via env/hook" in result.correlation["reason"]


def test_ardur_run_denies_when_no_tools_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, standin_agent: Path
) -> None:
    """A mission with an empty allowlist denies every call but still attests."""
    _hermetic_kernel_env(monkeypatch, tmp_path)
    home = tmp_path / "deny-home"

    result = run_governed(
        command=[sys.executable, str(standin_agent)],
        mission="Deny everything.",
        allowed_tools=[],
        forbidden_tools=["Bash"],
        max_tool_calls=10,
        home=home,
        via="env",
    )
    assert result.total_events == 3
    assert result.denials >= 1
    assert result.receipt_count == 3
    assert result.attestation_token


def test_run_governed_rejects_empty_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _hermetic_kernel_env(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="requires a command"):
        run_governed(command=[], mission="x", home=tmp_path / "h")


def test_run_governed_rejects_unknown_via(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _hermetic_kernel_env(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="unknown --via"):
        run_governed(command=["true"], via="bogus", home=tmp_path / "h")


# ── adapter unit tests ─────────────────────────────────────────────────────────


def _ctx(tmp_path: Path, plugin_dir: Path | None = None) -> RunContext:
    return RunContext(
        home=tmp_path,
        passport_token="tok",
        passport_path=tmp_path / "active_mission.jwt",
        session_id="sess-1",
        mission_id="mission-1",
        trace_id="sess-1",
        proxy_url="http://127.0.0.1:9",
        api_token="api-tok",
        plugin_dir=plugin_dir,
    )


def test_select_adapter_routes_by_mode_and_autodetect() -> None:
    assert isinstance(select_adapter(["python", "agent.py"], "env"), EnvProxyAdapter)
    assert isinstance(select_adapter(["claude"], "auto"), ClaudeCodeAdapter)
    assert isinstance(select_adapter(["/usr/bin/claude"], "auto"), ClaudeCodeAdapter)
    assert isinstance(select_adapter(["grok"], "auto"), EnvProxyAdapter)
    assert isinstance(select_adapter(["x"], "intercept"), TransparentInterceptAdapter)


def test_env_adapter_exports_governance_contract(tmp_path: Path) -> None:
    env, command, notes = EnvProxyAdapter().prepare(_ctx(tmp_path), ["python", "a.py"], {})
    assert env["ARDUR_PROXY_URL"] == "http://127.0.0.1:9"
    assert env["ARDUR_API_TOKEN"] == "api-tok"
    assert env["ARDUR_SESSION_ID"] == "sess-1"
    assert env["VIBAP_HOME"] == str(tmp_path)
    assert env["ARDUR_MISSION_PASSPORT"] == str(tmp_path / "active_mission.jwt")
    assert command == ["python", "a.py"]
    assert notes


def test_claude_adapter_injects_plugin_dir_scoped(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugins" / "claude-code"
    plugin_dir.mkdir(parents=True)
    env, command, notes = ClaudeCodeAdapter().prepare(
        _ctx(tmp_path, plugin_dir=plugin_dir), ["claude", "-p", "do work"], {}
    )
    assert command == ["claude", "--plugin-dir", str(plugin_dir), "-p", "do work"]
    # The hook is pointed at this run via env, not a settings.json edit.
    assert env["VIBAP_HOME"] == str(tmp_path)
    assert any("no settings.json edit" in note for note in notes)


def test_claude_adapter_does_not_double_inject_plugin_dir(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "p"
    plugin_dir.mkdir()
    _env, command, _notes = ClaudeCodeAdapter().prepare(
        _ctx(tmp_path, plugin_dir=plugin_dir), ["claude", "--plugin-dir", "/other"], {}
    )
    assert command == ["claude", "--plugin-dir", "/other"]


def test_transparent_intercept_is_scaffold_only(tmp_path: Path) -> None:
    with pytest.raises(NotImplementedError, match="scaffolded only"):
        TransparentInterceptAdapter().prepare(_ctx(tmp_path), ["grok"], {})


# ── CLI dispatch ───────────────────────────────────────────────────────────────


def test_run_dispatch_legacy_vs_governance() -> None:
    """`ardur run` stays on the legacy hub path until a governance flag appears."""
    from vibap.cli import _run_has_governance_intent, build_parser

    parser = build_parser()
    legacy = parser.parse_args(["run", "--", "echo", "hi"])
    assert _run_has_governance_intent(legacy) is False

    for argv in (
        ["run", "--mission", "x", "--", "echo"],
        ["run", "--allowed-tools", "Read", "--", "echo"],
        ["run", "--max-tool-calls", "5", "--", "echo"],
        ["run", "--via", "env", "--", "echo"],
    ):
        args = parser.parse_args(argv)
        assert _run_has_governance_intent(args) is True, argv
