"""Organic governance integration tests — exercise Ardur through the same
code paths the examples/demos use, without needing live LLM providers.

These tests verify that the GovernanceProxy correctly allows/denies tool
calls, tracks events, enforces mission boundaries, and that the demo's
governed-tool wrappers work — exactly what the LangChain/LangGraph/AutoGen
demos exercise at runtime.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from vibap.passport import MissionPassport, issue_passport
from vibap.proxy import Decision, GovernanceProxy, GovernanceSession


def _issue_read_only_passport(keypair, agent_id="demo-agent", **overrides):
    private_key, _public_key = keypair
    kwargs = dict(
        agent_id=agent_id,
        mission="read-only review of a temporary project",
        allowed_tools=["read_file", "write_report"],
        forbidden_tools=["delete_file", "send_email"],
        resource_scope=[],
        max_tool_calls=10,
        max_duration_s=300,
        delegation_allowed=False,
    )
    kwargs.update(overrides)
    return issue_passport(MissionPassport(**kwargs), private_key)


# -- core governance engine tests -------------------------------------------


class TestGovernanceEngineThroughDemoPaths:
    """Test the GovernanceProxy exactly as the demos do — issue a
    passport, start a session, evaluate tool calls."""

    def test_allowed_tool_permitted(self, proxy, keypair):
        jwt_str = _issue_read_only_passport(keypair)
        session = proxy.start_session(jwt_str)
        decision, reason = proxy.evaluate_tool_call(
            session, "read_file", {"path": "notes.txt"}
        )
        assert decision == Decision.PERMIT, (
            f"expected PERMIT, got {decision}: {reason}"
        )
        assert len(session.events) >= 1
        assert session.tool_call_count == 1

    def test_forbidden_tool_denied(self, proxy, keypair):
        jwt_str = _issue_read_only_passport(keypair)
        session = proxy.start_session(jwt_str)
        decision, reason = proxy.evaluate_tool_call(
            session, "delete_file", {"path": "notes.txt"}
        )
        assert decision == Decision.DENY, (
            f"expected DENY, got {decision}: {reason}"
        )

    def test_unknown_tool_denied(self, proxy, keypair):
        jwt_str = _issue_read_only_passport(keypair)
        session = proxy.start_session(jwt_str)
        decision, _ = proxy.evaluate_tool_call(
            session, "execute_shell", {"command": "rm -rf /"}
        )
        assert decision == Decision.DENY

    def test_events_tracked_correctly(self, proxy, keypair):
        jwt_str = _issue_read_only_passport(keypair)
        session = proxy.start_session(jwt_str)

        proxy.evaluate_tool_call(session, "read_file", {"path": "a.txt"})
        proxy.evaluate_tool_call(
            session, "write_report", {"path": "b.md", "content": "ok"}
        )
        proxy.evaluate_tool_call(session, "delete_file", {"path": "x"})

        assert len(session.events) == 3
        # Events should have decisions matching the tool calls.
        decisions = [e.decision for e in session.events]
        assert Decision.PERMIT in decisions
        assert Decision.DENY in decisions

    def test_budget_exhausted_denies(self, proxy, keypair):
        jwt_str = _issue_read_only_passport(
            keypair, agent_id="budget-agent", max_tool_calls=3
        )
        session = proxy.start_session(jwt_str)
        for i in range(3):
            d, _ = proxy.evaluate_tool_call(
                session, "read_file", {"path": f"file{i}.txt"}
            )
            assert d == Decision.PERMIT, f"call {i} should be permitted"
        d, reason = proxy.evaluate_tool_call(
            session, "read_file", {"path": "overbudget.txt"}
        )
        assert d == Decision.DENY, (
            f"over-budget call should be denied: {reason}"
        )

    def test_session_end_produces_summary(self, proxy, keypair):
        jwt_str = _issue_read_only_passport(keypair)
        session = proxy.start_session(jwt_str)
        proxy.evaluate_tool_call(session, "read_file", {"path": "a.txt"})
        summary = proxy.end_session(session)
        assert isinstance(summary, dict)
        # Summary should reference the agent.
        assert summary.get("agent") == "demo-agent"

    def test_delegation_parent_child_independent(self, proxy, keypair):
        private_key, _public_key = keypair

        parent_jwt = _issue_read_only_passport(
            keypair,
            agent_id="parent",
            allowed_tools=["read_file", "write_report", "send_email"],
            delegation_allowed=True,
            max_delegation_depth=2,
            max_tool_calls=50,
        )
        parent_session = proxy.start_session(parent_jwt)

        child_jwt = _issue_read_only_passport(
            keypair,
            agent_id="child",
            allowed_tools=["read_file"],
            forbidden_tools=["delete_file", "send_email", "write_report"],
            delegation_allowed=False,
            max_tool_calls=5,
            max_duration_s=60,
        )
        child_session = proxy.start_session(child_jwt)

        # Child can read (allowed).
        d, _ = proxy.evaluate_tool_call(
            child_session, "read_file", {"path": "data.csv"}
        )
        assert d == Decision.PERMIT

        # Child cannot write (not in allowed list).
        d, reason = proxy.evaluate_tool_call(
            child_session, "write_report", {"path": "r.md", "content": "x"}
        )
        assert d == Decision.DENY

        # Parent can still write (independent session).
        d, _ = proxy.evaluate_tool_call(
            parent_session, "write_report", {"path": "r.md", "content": "x"}
        )
        assert d == Decision.PERMIT


# -- LangChain governed-tool integration ------------------------------------


class TestLangChainGovernedTools:
    """Exercise the governed-tool wrappers that the LangChain/LangGraph/
    AutoGen demos use at runtime. Needs langchain-core installed."""

    def test_governed_tools_permit_and_deny(self, proxy, keypair, tmp_path):
        pytest.importorskip("langchain_core")

        examples_dir = (
            Path(__file__).resolve().parents[2] / "examples" / "_shared"
        )
        sys.path.insert(0, str(examples_dir))
        try:
            import demo_scenes
        finally:
            sys.path.remove(str(examples_dir))

        jwt_str = _issue_read_only_passport(keypair)
        session = proxy.start_session(jwt_str)
        session_ref = [session]

        tools = demo_scenes.make_langchain_governed_tools(
            proxy, session_ref, tmp_path
        )
        tool_map = {t.name: t for t in tools}

        # read_file — allowed.
        result = tool_map["read_file"].func("notes.txt")
        assert "DENIED" not in result

        # delete_file — forbidden.
        result = tool_map["delete_file"].func("secret.txt")
        assert "DENIED by Ardur" in result

        # write_report — allowed.
        (tmp_path / "reports").mkdir(parents=True, exist_ok=True)
        result = tool_map["write_report"].func("rpt.md", "summary")
        assert "DENIED" not in result

        # Governed tools print decisions but only permitted calls increment
        # the session counter. We had 2 PERMITs + 1 DENY.
        assert session.tool_call_count == 2
        assert len(session.events) == 3


# -- demo_scenes standalone (no framework deps) -----------------------------


class TestDemoScenesGovernance:
    """demo_scenes.py functions that don't need any framework imports."""

    def test_provider_label_ollama_default(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_MODEL", "llama3")
        examples_dir = (
            Path(__file__).resolve().parents[2] / "examples" / "_shared"
        )
        sys.path.insert(0, str(examples_dir))
        try:
            import demo_scenes
        finally:
            sys.path.remove(str(examples_dir))
        label = demo_scenes.provider_label()
        assert "Ollama" in label
        assert "llama3" in label

    def test_provider_label_missing_raises(self, monkeypatch):
        monkeypatch.delenv("OLLAMA_MODEL", raising=False)
        monkeypatch.delenv("OPENAI_MODEL", raising=False)
        monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
        examples_dir = (
            Path(__file__).resolve().parents[2] / "examples" / "_shared"
        )
        sys.path.insert(0, str(examples_dir))
        try:
            import demo_scenes
        finally:
            sys.path.remove(str(examples_dir))
        with pytest.raises(RuntimeError, match="OLLAMA_MODEL"):
            demo_scenes.provider_label()

    def test_fetch_svid_fails_gracefully(self):
        """When SPIFFE is unavailable the demos should raise a clear error."""
        examples_dir = (
            Path(__file__).resolve().parents[2] / "examples" / "_shared"
        )
        sys.path.insert(0, str(examples_dir))
        try:
            import demo_scenes
        finally:
            sys.path.remove(str(examples_dir))
        # No SPIFFE agent running — raises an error from the SPIFFE SDK
        # (spiffe.errors.ArgumentError on macOS, potentially RuntimeError
        # on other platforms).
        with pytest.raises(BaseException):
            demo_scenes.fetch_svid_via_spiffe_python()
