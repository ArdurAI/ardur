"""Tests for the OPA/Rego policy backend."""

from __future__ import annotations

import hashlib
import os
import subprocess

import pytest

from vibap.backends.opa import (
    BACKEND_NAME,
    OPAIntegrityError,
    OPAUnavailableError,
    OPABackend,
    _build_rego_input,
    _is_opa_available,
    _opa_binary_path,
    _verify_sha256,
)
from vibap.policy_backend import (
    clear_registry,
    compose_decisions,
    get_backend,
    register_backend,
)


# ── Skip marker for tests that need the opa binary ──────────────────
_opa_available = _is_opa_available()
needs_opa = pytest.mark.skipif(not _opa_available, reason="opa binary not on PATH")


def _spec(policy: str, **overrides) -> dict:
    base = {
        "backend": BACKEND_NAME,
        "label": "test",
        "policy_inline": policy,
        "policy_sha256": hashlib.sha256(policy.encode("utf-8")).hexdigest(),
        "data_inline": None,
    }
    base.update(overrides)
    return base


# ── Unit tests (no opa binary needed) ──────────────────────────────

class TestVerifySHA256:
    def test_matching_hash_passes(self):
        policy = "package ardur\nallow = true"
        digest = hashlib.sha256(policy.encode("utf-8")).hexdigest()
        _verify_sha256(policy, digest)

    def test_missing_hash_raises(self):
        with pytest.raises(OPAIntegrityError, match="missing"):
            _verify_sha256("package ardur", "")

    def test_mismatched_hash_raises(self):
        with pytest.raises(OPAIntegrityError, match="mismatch"):
            _verify_sha256("package ardur", "a" * 64)

    def test_case_insensitive_match(self):
        policy = "package ardur"
        digest = hashlib.sha256(policy.encode("utf-8")).hexdigest()
        _verify_sha256(policy, digest.upper())


class TestRegoInput:
    def test_builds_input_dict(self):
        result = _build_rego_input(
            tool_name="read_file",
            arguments={"path": "/tmp/x"},
            principal="agent-1",
            target="/tmp/x",
            context={"elapsed_s": 1.5},
        )
        assert result["tool_name"] == "read_file"
        assert result["arguments"]["path"] == "/tmp/x"
        assert result["principal"] == "agent-1"
        assert result["target"] == "/tmp/x"
        assert result["context"]["elapsed_s"] == 1.5


class TestOPABinary:
    def test_finds_binary_if_available(self):
        if not _opa_available:
            pytest.skip("opa not on PATH")
        path = _opa_binary_path()
        assert path is not None
        assert os.path.isabs(path)

    def test_raises_when_not_available(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda _: None)
        with pytest.raises(OPAUnavailableError, match="not found on PATH"):
            _opa_binary_path()


class TestBackendIntegrityEnforcement:
    def test_hash_mismatch_returns_deny(self):
        backend = OPABackend()
        policy = "package ardur\nallow = true"
        decision = backend.evaluate(
            tool_name="read",
            arguments={},
            principal="test",
            target="test",
            context={},
            policy_spec=_spec(policy, policy_sha256="b" * 64),
        )
        assert decision.decision == "Deny"
        assert "integrity" in decision.reasons[0]

    def test_empty_policy_abstains(self):
        backend = OPABackend()
        decision = backend.evaluate(
            tool_name="read",
            arguments={},
            principal="test",
            target="test",
            context={},
            policy_spec={"backend": BACKEND_NAME, "label": "test", "policy_inline": "", "policy_sha256": ""},
        )
        assert decision.decision == "Abstain"


# ── Integration tests (opa binary required) ─────────────────────────

@pytest.mark.skipif(not _opa_available, reason="opa binary not on PATH")
class TestOPAEval:
    def test_allow_policy(self):
        policy = "package ardur\n\nallow = true"
        backend = OPABackend()
        decision = backend.evaluate(
            tool_name="read_file",
            arguments={"path": "/tmp/x"},
            principal="agent-1",
            target="/tmp/x",
            context={},
            policy_spec=_spec(policy),
        )
        assert decision.decision == "Allow"

    def test_deny_policy(self):
        policy = "package ardur\n\ndefault allow = false"
        backend = OPABackend()
        decision = backend.evaluate(
            tool_name="read_file",
            arguments={"path": "/etc/passwd"},
            principal="agent-1",
            target="/etc/passwd",
            context={},
            policy_spec=_spec(policy),
        )
        assert decision.decision == "Deny"

    def test_conditional_policy(self):
        policy = """package ardur

default allow = false
allow if {
    input.tool_name == "read_file"
    not contains(input.arguments.path, "/etc/")
}"""
        backend = OPABackend()
        decision = backend.evaluate(
            tool_name="read_file",
            arguments={"path": "/tmp/data.txt"},
            principal="agent-1",
            target="/tmp/data.txt",
            context={},
            policy_spec=_spec(policy),
        )
        assert decision.decision == "Allow"

    def test_conditional_policy_blocks_etc(self):
        policy = """package ardur

default allow = false
allow if {
    input.tool_name == "read_file"
    not contains(input.arguments.path, "/etc/")
}"""
        backend = OPABackend()
        decision = backend.evaluate(
            tool_name="read_file",
            arguments={"path": "/etc/passwd"},
            principal="agent-1",
            target="/etc/passwd",
            context={},
            policy_spec=_spec(policy),
        )
        assert decision.decision in ("Deny", "Abstain")

    def test_context_aware_policy(self):
        policy = """package ardur

default allow = false
allow if {
    input.tool_name == "write_file"
    input.context.elapsed_s < 3600
}"""
        backend = OPABackend()
        decision = backend.evaluate(
            tool_name="write_file",
            arguments={"path": "/tmp/out.txt"},
            principal="agent-1",
            target="/tmp/out.txt",
            context={"elapsed_s": 100.0},
            policy_spec=_spec(policy),
        )
        assert decision.decision == "Allow"


@pytest.mark.skipif(not _opa_available, reason="opa binary not on PATH")
class TestOPABackendComposition:
    def test_compose_with_native_allows(self):
        clear_registry()
        try:
            from vibap.backends.native import NativeBackend

            native = NativeBackend()
            register_backend(native)
            register_backend(OPABackend())

            nb = OPABackend()
            policy = "package ardur\n\nallow = true"
            n_decision = native.evaluate(
                tool_name="read_file",
                arguments={"path": "/tmp/x"},
                principal="test",
                target="/tmp/x",
                context={},
                policy_spec={"backend": "native", "label": "native", "policy_inline": "", "policy_sha256": ""},
            )
            o_decision = nb.evaluate(
                tool_name="read_file",
                arguments={"path": "/tmp/x"},
                principal="test",
                target="/tmp/x",
                context={},
                policy_spec=_spec(policy),
            )
            verdict, denier = compose_decisions([n_decision, o_decision])
            assert verdict == "Allow"
            assert denier is None
        finally:
            clear_registry()
