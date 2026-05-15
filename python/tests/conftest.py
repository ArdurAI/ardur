"""Shared pytest fixtures for the VIBAP test suite.

Keys are generated once per session to avoid paying the ES256 keygen cost on
every test. Filesystem-dependent fixtures use tmp_path so tests never touch
the user's real ~/.vibap directory.
"""

from __future__ import annotations

collect_ignore = ["run_cloud_model_test.py", "run_all_models.py", "run_adversarial_suite.py", "run_advanced_adversarial.py", "test_ardur_overhead_ab.py"]

import os
import socket
from pathlib import Path
from typing import Any, Callable

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from vibap.passport import MissionPassport, generate_keypair, issue_passport
from vibap.proxy import GovernanceProxy


# v0.1 spec required-members helper (FIX-3 from S2 audit, 2026-04-28).
#
# The Mission Declaration loader unconditionally enforces that the seven
# audit-flagged required v0.1 members are present and well-shaped. Test
# factories that mint MDs (test_mission_binding, test_aat_adapter,
# test_http) merge this helper's output into ``extra_claims`` so the
# minted MD survives the load-time guard.
#
# Because the loader runs ``mission_is_revoked`` on the MD whenever a
# session is started, the helper's ``revocation_ref`` MUST resolve at
# fetch time. ``v01_default_status_url(mission_id)`` and
# ``v01_default_status_list_token(private_key, mission_id)`` produce a
# matching never-revoked status-list response that tests can splice into
# their ``_install_fetch_map`` calls.
#
# These defaults are deliberately benign / minimal — the goal is to
# satisfy the schema without inadvertently widening test policy. Tests
# that exercise specific values (e.g. revocation_ref index) can override.
def v01_default_status_url(mission_id: str) -> str:
    """Return the never-revoked status-list URL the helper points to.

    Predictable per ``mission_id`` so tests can include exactly one entry
    per mission in their fetch map.
    """
    # mission_id is typically an opaque URN; hash to keep URL paths sane.
    import hashlib
    digest = hashlib.sha256(mission_id.encode("utf-8")).hexdigest()[:16]
    return f"https://issuer.example/status/v01-default-{digest}.jwt"


def v01_default_status_list_token(private_key, mission_id: str) -> str:
    """Mint a never-revoked status-list JWT for the helper's default URL.

    Companion to :func:`v01_default_status_url`. Returns a status_list with
    a 1-bit list whose only relevant bit (idx=0) is unset — i.e. the
    mission referenced by the helper is reported as not revoked.
    """
    import base64
    import json
    import time
    import zlib

    import jwt

    raw = bytes([0])  # 1 byte covers idx=0; bit at idx=0 is 0 → not revoked.
    encoded = (
        base64.urlsafe_b64encode(zlib.compress(raw)).rstrip(b"=").decode("ascii")
    )
    now = int(time.time())
    claims = {
        "iss": "test-status-authority",
        "sub": "v01-default-status-list",
        "iat": now,
        "exp": now + 3600,
        "status_list": {"bits": 1, "lst": encoded},
    }
    return jwt.encode(claims, private_key, algorithm="ES256")


def v01_required_md_extras(
    *,
    mission_id: str,
    revocation_ref: str | None = None,
    conformance_profile: str = "Delegation-Core",
    receipt_level: str = "minimal",
    probing_rate_limit: int = 10,
    approval_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the v0.1 spec extras the always-on loader guard requires.

    ``approval_policy`` is intentionally NOT in the always-required set
    (see :mod:`vibap.mission` ``_REQUIRED_V01_MEMBERS``), so the helper
    omits it by default — including it would force every test tool call
    to carry an ``operator_id`` to satisfy the proxy's approval gate.
    Tests that exercise approval-rate-limit semantics
    (``test_approval_governance``) pass it explicitly.
    """
    extras: dict[str, Any] = {
        "mission_id": mission_id,
        "receipt_policy": {"level": receipt_level},
        "conformance_profile": conformance_profile,
        "tool_manifest_digest": "sha-256:" + ("a" * 64),
        "revocation_ref": (
            revocation_ref
            or f"{v01_default_status_url(mission_id)}#idx=0"
        ),
        "governed_memory_stores": [],
        "probing_rate_limit": probing_rate_limit,
    }
    if approval_policy is not None:
        extras["approval_policy"] = approval_policy
    return extras


@pytest.fixture(scope="session")
def session_keys_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Session-scoped keys directory so we only generate one keypair."""
    keys_dir = tmp_path_factory.mktemp("vibap-keys")
    # Materialize the keypair once; subsequent loads reuse the PEM files.
    generate_keypair(keys_dir=keys_dir)
    return keys_dir


@pytest.fixture(scope="session")
def keypair(session_keys_dir: Path) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    return generate_keypair(keys_dir=session_keys_dir)


@pytest.fixture(scope="session")
def private_key(keypair) -> ec.EllipticCurvePrivateKey:
    return keypair[0]


@pytest.fixture(scope="session")
def public_key(keypair) -> ec.EllipticCurvePublicKey:
    return keypair[1]


@pytest.fixture
def example_mission() -> MissionPassport:
    """A plain, non-delegating mission used for simple pass/fail flows.

    resource_scope is intentionally empty here so tests can use arbitrary
    arguments without having to match a glob. There's a separate
    ``scoped_mission`` fixture for resource-scope tests.
    """
    return MissionPassport(
        agent_id="agent-test",
        mission="run Q1 sales analysis",
        allowed_tools=["read_file", "write_file", "analyze"],
        forbidden_tools=["delete_file", "execute_shell"],
        resource_scope=[],
        max_tool_calls=5,
        max_duration_s=60,
        delegation_allowed=False,
        max_delegation_depth=0,
    )


@pytest.fixture
def delegating_mission() -> MissionPassport:
    """A mission that permits multi-level delegation for delegation tests."""
    return MissionPassport(
        agent_id="agent-parent",
        mission="coordinate research subtasks",
        allowed_tools=["read_file", "write_file", "analyze", "search"],
        forbidden_tools=["delete_file"],
        resource_scope=["/data/*"],
        max_tool_calls=100,
        max_duration_s=600,
        delegation_allowed=True,
        max_delegation_depth=3,
    )


@pytest.fixture
def issued_passport(example_mission, private_key) -> str:
    return issue_passport(example_mission, private_key, ttl_s=example_mission.max_duration_s)


@pytest.fixture
def issued_delegating_passport(delegating_mission, private_key) -> str:
    return issue_passport(delegating_mission, private_key, ttl_s=delegating_mission.max_duration_s)


@pytest.fixture
def proxy(tmp_path: Path, public_key, session_keys_dir: Path) -> GovernanceProxy:
    """A fresh GovernanceProxy rooted in tmp_path so tests never pollute $HOME."""
    return GovernanceProxy(
        log_path=tmp_path / "governance_log.jsonl",
        state_dir=tmp_path / "state",
        public_key=public_key,
        keys_dir=session_keys_dir,
    )


@pytest.fixture
def proxy_factory(tmp_path: Path, public_key, session_keys_dir: Path) -> Callable[[], GovernanceProxy]:
    """Create independent proxy instances sharing the session keypair."""
    counter = {"n": 0}

    def _make() -> GovernanceProxy:
        counter["n"] += 1
        n = counter["n"]
        return GovernanceProxy(
            log_path=tmp_path / f"log-{n}.jsonl",
            state_dir=tmp_path / f"state-{n}",
            public_key=public_key,
            keys_dir=session_keys_dir,
        )

    return _make


@pytest.fixture
def unused_tcp_port() -> int:
    """Allocate an ephemeral TCP port. Falls back to socket.bind(0) so we don't
    depend on pytest-asyncio being installed."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(autouse=True)
def _isolate_vibap_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point VIBAP_HOME at tmp_path for every test so nothing leaks into $HOME."""
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path / "vibap-home"))
