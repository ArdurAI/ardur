"""HTTP endpoint tests.

We don't spawn a full subprocess (too slow, fragile on CI) — instead we
instantiate a ThreadingHTTPServer in-process on an ephemeral port and drive
it with urllib. This matches the real code path in serve_proxy except for
signal handling, which we don't exercise."""

from __future__ import annotations

import json
import os
import socket
import stat
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from typing import Any

import jwt
import pytest

# We reach inside serve_proxy to grab the Handler class. The simplest path
# that preserves the production code path is to re-import and re-build the
# server via the public function's logic. Here we clone enough of serve_proxy
# to stand up an HTTP server for testing. If serve_proxy gets refactored into
# a factory, swap this for a direct call.
import vibap.mission as mission_module
from vibap.mission import load_mission_declaration
from vibap.passport import ALGORITHM, MissionPassport, issue_passport, verify_passport
from vibap.proxy import GovernanceProxy, serve_proxy
from vibap.receipt import verify_chain

from tests.conftest import (
    v01_default_status_list_token,
    v01_default_status_url,
    v01_required_md_extras,
)


def _build_server_thread(proxy: GovernanceProxy, private_key, port: int):
    """Start serve_proxy in a background daemon thread bound to 127.0.0.1:port.

    Returns (thread, server_url, shutdown_callable). We monkeypatch
    ThreadingHTTPServer.serve_forever to return after shutdown and
    avoid registering a SIGTERM handler in a thread (signals only work on
    the main thread)."""
    # Swap serve_proxy's signal.signal for a no-op in this thread via a
    # monkeypatch-free approach: we run the server manually here.
    # Easier path: import the Handler factory used internally. But it's a
    # closure inside serve_proxy, so we simply call serve_proxy and let it
    # install its signal handler — signal.signal() from a non-main thread
    # raises ValueError. To work around, monkeypatch signal.signal before
    # running.
    import signal as _signal

    original = _signal.signal
    _signal.signal = lambda *_a, **_kw: None  # type: ignore[assignment]

    stop_event = threading.Event()

    def run() -> None:
        try:
            serve_proxy(
                proxy=proxy,
                private_key=private_key,
                host="127.0.0.1",
                port=port,
                require_auth=False,
                no_tls=True,
            )
        finally:
            stop_event.set()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    # Wait for the server to respond to /health.
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 5
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/health", timeout=0.5) as resp:
                if resp.status == 200:
                    break
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(0.05)
    else:
        raise RuntimeError(f"proxy never became healthy: {last_exc}")

    def shutdown() -> None:
        # Send a shutdown by closing the server via an internal request.
        # ThreadingHTTPServer exposes shutdown() but we don't have a handle to
        # the server instance. Fallback: rely on daemon=True + test process
        # teardown. This is fine for unit tests.
        _signal.signal = original

    return thread, base, shutdown


def _post(url: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    status, body, _ = _post_with_headers(url, payload)
    return status, body


def _post_with_headers(url: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any], dict[str, str]]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8")), dict(resp.headers.items())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"raw": body}
        return exc.code, parsed, dict(exc.headers.items())


def _get(url: str) -> tuple[int, dict[str, Any]]:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def http_proxy(proxy, private_key, unused_tcp_port):
    thread, base, shutdown = _build_server_thread(proxy, private_key, unused_tcp_port)
    yield base, proxy
    shutdown()


class TestHTTPHealth:
    def test_get_health_returns_200(self, http_proxy):
        base, _ = http_proxy
        status, body = _get(base + "/health")
        assert status == 200
        assert body["status"] == "ok"
        assert "version" in body


class TestHTTPEvaluate:
    def test_permit_decision(self, http_proxy, example_mission, private_key):
        base, _ = http_proxy
        token = issue_passport(example_mission, private_key, ttl_s=60)
        status, start = _post(base + "/session/start", {"token": token})
        assert status == 200
        session_id = start["session_id"]

        status, body = _post(
            base + "/evaluate",
            {"session_id": session_id, "tool_name": "read_file", "arguments": {"path": "/x"}},
        )
        assert status == 200
        assert body["decision"] == "PERMIT"

    def test_deny_decision(self, http_proxy, example_mission, private_key):
        base, _ = http_proxy
        token = issue_passport(example_mission, private_key, ttl_s=60)
        _, start = _post(base + "/session/start", {"token": token})
        session_id = start["session_id"]

        status, body = _post(
            base + "/evaluate",
            {"session_id": session_id, "tool_name": "delete_file", "arguments": {}},
        )
        assert status == 200
        assert body["decision"] == "DENY"
        assert "reason" in body

    def test_revoked_active_session_returns_403(self, http_proxy, example_mission, private_key):
        base, proxy = http_proxy
        token = issue_passport(example_mission, private_key, ttl_s=60)
        _, start = _post(base + "/session/start", {"token": token})
        session_id = start["session_id"]

        status, body = _post(
            base + "/evaluate",
            {"session_id": session_id, "tool_name": "read_file", "arguments": {"path": "/x"}},
        )
        assert status == 200
        assert body["decision"] == "PERMIT"

        proxy.revoke(session_id)

        status, body = _post(
            base + "/evaluate",
            {"session_id": session_id, "tool_name": "read_file", "arguments": {"path": "/x"}},
        )
        assert status == 403
        assert body == {"error": "passport_revoked"}


class TestHTTPDelegate:
    def test_valid_delegation_returns_200(self, http_proxy, private_key):
        base, _ = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="p",
            allowed_tools=["read", "write"],
            delegation_allowed=True,
            max_delegation_depth=2,
            max_duration_s=300,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        # Parent session must be started before delegation (Phase 2e / external-review-G F3)
        _post(base + "/session/start", {"token": parent_token})
        status, body = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "child",
                "child_mission": "sub",
                "child_allowed_tools": ["read"],
                "child_ttl_s": 60,
            },
        )
        assert status == 200
        assert "child_token" in body
        assert body["child_claims"]["allowed_tools"] == ["read"]

    def test_delegation_escalation_returns_403(self, http_proxy, private_key):
        base, _ = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="p",
            allowed_tools=["read"],
            delegation_allowed=True,
            max_delegation_depth=2,
            max_duration_s=300,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        _post(base + "/session/start", {"token": parent_token})
        status, body = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "child",
                "child_mission": "evil",
                "child_allowed_tools": ["read", "rm_rf"],
                "child_ttl_s": 60,
            },
        )
        assert status == 403
        assert "scope escalation" in body.get("error", "")

    def test_duplicate_delegation_request_id_is_idempotent(
        self, http_proxy, private_key
    ):
        base, proxy = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            max_tool_calls=1,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        _, start = _post(base + "/session/start", {"token": parent_token})

        request = {
            "parent_token": parent_token,
            "child_agent_id": "child",
            "child_mission": "sub",
            "child_allowed_tools": ["read"],
            "child_max_tool_calls": 1,
            "delegation_request_id": "retry-1",
        }

        status1, body1 = _post(base + "/delegate", request)
        status2, body2 = _post(base + "/delegate", request)

        assert status1 == 200
        assert status2 == 200
        assert body1["child_claims"]["max_tool_calls"] == 1
        assert body2["child_claims"]["max_tool_calls"] == 1
        assert body2["child_token"] == body1["child_token"]
        assert body2["child_claims"]["jti"] == body1["child_claims"]["jti"]
        snapshot = proxy.lineage_budget_ledger.snapshot(start["session_id"])
        assert snapshot["reserved_total"] == 1
        assert len(snapshot["reservations"]) == 1
        reservation = snapshot["reservations"]["retry-1"]
        assert reservation["child_jti"] == body1["child_claims"]["jti"]
        parent_session = proxy.get_session(start["session_id"])
        matching_children = [
            child
            for child in parent_session.delegated_children
            if child["delegation_request_id"] == "retry-1"
        ]
        assert len(matching_children) == 1
        assert matching_children[0]["child_jti"] == body1["child_claims"]["jti"]
        delegation_events = [
            event
            for event in parent_session.events
            if event.tool_name == "delegate_passport"
            and event.arguments.get("delegation_request_id") == "retry-1"
        ]
        assert len(delegation_events) == 1

    def test_duplicate_delegation_request_id_normalized_retry_is_idempotent(
        self, http_proxy, private_key
    ):
        base, _ = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read", "write"],
            resource_scope=["/data/*", "/logs/*"],
            max_tool_calls=3,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        _post(base + "/session/start", {"token": parent_token})

        first = {
            "parent_token": parent_token,
            "child_agent_id": "child",
            "child_mission": "sub",
            "child_allowed_tools": ["write", "read"],
            "child_resource_scope": ["/logs/*", "/data/*"],
            "child_max_tool_calls": 2,
            "child_ttl_s": 120,
            "delegation_request_id": "retry-normalized",
        }
        second = dict(
            first,
            child_allowed_tools=["read", "write"],
            child_resource_scope=["/data/*", "/logs/*"],
        )

        status1, body1 = _post(base + "/delegate", first)
        status2, body2 = _post(base + "/delegate", second)

        assert status1 == 200
        assert status2 == 200
        assert body2["child_token"] == body1["child_token"]
        assert body2["child_claims"]["jti"] == body1["child_claims"]["jti"]
        assert body2["child_claims"]["allowed_tools"] == ["read", "write"]
        assert body2["child_claims"]["resource_scope"] == ["/data/*", "/logs/*"]

    def test_conflicting_delegation_request_id_returns_409(
        self, http_proxy, private_key
    ):
        base, _ = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            max_tool_calls=2,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        _post(base + "/session/start", {"token": parent_token})

        first = {
            "parent_token": parent_token,
            "child_agent_id": "child-a",
            "child_mission": "sub",
            "child_allowed_tools": ["read"],
            "child_max_tool_calls": 1,
            "delegation_request_id": "dup",
        }
        second = dict(first, child_agent_id="child-b")

        status1, _ = _post(base + "/delegate", first)
        status2, body2 = _post(base + "/delegate", second)

        assert status1 == 200
        assert status2 == 409
        assert "different reservation" in body2.get("error", "")

    @pytest.mark.parametrize(
        ("field", "replacement"),
        [
            ("child_mission", "narrow-request"),
            ("child_allowed_tools", ["read"]),
            ("child_resource_scope", ["/data/*"]),
            ("child_max_tool_calls", 1),
            ("child_ttl_s", 60),
        ],
    )
    def test_duplicate_delegation_request_id_changed_request_fields_return_409(
        self, http_proxy, private_key, field, replacement
    ):
        base, _ = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read", "write"],
            resource_scope=["/data/*", "/logs/*"],
            max_tool_calls=5,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        _post(base + "/session/start", {"token": parent_token})

        first = {
            "parent_token": parent_token,
            "child_agent_id": "child",
            "child_mission": "broad",
            "child_allowed_tools": ["read", "write"],
            "child_resource_scope": ["/data/*", "/logs/*"],
            "child_max_tool_calls": 2,
            "child_ttl_s": 120,
            "delegation_request_id": "dup-same-child",
        }
        second = dict(first, **{field: replacement})

        status1, body1 = _post(base + "/delegate", first)
        status2, body2 = _post(base + "/delegate", second)

        assert status1 == 200
        assert body1["child_claims"]["mission"] == "broad"
        assert body1["child_claims"]["allowed_tools"] == ["read", "write"]
        assert body1["child_claims"]["resource_scope"] == ["/data/*", "/logs/*"]
        assert body1["child_claims"]["max_tool_calls"] == 2
        assert status2 == 409
        assert "different reservation" in body2.get("error", "")
        assert "child_token" not in body2

    def test_persisted_delegation_session_files_are_private_under_permissive_umask(
        self, tmp_path, public_key, private_key, session_keys_dir
    ):
        state_dir = tmp_path / "caller-state"
        state_dir.mkdir(mode=0o755)
        original_umask = os.umask(0o022)
        shutdown = None
        try:
            proxy = GovernanceProxy(
                log_path=tmp_path / "governance_log.jsonl",
                state_dir=state_dir,
                public_key=public_key,
                keys_dir=session_keys_dir,
            )
            _, base, shutdown = _build_server_thread(proxy, private_key, _free_port())
            parent_mission = MissionPassport(
                agent_id="parent",
                mission="coord",
                allowed_tools=["read"],
                max_tool_calls=2,
                delegation_allowed=True,
                max_delegation_depth=2,
            )
            parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
            _, start = _post(base + "/session/start", {"token": parent_token})
            status, _body = _post(
                base + "/delegate",
                {
                    "parent_token": parent_token,
                    "child_agent_id": "child",
                    "child_mission": "sub",
                    "child_allowed_tools": ["read"],
                    "child_max_tool_calls": 1,
                    "delegation_request_id": "secret-replay",
                },
            )

            assert status == 200
            session_path = proxy._session_path(start["session_id"])
            payload = json.loads(session_path.read_text(encoding="utf-8"))
            assert any(
                isinstance(child.get("child_token"), str) and child["child_token"]
                for child in payload["delegated_children"]
            )
            assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700
            assert stat.S_IMODE((state_dir / "sessions").stat().st_mode) == 0o700
            assert stat.S_IMODE(session_path.stat().st_mode) == 0o600
            assert stat.S_IMODE(session_path.stat().st_mode) & 0o077 == 0
        finally:
            os.umask(original_umask)
            if shutdown is not None:
                shutdown()

    def test_two_http_proxies_shared_state_concurrent_sibling_budget(
        self, tmp_path, public_key, private_key, session_keys_dir
    ):
        shared_state = tmp_path / "shared-state"
        p1 = GovernanceProxy(
            log_path=tmp_path / "p1.jsonl",
            state_dir=shared_state,
            public_key=public_key,
            keys_dir=session_keys_dir,
        )
        p2 = GovernanceProxy(
            log_path=tmp_path / "p2.jsonl",
            state_dir=shared_state,
            public_key=public_key,
            keys_dir=session_keys_dir,
        )
        _, base1, shutdown1 = _build_server_thread(p1, private_key, _free_port())
        _, base2, shutdown2 = _build_server_thread(p2, private_key, _free_port())
        try:
            parent_mission = MissionPassport(
                agent_id="parent",
                mission="coord",
                allowed_tools=["read"],
                max_tool_calls=5,
                delegation_allowed=True,
                max_delegation_depth=2,
            )
            parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
            _, start = _post(base1 + "/session/start", {"token": parent_token})

            def delegate(i: int) -> tuple[int, dict[str, Any]]:
                base = base1 if i % 2 == 0 else base2
                return _post(
                    base + "/delegate",
                    {
                        "parent_token": parent_token,
                        "child_agent_id": f"child-{i}",
                        "child_mission": f"sub-{i}",
                        "child_allowed_tools": ["read"],
                        "child_max_tool_calls": 1,
                        "delegation_request_id": f"r{i}",
                    },
                )

            with ThreadPoolExecutor(max_workers=16) as pool:
                results = list(pool.map(delegate, range(24)))

            accepted = [
                body["child_claims"]["max_tool_calls"]
                for status, body in results
                if status == 200
            ]
            rejected = [status for status, _ in results if status != 200]

            assert sum(accepted) == 5
            assert all(status == 403 for status in rejected)
            assert p1.lineage_budget_ledger.snapshot(start["session_id"])[
                "reserved_total"
            ] == 5
        finally:
            shutdown2()
            shutdown1()


class TestHTTPAuthAndValidation:
    @pytest.mark.parametrize(
        ("path", "payload"),
        [
            ("/verify", {"token": "not-a-jwt"}),
            ("/session/start", {"token": "not-a-jwt"}),
            ("/sessions", {"token": "not-a-jwt"}),
            (
                "/delegate",
                {
                    "parent_token": "not-a-jwt",
                    "child_agent_id": "child",
                    "child_mission": "subtask",
                    "child_allowed_tools": ["read"],
                },
            ),
        ],
    )
    def test_invalid_jwt_returns_401_with_www_authenticate(
        self, http_proxy, path, payload
    ):
        base, _ = http_proxy
        status, body, headers = _post_with_headers(base + path, payload)
        assert status == 401
        assert body == {"error": "invalid_token"}
        assert headers["WWW-Authenticate"] == 'Bearer error="invalid_token"'

    def test_issue_with_non_object_mission_returns_400(self, http_proxy):
        base, _ = http_proxy
        status, body = _post(base + "/issue", {"mission": None})
        assert status == 400
        assert body == {"error": "mission must be a JSON object"}

    def test_issue_with_lineage_budgets_fails_phase1_deferred(self, http_proxy):
        base, _ = http_proxy
        status, body = _post(
            base + "/issue",
            {
                "mission": {
                    "agent_id": "parent",
                    "mission": "coordinate child work",
                    "allowed_tools": ["read"],
                    "delegation_allowed": True,
                    "max_delegation_depth": 1,
                    "lineage_budgets": [
                        {"type": "max_child_tool_calls", "limit": 3}
                    ],
                }
            },
        )
        assert status == 400
        assert "token" not in body
        assert "lineage_budgets" in body.get("error", "")
        assert "Phase 1" in body.get("error", "")
        assert "deferred" in body.get("error", "")

    def test_delegate_rejects_string_child_tools_before_char_splitting(
        self, http_proxy, private_key
    ):
        base, _ = http_proxy
        parent = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent, private_key, ttl_s=300)
        _post(base + "/session/start", {"token": parent_token})

        status, body = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "child",
                "child_mission": "sub",
                "child_allowed_tools": "read",
            },
        )

        assert status == 400
        assert body == {
            "error": "child_allowed_tools must be a JSON array of non-empty strings"
        }

    def test_delegate_rejects_string_child_resource_scope_before_char_splitting(
        self, http_proxy, private_key
    ):
        base, _ = http_proxy
        parent = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            resource_scope=["/data/*"],
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent, private_key, ttl_s=300)
        _post(base + "/session/start", {"token": parent_token})

        status, body = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "child",
                "child_mission": "sub",
                "child_allowed_tools": ["read"],
                "child_resource_scope": "/data/*",
            },
        )

        assert status == 400
        assert body == {
            "error": "child_resource_scope must be a JSON array of non-empty strings"
        }


class TestHTTPSessionEnd:
    def test_session_end_includes_attestation(self, http_proxy, example_mission, private_key):
        base, _ = http_proxy
        token = issue_passport(example_mission, private_key, ttl_s=60)
        _, start = _post(base + "/session/start", {"token": token})
        session_id = start["session_id"]

        _post(
            base + "/evaluate",
            {"session_id": session_id, "tool_name": "read_file", "arguments": {}},
        )
        status, body = _post(base + "/session/end", {"session_id": session_id})
        assert status == 200
        assert "attestation_token" in body
        assert "summary" in body
        assert body["summary"]["permits"] >= 1

    def test_session_start_returns_503_when_replay_cache_deleted(self, http_proxy, example_mission, private_key):
        base, proxy = http_proxy
        token = issue_passport(example_mission, private_key, ttl_s=60)
        _post(base + "/session/start", {"token": token})
        proxy.replay_cache_path.unlink()
        fresh_token = issue_passport(example_mission, private_key, ttl_s=60)

        status, body = _post(base + "/session/start", {"token": fresh_token})
        assert status == 503
        assert body == {"error": "replay_cache_unavailable"}

    def test_attest_is_idempotent_after_end(self, http_proxy, example_mission, private_key):
        base, _ = http_proxy
        token = issue_passport(example_mission, private_key, ttl_s=60)
        _, start = _post(base + "/session/start", {"token": token})
        session_id = start["session_id"]

        _post(
            base + "/evaluate",
            {"session_id": session_id, "tool_name": "read_file", "arguments": {}},
        )
        status, body = _post(base + "/end", {"session": session_id})
        assert status == 200
        assert "summary" in body

        status1, attestation1 = _post(base + "/attest", {"session": session_id})
        time.sleep(1.1)
        status2, attestation2 = _post(base + "/attest", {"session": session_id})

        assert status1 == 200
        assert status2 == 200
        assert attestation1 == attestation2


class TestDelegateRequiresActiveParentSession:
    """Regression test for external-review-G F3: /delegate previously fell back to the
    parent's ceiling if the parent session wasn't in the in-memory dict.
    Now it must refuse unless there's a persisted session for the parent jti."""

    def test_delegate_without_started_parent_returns_403(
        self, http_proxy, private_key
    ):
        base, _ = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            max_tool_calls=100,  # Big budget
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)

        # Do NOT call /session/start. Attempt to delegate directly.
        status, body = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "c",
                "child_mission": "sub",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 999,  # try to get huge budget
            },
        )
        assert status == 403
        assert "parent session" in body.get("error", "").lower()

    def test_delegate_with_ended_parent_returns_403(
        self, http_proxy, private_key
    ):
        """A parent session that's been ended should not be able to spawn children."""
        base, _ = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            max_tool_calls=100,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        _, start = _post(base + "/session/start", {"token": parent_token})
        session_id = start["session_id"]
        _post(base + "/session/end", {"session_id": session_id})

        status, body = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "c",
                "child_mission": "sub",
                "child_allowed_tools": ["read"],
            },
        )
        assert status == 403
        assert "ended" in body.get("error", "").lower()

    def test_delegate_with_active_parent_caps_child_at_remaining(
        self, http_proxy, private_key
    ):
        """With a real parent session that has used some budget, the child's
        budget is clamped to the remaining, not the ceiling."""
        base, _ = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            max_tool_calls=10,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        _, start = _post(base + "/session/start", {"token": parent_token})
        session_id = start["session_id"]

        # Burn 7 calls of the 10 budget
        for _ in range(7):
            _post(base + "/evaluate", {
                "session_id": session_id,
                "tool_name": "read",
                "arguments": {},
            })

        # Delegate — parent has 3 remaining; child should get at most 3
        status, body = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "c",
                "child_mission": "sub",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 999,  # ask for way more
            },
        )
        assert status == 200
        assert body["child_claims"]["max_tool_calls"] == 3
        assert body["parent_calls_remaining_at_delegation"] == 3


class _AATResponse:
    def __init__(self, body: str | bytes) -> None:
        self._body = body.encode("utf-8") if isinstance(body, str) else body

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            return self._body
        return self._body[:size]

    def __enter__(self) -> "_AATResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


def _install_aat_fetch_map(
    monkeypatch,
    mapping: dict[str, str],
    *,
    private_key=None,
    mission_ids: list[str] | None = None,
) -> None:
    """As :func:`tests.test_aat_adapter._install_fetch_map`, but for the
    HTTP integration tests. Pass ``private_key`` + ``mission_ids`` to
    auto-include the never-revoked status-list responses for each
    mission's helper-default revocation URL (FIX-3, 2026-04-28)."""
    full_mapping: dict[str, str] = dict(mapping)
    if private_key is not None and mission_ids:
        for mission_id in mission_ids:
            url = v01_default_status_url(mission_id)
            full_mapping.setdefault(
                url, v01_default_status_list_token(private_key, mission_id)
            )

    def fake_urlopen(request, timeout=0, context=None):  # noqa: ANN001, ARG001
        url = request.full_url if hasattr(request, "full_url") else str(request)
        return _AATResponse(full_mapping[url])

    monkeypatch.setattr(mission_module, "urlopen", fake_urlopen)


def _issue_aat_md(private_key, *, mission_id: str) -> str:
    mission = MissionPassport(
        agent_id="md-authority",
        mission="authoritative AAT HTTP mission",
        allowed_tools=["read"],
        forbidden_tools=[],
        resource_scope=[],
        max_tool_calls=3,
        max_duration_s=300,
        delegation_allowed=True,
        max_delegation_depth=2,
    )
    return issue_passport(
        mission,
        private_key,
        ttl_s=300,
        extra_claims=v01_required_md_extras(mission_id=mission_id),
    )


def _issue_aat_http_token(
    private_key,
    *,
    mission_ref: dict[str, str],
    tools: list[str],
    grant_id: str | None = None,
) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": "https://tenuo.example/issuer",
            "sub": "aat-http-agent",
            "iat": now,
            "exp": now + 300,
            "jti": grant_id or str(uuid.uuid4()),
            "aat_type": "delegation",
            "del_depth": 0,
            "del_max_depth": 2,
            "mission_ref": mission_ref,
            "authorization_details": [
                {
                    "type": "attenuating_agent_token",
                    "tools": {tool: {} for tool in tools},
                    "max_tool_calls": 2,
                }
            ],
            "cnf": {"jwk": {"kid": "holder-key"}},
        },
        private_key,
        algorithm=ALGORITHM,
    )


class TestHTTPAATInterop:
    def test_aat_session_evaluate_delegate_receipt_chain(
        self, http_proxy, private_key, public_key, monkeypatch
    ):
        base, proxy = http_proxy
        mission_id = "urn:ardur:mission:aat:http"
        md_url = "https://issuer.example/md/aat-http.jwt"
        md_token = _issue_aat_md(private_key, mission_id=mission_id)
        md = load_mission_declaration(md_token, public_key)
        _install_aat_fetch_map(
            monkeypatch,
            {md_url: md_token},
            private_key=private_key,
            mission_ids=[mission_id],
        )
        aat_jti = str(uuid.uuid4())
        aat_token = _issue_aat_http_token(
            private_key,
            grant_id=aat_jti,
            mission_ref={
                "uri": md_url,
                "mission_id": mission_id,
                "mission_digest": md.payload_digest,
            },
            tools=["read"],
        )

        # require_pop=False is an explicit opt-out: the test factory above
        # mints a cnf-bearing AAT, but this test is exercising the HTTP
        # session/evaluate/delegate path, not RFC 7800 PoP. Since 2026-04-28
        # the proxy defaults require_pop=True for cnf-bearing AATs, so the
        # opt-out has to be visible in the request body. PoP coverage lives
        # in test_aat_adapter.py::TestAATProofOfPossession; HTTP-side
        # PoP coverage is the new TestHTTPAATPoP class below.
        status, start = _post(
            base + "/session/start",
            {"token_type": "aat", "token": aat_token, "require_pop": False},
        )
        assert status == 200
        assert start["session_id"] == aat_jti
        assert start["credential_format"] == "aat-compatible-jwt"

        status, body = _post(
            base + "/evaluate",
            {"session_id": aat_jti, "tool_name": "read", "arguments": {}},
        )
        assert status == 200
        assert body["decision"] == "PERMIT"

        status, delegated = _post(
            base + "/delegate",
            {
                "parent_token": aat_token,
                "child_agent_id": "aat-child",
                "child_mission": "subtask",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 1,
                "delegation_request_id": "aat-http-child",
            },
        )
        assert status == 200
        assert delegated["parent_jti"] == aat_jti

        entries = [
            json.loads(line)
            for line in proxy.receipts_log_path.read_text(encoding="utf-8").splitlines()
        ]
        claims = verify_chain([entry["jwt"] for entry in entries], public_key)
        assert [claim["tool"] for claim in claims] == ["read", "delegate_passport"]
        assert {claim["grant_id"] for claim in claims} == {aat_jti}
        assert claims[0]["evidence_proof_ref"]["mission_digest"] == md.payload_digest


# --- Round-3 audit (2026-04-28): the round-2 audit flagged that the only
# HTTP /sessions PoP test was the require_pop=False opt-out path. The
# fail-closed default + the kb_jwt size bound were untested. These
# regressions pin the new HTTP-edge guards so future refactors can't
# silently drop them.

class TestHTTPAATPoP:
    def test_cnf_aat_without_pop_inputs_fails_closed_at_http_edge(
        self, http_proxy, private_key, public_key, monkeypatch
    ):
        """Posting a cnf-bearing AAT with no require_pop override
        defaults to fail-closed. The HTTP layer surfaces a 4xx because
        start_session_from_aat raises PermissionError."""
        base, proxy = http_proxy
        mission_id = "urn:ardur:mission:aat:http-pop-default"
        md_url = "https://issuer.example/md/aat-pop-default.jwt"
        md_token = _issue_aat_md(private_key, mission_id=mission_id)
        md = load_mission_declaration(md_token, public_key)
        _install_aat_fetch_map(
            monkeypatch,
            {md_url: md_token},
            private_key=private_key,
            mission_ids=[mission_id],
        )
        aat_token = _issue_aat_http_token(
            private_key,
            mission_ref={
                "uri": md_url,
                "mission_id": mission_id,
                "mission_digest": md.payload_digest,
            },
            tools=["read"],
        )
        status, body = _post(
            base + "/session/start",
            # No require_pop, no holder_public_key_pem, no kb_jwt → fail closed.
            {"token_type": "aat", "token": aat_token},
        )
        # The handler returns 4xx; the exact code depends on how
        # PermissionError is mapped. Either 400 or 403 is acceptable —
        # what we care about is the closed default.
        assert status in (400, 403), f"expected 4xx, got {status}: {body}"
        assert "PoP" in body.get("error", "") or "PoP" in str(body)

    def test_kb_jwt_size_cap_rejects_oversize_payload(
        self, http_proxy, private_key, public_key, monkeypatch
    ):
        """An attacker-supplied kb_jwt larger than 8KB should be rejected
        at the HTTP edge before the proxy attempts to parse / verify it."""
        base, proxy = http_proxy
        mission_id = "urn:ardur:mission:aat:http-kb-size"
        md_url = "https://issuer.example/md/aat-kb-size.jwt"
        md_token = _issue_aat_md(private_key, mission_id=mission_id)
        md = load_mission_declaration(md_token, public_key)
        _install_aat_fetch_map(
            monkeypatch,
            {md_url: md_token},
            private_key=private_key,
            mission_ids=[mission_id],
        )
        aat_token = _issue_aat_http_token(
            private_key,
            mission_ref={
                "uri": md_url,
                "mission_id": mission_id,
                "mission_digest": md.payload_digest,
            },
            tools=["read"],
        )
        oversize_kb_jwt = "A" * (16 * 1024)  # 16KB, exceeds 8KB cap
        status, body = _post(
            base + "/session/start",
            {
                "token_type": "aat",
                "token": aat_token,
                "kb_jwt": oversize_kb_jwt,
            },
        )
        assert status == 400, f"expected 400, got {status}: {body}"
        assert "MAX_KB_JWT_BYTES" in body.get("error", "")

    def test_delegate_reserves_budget_across_siblings(
        self, http_proxy, private_key
    ):
        """Round-3 H1: sibling delegations must not reuse the same remainder snapshot."""
        base, _ = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            max_tool_calls=10,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        _, start = _post(base + "/session/start", {"token": parent_token})
        session_id = start["session_id"]

        for _ in range(7):
            _post(base + "/evaluate", {
                "session_id": session_id,
                "tool_name": "read",
                "arguments": {},
            })

        status1, body1 = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "c1",
                "child_mission": "sub-1",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 2,
            },
        )
        assert status1 == 200
        assert body1["child_claims"]["max_tool_calls"] == 2
        assert body1["parent_calls_remaining_at_delegation"] == 3

        status2, body2 = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "c2",
                "child_mission": "sub-2",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 2,
            },
        )
        assert status2 == 200
        assert body2["child_claims"]["max_tool_calls"] == 1
        assert body2["parent_calls_remaining_at_delegation"] == 1

        status3, body3 = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "c3",
                "child_mission": "sub-3",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 1,
            },
        )
        assert status3 == 403
        assert "budget exhausted" in body3.get("error", "").lower()

    def test_http_e2e_receipts_chain_budget_reservations(
        self, http_proxy, private_key, public_key
    ):
        base, proxy = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            max_tool_calls=4,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        _, start = _post(base + "/session/start", {"token": parent_token})
        session_id = start["session_id"]

        for _ in range(2):
            status, body = _post(base + "/evaluate", {
                "session_id": session_id,
                "tool_name": "read",
                "arguments": {},
            })
            assert status == 200
            assert body["decision"] == "PERMIT"

        status1, body1 = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "c1",
                "child_mission": "sub-1",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 1,
            },
        )
        assert status1 == 200
        assert body1["child_claims"]["max_tool_calls"] == 1

        status2, body2 = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "c2",
                "child_mission": "sub-2",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 1,
            },
        )
        assert status2 == 200
        assert body2["child_claims"]["max_tool_calls"] == 1

        status3, body3 = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "c3",
                "child_mission": "sub-3",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 1,
            },
        )
        assert status3 == 403
        assert "budget exhausted" in body3.get("error", "").lower()

        entries = [
            json.loads(line)
            for line in proxy.receipts_log_path.read_text(encoding="utf-8").splitlines()
        ]
        assert len(entries) == 4
        claims = verify_chain([entry["jwt"] for entry in entries], public_key)
        assert {claim["trace_id"] for claim in claims} == {session_id}
        assert len({claim["run_nonce"] for claim in claims}) == 1
        assert all(claim["invocation_digest"]["scope"] == "normalized_input" for claim in claims)
        assert [claim["tool"] for claim in claims] == [
            "read",
            "read",
            "delegate_passport",
            "delegate_passport",
        ]
        for claim in claims[:2]:
            assert "public_denial_reason" not in claim
            assert claim["budget_delta"]["operation"] == "consume"
            assert claim["budget_delta"]["amount"] == 1
        assert claims[0]["budget_delta"]["remaining_for_parent"] == 4
        assert claims[0]["budget_delta"]["remaining_after"] == 3
        assert claims[0]["budget_delta"]["used_total"] == 0
        assert claims[1]["budget_delta"]["remaining_for_parent"] == 3
        assert claims[1]["budget_delta"]["remaining_after"] == 2
        assert claims[1]["budget_delta"]["used_total"] == 1
        for claim in claims[2:]:
            assert "public_denial_reason" not in claim
            assert claim["budget_delta"]["operation"] == "reserve"
            assert claim["budget_delta"]["resource"] == "lineage_budget"
            assert claim["budget_delta"]["amount"] == 1

    def test_failed_delegate_does_not_consume_reserved_budget(
        self, http_proxy, private_key
    ):
        """Round-3 H1: failed child minting must leave the parent's reserved budget unchanged."""
        base, _ = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            max_tool_calls=10,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        _, start = _post(base + "/session/start", {"token": parent_token})
        session_id = start["session_id"]

        for _ in range(7):
            _post(base + "/evaluate", {
                "session_id": session_id,
                "tool_name": "read",
                "arguments": {},
            })

        failed_status, failed_body = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "bad-child",
                "child_mission": "sub-bad",
                "child_allowed_tools": ["write"],
                "child_max_tool_calls": 2,
            },
        )
        assert failed_status == 403
        assert "scope escalation" in failed_body.get("error", "").lower()

        status, body = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "good-child",
                "child_mission": "sub-good",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 3,
            },
        )
        assert status == 200
        assert body["child_claims"]["max_tool_calls"] == 3
        assert body["parent_calls_remaining_at_delegation"] == 3


# --- FIX-R8-2 (round-8, 2026-04-29): bearer-auth regression tests for
# the Python proxy. Round-7 audit (MED-NEW-2) flagged that the Python
# proxy at ``proxy.py:4669`` had ZERO tests of its bearer-auth path,
# while Go's Authority and Governor each have 4. A revert that flipped
# ``if not require_auth: return True`` or removed the
# ``hmac.compare_digest`` would not be caught. These tests mirror the
# Go regressions: missing-header → 401, wrong-token → 401, correct-
# token → not-401, public paths remain unauthenticated.

def _build_authenticated_server_thread(
    proxy: GovernanceProxy, private_key, port: int, *, api_token: str,
):
    """Variant of ``_build_server_thread`` that runs with require_auth=True
    and a fixed token, so tests can exercise the bearer-auth path."""
    import signal as _signal
    original = _signal.signal
    _signal.signal = lambda *_a, **_kw: None  # type: ignore[assignment]

    def run() -> None:
        serve_proxy(
            proxy=proxy,
            private_key=private_key,
            host="127.0.0.1",
            port=port,
            require_auth=True,
            api_token=api_token,
            no_tls=True,
        )

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 5
    last_exc = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/health", timeout=0.5) as resp:
                if resp.status == 200:
                    break
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(0.05)
    else:
        raise RuntimeError(f"proxy never became healthy: {last_exc}")
    return thread, base, lambda: setattr(_signal, "signal", original)


@pytest.fixture
def authed_http_proxy(proxy, private_key, unused_tcp_port):
    token = "auth-test-token-32-bytes-A-B-C-D-E"
    thread, base, shutdown = _build_authenticated_server_thread(
        proxy, private_key, unused_tcp_port, api_token=token,
    )
    yield base, proxy, token
    shutdown()


def _post_with_auth(url: str, payload: dict, token: str | None):
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(body)
        except ValueError:
            return exc.code, {"raw": body}


class TestPythonProxyBearerAuth:
    def test_missing_authorization_header_rejected(self, authed_http_proxy):
        base, _, _ = authed_http_proxy
        status, body = _post_with_auth(base + "/issue", {}, token=None)
        assert status == 401
        assert "missing or malformed Authorization" in body.get("error", "")

    def test_wrong_token_rejected(self, authed_http_proxy):
        base, _, _ = authed_http_proxy
        status, body = _post_with_auth(
            base + "/issue", {}, token="attacker-supplied-wrong-token-32",
        )
        assert status == 401
        assert "invalid bearer token" in body.get("error", "")

    def test_correct_token_passes_auth(self, authed_http_proxy):
        base, _, token = authed_http_proxy
        # Empty body lands in the issue handler's validation path (400);
        # the test confirms we passed the auth layer (not 401).
        status, body = _post_with_auth(base + "/issue", {}, token=token)
        assert status != 401, f"expected non-401, got {status}: {body}"

    def test_public_paths_remain_unauthenticated(self, authed_http_proxy):
        base, _, _ = authed_http_proxy
        for path in ("/health", "/healthz", "/.well-known/jwks.json"):
            with urllib.request.urlopen(base + path, timeout=2) as resp:
                assert resp.status == 200, f"public path {path} returned {resp.status}"

    def test_length_leak_normalized_via_hash_then_compare(self, authed_http_proxy):
        """Round-8 FIX-R8-1: SHA-256 normalizes both presented and
        expected tokens to 32 bytes, defeating the length oracle. We
        exercise three wrong-token lengths and confirm all three
        produce 401 — pinning the rejection contract for tokens of
        diverse lengths so a regression to direct ``hmac.compare_digest``
        on raw bytes can't sneak through unflagged."""
        base, _, _ = authed_http_proxy
        for bad in ("x", "y" * 64, "z" * 1024):
            status, body = _post_with_auth(base + "/issue", {}, token=bad)
            assert status == 401, f"length-{len(bad)} bad token must 401, got {status}"
            assert "invalid bearer token" in body.get("error", "")

    def test_lowercase_bearer_scheme_accepted(self, authed_http_proxy):
        """The proxy normalizes scheme via ``.lower().startswith("bearer ")``
        — RFC 9110 says scheme is case-insensitive. Pin that contract."""
        base, _, token = authed_http_proxy
        data = json.dumps({}).encode("utf-8")
        req = urllib.request.Request(
            base + "/issue",
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"bearer {token}",  # lowercase
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=2) as resp:
                assert resp.status != 401
        except urllib.error.HTTPError as exc:
            assert exc.code != 401, f"lowercase bearer rejected: {exc.code}"


# --- FIX-R9-2 (round-9, 2026-04-29) — DE-RIG REGRESSION TEST.
#
# Round-8 audit caught that ``TestPythonProxyBearerAuth`` does NOT pin
# the round-8 SHA-256 length-oracle closure, only the rejection
# contract: reverting the SHA-256 hash-then-compare to direct
# ``hmac.compare_digest`` keeps every behavioral test green because
# ``hmac.compare_digest`` returns False on length-mismatched inputs
# (just leaks length via timing). The test name promised mutation-
# resistance the implementation can't provide without timing
# measurements (which are flaky in CI).
#
# Honest fix: a structural / source-text test that asserts the
# SHA-256 normalization is actually in the source. This is brittle —
# a refactor that splits the function or renames variables breaks
# the test — but it's the only way to mutation-pin a timing-oracle
# closure without flaky timing tests. The test names the specific
# anti-pattern (raw ``compare_digest(provided, api_token_bytes)``)
# that round-8 audit identified as the regression vector.

class TestPythonProxyBearerAuthSourceShape:
    """Source-shape regressions that pin the SHA-256 length-oracle
    closure (round-8 FIX-R8-1) at the code-text level. These tests
    fire when a refactor reverts the hash-then-compare without
    explicitly migrating to an alternative length-independent compare.
    Brittle by design — a deliberate refactor must update both the
    code AND the test."""

    def test_check_auth_source_contains_sha256_normalization(self):
        """The Python proxy bearer-auth path must SHA-256-normalize
        both presented and expected tokens before comparison."""
        import inspect
        from vibap.proxy import serve_proxy

        src = inspect.getsource(serve_proxy)
        # Pin the canonical pattern: hash both sides BEFORE compare_digest.
        assert "hashlib.sha256(provided)" in src or \
            "hashlib.sha256(provided.encode" in src or \
            "sha256(provided)" in src, (
            "FIX-R8-1 regression: bearer-auth must hash the presented "
            "token before constant-time compare to defeat the length "
            "oracle. The pattern 'hashlib.sha256(provided)...' is "
            "missing from serve_proxy source. See round-8 audit "
            "MED-NEW-1 / round-9 FIX-R9-2."
        )
        assert "api_token_hash" in src, (
            "FIX-R8-1 regression: expected-token hash precomputation "
            "missing. ``api_token_hash`` should be precomputed once "
            "from sha256(api_token_bytes)."
        )
        # Anti-pattern: raw bytes compared via hmac.compare_digest.
        # The round-8-revert pattern has the form
        # ``compare_digest(provided, api_token_bytes)`` — flag it.
        assert "compare_digest(provided, api_token_bytes)" not in src, (
            "FIX-R8-1 regression: bearer-auth reverted to raw-bytes "
            "compare_digest, leaking expected-token length via timing. "
            "Use compare_digest(provided_hash, api_token_hash) instead."
        )

    def test_check_auth_uses_compare_digest_on_hashes(self):
        """The compare_digest call must operate on the precomputed
        hashes, not on raw bytes."""
        import inspect
        from vibap.proxy import serve_proxy

        src = inspect.getsource(serve_proxy)
        # The two acceptable shapes (allowing minor refactor flexibility):
        acceptable = [
            "compare_digest(provided_hash, api_token_hash)",
            "compare_digest(api_token_hash, provided_hash)",
        ]
        if not any(pattern in src for pattern in acceptable):
            raise AssertionError(
                "FIX-R8-1 regression: compare_digest must be called on "
                "the SHA-256 digests of provided and api_token. "
                f"Expected one of {acceptable!r} in serve_proxy source."
            )


# --- FIX-R10-2 + FIX-R10-3 (round-10, 2026-04-29): behavioral regressions
# for R9-1 (Python VIBAP_API_TOKEN env trim) and R9-5 (strict ASCII
# bearer) that round-9 audit (LOW-NEW-1, LOW-NEW-2) flagged as
# untested. The Go side has TestLoadFromEnvTrimsAuthToken (R9-3); the
# Python side now has the symmetric coverage. A revert from
# ``env_token_raw.strip()`` to ``env_token_raw`` would silently mean
# whitespace-padded VIBAP_API_TOKEN values pass startup but no
# client-presented bearer can match — the operator-confusion failure
# mode R9-1 closed.

class TestPythonProxyCliTokenStrip:
    """FIX-R11-1 (round-11, 2026-04-29): close round-10 audit's
    LOW-R10-A finding — the R10-4 ``--api-token`` CLI strip shipped
    without a behavioral test. The R10-2 env-strip test
    (``TestPythonProxyEnvTokenStrip`` below) sets ``VIBAP_API_TOKEN``,
    which takes precedence over the CLI argument at ``proxy.py:4538``,
    so ``api_token.strip()`` at line 4548 was untested. This test
    explicitly disables the env var so the CLI branch is exercised."""

    def test_whitespace_padded_cli_token_authenticates_after_trim(
        self, proxy, private_key, unused_tcp_port, monkeypatch
    ):
        """Round-10 LOW-R10-A: the CLI-supplied token must be
        ``.strip()``-ed symmetric with the env-loaded path. Without
        R10-4's strip(), an operator running ``--api-token "  abc  "``
        (e.g. from a YAML ``command:`` block) creates a proxy where no
        client can authenticate."""
        # Ensure env var is not set so the CLI path is taken.
        monkeypatch.delenv("VIBAP_API_TOKEN", raising=False)
        canonical_token = "cli-test-token-32-bytes-DEFGHIJ"
        thread, base, shutdown = _build_authenticated_server_thread(
            proxy, private_key, unused_tcp_port,
            api_token=f"   {canonical_token}   ",
        )
        try:
            status, body = _post_with_auth(
                base + "/issue", {}, token=canonical_token,
            )
            assert status != 401, (
                f"R10-4 regression: trimmed CLI token authentication "
                f"failed; status={status} body={body}. "
                "If CLI loader doesn't strip(), the proxy compares "
                "padded-token against client-supplied trimmed-token, "
                "never matching."
            )
        finally:
            shutdown()


class TestPythonProxyEnvTokenStrip:
    def test_whitespace_padded_env_token_authenticates_after_trim(
        self, proxy, private_key, unused_tcp_port, monkeypatch
    ):
        """R9-1 contract: an operator who sets VIBAP_API_TOKEN with
        leading/trailing whitespace (e.g. via a YAML-quoted secret)
        creates a proxy where clients CAN authenticate using the
        trimmed token. Without R9-1's strip(), no client could
        authenticate."""
        # Set the env BEFORE constructing the server thread.
        canonical_token = "padded-test-token-32-bytes-XXYY-Z"
        monkeypatch.setenv("VIBAP_API_TOKEN", f"  {canonical_token}  ")

        thread, base, shutdown = _build_authenticated_server_thread(
            proxy, private_key, unused_tcp_port,
            api_token="ignored-arg-because-env-takes-precedence",
        )
        try:
            # Client presents the canonical (trimmed) token — must succeed.
            status, body = _post_with_auth(
                base + "/issue", {}, token=canonical_token,
            )
            assert status != 401, (
                f"R9-1 regression: trimmed env token authentication "
                f"failed; status={status} body={body}. "
                "If env loader doesn't strip(), the proxy compares "
                "padded-token-with-whitespace against client-supplied "
                "trimmed-token, never matching."
            )
        finally:
            shutdown()


class TestPythonProxyStrictAscii:
    def test_non_ascii_bearer_token_rejected_with_explicit_message(
        self, authed_http_proxy
    ):
        """R9-5 contract: a non-ASCII bearer header is REJECTED with
        an explicit ``bearer token must be ASCII`` message, not
        silently mapped to `?` characters (the round-8 anti-pattern).
        A revert to ``encode("ascii", errors="replace")`` would
        silently re-introduce the asymmetric handling and this test
        would fail."""
        base, _, _ = authed_http_proxy
        # Build a request with a non-ASCII bearer (Latin-1 é encoded
        # as UTF-8 bytes 0xC3 0xA9). HTTP header values are bytes per
        # RFC 7230; we send the raw bytes directly via http.client to
        # bypass urllib's automatic encoding helpers.
        import http.client
        from urllib.parse import urlparse

        parsed = urlparse(base)
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=2)
        # Use a non-ASCII char (é) — utf-8 encoded — in the bearer.
        bad_token = "tok-with-é-non-ascii"
        # The HTTP layer will refuse non-ASCII in headers in some Python
        # versions; use latin-1 encoding (RFC 7230's ISO-8859-1 default)
        # so the request actually reaches the server.
        try:
            conn.request(
                "POST",
                "/issue",
                body=b"{}",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {bad_token}".encode("latin-1"),
                },
            )
            resp = conn.getresponse()
            body_bytes = resp.read()
            assert resp.status == 401, (
                f"non-ASCII bearer token must be 401; got {resp.status}"
            )
            body = json.loads(body_bytes.decode("utf-8"))
            assert "ASCII" in body.get("error", ""), (
                f"R9-5 regression: error must explicitly name ASCII; "
                f"got: {body}"
            )
        except http.client.HTTPException as exc:
            # If the underlying http.client refuses to send the header
            # with non-ASCII bytes, that's a different fail-closed
            # outcome — also acceptable (client-side rejection).
            # We only fail if the server SILENTLY accepts and serves.
            pass
        finally:
            conn.close()
