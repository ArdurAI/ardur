from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import sys
import threading
from argparse import Namespace
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from urllib import error as urlerror
from urllib import request as urlrequest

import pytest

from vibap.ardur_personal_native_host import HOST_OBSERVATION_TYPE, handle_native_host_message
from vibap.personal_hub import _HubRequestHandler, HubError, PersonalHub, run_under_hub, setup_personal
from vibap.personal_hub import _redact_url_tokens
from vibap.receipt import verify_receipt


def _digest(text: str) -> str:
    return "sha-256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _browser_payload(text: str = "hello from ChatGPT") -> dict:
    digest = _digest(text)
    return {
        "schema_version": "ardur.personal.event.v0.1",
        "source": {
            "type": "browser",
            "app": "ChatGPT",
            "origin": "https://chatgpt.com",
        },
        "session": {
            "id": "https://chatgpt.com:test-tab",
            "title": "ChatGPT test",
        },
        "event": {
            "kind": "browser_visible_observation",
            "action_class": "observe",
            "target": "manual_collect",
            "capture_mode": "structured_visible_text",
            "content_digest": digest,
            "raw_content_included": False,
            "text_snapshot_included": True,
            "text_excerpt": text,
            "messages": [
                {
                    "role": "user",
                    "text_digest": _digest("summarize this"),
                    "text_excerpt": "summarize this",
                },
                {
                    "role": "assistant",
                    "text_digest": _digest(text),
                    "text_excerpt": text,
                },
            ],
            "consent": {"visible_text": True},
        },
    }


def test_browser_observation_uses_standard_ardur_receipt(tmp_path):
    hub = PersonalHub(tmp_path)

    result = hub.observe(_browser_payload())

    assert result["ok"] is True
    assert result["decision"] == "PERMIT"
    assert result["receipt"]["type"] == "execution_receipt"
    assert result["session_review"]["provider"] == "ChatGPT"
    assert {"observed", "attested", "allowed"} <= set(
        result["session_review"]["policy_labels"]
    )
    assert any(
        action["kind"] == "assistant_response_observed"
        for action in result["session_review"]["actions"]
    )
    claims = verify_receipt(
        result["receipt"]["jwt"],
        hub.public_key,
        verify_expiry=False,
    )
    assert claims["verdict"] == "compliant"
    assert claims["tool"] == "browser_observe"


def test_cli_dangerous_command_is_blocked_and_receipted(tmp_path):
    hub = PersonalHub(tmp_path)
    payload = {
        "source": {"type": "cli", "app": "sh", "process": "sudo rm -rf /"},
        "session": {"id": "cli:test", "title": "sudo rm -rf /"},
        "event": {
            "kind": "cli_command",
            "action_class": "observe",
            "target": "sh",
            "command": ["sudo", "rm", "-rf", "/"],
            "raw_content_included": False,
        },
    }

    policy = hub.check_policy(payload)
    result = hub.observe(payload)

    assert policy["verdict"] == "blocked"
    assert result["decision"] == "DENY"
    assert "blocked" in result["session_review"]["policy_labels"]
    claims = verify_receipt(
        result["receipt"]["jwt"],
        hub.public_key,
        verify_expiry=False,
    )
    assert claims["verdict"] == "violation"
    assert claims["tool"] == "cli_blocked_action"


def test_visible_text_requires_explicit_consent(tmp_path):
    hub = PersonalHub(tmp_path)
    payload = _browser_payload()
    payload["event"]["consent"] = {"visible_text": False}

    with pytest.raises(HubError):
        hub.observe(payload)


def test_export_includes_session_reviews_and_receipts(tmp_path):
    hub = PersonalHub(tmp_path)
    hub.observe(_browser_payload("answer text"))

    exported = hub.export()

    assert exported["ok"] is True
    assert exported["session_reviews"]
    assert exported["receipts"]


def test_status_reports_configured_hub_url(tmp_path):
    hub = PersonalHub(tmp_path, hub_url="http://127.0.0.1:18765")

    assert hub.status()["hub_url"] == "http://127.0.0.1:18765"


def test_setup_generates_stable_hub_token(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "user-home"))

    class Args:
        host = "127.0.0.1"
        port = 8765
        home = tmp_path
        extension_path = None
        rotate_token = False

    first = setup_personal(Args())
    second = setup_personal(Args())

    assert first["hub_token"]
    assert second["hub_token"] == first["hub_token"]
    config_path = tmp_path / "config.json"
    assert json.loads(config_path.read_text())["hub_token"] == first["hub_token"]
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600


def test_hub_http_auth_protects_export_and_mutations(tmp_path):
    with _running_hub(tmp_path) as (hub, base_url):
        assert _get_json(base_url, "/healthz")["ok"] is True

        with pytest.raises(urlerror.HTTPError) as unauth_export:
            _get_json(base_url, "/v1/export")
        assert unauth_export.value.code == 401

        with pytest.raises(urlerror.HTTPError) as wrong_token:
            _get_json(base_url, "/v1/export", token="wrong")
        assert wrong_token.value.code == 401

        exported = _get_json(base_url, "/v1/export", token=hub.hub_token)
        assert exported["ok"] is True

        with pytest.raises(urlerror.HTTPError) as unauth_post:
            _post_json(base_url, "/v1/events/observe", _browser_payload())
        assert unauth_post.value.code == 401

        observed = _post_json(base_url, "/v1/events/observe", _browser_payload(), token=hub.hub_token)
        assert observed["ok"] is True


def test_hub_query_token_only_authorizes_dashboard_get(tmp_path):
    with _running_hub(tmp_path) as (hub, base_url):
        with pytest.raises(urlerror.HTTPError) as query_export:
            _get_json(base_url, f"/v1/export?token={hub.hub_token}")
        assert query_export.value.code == 401

        with pytest.raises(urlerror.HTTPError) as query_post:
            _post_json(base_url, f"/v1/events/observe?token={hub.hub_token}", _browser_payload())
        assert query_post.value.code == 401


def test_hub_log_redacts_full_query_token():
    message = 'GET /dashboard?token=abcsefg123&next=/ HTTP/1.1'

    redacted = _redact_url_tokens(message)

    assert "abcsefg123" not in redacted
    assert "sefg123" not in redacted
    assert "?token=<redacted>&next=/" in redacted


def test_hub_accepts_dashboard_token_query(tmp_path):
    with _running_hub(tmp_path) as (hub, base_url):
        request = urlrequest.Request(f"{base_url}/dashboard?token={hub.hub_token}")
        with urlrequest.urlopen(request, timeout=5) as response:
            html = response.read().decode("utf-8")
            csp = response.headers["content-security-policy"]

    assert response.status == 200
    assert "default-src 'none'" in csp
    assert "Ardur Personal Hub" in html


def test_native_host_uses_custom_home_for_hub_token(tmp_path):
    with _running_hub(tmp_path) as (_, base_url):
        response = handle_native_host_message(
            {
                "type": HOST_OBSERVATION_TYPE,
                "hub_event": _browser_payload("native bridge event"),
            },
            hub_url=base_url,
            home=tmp_path,
        )

    assert response["ok"] is True


def test_run_under_hub_streams_output_without_subprocess_run(tmp_path, capfd, monkeypatch):
    def fail_subprocess_run(*_args, **_kwargs):
        raise AssertionError("run_under_hub must not buffer output with subprocess.run")

    monkeypatch.setattr(subprocess, "run", fail_subprocess_run)
    with _running_hub(tmp_path) as (_, base_url):
        exit_code = run_under_hub(
            Namespace(
                command=[
                    sys.executable,
                    "-c",
                    "import sys; print('stream-out'); print('stream-err', file=sys.stderr)",
                ],
                hub_url=base_url,
                hub_token=None,
                home=tmp_path,
            )
        )

    captured = capfd.readouterr()
    assert exit_code == 0
    assert "stream-out" in captured.out
    assert "stream-err" in captured.err


@contextmanager
def _running_hub(home):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HubRequestHandler)
    host, port = server.server_address
    server.hub = PersonalHub(home, hub_url=f"http://{host}:{port}")  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.hub, f"http://{host}:{port}"  # type: ignore[attr-defined]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _get_json(base_url, path, *, token=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urlrequest.Request(base_url + path, headers=headers)
    with urlrequest.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _post_json(base_url, path, payload, *, token=None):
    headers = {"content-type": "application/json"}
    if token:
        headers["X-Ardur-Hub-Token"] = token
    request = urlrequest.Request(
        base_url + path,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers=headers,
    )
    with urlrequest.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# HTTP integration tests — Hub running as an actual HTTP server
# ---------------------------------------------------------------------------


class TestPersonalHubHTTPIntegration:
    """End-to-end HTTP integration tests against a running Personal Hub server."""

    def test_status_endpoint_returns_session_count(self, tmp_path):
        with _running_hub(tmp_path) as (hub, base_url):
            status = _get_json(base_url, "/v1/status", token=hub.hub_token)
            assert "sessions" in status
            assert status["sessions"] == 0

            # After an observation, session count increments
            _post_json(base_url, "/v1/events/observe", _browser_payload(), token=hub.hub_token)
            status2 = _get_json(base_url, "/v1/status", token=hub.hub_token)
            assert status2["sessions"] >= 1

    def test_multiple_sessions_coexist(self, tmp_path):
        with _running_hub(tmp_path) as (hub, base_url):
            chatgpt = _browser_payload("ChatGPT observation")
            claude = _browser_payload("Claude observation")
            claude["source"]["app"] = "Claude"
            claude["session"]["id"] = "https://claude.ai:test-tab"

            r1 = _post_json(base_url, "/v1/events/observe", chatgpt, token=hub.hub_token)
            r2 = _post_json(base_url, "/v1/events/observe", claude, token=hub.hub_token)
            assert r1["ok"] and r2["ok"]

            status = _get_json(base_url, "/v1/status", token=hub.hub_token)
            assert status["sessions"] >= 2

            exported = _get_json(base_url, "/v1/export", token=hub.hub_token)
            providers = {r["provider"] for r in exported["session_reviews"]}
            assert "ChatGPT" in providers
            assert "Claude" in providers

    def test_rate_limiting_returns_429(self, tmp_path):
        # Create a hub with a tight rate limiter
        from vibap.rate_limiter import RateLimiter
        from vibap.personal_hub import _HubRequestHandler
        from http.server import ThreadingHTTPServer

        server = ThreadingHTTPServer(("127.0.0.1", 0), _HubRequestHandler)
        host, port = server.server_address
        hub = PersonalHub(tmp_path, hub_url=f"http://{host}:{port}")
        server.hub = hub  # type: ignore[attr-defined]
        server.rate_limiter = RateLimiter(rate=5, burst=5)  # type: ignore[attr-defined]

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://{host}:{port}"

        try:
            # Health endpoint bypasses rate limiter
            assert _get_json(base_url, "/healthz")["ok"] is True

            # Flood the status endpoint (which IS rate-limited)
            rate_limited = False
            for _ in range(20):
                req = urlrequest.Request(
                    base_url + "/v1/status",
                    headers={"X-Ardur-Hub-Token": hub.hub_token},
                )
                try:
                    with urlrequest.urlopen(req, timeout=5) as resp:
                        if resp.status == 429:
                            rate_limited = True
                            break
                except urlerror.HTTPError as exc:
                    if exc.code == 429:
                        rate_limited = True
                        break

            assert rate_limited, "Expected 429 after exceeding rate limit"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
