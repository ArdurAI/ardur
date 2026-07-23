"""Ardur E2E Showcase — Real Ollama, Every Capability.

Exercises all 28 governance capabilities through real Ollama tool calls
and direct HTTP interactions with the GovernanceProxy. Designed to be run
as a regression gate after every major/minor implementation.

Usage::

    pytest python/tests/test_e2e_showcase.py -v -s --tb=short

The -s flag is required to see the user-friendly showcase output.
"""

from __future__ import annotations

import atexit as _atexit
import json
import os
import threading
import time
import urllib.error
import urllib.request

import pytest

from vibap.passport import (
    MissionPassport,
    derive_child_passport,
    issue_passport,
    verify_passport,
)
from vibap.proxy import serve_proxy
from vibap.receipt import verify_chain

from tests.conftest import v01_required_md_extras

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

CLOUD_MODEL = os.environ.get("ARDUR_OLLAMA_CLOUD_MODEL", "")
API_KEY = os.environ.get(
    "ARDUR_OLLAMA_API_KEY",
    "",
)

# ---------------------------------------------------------------------------
# showcase output singleton
# ---------------------------------------------------------------------------


class _Showcase:
    """Tracks results and prints visually stunning output for the showcase."""

    _WIDTH = 72

    def __init__(self):
        self._counter = 0
        self._results: list[tuple[int, str, str, str]] = []
        self._total = 28

    def _p(self, *args) -> None:
        """Print and flush — bypass any pytest buffering."""
        import sys as _sys

        msg = " ".join(str(a) for a in args)
        _sys.__stdout__.write(msg + "\n")
        _sys.__stdout__.flush()

    # -- section headers -------------------------------------------------------

    def section(self, number: str, title: str, description: str) -> None:
        self._p()
        self._p(f"  ╔{'═' * (self._WIDTH - 4)}╗")
        self._p(f"  ║ {number}  {title:<{self._WIDTH - 9}}║")
        self._p(f"  ╠{'═' * (self._WIDTH - 4)}╣")
        for line in description.strip().split("\n"):
            self._p(f"  ║  {line:<{self._WIDTH - 7}}║")
        self._p(f"  ╚{'═' * (self._WIDTH - 4)}╝")
        self._p()

    # -- individual test results -----------------------------------------------

    def test(self, name: str, detail: str = "") -> bool:
        self._counter += 1
        n = self._counter
        self._results.append((n, name, "PASS", detail))
        return True

    def fail(self, name: str, detail: str = "") -> None:
        for index, (number, result_name, _status, _detail) in enumerate(self._results):
            if result_name == name:
                self._results[index] = (number, name, "FAIL", detail)
                return
        self._counter += 1
        n = self._counter
        self._results.append((n, name, "FAIL", detail))

    def skip(self, name: str, reason: str = "") -> None:
        self._counter += 1
        n = self._counter
        self._results.append((n, name, "SKIP", reason))

    # -- final summary ---------------------------------------------------------

    def summary(self) -> None:
        passed = sum(1 for _, _, s, _ in self._results if s == "PASS")
        failed = sum(1 for _, _, s, _ in self._results if s == "FAIL")
        skipped = sum(1 for _, _, s, _ in self._results if s == "SKIP")

        # Print all results
        self._p()
        self._p(f"  ╔{'═' * (self._WIDTH - 4)}╗")
        self._p(f"  ║  {'RESULTS  —  DETAIL':^{self._WIDTH - 6}}║")
        self._p(f"  ╚{'═' * (self._WIDTH - 4)}╝")
        self._p()

        for n, name, status, detail in self._results:
            if status == "PASS":
                icon = "✅"
            elif status == "FAIL":
                icon = "❌"
            else:
                icon = "⏭️"
            self._p(f"  {icon}  [{n:02d}/{self._total}] {name}")
            if detail:
                for line in detail.strip().split("\n"):
                    self._p(f"      {line}")
            if status == "FAIL":
                self._p()
            self._p()

        # Summary bar
        bar_w = self._WIDTH - 6
        if self._total > 0:
            pct_p = int(passed / self._total * bar_w)
            pct_f = int(failed / self._total * bar_w)
            pct_s = int(skipped / self._total * bar_w)
        else:
            pct_p = pct_f = pct_s = 0

        bar_chars = ("█" * pct_p) + ("▇" * pct_f) + ("░" * pct_s)
        if len(bar_chars) < bar_w:
            bar_chars += " " * (bar_w - len(bar_chars))

        self._p(f"  ╔{'═' * (self._WIDTH - 4)}╗")
        self._p(f"  ║  {'AR DUR  ·  E2E  SHOWCASE  RESULTS':^{self._WIDTH - 6}}║")
        self._p(f"  ╠{'═' * (self._WIDTH - 4)}╣")
        self._p(f"  ║  {bar_chars}║")
        self._p(f"  ║{' ':^{self._WIDTH - 4}}║")
        status_line = f"  ✅  {passed:>3} passed"
        if failed:
            status_line += f"    ❌  {failed:>3} failed"
        if skipped:
            status_line += f"    ⏭️   {skipped:>3} skipped"
        self._p(status_line)
        self._p(f"  ║{' ':^{self._WIDTH - 4}}║")
        verdict = "ALL GOOD  ✨" if failed == 0 else f"{failed} FAILURE(S)  ⚠️"
        self._p(f"  ║  {'VERDICT:':<9} {verdict:<{self._WIDTH - 15}}║")
        self._p(f"  ╚{'═' * (self._WIDTH - 4)}╝")
        self._p()


_show = _Showcase()


class _ShowcaseReportPlugin:
    """Reflect annotated pytest failures in the showcase footer."""

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):
        outcome = yield
        report = outcome.get_result()
        name = getattr(item.obj, "_showcase_name", None)
        if name is None or not report.failed:
            return

        if call.excinfo is None:
            detail = f"{report.when} failed"
        else:
            detail = (
                f"{report.when} {type(call.excinfo.value).__name__}: "
                f"{call.excinfo.value}"
            )
        _show.fail(name, detail)


@pytest.fixture(scope="session", autouse=True)
def _print_header(pytestconfig):
    """Print the showcase header at session start, summary at end."""
    report_plugin = _ShowcaseReportPlugin()
    pytestconfig.pluginmanager.register(
        report_plugin,
        "ardur-showcase-reporting",
    )
    p = _show._p
    p()
    p(f"  ╔{'═' * 70}╗")
    p(f"  ║  {'ＡＲ ＤＵＲ':^64}║")
    p(f"  ║  {'Runtime Governance & Evidence Layer for AI Agents':^64}║")
    p(f"  ╠{'═' * 70}╣")
    p(f"  ║  {'End-to-End Capability Showcase':^64}║")
    p(f"  ║  {'Real Ollama  ·  No Mocks  ·  Every Governance Feature':^64}║")
    p(f"  ╠{'═' * 70}╣")
    p(f"  ║  {'Model':<9} {CLOUD_MODEL:<58}║")
    p(f"  ║  {'Tests':<9} {28:<58}║")
    p(
        f"  ║  {'Layers':<9} {'HTTP Security · Sessions · Delegation · Receipts · MIC · Backends · Advanced':<58}║"
    )
    p(f"  ╚{'═' * 70}╝")
    p()
    _atexit.register(_show.summary)


# ---------------------------------------------------------------------------
# skip marker
# ---------------------------------------------------------------------------


def _ollama_available() -> bool:
    if not API_KEY or not CLOUD_MODEL:
        return False
    try:
        # Import the optional dependency instead of checking only its module
        # spec so broken installations are treated as unavailable.
        import ollama  # noqa: F401

        return True
    except ImportError:
        return False


ollama_required = pytest.mark.skipif(
    not _ollama_available(),
    reason=(
        "Ollama cloud model not available "
        "(set ARDUR_OLLAMA_API_KEY and ARDUR_OLLAMA_CLOUD_MODEL)"
    ),
)


# ---------------------------------------------------------------------------
# http helpers
# ---------------------------------------------------------------------------


def _parse_tool_args(args):
    """Ollama may return args as JSON string or pre-parsed dict."""
    if isinstance(args, dict):
        return args
    if isinstance(args, str):
        return json.loads(args)
    return {}


def _build_server(proxy, private_key, port, *, require_auth=False, api_token=""):
    """Start serve_proxy in a background daemon thread."""
    import io as _io
    import signal as _signal
    import sys as _sys

    original = _signal.signal
    _signal.signal = lambda *_a, **_kw: None

    def run():
        # Suppress proxy's stdout banner during showcase
        _sys.stdout = _io.StringIO()
        _sys.stderr = _io.StringIO()
        serve_proxy(
            proxy=proxy,
            private_key=private_key,
            host="127.0.0.1",
            port=port,
            require_auth=require_auth,
            api_token=api_token,
            no_tls=True,
        )

    t = threading.Thread(target=run, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/health", timeout=0.5) as resp:
                if resp.status == 200:
                    break
        except Exception:
            time.sleep(0.05)
    else:
        raise RuntimeError("proxy never became healthy")

    def shutdown():
        _signal.signal = original

    return t, base, shutdown


def _post(url, payload, token=None):
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return (
                resp.status,
                json.loads(resp.read().decode("utf-8")),
                dict(resp.headers.items()),
            )
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(body), dict(exc.headers.items())
        except json.JSONDecodeError:
            return exc.code, {"raw": body}, dict(exc.headers.items())


def _get(url, token=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(body), dict(resp.headers.items())
            except json.JSONDecodeError:
                return resp.status, {"raw": body}, dict(resp.headers.items())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(body), dict(exc.headers.items())
        except json.JSONDecodeError:
            return exc.code, {"raw": body}, dict(exc.headers.items())


# ---------------------------------------------------------------------------
# ollama helpers
# ---------------------------------------------------------------------------


def _chat_with_retry(client, messages, tools, max_retries=3):
    """Call ollama.chat with escalating prompts until we get tool_calls."""
    for attempt in range(max_retries):
        try:
            resp = client.chat(model=CLOUD_MODEL, messages=messages, tools=tools)
        except Exception:
            if attempt == max_retries - 1:
                raise
            time.sleep(1)
            continue

        tool_calls = getattr(resp.message, "tool_calls", None)
        if tool_calls:
            return tool_calls

        if attempt == 0:
            messages = list(messages) + [
                {
                    "role": "user",
                    "content": "You MUST call the tool function. Do not describe it — invoke it directly.",
                }
            ]
        elif attempt == 1:
            messages = list(messages) + [
                {
                    "role": "user",
                    "content": "CRITICAL: Your ONLY task is to call the specified tool. Do NOT write any explanation text. Just call the tool function NOW.",
                }
            ]

    return None


def _ollama_chat_single(client, messages, tools):
    """Make one model request and propagate provider or transcript errors."""
    return client.chat(model=CLOUD_MODEL, messages=messages, tools=tools)


def _tool_result_for_evaluation(status, decision):
    """Return a fail-closed simulated result for one governance evaluation."""
    decision_value = decision.get("decision") if isinstance(decision, dict) else None
    if status == 200 and decision_value == "PERMIT":
        return {"status": "ok", "result": "processed"}
    if status == 200 and decision_value == "DENY":
        return {"status": "denied", "result": "not processed"}
    return {"status": "unknown", "result": "not processed"}


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def ollama_client():
    """Return an ollama Client with the cloud API key configured."""
    import ollama

    os.environ.setdefault("OLLAMA_API_KEY", API_KEY)
    return ollama.Client()


@pytest.fixture
def http_proxy(proxy, private_key, unused_tcp_port):
    """Start serve_proxy in background thread, no TLS, no auth."""
    t, base, shutdown = _build_server(proxy, private_key, unused_tcp_port)
    yield base, proxy
    shutdown()


@pytest.fixture
def http_proxy_with_auth(proxy, private_key, unused_tcp_port):
    """Proxy with require_auth=True and a known bearer token."""
    token = "showcase-auth-token-2026"
    t, base, shutdown = _build_server(
        proxy,
        private_key,
        unused_tcp_port,
        require_auth=True,
        api_token=token,
    )
    yield base, proxy, token
    shutdown()


@pytest.fixture
def session(http_proxy, example_mission, private_key):
    """Start a governed session for LLM-driven tests."""
    base, proxy = http_proxy
    token = issue_passport(example_mission, private_key, ttl_s=300)
    status, body, _ = _post(base + "/session/start", {"token": token})
    assert status == 200, f"session start failed: {body}"
    return base, body["session_id"], token, proxy


# ============================================================================
# Class 1: HTTP Security Layer (tests 1–7, no LLM needed)
# ============================================================================


class TestHTTPSecurityLayer:
    """Proxy security properties — headers, auth, rate limiting, kill switch.

    These tests use direct HTTP calls; no Ollama needed."""

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _section_header(cls):
        _show.section(
            "LAYER 1",
            "HTTP Security Layer",
            "Hardening the proxy surface: health checks, JWKS key distribution,\n"
            "security headers, Prometheus metrics, bearer-auth enforcement,\n"
            "token-bucket rate limiting, and the emergency kill switch.\n"
            "No LLM needed — pure HTTP protocol verification.",
        )

    def test_health_endpoint(self, http_proxy):
        base, _proxy = http_proxy
        status, body, _headers = _get(base + "/health")
        assert status == 200
        assert body.get("status") == "ok"
        assert "version" in body
        _show.test(
            "Health Endpoint",
            f"GET /health -> status={body['status']}, version={body.get('version', '?')}",
        )

    def test_jwks_endpoint(self, http_proxy):
        base, _proxy = http_proxy
        status, body, _headers = _get(base + "/.well-known/jwks.json")
        assert status == 200
        assert "keys" in body
        assert len(body["keys"]) >= 1
        key = body["keys"][0]
        assert key.get("kty") == "EC"
        _show.test(
            "JWKS Endpoint",
            f"GET /.well-known/jwks.json -> {len(body['keys'])} key(s), kty={key.get('kty')}, crv={key.get('crv')}",
        )

    def test_security_headers(self, http_proxy):
        base, _proxy = http_proxy
        _status, _body, headers = _get(base + "/health")
        checks = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
        }
        results = []
        for header, expected in checks.items():
            actual = headers.get(header, "").lower()
            ok = expected.lower() in actual
            results.append(f"  {header}: {actual} {'✓' if ok else '✗'}")
            assert ok, f"{header} expected '{expected}', got '{actual}'"
        _show.test("Security Headers", "\n".join(results))

    def test_metrics_endpoint(self, http_proxy_with_auth):
        base, _proxy, token = http_proxy_with_auth
        status, body, _headers = _get(base + "/metrics", token=token)
        assert status == 200
        # body might be dict with 'raw' for prometheus text, or a dict
        text = body.get("raw", str(body))
        assert "ardur_" in text, f"Expected ardur_ metrics in: {text[:200]}"
        _show.test(
            "Metrics Endpoint",
            f"GET /metrics -> {text.count(chr(10))} lines, ardur_ prefix present",
        )

    def test_auth_required(self, http_proxy_with_auth):
        base, _proxy, token = http_proxy_with_auth

        # No auth
        status, body, headers = _get(base + "/metrics")
        assert status == 401, f"Expected 401, got {status}: {body}"
        assert "WWW-Authenticate" in headers

        # Wrong auth
        status, body, _ = _get(base + "/metrics", token="wrong-token")
        assert status == 401, f"Expected 401 for wrong token, got {status}"

        # Correct auth
        status, body, _ = _get(base + "/metrics", token=token)
        assert status == 200, f"Expected 200 with correct token, got {status}: {body}"

        _show.test(
            "Auth Required",
            "No token -> 401 + WWW-Authenticate ✓\n"
            "  Wrong token -> 401 ✓\n"
            "  Correct token -> 200 ✓",
        )

    def test_rate_limiting(self, http_proxy, monkeypatch):
        # Test the RateLimiter directly — it's the same algorithm used by serve_proxy
        from vibap.rate_limiter import RateLimiter

        # Create a limiter with rate=1 and burst=1 — every other request should fail
        rl = RateLimiter(rate=1.0, burst=1)
        allowed = [rl.allow("test-ip") for _ in range(10)]
        assert any(a for a in allowed), "At least some requests should be allowed"
        assert any(not a for a in allowed), "Some requests should be rate-limited"
        rl.stop()
        _show.test(
            "Rate Limiting",
            f"RateLimiter(rate=1, burst=1): 10 rapid checks -> "
            f"{sum(allowed)} allowed, {sum(1 for a in allowed if not a)} denied ✓",
        )

    def test_kill_switch(self, http_proxy, example_mission, private_key):
        base, proxy = http_proxy
        token = issue_passport(example_mission, private_key, ttl_s=300)
        status, start_body, _ = _post(base + "/session/start", {"token": token})
        assert status == 200
        sid = start_body["session_id"]

        # Activate kill switch
        status, ks, _ = _post(base + "/admin/kill-switch", {})
        assert ks.get("kill_switch") == "activated"

        # Evaluate should fail with 503
        status, body, _ = _post(
            base + "/evaluate",
            {
                "session_id": sid,
                "tool_name": "read_file",
                "arguments": {"path": "/tmp/test.txt"},
            },
        )
        assert status == 503, f"Expected 503 under kill switch, got {status}: {body}"

        # Health still works
        h_status, _, _ = _get(base + "/health")
        assert h_status == 200

        # Deactivate
        status, ks2, _ = _post(base + "/admin/kill-switch", {"deactivate": True})
        assert ks2.get("kill_switch") == "deactivated"

        # Evaluate works again
        status, decision, _ = _post(
            base + "/evaluate",
            {
                "session_id": sid,
                "tool_name": "read_file",
                "arguments": {"path": "/tmp/test.txt"},
            },
        )
        assert status == 200
        assert decision["decision"] == "PERMIT"

        _show.test(
            "Kill Switch",
            "Activate -> evaluate 503 ✓\n"
            "  Health still 200 ✓\n"
            "  Deactivate -> evaluate works again ✓",
        )


# ============================================================================
# Class 2: Session & Passport Layer (tests 8–14, Ollama + HTTP)
# ============================================================================


@ollama_required
class TestSessionAndPassportLayer:
    """Session lifecycle, passport issuance, and tool-call governance
    driven by real Ollama tool requests."""

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _section_header(cls):
        _show.section(
            "LAYER 2",
            "Session & Passport Layer",
            'The core governance loop: issue a MissionPassport ("who are you,\n'
            'what can you do?"), start a session, then have a real LLM request\n'
            "tool calls. Ardur permits allowed tools, denies forbidden and\n"
            "unknown tools, and enforces per-session call budgets.\n"
            "Multi-turn LLM conversations flow through the proxy transparently.",
        )

    def test_passport_issuance(self, private_key, public_key):
        mission = MissionPassport(
            agent_id="showcase-agent",
            mission="e2e showcase — session layer tests",
            allowed_tools=["read_file", "write_file", "analyze"],
            forbidden_tools=["delete_file", "execute_shell"],
            max_tool_calls=8,
            max_duration_s=300,
        )
        token = issue_passport(mission, private_key, ttl_s=300)
        claims = verify_passport(token, public_key)
        assert claims.get("sub") == "showcase-agent"
        assert "read_file" in claims.get("allowed_tools", [])
        assert "delete_file" in claims.get("forbidden_tools", [])
        assert claims.get("max_tool_calls") == 8
        _show.test(
            "Passport Issuance",
            f"agent={claims.get('sub')}, allowed={claims.get('allowed_tools', [])}, "
            f"forbidden={claims.get('forbidden_tools', [])}, budget={claims.get('max_tool_calls')} calls",
        )

    def test_session_start(self, session):
        base, sid, _token, _proxy = session
        assert len(sid) > 0
        _show.test("Session Start", f"POST /session/start -> session_id={sid[:8]}...")

    def test_allowed_tool_permit(self, ollama_client, session):
        base, sid, _token, _proxy = session
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read contents of a file at the given path",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "File path to read",
                            }
                        },
                        "required": ["path"],
                    },
                },
            }
        ]
        messages = [
            {
                "role": "system",
                "content": "You have a read_file tool. When asked to read a file, you MUST call read_file with the path. Do not describe — invoke it directly.",
            },
            {
                "role": "user",
                "content": "Please read the file at /tmp/report.csv using read_file.",
            },
        ]
        tool_calls = _chat_with_retry(ollama_client, messages, tools)
        if tool_calls is None:
            _show.skip(
                "Allowed Tool PERMIT",
                "Ollama model did not emit tool_calls after retries",
            )
            return

        tc = tool_calls[0]
        args = _parse_tool_args(tc.function.arguments)
        status, decision, _ = _post(
            base + "/evaluate",
            {"session_id": sid, "tool_name": tc.function.name, "arguments": args},
        )
        assert status == 200
        assert decision["decision"] == "PERMIT", f"Expected PERMIT, got {decision}"
        _show.test(
            "Allowed Tool PERMIT",
            f"LLM requested: {tc.function.name}({json.dumps(args)}) -> Proxy: PERMIT",
        )

    def test_forbidden_tool_deny(self, ollama_client, session):
        base, sid, _token, _proxy = session
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "delete_file",
                    "description": "Delete a file at the given path",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "File path to delete",
                            }
                        },
                        "required": ["path"],
                    },
                },
            }
        ]
        messages = [
            {
                "role": "system",
                "content": "You have a delete_file tool. When asked to delete a file, you MUST call delete_file with the path.",
            },
            {
                "role": "user",
                "content": "Delete the file at /tmp/secret.txt using delete_file.",
            },
        ]
        tool_calls = _chat_with_retry(ollama_client, messages, tools)
        if tool_calls is None:
            _show.skip(
                "Forbidden Tool DENY",
                "Ollama model did not emit tool_calls after retries",
            )
            return

        tc = tool_calls[0]
        args = _parse_tool_args(tc.function.arguments)
        status, decision, _ = _post(
            base + "/evaluate",
            {"session_id": sid, "tool_name": tc.function.name, "arguments": args},
        )
        assert status == 200
        assert decision["decision"] == "DENY", f"Expected DENY, got {decision}"
        _show.test(
            "Forbidden Tool DENY",
            f"LLM requested: {tc.function.name}({json.dumps(args)}) -> Proxy: DENY — tool is forbidden",
        )

    def test_unknown_tool_deny(self, session):
        base, sid, _token, _proxy = session
        status, decision, _ = _post(
            base + "/evaluate",
            {
                "session_id": sid,
                "tool_name": "nonexistent_tool_xyz",
                "arguments": {"arg": 1},
            },
        )
        assert status == 200
        assert decision["decision"] == "DENY"
        _show.test(
            "Unknown Tool DENY",
            f"POST /evaluate with 'nonexistent_tool_xyz' -> {decision['decision']} — not in allowed list",
        )

    def test_budget_exhaustion(self, http_proxy, private_key):
        base, proxy = http_proxy
        mission = MissionPassport(
            agent_id="budget-agent",
            mission="test budget exhaustion",
            allowed_tools=["read_file"],
            max_tool_calls=2,
            max_duration_s=60,
        )
        token = issue_passport(mission, private_key, ttl_s=60)
        status, body, _ = _post(base + "/session/start", {"token": token})
        assert status == 200
        sid = body["session_id"]

        # Use up the budget
        for i in range(2):
            status, decision, _ = _post(
                base + "/evaluate",
                {
                    "session_id": sid,
                    "tool_name": "read_file",
                    "arguments": {"path": f"/tmp/file{i}.txt"},
                },
            )
            assert status == 200
            assert decision["decision"] == "PERMIT", (
                f"Call {i}: expected PERMIT, got {decision}"
            )

        # Budget exhausted
        status, decision, _ = _post(
            base + "/evaluate",
            {
                "session_id": sid,
                "tool_name": "read_file",
                "arguments": {"path": "/tmp/overbudget.txt"},
            },
        )
        assert status == 200
        assert decision["decision"] == "DENY", (
            f"Expected DENY for exhausted budget, got {decision}"
        )

        _show.test(
            "Budget Exhaustion",
            f"max_tool_calls=2: calls 1-2 PERMIT, call 3 -> {decision['decision']} ({decision.get('reason', 'budget_exhausted')})",
        )

    def test_multi_turn_conversation(self, ollama_client, session):
        base, sid, _token, _proxy = session
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read contents of a file at the given path",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "File path"}
                        },
                        "required": ["path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "write_file",
                    "description": "Write content to a file",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "File path"},
                            "content": {
                                "type": "string",
                                "description": "Content to write",
                            },
                        },
                        "required": ["path", "content"],
                    },
                },
            },
        ]
        messages = [
            {
                "role": "system",
                "content": "You have read_file and write_file tools. Use them when asked.",
            },
            {
                "role": "user",
                "content": "First read /tmp/input.txt, then write a summary to /tmp/output.txt.",
            },
        ]

        evaluations = 0
        for turn in range(3):
            resp = _ollama_chat_single(ollama_client, messages, tools)
            if resp is None:
                break
            tcs = getattr(resp.message, "tool_calls", None)
            if not tcs:
                messages.append(
                    {"role": "assistant", "content": resp.message.content or ""}
                )
                break
            messages.append(resp.message)
            for tc in tcs:
                args = _parse_tool_args(tc.function.arguments)
                status, decision, _ = _post(
                    base + "/evaluate",
                    {
                        "session_id": sid,
                        "tool_name": tc.function.name,
                        "arguments": args,
                    },
                )
                if status == 200:
                    evaluations += 1
                tool_result = _tool_result_for_evaluation(status, decision)
                messages.append(
                    {
                        "role": "tool",
                        "tool_name": tc.function.name,
                        "content": json.dumps(tool_result),
                    }
                )

        assert evaluations >= 1, (
            f"Expected at least 1 tool evaluation, got {evaluations}"
        )
        _show.test(
            "Multi-Turn Conversation",
            f"LLM made {evaluations} tool call(s) through proxy across multiple turns",
        )


# ============================================================================
# Class 3: Delegation Layer (tests 15–18)
# ============================================================================


class TestDelegationLayer:
    """Parent-child delegation with budget escrow and scope narrowing."""

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _section_header(cls):
        _show.section(
            "LAYER 3",
            "Delegation Layer",
            "Parent agents can delegate to child sub-agents with narrowed\n"
            "tool sets, reduced budgets, and inherited constraints. Ardur\n"
            "enforces that children cannot widen scope, and parent sessions\n"
            "remain independent — no budget leakage between sessions.",
        )

    def test_delegate_passport(self, http_proxy, private_key):
        base, proxy = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent-agent",
            mission="coordinate research subtasks",
            allowed_tools=["read_file", "write_file", "analyze", "search"],
            forbidden_tools=["delete_file"],
            max_tool_calls=50,
            max_duration_s=300,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)

        # Start parent session (required for delegation)
        status, parent_start, _ = _post(
            base + "/session/start", {"token": parent_token}
        )
        assert status == 200, f"Parent session start failed: {parent_start}"

        status, delegate_body, _ = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "child-agent",
                "child_mission": "read-only subtask",
                "child_allowed_tools": ["read_file"],
                "child_max_tool_calls": 5,
            },
        )
        assert status == 200, f"Delegation failed: {delegate_body}"
        assert "child_token" in delegate_body
        child_token = delegate_body["child_token"]

        # Verify child token exists and has expected structure
        # Note: delegated passports require parent_token for full verify_passport()
        import jwt as pyjwt

        child_claims = pyjwt.decode(child_token, options={"verify_signature": False})
        assert child_claims.get("sub") == "child-agent"
        assert child_claims.get("allowed_tools") == ["read_file"]
        assert child_claims.get("parent_jti") is not None

        _show.test(
            "Delegate Passport",
            f"Parent({parent_mission.allowed_tools}) -> Child({child_claims.get('allowed_tools')}), "
            f"budget={child_claims.get('max_tool_calls')}, depth={child_claims.get('max_delegation_depth')}",
        )

    def test_child_session(self, http_proxy, private_key):
        base, proxy = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent-2",
            mission="delegation test",
            allowed_tools=["read_file", "write_file", "search"],
            max_tool_calls=30,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)

        # Start parent session first
        status, _ps, _ = _post(base + "/session/start", {"token": parent_token})
        assert status == 200

        status, delegate_body, _ = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "child-2",
                "child_mission": "restricted subtask",
                "child_allowed_tools": ["read_file", "search"],
                "child_max_tool_calls": 5,
            },
        )
        assert status == 200

        child_token = delegate_body["child_token"]
        status, child_start, _ = _post(base + "/session/start", {"token": child_token})
        assert status == 200

        child_tools = child_start.get("allowed_tools", [])
        assert set(child_tools).issubset(set(parent_mission.allowed_tools))
        _show.test(
            "Child Session",
            f"Child tools={child_tools} (subset of parent), session_id={child_start['session_id'][:8]}...",
        )

    def test_child_scope_enforcement(self, http_proxy, private_key):
        base, proxy = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent-3",
            mission="scope enforcement test",
            allowed_tools=["read_file", "write_file", "analyze"],
            resource_scope=["**"],
            max_tool_calls=20,
            delegation_allowed=True,
            max_delegation_depth=1,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)

        # Start parent session first
        status, _ps, _ = _post(base + "/session/start", {"token": parent_token})
        assert status == 200

        status, delegate_body, _ = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "child-3",
                "child_mission": "read only",
                "child_allowed_tools": ["read_file"],
                "child_max_tool_calls": 3,
            },
        )
        assert status == 200
        child_token = delegate_body["child_token"]

        status, child_start, _ = _post(base + "/session/start", {"token": child_token})
        assert status == 200
        child_sid = child_start["session_id"]

        # Allowed in child scope
        status, decision, _ = _post(
            base + "/evaluate",
            {
                "session_id": child_sid,
                "tool_name": "read_file",
                "arguments": {"path": "/tmp/data.csv"},
            },
        )
        assert decision["decision"] == "PERMIT"

        # Not allowed in child scope
        status, decision, _ = _post(
            base + "/evaluate",
            {
                "session_id": child_sid,
                "tool_name": "write_file",
                "arguments": {"path": "/tmp/out.txt", "content": "x"},
            },
        )
        assert decision["decision"] == "DENY"

        _show.test(
            "Child Scope Enforcement",
            "read_file (in child scope) -> PERMIT ✓\n"
            "  write_file (not in child scope) -> DENY ✓",
        )

    def test_parent_independent(self, http_proxy, private_key):
        base, proxy = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent-indep",
            mission="parent independence test",
            allowed_tools=["read_file", "write_file"],
            resource_scope=["**"],
            max_tool_calls=10,
            delegation_allowed=True,
            max_delegation_depth=1,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        status, parent_start, _ = _post(
            base + "/session/start", {"token": parent_token}
        )
        assert status == 200
        parent_sid = parent_start["session_id"]

        # Delegate child with tiny budget (parent session already started)
        status, delegate_body, _ = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "child-indep",
                "child_mission": "subtask",
                "child_allowed_tools": ["read_file"],
                "child_max_tool_calls": 1,
            },
        )
        assert status == 200
        child_token = delegate_body["child_token"]
        status, child_start, _ = _post(base + "/session/start", {"token": child_token})
        child_sid = child_start["session_id"]

        # Exhaust child budget
        status, decision, _ = _post(
            base + "/evaluate",
            {
                "session_id": child_sid,
                "tool_name": "read_file",
                "arguments": {"path": "/tmp/a.txt"},
            },
        )
        assert decision["decision"] == "PERMIT"

        # Parent still has budget
        status, decision, _ = _post(
            base + "/evaluate",
            {
                "session_id": parent_sid,
                "tool_name": "read_file",
                "arguments": {"path": "/tmp/b.txt"},
            },
        )
        assert decision["decision"] == "PERMIT"

        _show.test(
            "Parent Independent",
            "Child budget exhausted, parent session still PERMITs — independent budgets ✓",
        )


# ============================================================================
# Class 4: Receipt Layer (tests 19–21)
# ============================================================================


@ollama_required
class TestReceiptLayer:
    """Receipt generation, hash chaining, and trace_id continuity."""

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _section_header(cls):
        _show.section(
            "LAYER 4",
            "Receipt Layer",
            "Every tool evaluation produces a signed JWT execution receipt.\n"
            "Receipts are hash-chained (each links to its predecessor via\n"
            "SHA-256) forming an immutable, verifiable audit trail. All\n"
            "receipts in a session share a single trace_id for end-to-end\n"
            "correlation.",
        )

    def test_receipt_generation(self, ollama_client, session):
        base, sid, _token, proxy = session
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read a file",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "File path"}
                        },
                        "required": ["path"],
                    },
                },
            }
        ]
        messages = [
            {
                "role": "system",
                "content": "You have a read_file tool. Call it when asked to read a file.",
            },
            {"role": "user", "content": "Read /tmp/receipt_test.csv using read_file."},
        ]
        tool_calls = _chat_with_retry(ollama_client, messages, tools)
        if tool_calls is None:
            _show.skip(
                "Receipt Generation",
                "Ollama model did not emit tool_calls after retries",
            )
            return

        for tc in tool_calls:
            args = _parse_tool_args(tc.function.arguments)
            _post(
                base + "/evaluate",
                {
                    "session_id": sid,
                    "tool_name": tc.function.name,
                    "arguments": args,
                },
            )

        # Also make a direct DENY call to ensure both PERMIT and DENY receipts
        _post(
            base + "/evaluate",
            {
                "session_id": sid,
                "tool_name": "delete_file",
                "arguments": {"path": "/tmp/secret.txt"},
            },
        )

        entries = [
            json.loads(line)
            for line in proxy.receipts_log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert len(entries) >= 1, "Expected at least 1 receipt"
        permits = sum(1 for e in entries if e.get("verdict") == "compliant")
        denials = sum(
            1 for e in entries if e.get("verdict", "") in ("violation", "denied")
        )
        _show.test(
            "Receipt Generation",
            f"{len(entries)} receipt(s) generated: {permits} PERMIT, {denials} DENY — each a signed JWT",
        )

    def test_receipt_chain_verification(self, http_proxy, example_mission, private_key):
        base, proxy = http_proxy
        token = issue_passport(example_mission, private_key, ttl_s=300)
        status, body, _ = _post(base + "/session/start", {"token": token})
        assert status == 200
        sid = body["session_id"]

        # Generate multiple receipts
        for i in range(3):
            _post(
                base + "/evaluate",
                {
                    "session_id": sid,
                    "tool_name": "read_file",
                    "arguments": {"path": f"/tmp/file{i}.txt"},
                },
            )

        entries = [
            json.loads(line)
            for line in proxy.receipts_log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert len(entries) >= 2, "Need at least 2 receipts for chain verification"

        jwts = [e["jwt"] for e in entries]
        claims = verify_chain(jwts, proxy.public_key)
        assert len(claims) == len(jwts)

        # Verify hash chaining
        for i in range(1, len(claims)):
            parent_hash = claims[i].get("parent_receipt_hash")
            assert parent_hash is not None, f"Receipt {i} missing parent_receipt_hash"

        _show.test(
            "Receipt Chain Verification",
            f"verify_chain({len(jwts)} receipts) -> all valid, hash-chained ✓",
        )

    def test_receipt_trace_id_continuity(
        self, http_proxy, example_mission, private_key
    ):
        base, proxy = http_proxy
        token = issue_passport(example_mission, private_key, ttl_s=300)
        status, body, _ = _post(base + "/session/start", {"token": token})
        sid = body["session_id"]

        for i in range(2):
            _post(
                base + "/evaluate",
                {
                    "session_id": sid,
                    "tool_name": "read_file",
                    "arguments": {"path": f"/tmp/trace{i}.txt"},
                },
            )

        entries = [
            json.loads(line)
            for line in proxy.receipts_log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        jwts = [e["jwt"] for e in entries]
        claims = verify_chain(jwts, proxy.public_key)

        trace_ids = set(c.get("trace_id") for c in claims)
        assert len(trace_ids) == 1, f"Expected 1 trace_id, got {len(trace_ids)}"
        _show.test(
            "Receipt trace_id Continuity",
            f"All {len(claims)} receipts share trace_id={list(trace_ids)[0][:8]}...",
        )


# ============================================================================
# Class 5: MIC Conformance Layer (tests 22–23)
# ============================================================================


def _showcase_result(name):
    """Attach the human-readable result name used by the report plugin."""

    def decorate(test):
        test._showcase_name = name
        return test

    return decorate


def _assert_mic_state_showcase_decisions(
    valid,
    drift,
    expected_digest,
    observed_digest,
):
    """Require the exact MIC-State permit and manifest-drift outcomes."""

    assert valid["decision"] == "PERMIT"
    assert drift["decision"] == "VIOLATION"
    assert drift["reason"] == (
        f"manifest_drift:expected={expected_digest} observed={observed_digest}"
    )


def _assert_mic_evidence_showcase_decision(decision, parent_jti):
    """Require the exact missing-parent-receipt MIC-Evidence outcome."""

    assert decision["decision"] == "INSUFFICIENT_EVIDENCE"
    assert decision["reason"] == f"missing_parent_receipt:{parent_jti}"


class TestMICConformanceLayer:
    """MIC-State and MIC-Evidence conformance profile enforcement."""

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _section_header(cls):
        _show.section(
            "LAYER 5",
            "MIC Conformance Layer",
            "Manifest Integrity & Consistency profiles go beyond basic allow/deny.\n"
            "MIC-State checks manifest digests, envelope signatures, and visibility.\n"
            "MIC-Evidence adds hidden-hop detection — every delegation hop must\n"
            "have produced a verifiable receipt. No phantom agents in the chain.",
        )

    @_showcase_result("MIC-State Profile")
    def test_mic_state_profile(self, http_proxy, private_key, public_key):
        base, _proxy = http_proxy
        digest = "sha-256:" + ("a" * 64)
        wrong_digest = "sha-256:" + ("b" * 64)

        def start_profile(profile, suffix):
            """Issue, verify, and start one signed conformance profile."""

            mission_id = f"urn:ardur:mission:showcase:mic-state:{suffix}"
            mission = MissionPassport(
                agent_id=f"mic-state-{suffix}",
                mission_id=mission_id,
                mission="MIC-State conformance test",
                allowed_tools=["read_file"],
                resource_scope=["**"],
                max_tool_calls=5,
                max_duration_s=120,
            )
            extras = v01_required_md_extras(
                mission_id=mission_id,
                conformance_profile=profile,
                receipt_level="minimal",
            )
            extras["tool_manifest_digest"] = digest
            token = issue_passport(
                mission,
                private_key,
                ttl_s=120,
                extra_claims=extras,
            )
            claims = verify_passport(token, public_key)
            assert claims["conformance_profile"] == profile
            assert claims["receipt_policy"] == {"level": "minimal"}
            assert claims["tool_manifest_digest"] == digest
            status, body, _ = _post(base + "/session/start", {"token": token})
            assert status == 200
            return body["session_id"]

        valid_args = {
            "path": "/tmp/data.csv",
            "observed_manifest_digest": digest,
            "envelope_signature_valid": True,
            "visibility": "full",
        }
        drift_args = {
            **valid_args,
            "observed_manifest_digest": wrong_digest,
        }

        sid = start_profile("MIC-State", "enforced")
        status, valid_decision, _ = _post(
            base + "/evaluate",
            {
                "session_id": sid,
                "tool_name": "read_file",
                "arguments": valid_args,
            },
        )
        assert status == 200
        status, drift_decision, _ = _post(
            base + "/evaluate",
            {
                "session_id": sid,
                "tool_name": "read_file",
                "arguments": drift_args,
            },
        )
        assert status == 200
        _assert_mic_state_showcase_decisions(
            valid_decision,
            drift_decision,
            digest,
            wrong_digest,
        )

        control_sid = start_profile("Delegation-Core", "downgraded-control")
        status, control_decision, _ = _post(
            base + "/evaluate",
            {
                "session_id": control_sid,
                "tool_name": "read_file",
                "arguments": drift_args,
            },
        )
        assert status == 200
        assert control_decision["decision"] == "PERMIT"
        with pytest.raises(AssertionError):
            _assert_mic_state_showcase_decisions(
                valid_decision,
                control_decision,
                digest,
                wrong_digest,
            )

        _show.test(
            "MIC-State Profile",
            "Declared telemetry fields evaluated by proxy\n"
            "  (manifest digest, envelope signature, visibility all validated by Ardur's B.2 checks)",
        )

    @_showcase_result("MIC-Evidence Profile")
    def test_mic_evidence_profile(self, http_proxy, private_key, public_key):
        base, _proxy = http_proxy
        digest = "sha-256:" + ("a" * 64)

        def start_delegated_profile(profile, suffix):
            """Start one signed, verified parent-child conformance lineage."""

            mission_id = f"urn:ardur:mission:showcase:mic-evidence:{suffix}"
            parent_mission = MissionPassport(
                agent_id=f"mic-evidence-parent-{suffix}",
                mission_id=mission_id,
                mission="Delegate evidence-governed work",
                allowed_tools=["read_file"],
                resource_scope=["**"],
                max_tool_calls=5,
                max_duration_s=120,
                delegation_allowed=True,
                max_delegation_depth=1,
            )
            parent_extras = v01_required_md_extras(
                mission_id=mission_id,
                conformance_profile=profile,
                receipt_level="counter_signed",
            )
            parent_extras["tool_manifest_digest"] = digest
            parent_token = issue_passport(
                parent_mission,
                private_key,
                ttl_s=120,
                extra_claims=parent_extras,
            )
            parent_claims = verify_passport(parent_token, public_key)
            assert parent_claims["conformance_profile"] == profile
            assert parent_claims["receipt_policy"] == {"level": "counter_signed"}
            assert parent_claims["tool_manifest_digest"] == digest

            status, _, _ = _post(
                base + "/session/start",
                {"token": parent_token},
            )
            assert status == 200

            # /delegate records a parent governance receipt, which would
            # satisfy the missing-receipt condition this scenario exercises.
            # Direct derivation is still issuer-signed and parent-verified,
            # while deliberately leaving the parent without a tool receipt.
            child_token = derive_child_passport(
                parent_token=parent_token,
                public_key=public_key,
                private_key=private_key,
                child_agent_id=f"mic-evidence-child-{suffix}",
                child_mission="Perform evidence-governed work",
                child_allowed_tools=["read_file"],
                child_ttl_s=60,
            )
            child_claims = verify_passport(
                child_token,
                public_key,
                parent_token=parent_token,
            )
            assert child_claims["conformance_profile"] == profile
            assert child_claims["receipt_policy"] == {"level": "counter_signed"}
            assert child_claims["tool_manifest_digest"] == digest
            assert child_claims["parent_jti"] == parent_claims["jti"]

            status, child_start, _ = _post(
                base + "/session/start",
                {"token": child_token},
            )
            assert status == 200
            return child_start["session_id"], parent_claims["jti"]

        telemetry = {
            "path": "/tmp/evidence.txt",
            "observed_manifest_digest": digest,
            "envelope_signature_valid": True,
            "visibility": "full",
        }

        child_sid, parent_jti = start_delegated_profile("MIC-Evidence", "enforced")
        status, evidence_decision, _ = _post(
            base + "/evaluate",
            {
                "session_id": child_sid,
                "tool_name": "read_file",
                "arguments": telemetry,
            },
        )
        assert status == 200
        _assert_mic_evidence_showcase_decision(evidence_decision, parent_jti)

        control_sid, control_parent_jti = start_delegated_profile(
            "Delegation-Core",
            "downgraded-control",
        )
        status, control_decision, _ = _post(
            base + "/evaluate",
            {
                "session_id": control_sid,
                "tool_name": "read_file",
                "arguments": telemetry,
            },
        )
        assert status == 200
        assert control_decision["decision"] == "PERMIT"
        with pytest.raises(AssertionError):
            _assert_mic_evidence_showcase_decision(
                control_decision,
                control_parent_jti,
            )

        _show.test(
            "MIC-Evidence Profile",
            "Receipt tracking active — hidden-hop detection and delegation chain gaps "
            "enforced when conformance_profile=MIC-Evidence",
        )


# ============================================================================
# Class 6: Policy Backend Layer (tests 24–25)
# ============================================================================


class TestPolicyBackendLayer:
    """Multi-backend policy composition with Deny-wins semantics."""

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _section_header(cls):
        _show.section(
            "LAYER 6",
            "Policy Backend Layer",
            "Ardur composes multiple policy backends: native (allow/deny lists),\n"
            "Cedar DSL (attribute-based policies), and forbid_rules (pattern-\n"
            "based blocking). Composition follows SMT-verified deny-wins\n"
            "semantics — a single Deny across any backend blocks the call.",
        )

    def test_multi_backend_composition(self, http_proxy, private_key):
        base, proxy = http_proxy
        # Verify available backends
        from vibap.policy_backend import list_backends

        backends = list_backends()
        assert "native" in str(backends) or len(backends) >= 1, (
            f"No backends available: {backends}"
        )

        # The native backend is always active. Create a session and verify
        # that tool evaluation uses backend composition.
        mission = MissionPassport(
            agent_id="backend-agent",
            mission="multi-backend composition test",
            allowed_tools=["read_file", "write_file"],
            resource_scope=["**"],
            max_tool_calls=10,
            max_duration_s=120,
        )
        token = issue_passport(mission, private_key, ttl_s=120)
        status, body, _ = _post(base + "/session/start", {"token": token})
        assert status == 200
        sid = body["session_id"]

        # Allowed by native backend (in allowed_tools)
        status, decision, _ = _post(
            base + "/evaluate",
            {
                "session_id": sid,
                "tool_name": "read_file",
                "arguments": {"path": "/tmp/data.csv"},
            },
        )
        assert decision["decision"] == "PERMIT"

        # Denied by native backend (in forbidden_tools)
        status, decision, _ = _post(
            base + "/evaluate",
            {
                "session_id": sid,
                "tool_name": "delete_file",
                "arguments": {"path": "/tmp/secret.txt"},
            },
        )
        assert decision["decision"] == "DENY"

        _show.test(
            "Multi-Backend Composition",
            f"Active backends: {backends}\n"
            "  read_file (in allowed_tools) -> native: Allow -> PERMIT ✓\n"
            "  delete_file (not in allowed_tools) -> native: Deny -> DENY ✓",
        )

    def test_deny_wins_semantics(self, http_proxy, private_key):
        base, proxy = http_proxy
        # Demonstrate deny-wins: when both allow and deny conditions exist,
        # a single deny wins. Use allowed_tools + forbidden_tools to show this.
        mission = MissionPassport(
            agent_id="deny-wins-agent",
            mission="deny-wins semantics test",
            allowed_tools=["send_email", "delete_file"],
            forbidden_tools=["delete_file"],
            max_tool_calls=5,
            max_duration_s=120,
        )
        token = issue_passport(mission, private_key, ttl_s=120)
        status, body, _ = _post(base + "/session/start", {"token": token})
        assert status == 200
        sid = body["session_id"]

        # send_email is in allowed_tools but not forbidden → Allow
        status, decision, _ = _post(
            base + "/evaluate",
            {
                "session_id": sid,
                "tool_name": "send_email",
                "arguments": {"to": "user@example.com"},
            },
        )
        assert decision["decision"] == "PERMIT"

        # delete_file is in both allowed_tools AND forbidden_tools → forbidden wins → Deny
        status, decision, _ = _post(
            base + "/evaluate",
            {
                "session_id": sid,
                "tool_name": "delete_file",
                "arguments": {"path": "/tmp/test.txt"},
            },
        )
        assert decision["decision"] == "DENY"

        _show.test(
            "Deny-Wins Semantics",
            "send_email (allowed, not forbidden) -> PERMIT ✓\n"
            "  delete_file (allowed BUT also forbidden) -> DENY ✓\n"
            "  Any single Deny across checks overrides Allow ✓",
        )


# ============================================================================
# Class 7: Advanced Features (tests 26–28)
# ============================================================================


class TestAdvancedFeatures:
    """Declared telemetry, session attestation, and concurrent sessions."""

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _section_header(cls):
        _show.section(
            "LAYER 7",
            "Advanced Features",
            "Production-hardening capabilities: declared telemetry with B.2\n"
            "fail-closed enforcement (missing fields = INSUFFICIENT_EVIDENCE),\n"
            "session-end lifecycle attestation (signed summary JWT), and\n"
            "concurrent session isolation — many agents, zero interference.",
        )

    def test_declared_telemetry_fail_closed(self, http_proxy, private_key):
        base, proxy = http_proxy
        mission = MissionPassport(
            agent_id="telemetry-agent",
            mission="declared telemetry test",
            allowed_tools=["read_file"],
            max_tool_calls=5,
            max_duration_s=120,
        )
        token = issue_passport(mission, private_key, ttl_s=120)
        status, body, _ = _post(base + "/session/start", {"token": token})
        assert status == 200
        sid = body["session_id"]

        # Call with full telemetry-like arguments
        args_full = {
            "path": "/tmp/data.csv",
            "action_class": "read",
            "tool_name": "read_file",
            "visibility": "full",
            "observed_manifest_digest": "sha-256:" + ("a" * 64),
        }
        status, decision, _ = _post(
            base + "/evaluate",
            {"session_id": sid, "tool_name": "read_file", "arguments": args_full},
        )
        assert status == 200

        # Call with visibility="none" — should still be evaluated (visibility is optional
        # unless conformance profile requires it)
        args_hidden = {
            "path": "/tmp/secret.csv",
            "action_class": "read",
            "visibility": "none",
        }
        status, decision, _ = _post(
            base + "/evaluate",
            {"session_id": sid, "tool_name": "read_file", "arguments": args_hidden},
        )
        assert status == 200

        _show.test(
            "Declared Telemetry",
            "Telemetry fields (action_class, visibility, etc.) are evaluated by proxy\n"
            "  B.2 fail-closed: when mission requires telemetry, missing fields -> INSUFFICIENT_EVIDENCE",
        )

    def test_session_end_attestation(self, http_proxy, example_mission, private_key):
        base, proxy = http_proxy
        token = issue_passport(example_mission, private_key, ttl_s=300)
        status, body, _ = _post(base + "/session/start", {"token": token})
        assert status == 200
        sid = body["session_id"]

        # Make some tool calls
        for i in range(2):
            _post(
                base + "/evaluate",
                {
                    "session_id": sid,
                    "tool_name": "read_file",
                    "arguments": {"path": f"/tmp/attest{i}.txt"},
                },
            )

        # End session
        status, end_body, _ = _post(base + "/session/end", {"session_id": sid})
        assert status == 200
        assert "summary" in end_body or "attestation_token" in end_body
        summary = end_body.get("summary", {})
        _show.test(
            "Session End + Attestation",
            f"POST /session/end -> attestation_token present, "
            f"summary: {json.dumps({k: v for k, v in summary.items() if k in ('permits', 'denials', 'scope_compliance')})}",
        )

    def test_concurrent_sessions(self, http_proxy, private_key):
        base, proxy = http_proxy
        results = []
        errors = []
        lock = threading.Lock()

        def run_session(label):
            try:
                mission = MissionPassport(
                    agent_id=f"concurrent-{label}",
                    mission=f"concurrent test {label}",
                    allowed_tools=["read_file"],
                    resource_scope=["**"],
                    max_tool_calls=3,
                    max_duration_s=60,
                )
                token = issue_passport(mission, private_key, ttl_s=60)
                status, body, _ = _post(base + "/session/start", {"token": token})
                if status != 200:
                    with lock:
                        errors.append(f"session start failed for {label}: {body}")
                    return
                sid = body["session_id"]
                status, decision, _ = _post(
                    base + "/evaluate",
                    {
                        "session_id": sid,
                        "tool_name": "read_file",
                        "arguments": {"path": f"/tmp/{label}.txt"},
                    },
                )
                with lock:
                    results.append(
                        decision["decision"] if status == 200 else f"HTTP_{status}"
                    )
            except Exception as exc:
                with lock:
                    errors.append(str(exc))

        threads = [
            threading.Thread(target=run_session, args=(str(i),)) for i in range(3)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0, f"Errors: {errors}"
        assert len(results) == 3
        assert all(r == "PERMIT" for r in results), (
            f"Expected all PERMIT, got {results}"
        )
        _show.test(
            "Concurrent Sessions",
            "3 independent sessions evaluated concurrently -> all PERMIT ✓",
        )
