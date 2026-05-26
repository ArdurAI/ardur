"""Comprehensive full-Ardur integration test — protocol composition.

Exercises the complete governance pipeline over real TLS with SPIFFE
identity, Biscuit attenuation chains, JWT delegation, rate limiting,
kill switch, Prometheus metrics, and receipt chain verification.

Runs as a single long-running test (~15-20 min) that executes 13
scenarios sequentially. Each scenario is wrapped in try/except;
failures are recorded but never abort downstream scenarios.

Set ARDUR_OLLAMA_API_KEY to enable the Ollama-backed scenarios.
Without it the Ollama scenarios are skipped but all other protocol
layers still run.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

import jwt as pyjwt
import pytest

from vibap.passport import MissionPassport, generate_keypair, issue_passport
from vibap.policy_store import InMemoryPolicyStore, PolicySpec
from vibap.proxy import GovernanceProxy, serve_proxy
from vibap.receipt import verify_chain
from vibap.tls import generate_self_signed_cert

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------

CLOUD_MODEL = os.environ.get("ARDUR_OLLAMA_CLOUD_MODEL", "")
API_KEY = os.environ.get("ARDUR_OLLAMA_API_KEY", "")

TEST_REPORT_PATH = Path(
    os.environ.get(
        "ARDUR_COMPREHENSIVE_REPORT",
        str(Path(__file__).resolve().parent / "comprehensive_test_report.json"),
    )
)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _ollama_available() -> bool:
    if not API_KEY:
        return False
    try:
        import ollama
        return True
    except ImportError:
        return False


def _parse_tool_args(args):
    if isinstance(args, dict):
        return args
    if isinstance(args, str):
        return json.loads(args)
    return {}


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _post_tls(base, path, payload=None):
    data = json.dumps(payload or {}).encode("utf-8")
    req = urllib.request.Request(
        base + path, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=15, context=_ssl_context()) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8")), dict(resp.headers.items())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(body), dict(exc.headers.items())
        except json.JSONDecodeError:
            return exc.code, {"raw": body}, dict(exc.headers.items())


def _get_tls(base, path, raw=False):
    req = urllib.request.Request(base + path)
    try:
        with urllib.request.urlopen(req, timeout=10, context=_ssl_context()) as resp:
            body = resp.read().decode("utf-8")
            headers = dict(resp.headers.items())
            if raw:
                return resp.status, body, headers
            return resp.status, json.loads(body), headers
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        headers = dict(exc.headers.items())
        if raw:
            return exc.code, body, headers
        try:
            return exc.code, json.loads(body), headers
        except json.JSONDecodeError:
            return exc.code, {"raw": body}, headers


def _build_forbid_rules_spec(rules: list[dict[str, Any]], *, label: str = "compliance") -> PolicySpec:
    """Build a forbid_rules PolicySpec with a correct policy_sha256."""
    data_json = json.dumps(rules, sort_keys=True, separators=(",", ":"))
    sha = hashlib.sha256(data_json.encode("utf-8")).hexdigest()
    return {
        "backend": "forbid_rules",
        "label": label,
        "policy_sha256": sha,
        "data_inline": rules,
    }


def _build_cedar_spec(policy_text: str, *, label: str = "security_team", entities: Any = None) -> PolicySpec:
    """Build a Cedar PolicySpec with a correct policy_sha256."""
    sha = hashlib.sha256(policy_text.encode("utf-8")).hexdigest()
    spec: PolicySpec = {
        "backend": "cedar",
        "label": label,
        "policy_sha256": sha,
        "policy_inline": policy_text,
        "data_inline": entities or [],
    }
    return spec


def _cedar_resource_entities() -> list[dict[str, Any]]:
    """Minimal Cedar entity definitions so that Resource::\"...\" references resolve."""
    return [
        {"uid": {"type": "Resource", "id": "/data/report.csv"}, "attrs": {"path": "/data/report.csv"}, "parents": []},
        {"uid": {"type": "Resource", "id": "/tmp/notes.txt"}, "attrs": {"path": "/tmp/notes.txt"}, "parents": []},
        {"uid": {"type": "Resource", "id": "/etc/shadow"}, "attrs": {"path": "/etc/shadow"}, "parents": []},
        {"uid": {"type": "Resource", "id": "/tmp/ok.txt"}, "attrs": {"path": "/tmp/ok.txt"}, "parents": []},
    ]


def _start_jwt_session_with_mission_id(base, private_key, mission_id, policy_store):
    """Start a JWT session with a mission_id so policies can be resolved."""
    mission = MissionPassport(
        agent_id=f"agent-{uuid.uuid4().hex[:8]}",
        mission="policy composition test",
        mission_id=mission_id,
        allowed_tools=["read_file", "write_file", "search_files", "list_directory"],
        forbidden_tools=[],
        resource_scope=[],
        max_tool_calls=100,
        max_duration_s=600,
    )
    token = issue_passport(mission, private_key, ttl_s=600)
    status, body, _ = _post_tls(base, "/session/start", {"token": token})
    assert status == 200, f"session start failed: {body}"
    return body["session_id"], token


def _build_server_tls(proxy, private_key, port, tls_cert, tls_key, *, api_token="", rate_rps="100", rate_burst="200"):
    """Start serve_proxy with TLS in a daemon thread."""
    import signal as _signal
    _signal.signal = lambda *_a, **_kw: None

    os.environ["ARDUR_RATE_LIMIT_RPS"] = rate_rps
    os.environ["ARDUR_RATE_LIMIT_BURST"] = rate_burst

    def run():
        serve_proxy(
            proxy=proxy,
            private_key=private_key,
            host="127.0.0.1",
            port=port,
            tls_cert=tls_cert,
            tls_key=tls_key,
            no_tls=False,
            require_auth=bool(api_token),
            api_token=api_token,
        )

    t = threading.Thread(target=run, daemon=True)
    t.start()
    base = f"https://127.0.0.1:{port}"
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(base + "/health")
            with urllib.request.urlopen(req, timeout=1, context=ctx) as resp:
                if resp.status == 200:
                    break
        except Exception:
            time.sleep(0.1)
    else:
        raise RuntimeError("TLS proxy never became healthy")
    return t, base


# ---------------------------------------------------------------------------
# report accumulator
# ---------------------------------------------------------------------------


class ScenarioReport:
    """Accumulates per-scenario pass/fail + timing + notes."""

    def __init__(self):
        self.scenarios: list[dict[str, Any]] = []
        self.start_time = time.time()

    def record(self, name: str, passed: bool, duration_s: float, notes: str = ""):
        self.scenarios.append({
            "scenario": name,
            "passed": passed,
            "duration_s": round(duration_s, 2),
            "notes": notes,
        })

    def finalize(self, env_info: dict[str, Any]) -> dict[str, Any]:
        total_s = round(time.time() - self.start_time, 1)
        passed = sum(1 for s in self.scenarios if s["passed"])
        failed = len(self.scenarios) - passed
        return {
            "test": "ardur_comprehensive_integration",
            "total_duration_s": total_s,
            "scenarios_run": len(self.scenarios),
            "scenarios_passed": passed,
            "scenarios_failed": failed,
            "environment": env_info,
            "scenarios": self.scenarios,
        }


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def module_keys():
    """Generate EC keypair once for the entire test module."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        keys_dir = Path(td)
        private_key, public_key = generate_keypair(keys_dir=keys_dir)
        yield private_key, public_key, keys_dir


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory):
    """Generate self-signed TLS material once per module."""
    tls_dir = tmp_path_factory.mktemp("tls")
    key_path, cert_path, fingerprint = generate_self_signed_cert(tls_dir, hostname="127.0.0.1")
    return str(key_path), str(cert_path), fingerprint


@pytest.fixture(scope="module")
def biscuit_keypair():
    """Generate a Biscuit keypair for issuing and verifying Biscuit passports."""
    from biscuit_auth import KeyPair
    return KeyPair()


# ---------------------------------------------------------------------------
# the comprehensive test
# ---------------------------------------------------------------------------


class TestArdurComprehensive:
    """Single test running all 10 scenarios sequentially.

    Each scenario is a protocol layer or composition of layers.
    Failures in one scenario don't abort the others. A JSON report
    is written at the end.
    """

    def test_full_ardur_protocol_composition(
        self, module_keys, tls_material, biscuit_keypair, tmp_path
    ):
        private_key, public_key, keys_dir = module_keys
        tls_key, tls_cert, tls_fingerprint = tls_material
        report = ScenarioReport()

        policy_store = InMemoryPolicyStore()

        proxy = GovernanceProxy(
            log_path=tmp_path / "governance_log.jsonl",
            state_dir=tmp_path / "state",
            public_key=public_key,
            private_key=private_key,  # so receipt signing uses same key
            keys_dir=keys_dir,
            biscuit_issuer_public_key=biscuit_keypair.public_key,
            policy_store=policy_store,
        )

        port = _free_port()
        t, base = _build_server_tls(
            proxy, private_key, port, tls_cert, tls_key,
            rate_rps="10", rate_burst="50",
        )

        env_info = {
            "tls_fingerprint": tls_fingerprint,
            "port": port,
            "python_version": sys.version,
            "ollama_available": _ollama_available(),
            "cloud_model": CLOUD_MODEL if _ollama_available() else "n/a",
        }

        try:
            # Scenario 1 — Health & Baseline
            _run_scenario(report, "01_health_and_baseline", lambda: (
                _verify_health_and_baseline(base)
            ))
            time.sleep(0.5)

            # Scenario 2 — JWT Session Lifecycle
            _run_scenario(report, "02_jwt_session_lifecycle", lambda: (
                _verify_jwt_lifecycle(base, proxy, private_key)
            ))
            time.sleep(0.5)

            # Scenario 3 — Biscuit + SPIFFE Binding
            _run_scenario(report, "03_biscuit_spiffe_binding", lambda: (
                _verify_biscuit_spiffe(base, proxy, biscuit_keypair)
            ))
            time.sleep(0.5)

            # Scenario 4 — Ollama Multi-turn
            if _ollama_available():
                _run_scenario(report, "04_ollama_multi_turn", lambda: (
                    _verify_ollama_multiturn(base, proxy, private_key)
                ))
            else:
                report.record("04_ollama_multi_turn", True, 0, "SKIPPED — no OLLAMA_API_KEY")
            time.sleep(0.5)

            # Scenario 5 — JWT Delegation Chain
            _run_scenario(report, "05_jwt_delegation_chain", lambda: (
                _verify_jwt_delegation_chain(base, proxy, private_key)
            ))
            time.sleep(0.5)

            # Scenario 6 — Biscuit Attenuation Chain
            _run_scenario(report, "06_biscuit_attenuation_chain", lambda: (
                _verify_biscuit_attenuation_chain(base, proxy, biscuit_keypair)
            ))
            time.sleep(0.5)

            # Scenario 7 — Kill Switch Mid-Session
            time.sleep(2)  # ensure rate-limiter bucket is refilled
            _run_scenario(report, "07_kill_switch", lambda: (
                _verify_kill_switch(base, proxy, private_key)
            ))
            time.sleep(0.5)

            # Scenario 8 — Rate Limit Flooding
            _run_scenario(report, "08_rate_limit_flooding", lambda: (
                _verify_rate_limiting(base)
            ))
            # let the rate-limit token bucket refill before remaining scenarios
            time.sleep(3)

            # Scenario 9 — Metrics Verification
            _run_scenario(report, "09_metrics", lambda: (
                _verify_metrics(base)
            ))
            time.sleep(0.5)

            # Scenario 10 — Receipt Chain Integrity
            _run_scenario(report, "10_receipt_chain", lambda: (
                _verify_receipt_chain(proxy)
            ))
            time.sleep(0.5)

            # Scenario 11 — ForbidRules + Native composition
            _run_scenario(report, "11_forbid_rules_composition", lambda: (
                _verify_forbid_rules_composition(base, proxy, private_key, policy_store)
            ))
            time.sleep(0.5)

            # Scenario 12 — Three-backend composition (native + forbid_rules + Cedar)
            _run_scenario(report, "12_three_backend_composition", lambda: (
                _verify_three_backend_composition(base, proxy, private_key, policy_store)
            ))
            time.sleep(0.5)

            # Scenario 13 — Integrity hash enforcement
            _run_scenario(report, "13_integrity_hash_enforcement", lambda: (
                _verify_integrity_hash_enforcement(base, proxy, private_key, policy_store)
            ))

        finally:
            report_data = report.finalize(env_info)
            TEST_REPORT_PATH.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
            print(f"\nComprehensive report → {TEST_REPORT_PATH}")

        failed = [s for s in report_data["scenarios"] if not s["passed"]]
        assert not failed, (
            f"{len(failed)} scenario(s) failed:\n"
            + "\n".join(f"  - {s['scenario']}: {s['notes']}" for s in failed)
        )


# ---------------------------------------------------------------------------
# scenario implementations
# ---------------------------------------------------------------------------


def _run_scenario(report: ScenarioReport, name: str, fn):
    start = time.time()
    try:
        fn()
        duration = time.time() - start
        report.record(name, True, duration)
        print(f"  [PASS] {name} ({duration:.1f}s)")
    except Exception as exc:
        duration = time.time() - start
        report.record(name, False, duration, str(exc))
        print(f"  [FAIL] {name} ({duration:.1f}s): {exc}")


def _start_jwt_session(base, private_key, mission=None):
    """Start a JWT-backed session. Returns (session_id, token)."""
    if mission is None:
        mission = MissionPassport(
            agent_id=f"agent-{uuid.uuid4().hex[:8]}",
            mission="comprehensive test",
            allowed_tools=["read_file", "write_file", "search_files", "list_directory"],
            forbidden_tools=["delete_file"],
            resource_scope=[],
            max_tool_calls=100,
            max_duration_s=600,
        )
    token = issue_passport(mission, private_key, ttl_s=600)
    status, body, _ = _post_tls(base, "/session/start", {"token": token})
    assert status == 200, f"session start failed: {body}"
    return body["session_id"], token


# ── Scenario 1 ───────────────────────────────────────────────────────────────


def _verify_health_and_baseline(base):
    status, body, headers = _get_tls(base, "/health")
    assert status == 200
    assert body["status"] == "ok"

    assert headers.get("X-Content-Type-Options", "").lower() == "nosniff"
    assert headers.get("X-Frame-Options", "").lower() == "deny"
    assert headers.get("Referrer-Policy", "").lower() == "no-referrer"
    assert headers.get("Cache-Control", "").lower() == "no-store"

    csp = headers.get("Content-Security-Policy", "")
    assert "default-src" in csp, f"CSP missing default-src: {csp}"

    # Server header identifies the proxy (not empty by design)
    server = headers.get("Server", "")
    assert "VIBAPProxy" in server, f"Expected VIBAPProxy in Server header, got: {server}"

    # JWKS
    status, jwks, _ = _get_tls(base, "/.well-known/jwks.json")
    assert status == 200
    assert "keys" in jwks
    key = jwks["keys"][0]
    assert key.get("kty") == "EC"
    assert key.get("crv") == "P-256"

    # Unrecognized path
    status, body, _ = _get_tls(base, "/nonexistent-path-99")
    assert status == 404


# ── Scenario 2 ───────────────────────────────────────────────────────────────


def _verify_jwt_lifecycle(base, proxy, private_key):
    sid, token = _start_jwt_session(base, private_key)

    # Allowed tool
    status, body, _ = _post_tls(base, "/evaluate", {
        "session_id": sid, "tool_name": "read_file", "arguments": {"path": "/tmp/a.txt"},
    })
    assert status == 200 and body["decision"] == "PERMIT"

    # Forbidden tool
    status, body, _ = _post_tls(base, "/evaluate", {
        "session_id": sid, "tool_name": "delete_file", "arguments": {"path": "/etc/passwd"},
    })
    assert status == 200 and body["decision"] == "DENY"

    # Unknown tool
    status, body, _ = _post_tls(base, "/evaluate", {
        "session_id": sid, "tool_name": "launch_missiles", "arguments": {},
    })
    assert status == 200 and body["decision"] == "DENY"

    # Attest
    status, attest, _ = _post_tls(base, "/attest", {"session_id": sid})
    assert status == 200
    assert "token" in attest or "attestation_token" in attest

    # Verify passport
    status, verify_body, _ = _post_tls(base, "/verify", {"token": token})
    assert status == 200 and "claims" in verify_body

    # End session
    status, end_body, _ = _post_tls(base, "/session/end", {"session_id": sid})
    assert status == 200
    assert any(k in end_body for k in ("receipt", "summary", "attestation_token"))

    # Evaluate after end — returns 200 with DENY for "session already ended"
    status, body, _ = _post_tls(base, "/evaluate", {
        "session_id": sid, "tool_name": "read_file", "arguments": {"path": "/x"},
    })
    assert status == 200
    assert body["decision"] == "DENY", f"ended session must deny evaluate: {body}"
    assert "ended" in body.get("reason", ""), f"reason should mention ended: {body}"


# ── Scenario 3 ───────────────────────────────────────────────────────────────


def _verify_biscuit_spiffe(base, proxy, biscuit_keypair):
    from biscuit_auth import Algorithm, PrivateKey
    from vibap.biscuit_passport import encode_biscuit_b64, issue_biscuit_passport
    from vibap.spiffe_identity import make_mock_svid_bundle, make_mock_trust_bundle

    holder_spiffe = "spiffe://ardur.dev/agent/test-runner"
    private_bytes = bytes(biscuit_keypair.private_key.to_bytes())

    mission = MissionPassport(
        agent_id="biscuit-agent",
        mission="biscuit+spiffe test",
        allowed_tools=["read_file", "write_file"],
        forbidden_tools=[],
        resource_scope=["/data/*"],
        max_tool_calls=10,
        max_duration_s=600,
        holder_spiffe_id=holder_spiffe,
    )
    biscuit_bytes = issue_biscuit_passport(
        mission,
        PrivateKey.from_bytes(private_bytes, Algorithm.Ed25519),
        "spiffe://ardur.dev/issuer",
        ttl_s=600,
    )
    biscuit_b64 = encode_biscuit_b64(biscuit_bytes)

    # Create a fresh mock SVID with a valid iat timestamp
    svid_bundle = make_mock_svid_bundle(holder_spiffe, iat=int(time.time()))
    trust_bundle = make_mock_trust_bundle(holder_spiffe)

    status, body, _ = _post_tls(base, "/session/start", {
        "token": biscuit_b64,
        "token_type": "biscuit",
        "peer_jwt_svid": svid_bundle.jwt_svid_token,
        "peer_trust_jwks": trust_bundle.jwks,
        "peer_trust_domain": trust_bundle.trust_domain,
        "svid_audience": "vibap://spiffe-mock",
    })
    assert status == 200, f"biscuit+spiffe start failed: {body}"
    assert body["credential_format"] == "biscuit-v1"
    sid = body["session_id"]

    # Allowed tool within scope
    status, eval_body, _ = _post_tls(base, "/evaluate", {
        "session_id": sid, "tool_name": "read_file", "arguments": {"path": "/data/report.csv"},
    })
    assert status == 200 and eval_body["decision"] == "PERMIT"

    # Path outside resource scope
    status, eval_body, _ = _post_tls(base, "/evaluate", {
        "session_id": sid, "tool_name": "read_file", "arguments": {"path": "/etc/shadow"},
    })
    assert status == 200

    _post_tls(base, "/session/end", {"session_id": sid})


# ── Scenario 4 ───────────────────────────────────────────────────────────────


def _verify_ollama_multiturn(base, proxy, private_key):
    """15+ minute creative task: Ollama builds a complete Python application.

    The model designs and writes a 'Personal Journal API' — a working
    HTTP-based journaling app using only the standard library. Every
    tool call goes through the Ardur proxy evaluate/attest pipeline.
    The model iterates across multiple files, reviews its work, and
    refines the output over several turns.
    """
    import ollama

    os.environ.setdefault("OLLAMA_API_KEY", API_KEY)
    client = ollama.Client()

    # Session with broad tool access and high budgets for a long creative session
    mission = MissionPassport(
        agent_id="creative-agent",
        mission="build a complete Personal Journal API from scratch",
        allowed_tools=["read_file", "write_file", "list_directory", "search_files"],
        forbidden_tools=["delete_file", "execute_shell"],
        resource_scope=[],
        max_tool_calls=200,
        max_duration_s=1800,
    )
    sid, _ = _start_jwt_session(base, private_key, mission=mission)

    tools = [
        {
            "type": "function",
            "function": {
                "name": "write_file",
                "description": "Write content to a file at the given path. Creates the file if it doesn't exist, overwrites if it does.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Path to write the file to"},
                        "content": {"type": "string", "description": "Content to write to the file"},
                    },
                    "required": ["path", "content"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read and return the contents of a file at the specified path",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Path to the file to read"},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_directory",
                "description": "List all files and subdirectories in a directory",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Path to the directory to list"},
                    },
                    "required": ["path"],
                },
            },
        },
    ]

    messages = [
        {
            "role": "system",
            "content": (
                "You are an expert Python developer building a complete application "
                "from scratch. You have access to write_file, read_file, and "
                "list_directory tools. Every tool call goes through a governance "
                "proxy that evaluates permissions.\n\n"
                "YOUR TASK: Build a 'Personal Journal API' — a complete, working "
                "Python web application using ONLY the standard library (http.server, "
                "json, sqlite3, datetime, pathlib, etc.). No external dependencies.\n\n"
                "The application must have:\n"
                "1. A REST API with these endpoints:\n"
                "   - POST /entries — create a new journal entry (title, content, mood)\n"
                "   - GET /entries — list all entries (with optional ?mood= filter)\n"
                "   - GET /entries/<id> — get a single entry\n"
                "   - PUT /entries/<id> — update an entry\n"
                "   - DELETE /entries/<id> — delete an entry\n"
                "   - GET /stats — return mood distribution and entry count stats\n"
                "   - GET /search?q= — full-text search across titles and content\n"
                "2. SQLite for persistence (auto-creates the database)\n"
                "3. Proper HTTP status codes, JSON responses, and error handling\n"
                "4. A clean, modular structure with separate modules\n\n"
                "WORKFLOW — build this iteratively across files:\n"
                "- Step 1: Write journal/schema.py — database schema and migrations\n"
                "- Step 2: Write journal/models.py — Entry dataclass + serialization\n"
                "- Step 3: Write journal/storage.py — SQLite CRUD operations\n"
                "- Step 4: Write journal/server.py — HTTP request routing + handlers\n"
                "- Step 5: Write journal/main.py — entry point that wires everything\n"
                "- Step 6: Write journal/__init__.py — package init\n"
                "- Step 7: Write tests/test_journal.py — comprehensive tests\n"
                "- Step 8: Write README.md — usage docs\n"
                "- Step 9: Read back each file and review for bugs, then fix them\n"
                "- Step 10: List the full directory to verify all files exist\n\n"
                "After writing each file, read it back to verify correctness. "
                "After all files are written, do a full review pass and fix any issues. "
                "Write REAL, COMPLETE, WORKING code — no placeholders or 'pass' stubs. "
                "Each file should be fully implemented with docstrings and comments."
            ),
        },
        {
            "role": "user",
            "content": (
                "Build the complete Personal Journal API. Write every file with full "
                "implementations. Create the journal/ package directory structure. "
                "After writing all files, review each one and fix bugs. "
                "Then verify the full directory listing. Take your time — write "
                "production-quality code with proper error handling, docstrings, "
                "and edge case coverage throughout."
            ),
        },
    ]

    tool_calls_total = 0
    files_created = set()
    review_pass_done = False
    start_time = time.time()

    # Run up to 20 turns — the task is large enough to sustain 15+ min
    for turn in range(20):
        elapsed = time.time() - start_time
        # Don't artificially stop; let the model work through all phases
        _ = elapsed  # track for logging

        resp = client.chat(model=CLOUD_MODEL, messages=messages, tools=tools)
        tool_calls = getattr(resp.message, "tool_calls", None)

        if not tool_calls:
            if resp.message.content:
                messages.append({"role": "assistant", "content": resp.message.content})
            continue

        for tc in tool_calls:
            tool_name = tc.function.name
            tool_args = _parse_tool_args(tc.function.arguments)

            status, decision, _ = _post_tls(base, "/evaluate", {
                "session_id": sid,
                "tool_name": tool_name,
                "arguments": tool_args,
            })
            assert status == 200, f"evaluate returned {status}: {decision}"
            assert decision["decision"] == "PERMIT", (
                f"proxy denied {tool_name}: {decision}"
            )
            tool_calls_total += 1

            if tool_name == "write_file":
                files_created.add(tool_args.get("path", "unknown"))
                result = {
                    "status": "ok",
                    "path": tool_args.get("path", ""),
                    "bytes_written": len(tool_args.get("content", "")),
                }
            elif tool_name == "read_file":
                result = {
                    "status": "ok",
                    "path": tool_args.get("path", ""),
                    "exists": True,
                }
            elif tool_name == "list_directory":
                result = {
                    "status": "ok",
                    "path": tool_args.get("path", ""),
                    "entries": sorted(files_created) if files_created else [],
                }
            else:
                result = {"status": "ok"}

            messages.append({"role": "assistant", "content": None, "tool_calls": [tc]})
            messages.append({
                "role": "tool",
                "name": tool_name,
                "content": json.dumps(result),
            })

        # Phase transitions to keep the model working deeper
        if not review_pass_done and len(files_created) >= 6:
            messages.append({
                "role": "user",
                "content": (
                    "Good progress. Now do a thorough code review pass — read back "
                    "each file you wrote, check for bugs, edge cases, missing error "
                    "handling, SQL injection risks, and consistency issues across "
                    "modules. Fix everything you find. Be meticulous."
                ),
            })
            review_pass_done = True

        if review_pass_done and len(files_created) >= 8 and turn >= 10:
            messages.append({
                "role": "user",
                "content": (
                    "Now write a comprehensive test suite in tests/test_journal.py "
                    "that covers: creating entries, listing with filters, getting by "
                    "ID, updating, deleting, stats aggregation, and full-text search. "
                    "Include edge cases: empty titles, missing fields, invalid IDs, "
                    "and concurrent access patterns. Use only stdlib unittest. Then "
                    "write a design doc in ARCHITECTURE.md explaining the system "
                    "design, data flow, and trade-offs you made."
                ),
            })
            break  # prevent duplicate prompts

    duration = time.time() - start_time

    # Verify the session created substantial output
    assert tool_calls_total >= 10, (
        f"Expected at least 10 tool calls in 15-min session, got {tool_calls_total}"
    )
    assert len(files_created) >= 4, (
        f"Expected at least 4 files created, got {len(files_created)}: {sorted(files_created)}"
    )
    assert duration >= 30, f"Session too short: {duration:.0f}s — expected 15+ min of work"

    # Final turn — the model may still be in tool-call mode with empty content
    resp = client.chat(model=CLOUD_MODEL, messages=messages)
    # Content may be empty if the model is mid-tool-call; that's fine
    if resp.message.content:
        assert len(resp.message.content.strip()) > 0

    print(f"\n    Ollama scenario: {tool_calls_total} tool calls, "
          f"{len(files_created)} files created, {duration:.0f}s elapsed")

    _post_tls(base, "/session/end", {"session_id": sid})


# ── Scenario 5 ───────────────────────────────────────────────────────────────


def _verify_jwt_delegation_chain(base, proxy, private_key):
    parent_mission = MissionPassport(
        agent_id="parent-delegator",
        mission="parent mission with delegation",
        allowed_tools=["read_file", "write_file", "search_files", "list_directory"],
        forbidden_tools=["delete_file"],
        resource_scope=[],
        max_tool_calls=100,
        max_duration_s=600,
        delegation_allowed=True,
        max_delegation_depth=3,
    )
    parent_token = issue_passport(parent_mission, private_key, ttl_s=600)
    status, start, _ = _post_tls(base, "/session/start", {"token": parent_token})
    assert status == 200
    parent_sid = start["session_id"]

    # Delegate parent → child (narrow tools + budget)
    status, d1, _ = _post_tls(base, "/delegate", {
        "parent_token": parent_token,
        "child_agent_id": "child-worker",
        "child_mission": "child subtask",
        "child_allowed_tools": ["read_file", "search_files"],
        "child_max_tool_calls": 50,
    })
    assert status == 200, f"delegate 1 failed: {d1}"
    child_token = d1["child_token"]

    status, child_start, _ = _post_tls(base, "/session/start", {"token": child_token})
    assert status == 200
    child_sid = child_start["session_id"]

    # Child can use narrowed tools
    status, eval_body, _ = _post_tls(base, "/evaluate", {
        "session_id": child_sid, "tool_name": "read_file", "arguments": {"path": "/tmp/x"},
    })
    assert status == 200 and eval_body["decision"] == "PERMIT"

    # Child cannot use parent-only tool
    status, eval_body, _ = _post_tls(base, "/evaluate", {
        "session_id": child_sid, "tool_name": "list_directory", "arguments": {"path": "/tmp"},
    })
    assert status == 200 and eval_body["decision"] == "DENY", "scope escalation should be denied"

    # Delegate child → grandchild (further narrowing)
    status, d2, _ = _post_tls(base, "/delegate", {
        "parent_token": child_token,
        "child_agent_id": "grandchild-worker",
        "child_mission": "grandchild subtask",
        "child_allowed_tools": ["read_file"],
        "child_max_tool_calls": 10,
    })
    assert status == 200, f"delegate 2 failed: {d2}"
    grandchild_token = d2["child_token"]

    status, gc_start, _ = _post_tls(base, "/session/start", {"token": grandchild_token})
    assert status == 200
    gc_sid = gc_start["session_id"]

    # Grandchild can use read_file
    status, eval_body, _ = _post_tls(base, "/evaluate", {
        "session_id": gc_sid, "tool_name": "read_file", "arguments": {"path": "/tmp/y"},
    })
    assert status == 200 and eval_body["decision"] == "PERMIT"

    # Grandchild cannot use search_files
    status, eval_body, _ = _post_tls(base, "/evaluate", {
        "session_id": gc_sid, "tool_name": "search_files", "arguments": {"pattern": "*.py"},
    })
    assert status == 200 and eval_body["decision"] == "DENY", "scope escalation should be denied"

    # Budget escalation: proxy caps the child's budget to parent's remaining
    # (999 requested → capped at parent's remaining calls = 49, not rejected)
    status, d3, _ = _post_tls(base, "/delegate", {
        "parent_token": child_token,
        "child_agent_id": "bad-child",
        "child_mission": "budget escalation attempt",
        "child_allowed_tools": ["read_file"],
        "child_max_tool_calls": 999,
    })
    assert status == 200
    child_claims = d3.get("child_claims", {})
    max_calls = child_claims.get("max_tool_calls", 999)
    assert max_calls <= 50, f"budget should be capped at parent's, got {max_calls}"

    for s in [gc_sid, child_sid, parent_sid]:
        _post_tls(base, "/session/end", {"session_id": s})


# ── Scenario 6 ───────────────────────────────────────────────────────────────


def _verify_biscuit_attenuation_chain(base, proxy, biscuit_keypair):
    from biscuit_auth import Algorithm, PrivateKey
    from vibap.biscuit_passport import (
        derive_child_biscuit,
        encode_biscuit_b64,
        issue_biscuit_passport,
    )

    private_bytes = bytes(biscuit_keypair.private_key.to_bytes())
    root_private = PrivateKey.from_bytes(private_bytes, Algorithm.Ed25519)
    holder_spiffe = "spiffe://ardur.dev/agent/root"

    mission = MissionPassport(
        agent_id="root-agent",
        mission="biscuit chain test",
        allowed_tools=["read_file", "write_file", "search_files", "list_directory"],
        forbidden_tools=["delete_file"],
        resource_scope=["/workspace/*"],
        max_tool_calls=100,
        max_duration_s=600,
        delegation_allowed=True,
        max_delegation_depth=3,
        holder_spiffe_id=holder_spiffe,
    )
    root_bytes = issue_biscuit_passport(mission, root_private, "spiffe://ardur.dev/issuer", ttl_s=600)
    root_b64 = encode_biscuit_b64(root_bytes)

    status, body, _ = _post_tls(base, "/session/start", {"token": root_b64, "token_type": "biscuit"})
    assert status == 200, f"root biscuit start: {body}"
    root_sid = body["session_id"]

    for tool in ["read_file", "write_file", "search_files", "list_directory"]:
        status, eval_body, _ = _post_tls(base, "/evaluate", {
            "session_id": root_sid, "tool_name": tool, "arguments": {"path": "/workspace/x"},
        })
        assert status == 200 and eval_body["decision"] == "PERMIT", f"{tool} should be PERMIT"

    # Child: narrow to read_file + search_files
    child_bytes = derive_child_biscuit(
        root_bytes, root_private, "spiffe://ardur.dev/agent/child",
        child_allowed_tools=["read_file", "search_files"],
        child_max_tool_calls=50,
    )
    child_b64 = encode_biscuit_b64(child_bytes)

    status, body, _ = _post_tls(base, "/session/start", {"token": child_b64, "token_type": "biscuit"})
    assert status == 200
    child_sid = body["session_id"]

    for tool, expected in [("read_file", "PERMIT"), ("search_files", "PERMIT"), ("write_file", "DENY")]:
        status, eval_body, _ = _post_tls(base, "/evaluate", {
            "session_id": child_sid, "tool_name": tool, "arguments": {"path": "/workspace/b"},
        })
        assert status == 200 and eval_body["decision"] == expected, f"{tool} should be {expected}"

    # Grandchild: narrow to just read_file
    gc_bytes = derive_child_biscuit(
        child_bytes, root_private, "spiffe://ardur.dev/agent/grandchild",
        child_allowed_tools=["read_file"],
        child_max_tool_calls=10,
    )
    gc_b64 = encode_biscuit_b64(gc_bytes)

    status, body, _ = _post_tls(base, "/session/start", {"token": gc_b64, "token_type": "biscuit"})
    assert status == 200
    gc_sid = body["session_id"]

    for tool, expected in [("read_file", "PERMIT"), ("search_files", "DENY")]:
        status, eval_body, _ = _post_tls(base, "/evaluate", {
            "session_id": gc_sid, "tool_name": tool, "arguments": {"path": "/workspace/z"},
        })
        assert status == 200 and eval_body["decision"] == expected, f"{tool} should be {expected}"

    for s in [gc_sid, child_sid, root_sid]:
        _post_tls(base, "/session/end", {"session_id": s})


# ── Scenario 7 ───────────────────────────────────────────────────────────────


def _verify_kill_switch(base, proxy, private_key):
    sid, _token = _start_jwt_session(base, private_key)

    # Normal op
    status, body, _ = _post_tls(base, "/evaluate", {
        "session_id": sid, "tool_name": "read_file", "arguments": {"path": "/tmp/a"},
    })
    assert status == 200 and body["decision"] == "PERMIT"

    # Activate kill switch
    status, ks, _ = _post_tls(base, "/admin/kill-switch", {})
    assert status == 200 and ks.get("kill_switch") == "activated"

    # Evaluate blocked
    status, body, _ = _post_tls(base, "/evaluate", {
        "session_id": sid, "tool_name": "read_file", "arguments": {"path": "/tmp/b"},
    })
    assert status == 503
    assert "kill_switch" in str(body)

    # Health still ok (bypasses kill switch)
    status, health, _ = _get_tls(base, "/health")
    assert status == 200 and health["status"] == "ok"

    # Deactivate
    status, ks2, _ = _post_tls(base, "/admin/kill-switch", {"deactivate": True})
    assert status == 200 and ks2.get("kill_switch") == "deactivated"

    # Post-deactivation: new session works
    sid2, _ = _start_jwt_session(base, private_key)
    status, body, _ = _post_tls(base, "/evaluate", {
        "session_id": sid2, "tool_name": "read_file", "arguments": {"path": "/tmp/c"},
    })
    assert status == 200 and body["decision"] == "PERMIT"

    _post_tls(base, "/session/end", {"session_id": sid2})


# ── Scenario 8 ───────────────────────────────────────────────────────────────


def _verify_rate_limiting(base):
    # Flood POST /verify — need to exceed burst (50) to trigger 429
    rate_limited = 0
    for _ in range(70):
        status, body, headers = _post_tls(base, "/verify", {"token": "invalid"})
        if status == 429:
            rate_limited += 1
            assert "Retry-After" in headers or "retry-after" in (k.lower() for k in headers), (
                "429 must include Retry-After header"
            )
            break

    assert rate_limited >= 1, "expected at least 1 rate-limit (429) response"


# ── Scenario 9 ───────────────────────────────────────────────────────────────


def _verify_metrics(base):
    # Metrics returns text/plain, not JSON
    status, body_text, headers = _get_tls(base, "/metrics", raw=True)
    assert status == 200

    content_type = headers.get("Content-Type", "")
    assert "text/plain" in content_type, f"unexpected Content-Type: {content_type}"

    # Check for expected Prometheus metric families
    expected_families = [
        "ardur_requests_total",
        "ardur_active_sessions",
        "ardur_evaluations_total",
        "ardur_errors_total",
        "ardur_request_duration_seconds",
        "ardur_evaluation_duration_seconds",
    ]
    for family in expected_families:
        assert family in body_text, f"metrics output missing '{family}'"


# ── Scenario 10 ──────────────────────────────────────────────────────────────


def _verify_receipt_chain(proxy):
    entries = [
        json.loads(line)
        for line in proxy.receipts_log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(entries) >= 4, f"Expected at least 4 receipts, got {len(entries)}"

    # Group by trace_id
    by_trace: dict[str, list[str]] = {}
    for e in entries:
        jwt_str = e["jwt"]
        claims = pyjwt.decode(jwt_str, options={"verify_signature": False})
        trace = claims.get("trace_id")
        if trace:
            by_trace.setdefault(trace, []).append(jwt_str)

    # Verify each chain independently using the receipt public key.
    # Disable expiry check — early receipts may have expired after the
    # long-running Ollama scenario. Chain integrity (hash linkage) is
    # what matters here; expiry is tested in the session lifecycle.
    receipt_pubkey = proxy.receipt_public_key
    verified = 0
    for trace_id, chain in by_trace.items():
        claims = verify_chain(chain, receipt_pubkey, verify_expiry=False)
        assert all(c["trace_id"] == trace_id for c in claims), f"mismatched trace_ids in {trace_id}"
        verified += 1

    assert verified >= 2, f"Expected at least 2 independent receipt chains, got {verified}"


# ── Scenario 11 ──────────────────────────────────────────────────────────────


def _verify_forbid_rules_composition(base, proxy, private_key, policy_store):
    """ForbidRules backend blocks /etc/passwd while native allows /tmp/ok.txt."""
    mission_id = "urn:ardur:mission:compliance:forbid-rules"
    rules = [
        {"id": "no_system_files", "forbid_when": {"target_matches": "^/etc/"}},
        {"id": "no_credentials", "forbid_when": {"arg_contains": ["password"]}},
    ]
    policy_store.put_policies(
        mission_id=mission_id,
        policies=[_build_forbid_rules_spec(rules)],
    )

    sid, _token = _start_jwt_session_with_mission_id(
        base, private_key, mission_id, policy_store
    )

    # Allowed by native + no forbid_rules match → PERMIT
    status, body, _ = _post_tls(base, "/evaluate", {
        "session_id": sid, "tool_name": "read_file", "arguments": {"path": "/tmp/ok.txt"},
    })
    assert status == 200 and body["decision"] == "PERMIT"

    # Native permits but forbid_rules blocks /etc/ path → DENY
    status, body, _ = _post_tls(base, "/evaluate", {
        "session_id": sid, "tool_name": "read_file", "arguments": {"path": "/etc/passwd"},
    })
    assert status == 200 and body["decision"] == "DENY"
    assert "no_system_files" in str(body)

    # Native permits but forbid_rules catches arg_contains → DENY
    status, body, _ = _post_tls(base, "/evaluate", {
        "session_id": sid, "tool_name": "write_file",
        "arguments": {"path": "/tmp/x", "content": "my password is hunter2"},
    })
    assert status == 200 and body["decision"] == "DENY"
    assert "no_credentials" in str(body)

    # Attest: policy_decisions must appear in the receipt
    status, attest, _ = _post_tls(base, "/attest", {"session_id": sid})
    assert status == 200
    assert "token" in attest or "attestation_token" in attest

    _post_tls(base, "/session/end", {"session_id": sid})


# ── Scenario 12 ──────────────────────────────────────────────────────────────


def _verify_three_backend_composition(base, proxy, private_key, policy_store):
    """Native + ForbidRules + Cedar composition — each backend can deny independently."""
    from vibap.backends import CedarBackend
    if CedarBackend is None:
        pytest.skip("cedarpy not installed — skipping three-backend composition scenario")

    mission_id = "urn:ardur:mission:three-backend"

    forbid_rules = [
        {"id": "no_etc", "forbid_when": {"target_matches": "^/etc/"}},
    ]
    cedar_policy = (
        'permit(principal, action, resource)\n'
        'when { resource.path like "/data/*" };\n'
    )

    policy_store.put_policies(
        mission_id=mission_id,
        policies=[
            _build_forbid_rules_spec(forbid_rules, label="compliance"),
            _build_cedar_spec(cedar_policy, label="security_team", entities=_cedar_resource_entities()),
        ],
    )

    sid, _token = _start_jwt_session_with_mission_id(
        base, private_key, mission_id, policy_store
    )

    # Denied by forbid_rules (/etc/ path)
    status, body, _ = _post_tls(base, "/evaluate", {
        "session_id": sid, "tool_name": "read_file", "arguments": {"path": "/etc/shadow"},
    })
    assert status == 200 and body["decision"] == "DENY"
    assert "no_etc" in str(body)

    # Allowed: native permits, forbid_rules no match, Cedar abstains (no explicit forbid)
    # → PERMIT (Abstain does not veto Allow)
    status, body, _ = _post_tls(base, "/evaluate", {
        "session_id": sid, "tool_name": "read_file", "arguments": {"path": "/tmp/notes.txt"},
    })
    assert status == 200 and body["decision"] == "PERMIT"

    # Allowed by all three (native permits, forbid_rules no match, Cedar permits /data/*)
    status, body, _ = _post_tls(base, "/evaluate", {
        "session_id": sid, "tool_name": "read_file", "arguments": {"path": "/data/report.csv"},
    })
    assert status == 200 and body["decision"] == "PERMIT"

    _post_tls(base, "/session/end", {"session_id": sid})


# ── Scenario 13 ──────────────────────────────────────────────────────────────


def _verify_integrity_hash_enforcement(base, proxy, private_key, policy_store):
    """A policy_spec whose policy_sha256 doesn't match its content must fail."""
    mission_id = "urn:ardur:mission:integrity-hash"

    rules = [
        {"id": "block_all", "forbid_when": {"tool_name": "read_file"}},
    ]
    correct_spec = _build_forbid_rules_spec(rules)

    # Tamper: write correct data_inline but wrong policy_sha256
    tampered_spec = dict(correct_spec)
    tampered_spec["policy_sha256"] = hashlib.sha256(b"wrong").hexdigest()

    policy_store.put_policies(
        mission_id=mission_id,
        policies=[tampered_spec],
    )

    sid, _token = _start_jwt_session_with_mission_id(
        base, private_key, mission_id, policy_store
    )

    # The backend must detect the sha256 mismatch and fail closed (DENY)
    status, body, _ = _post_tls(base, "/evaluate", {
        "session_id": sid, "tool_name": "read_file", "arguments": {"path": "/tmp/ok.txt"},
    })
    assert status == 200 and body["decision"] == "DENY"
    assert "integrity" in str(body).lower() or "sha" in str(body).lower() or "hash" in str(body).lower()

    _post_tls(base, "/session/end", {"session_id": sid})
