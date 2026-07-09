from __future__ import annotations

import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFY_SCRIPT = REPO_ROOT / "scripts" / "verify-mvp.sh"
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
API_TOKEN = "verify-mvp-test-token"


class _VerifierHandler(BaseHTTPRequestHandler):
    server: ThreadingHTTPServer

    def log_message(self, _format: str, *_args: object) -> None:
        return

    @property
    def state(self) -> dict[str, Any]:
        return self.server.state  # type: ignore[attr-defined]

    def _authorized(self) -> bool:
        return self.headers.get("Authorization") == f"Bearer {API_TOKEN}"

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path in {"/health", "/healthz"}:
            self._send_json(200, {"status": "ok"})
            return
        if path == "/.well-known/jwks.json":
            self._send_json(200, {"keys": [{"kty": "EC"}]})
            return
        if path == "/metrics":
            if not self._authorized():
                self._send_json(401, {"error": "missing authorization"})
                return
            body = b"# HELP ardur_requests_total requests\nardur_requests_total 1\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorized():
            self._send_json(401, {"error": "missing authorization"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        path = urlsplit(self.path).path
        self.state["requests"].append((path, payload))

        if path == "/issue":
            self._send_json(200, {"token": "passport-token"})
            return
        if path == "/session/start":
            self._send_json(200, {"session_id": "session-1"})
            return
        if path == "/evaluate":
            decision = "PERMIT" if payload["tool_name"] == "read_file" else "DENY"
            self._send_json(200, {"decision": decision, "session_id": "session-1"})
            return
        if path == "/attest":
            self._send_json(200, {"token": "attestation-token", "claims": {}})
            return
        if path == "/session/end":
            self._send_json(
                200, {"attestation_token": "ended-attestation", "summary": {}}
            )
            return
        self._send_json(404, {"error": "not found"})


def test_verifier_uses_current_authenticated_proxy_contract() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _VerifierHandler)
    server.state = {"requests": []}  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        env = os.environ | {
            "ARDUR_API_TOKEN": API_TOKEN,
            "ARDUR_PROXY_URL": f"http://127.0.0.1:{server.server_port}",
        }
        result = subprocess.run(
            ["bash", str(VERIFY_SCRIPT)],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASSED: 11" in result.stdout
    assert "FAILED: 0" in result.stdout

    requests = server.state["requests"]  # type: ignore[attr-defined]
    assert requests == [
        (
            "/issue",
            {
                "mission": {
                    "agent_id": "mvp-verifier",
                    "mission": "verify the local governance proxy",
                    "allowed_tools": ["read_file", "delete_file"],
                    "forbidden_tools": ["delete_file"],
                    "max_tool_calls": 4,
                }
            },
        ),
        ("/session/start", {"token": "passport-token"}),
        (
            "/evaluate",
            {
                "session_id": "session-1",
                "tool_name": "read_file",
                "arguments": {"path": "/tmp/ardur-mvp-verifier.txt"},
            },
        ),
        (
            "/evaluate",
            {
                "session_id": "session-1",
                "tool_name": "delete_file",
                "arguments": {"path": "/tmp/ardur-mvp-verifier.txt"},
            },
        ),
        ("/attest", {"session_id": "session-1"}),
        ("/session/end", {"session_id": "session-1"}),
    ]


def test_compose_exposes_the_configured_token_to_the_proxy() -> None:
    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))

    assert (
        "VIBAP_API_TOKEN=${ARDUR_API_TOKEN:-}"
        in compose["services"]["proxy"]["environment"]
    )
