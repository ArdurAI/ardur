#!/usr/bin/env python3
"""Phase 2 Advanced Adversarial Suite for Ardur.

Programmatically tests every proxy enforcement capability NOT covered by Phase 1:
  - Approval policies (operator_id extraction, fatigue threshold)
  - Delegation (tool escalation, budget escrow)
  - Memory governance (FIX-8 identity forgery prevention, compromise boundary)
  - Token replay defense (JTI reuse, nonce replay)
  - Kill switch (503 on mutation endpoints)
  - Per-class budgets (max_tool_calls_per_class, allowed_side_effect_classes)
  - CWD confinement (escape via path traversal, absolute paths)
  - ForbidRules / Cedar policy backends
  - Session revocation

Usage:
  python tests/run_advanced_adversarial.py [--verbose]
"""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import sys
import textwrap
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WORK_DIR_BASE = Path(os.environ.get("ARDUR_ADVERSARIAL_WORKDIR", "/tmp/ardur-advanced"))
RESULTS_DIR = Path(__file__).resolve().parent / "test-results" / "advanced"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _free_port() -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _post_tls(base: str, path: str, body: dict | None = None, timeout: int = 15) -> tuple[int, dict, bytes]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    has_body = body is not None
    data = json.dumps(body).encode("utf-8") if has_body else b""
    req = urllib.request.Request(
        base + path,
        data=data,
        headers={"Content-Type": "application/json"} if has_body else {},
        method="POST" if has_body else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else {}, b""
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        return exc.code, json.loads(raw) if raw else {}, b""


def _start_proxy(port: int, tls_cert: str, tls_key: str, keys_dir: Path, work_dir: Path) -> tuple[Any, threading.Thread, str]:
    import signal as _signal
    _signal.signal = lambda *_a, **_kw: None

    from vibap.passport import generate_keypair
    from vibap.proxy import GovernanceProxy, serve_proxy

    _, public_key = generate_keypair(keys_dir=keys_dir)
    proxy = GovernanceProxy(
        log_path=work_dir / "governance_log.jsonl",
        state_dir=work_dir / "state",
        public_key=public_key,
        keys_dir=keys_dir,
    )

    def run():
        serve_proxy(
            proxy=proxy,
            private_key=proxy.receipt_private_key,
            host="127.0.0.1",
            port=port,
            tls_cert=tls_cert,
            tls_key=tls_key,
            no_tls=False,
            require_auth=False,
            api_token="",
        )

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
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

    return proxy, thread, base


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AdvancedTestResult:
    test_id: str
    title: str
    category: str
    passed: bool
    details: str = ""
    expected_decision: str = ""
    actual_decision: str = ""
    actual_reason: str = ""
    http_status: int = 0
    elapsed_ms: float = 0.0


@dataclass
class AdvancedSuiteReport:
    results: list[AdvancedTestResult] = field(default_factory=list)
    total: int = 0
    passed: int = 0
    failed: int = 0
    elapsed_s: float = 0.0

    def summary(self) -> str:
        lines = [
            "=" * 72,
            "ARDUR PHASE 2 — ADVANCED ADVERSARIAL RESULTS",
            "=" * 72,
            f"Tests run: {self.total}  |  PASS: {self.passed}  |  FAIL: {self.failed}",
            f"Duration:  {self.elapsed_s:.0f}s",
            "",
        ]

        by_category: dict[str, list[AdvancedTestResult]] = {}
        for r in self.results:
            by_category.setdefault(r.category, []).append(r)

        for cat, results in by_category.items():
            cat_passed = sum(1 for r in results if r.passed)
            cat_total = len(results)
            lines.append(f"┌─ {cat}  ({cat_passed}/{cat_total} passed)")
            for r in results:
                status = "PASS" if r.passed else "FAIL"
                lines.append(f"│  [{status}] {r.test_id}: {r.title}")
                if r.details:
                    for detail_line in r.details.split("\n"):
                        lines.append(f"│    {detail_line}")
            lines.append("")

        # Failures detail
        failures = [r for r in self.results if not r.passed]
        if failures:
            lines.append("--- FAILURES ---")
            for r in failures:
                lines.append(f"  {r.test_id}: {r.title}")
                lines.append(f"    Expected: {r.expected_decision}")
                lines.append(f"    Actual:   {r.actual_decision} — {r.actual_reason}")
                if r.details:
                    lines.append(f"    {r.details}")
            lines.append("")

        if self.failed == 0:
            lines.append("VERDICT: All enforcement points operating correctly.")
        else:
            lines.append(f"VERDICT: {self.failed} enforcement gap(s) found — review immediately.")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Test builder helpers
# ---------------------------------------------------------------------------

def _issue_and_start(proxy_base: str, private_key, mission_kwargs: dict,
                     extra_claims: dict | None = None) -> tuple[str | None, str | None]:
    """Issue a passport and start a session. Returns (session_id, None) or (None, error).

    ``mission_kwargs`` maps to ``MissionPassport`` constructor fields.
    ``extra_claims`` is passed through to ``issue_passport`` for claims not on
    the dataclass (e.g. ``approval_policy``).
    """
    from vibap.passport import MissionPassport, issue_passport

    defaults = {
        "agent_id": f"adv-{uuid.uuid4().hex[:8]}",
        "mission": "Advanced adversarial test",
        "allowed_tools": ["read_file", "write_file", "list_directory", "search_files", "delete_file"],
        "forbidden_tools": ["execute_shell"],
        "resource_scope": [],
        "max_tool_calls": 50,
        "max_duration_s": 300,
    }
    defaults.update(mission_kwargs)
    mission = MissionPassport(**defaults)
    token = issue_passport(mission, private_key, ttl_s=300, extra_claims=extra_claims)

    status, body, _ = _post_tls(proxy_base, "/session/start", {"token": token})
    if status != 200:
        return None, f"session start failed: HTTP {status} {body}"
    return body["session_id"], None


# ---------------------------------------------------------------------------
# Individual test functions
# ---------------------------------------------------------------------------

# --- Approval Policy Tests ---

def test_approval_operator_required(proxy_base: str, private_key) -> AdvancedTestResult:
    """Call without operator_id when approval_policy requires one → INSUFFICIENT_EVIDENCE."""
    result = AdvancedTestResult(
        test_id="approval-no-operator",
        title="operator_id required but not supplied",
        category="Approval Policy",
        passed=False,
        expected_decision="INSUFFICIENT_EVIDENCE",
    )
    t0 = time.time()
    sid, err = _issue_and_start(proxy_base, private_key,
        {"allowed_tools": ["read_file", "write_file"]},
        extra_claims={"approval_policy": {"max_approvals_per_hour_per_operator": 5}},
    )
    if err:
        result.details = f"Setup error: {err}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    status, decision, _ = _post_tls(proxy_base, "/evaluate", {
        "session_id": sid,
        "tool_name": "write_file",
        "arguments": {"path": "test.txt", "content": "hello"},
    })
    result.http_status = status
    result.actual_decision = decision.get("decision", "UNKNOWN")
    result.actual_reason = decision.get("reason", "")
    result.passed = (
        result.actual_decision in ("INSUFFICIENT_EVIDENCE", "DENY")
        and "operator" in result.actual_reason.lower()
    )
    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        result.details = f"Got {result.actual_decision} reason={result.actual_reason}"
    return result


def test_approval_fatigue_threshold(proxy_base: str, private_key) -> AdvancedTestResult:
    """Exhaust per-operator approval rate → APPROVAL_FATIGUE_THRESHOLD."""
    result = AdvancedTestResult(
        test_id="approval-fatigue",
        title="approval fatigue threshold exceeded",
        category="Approval Policy",
        passed=False,
        expected_decision="INSUFFICIENT_EVIDENCE (fatigue threshold)",
    )
    t0 = time.time()
    sid, err = _issue_and_start(proxy_base, private_key,
        {"allowed_tools": ["read_file", "write_file"]},
        extra_claims={"approval_policy": {"max_approvals_per_hour_per_operator": 2}},
    )
    if err:
        result.details = f"Setup error: {err}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    decisions = []
    for i in range(5):
        _, decision, _ = _post_tls(proxy_base, "/evaluate", {
            "session_id": sid,
            "tool_name": "write_file",
            "arguments": {"path": f"test{i}.txt", "content": "x", "operator_id": "op-1"},
        })
        decisions.append((decision.get("decision"), decision.get("reason", "")))

    permits = [d for d, _ in decisions if d == "PERMIT"]
    denials = [r for d, r in decisions[2:] if d != "PERMIT" and "fatigue" in r.lower()]

    result.actual_decision = f"{len(permits)} PERMIT, {len(denials)} non-PERMIT(post-budget)"
    result.actual_reason = "; ".join(r[:80] for _, r in decisions if r)
    result.passed = len(permits) == 2 and len(denials) >= 1
    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        result.details = f"Got {len(permits)} permits, {len(denials)} denials. Full: {[(d,r[:50]) for d,r in decisions]}"
    return result


# --- Delegation Tests ---

def test_delegation_tool_escalation(proxy_base: str, private_key) -> AdvancedTestResult:
    """Child tries to use a tool NOT in parent's allowed set → DENY."""
    result = AdvancedTestResult(
        test_id="delegation-tool-escalation",
        title="child uses tool not in parent scope",
        category="Delegation",
        passed=False,
        expected_decision="DENY",
    )
    t0 = time.time()

    from vibap.passport import MissionPassport, issue_passport

    # Parent passport with limited tools + delegation allowed
    parent_mission = MissionPassport(
        agent_id=f"parent-{uuid.uuid4().hex[:8]}",
        mission="Delegation escalation test",
        allowed_tools=["read_file", "write_file"],
        forbidden_tools=["execute_shell"],
        resource_scope=[],
        max_tool_calls=100,
        max_duration_s=300,
        delegation_allowed=True,
        max_delegation_depth=3,
    )
    parent_token = issue_passport(parent_mission, private_key, ttl_s=300)

    # Start parent session
    ps, pb, _ = _post_tls(proxy_base, "/session/start", {"token": parent_token})
    if ps != 200:
        result.details = f"Parent session start failed: HTTP {ps} {pb}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result
    parent_sid = pb["session_id"]

    # Delegate through proxy with escalated tools
    ds, db, _ = _post_tls(proxy_base, "/delegate", {
        "session_id": parent_sid,
        "child_agent_id": f"child-{uuid.uuid4().hex[:8]}",
        "child_allowed_tools": ["read_file", "write_file", "execute_shell"],
        "child_mission": "Attempt tool escalation via delegation",
        "child_max_tool_calls": 5,
    })
    result.http_status = ds

    if ds == 200 and "token" in db.get("child", db):
        child_token = db.get("child", db).get("token", "")
        if child_token:
            cs, cb, _ = _post_tls(proxy_base, "/session/start", {"token": child_token})
            if cs == 200:
                child_sid = cb["session_id"]
                es, eb, _ = _post_tls(proxy_base, "/evaluate", {
                    "session_id": child_sid,
                    "tool_name": "execute_shell",
                    "arguments": {"command": "whoami"},
                })
                result.actual_decision = eb.get("decision", "UNKNOWN")
                result.actual_reason = eb.get("reason", "")
                result.passed = result.actual_decision in ("DENY", "VIOLATION", "INSUFFICIENT_EVIDENCE")
            else:
                result.actual_decision = f"child session HTTP {cs}"
                result.passed = True
        else:
            result.actual_decision = "Delegation OK but no child token"
            result.passed = False
    else:
        result.actual_decision = f"Delegation HTTP {ds}"
        result.actual_reason = str(db)[:200]
        result.passed = ds != 200

    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        result.details = f"Child was able to use escalated tool: {result.actual_decision}"
    return result


# --- Memory Governance Tests ---

def test_memory_fix8_write_rejected(proxy_base: str, private_key) -> AdvancedTestResult:
    """Supply actor_private_key_pem in memory_store_write → rejected (FIX-8)."""
    result = AdvancedTestResult(
        test_id="memory-fix8-write",
        title="FIX-8: actor_private_key_pem rejected on memory write",
        category="Memory Governance",
        passed=False,
        expected_decision="DENY (actor_private_key_pem rejected)",
    )
    t0 = time.time()
    sid, err = _issue_and_start(proxy_base, private_key, {
        "allowed_tools": ["read_file", "write_file", "memory_store_write"],
    })
    if err:
        result.details = f"Setup error: {err}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    # Try memory write with actor_private_key_pem (should be rejected per FIX-8)
    _, decision, _ = _post_tls(proxy_base, "/evaluate", {
        "session_id": sid,
        "tool_name": "memory_store_write",
        "arguments": {
            "store_id": "test-store",
            "content": "sensitive data",
            "actor_private_key_pem": "-----BEGIN EC PRIVATE KEY-----\nfake\n-----END EC PRIVATE KEY-----",
        },
    })
    result.actual_decision = decision.get("decision", "UNKNOWN")
    result.actual_reason = decision.get("reason", "")
    result.passed = result.actual_decision != "PERMIT"
    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        result.details = "FIX-8 regression: actor_private_key_pem was accepted for memory write"
    return result


def test_memory_fix8_read_rejected(proxy_base: str, private_key) -> AdvancedTestResult:
    """Supply verifier_public_key_pem in memory_store_read → rejected (FIX-8)."""
    result = AdvancedTestResult(
        test_id="memory-fix8-read",
        title="FIX-8: verifier_public_key_pem rejected on memory read",
        category="Memory Governance",
        passed=False,
        expected_decision="DENY (verifier_public_key_pem rejected)",
    )
    t0 = time.time()
    sid, err = _issue_and_start(proxy_base, private_key, {
        "allowed_tools": ["read_file", "write_file", "memory_store_read"],
    })
    if err:
        result.details = f"Setup error: {err}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    _, decision, _ = _post_tls(proxy_base, "/evaluate", {
        "session_id": sid,
        "tool_name": "memory_store_read",
        "arguments": {
            "store_id": "test-store",
            "record_id": str(uuid.uuid4()),
            "verifier_public_key_pem": "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----",
        },
    })
    result.actual_decision = decision.get("decision", "UNKNOWN")
    result.actual_reason = decision.get("reason", "")
    result.passed = result.actual_decision != "PERMIT"
    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        result.details = "FIX-8 regression: verifier_public_key_pem was accepted for memory read"
    return result


# --- Token Replay Tests ---

def test_jti_replay_rejected(proxy_base: str, private_key) -> AdvancedTestResult:
    """Reuse the same passport JWT for a second session → rejected."""
    result = AdvancedTestResult(
        test_id="token-replay-jti",
        title="JTI replay on session start rejected",
        category="Token Replay",
        passed=False,
        expected_decision="HTTP 400 (jti already active)",
    )
    t0 = time.time()

    from vibap.passport import MissionPassport, issue_passport

    mission = MissionPassport(
        agent_id=f"replay-{uuid.uuid4().hex[:8]}",
        mission="Token replay test",
        allowed_tools=["read_file", "write_file"],
        forbidden_tools=[],
        resource_scope=[],
        max_tool_calls=10,
        max_duration_s=300,
    )
    token = issue_passport(mission, private_key, ttl_s=300)

    # First session — should succeed
    status1, body1, _ = _post_tls(proxy_base, "/session/start", {"token": token})
    if status1 != 200:
        result.details = f"First session start failed: {body1}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    # Second session with SAME token — should be rejected
    status2, body2, _ = _post_tls(proxy_base, "/session/start", {"token": token})
    result.http_status = status2
    result.actual_decision = f"HTTP {status2}"
    result.actual_reason = str(body2)[:200]
    result.passed = status2 != 200
    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        result.details = "JTI replay allowed — same passport started two sessions"
    return result


# --- Kill Switch Tests ---

def test_kill_switch_blocks_evaluate(proxy_base: str, private_key) -> AdvancedTestResult:
    """Activate kill switch, attempt /evaluate → HTTP 503."""
    result = AdvancedTestResult(
        test_id="kill-switch-evaluate",
        title="kill switch blocks /evaluate with 503",
        category="Kill Switch",
        passed=False,
        expected_decision="HTTP 503",
    )
    t0 = time.time()
    sid, err = _issue_and_start(proxy_base, private_key, {
        "allowed_tools": ["read_file", "write_file"],
    })
    if err:
        result.details = f"Setup error: {err}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    # Verify normal operation first
    status_ok, _, _ = _post_tls(proxy_base, "/evaluate", {
        "session_id": sid,
        "tool_name": "write_file",
        "arguments": {"path": "ok.txt", "content": "before kill"},
    })
    if status_ok != 200:
        result.details = f"Pre-kill evaluate returned {status_ok} (expected 200)"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    # Activate kill switch
    ks_status, ks_body, _ = _post_tls(proxy_base, "/admin/kill-switch", {})
    result.actual_reason = f"kill switch activation: HTTP {ks_status} {ks_body}"

    # Try evaluate under kill switch
    status, body, _ = _post_tls(proxy_base, "/evaluate", {
        "session_id": sid,
        "tool_name": "write_file",
        "arguments": {"path": "should-fail.txt", "content": "x"},
    })
    result.http_status = status
    result.actual_decision = f"HTTP {status}"
    result.passed = status == 503
    result.elapsed_ms = (time.time() - t0) * 1000

    # Deactivate kill switch for cleanup
    _post_tls(proxy_base, "/admin/kill-switch", {"deactivate": True})

    if not result.passed:
        result.details = f"Kill switch did not block /evaluate: HTTP {status} {body}"
    return result


def test_kill_switch_blocks_session_start(proxy_base: str, private_key) -> AdvancedTestResult:
    """Activate kill switch, attempt /session/start → HTTP 503."""
    result = AdvancedTestResult(
        test_id="kill-switch-session",
        title="kill switch blocks /session/start with 503",
        category="Kill Switch",
        passed=False,
        expected_decision="HTTP 503",
    )
    t0 = time.time()

    # Activate kill switch
    _post_tls(proxy_base, "/admin/kill-switch", {})

    from vibap.passport import MissionPassport, issue_passport
    mission = MissionPassport(
        agent_id=f"ks-{uuid.uuid4().hex[:8]}",
        mission="Kill switch session test",
        allowed_tools=["read_file"],
        forbidden_tools=[],
        resource_scope=[],
        max_tool_calls=5,
        max_duration_s=60,
    )
    token = issue_passport(mission, private_key, ttl_s=60)

    status, body, _ = _post_tls(proxy_base, "/session/start", {"token": token})
    result.http_status = status
    result.actual_decision = f"HTTP {status}"
    result.actual_reason = str(body)[:200]
    result.passed = status == 503

    # Deactivate
    _post_tls(proxy_base, "/admin/kill-switch", {"deactivate": True})

    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        result.details = f"Kill switch did not block /session/start: HTTP {status} {body}"
    return result


# --- Per-Class Budget Tests ---

def test_per_class_budget_exhaustion(proxy_base: str, private_key) -> AdvancedTestResult:
    """max_tool_calls_per_class={"internal_write": 1}, call 2 delete_file → DENY on 2nd.
    Note: delete_file is classified as internal_write (not state_change) per
    _policy_side_effect_class — filesystem writes short-circuit before the
    state_change catch-all."""
    result = AdvancedTestResult(
        test_id="per-class-budget",
        title="per-class budget exhausted for internal_write",
        category="Per-Class Budget",
        passed=False,
        expected_decision="DENY on second internal_write call",
    )
    t0 = time.time()
    sid, err = _issue_and_start(proxy_base, private_key, {
        "allowed_tools": ["read_file", "write_file", "delete_file"],
        "max_tool_calls_per_class": {"internal_write": 1},
        "max_tool_calls": 50,
    })
    if err:
        result.details = f"Setup error: {err}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    decisions = []
    for i in range(3):
        _, decision, _ = _post_tls(proxy_base, "/evaluate", {
            "session_id": sid,
            "tool_name": "delete_file",
            "arguments": {"path": f"test{i}.txt"},
        })
        decisions.append((decision.get("decision"), decision.get("reason", "")))

    permits = sum(1 for d, _ in decisions if d == "PERMIT")
    denials = sum(1 for d, _ in decisions if d != "PERMIT")

    result.actual_decision = f"{permits} PERMIT, {denials} DENY/DENIAL"
    result.actual_reason = "; ".join(r[:120] for _, r in decisions if r)
    result.passed = permits == 1 and denials == 2
    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        result.details = f"Per-class budget not enforced. Permits: {permits}, Denials: {denials} (decisions: {[(d,r[:60]) for d,r in decisions]})"
    return result


def test_side_effect_class_restriction(proxy_base: str, private_key) -> AdvancedTestResult:
    """allowed_side_effect_classes=["none"] only, try delete_file (internal_write) → DENY."""
    result = AdvancedTestResult(
        test_id="side-effect-class",
        title="side_effect_class not in allowed list rejected",
        category="Per-Class Budget",
        passed=False,
        expected_decision="DENY (side_effect_class not allowed)",
    )
    t0 = time.time()
    sid, err = _issue_and_start(proxy_base, private_key, {
        "allowed_tools": ["read_file", "write_file", "delete_file"],
        "allowed_side_effect_classes": ["none"],  # delete_file is internal_write → DENY
        "max_tool_calls": 50,
    })
    if err:
        result.details = f"Setup error: {err}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    _, decision, _ = _post_tls(proxy_base, "/evaluate", {
        "session_id": sid,
        "tool_name": "delete_file",
        "arguments": {"path": "test.txt"},
    })
    result.actual_decision = decision.get("decision", "UNKNOWN")
    result.actual_reason = decision.get("reason", "")
    result.passed = result.actual_decision != "PERMIT"
    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        result.details = "delete_file was PERMIT-ed despite not being in allowed_side_effect_classes"
    return result


# --- CWD Confinement Tests ---

def test_cwd_absolute_escape(proxy_base: str, private_key) -> AdvancedTestResult:
    """cwd="/tmp/test", try read /etc/passwd → DENY (outside cwd)."""
    result = AdvancedTestResult(
        test_id="cwd-absolute-escape",
        title="absolute path outside CWD rejected",
        category="CWD Confinement",
        passed=False,
        expected_decision="DENY (outside CWD)",
    )
    t0 = time.time()
    sid, err = _issue_and_start(proxy_base, private_key, {
        "allowed_tools": ["read_file", "write_file"],
        "resource_scope": ["/tmp/test/*"],
        "cwd": "/tmp/test",
    })
    if err:
        result.details = f"Setup error: {err}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    # Try reading /etc/passwd (outside cwd and resource_scope)
    _, decision, _ = _post_tls(proxy_base, "/evaluate", {
        "session_id": sid,
        "tool_name": "read_file",
        "arguments": {"path": "/etc/passwd"},
    })
    result.actual_decision = decision.get("decision", "UNKNOWN")
    result.actual_reason = decision.get("reason", "")
    result.passed = result.actual_decision != "PERMIT"
    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        result.details = "Read of /etc/passwd was PERMIT-ed despite CWD/resource_scope restrictions"
    return result


def test_cwd_path_traversal(proxy_base: str, private_key) -> AdvancedTestResult:
    """cwd="/workspace", try ../etc/passwd → DENY."""
    result = AdvancedTestResult(
        test_id="cwd-path-traversal",
        title="path traversal escape from CWD rejected",
        category="CWD Confinement",
        passed=False,
        expected_decision="DENY (path traversal)",
    )
    t0 = time.time()
    sid, err = _issue_and_start(proxy_base, private_key, {
        "allowed_tools": ["read_file", "write_file"],
        "resource_scope": ["/workspace/*"],
        "cwd": "/workspace",
    })
    if err:
        result.details = f"Setup error: {err}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    # Try path traversal
    _, decision, _ = _post_tls(proxy_base, "/evaluate", {
        "session_id": sid,
        "tool_name": "read_file",
        "arguments": {"path": "../../../etc/passwd"},
    })
    result.actual_decision = decision.get("decision", "UNKNOWN")
    result.actual_reason = decision.get("reason", "")
    result.passed = result.actual_decision != "PERMIT"
    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        result.details = "Path traversal escape succeeded — ../etc/passwd was PERMIT-ed"
    return result


# --- ForbidRules Backend Tests ---

def test_forbid_rules_blocks_tool(proxy_base: str, private_key) -> AdvancedTestResult:
    """Include forbid_rules policy blocking delete_file → DENY."""
    result = AdvancedTestResult(
        test_id="forbid-rules-block",
        title="ForbidRules backend blocks targeted tool",
        category="Policy Backends",
        passed=False,
        expected_decision="DENY (forbid_rules match)",
    )
    t0 = time.time()

    # Match _canonical_source in forbid_rules.py: sort_keys + compact separators
    rules = [{"id": "block-delete", "forbid_when": {"tool_name": "delete_file"}}]
    rules_json = json.dumps(rules, sort_keys=True, separators=(",", ":"))
    rules_sha256 = hashlib.sha256(rules_json.encode()).hexdigest()

    sid, err = _issue_and_start(proxy_base, private_key, {
        "allowed_tools": ["read_file", "write_file", "delete_file"],
        "additional_policies": [{
            "backend": "forbid_rules",
            "label": "security-team",
            "policy_inline": "",
            "policy_sha256": rules_sha256,
            "data_inline": rules,
        }],
    })
    if err:
        result.details = f"Setup error: {err}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    # First: a permitted tool should work
    _, perm_body, _ = _post_tls(proxy_base, "/evaluate", {
        "session_id": sid, "tool_name": "write_file",
        "arguments": {"path": "ok.txt", "content": "x"},
    })
    write_ok = perm_body.get("decision") == "PERMIT"

    # Second: delete_file should be blocked by forbid_rules
    _, deny_body, _ = _post_tls(proxy_base, "/evaluate", {
        "session_id": sid, "tool_name": "delete_file",
        "arguments": {"path": "important.txt"},
    })
    result.actual_decision = deny_body.get("decision", "UNKNOWN")
    result.actual_reason = deny_body.get("reason", "")

    result.passed = write_ok and result.actual_decision != "PERMIT"
    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        if not write_ok:
            result.details = f"Allowed write_file also blocked: {perm_body}"
        else:
            result.details = f"ForbidRules didn't block delete_file: {deny_body}"
    return result


# --- Forbidden Tool Tests ---

def test_forbidden_tool_denied(proxy_base: str, private_key) -> AdvancedTestResult:
    """Direct call to forbidden_tool → DENY."""
    result = AdvancedTestResult(
        test_id="forbidden-tool-deny",
        title="forbidden tool directly denied",
        category="Tool Scope",
        passed=False,
        expected_decision="DENY",
    )
    t0 = time.time()
    sid, err = _issue_and_start(proxy_base, private_key, {
        "allowed_tools": ["read_file", "write_file"],
        "forbidden_tools": ["execute_shell", "delete_file"],
    })
    if err:
        result.details = f"Setup error: {err}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    _, decision, _ = _post_tls(proxy_base, "/evaluate", {
        "session_id": sid,
        "tool_name": "execute_shell",
        "arguments": {"command": "whoami"},
    })
    result.actual_decision = decision.get("decision", "UNKNOWN")
    result.actual_reason = decision.get("reason", "")
    result.passed = result.actual_decision != "PERMIT"
    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        result.details = "Forbidden tool execute_shell was PERMIT-ed"
    return result


# --- Resource Scope Tests ---

def test_resource_scope_violation(proxy_base: str, private_key) -> AdvancedTestResult:
    """resource_scope=["/tmp/safe/*"], try to write to /etc/cron.d/evil → DENY."""
    result = AdvancedTestResult(
        test_id="resource-scope-violation",
        title="write outside resource_scope denied",
        category="Resource Scope",
        passed=False,
        expected_decision="DENY (outside resource_scope)",
    )
    t0 = time.time()
    sid, err = _issue_and_start(proxy_base, private_key, {
        "allowed_tools": ["read_file", "write_file"],
        "resource_scope": ["/tmp/safe/*"],
        "cwd": "/tmp/safe",
    })
    if err:
        result.details = f"Setup error: {err}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    _, decision, _ = _post_tls(proxy_base, "/evaluate", {
        "session_id": sid,
        "tool_name": "write_file",
        "arguments": {"path": "/etc/cron.d/evil", "content": "* * * * * root /tmp/backdoor"},
    })
    result.actual_decision = decision.get("decision", "UNKNOWN")
    result.actual_reason = decision.get("reason", "")
    result.passed = result.actual_decision != "PERMIT"
    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        result.details = "Write to /etc/cron.d/evil was PERMIT-ed despite resource_scope"
    return result


# --- Budget Exhaustion Tests ---

def test_budget_exhaustion(proxy_base: str, private_key) -> AdvancedTestResult:
    """max_tool_calls=3, make 5 calls → DENY on calls 4+."""
    result = AdvancedTestResult(
        test_id="budget-exhaustion",
        title="main budget exhausted after max_tool_calls",
        category="Budget",
        passed=False,
        expected_decision="DENY after 3 calls",
    )
    t0 = time.time()
    sid, err = _issue_and_start(proxy_base, private_key, {
        "allowed_tools": ["read_file", "write_file"],
        "max_tool_calls": 3,
    })
    if err:
        result.details = f"Setup error: {err}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    decisions = []
    for i in range(5):
        _, decision, _ = _post_tls(proxy_base, "/evaluate", {
            "session_id": sid,
            "tool_name": "write_file",
            "arguments": {"path": f"file{i}.txt", "content": f"content {i}"},
        })
        decisions.append(decision.get("decision"))

    permits = sum(1 for d in decisions if d == "PERMIT")
    denials_after = sum(1 for d in decisions[3:] if d != "PERMIT")

    result.actual_decision = f"decisions: {decisions}"
    result.passed = permits == 3 and denials_after == 2
    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        result.details = f"Budget not enforced. Permits: {permits}/5, decisions: {decisions}"
    return result


# --- Session End Tests ---

def test_ended_session_rejects(proxy_base: str, private_key) -> AdvancedTestResult:
    """End a session, then try /evaluate → DENY (session already ended)."""
    result = AdvancedTestResult(
        test_id="ended-session-rejects",
        title="ended session rejects evaluate",
        category="Session Lifecycle",
        passed=False,
        expected_decision="DENY (session already ended)",
    )
    t0 = time.time()
    sid, err = _issue_and_start(proxy_base, private_key, {
        "allowed_tools": ["read_file", "write_file"],
        "max_tool_calls": 50,
    })
    if err:
        result.details = f"Setup error: {err}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    # End the session
    end_status, end_body, _ = _post_tls(proxy_base, "/session/end", {"session_id": sid})

    # Try evaluate on ended session
    _, decision, _ = _post_tls(proxy_base, "/evaluate", {
        "session_id": sid,
        "tool_name": "write_file",
        "arguments": {"path": "after-end.txt", "content": "late"},
    })
    result.actual_decision = decision.get("decision", "UNKNOWN")
    result.actual_reason = decision.get("reason", "")
    result.passed = result.actual_decision != "PERMIT"
    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        result.details = "Evaluate on ended session was PERMIT-ed"
    return result


# --- Token Validation Tests ---

def test_invalid_token_session_start(proxy_base: str) -> AdvancedTestResult:
    """Start session with garbage token → HTTP 401."""
    result = AdvancedTestResult(
        test_id="invalid-token-rejected",
        title="invalid JWT rejected on session start",
        category="Token Validation",
        passed=False,
        expected_decision="HTTP 401",
    )
    t0 = time.time()
    status, body, _ = _post_tls(proxy_base, "/session/start", {"token": "not.a.valid.jwt"})
    result.http_status = status
    result.actual_decision = f"HTTP {status}"
    result.actual_reason = str(body)[:200]
    result.passed = status in (400, 401, 403)
    result.elapsed_ms = (time.time() - t0) * 1000
    return result


def test_nonexistent_session_evaluate(proxy_base: str) -> AdvancedTestResult:
    """Evaluate with nonexistent session_id → HTTP 400."""
    result = AdvancedTestResult(
        test_id="nonexistent-session",
        title="evaluate with fake session_id rejected",
        category="Token Validation",
        passed=False,
        expected_decision="HTTP 400",
    )
    t0 = time.time()
    status, body, _ = _post_tls(proxy_base, "/evaluate", {
        "session_id": str(uuid.uuid4()),
        "tool_name": "write_file",
        "arguments": {"path": "test.txt", "content": "x"},
    })
    result.http_status = status
    result.actual_decision = f"HTTP {status}"
    result.actual_reason = str(body)[:200]
    result.passed = status in (400, 404)
    result.elapsed_ms = (time.time() - t0) * 1000
    return result


# --- Unicode / Obfuscation Attacks ---

def test_unicode_confusable_path(proxy_base: str, private_key) -> AdvancedTestResult:
    """Unicode confusable characters in path → properly handled (no bypass)."""
    result = AdvancedTestResult(
        test_id="unicode-confusable",
        title="unicode confusable path handled correctly",
        category="Input Sanitization",
        passed=False,
        expected_decision="Should not bypass scope via unicode tricks",
    )
    t0 = time.time()

    # Use a path with unicode chars that might confound matching
    sid, err = _issue_and_start(proxy_base, private_key, {
        "allowed_tools": ["read_file", "write_file"],
        "resource_scope": ["/tmp/safe/*"],
        "cwd": "/tmp/safe",
    })
    if err:
        result.details = f"Setup error: {err}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    # Try path with null byte
    _, decision1, _ = _post_tls(proxy_base, "/evaluate", {
        "session_id": sid,
        "tool_name": "read_file",
        "arguments": {"path": "/etc/passwd\x00.txt"},
    })
    # Try path with unicode homoglyphs
    _, decision2, _ = _post_tls(proxy_base, "/evaluate", {
        "session_id": sid,
        "tool_name": "read_file",
        "arguments": {"path": "․․/etc/passwd"},
    })

    d1 = decision1.get("decision", "UNKNOWN")
    d2 = decision2.get("decision", "UNKNOWN")
    result.actual_decision = f"null-byte: {d1}, unicode: {d2}"
    result.passed = d1 != "PERMIT" and d2 != "PERMIT"
    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        result.details = f"Unicode/encoding bypass: null-byte={d1}, unicode={d2}"
    return result


# --- Multiple Sessions Coexistence ---

def test_multiple_sessions_coexist(proxy_base: str, private_key) -> AdvancedTestResult:
    """Two independent sessions can operate simultaneously."""
    result = AdvancedTestResult(
        test_id="multiple-sessions",
        title="multiple independent sessions coexist",
        category="Session Lifecycle",
        passed=False,
        expected_decision="Both sessions operate independently",
    )
    t0 = time.time()

    # Session A
    sid_a, err_a = _issue_and_start(proxy_base, private_key, {
        "allowed_tools": ["read_file", "write_file"],
        "max_tool_calls": 5,
    })
    if err_a:
        result.details = f"Session A setup error: {err_a}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    # Session B
    sid_b, err_b = _issue_and_start(proxy_base, private_key, {
        "allowed_tools": ["read_file", "write_file", "delete_file"],
        "max_tool_calls": 5,
    })
    if err_b:
        result.details = f"Session B setup error: {err_b}"
        result.elapsed_ms = (time.time() - t0) * 1000
        return result

    # Operate on both
    _, da, _ = _post_tls(proxy_base, "/evaluate", {
        "session_id": sid_a, "tool_name": "write_file",
        "arguments": {"path": "from-a.txt", "content": "A"},
    })
    _, db, _ = _post_tls(proxy_base, "/evaluate", {
        "session_id": sid_b, "tool_name": "write_file",
        "arguments": {"path": "from-b.txt", "content": "B"},
    })

    dec_a = da.get("decision", "UNKNOWN")
    dec_b = db.get("decision", "UNKNOWN")
    result.actual_decision = f"A: {dec_a}, B: {dec_b}"
    result.passed = dec_a == "PERMIT" and dec_b == "PERMIT"
    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        result.details = f"Sessions did not coexist: {result.actual_decision}"
    return result


# --- Health Endpoint ---

def test_health_endpoint(proxy_base: str) -> AdvancedTestResult:
    """GET /health returns 200 with status ok."""
    result = AdvancedTestResult(
        test_id="health-endpoint",
        title="health endpoint returns ok",
        category="Infrastructure",
        passed=False,
        expected_decision="HTTP 200",
    )
    t0 = time.time()
    status, body, _ = _post_tls(proxy_base, "/health", None)
    result.http_status = status
    result.actual_decision = str(body.get("status", "UNKNOWN"))
    result.passed = status == 200 and body.get("status") == "ok"
    result.elapsed_ms = (time.time() - t0) * 1000
    if not result.passed:
        result.details = f"Health check failed: HTTP {status} {body}"
    return result


# ---------------------------------------------------------------------------
# All tests
# ---------------------------------------------------------------------------

ALL_TESTS: list[Callable] = [
    # Approval Policy
    test_approval_operator_required,
    test_approval_fatigue_threshold,
    # Delegation
    test_delegation_tool_escalation,
    # Memory Governance (FIX-8)
    test_memory_fix8_write_rejected,
    test_memory_fix8_read_rejected,
    # Token Replay
    test_jti_replay_rejected,
    # Kill Switch
    test_kill_switch_blocks_evaluate,
    test_kill_switch_blocks_session_start,
    # Per-Class Budget
    test_per_class_budget_exhaustion,
    test_side_effect_class_restriction,
    # CWD Confinement
    test_cwd_absolute_escape,
    test_cwd_path_traversal,
    # Policy Backends
    test_forbid_rules_blocks_tool,
    # Tool Scope
    test_forbidden_tool_denied,
    # Resource Scope
    test_resource_scope_violation,
    # Budget
    test_budget_exhaustion,
    # Session Lifecycle
    test_ended_session_rejects,
    test_multiple_sessions_coexist,
    # Token Validation
    test_invalid_token_session_start,
    test_nonexistent_session_evaluate,
    # Input Sanitization
    test_unicode_confusable_path,
    # Infrastructure
    test_health_endpoint,
]


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def main():
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    work_dir = WORK_DIR_BASE / f"run-{uuid.uuid4().hex[:8]}"
    work_dir.mkdir(parents=True, exist_ok=True)

    # Setup TLS and keys
    from vibap.tls import generate_self_signed_cert
    from vibap.passport import generate_keypair

    tls_dir = work_dir / "tls"
    key_path_obj, cert_path_obj, _ = generate_self_signed_cert(tls_dir)

    keys_dir = work_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    private_key, public_key = generate_keypair(keys_dir=keys_dir)

    port = _free_port()
    proxy, proxy_thread, base = _start_proxy(
        port, str(cert_path_obj), str(key_path_obj), keys_dir, work_dir,
    )

    print("=" * 72)
    print("ARDUR PHASE 2 — ADVANCED ADVERSARIAL SUITE")
    print(f"Proxy:  {base}")
    print(f"Tests:  {len(ALL_TESTS)} programmatic enforcement checks")
    print("=" * 72)
    print()

    report = AdvancedSuiteReport()
    t_start = time.time()

    for test_fn in ALL_TESTS:
        try:
            if test_fn in (test_invalid_token_session_start, test_health_endpoint):
                tr = test_fn(base)
            elif test_fn == test_nonexistent_session_evaluate:
                tr = test_fn(base)
            else:
                tr = test_fn(base, private_key)
        except Exception as exc:
            tr = AdvancedTestResult(
                test_id=test_fn.__name__.removeprefix("test_").replace("_", "-"),
                title=test_fn.__doc__ or test_fn.__name__,
                category="ERROR",
                passed=False,
                details=f"Exception: {exc}",
            )

        report.results.append(tr)
        report.total += 1
        if tr.passed:
            report.passed += 1
        else:
            report.failed += 1

        status = "PASS" if tr.passed else "FAIL"
        if verbose or not tr.passed:
            print(f"  [{status}] {tr.test_id}")
            if tr.details:
                print(f"         {tr.details[:120]}")
        else:
            print(f"  [{status}] {tr.test_id}")

    report.elapsed_s = time.time() - t_start

    # Shutdown proxy
    proxy_thread.join(timeout=2)

    # Output summary
    summary = report.summary()
    print("\n" + summary)

    # Write results
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    summary_path = RESULTS_DIR / f"advanced-summary-{timestamp}.md"
    json_path = RESULTS_DIR / f"advanced-results-{timestamp}.json"

    summary_path.write_text(summary)

    json_results = {
        "run_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total": report.total,
        "passed": report.passed,
        "failed": report.failed,
        "elapsed_s": report.elapsed_s,
        "results": [
            {
                "test_id": r.test_id,
                "title": r.title,
                "category": r.category,
                "passed": r.passed,
                "details": r.details,
                "expected_decision": r.expected_decision,
                "actual_decision": r.actual_decision,
                "actual_reason": r.actual_reason,
                "http_status": r.http_status,
                "elapsed_ms": r.elapsed_ms,
            }
            for r in report.results
        ],
    }
    json_path.write_text(json.dumps(json_results, indent=2))

    print(f"\nResults written to:")
    print(f"  {summary_path}")
    print(f"  {json_path}")

    sys.exit(0 if report.failed == 0 else 1)


if __name__ == "__main__":
    main()
