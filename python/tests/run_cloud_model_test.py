#!/usr/bin/env python3
"""Real-world Ardur governance test with a cloud model building a
sophisticated web application.

Every tool call flows through the Ardur governance proxy (evaluate → attest → receipt).
The model builds a **Code Repository Manager** — a mini-GitHub clone with:
  - Repository CRUD, file tree browsing, commit history
  - Branch management, pull request workflow, issue tracking
  - User authentication, activity feed, full-text code search
  - Admin dashboard SPA (HTML/CSS/JS), REST API, SQLite persistence
  - All using Python stdlib only (http.server, json, sqlite3, etc.)

Usage:
  ARDUR_OLLAMA_API_KEY="<key>" python tests/run_cloud_model_test.py [model_name]

  model_name overrides ARDUR_OLLAMA_CLOUD_MODEL env var.
  Results are written to tests/test-results/<model_safe_name>.json
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
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

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CLOUD_MODEL = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ARDUR_OLLAMA_CLOUD_MODEL", "")
MODEL_SAFE = CLOUD_MODEL.replace(":", "_").replace("/", "_")
API_KEY = os.environ.get("ARDUR_OLLAMA_API_KEY", "")

WORK_DIR = Path(os.environ.get("ARDUR_TEST_WORKDIR", f"/tmp/ardur-cloud-test-{MODEL_SAFE}"))
WORK_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR = Path(__file__).resolve().parent / "test-results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
REPORT_PATH = RESULTS_DIR / f"{MODEL_SAFE}.json"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def _parse_tool_args(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return {}

def _post_tls(base: str, path: str, body: dict) -> tuple[int, dict, bytes]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        base + path,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8")), b""
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8")), b""

# ---------------------------------------------------------------------------
# Proxy lifecycle
# ---------------------------------------------------------------------------

def _start_proxy(port: int, tls_cert: str, tls_key: str, keys_dir: Path, work_dir: Path) -> tuple[GovernanceProxy, threading.Thread, str]:
    import signal as _signal
    _signal.signal = lambda *_a, **_kw: None  # only works in main thread

    from vibap.passport import generate_keypair
    from vibap.proxy import GovernanceProxy, serve_proxy
    from vibap.policy_store import InMemoryPolicyStore

    _, public_key = generate_keypair(keys_dir=keys_dir)
    proxy = GovernanceProxy(
        log_path=work_dir / "governance_log.jsonl",
        state_dir=work_dir / "state",
        public_key=public_key,
        keys_dir=keys_dir,
        policy_store=InMemoryPolicyStore(),
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

    # Wait for healthy
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
# Main test
# ---------------------------------------------------------------------------

def main():
    if not API_KEY:
        print("ERROR: ARDUR_OLLAMA_API_KEY not set. Export it and retry.")
        sys.exit(1)

    print("=" * 72)
    print("Ardur Cloud Model Governance Test")
    print(f"  Model:   {CLOUD_MODEL}")
    print(f"  Workdir: {WORK_DIR}")
    print("=" * 72)

    # ---- Setup TLS & proxy ----
    from vibap.tls import generate_self_signed_cert
    from vibap.passport import generate_keypair

    tls_dir = WORK_DIR / "tls"
    key_path_obj, cert_path_obj, _ = generate_self_signed_cert(tls_dir)
    cert_path = str(cert_path_obj)
    key_path = str(key_path_obj)

    keys_dir = WORK_DIR / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)

    port = _free_port()
    proxy, proxy_thread, base = _start_proxy(port, cert_path, key_path, keys_dir, WORK_DIR)

    print(f"\nProxy healthy at {base}\n")
    report: dict[str, Any] = {
        "model": CLOUD_MODEL,
        "started": time.time(),
        "phases": [],
        "tool_calls_total": 0,
        "files_created": [],
        "errors": [],
    }

    try:
        # ---- Start session ----
        from vibap.passport import MissionPassport, issue_passport

        mission = MissionPassport(
            agent_id="cloud-builder-agent",
            mission="build a complete Code Repository Manager from scratch",
            allowed_tools=["read_file", "write_file", "list_directory", "search_files"],
            forbidden_tools=["delete_file", "execute_shell"],
            resource_scope=[],
            max_tool_calls=250,
            max_duration_s=3600,
        )
        token = issue_passport(mission, proxy.receipt_private_key, ttl_s=3600)

        status, body, _ = _post_tls(base, "/session/start", {"token": token})
        assert status == 200, f"session start failed: {body}"
        sid = body["session_id"]
        print(f"\nSession started: {sid[:8]}...\n")

        # ---- Tool definitions ----
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "write_file",
                    "description": "Write content to a file. Creates directories as needed.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "File path relative to workspace"},
                            "content": {"type": "string", "description": "File content"},
                        },
                        "required": ["path", "content"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read file contents at the given path",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "File path to read"},
                        },
                        "required": ["path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "list_directory",
                    "description": "List files and directories at a path",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "Directory path"},
                        },
                        "required": ["path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "search_files",
                    "description": "Search file contents for a pattern",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "Directory to search in"},
                            "pattern": {"type": "string", "description": "Regex pattern to search for"},
                        },
                        "required": ["path", "pattern"],
                    },
                },
            },
        ]

        # ---- System prompt ----
        messages = [
            {
                "role": "system",
                "content": (
                    "You are an expert full-stack developer building a sophisticated "
                    "web application from scratch. You have access to write_file, "
                    "read_file, list_directory, and search_files tools. Every tool "
                    "call goes through a governance proxy that evaluates permissions.\n\n"
                    "YOUR TASK: Build a **Code Repository Manager** (mini-GitHub) — "
                    "a complete, working Python web application using ONLY the "
                    "standard library (http.server, json, sqlite3, datetime, pathlib, "
                    "hashlib, secrets, html, urllib.parse, etc.). NO external "
                    "dependencies whatsoever.\n\n"
                    "APPLICATION ARCHITECTURE:\n\n"
                    "Backend (Python stdlib http.server):\n"
                    "  A. Repository Management:\n"
                    "     - POST   /api/repos — create repository (name, description, visibility)\n"
                    "     - GET    /api/repos — list all repositories\n"
                    "     - GET    /api/repos/<id> — get repo details + file tree\n"
                    "     - DELETE /api/repos/<id> — delete repository\n"
                    "  B. File Management:\n"
                    "     - GET    /api/repos/<id>/tree — recursive file tree\n"
                    "     - GET    /api/repos/<id>/blob/<path> — get file content\n"
                    "     - POST   /api/repos/<id>/files — create/update file\n"
                    "     - DELETE /api/repos/<id>/files/<path> — delete file\n"
                    "  C. Commit History:\n"
                    "     - GET    /api/repos/<id>/commits — list commits (paginated)\n"
                    "     - GET    /api/repos/<id>/commits/<hash> — get commit detail + diff\n"
                    "  D. Branch Management:\n"
                    "     - POST   /api/repos/<id>/branches — create branch from commit\n"
                    "     - GET    /api/repos/<id>/branches — list branches\n"
                    "     - POST   /api/repos/<id>/merge — merge branch into main\n"
                    "  E. Issues:\n"
                    "     - POST   /api/repos/<id>/issues — create issue\n"
                    "     - GET    /api/repos/<id>/issues — list issues (filterable)\n"
                    "     - PATCH  /api/repos/<id>/issues/<num> — update issue (status/assignee)\n"
                    "     - POST   /api/repos/<id>/issues/<num>/comments — add comment\n"
                    "  F. Pull Requests:\n"
                    "     - POST   /api/repos/<id>/pulls — open PR\n"
                    "     - GET    /api/repos/<id>/pulls — list PRs\n"
                    "     - POST   /api/repos/<id>/pulls/<num>/merge — merge PR\n"
                    "  G. Authentication:\n"
                    "     - POST   /api/auth/register — register user\n"
                    "     - POST   /api/auth/login — login, returns API token\n"
                    "     - GET    /api/auth/me — current user info\n"
                    "  H. Activity Feed:\n"
                    "     - GET    /api/activity — recent events across all repos\n"
                    "  I. Search:\n"
                    "     - GET    /api/search?q= — full-text search across repos, files, issues\n"
                    "  J. Stats:\n"
                    "     - GET    /api/stats — platform stats (repos, users, commits, issues)\n\n"
                    "Frontend (single HTML file served at /):\n"
                    "  - Modern dashboard SPA with CSS Grid/Flexbox layout\n"
                    "  - Repository browser with file tree navigation\n"
                    "  - Issue board with status columns\n"
                    "  - Pull request list with merge buttons\n"
                    "  - Activity timeline\n"
                    "  - Search bar with live results\n"
                    "  - Dark theme by default, responsive design\n"
                    "  - All JS is vanilla — no frameworks\n\n"
                    "Database (SQLite):\n"
                    "  - users, repos, files, commits, branches, issues, issue_comments,\n"
                    "    pull_requests, pr_comments, activity_log tables\n"
                    "  - Foreign key constraints, indexes for search\n"
                    "  - Auto-migration on startup\n\n"
                    "FILE STRUCTURE (create in this order):\n"
                    "  1.  repohub/__init__.py — package init with version\n"
                    "  2.  repohub/schema.py — SQLite schema + migrations\n"
                    "  3.  repohub/models.py — dataclasses: User, Repo, File, Commit,\n"
                    "      Branch, Issue, PullRequest + JSON serialization\n"
                    "  4.  repohub/db.py — database CRUD layer with connection pooling\n"
                    "  5.  repohub/auth.py — user registration, login, bcrypt-like hashing\n"
                    "      (use hashlib pbkdf2), token generation, middleware\n"
                    "  6.  repohub/repos.py — repository + file operations\n"
                    "  7.  repohub/commits.py — commit creation, history, diff computation\n"
                    "  8.  repohub/branches.py — branch CRUD, merge logic\n"
                    "  9.  repohub/issues.py — issue tracker with comments\n"
                    "  10. repohub/pulls.py — pull request workflow\n"
                    "  11. repohub/search.py — full-text search across tables\n"
                    "  12. repohub/activity.py — activity feed aggregation\n"
                    "  13. repohub/router.py — HTTP request routing + all endpoint handlers\n"
                    "  14. repohub/server.py — http.server ThreadingHTTPServer setup\n"
                    "  15. repohub/main.py — entry point, arg parsing, server start\n"
                    "  16. static/index.html — SPA dashboard frontend\n"
                    "  17. static/style.css — dark theme stylesheet\n"
                    "  18. static/app.js — vanilla JS SPA router + API client\n"
                    "  19. tests/test_repohub.py — comprehensive test suite\n"
                    "  20. README.md — architecture docs + API reference\n\n"
                    "WORKFLOW:\n"
                    "  Phase 1 (files 1-5): Core infrastructure — schema, models, DB, auth\n"
                    "  Phase 2 (files 6-10): Business logic — repos, commits, branches, issues, PRs\n"
                    "  Phase 3 (files 11-12): Search + activity feed\n"
                    "  Phase 4 (files 13-15): HTTP layer + server + entry point\n"
                    "  Phase 5 (files 16-18): Frontend SPA\n"
                    "  Phase 6 (files 19-20): Tests + docs\n"
                    "  Phase 7: Full review — read back every file, fix bugs, improve error handling\n\n"
                    "QUALITY REQUIREMENTS:\n"
                    "  - Every endpoint returns proper HTTP status codes + JSON\n"
                    "  - Comprehensive error handling (try/except, meaningful messages)\n"
                    "  - Input validation on all endpoints\n"
                    "  - SQL injection prevention (parameterized queries)\n"
                    "  - Password hashing with PBKDF2 + salt\n"
                    "  - Token-based auth with expiration\n"
                    "  - Docstrings on all public functions and classes\n"
                    "  - Type hints throughout\n"
                    "  - NO placeholders, NO 'pass', NO stubs — real working code only\n"
                    "  - Each file should be 50-200+ lines of complete implementation\n\n"
                    "Write REAL, COMPLETE, WORKING code. After each phase, review the "
                    "files you just wrote. Take your time — build production-quality "
                    "software. This is a showcase project."
                ),
            },
            {
                "role": "user",
                "content": (
                    "Build the complete Code Repository Manager. Start with Phase 1 "
                    "(core infrastructure). After each phase, read back your files to "
                    "verify correctness. When all phases are complete, do a final "
                    "full review pass, list the directory, and confirm everything "
                    "is properly wired together. Write extensive, well-documented, "
                    "production-quality code with no shortcuts."
                ),
            },
        ]

        # ---- Run the model ----
        import ollama
        os.environ.setdefault("OLLAMA_API_KEY", API_KEY)
        client = ollama.Client()

        files_created: set[str] = set()
        tool_calls_total = 0
        phase = 0
        start_time = time.time()

        print("Starting model interaction...\n")

        for turn in range(30):
            elapsed = time.time() - start_time
            print(f"[Turn {turn + 1}] {elapsed:.0f}s elapsed, {tool_calls_total} tool calls so far...")

            try:
                resp = client.chat(model=CLOUD_MODEL, messages=messages, tools=tools)
            except Exception as exc:
                print(f"  ERROR calling model: {exc}")
                report["errors"].append({"turn": turn, "error": str(exc)})
                break

            tool_calls = getattr(resp.message, "tool_calls", None) or []

            if not tool_calls:
                content = resp.message.content or ""
                if content:
                    print(f"  Model message: {content[:200]}...")
                    messages.append({"role": "assistant", "content": content})
                else:
                    print("  Model returned no tool calls and no content — ending")
                    break
                continue

            for tc in tool_calls:
                tool_name = tc.function.name
                tool_args = _parse_tool_args(tc.function.arguments)

                # ---- Evaluate through Ardur proxy ----
                status, decision, _ = _post_tls(base, "/evaluate", {
                    "session_id": sid,
                    "tool_name": tool_name,
                    "arguments": tool_args,
                })

                if status != 200 or decision.get("decision") != "PERMIT":
                    print(f"  DENIED: {tool_name}({list(tool_args.keys())}) → {decision.get('decision', 'UNKNOWN')}")
                    report["errors"].append({
                        "tool": tool_name,
                        "args_keys": list(tool_args.keys()),
                        "decision": decision,
                    })
                    result = {"status": "denied", "reason": str(decision)}
                else:
                    tool_calls_total += 1

                    if tool_name == "write_file":
                        path = tool_args.get("path", "unknown")
                        content = tool_args.get("content", "")
                        files_created.add(path)
                        print(f"  ✓ write_file: {path} ({len(content)} bytes)")
                        result = {"status": "ok", "path": path, "bytes_written": len(content)}

                    elif tool_name == "read_file":
                        path = tool_args.get("path", "")
                        print(f"  ✓ read_file: {path}")
                        result = {"status": "ok", "path": path, "exists": True}

                    elif tool_name == "list_directory":
                        path = tool_args.get("path", "")
                        print(f"  ✓ list_directory: {path}")
                        result = {"status": "ok", "path": path, "entries": sorted(files_created)}

                    elif tool_name == "search_files":
                        path = tool_args.get("path", "")
                        pattern = tool_args.get("pattern", "")
                        print(f"  ✓ search_files: {path} pattern={pattern}")
                        result = {"status": "ok", "path": path, "matches": []}

                    else:
                        result = {"status": "ok"}

                # ---- Append to conversation ----
                messages.append({
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [tc],
                })
                messages.append({
                    "role": "tool",
                    "name": tool_name,
                    "content": json.dumps(result),
                })

            # Phase tracking
            new_phase = 0
            fc = len(files_created)
            if fc >= 16:
                new_phase = 7
            elif fc >= 13:
                new_phase = 6
            elif fc >= 11:
                new_phase = 5
            elif fc >= 8:
                new_phase = 4
            elif fc >= 5:
                new_phase = 3
            elif fc >= 3:
                new_phase = 2
            elif fc >= 1:
                new_phase = 1

            if new_phase > phase:
                phase = new_phase
                print(f"\n  >>> PHASE {phase}: {fc} files created <<<\n")
                report["phases"].append({
                    "phase": phase,
                    "files_so_far": fc,
                    "elapsed_s": elapsed,
                    "tool_calls": tool_calls_total,
                })

            # After files 18+, add a nudge for review
            if fc >= 18 and not any("review" in str(m.get("content", "")).lower() for m in messages[-5:]):
                messages.append({
                    "role": "user",
                    "content": "Excellent progress! Now do a thorough review pass: "
                    "read back each file you've written and fix any bugs, "
                    "add missing error handling, and ensure all modules are "
                    "properly wired together. Then list the full directory.",
                })

        # ---- End session ----
        _post_tls(base, "/session/end", {"session_id": sid})
        total_elapsed = time.time() - start_time

        # ---- Write report ----
        report.update({
            "completed": True,
            "total_elapsed_s": total_elapsed,
            "tool_calls_total": tool_calls_total,
            "files_created": sorted(files_created),
        })

        REPORT_PATH.write_text(json.dumps(report, indent=2))
        print("\n" + "=" * 72)
        print("TEST COMPLETE")
        print(f"  Duration:       {total_elapsed:.0f}s")
        print(f"  Tool calls:     {tool_calls_total}")
        print(f"  Files created:  {len(files_created)}")
        print(f"  Report:         {REPORT_PATH}")
        print("  Files:")
        for f in sorted(files_created):
            print(f"    - {f}")
        print("=" * 72)

        if report["errors"]:
            print(f"\nWARNING: {len(report['errors'])} errors encountered:")
            for e in report["errors"]:
                print(f"  - {e}")

    finally:
        # Daemon thread will exit when process exits
        print("\nProxy daemon thread running — exiting cleanly.")


if __name__ == "__main__":
    main()
