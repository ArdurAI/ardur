"""A/B overhead measurement: model performance with vs without Ardur governance.

Runs the same creative coding task twice:
  A) WITHOUT Ardur — tools simulated locally, no proxy calls
  B) WITH Ardur — every tool call evaluated by GovernanceProxy over TLS

Compares: prompt tokens, completion tokens, total time, tool call count.
Reports absolute and percentage overhead.

Usage:
  .venv/bin/python3 tests/test_ardur_overhead_ab.py

Connects to the local Ollama server at http://localhost:11434 which
handles cloud model authentication transparently.
"""

from __future__ import annotations

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

import ollama

# Add project root to path so vibap imports work
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vibap.passport import MissionPassport, generate_keypair, issue_passport
from vibap.proxy import GovernanceProxy, serve_proxy
from vibap.tls import generate_self_signed_cert

# ---------------------------------------------------------------------------
CLOUD_MODEL = os.environ.get("ARDUR_OLLAMA_CLOUD_MODEL", "")
API_KEY = os.environ.get("ARDUR_OLLAMA_API_KEY", "")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
REPORT_PATH = Path(__file__).resolve().parent / "overhead_ab_report.json"
TURNS = 16  # enough turns for a ~5 min creative task per run
# ---------------------------------------------------------------------------


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _post_tls(base, path, payload=None):
    data = json.dumps(payload or {}).encode("utf-8")
    req = urllib.request.Request(
        base + path, data=data,
        headers={"Content-Type": "application/json"}, method="POST",
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


def _build_server_tls(proxy, private_key, port, tls_cert, tls_key):
    """Start TLS proxy in a daemon thread, return base URL."""
    import signal as _signal
    _signal.signal = lambda *_a, **_kw: None

    os.environ["ARDUR_RATE_LIMIT_RPS"] = "100"
    os.environ["ARDUR_RATE_LIMIT_BURST"] = "200"

    def run():
        serve_proxy(
            proxy=proxy, private_key=private_key,
            host="127.0.0.1", port=port,
            tls_cert=tls_cert, tls_key=tls_key,
            no_tls=False, require_auth=False, api_token="",
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
            with urllib.request.urlopen(base + "/health", timeout=1, context=ctx) as r:
                if r.status == 200:
                    break
        except Exception:
            time.sleep(0.1)
    else:
        raise RuntimeError("TLS proxy never became healthy")
    return base


# ---------------------------------------------------------------------------
# tool definitions (same for both runs)
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write content to a file at the given path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read and return the contents of a file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_directory",
            "description": "List all files and subdirectories in a directory.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                },
                "required": ["path"],
            },
        },
    },
]

SYSTEM_PROMPT = (
    "You are an expert Python developer building a complete application "
    "from scratch. You have access to write_file, read_file, and "
    "list_directory tools.\n\n"
    "YOUR TASK: Build a 'Task Tracker CLI' — a complete, working "
    "Python command-line application using ONLY the standard library. "
    "No external dependencies.\n\n"
    "The application must have:\n"
    "1. Task CRUD: add, list, update, delete tasks with priority and status\n"
    "2. SQLite for persistence (auto-creates the database)\n"
    "3. A clean CLI with argparse subcommands: add, list, done, undo, delete, stats\n"
    "4. Proper error handling and colored terminal output (ANSI codes)\n\n"
    "WORKFLOW — build iteratively:\n"
    "- Step 1: Write tracker/schema.py — database schema\n"
    "- Step 2: Write tracker/models.py — Task dataclass + serialization\n"
    "- Step 3: Write tracker/storage.py — SQLite CRUD operations\n"
    "- Step 4: Write tracker/cli.py — argparse CLI with all subcommands\n"
    "- Step 5: Write tracker/__init__.py — package init\n"
    "- Step 6: Write main.py — entry point\n"
    "- Step 7: Write tests/test_tracker.py — comprehensive tests\n"
    "- Step 8: Read back each file and review for bugs, then fix them\n\n"
    "Write REAL, COMPLETE, WORKING code — no placeholders or stubs. "
    "Each file fully implemented with docstrings."
)


def build_initial_messages():
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": (
            "Build the complete Task Tracker CLI. Write every file with full "
            "implementations. Create the tracker/ package directory structure. "
            "After writing all files, review each one and fix bugs. "
            "Write production-quality code."
        )},
    ]


# ---------------------------------------------------------------------------
# Run A: WITHOUT Ardur (local tool simulation)
# ---------------------------------------------------------------------------

def run_without_ardur(client) -> dict[str, Any]:
    """Model calls tools; harness simulates results locally. No proxy."""
    messages = build_initial_messages()

    total_prompt_tokens = 0
    total_completion_tokens = 0
    total_duration_ns = 0
    tool_calls_total = 0
    files_created: set[str] = set()
    turns_used = 0

    t0 = time.time()

    for turn in range(TURNS):
        resp = client.chat(model=CLOUD_MODEL, messages=messages, tools=TOOLS)

        total_prompt_tokens += getattr(resp, "prompt_eval_count", 0) or 0
        total_completion_tokens += getattr(resp, "eval_count", 0) or 0
        total_duration_ns += getattr(resp, "total_duration", 0) or 0

        tool_calls = getattr(resp.message, "tool_calls", None)
        if not tool_calls:
            if resp.message.content:
                messages.append({"role": "assistant", "content": resp.message.content})
            continue

        turns_used = turn + 1

        tool_msgs = []
        for tc in tool_calls:
            tool_name = tc.function.name
            tool_args = tc.function.arguments
            if isinstance(tool_args, str):
                try:
                    tool_args = json.loads(tool_args)
                except json.JSONDecodeError:
                    tool_args = {}
            tool_calls_total += 1

            # Simulate tool locally — no governance
            if tool_name == "write_file":
                files_created.add(tool_args.get("path", "unknown"))
                result = {
                    "status": "ok", "path": tool_args.get("path", ""),
                    "bytes_written": len(tool_args.get("content", "")),
                }
            elif tool_name == "read_file":
                result = {"status": "ok", "path": tool_args.get("path", ""), "exists": True}
            elif tool_name == "list_directory":
                result = {"status": "ok", "path": tool_args.get("path", ""), "entries": sorted(files_created)}
            else:
                result = {"status": "ok"}

            tool_msgs.append(tc)
            messages.append({"role": "tool", "name": tool_name, "content": json.dumps(result)})

        messages.append({"role": "assistant", "content": None, "tool_calls": tool_msgs})

        # Progress prompts (same at same thresholds as B run)
        if len(files_created) >= 4 and not any(
            m.get("content", "") and "review pass" in str(m.get("content", ""))
            for m in messages if m["role"] == "user"
        ):
            messages.append({"role": "user", "content": (
                "Good. Now do a code review — read back each file, check for bugs, "
                "edge cases, and fix everything you find."
            )})

    wall_s = time.time() - t0
    return {
        "label": "without_ardur",
        "wall_seconds": round(wall_s, 1),
        "prompt_tokens": total_prompt_tokens,
        "completion_tokens": total_completion_tokens,
        "total_tokens": total_prompt_tokens + total_completion_tokens,
        "total_duration_ns": total_duration_ns,
        "total_duration_s": round(total_duration_ns / 1e9, 1),
        "tool_calls": tool_calls_total,
        "files_created": len(files_created),
        "turns_used": turns_used,
    }


# ---------------------------------------------------------------------------
# Run B: WITH Ardur (full governance over TLS)
# ---------------------------------------------------------------------------

def run_with_ardur(client, base, sid) -> dict[str, Any]:
    """Every tool call evaluated by GovernanceProxy before execution."""
    messages = build_initial_messages()

    total_prompt_tokens = 0
    total_completion_tokens = 0
    total_duration_ns = 0
    tool_calls_total = 0
    files_created: set[str] = set()
    turns_used = 0

    t0 = time.time()

    for turn in range(TURNS):
        resp = client.chat(model=CLOUD_MODEL, messages=messages, tools=TOOLS)

        total_prompt_tokens += getattr(resp, "prompt_eval_count", 0) or 0
        total_completion_tokens += getattr(resp, "eval_count", 0) or 0
        total_duration_ns += getattr(resp, "total_duration", 0) or 0

        tool_calls = getattr(resp.message, "tool_calls", None)
        if not tool_calls:
            if resp.message.content:
                messages.append({"role": "assistant", "content": resp.message.content})
            continue

        turns_used = turn + 1

        tool_msgs = []
        for tc in tool_calls:
            tool_name = tc.function.name
            tool_args = tc.function.arguments
            if isinstance(tool_args, str):
                try:
                    tool_args = json.loads(tool_args)
                except json.JSONDecodeError:
                    tool_args = {}
            tool_calls_total += 1

            # Governance evaluation over TLS
            status, decision, _ = _post_tls(base, "/evaluate", {
                "session_id": sid,
                "tool_name": tool_name,
                "arguments": tool_args,
            })
            if status != 200 or decision.get("decision") != "PERMIT":
                result = {"status": "denied", "reason": decision.get("reason", "unknown")}
            elif tool_name == "write_file":
                files_created.add(tool_args.get("path", "unknown"))
                result = {
                    "status": "ok", "path": tool_args.get("path", ""),
                    "bytes_written": len(tool_args.get("content", "")),
                }
            elif tool_name == "read_file":
                result = {"status": "ok", "path": tool_args.get("path", ""), "exists": True}
            elif tool_name == "list_directory":
                result = {"status": "ok", "path": tool_args.get("path", ""), "entries": sorted(files_created)}
            else:
                result = {"status": "ok"}

            tool_msgs.append(tc)
            messages.append({"role": "tool", "name": tool_name, "content": json.dumps(result)})

        messages.append({"role": "assistant", "content": None, "tool_calls": tool_msgs})

        if len(files_created) >= 4 and not any(
            m.get("content", "") and "review pass" in str(m.get("content", ""))
            for m in messages if m["role"] == "user"
        ):
            messages.append({"role": "user", "content": (
                "Good. Now do a code review — read back each file, check for bugs, "
                "edge cases, and fix everything you find."
            )})

    wall_s = time.time() - t0
    return {
        "label": "with_ardur",
        "wall_seconds": round(wall_s, 1),
        "prompt_tokens": total_prompt_tokens,
        "completion_tokens": total_completion_tokens,
        "total_tokens": total_prompt_tokens + total_completion_tokens,
        "total_duration_ns": total_duration_ns,
        "total_duration_s": round(total_duration_ns / 1e9, 1),
        "tool_calls": tool_calls_total,
        "files_created": len(files_created),
        "turns_used": turns_used,
    }


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def compute_overhead(no_ardur: dict, with_ardur: dict) -> dict:
    def pct(a, b):
        if b == 0:
            return None
        return round((a - b) / b * 100, 1)

    return {
        "prompt_tokens_overhead_pct": pct(
            with_ardur["prompt_tokens"], no_ardur["prompt_tokens"]),
        "completion_tokens_overhead_pct": pct(
            with_ardur["completion_tokens"], no_ardur["completion_tokens"]),
        "total_tokens_overhead_pct": pct(
            with_ardur["total_tokens"], no_ardur["total_tokens"]),
        "wall_time_overhead_pct": pct(
            with_ardur["wall_seconds"], no_ardur["wall_seconds"]),
        "model_time_overhead_pct": pct(
            with_ardur["total_duration_s"], no_ardur["total_duration_s"]),
        "tool_calls_delta": with_ardur["tool_calls"] - no_ardur["tool_calls"],
    }


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    client = ollama.Client(host=OLLAMA_HOST)
    try:
        model_names = [m.model for m in client.list().models]
        if not any("cloud" in m for m in model_names):
            print("SKIPPED: no cloud-capable model found in local ollama")
            sys.exit(0)
    except Exception as exc:
        print(f"SKIPPED: cannot reach ollama at {OLLAMA_HOST}: {exc}")
        sys.exit(0)

    print("=" * 60)
    print("Ardur Governance Overhead — A/B Measurement")
    print(f"Model: {CLOUD_MODEL}  |  Max turns per run: {TURNS}")
    print("=" * 60)

    # ------- Run A: WITHOUT Ardur -------
    print("\n>>> Run A: WITHOUT Ardur (local tool simulation)")
    result_no_ardur = run_without_ardur(client)
    print(f"  prompt_tokens={result_no_ardur['prompt_tokens']}  "
          f"completion_tokens={result_no_ardur['completion_tokens']}  "
          f"total_tokens={result_no_ardur['total_tokens']}")
    print(f"  model_time={result_no_ardur['total_duration_s']}s  "
          f"wall_time={result_no_ardur['wall_seconds']}s  "
          f"tool_calls={result_no_ardur['tool_calls']}  "
          f"files={result_no_ardur['files_created']}")

    # ------- Run B: WITH Ardur -------
    print("\n>>> Run B: WITH Ardur (governance proxy over TLS)")

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        keys_dir = Path(td)
        private_key, public_key = generate_keypair(keys_dir=keys_dir)

        tls_dir = Path(td) / "tls"
        tls_dir.mkdir()
        tls_key, tls_cert, _ = generate_self_signed_cert(tls_dir, hostname="127.0.0.1")

        proxy = GovernanceProxy(
            log_path=Path(td) / "gov.jsonl",
            state_dir=Path(td) / "state",
            public_key=public_key,
            private_key=private_key,
            keys_dir=keys_dir,
        )

        port = _free_port()
        base = _build_server_tls(proxy, private_key, port, tls_cert, tls_key)

        # Start a JWT session
        mission = MissionPassport(
            agent_id="ab-test-agent",
            mission="build Task Tracker CLI",
            allowed_tools=["read_file", "write_file", "list_directory", "search_files"],
            forbidden_tools=["delete_file", "execute_shell"],
            resource_scope=[],
            max_tool_calls=200,
            max_duration_s=1800,
        )
        token = issue_passport(mission, private_key, ttl_s=600)
        status, body, _ = _post_tls(base, "/session/start", {"token": token})
        assert status == 200, f"session start failed: {body}"
        sid = body["session_id"]

        result_with_ardur = run_with_ardur(client, base, sid)

        _post_tls(base, "/session/end", {"session_id": sid})

    print(f"  prompt_tokens={result_with_ardur['prompt_tokens']}  "
          f"completion_tokens={result_with_ardur['completion_tokens']}  "
          f"total_tokens={result_with_ardur['total_tokens']}")
    print(f"  model_time={result_with_ardur['total_duration_s']}s  "
          f"wall_time={result_with_ardur['wall_seconds']}s  "
          f"tool_calls={result_with_ardur['tool_calls']}  "
          f"files={result_with_ardur['files_created']}")

    # ------- Overhead report -------
    overhead = compute_overhead(result_no_ardur, result_with_ardur)

    print("\n" + "=" * 60)
    print("OVERHEAD SUMMARY")
    print("=" * 60)
    for key, val in overhead.items():
        label = key.replace("_", " ").replace("pct", "(%)")
        if val is None:
            print(f"  {label}: N/A")
        else:
            print(f"  {label}: {val:+}")

    report = {
        "model": CLOUD_MODEL,
        "max_turns": TURNS,
        "without_ardur": result_no_ardur,
        "with_ardur": result_with_ardur,
        "overhead": overhead,
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nReport → {REPORT_PATH}")

    # Quick sanity assertion
    assert result_no_ardur["tool_calls"] >= 5, "Run A: too few tool calls"
    assert result_with_ardur["tool_calls"] >= 5, "Run B: too few tool calls"
    assert result_no_ardur["files_created"] >= 3, "Run A: too few files"
    assert result_with_ardur["files_created"] >= 3, "Run B: too few files"


if __name__ == "__main__":
    main()
