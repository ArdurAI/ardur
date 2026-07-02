"""``ardur run`` governance bridge — zero-setup auto-governance for a launched agent.

This is the bridge layer that turns Ardur's detection into governance. Running

    ardur run --mission "..." --allowed-tools Read,Glob --max-tool-calls 50 -- <agent-cmd...>

does all of this with no prior ``ardur protect`` and no permanent edits to the
user's ``~/.claude/settings.json``:

1. Issues a Mission Passport and starts a governance session for the agent, in a
   private ephemeral Ardur home (keys + state + active passport).
2. Launches ``<agent-cmd>`` with the environment that routes the agent's
   tool-call governance to this session. For a hook-supporting agent (Claude
   Code) it points the hook at this run via ``VIBAP_HOME`` + a scoped
   ``--plugin-dir`` — temporary, run-scoped, no settings.json mutation.
3. If the eBPF kernelcapture daemon is available, creates a dedicated cgroup for
   the agent and registers it with the daemon, closing the detect→session link.
   Otherwise it degrades gracefully and still governs via the hook/env path.
4. On agent exit, finalizes the session into a behavioral attestation + a signed
   receipt chain and prints a short governance summary.

The transparent-intercept path for non-hook agents (Grok/Kimi/arbitrary CLIs)
is scaffolded only — see :class:`TransparentInterceptAdapter`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import kernel_correlation as kc

# Environment-variable contract the bridge exports to the launched agent. The
# proxy-routed path (EnvProxyAdapter) and any cooperating agent read these.
ENV_PROXY_URL = "ARDUR_PROXY_URL"
ENV_API_TOKEN = "ARDUR_API_TOKEN"
ENV_SESSION_ID = "ARDUR_SESSION_ID"
ENV_HOME = "VIBAP_HOME"
ENV_MISSION_PASSPORT = "ARDUR_MISSION_PASSPORT"
ENV_TRACE_ID = "ARDUR_TRACE_ID"

DEFAULT_AGENT_ID = "local-user:ardur-run"
DEFAULT_MAX_TOOL_CALLS = 250
DEFAULT_MAX_DURATION_S = 86400

VALID_VIA_MODES = ("auto", "env", "claude-code", "intercept")


# ── agent adapters ─────────────────────────────────────────────────────────────


@dataclass
class RunContext:
    """Everything an adapter needs to wire an agent into the live session."""

    home: Path
    passport_token: str
    passport_path: Path
    session_id: str
    mission_id: str
    trace_id: str
    proxy_url: str
    api_token: str
    plugin_dir: Path | None


class AgentAdapter:
    """Strategy for routing a launched agent's tool calls to the session."""

    name = "base"

    def prepare(
        self,
        ctx: RunContext,
        command: list[str],
        base_env: dict[str, str],
    ) -> tuple[dict[str, str], list[str], list[str]]:
        """Return ``(env, command, notes)`` for launching the agent."""
        raise NotImplementedError


class EnvProxyAdapter(AgentAdapter):
    """Route governance via environment variables to the embedded proxy.

    This is the generic path: a cooperating agent (or the integration test's
    stand-in) reads :data:`ENV_PROXY_URL`/:data:`ENV_API_TOKEN`/
    :data:`ENV_SESSION_ID` and POSTs each tool call to ``/evaluate`` before
    acting on it.
    """

    name = "env-proxy"

    def prepare(
        self,
        ctx: RunContext,
        command: list[str],
        base_env: dict[str, str],
    ) -> tuple[dict[str, str], list[str], list[str]]:
        env = dict(base_env)
        env[ENV_PROXY_URL] = ctx.proxy_url
        env[ENV_API_TOKEN] = ctx.api_token
        env[ENV_SESSION_ID] = ctx.session_id
        env[ENV_HOME] = str(ctx.home)
        env[ENV_MISSION_PASSPORT] = str(ctx.passport_path)
        env[ENV_TRACE_ID] = ctx.trace_id
        return env, list(command), [f"governance routed via env → {ctx.proxy_url}/evaluate"]


class ClaudeCodeAdapter(EnvProxyAdapter):
    """Point Claude Code's hook at this run without touching settings.json.

    Builds on :class:`EnvProxyAdapter` (so the proxy env is also present) and
    additionally activates the Claude Code plugin for *this run only* by
    injecting ``--plugin-dir`` into the ``claude`` invocation. Combined with the
    ``VIBAP_HOME`` the base adapter sets — which makes the hook load this run's
    ``active_mission.jwt`` — the agent is governed by the hook with zero
    permanent configuration. Nothing is written to ``~/.claude/settings.json``.

    .. note::
        **Receipt gap**: the Claude Code hook evaluates tool calls locally via
        the plugin mechanism; it does **not** POST to ``ARDUR_PROXY_URL``
        (``/evaluate``).  As a result, ``RunResult.total_events`` is 0 on this
        path — governance is enforced by the hook but the embedded proxy-side
        receipt chain is empty.  The hook's own JSONL output in ``VIBAP_HOME``
        is the authoritative governance record for ClaudeCode invocations.
        Wiring the hook to also report to the embedded proxy is tracked as a
        follow-up under Epic A (#63).
    """

    name = "claude-code"

    _CLAUDE_BASENAMES = {"claude", "claude-code"}

    def prepare(
        self,
        ctx: RunContext,
        command: list[str],
        base_env: dict[str, str],
    ) -> tuple[dict[str, str], list[str], list[str]]:
        env, command, notes = super().prepare(ctx, command, base_env)
        new_command = list(command)
        basename = Path(command[0]).name if command else ""
        if (
            basename in self._CLAUDE_BASENAMES
            and ctx.plugin_dir is not None
            and "--plugin-dir" not in command
        ):
            new_command = [command[0], "--plugin-dir", str(ctx.plugin_dir), *command[1:]]
            notes.append(
                f"Claude Code hook scoped to this run via --plugin-dir {ctx.plugin_dir} "
                "and VIBAP_HOME (no settings.json edit)"
            )
        else:
            notes.append(
                "Claude Code hook scoped via VIBAP_HOME (no settings.json edit); "
                "--plugin-dir left as supplied"
            )
        return env, new_command, notes


class TransparentInterceptAdapter(AgentAdapter):
    """SCAFFOLD: transparent interception for non-hook agents.

    Grok, Kimi, and arbitrary CLIs do not expose a tool-call hook, so governance
    cannot be wired through env or a plugin. The intended mechanism is to
    transparently intercept the agent's *egress* (model/tool API traffic) and
    route it through the governance proxy, via one of:

    * an ``iptables`` REDIRECT (Linux) sending the agent's outbound connections
      to a local transparent proxy that evaluates each tool call, or
    * an ``LD_PRELOAD`` / proxy-env shim that injects ``HTTP(S)_PROXY`` and a
      CA-trust bundle so the agent's HTTPS client talks to the governance proxy.

    This is intentionally NOT implemented in this slice. It is the follow-up for
    issue #69 (wire governance to auto-detected agents). The interface is fixed
    here so the launcher can dispatch to it once the path is built.
    """

    name = "transparent-intercept"

    def prepare(
        self,
        ctx: RunContext,
        command: list[str],
        base_env: dict[str, str],
    ) -> tuple[dict[str, str], list[str], list[str]]:
        raise NotImplementedError(
            "transparent-intercept governance is scaffolded only (issue #69). "
            "Use --via env for cooperating agents or --via claude-code for Claude Code. "
            "TODO: iptables REDIRECT / LD_PRELOAD egress shim to the governance proxy."
        )


def select_adapter(command: list[str], via: str) -> AgentAdapter:
    if via == "env":
        return EnvProxyAdapter()
    if via == "claude-code":
        return ClaudeCodeAdapter()
    if via == "intercept":
        return TransparentInterceptAdapter()
    # auto
    basename = Path(command[0]).name if command else ""
    if basename in ClaudeCodeAdapter._CLAUDE_BASENAMES:
        return ClaudeCodeAdapter()
    return EnvProxyAdapter()


def _claude_plugin_dir() -> Path | None:
    candidate = Path(__file__).resolve().parents[2] / "plugins" / "claude-code"
    return candidate if candidate.exists() else None


# ── embedded governance server ─────────────────────────────────────────────────


def _build_embedded_server(
    proxy: Any,
    session_id: str,
    api_token: str,
    private_key: Any,
    host: str = "127.0.0.1",
) -> ThreadingHTTPServer:
    """A minimal loopback HTTP server delegating to the real GovernanceProxy.

    Exposes just the endpoints the launched agent needs (``/health``,
    ``/evaluate``, ``/result``, ``/session/end``, ``/attest``). It reuses the
    proxy's real evaluation, receipt-signing, and attestation logic — it is only
    the transport. Unlike :func:`proxy.serve_proxy` it is cleanly stoppable
    (``shutdown()``), which the launcher needs so the server does not outlive the
    run (important when the bridge runs in-process under a test).
    """
    from .proxy import Decision

    token_material = api_token.encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        server_version = "ArdurRunBridge/0.1"

        def log_message(self, *_args: object) -> None:  # silence default logging
            return

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            prefix = "Bearer "
            if not header.startswith(prefix):
                return False
            supplied = header[len(prefix):].strip().encode("utf-8")
            return hmac.compare_digest(supplied, token_material)

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(raw.decode("utf-8") or "{}")
            if not isinstance(data, dict):
                raise ValueError("request body must be a JSON object")
            return data

        def do_GET(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] in {"/health", "/healthz"}:
                self._send(200, {"status": "ok", "session_id": session_id})
                return
            self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if not self._authorized():
                self._send(401, {"error": "unauthorized"})
                return
            try:
                payload = self._read_json()
            except (ValueError, UnicodeDecodeError) as exc:
                self._send(400, {"error": f"bad request: {exc}"})
                return
            sid = str(payload.get("session_id") or session_id)
            try:
                if path == "/evaluate":
                    arguments = payload.get("arguments") or {}
                    if not isinstance(arguments, dict):
                        raise ValueError("arguments must be a JSON object")
                    tool_name = payload.get("tool_name")
                    if not tool_name:
                        raise ValueError("missing field: tool_name")
                    decision, reason = proxy.evaluate_tool_call(sid, str(tool_name), dict(arguments))
                    response: dict[str, Any] = {"decision": decision.value, "session_id": sid}
                    if decision != Decision.PERMIT:
                        response["reason"] = reason
                    self._send(200, response)
                    return
                if path == "/result":
                    proxy.record_tool_result(
                        sid,
                        str(payload.get("response", "")),
                        float(payload.get("duration_ms", 0.0)),
                    )
                    self._send(200, {"status": "recorded"})
                    return
                if path in {"/session/end", "/end"}:
                    summary = proxy.end_session(sid)
                    token, _ = proxy.issue_attestation_for_session(sid, private_key)
                    self._send(200, {"attestation_token": token, "summary": summary})
                    return
                if path == "/attest":
                    token, claims = proxy.issue_attestation_for_session(sid, private_key)
                    self._send(200, {"token": token, "claims": claims})
                    return
            except (ValueError, KeyError, PermissionError) as exc:
                self._send(400, {"error": str(exc)})
                return
            except Exception as exc:  # noqa: BLE001 — embedded server must not crash the run
                self._send(500, {"error": f"internal error: {exc}"})
                return
            self._send(404, {"error": "not found"})

    server = ThreadingHTTPServer((host, 0), Handler)
    return server


# ── result type ────────────────────────────────────────────────────────────────


@dataclass
class GovernanceRunResult:
    exit_code: int
    session_id: str
    mission_id: str
    agent_id: str
    adapter: str
    via: str
    proxy_url: str
    home: str
    passport_path: str
    summary: dict[str, Any]
    permits: int
    denials: int
    total_events: int
    attestation_token: str
    attestation_digest: str
    receipts_path: str
    receipt_count: int
    correlation: dict[str, Any]
    notes: list[str] = field(default_factory=list)


def _count_lines(path: Path) -> int:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


def _write_private_text(path: Path, text: str) -> None:
    """Write sensitive run-scoped text without a permissive-umask window."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(text)
    finally:
        if fd != -1:
            os.close(fd)


def _attestation_digest(token: str) -> str:
    return "sha-256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


# ── kernel correlation orchestration ───────────────────────────────────────────


def _correlate_launch(
    *,
    session_id: str,
    mission_id: str,
    trace_id: str,
    pid: int,
    cgroup_handle: kc.CgroupHandle | None,
    ttl_seconds: int,
    enabled: bool,
) -> kc.CorrelationResult:
    """Register the launched process's cgroup with the eBPF daemon, if possible.

    Never raises — returns an ``available=False`` result describing why
    correlation was skipped or failed, so the caller can keep governing.
    """
    socket_path = kc.daemon_socket_path()
    if not enabled:
        return kc.CorrelationResult(available=False, reason="kernel correlation disabled by caller")
    if cgroup_handle is None:
        return kc.CorrelationResult(
            available=False,
            reason="cgroup v2 unavailable or not writable (governing via env/hook only)",
            method="degraded",
            daemon_socket=str(socket_path),
        )
    if not kc.daemon_available(socket_path):
        return kc.CorrelationResult(
            available=False,
            reason="eBPF kernelcapture daemon socket not present (cgroup created, governing via env/hook)",
            method="degraded",
            cgroup_id=cgroup_handle.cgroup_id,
            cgroup_path=str(cgroup_handle.path),
            daemon_socket=str(socket_path),
        )
    try:
        client = kc.KernelCaptureClient(socket_path)
        response = client.register_session(
            session_id=session_id,
            root_pid=pid,
            cgroup_id=cgroup_handle.cgroup_id,
            ttl_seconds=ttl_seconds,
            mission_id=mission_id,
            trace_id=trace_id,
        )
    except (kc.DaemonUnavailable, kc.DaemonProtocolError, ValueError) as exc:
        return kc.CorrelationResult(
            available=False,
            reason=f"daemon registration failed: {exc}",
            method="degraded",
            cgroup_id=cgroup_handle.cgroup_id,
            cgroup_path=str(cgroup_handle.path),
            daemon_socket=str(socket_path),
        )
    return kc.CorrelationResult(
        available=True,
        reason="cgroup registered with eBPF daemon; detect→session link active",
        method="cgroup_daemon_register",
        cgroup_id=cgroup_handle.cgroup_id,
        cgroup_path=str(cgroup_handle.path),
        daemon_socket=str(socket_path),
        daemon_status=str(response.get("status") or "registered"),
    )


def _kernel_enforcement_claim(
    session_id: str,
    correlation: kc.CorrelationResult,
) -> dict[str, Any] | None:
    """Fetch the daemon's kernel-enforcement rollup for a correlated session.

    Returns ``None`` (never raises) when correlation was never established or
    the daemon cannot be reached — kernel enforcement data is an enhancement
    to the attestation, never a hard dependency for finalizing a run. This
    must be called before the kernel daemon's ``end_session``, which retires
    the session's enforcement summary daemon-side.
    """
    if not correlation.available:
        return None
    try:
        client = kc.KernelCaptureClient(kc.daemon_socket_path())
        response = client.session_status(session_id=session_id)
    except (kc.DaemonUnavailable, kc.DaemonProtocolError, ValueError):
        return None
    enforcement = response.get("enforcement")
    if not isinstance(enforcement, dict):
        return None
    return enforcement


# ── main entry ─────────────────────────────────────────────────────────────────


def run_governed(
    *,
    command: list[str],
    mission: str | None = None,
    allowed_tools: list[str] | None = None,
    forbidden_tools: list[str] | None = None,
    max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS,
    max_duration_s: int = DEFAULT_MAX_DURATION_S,
    home: Path | None = None,
    via: str = "auto",
    agent_id: str = DEFAULT_AGENT_ID,
    env: dict[str, str] | None = None,
    enable_kernel_correlation: bool = True,
    cwd: Path | None = None,
    stdout: Any | None = None,
    stderr: Any | None = None,
) -> GovernanceRunResult:
    """Launch ``command`` under a fresh, fully-governed Ardur session.

    Returns a :class:`GovernanceRunResult` once the agent exits. Raises
    ``ValueError`` for invalid input (empty command, bad ``via``) and
    ``NotImplementedError`` for the scaffolded intercept path.
    """
    from .passport import MissionPassport, generate_keypair, issue_passport

    if not command:
        raise ValueError("ardur run requires a command to govern")
    if via not in VALID_VIA_MODES:
        raise ValueError(f"unknown --via mode: {via!r} (choose from {', '.join(VALID_VIA_MODES)})")

    work_dir = Path(cwd).expanduser().resolve() if cwd else Path.cwd()

    ephemeral = home is None
    if ephemeral:
        home = Path(tempfile.mkdtemp(prefix="ardur-run-"))
    else:
        home = Path(home).expanduser().resolve()
        home.mkdir(parents=True, exist_ok=True)
    keys_dir = home / "keys"
    state_dir = home / "state"

    # 1. Key material + Mission Passport (zero manual `ardur protect`).
    private_key, _public_key = generate_keypair(keys_dir=keys_dir)
    mission_text = mission or "Ardur-governed agent run."
    passport = MissionPassport(
        agent_id=agent_id,
        mission=mission_text,
        allowed_tools=list(allowed_tools or []),
        forbidden_tools=list(forbidden_tools or []),
        resource_scope=[str(work_dir), f"{work_dir}/*"],
        cwd=str(work_dir),
        max_tool_calls=max_tool_calls,
        max_duration_s=max_duration_s,
    )
    token = issue_passport(passport, private_key, ttl_s=max_duration_s)
    passport_path = home / "active_mission.jwt"
    _write_private_text(passport_path, token + "\n")

    # 2. Embedded governance proxy + session.
    from .proxy import GovernanceProxy

    proxy = GovernanceProxy(
        log_path=home / "governance_log.jsonl",
        state_dir=state_dir,
        keys_dir=keys_dir,
    )
    session = proxy.start_session(token)
    session_id = session.jti
    mission_id = str(session.passport_claims.get("mission_id") or "")
    trace_id = session_id

    api_token = _generate_api_token()
    server = _build_embedded_server(proxy, session_id, api_token, proxy.receipt_private_key)
    port = server.server_address[1]
    proxy_url = f"http://127.0.0.1:{port}"
    server_thread = threading.Thread(target=server.serve_forever, name="ardur-run-proxy", daemon=True)
    server_thread.start()

    cgroup_handle: kc.CgroupHandle | None = None
    daemon_registered = False
    proc: subprocess.Popen[bytes] | None = None
    notes: list[str] = []
    # Pre-initialized so the finally block has a safe value even if an
    # exception is raised before kernel correlation is attempted below.
    correlation = kc.CorrelationResult(available=False, reason="run did not reach kernel correlation")
    try:
        _wait_for_health(proxy_url, api_token)

        # 3. Build the run environment via the selected adapter.
        adapter = select_adapter(command, via)
        ctx = RunContext(
            home=home,
            passport_token=token,
            passport_path=passport_path,
            session_id=session_id,
            mission_id=mission_id,
            trace_id=trace_id,
            proxy_url=proxy_url,
            api_token=api_token,
            plugin_dir=_claude_plugin_dir(),
        )
        run_env, run_command, adapter_notes = adapter.prepare(
            ctx, command, env if env is not None else dict(os.environ)
        )
        notes.extend(adapter_notes)

        # 4. Dedicated cgroup (Linux + cgroup v2 + writable), best effort.
        if enable_kernel_correlation:
            cgroup_handle = kc.create_run_cgroup(session_id)

        # 5. Launch the agent.
        proc = subprocess.Popen(
            run_command,
            env=run_env,
            cwd=str(work_dir),
            stdout=stdout,
            stderr=stderr,
        )

        if cgroup_handle is not None:
            try:
                cgroup_handle.adopt_pid(proc.pid)
            except OSError:
                cgroup_handle.cleanup()
                cgroup_handle = None

        correlation = _correlate_launch(
            session_id=session_id,
            mission_id=mission_id,
            trace_id=trace_id,
            pid=proc.pid,
            cgroup_handle=cgroup_handle,
            ttl_seconds=min(max_duration_s, kc.MAX_TTL_SECONDS),
            enabled=enable_kernel_correlation,
        )
        daemon_registered = correlation.available

        # 6. Wait for the agent to exit (bounded by the mission duration budget).
        try:
            exit_code = proc.wait(timeout=max_duration_s)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                exit_code = proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                exit_code = proc.wait()
            notes.append(f"agent exceeded max-duration {max_duration_s}s and was terminated")
    finally:
        # 7. Finalize the governance session: attestation + receipt chain.
        # Kernel enforcement must be fetched before the kernel daemon's
        # end_session call below, which retires the session's summary.
        kernel_enforcement = _kernel_enforcement_claim(session_id, correlation)
        summary = proxy.end_session(session_id)
        attestation_token, _claims = proxy.issue_attestation_for_session(
            session_id, proxy.receipt_private_key, kernel_enforcement=kernel_enforcement
        )
        if daemon_registered and cgroup_handle is not None:
            try:
                kc.KernelCaptureClient(kc.daemon_socket_path()).end_session(
                    session_id=session_id, trace_id=trace_id
                )
            except (kc.DaemonUnavailable, kc.DaemonProtocolError):
                notes.append("kernel daemon end_session unavailable during local cleanup")
        if cgroup_handle is not None:
            cgroup_handle.cleanup()
        server.shutdown()
        server.server_close()

    receipts_path = proxy.receipts_log_path
    result = GovernanceRunResult(
        exit_code=exit_code if proc is not None else 127,
        session_id=session_id,
        mission_id=mission_id,
        agent_id=agent_id,
        adapter=adapter.name,
        via=via,
        proxy_url=proxy_url,
        home=str(home),
        passport_path=str(passport_path),
        summary=dict(summary),
        permits=int(summary.get("permits", 0)),
        denials=int(summary.get("denials", 0)),
        total_events=int(summary.get("total_events", 0)),
        attestation_token=attestation_token,
        attestation_digest=_attestation_digest(attestation_token),
        receipts_path=str(receipts_path),
        receipt_count=_count_lines(receipts_path),
        correlation=correlation.to_dict(),
        notes=notes,
    )
    return result


def _generate_api_token() -> str:
    import secrets

    return secrets.token_urlsafe(32)


def _wait_for_health(proxy_url: str, api_token: str, timeout_s: float = 5.0) -> None:
    deadline = time.time() + timeout_s
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            request = urllib.request.Request(f"{proxy_url}/health", method="GET")
            with urllib.request.urlopen(request, timeout=1.0) as response:  # noqa: S310 — loopback only
                if response.status == 200:
                    return
        except (urllib.error.URLError, OSError) as exc:
            last_error = exc
            time.sleep(0.02)
    raise RuntimeError(f"embedded governance proxy did not become healthy: {last_error}")


# ── human-readable summary + CLI glue ──────────────────────────────────────────


def format_summary(result: GovernanceRunResult) -> str:
    lines = [
        "── Ardur governance summary ─────────────────────────────",
        f"  session       {result.session_id}",
        f"  mission_id    {result.mission_id}",
        f"  adapter       {result.adapter} (--via {result.via})",
        f"  tool calls    {result.total_events} evaluated "
        f"({result.permits} permit / {result.denials} deny)",
        f"  receipts      {result.receipt_count} signed → {result.receipts_path}",
        f"  attestation   {result.attestation_digest}",
        f"  kernel link   {result.correlation.get('reason')}",
        f"  agent exit    {result.exit_code}",
    ]
    for note in result.notes:
        lines.append(f"  note          {note}")
    lines.append("─────────────────────────────────────────────────────────")
    return "\n".join(lines)


def run_governed_missing_command_next_steps() -> list[dict[str, str]]:
    """Return deterministic stderr remediation hints for malformed governance runs."""
    return [
        {
            "condition": "missing_governance_run_command",
            "action": "pass_command_after_separator",
            "command": "ardur run --mission <mission> --allowed-tools <tools> -- <command>",
            "detail": (
                "Pass one non-interactive local command after --. Keep secrets, raw tokens, "
                "and private paths out of shared command examples."
            ),
        },
        {
            "condition": "missing_governance_run_command",
            "action": "use_explicit_home_only_when_needed",
            "command": "ardur run --home <ardur-home> --mission <mission> --via env -- <command>",
            "detail": (
                "Use an explicit Ardur home placeholder only when you need a durable local "
                "evidence home; omit --home for the default ephemeral governance run."
            ),
        },
        {
            "condition": "missing_governance_run_command",
            "action": "check_local_setup_before_running",
            "command": "ardur doctor --home <ardur-home>",
            "detail": (
                "Confirm local setup before retrying if you use a persistent home. This "
                "guidance is local/no-key recovery only; it does not execute a child "
                "command, call live providers, or broaden runtime-capture claims."
            ),
        },
    ]


def _print_run_governed_missing_command_next_steps() -> None:
    print("Next steps:", file=sys.stderr)
    for index, step in enumerate(run_governed_missing_command_next_steps(), start=1):
        print(f"{index}. {step['command']}", file=sys.stderr)
        detail = step.get("detail", "")
        if detail:
            print(f"   {detail}", file=sys.stderr)


def run_governed_cli(args: Any) -> int:
    """Argparse entry point used by ``cmd_run`` when governance flags are present."""
    command = list(getattr(args, "command", None) or [])
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("ardur run requires a command to govern after --", file=sys.stderr)
        print("usage: ardur run --mission \"...\" --allowed-tools Read,Glob -- <agent-cmd...>", file=sys.stderr)
        _print_run_governed_missing_command_next_steps()
        return 2

    allowed = _split_csv(getattr(args, "allowed_tools", None))
    forbidden = _split_csv(getattr(args, "forbidden_tools", None))
    try:
        result = run_governed(
            command=command,
            mission=getattr(args, "mission", None),
            allowed_tools=allowed,
            forbidden_tools=forbidden,
            max_tool_calls=int(getattr(args, "max_tool_calls", DEFAULT_MAX_TOOL_CALLS)),
            max_duration_s=int(getattr(args, "max_duration_s", DEFAULT_MAX_DURATION_S)),
            home=getattr(args, "home", None),
            via=getattr(args, "via", None) or "auto",
            enable_kernel_correlation=not getattr(args, "no_kernel_correlation", False),
        )
    except NotImplementedError as exc:
        print(f"ardur run: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"ardur run: {exc}", file=sys.stderr)
        return 2

    print(format_summary(result), file=sys.stderr)
    return result.exit_code


def _split_csv(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, (list, tuple)):
        items: list[str] = []
        for entry in value:
            items.extend(_split_csv(entry))
        return items
    return [part.strip() for part in str(value).split(",") if part.strip()]
