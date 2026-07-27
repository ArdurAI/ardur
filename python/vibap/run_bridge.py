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
from contextlib import suppress
from dataclasses import dataclass, field, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import kernel_correlation as kc
from .launch_gate import (
    RELEASE_BYTE as LAUNCH_GATE_RELEASE_BYTE,
    release_exec_stop,
    wait_for_exec_stop,
)
from .package_assets import claude_code_plugin_dir

if TYPE_CHECKING:
    from .passport import MissionPassport

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

# Daemon-owned, root-PID-only read exceptions needed after the kernel has
# completed exec but before a dynamic target runtime has finished starting.
# Mission data never extends this list. The BPF hook permits reads only; writes
# continue through the ordinary mission policy.
BPF_BOOTSTRAP_READ_ALLOW = (
    "/usr",
    "/lib",
    "/lib64",
    "/etc/ld.so.cache",
    "/etc/ssl/certs",
    "/dev/urandom",
)

VALID_VIA_MODES = ("auto", "env", "claude-code", "intercept")


class KernelPolicyEnforcementError(RuntimeError):
    """Raised when ``--enforce`` requires kernel-level BPF policy and it cannot
    be installed (daemon absent, cgroup uncorrelated, or the daemon rejected
    the plan). Callers must treat this as a hard abort of the run."""


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
        return (
            env,
            list(command),
            [f"governance routed via env → {ctx.proxy_url}/evaluate"],
        )


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
            new_command = [
                command[0],
                "--plugin-dir",
                str(ctx.plugin_dir),
                *command[1:],
            ]
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
    candidate = claude_code_plugin_dir()
    return candidate if candidate.is_dir() else None


class _KernelReceiptRegistrar:
    """Best-effort receipt bridge from the embedded proxy to the daemon."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._session_id: str | None = None
        self._failures = 0
        self._last_error: str | None = None

    def activate(self, session_id: str) -> None:
        with self._lock:
            self._session_id = session_id

    def register(self, receipt_id: str) -> None:
        if not receipt_id:
            return
        with self._lock:
            if self._session_id is None:
                return
            try:
                kc.KernelCaptureClient(kc.daemon_socket_path()).register_receipt(
                    session_id=self._session_id,
                    receipt_id=receipt_id,
                )
            except (kc.DaemonUnavailable, kc.DaemonProtocolError, ValueError) as exc:
                self._failures += 1
                self._last_error = type(exc).__name__

    def failure_note(self) -> str | None:
        with self._lock:
            if self._failures == 0:
                return None
            return (
                f"kernel receipt registration degraded: {self._failures} request(s) failed"
                f" ({self._last_error or 'unknown error'})"
            )


# ── embedded governance server ─────────────────────────────────────────────────


def _build_embedded_server(
    proxy: Any,
    session_id: str,
    api_token: str,
    private_key: Any,
    host: str = "127.0.0.1",
    receipt_registrar: _KernelReceiptRegistrar | None = None,
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
            supplied = header[len(prefix) :].strip().encode("utf-8")
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
                self._send(200, {"status": "ok"})
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
                    decision, reason = proxy.evaluate_tool_call(
                        sid,
                        str(tool_name),
                        dict(arguments),
                        receipt_callback=receipt_registrar.register
                        if receipt_registrar is not None
                        else None,
                    )
                    response: dict[str, Any] = {
                        "decision": decision.value,
                        "session_id": sid,
                    }
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
                    token, claims = proxy.issue_attestation_for_session(
                        sid, private_key
                    )
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
    kernel_policy: dict[str, Any]
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
        return kc.CorrelationResult(
            available=False, reason="kernel correlation disabled by caller"
        )
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
    """Fetch the daemon's signed kernel evidence rollup for a session.

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
    lifecycle_capture = response.get("lifecycle_capture")
    observability_gap = response.get("observability_gap")
    if (
        not isinstance(enforcement, dict)
        and not isinstance(lifecycle_capture, dict)
        and not isinstance(observability_gap, dict)
    ):
        return None
    claim = dict(enforcement) if isinstance(enforcement, dict) else {}
    if isinstance(lifecycle_capture, dict):
        claim["lifecycle_capture"] = lifecycle_capture
    if isinstance(observability_gap, dict):
        claim["observability_gap"] = observability_gap
    return claim


@dataclass
class SeccompShimPlan:
    """Decision of whether/how to route the agent through ``ardur-exec-shim``
    (plan E4's seccomp user-notify on-ramp), made *before* the agent is
    spawned so the wrapped launch command can be built in time.

    This exists because of issue #104: on a seccomp-only host (no ``bpf`` in
    the boot ``lsm=`` list — the majority case), ``apply_policy`` succeeding
    only proves the daemon's in-memory seccomp policy store is synced. It is
    not proof that anything actually enforces it — that requires a real
    ``ardur-exec-shim`` process to have installed a filter on the agent and
    handed its listener off to the daemon. Deciding to wrap (or why not) has
    to happen before ``subprocess.Popen`` — seccomp enforcement is
    per-process (a filter the shim installs on itself before it execs into
    the agent), unlike BPF-LSM's per-cgroup enforcement, so there is no way
    to retroactively attach it to an already-running, unwrapped process.
    """

    tier: str | None
    wrapped: bool
    shim_path: Path | None = None
    reason: str = ""


def _plan_seccomp_shim(*, enabled: bool) -> SeccompShimPlan:
    """Detect the daemon's active enforcement tier and, when it is the
    seccomp fallback, resolve ``ardur-exec-shim`` so the agent can be
    wrapped with it.

    Never raises. Mirrors ``_correlate_launch``'s graceful-degradation
    contract: any failure here (daemon absent, health call rejected, shim
    binary missing) just means ``wrapped=False`` with a reason — the caller
    (``_apply_kernel_policy``, after ``apply_policy`` actually runs) decides
    whether that is a permissive degrade or an ``--enforce`` abort.
    """
    if not enabled:
        return SeccompShimPlan(
            tier=None, wrapped=False, reason="kernel correlation disabled by caller"
        )
    socket_path = kc.daemon_socket_path()
    if not kc.daemon_available(socket_path):
        return SeccompShimPlan(
            tier=None, wrapped=False, reason="kernelcapture daemon socket not present"
        )
    try:
        response = kc.KernelCaptureClient(socket_path).health()
    except (kc.DaemonUnavailable, kc.DaemonProtocolError, ValueError) as exc:
        return SeccompShimPlan(
            tier=None, wrapped=False, reason=f"daemon health check failed: {exc}"
        )
    tier = response.get("enforcement_tier") or None
    if tier != kc.ENFORCEMENT_TIER_SECCOMP:
        return SeccompShimPlan(
            tier=tier,
            wrapped=False,
            reason=f"active enforcement tier is {tier!r}, no shim needed",
        )
    shim_path = kc.exec_shim_path()
    if shim_path is None:
        return SeccompShimPlan(
            tier=tier,
            wrapped=False,
            reason="seccomp tier is active but the ardur-exec-shim binary was not found",
        )
    return SeccompShimPlan(tier=tier, wrapped=True, shim_path=shim_path)


def _wrap_command_with_seccomp_shim(
    command: list[str], *, session_id: str, shim_path: Path, ready_file: Path
) -> list[str]:
    """Prepend an ``ardur-exec-shim`` invocation to ``command``.

    The shim installs the connect(2) filter, hands its listener off to the
    daemon, then ``execve()``s into ``command`` — replacing itself, so the
    governed process keeps the shim's PID (what cgroup adoption and
    ``register_session``'s ``root_pid`` see downstream is unaffected by this
    wrapping) and the filter carries over unchanged.

    ``--ready-file`` points the shim at a marker file this run creates right
    after its own ``register_session`` call succeeds (see
    ``run_governed``) — the shim waits for it before attempting its one-shot
    daemon handoff, closing a real race caught only by running the actual
    shim through an actual `ardur run` (issue #104's verification): the
    handoff cannot be retried once the seccomp filter is installed, so
    without this wait a slow ``register_session`` could permanently lose the
    race. A first attempt at this used a daemon round trip instead of a
    file — reverted because the daemon's session_status enforces exact-PID
    peer ownership on the session record, which the shim (a different
    process than whoever registered the session) can never satisfy.
    """
    return [
        str(shim_path),
        "--session-id",
        session_id,
        "--seccomp-socket",
        str(kc.seccomp_handoff_socket_path()),
        "--ready-file",
        str(ready_file),
        "--",
        *command,
    ]


def _wrap_command_with_launch_gate(
    command: list[str], *, ready_fd: int | None = None, trace_exec: bool = False
) -> list[str]:
    """Block the target exec until cgroup adoption and registration finish.

    The gate process is the child returned by ``Popen``. It retains that PID
    when it eventually execs ``command``, so the cgroup and daemon registration
    continue to identify the governed root process after release.
    """
    if (ready_fd is None) == (not trace_exec):
        raise ValueError("launch gate requires exactly one of ready_fd or trace_exec")
    gate_args = ["--trace-exec"] if trace_exec else ["--ready-fd", str(ready_fd)]
    return [
        sys.executable,
        "-I",
        str(Path(__file__).with_name("launch_gate.py")),
        *gate_args,
        "--",
        *command,
    ]


def _release_launch_gate(ready_fd: int) -> None:
    try:
        os.write(ready_fd, LAUNCH_GATE_RELEASE_BYTE)
    finally:
        os.close(ready_fd)


# Module-level so tests can monkeypatch a short timeout rather than either
# waiting out the real budget or threading an override through
# run_governed's public signature for a purely internal verification detail.
# 5 seconds comfortably covers ardur-exec-shim's own handoff-dial retry
# budget (3 attempts, 500ms apart) plus process-startup and scheduling
# slack; it is not tuned to any tighter bound than that.
SECCOMP_LISTENER_VERIFY_TIMEOUT_S = 5.0
SECCOMP_LISTENER_VERIFY_POLL_INTERVAL_S = 0.1


def _verify_seccomp_listener_attached(
    session_id: str,
    *,
    timeout_s: float | None = None,
    poll_interval_s: float | None = None,
) -> bool:
    """Poll the daemon until it reports ``session_id``'s seccomp listener
    attached, or the timeout elapses.

    Bounded and best-effort: returns ``False`` (never raises) on timeout or
    any daemon-communication failure.
    """
    timeout_s = SECCOMP_LISTENER_VERIFY_TIMEOUT_S if timeout_s is None else timeout_s
    poll_interval_s = (
        SECCOMP_LISTENER_VERIFY_POLL_INTERVAL_S
        if poll_interval_s is None
        else poll_interval_s
    )
    deadline = time.time() + timeout_s
    client = kc.KernelCaptureClient(kc.daemon_socket_path())
    while True:
        try:
            response = client.session_status(session_id=session_id)
        except (kc.DaemonUnavailable, kc.DaemonProtocolError, ValueError):
            return False
        if response.get("seccomp_listener_attached") is True:
            return True
        if time.time() >= deadline:
            return False
        time.sleep(poll_interval_s)


def _apply_kernel_policy(
    *,
    session_id: str,
    passport: MissionPassport,
    kernel_resource_scope: list[str],
    correlation: kc.CorrelationResult,
    enforce: bool,
    seccomp_plan: SeccompShimPlan,
    control_plane_endpoint: tuple[str, int] | None = None,
    bootstrap_read_allow: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Lower the passport's policy and push it to the daemon's BPF maps.

    Loud-abort contract: when ``enforce`` is True, any failure to install
    kernel-level enforcement — the cgroup never got correlated with the
    daemon, the daemon rejected the plan, or (issue #104) the active tier is
    seccomp and no ``ardur-exec-shim`` listener ever attached for this
    session — raises :class:`KernelPolicyEnforcementError` so the caller
    aborts the run instead of letting the agent proceed unguarded. When
    ``enforce`` is False the same failures degrade to a recorded reason in
    the returned dict; the hook/proxy path still governs the run.

    ``bpf_lower`` (and the mission compiler it builds on) is only imported
    once a live daemon correlation exists. That keeps the common degraded
    path — no kernelcapture daemon on the host, the default on most installs
    — free of the mission-compiler's optional dependencies (e.g.
    ``biscuit-python``, a ``[dev]`` extra) so a plain ``ardur run`` never pays
    for kernel-enforcement machinery it isn't using.

    ``kernel_resource_scope`` is deliberately separate from the signed
    passport claim. For an explicit ``--no-resource-scope`` run the passport
    records ``["**"]`` for honest user-space authority while kernel lowering
    receives ``[]`` so the network-only seccomp plan remains file-op-free.

    ``seccomp_plan`` is threaded in from ``run_governed`` (it was resolved
    before the agent was even spawned, so the launch command could be
    wrapped in time — see :class:`SeccompShimPlan`) rather than re-detected
    here, so the tier this function verifies against is exactly the one the
    launch decision was actually made on.
    """
    if not correlation.available:
        reason = f"kernel policy not applied: {correlation.reason}"
        if enforce:
            raise KernelPolicyEnforcementError(reason)
        return {"applied": False, "reason": reason, "tier2_ops": []}

    from .bpf_lower import OpPolicyEntry, lower_to_bpf_policy_plan
    from .bpf_types import (
        ACT_DENY,
        ENFORCE_MODE_ENFORCE,
        ENFORCE_MODE_PERMISSIVE,
        OP_NET_CONNECT,
    )

    plan = lower_to_bpf_policy_plan(
        allowed_side_effect_classes=passport.allowed_side_effect_classes,
        forbidden_tools=passport.forbidden_tools,
        allowed_tools=passport.allowed_tools,
        resource_scope=kernel_resource_scope,
        enforce_mode=ENFORCE_MODE_ENFORCE if enforce else ENFORCE_MODE_PERMISSIVE,
    )
    tier2_ops = list(plan.tier2_ops)

    # The exact bridge endpoint is a trusted side channel, not mission network
    # authority. Keep OP_NET_CONNECT explicit on the wire (the daemon rejects
    # endpoint exceptions without it), while the dedicated root-PID/port BPF
    # map makes only this tuple reachable. Every unrelated connect remains
    # denied in strict mode.
    if control_plane_endpoint is not None and not any(
        entry.op == OP_NET_CONNECT for entry in plan.op_policies
    ):
        plan = replace(
            plan,
            op_policies=plan.op_policies
            + (OpPolicyEntry(OP_NET_CONNECT, ACT_DENY, plan.enforce_mode),),
        )

    if not plan.op_policies and not plan.path_allow and not plan.net_allow:
        return {
            "applied": False,
            "reason": "mission has no kernel-enforceable policy dimensions",
            "tier2_ops": tier2_ops,
        }

    generation = 1  # first (and only) apply for this fresh session/cgroup pair.
    if (
        seccomp_plan.tier == kc.ENFORCEMENT_TIER_SECCOMP
        and control_plane_endpoint is None
    ):
        reason = "seccomp tier requires an exact governance control-plane endpoint"
        if enforce:
            raise KernelPolicyEnforcementError(reason)
        return {"applied": False, "reason": reason, "tier2_ops": tier2_ops}
    try:
        kc.KernelCaptureClient(kc.daemon_socket_path()).apply_policy(
            session_id=session_id,
            plan=plan,
            generation=generation,
            control_plane_endpoint=control_plane_endpoint,
            bootstrap_read_allow=bootstrap_read_allow,
        )
    except (kc.DaemonUnavailable, kc.DaemonProtocolError, ValueError) as exc:
        reason = f"kernel policy apply rejected: {exc}"
        if enforce:
            raise KernelPolicyEnforcementError(reason) from exc
        return {"applied": False, "reason": reason, "tier2_ops": tier2_ops}

    # Issue #104: apply_policy succeeding only proves the daemon's in-memory
    # policy store is synced — on a seccomp-tier host that says nothing about
    # whether anything actually enforces it. That requires a live
    # ardur-exec-shim listener attached to *this* session, which is a
    # separate, asynchronous handoff this function has no other visibility
    # into. Without this check, a host where the shim silently failed to
    # hand off (or was never invoked) would report "applied" while nothing
    # wraps the agent — exactly the false-success this closes. BPF-LSM needs
    # no equivalent check: correlation.available already proved cgroup
    # adoption succeeded before this function was ever called, and cgroup
    # membership *is* that tier's enforcement mechanism, not a separate
    # asynchronous step.
    if seccomp_plan.tier == kc.ENFORCEMENT_TIER_SECCOMP:
        if not seccomp_plan.wrapped:
            reason = f"seccomp tier active but not wired: {seccomp_plan.reason}"
            if enforce:
                raise KernelPolicyEnforcementError(reason)
            return {"applied": False, "reason": reason, "tier2_ops": tier2_ops}
        if not _verify_seccomp_listener_attached(session_id):
            reason = "seccomp listener never attached (ardur-exec-shim handoff did not complete)"
            if enforce:
                raise KernelPolicyEnforcementError(reason)
            return {"applied": False, "reason": reason, "tier2_ops": tier2_ops}

    return {
        "applied": True,
        "reason": "kernel BPF policy installed",
        "generation": generation,
        "tier2_ops": tier2_ops,
    }


# ── main entry ─────────────────────────────────────────────────────────────────


def _resolve_run_resource_scope(
    work_dir: Path,
    *,
    resource_scope: list[str] | None,
    disabled: bool,
) -> list[str]:
    """Return exact + subtree patterns for validated roots inside ``work_dir``."""
    if disabled and resource_scope is not None:
        raise ValueError("resource_scope cannot be combined with no_resource_scope")
    if disabled:
        return []

    raw_roots = [str(work_dir)] if resource_scope is None else resource_scope
    if not raw_roots:
        raise ValueError("resource_scope must contain at least one path root")

    roots: list[Path] = []
    for raw_root in raw_roots:
        if not isinstance(raw_root, str) or not raw_root.strip():
            raise ValueError("resource_scope entries must be non-empty path roots")
        if any(char in raw_root for char in "*?[]"):
            raise ValueError(
                "resource_scope entries must be path roots, not glob patterns"
            )
        candidate = Path(raw_root).expanduser()
        if not candidate.is_absolute():
            candidate = work_dir / candidate
        try:
            root = candidate.resolve()
        except (OSError, ValueError) as exc:
            raise ValueError(f"invalid resource_scope path root: {exc}") from exc
        if root != work_dir and not root.is_relative_to(work_dir):
            raise ValueError(
                "resource_scope path roots must stay inside the governed cwd"
            )
        if root not in roots:
            roots.append(root)

    patterns: list[str] = []
    for root in roots:
        root_text = str(root)
        patterns.extend((root_text, "/*" if root_text == "/" else f"{root_text}/*"))
    return patterns


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
    enforce: bool = False,
    resource_scope: list[str] | None = None,
    no_resource_scope: bool = False,
    cwd: Path | None = None,
    stdout: Any | None = None,
    stderr: Any | None = None,
) -> GovernanceRunResult:
    """Launch ``command`` under a fresh, fully-governed Ardur session.

    Returns a :class:`GovernanceRunResult` once the agent exits. Raises
    ``ValueError`` for invalid input (empty command, bad ``via``),
    ``NotImplementedError`` for the scaffolded intercept path, and
    :class:`KernelPolicyEnforcementError` when ``enforce=True`` and
    kernel-level BPF policy enforcement could not be installed — the launched
    agent is killed before the error propagates.

    ``resource_scope`` narrows the default cwd-based file scope to one or more
    path roots inside ``cwd``. Relative roots resolve against ``cwd``; each is
    represented as exact + recursive patterns for proxy enforcement and as an
    absolute path prefix for BPF lowering. It cannot be combined with
    ``no_resource_scope``.

    ``no_resource_scope`` explicitly grants unrestricted resources to the
    user-space proxy while skipping the default cwd-based file resource_scope
    (``path_allow``/``OP_FILE_READ``+``OP_FILE_WRITE``), which every mission
    otherwise gets unconditionally. It exists because the seccomp fallback
    tier (plan E4) can only ever enforce ``OP_NET_CONNECT`` — a mission that
    also carries a file-scope dimension can never be "fully seccomp-coverable"
    (see ``seccompFullyCoversPolicy`` in the daemon), so on a seccomp-only
    host it always degrades/aborts under ``--enforce`` regardless of how
    tightly the network side is scoped. Set this for a mission that is
    genuinely network-only and needs the seccomp tier's real enforcement
    rather than always taking that path. Leaving it False (the default)
    preserves every existing caller's behavior unchanged.
    """
    from .passport import (
        MissionPassport,
        UNRESTRICTED_RESOURCE_SCOPE_PATTERN,
        generate_keypair,
        issue_passport,
    )

    if not command:
        raise ValueError("ardur run requires a command to govern")
    if via not in VALID_VIA_MODES:
        raise ValueError(
            f"unknown --via mode: {via!r} (choose from {', '.join(VALID_VIA_MODES)})"
        )

    work_dir = Path(cwd).expanduser().resolve() if cwd else Path.cwd()
    scope_patterns = _resolve_run_resource_scope(
        work_dir,
        resource_scope=resource_scope,
        disabled=no_resource_scope,
    )

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
        resource_scope=(
            [UNRESTRICTED_RESOURCE_SCOPE_PATTERN]
            if no_resource_scope
            else scope_patterns
        ),
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
        receipts_log_path=home / "receipts.jsonl",
        state_dir=state_dir,
        keys_dir=keys_dir,
    )
    session = proxy.start_session(token)
    session_id = session.jti
    mission_id = str(session.passport_claims.get("mission_id") or "")
    trace_id = session_id

    api_token = _generate_api_token()
    receipt_registrar = _KernelReceiptRegistrar()
    server = _build_embedded_server(
        proxy,
        session_id,
        api_token,
        proxy.receipt_private_key,
        receipt_registrar=receipt_registrar,
    )
    proxy_host = str(server.server_address[0])
    port = server.server_address[1]
    proxy_url = f"http://{proxy_host}:{port}"
    server_thread = threading.Thread(
        target=server.serve_forever, name="ardur-run-proxy", daemon=True
    )
    server_thread.start()

    cgroup_handle: kc.CgroupHandle | None = None
    daemon_registered = False
    proc: subprocess.Popen[bytes] | None = None
    notes: list[str] = []
    if no_resource_scope:
        notes.append(
            "explicitly unrestricted resource scope: the signed passport permits "
            "all resources via the sole '**' pattern"
        )
    # Pre-initialized so the finally block has a safe value even if an
    # exception is raised before kernel correlation is attempted below.
    correlation = kc.CorrelationResult(
        available=False, reason="run did not reach kernel correlation"
    )
    seccomp_ready_file: Path | None = None
    launch_gate_read_fd: int | None = None
    launch_gate_write_fd: int | None = None
    bpf_exec_stopped = False
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

        # 3b. Detect the daemon's active enforcement tier and, if it's the
        # seccomp fallback (issue #104), route the agent through
        # ardur-exec-shim so a filter actually wraps it. Must happen before
        # Popen below — see SeccompShimPlan's docstring for why this can't
        # be done after the fact.
        seccomp_plan = _plan_seccomp_shim(enabled=enable_kernel_correlation)
        seccomp_ready_file = home / f"seccomp-ready-{session_id}"
        if seccomp_plan.wrapped and seccomp_plan.shim_path is not None:
            run_command = _wrap_command_with_seccomp_shim(
                run_command,
                session_id=session_id,
                shim_path=seccomp_plan.shim_path,
                ready_file=seccomp_ready_file,
            )
            notes.append(
                f"seccomp enforcement tier active — agent launched via ardur-exec-shim ({seccomp_plan.shim_path})"
            )
        elif seccomp_plan.tier == kc.ENFORCEMENT_TIER_SECCOMP:
            # Recorded now so it's visible even if the run never reaches
            # _apply_kernel_policy's own (mission-content-gated) check of
            # this same plan — e.g. a mission with no kernel-enforceable
            # policy dimensions at all.
            notes.append(f"seccomp tier active but not wired: {seccomp_plan.reason}")

        # 4. Dedicated cgroup (Linux + cgroup v2 + writable), best effort.
        if enable_kernel_correlation:
            cgroup_handle = kc.create_run_cgroup(session_id)

        # A child PID does not exist until Popen returns, but an ordinary target
        # can exec before that PID is adopted into the cgroup and registered
        # with the daemon. Launch a tiny inherited-FD gate as the child whenever
        # a cgroup exists; exec preserves its PID after the parent releases it.
        popen_extra: dict[str, Any] = {}
        bpf_trace_handoff = (
            enforce
            and cgroup_handle is not None
            and seccomp_plan.tier == kc.ENFORCEMENT_TIER_BPF_LSM
        )
        if bpf_trace_handoff:
            run_command = _wrap_command_with_launch_gate(run_command, trace_exec=True)
        elif cgroup_handle is not None:
            launch_gate_read_fd, launch_gate_write_fd = os.pipe()
            run_command = _wrap_command_with_launch_gate(
                run_command, ready_fd=launch_gate_read_fd
            )
            popen_extra["pass_fds"] = (launch_gate_read_fd,)

        # 5. Launch the agent.
        try:
            proc = subprocess.Popen(
                run_command,
                env=run_env,
                cwd=str(work_dir),
                stdout=stdout,
                stderr=stderr,
                **popen_extra,
            )
        finally:
            if launch_gate_read_fd is not None:
                with suppress(OSError):
                    os.close(launch_gate_read_fd)
                launch_gate_read_fd = None

        if bpf_trace_handoff:
            try:
                wait_for_exec_stop(proc.pid)
                bpf_exec_stopped = True
            except (OSError, RuntimeError, TimeoutError) as exc:
                with suppress(OSError):
                    proc.kill()
                with suppress(Exception):
                    proc.wait(timeout=5)
                raise KernelPolicyEnforcementError(
                    f"BPF exec handoff failed closed: {exc}"
                ) from exc

        if cgroup_handle is not None:
            try:
                cgroup_handle.adopt_pid(proc.pid)
            except OSError as exc:
                cgroup_handle.cleanup()
                cgroup_handle = None
                if bpf_exec_stopped:
                    proc.kill()
                    proc.wait()
                    bpf_exec_stopped = False
                    raise KernelPolicyEnforcementError(
                        f"BPF cgroup adoption failed closed: {exc}"
                    ) from exc

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
        if daemon_registered:
            receipt_registrar.activate(session_id)

        # 5a. Signal ardur-exec-shim (if this run wrapped the agent with it)
        # that register_session has landed — see _wrap_command_with_seccomp_shim's
        # docstring for why this is a marker file rather than a daemon call
        # or a signal. Only meaningful when the wrap actually happened;
        # touching it otherwise would be inert but pointless.
        if seccomp_plan.wrapped and correlation.available:
            with suppress(OSError):
                seccomp_ready_file.touch()

        # The seccomp shim must run before _apply_kernel_policy can verify its
        # listener handoff. Other tiers stay gated through policy application,
        # eliminating both the registration race and a target-vs-policy race.
        if seccomp_plan.wrapped and launch_gate_write_fd is not None:
            _release_launch_gate(launch_gate_write_fd)
            launch_gate_write_fd = None

        # 5b. Push the mission's lowered BPF policy to the daemon now that the
        # cgroup is registered. Under --enforce a failure here kills the agent
        # and aborts the run; under permissive it degrades to a recorded note.
        try:
            kernel_policy = _apply_kernel_policy(
                session_id=session_id,
                passport=passport,
                kernel_resource_scope=scope_patterns,
                correlation=correlation,
                enforce=enforce,
                seccomp_plan=seccomp_plan,
                control_plane_endpoint=(proxy_host, port)
                if seccomp_plan.tier
                in {kc.ENFORCEMENT_TIER_BPF_LSM, kc.ENFORCEMENT_TIER_SECCOMP}
                else None,
                bootstrap_read_allow=BPF_BOOTSTRAP_READ_ALLOW
                if bpf_trace_handoff
                else (),
            )
        except KernelPolicyEnforcementError as exc:
            notes.append(f"ENFORCE abort: {exc}")
            proc.kill()
            proc.wait()
            raise
        if not kernel_policy["applied"]:
            notes.append(kernel_policy["reason"])

        if launch_gate_write_fd is not None:
            _release_launch_gate(launch_gate_write_fd)
            launch_gate_write_fd = None
        if bpf_exec_stopped:
            try:
                release_exec_stop(proc.pid)
            except OSError as exc:
                proc.kill()
                proc.wait()
                bpf_exec_stopped = False
                raise KernelPolicyEnforcementError(
                    f"BPF exec release failed closed: {exc}"
                ) from exc
            bpf_exec_stopped = False

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
            notes.append(
                f"agent exceeded max-duration {max_duration_s}s and was terminated"
            )
    finally:
        if bpf_exec_stopped and proc is not None:
            with suppress(OSError):
                proc.kill()
            with suppress(Exception):
                proc.wait(timeout=5)
        # 7. Finalize the governance session: attestation + receipt chain.
        # Kernel enforcement must be fetched before the kernel daemon's
        # end_session call below, which retires the session's summary.
        kernel_enforcement = _kernel_enforcement_claim(session_id, correlation)
        if registration_note := receipt_registrar.failure_note():
            notes.append(registration_note)
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
                notes.append(
                    "kernel daemon end_session unavailable during local cleanup"
                )
        if cgroup_handle is not None:
            cgroup_handle.cleanup()
        if seccomp_ready_file is not None:
            with suppress(OSError):
                seccomp_ready_file.unlink()
        for fd in (launch_gate_read_fd, launch_gate_write_fd):
            if fd is not None:
                with suppress(OSError):
                    os.close(fd)
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
        kernel_policy=dict(kernel_policy),
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
    raise RuntimeError(
        f"embedded governance proxy did not become healthy: {last_error}"
    )


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
        f"  kernel policy {result.kernel_policy.get('reason')}",
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


def _print_next_steps(steps: list[dict[str, str]]) -> None:
    """Render deterministic remediation hints to stderr.

    Mirrors the proven-safe ``_print_report_next_steps`` pattern in
    ``python/vibap/cli.py``: extract ``command``/``detail`` into local
    variables per step, then print each. ``command``/``detail`` are static
    developer-guidance strings baked into the ``run_governed_*_next_steps``
    helpers; they never contain user input, credentials, secrets, tokens,
    or key material.
    """
    print("Next steps:", file=sys.stderr)
    for index, step in enumerate(steps, start=1):
        command = step.get("command", "")
        detail = step.get("detail", "")
        print(f"{index}. {command}", file=sys.stderr)
        if detail:
            print(f"   {detail}", file=sys.stderr)


def _print_run_governed_missing_command_next_steps() -> None:
    _print_next_steps(run_governed_missing_command_next_steps())


def run_governed_mission_invalid_next_steps() -> list[dict[str, str]]:
    """Return deterministic stderr remediation hints for an invalid ``--mission`` value."""
    return [
        {
            "condition": "run_mission_invalid",
            "action": "supply_non_empty_mission",
            "command": "ardur run --mission <mission> --allowed-tools <tools> -- <command>",
            "detail": (
                "Pass a non-empty mission description after --mission. The mission "
                "text is embedded in the signed Mission Passport; empty or whitespace-only "
                "values are rejected before any keys or passports are created."
            ),
        },
        {
            "condition": "run_mission_invalid",
            "action": "omit_mission_for_default",
            "command": "ardur run -- <command>",
            "detail": (
                "Omit --mission to use the built-in default mission text for the "
                "governed run."
            ),
        },
    ]


def _print_run_governed_mission_invalid_next_steps() -> None:
    _print_next_steps(run_governed_mission_invalid_next_steps())


def run_governed_home_not_directory_next_steps() -> list[dict[str, str]]:
    """Return deterministic stderr remediation hints for a ``--home`` value
    that is an existing non-directory (file, socket, symlink-to-file, etc.)."""
    return [
        {
            "condition": "run_home_not_directory",
            "action": "pass_a_directory_or_nonexistent_path",
            "command": "ardur run --home <ardur-home> --mission <mission> -- <command>",
            "detail": (
                "Pass a path that is either nonexistent (it will be created) or "
                "an existing directory. The path you provided is an existing "
                "non-directory (for example a regular file or socket)."
            ),
        },
        {
            "condition": "run_home_not_directory",
            "action": "omit_home_for_ephemeral",
            "command": "ardur run -- <command>",
            "detail": (
                "Omit --home to use an ephemeral Ardur home that is created "
                "and cleaned up automatically."
            ),
        },
    ]


def _print_run_governed_home_not_directory_next_steps() -> None:
    _print_next_steps(run_governed_home_not_directory_next_steps())


def run_governed_home_dangling_symlink_next_steps() -> list[dict[str, str]]:
    """Return deterministic stderr remediation hints for a ``--home`` value
    that is a dangling symlink (symlink whose target does not exist).

    ``Path.exists()`` follows a symlink and returns False when the target is
    missing, which previously defeated the ``exists() and not is_dir()``
    guard on the resolved path.  The fix checks ``is_symlink() and not
    exists()`` on the UN-resolved path before ``.resolve()`` follows the
    link, rejecting dangling ``--home`` before any key generation or
    artifact write.
    """
    return [
        {
            "condition": "run_home_dangling_symlink",
            "action": "pass_an_existing_or_nonexistent_path",
            "command": "ardur run --home <ardur-home> --mission <mission> -- <command>",
            "detail": (
                "Pass a path that is either an existing directory or a "
                "nonexistent path (it will be created). The path you "
                "provided is a dangling symlink: it points at a target that "
                "does not exist, so it looks like it resolves somewhere "
                "but does not."
            ),
        },
        {
            "condition": "run_home_dangling_symlink",
            "action": "omit_home_for_ephemeral",
            "command": "ardur run -- <command>",
            "detail": (
                "Omit --home to use an ephemeral Ardur home that is created "
                "and cleaned up automatically."
            ),
        },
    ]


def _print_run_governed_home_dangling_symlink_next_steps() -> None:
    _print_next_steps(run_governed_home_dangling_symlink_next_steps())


def run_governed_command_not_found_next_steps(cmd_repr: str) -> list[dict[str, str]]:
    """Return deterministic stderr remediation hints when the governed command
    could not be found (``FileNotFoundError`` from ``subprocess.Popen``).

    ``cmd_repr`` is the executable name/path that Popen tried to launch; it is
    a local filesystem reference supplied by the operator, never a credential,
    token, or secret.
    """
    safe = cmd_repr if cmd_repr and all(c not in cmd_repr for c in ("\n", "\r")) else "<command>"
    return [
        {
            "condition": "run_command_not_found",
            "action": "verify_command_name_and_path",
            "command": f"ardur run --mission <mission> -- {safe} <args...>",
            "detail": (
                "The command could not be found. Check the spelling, confirm it is "
                "installed, and verify it is on your PATH (for a bare name) or that "
                "the full path exists (for an absolute path)."
            ),
        },
        {
            "condition": "run_command_not_found",
            "action": "use_env_via_for_cooperating_agents",
            "command": "ardur run --via env --mission <mission> -- <command>",
            "detail": (
                "If the agent is not Claude Code, --via env routes governance through "
                "environment variables to the embedded proxy without depending on a "
                "host-specific hook."
            ),
        },
    ]


def run_governed_command_not_executable_next_steps(cmd_repr: str) -> list[dict[str, str]]:
    """Return deterministic stderr remediation hints when the governed command
    exists but is not executable (``PermissionError`` from ``subprocess.Popen``).

    ``cmd_repr`` is the executable name/path that Popen tried to launch; it is
    a local filesystem reference supplied by the operator, never a credential,
    token, or secret.
    """
    safe = cmd_repr if cmd_repr and all(c not in cmd_repr for c in ("\n", "\r")) else "<command>"
    return [
        {
            "condition": "run_command_not_executable",
            "action": "set_executable_bit",
            "command": f"chmod +x {safe}",
            "detail": (
                "The file exists but does not have the executable bit set. Add the "
                "executable permission (e.g. chmod +x) and retry."
            ),
        },
        {
            "condition": "run_command_not_executable",
            "action": "invoke_via_interpreter",
            "command": f"ardur run --mission <mission> -- python {safe} <args...>",
            "detail": (
                "If the file is a script, invoke it through its interpreter "
                "(e.g. python, bash) so the interpreter is the governed process."
            ),
        },
    ]


def _run_governed_budget_failure(
    condition: str, message: str, detail: str, next_steps: list[dict[str, str]]
) -> int:
    """Emit a structured JSON failure response and return exit code 2.

    Uses ``json.dump`` directly to avoid a circular import of ``cli._print_json``.
    """
    response: dict[str, object] = {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": message,
        "detail": detail,
        "next_steps": next_steps,
    }
    json.dump(response, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 2


def _run_max_duration_invalid_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "action": "provide_positive_max_duration_s",
            "command": "ardur run --mission <mission> --max-duration-s <positive-seconds> -- <command>",
            "detail": (
                "--max-duration-s must be a positive integer number of seconds."
            ),
        },
    ]


def _run_max_tool_calls_invalid_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "action": "provide_valid_max_tool_calls",
            "command": "ardur run --mission <mission> --max-tool-calls <zero-or-positive-count> -- <command>",
            "detail": ("--max-tool-calls must be zero or a positive integer."),
        },
    ]


def run_governed_cli(args: Any) -> int:
    """Argparse entry point used by ``cmd_run`` when governance flags are present."""
    command = list(getattr(args, "command", None) or [])
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("ardur run requires a command to govern after --", file=sys.stderr)
        print(
            'usage: ardur run --mission "..." --allowed-tools Read,Glob -- <agent-cmd...>',
            file=sys.stderr,
        )
        _print_run_governed_missing_command_next_steps()
        return 2

    mission_arg = getattr(args, "mission", None)
    if isinstance(mission_arg, str) and not mission_arg.strip():
        print("ardur run --mission must be a non-empty string.", file=sys.stderr)
        print(
            'usage: ardur run --mission "..." --allowed-tools Read,Glob -- <agent-cmd...>',
            file=sys.stderr,
        )
        _print_run_governed_mission_invalid_next_steps()
        return 2

    # Validate --home before budget checks so a broken or non-directory path
    # is rejected without creating key material or issuing a passport.
    #
    # The dangling-symlink check MUST run against the UN-resolved path and
    # BEFORE ``.resolve()``: ``Path.exists()`` follows the symlink and returns
    # False for a missing target, which previously defeated the
    # ``exists() and not is_dir()`` guard on the resolved path and let
    # ``resolve_keys_dir`` silently mkdir the broken target.  See
    # ``run_governed_home_dangling_symlink_next_steps`` for the recovery
    # contract.  Only dangling symlinks are rejected here: a plain
    # nonexistent non-symlink path is legitimate (Ardur creates it later),
    # and a symlink-to-existing-directory proceeds normally.
    home_arg = getattr(args, "home", None)
    if home_arg is not None:
        try:
            expanded_home = Path(home_arg).expanduser()
        except (OSError, ValueError) as exc:
            print(f"ardur run: {exc}", file=sys.stderr)
            return 2
        if expanded_home.is_symlink() and not expanded_home.exists():
            print(
                "ardur run --home must not point to a dangling symlink.",
                file=sys.stderr,
            )
            print(
                'usage: ardur run --home <ardur-home> --mission "..." -- <agent-cmd...>',
                file=sys.stderr,
            )
            _print_run_governed_home_dangling_symlink_next_steps()
            return 2
        try:
            resolved_home = expanded_home.resolve()
        except (OSError, ValueError) as exc:
            print(f"ardur run: {exc}", file=sys.stderr)
            return 2
        if resolved_home.exists() and not resolved_home.is_dir():
            print("ardur run --home must point to a directory path.", file=sys.stderr)
            print(
                'usage: ardur run --home <ardur-home> --mission "..." -- <agent-cmd...>',
                file=sys.stderr,
            )
            _print_run_governed_home_not_directory_next_steps()
            return 2

    allowed = _split_csv(getattr(args, "allowed_tools", None))
    forbidden = _split_csv(getattr(args, "forbidden_tools", None))
    # The `run` subparser defaults --max-tool-calls to None (so an explicit 0 is
    # distinguishable from "unset"), which means the attribute exists as None and
    # getattr's fallback never fires. Coerce None to the default here rather than
    # letting int(None) raise TypeError — otherwise a plain `ardur run` with no
    # --max-tool-calls crashes before the run even starts. Same guard for
    # --max-duration-s for symmetry.
    max_tool_calls_arg = getattr(args, "max_tool_calls", None)
    max_duration_s_arg = getattr(args, "max_duration_s", None)

    # Validate budget arguments BEFORE calling run_governed so invalid values
    # are rejected without creating key material or issuing a passport.
    if max_duration_s_arg is not None:
        try:
            parsed = int(max_duration_s_arg)
        except (TypeError, ValueError):
            return _run_governed_budget_failure(
                "run_max_duration_invalid",
                "Run governance max-duration-s is invalid.",
                "--max-duration-s must be a positive integer number of seconds.",
                _run_max_duration_invalid_next_steps("run_max_duration_invalid"),
            )
        if parsed <= 0:
            return _run_governed_budget_failure(
                "run_max_duration_invalid",
                "Run governance max-duration-s is invalid.",
                "--max-duration-s must be a positive integer number of seconds.",
                _run_max_duration_invalid_next_steps("run_max_duration_invalid"),
            )

    if max_tool_calls_arg is not None:
        try:
            parsed = int(max_tool_calls_arg)
        except (TypeError, ValueError):
            return _run_governed_budget_failure(
                "run_max_tool_calls_invalid",
                "Run governance max-tool-calls is invalid.",
                "--max-tool-calls must be zero or a positive integer.",
                _run_max_tool_calls_invalid_next_steps("run_max_tool_calls_invalid"),
            )
        if parsed < 0:
            return _run_governed_budget_failure(
                "run_max_tool_calls_invalid",
                "Run governance max-tool-calls is invalid.",
                "--max-tool-calls must be zero or a positive integer.",
                _run_max_tool_calls_invalid_next_steps("run_max_tool_calls_invalid"),
            )

    try:
        result = run_governed(
            command=command,
            mission=getattr(args, "mission", None),
            allowed_tools=allowed,
            forbidden_tools=forbidden,
            max_tool_calls=DEFAULT_MAX_TOOL_CALLS
            if max_tool_calls_arg is None
            else int(max_tool_calls_arg),
            max_duration_s=DEFAULT_MAX_DURATION_S
            if max_duration_s_arg is None
            else int(max_duration_s_arg),
            home=getattr(args, "home", None),
            via=getattr(args, "via", None) or "auto",
            enable_kernel_correlation=not getattr(args, "no_kernel_correlation", False),
            enforce=bool(getattr(args, "enforce", False)),
            resource_scope=getattr(args, "resource_scope", None),
            no_resource_scope=bool(getattr(args, "no_resource_scope", False)),
        )
    except NotImplementedError as exc:
        print(f"ardur run: {exc}", file=sys.stderr)
        return 2
    except KernelPolicyEnforcementError as exc:
        print(
            f"ardur run: --enforce requires kernel-level policy enforcement: {exc}",
            file=sys.stderr,
        )
        return 3
    except ValueError as exc:
        print(f"ardur run: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        # subprocess.Popen raises FileNotFoundError (Errno 2) when the
        # governed executable does not exist on PATH or at the given path.
        # Surface a clean, actionable error instead of a raw traceback.
        cmd_repr = exc.filename or (command[0] if command else "<command>")
        print(
            f"ardur run: governed command not found: {cmd_repr}", file=sys.stderr
        )
        _print_next_steps(
            run_governed_command_not_found_next_steps(cmd_repr)
        )
        return 2
    except PermissionError as exc:
        # subprocess.Popen raises PermissionError (Errno 13) when the target
        # path exists but is not executable. Surface a clean, actionable error.
        cmd_repr = exc.filename or (command[0] if command else "<command>")
        print(
            f"ardur run: governed command not executable: {cmd_repr}",
            file=sys.stderr,
        )
        _print_next_steps(
            run_governed_command_not_executable_next_steps(cmd_repr)
        )
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
