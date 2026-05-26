"""Console entry point for the pip-installable VIBAP proxy package."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Sequence

from . import __version__
from .ardur_profile import PROFILE_TEMPLATES, ArdurProfile, load_ardur_profile, write_profile_template
from .ardur_personal_native_host import (
    build_native_host_manifest,
    handle_native_host_message,
    run_native_host,
)
from .passport import DEFAULT_HOME, MissionPassport, generate_keypair, issue_passport, load_mission_file, verify_passport
from .personal_hub import (
    DEFAULT_HUB_HOST,
    DEFAULT_HUB_PORT,
    DEFAULT_HUB_URL,
    desktop_observe,
    doctor_personal,
    hub_request,
    run_under_hub,
    serve_hub,
    setup_personal,
    uninstall_personal,
)
from .claude_code_report import build_claude_code_report
from .claude_code_hook import main as claude_code_hook_main
from .gemini_cli_hook import (
    build_local_fixture as build_gemini_local_fixture,
    build_shareable_context as build_gemini_shareable_context,
    build_shareable_report as build_gemini_shareable_report,
    main as gemini_cli_hook_main,
)
from .codex_app_server_fixture import (
    build_local_fixture as build_codex_local_fixture,
    build_shareable_context as build_codex_shareable_context,
    build_shareable_report as build_codex_shareable_report,
    handle_host_event as handle_codex_host_event,
)
from .posture_index import build_posture_index, format_posture_report
from .claude_code_daemon import install_native_pre_tool_use_command, resolve_native_pre_tool_use_command_path
from .proxy import GovernanceProxy, serve_proxy


def _print_json(payload: dict) -> None:
    print(json.dumps(payload, indent=2))


def cmd_start(args: argparse.Namespace) -> int:
    private_key, public_key = generate_keypair(keys_dir=args.keys_dir)
    proxy = GovernanceProxy(
        log_path=args.log_path,
        state_dir=args.state_dir,
        keys_dir=args.keys_dir,
        public_key=public_key,
    )

    initial_session_id = None
    if args.mission:
        mission, ttl_s, _ = load_mission_file(args.mission)
        token = issue_passport(mission, private_key, ttl_s=ttl_s)
        session = proxy.start_session(token)
        initial_session_id = session.jti
        _print_json(
            {
                "status": "session_started",
                "mission_file": str(Path(args.mission).expanduser()),
                "session_id": session.jti,
                "agent_id": mission.agent_id,
                "mission": mission.mission,
                "token": token,
            }
        )

    serve_proxy(
        proxy=proxy,
        private_key=private_key,
        host=args.host,
        port=args.port,
        initial_session_id=initial_session_id,
        require_auth=args.require_auth,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
        no_tls=args.no_tls,
    )
    return 0


def cmd_issue(args: argparse.Namespace) -> int:
    private_key, public_key = generate_keypair(keys_dir=args.keys_dir)
    mission = MissionPassport(
        agent_id=args.agent_id,
        mission=args.mission,
        allowed_tools=list(args.allowed_tools or []),
        forbidden_tools=list(args.forbidden_tools or []),
        resource_scope=list(args.resource_scope or []),
        max_tool_calls=args.max_tool_calls,
        max_duration_s=args.max_duration_s,
        delegation_allowed=args.delegation_allowed,
        max_delegation_depth=args.max_delegation_depth,
    )
    token = issue_passport(mission, private_key, ttl_s=args.ttl_s)
    claims = verify_passport(token, public_key)
    _print_json({"token": token, "claims": claims})
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    _, public_key = generate_keypair(keys_dir=args.keys_dir)
    claims = verify_passport(args.token, public_key)
    _print_json({"valid": True, "claims": claims})
    return 0


def cmd_attest(args: argparse.Namespace) -> int:
    private_key, public_key = generate_keypair(keys_dir=args.keys_dir)
    proxy = GovernanceProxy(
        log_path=args.log_path,
        state_dir=args.state_dir,
        keys_dir=args.keys_dir,
        public_key=public_key,
    )
    token, claims = proxy.issue_attestation_for_session(args.session, private_key)
    _print_json({"token": token, "claims": claims})
    return 0


def cmd_claude_code_hook(args: argparse.Namespace) -> int:
    argv = [args.phase]
    if args.keys_dir:
        argv.extend(["--keys-dir", str(args.keys_dir)])
    return claude_code_hook_main(argv)


def cmd_claude_code_report(args: argparse.Namespace) -> int:
    report = build_claude_code_report(
        home=args.home,
        chain_dir=args.chain_dir,
        keys_dir=args.keys_dir,
        verify_expiry=args.verify_expiry,
    )
    if args.json:
        _print_json(report)
        return 0

    print(f"Ardur Claude Code receipt report: {report['receipt_count']} receipts across {report['chain_count']} chains")
    print(f"Home: {report['home']}")
    print(f"Chains: {report['chain_dir']}")
    print(f"Tools: {report['totals']['tools']}")
    print(f"Verdicts: {report['totals']['verdicts']}")
    print(f"Side effects: {report['totals']['side_effect_classes']}")
    print(
        "Subagent dispatches: "
        f"{report['totals']['dispatch_launch_count']} launches, "
        f"{report['totals']['dispatch_observation_count']} post observations"
    )
    print(
        "Subagent lifecycle: "
        f"{report['totals']['subagents_started']} started, "
        f"{report['totals']['subagents_stopped']} stopped"
    )
    print(f"Per-child attribution: {report['coverage']['per_child_attribution']}")
    print(f"Attribution: {report['coverage']['attribution']}")
    return 0


def cmd_gemini_cli_hook(args: argparse.Namespace) -> int:
    phase = args.phase or args.phase_pos or "pre"
    argv = ["--phase", phase]
    if args.keys_dir:
        argv.extend(["--keys-dir", str(args.keys_dir)])
    return gemini_cli_hook_main(argv)


def cmd_gemini_cli_fixture(args: argparse.Namespace) -> int:
    fixture = build_gemini_local_fixture(
        home=args.home,
        project_dir=args.project_dir,
        chain_dir=args.chain_dir,
        keys_dir=args.keys_dir,
    )
    _print_json(build_gemini_shareable_context(fixture))
    return 0


def cmd_gemini_cli_report(args: argparse.Namespace) -> int:
    report = build_gemini_shareable_report(
        home=args.home,
        chain_dir=args.chain_dir,
        keys_dir=args.keys_dir,
        verify_expiry=args.verify_expiry,
    )
    if args.json:
        _print_json(report)
        return 0
    print(f"Ardur Gemini CLI receipt report: {report['receipt_count']} receipts across {report['chain_count']} chains")
    print(f"Chains: {report['chain_dir']}")
    print(f"Verdicts: {report['policy_verdict_counts']}")
    print(f"Coverage gaps: {report['coverage_gaps']}")
    return 0


def cmd_codex_app_server_event(args: argparse.Namespace) -> int:
    raw = sys.stdin.read()
    payload = json.loads(raw) if raw.strip() else {}
    if not isinstance(payload, dict):
        raise ValueError("Codex app-server host-event payload must be a JSON object")
    output = handle_codex_host_event(payload, keys_dir=args.keys_dir)
    _print_json(output)
    return 2 if output.get("block") else 0


def cmd_codex_app_server_fixture(args: argparse.Namespace) -> int:
    fixture = build_codex_local_fixture(
        home=args.home,
        project_dir=args.project_dir,
        chain_dir=args.chain_dir,
        keys_dir=args.keys_dir,
    )
    _print_json(build_codex_shareable_context(fixture))
    return 0


def cmd_codex_app_server_report(args: argparse.Namespace) -> int:
    report = build_codex_shareable_report(
        home=args.home,
        chain_dir=args.chain_dir,
        keys_dir=args.keys_dir,
        verify_expiry=args.verify_expiry,
    )
    if args.json:
        _print_json(report)
        return 0
    print(f"Ardur Codex app-server receipt report: {report['receipt_count']} receipts across {report['chain_count']} chains")
    print(f"Chains: {report['chain_dir']}")
    print(f"Verdicts: {report['policy_verdict_counts']}")
    print(f"Coverage gaps: {report['coverage_gaps']}")
    return 0


def cmd_posture_scan(args: argparse.Namespace) -> int:
    posture = build_posture_index(
        receipts=args.receipts,
        keys_dir=args.keys_dir,
        profile=args.profile,
        evidence_bundle=args.evidence_bundle,
        verify_expiry=args.verify_expiry,
    )
    if args.format == "json":
        _print_json(posture)
        return 0
    print(format_posture_report(posture))
    return 0


def cmd_posture_report(args: argparse.Namespace) -> int:
    posture = json.loads(args.input.read_text(encoding="utf-8"))
    if args.format == "json":
        _print_json(posture)
        return 0
    print(format_posture_report(posture))
    return 0


def cmd_hub(args: argparse.Namespace) -> int:
    serve_hub(
        host=args.host,
        port=args.port,
        home=args.home,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
        no_tls=args.no_tls,
    )
    return 0


def cmd_kill_switch(args: argparse.Namespace) -> int:
    import ssl
    import urllib.request as urlreq

    proxy_url = (
        args.proxy_url
        or os.environ.get("ARDUR_PROXY_URL")
        or "https://127.0.0.1:8443"
    )
    api_token = args.api_token or os.environ.get("ARDUR_API_TOKEN", "")
    payload = json.dumps({"deactivate": args.deactivate}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_token}",
    }
    req = urlreq.Request(f"{proxy_url.rstrip('/')}/admin/kill-switch", data=payload, headers=headers)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # localhost self-signed cert
    try:
        with urlreq.urlopen(req, timeout=5, context=ctx) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            _print_json(result)
            return 0
    except Exception as exc:
        _print_json({"ok": False, "error": str(exc)})
        return 1


def cmd_setup(args: argparse.Namespace) -> int:
    _print_json(setup_personal(args))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    response = hub_request(
        "GET",
        "/v1/status",
        hub_url=args.hub_url,
        hub_token=args.hub_token,
        home=args.home,
    )
    _print_json(response)
    return 0 if response.get("ok") else 1


def cmd_doctor(args: argparse.Namespace) -> int:
    response = doctor_personal(args)
    _print_json(response)
    return 0 if response.get("ok") else 1


def cmd_uninstall(args: argparse.Namespace) -> int:
    _print_json(uninstall_personal(args))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    return run_under_hub(args)


def cmd_desktop_observe(args: argparse.Namespace) -> int:
    response = desktop_observe(args)
    _print_json(response)
    return 0 if response.get("ok") else 1


def cmd_personal_native_host(args: argparse.Namespace) -> int:
    if args.once_json:
        message = json.loads(args.once_json.read_text(encoding="utf-8"))
        response = handle_native_host_message(message, hub_url=args.hub_url, hub_token=args.hub_token, home=args.home)
        _print_json(response)
        return 0 if response.get("ok") else 1
    run_native_host(sys.stdin.buffer, sys.stdout.buffer, hub_url=args.hub_url, hub_token=args.hub_token, home=args.home)
    return 0


def cmd_personal_native_manifest(args: argparse.Namespace) -> int:
    _print_json(
        build_native_host_manifest(
            args.host_path,
            args.extension_id,
            browser=args.browser,
        )
    )
    return 0


CLAUDE_CODE_PROTECT_MODES = {
    "safe-coding": {
        "mission": "Safe Claude Code work inside the selected folder.",
        "allowed_tools": ["Read", "Glob", "Grep", "Edit", "MultiEdit", "Write"],
        "forbidden_tools": ["Bash"],
    },
    "read-only": {
        "mission": "Read-only Claude Code review inside the selected folder.",
        "allowed_tools": ["Read", "Glob", "Grep"],
        "forbidden_tools": ["Bash", "Edit", "MultiEdit", "Write"],
    },
}


def _default_claude_plugin_dir() -> Path:
    cwd_candidate = Path.cwd() / "plugins" / "claude-code"
    if cwd_candidate.exists():
        return cwd_candidate
    source_candidate = Path(__file__).resolve().parents[2] / "plugins" / "claude-code"
    return source_candidate


def _normalize_protect_mode(value: str) -> str:
    return value.strip().lower().replace("_", "-").replace(" ", "-")


def _claude_code_plugin_checks(plugin_dir: Path) -> list[dict[str, object]]:
    return [
        {
            "name": "plugin_dir",
            "ok": plugin_dir.exists() and plugin_dir.is_dir(),
            "detail": str(plugin_dir),
        },
        {
            "name": "plugin_manifest",
            "ok": (plugin_dir / ".claude-plugin" / "plugin.json").is_file(),
            "detail": str(plugin_dir / ".claude-plugin" / "plugin.json"),
        },
        {
            "name": "plugin_hooks",
            "ok": (plugin_dir / "hooks" / "hooks.json").is_file(),
            "detail": str(plugin_dir / "hooks" / "hooks.json"),
        },
        {
            "name": "pre_tool_use",
            "ok": (plugin_dir / "hooks" / "pre_tool_use").is_file(),
            "detail": str(plugin_dir / "hooks" / "pre_tool_use"),
        },
        {
            "name": "post_tool_use",
            "ok": (plugin_dir / "hooks" / "post_tool_use").is_file(),
            "detail": str(plugin_dir / "hooks" / "post_tool_use"),
        },
        {
            "name": "subagent_start",
            "ok": (plugin_dir / "hooks" / "subagent_start").is_file(),
            "detail": str(plugin_dir / "hooks" / "subagent_start"),
        },
        {
            "name": "subagent_stop",
            "ok": (plugin_dir / "hooks" / "subagent_stop").is_file(),
            "detail": str(plugin_dir / "hooks" / "subagent_stop"),
        },
    ]


def _validate_claude_code_plugin_dir(plugin_dir: Path) -> None:
    failed = [check for check in _claude_code_plugin_checks(plugin_dir) if not check["ok"]]
    if failed:
        details = ", ".join(str(item["detail"]) for item in failed)
        raise FileNotFoundError(f"Claude Code plugin is incomplete: {details}")


def _write_private_text(path: Path, text: str) -> None:
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


def claude_code_doctor(plugin_dir: Path | None = None, home: Path | None = None) -> dict[str, object]:
    plugin = (plugin_dir or _default_claude_plugin_dir()).expanduser().resolve()
    checks = _claude_code_plugin_checks(plugin)
    claude_binary = shutil.which("claude")
    checks.append({
        "name": "claude_binary",
        "ok": bool(claude_binary),
        "detail": claude_binary or "claude not found on PATH",
    })
    active_passport = (home.expanduser() if home else DEFAULT_HOME) / "active_mission.jwt"
    checks.append({
        "name": "active_passport",
        "ok": active_passport.is_file(),
        "detail": str(active_passport),
    })
    if claude_binary and all(check["ok"] for check in checks[:5]):
        result = subprocess.run(
            [claude_binary, "plugin", "validate", str(plugin)],
            capture_output=True,
            text=True,
        )
        checks.append({
            "name": "plugin_validate",
            "ok": result.returncode == 0,
            "detail": result.stdout.strip() or result.stderr.strip(),
        })
    else:
        checks.append({
            "name": "plugin_validate",
            "ok": False,
            "detail": "skipped; missing claude binary or plugin files",
        })
    return {"ok": all(bool(check["ok"]) for check in checks), "checks": checks}


def _resolve_protect_policies(
    args: argparse.Namespace,
    profile: ArdurProfile | None,
    home: Path,
) -> list[dict[str, object]]:
    """Build additional_policies from CLI flags + profile."""
    policies: list[dict[str, object]] = []

    # CLI flags (highest priority)
    if getattr(args, "forbid_rules", None) is not None:
        rules = json.loads(Path(args.forbid_rules).read_text("utf-8"))
        if not isinstance(rules, list):
            rules = [rules]
        policies.append({
            "backend": "forbid_rules",
            "label": "cli-forbid-rules",
            "policy_inline": "",
            "policy_sha256": hashlib.sha256(
                json.dumps(rules, sort_keys=True).encode()
            ).hexdigest(),
            "data_inline": rules,
        })
    if getattr(args, "cedar_policy", None) is not None:
        policy_src = Path(args.cedar_policy).read_text("utf-8")
        entities: list[dict[str, object]] = []
        if getattr(args, "cedar_entities", None) is not None:
            entities = json.loads(Path(args.cedar_entities).read_text("utf-8"))
        policies.append({
            "backend": "cedar",
            "label": "cli-cedar-policy",
            "policy_inline": policy_src,
            "policy_sha256": hashlib.sha256(policy_src.encode()).hexdigest(),
            "data_inline": entities,
        })

    # Profile policies
    if profile and profile.forbid_rules:
        policies.append({
            "backend": "forbid_rules",
            "label": "profile-forbid-rules",
            "policy_inline": "",
            "policy_sha256": hashlib.sha256(
                json.dumps(profile.forbid_rules, sort_keys=True).encode()
            ).hexdigest(),
            "data_inline": profile.forbid_rules,
        })
    if profile and profile.cedar_policy:
        policies.append({
            "backend": "cedar",
            "label": "profile-cedar-policy",
            "policy_inline": profile.cedar_policy,
            "policy_sha256": hashlib.sha256(
                profile.cedar_policy.encode()
            ).hexdigest(),
            "data_inline": [],
        })

    return policies


def protect_claude_code(args: argparse.Namespace) -> dict[str, object]:
    profile = load_ardur_profile(args.profile) if args.profile else None
    mode_name = _normalize_protect_mode(args.mode or (profile.mode if profile and profile.mode else "safe-coding"))
    if mode_name not in CLAUDE_CODE_PROTECT_MODES:
        raise ValueError(f"unsupported Claude Code protection mode: {mode_name}")
    mode = CLAUDE_CODE_PROTECT_MODES[mode_name]
    raw_scope = args.scope
    if raw_scope is None and profile and profile.scope:
        profile_scope = Path(profile.scope).expanduser()
        if profile_scope.is_absolute():
            raw_scope = profile_scope
        else:
            raw_scope = Path(args.profile).expanduser().parent / profile_scope
    if raw_scope is None:
        raise ValueError("ardur protect claude-code requires --scope or a profile with `Protect folder:`")
    scope = Path(raw_scope).expanduser().resolve()
    home = Path(args.home).expanduser().resolve() if args.home else DEFAULT_HOME
    home.mkdir(parents=True, exist_ok=True)
    plugin_dir = Path(args.plugin_dir).expanduser().resolve()
    _validate_claude_code_plugin_dir(plugin_dir)
    private_key, public_key = generate_keypair(keys_dir=args.keys_dir or (home / "keys"))
    if profile and profile.allowed_tools:
        # A profile with an explicit allowlist is authoritative: if the author
        # leaves the blocklist empty, that means "no explicit tool denylist" and
        # should not silently inherit the mode's default denies. The built-in
        # templates still include their blocklists explicitly.
        allowed_tools = list(profile.allowed_tools)
        forbidden_tools = list(profile.forbidden_tools)
    else:
        allowed_tools = list(mode["allowed_tools"])
        forbidden_tools = list(profile.forbidden_tools if profile and profile.forbidden_tools else mode["forbidden_tools"])
    max_tool_calls = profile.max_tool_calls if profile and profile.max_tool_calls is not None else args.max_tool_calls
    max_duration_s = profile.max_duration_s if profile and profile.max_duration_s is not None else args.max_duration_s
    mission = MissionPassport(
        agent_id=args.agent_id,
        mission=args.mission or (profile.mission if profile and profile.mission else mode["mission"]),
        allowed_tools=allowed_tools,
        forbidden_tools=forbidden_tools,
        resource_scope=[str(scope), f"{scope}/*"],
        cwd=str(scope),
        max_tool_calls=max_tool_calls,
        max_duration_s=max_duration_s,
    )
    token = issue_passport(mission, private_key, ttl_s=args.ttl_s or max_duration_s)
    # Seed additional policies (Cedar / forbid_rules) into the persistent
    # store so the proxy picks them up at session-start time. Policies are
    # resolved from CLI flags first, then from the profile.
    additional_policies = _resolve_protect_policies(args, profile, home)
    if additional_policies:
        from vibap.backed_policy_store import FileBackedPolicyStore
        store = FileBackedPolicyStore(home)
        store.put_policies(mission_id=args.agent_id, policies=additional_policies)
    claims = verify_passport(token, public_key)
    active_passport = home / "active_mission.jwt"
    _write_private_text(active_passport, token + "\n")
    hook_python = home / "claude-code-hook-python"
    _write_private_text(hook_python, sys.executable + "\n")
    native_pre_hook_command = install_native_pre_tool_use_command(home=home)
    native_pre_hook_command_expected = resolve_native_pre_tool_use_command_path(home)
    run_command = f"VIBAP_HOME={shlex.quote(str(home))} claude --plugin-dir {shlex.quote(str(plugin_dir))}"
    return {
        "ok": True,
        "agent": "claude-code",
        "mode": mode_name,
        "profile": str(Path(args.profile).expanduser()) if args.profile else None,
        "scope": str(scope),
        "home": str(home),
        "active_passport": str(active_passport),
        # Matrix-compatible alias for real-world test harnesses and docs that
        # describe this artifact as an active Mission path. Keep the original
        # ``active_passport`` key for existing callers.
        "active_mission_path": str(active_passport),
        "hook_python": str(hook_python),
        "native_pre_hook_command": str(native_pre_hook_command) if native_pre_hook_command else None,
        "native_pre_hook_command_expected": str(native_pre_hook_command_expected),
        "plugin_dir": str(plugin_dir),
        "run_command": run_command,
        "allowed_tools": allowed_tools,
        "forbidden_tools": forbidden_tools,
        "claims": claims,
    }


def cmd_protect_claude_code(args: argparse.Namespace) -> int:
    result = protect_claude_code(args)
    if args.json:
        _print_json(result)
        return 0
    print("Ardur Claude Code protection configured.")
    print(f"mode: {result['mode']}")
    print(f"scope: {result['scope']}")
    print(f"active passport: {result['active_passport']}")
    print(f"run: {result['run_command']}")
    return 0


def cmd_profile_init(args: argparse.Namespace) -> int:
    path = write_profile_template(args.path, template=args.template, force=args.force)
    result = {
        "ok": True,
        "template": args.template,
        "path": str(path),
        "next_step": f"ardur protect claude-code --profile {path}",
    }
    if args.json:
        _print_json(result)
    else:
        print(f"Created {path}")
        print(result["next_step"])
    return 0


def cmd_doctor_claude_code(args: argparse.Namespace) -> int:
    response = claude_code_doctor(plugin_dir=args.plugin_dir, home=args.home)
    _print_json(response)
    return 0 if response.get("ok") else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ardur",
        description="Ardur governance proxy and mission-passport tooling",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    start = subparsers.add_parser("start", help="start the VIBAP proxy HTTP service")
    start.add_argument("--host", default="127.0.0.1", help="bind address")
    start.add_argument("--port", type=int, default=8080, help="listen port")
    start.add_argument("--mission", type=Path, help="optional mission JSON to issue and start immediately")
    start.add_argument("--keys-dir", type=Path, help="directory containing VIBAP signing keys")
    start.add_argument("--state-dir", type=Path, help="directory for persisted sessions")
    start.add_argument("--log-path", type=Path, help="JSONL audit log path")
    start.add_argument("--tls-cert", type=Path, help="TLS certificate PEM file")
    start.add_argument("--tls-key", type=Path, help="TLS private key PEM file")
    start.add_argument("--no-tls", action="store_true", help="disable TLS (plain HTTP only)")
    auth_group = start.add_mutually_exclusive_group()
    auth_group.add_argument(
        "--require-auth",
        dest="require_auth",
        action="store_true",
        help="require Bearer token on all endpoints except /health and /healthz (default)",
    )
    auth_group.add_argument(
        "--no-require-auth",
        dest="require_auth",
        action="store_false",
        help="DISABLE Bearer auth — DO NOT USE IN PRODUCTION",
    )
    start.set_defaults(func=cmd_start, require_auth=True)

    issue = subparsers.add_parser("issue", help="issue a mission passport JWT")
    issue.add_argument("--agent-id", required=True, help="agent subject identifier")
    issue.add_argument("--mission", required=True, help="declared mission string")
    issue.add_argument("--allowed-tools", nargs="*", default=[], help="allowed tool names")
    issue.add_argument("--forbidden-tools", nargs="*", default=[], help="forbidden tool names")
    issue.add_argument("--resource-scope", nargs="*", default=[], help="resource scope patterns")
    issue.add_argument("--max-tool-calls", type=int, default=50, help="max permitted tool calls")
    issue.add_argument("--max-duration-s", type=int, default=600, help="max mission duration in seconds")
    issue.add_argument("--delegation-allowed", action="store_true", help="allow one-step delegation")
    issue.add_argument("--max-delegation-depth", type=int, default=0, help="delegation depth budget")
    issue.add_argument("--ttl-s", type=int, help="override token TTL in seconds")
    issue.add_argument("--keys-dir", type=Path, help="directory containing VIBAP signing keys")
    issue.set_defaults(func=cmd_issue)

    verify = subparsers.add_parser("verify", help="verify a mission passport JWT")
    verify.add_argument("--token", required=True, help="passport token to verify")
    verify.add_argument("--keys-dir", type=Path, help="directory containing VIBAP signing keys")
    verify.set_defaults(func=cmd_verify)

    attest = subparsers.add_parser("attest", help="issue a behavioral attestation for a saved session")
    attest.add_argument("--session", required=True, help="session identifier / passport jti")
    attest.add_argument("--keys-dir", type=Path, help="directory containing VIBAP signing keys")
    attest.add_argument("--state-dir", type=Path, help="directory containing persisted sessions")
    attest.add_argument("--log-path", type=Path, help="JSONL audit log path")
    attest.set_defaults(func=cmd_attest)

    cc_hook = subparsers.add_parser(
        "claude-code-hook",
        help="run the Claude Code hook adapter",
    )
    cc_hook.add_argument(
        "phase",
        choices=["pre", "post", "subagent-start", "subagent-stop"],
        help="hook lifecycle phase to invoke",
    )
    cc_hook.add_argument(
        "--keys-dir",
        type=Path,
        help="signing keys directory",
    )
    cc_hook.set_defaults(func=cmd_claude_code_hook)

    cc_report = subparsers.add_parser(
        "claude-code-report",
        help="verify Claude Code hook receipt chains and summarize observability",
    )
    cc_report.add_argument("--home", type=Path, help="Ardur home containing claude-code-hook receipts")
    cc_report.add_argument("--chain-dir", type=Path, help="explicit Claude Code receipt chain directory")
    cc_report.add_argument("--keys-dir", type=Path, help="signing public-key directory")
    cc_report.add_argument(
        "--verify-expiry",
        action="store_true",
        help="also enforce short receipt expiry windows while verifying",
    )
    cc_report.add_argument("--json", action="store_true", help="print machine-readable report")
    cc_report.set_defaults(func=cmd_claude_code_report)

    gemini_hook = subparsers.add_parser(
        "gemini-cli-hook",
        help="run the local-only Gemini CLI hook adapter",
    )
    gemini_hook.add_argument("phase_pos", nargs="?", choices=["pre"], help="hook lifecycle phase")
    gemini_hook.add_argument("--phase", choices=["pre"], help="hook lifecycle phase")
    gemini_hook.add_argument("--keys-dir", type=Path, help="signing keys directory")
    gemini_hook.set_defaults(func=cmd_gemini_cli_hook)

    gemini_fixture = subparsers.add_parser(
        "gemini-cli-fixture",
        help="write a local Gemini CLI settings/context fixture and print redacted context",
    )
    gemini_fixture.add_argument(
        "--home",
        type=Path,
        help="explicit Gemini home/settings directory to populate; defaults to isolated Ardur local fixture state",
    )
    gemini_fixture.add_argument("--project-dir", type=Path, help="project directory that receives GEMINI.md")
    gemini_fixture.add_argument("--chain-dir", type=Path, help="Ardur Gemini receipt chain directory")
    gemini_fixture.add_argument("--keys-dir", type=Path, help="signing keys directory")
    gemini_fixture.set_defaults(func=cmd_gemini_cli_fixture)

    gemini_report = subparsers.add_parser(
        "gemini-cli-report",
        help="verify Gemini CLI hook receipt chains and summarize local-only observability",
    )
    gemini_report.add_argument("--home", type=Path, help="Gemini/Ardur home used for redaction context")
    gemini_report.add_argument("--chain-dir", type=Path, help="explicit Gemini CLI receipt chain directory")
    gemini_report.add_argument("--keys-dir", type=Path, help="signing public-key directory")
    gemini_report.add_argument(
        "--verify-expiry",
        action="store_true",
        help="also enforce short receipt expiry windows while verifying",
    )
    gemini_report.add_argument("--json", action="store_true", help="print machine-readable report")
    gemini_report.set_defaults(func=cmd_gemini_cli_report)

    codex_event = subparsers.add_parser(
        "codex-app-server-event",
        help="ingest a local Codex app-server/host-event JSON payload and emit an Ardur receipt",
    )
    codex_event.add_argument("--keys-dir", type=Path, help="signing keys directory")
    codex_event.set_defaults(func=cmd_codex_app_server_event)

    codex_fixture = subparsers.add_parser(
        "codex-app-server-fixture",
        help="write a local Codex app-server config/schema fixture and print redacted context",
    )
    codex_fixture.add_argument(
        "--home",
        type=Path,
        help="explicit Codex home/config directory to populate; defaults to isolated Ardur local fixture state",
    )
    codex_fixture.add_argument("--project-dir", type=Path, help="project directory that receives CODEX.md")
    codex_fixture.add_argument("--chain-dir", type=Path, help="Ardur Codex receipt chain directory")
    codex_fixture.add_argument("--keys-dir", type=Path, help="signing keys directory")
    codex_fixture.set_defaults(func=cmd_codex_app_server_fixture)

    codex_report = subparsers.add_parser(
        "codex-app-server-report",
        help="verify Codex app-server receipt chains and summarize local-only observability",
    )
    codex_report.add_argument("--home", type=Path, help="Codex/Ardur home used for redaction context")
    codex_report.add_argument("--chain-dir", type=Path, help="explicit Codex app-server receipt chain directory")
    codex_report.add_argument("--keys-dir", type=Path, help="signing public-key directory")
    codex_report.add_argument(
        "--verify-expiry",
        action="store_true",
        help="also enforce short receipt expiry windows while verifying",
    )
    codex_report.add_argument("--json", action="store_true", help="print machine-readable report")
    codex_report.set_defaults(func=cmd_codex_app_server_report)

    posture = subparsers.add_parser(
        "posture",
        help="derive a local evidence posture index from Ardur artifacts",
    )
    posture_subparsers = posture.add_subparsers(dest="posture_command", required=True)
    posture_scan = posture_subparsers.add_parser(
        "scan",
        help="scan receipt/profile/evidence artifacts into a posture JSON document",
    )
    posture_scan.add_argument("--receipts", type=Path, required=True, help="receipt chain directory or receipts.jsonl file")
    posture_scan.add_argument("--keys-dir", type=Path, help="directory containing passport_public.pem for read-only verification")
    posture_scan.add_argument("--profile", type=Path, help="optional ARDUR.md profile to digest")
    posture_scan.add_argument("--evidence-bundle", type=Path, help="optional redacted no-key evidence bundle to summarize")
    posture_scan.add_argument(
        "--verify-expiry",
        action="store_true",
        help="also enforce short receipt expiry windows while verifying",
    )
    posture_scan.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="json",
        help="output format (default: json)",
    )
    posture_scan.set_defaults(func=cmd_posture_scan)

    posture_report = posture_subparsers.add_parser(
        "report",
        help="render a posture JSON document as a concise report",
    )
    posture_report.add_argument("--input", type=Path, required=True, help="posture JSON produced by ardur posture scan")
    posture_report.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="output format (default: markdown)",
    )
    posture_report.set_defaults(func=cmd_posture_report)

    hub = subparsers.add_parser("hub", help="start the local Ardur Personal Hub")
    hub.add_argument("--host", default=DEFAULT_HUB_HOST, help="bind address")
    hub.add_argument("--port", type=int, default=DEFAULT_HUB_PORT, help="listen port")
    hub.add_argument("--home", type=Path, help="Ardur Personal home directory")
    hub.add_argument("--tls-cert", type=Path, help="TLS certificate PEM file")
    hub.add_argument("--tls-key", type=Path, help="TLS private key PEM file")
    hub.add_argument("--no-tls", action="store_true", help="disable TLS (plain HTTP only)")
    hub.set_defaults(func=cmd_hub)

    setup = subparsers.add_parser("setup", help="configure Ardur Personal on this Mac")
    setup.add_argument("--host", default=DEFAULT_HUB_HOST, help="Hub bind address")
    setup.add_argument("--port", type=int, default=DEFAULT_HUB_PORT, help="Hub port")
    setup.add_argument("--home", type=Path, help="Ardur Personal home directory")
    setup.add_argument(
        "--rotate-token",
        action="store_true",
        help="generate a new local Hub token instead of reusing the existing install token",
    )
    setup.add_argument(
        "--extension-path",
        type=Path,
        default=Path("examples/ardur-personal-extension"),
        help="browser extension directory to show in setup output",
    )
    setup.set_defaults(func=cmd_setup)

    status = subparsers.add_parser("status", help="show Ardur Personal Hub status")
    status.add_argument("--hub-url", default=DEFAULT_HUB_URL, help="Hub base URL")
    status.add_argument("--hub-token", default=None, help="Hub bearer token (defaults to config/env)")
    status.add_argument("--home", type=Path, help="Ardur Personal home directory")
    status.set_defaults(func=cmd_status)

    doctor = subparsers.add_parser("doctor", help="check local Ardur Personal setup")
    doctor.add_argument("--home", type=Path, help="Ardur Personal home directory")
    doctor.add_argument("--hub-url", default=DEFAULT_HUB_URL, help="Hub base URL")
    doctor.add_argument("--hub-token", default=None, help="Hub bearer token (defaults to config/env)")
    doctor.set_defaults(func=cmd_doctor)

    doctor_cc = subparsers.add_parser("doctor-claude-code", help="check Claude Code plugin and active passport setup")
    doctor_cc.add_argument("--home", type=Path, help="Ardur home containing active_mission.jwt")
    doctor_cc.add_argument("--plugin-dir", type=Path, default=_default_claude_plugin_dir(), help="Claude Code plugin directory")
    doctor_cc.set_defaults(func=cmd_doctor_claude_code)

    kill_switch = subparsers.add_parser("kill-switch", help="activate/deactivate the emergency kill switch")
    kill_switch.add_argument("--deactivate", action="store_true", help="deactivate the kill switch")
    kill_switch.add_argument("--proxy-url", default=None, help="proxy base URL (defaults to ARDUR_PROXY_URL env or https://127.0.0.1:8443)")
    kill_switch.add_argument("--api-token", default=None, help="proxy bearer token (defaults to ARDUR_API_TOKEN env)")
    kill_switch.set_defaults(func=cmd_kill_switch)

    uninstall = subparsers.add_parser("uninstall", help="remove Ardur Personal launch files")
    uninstall.add_argument("--home", type=Path, help="Ardur Personal home directory")
    uninstall.add_argument(
        "--remove-data",
        action="store_true",
        help="also remove local Ardur Personal evidence and keys",
    )
    uninstall.set_defaults(func=cmd_uninstall)

    run = subparsers.add_parser("run", help="run a CLI command through Ardur Personal Hub")
    run.add_argument("--hub-url", default=DEFAULT_HUB_URL, help="Hub base URL")
    run.add_argument("--hub-token", default=None, help="Hub bearer token (defaults to config/env)")
    run.add_argument("--home", type=Path, help="Ardur Personal home directory")
    run.add_argument("command", nargs=argparse.REMAINDER, help="command to run after --")
    run.set_defaults(func=cmd_run)

    desktop = subparsers.add_parser(
        "desktop-observe",
        help="record a Mac desktop app observation through Ardur Personal Hub",
    )
    desktop.add_argument("--hub-url", default=DEFAULT_HUB_URL, help="Hub base URL")
    desktop.add_argument("--hub-token", default=None, help="Hub bearer token (defaults to config/env)")
    desktop.add_argument("--home", type=Path, help="Ardur Personal home directory")
    desktop.add_argument("--session-id", help="stable desktop session id")
    desktop.add_argument("--app", help="application name; autodetected on macOS when omitted")
    desktop.add_argument("--title", help="window title; autodetected on macOS when omitted")
    desktop.add_argument(
        "--text",
        help="explicit-consent visible text excerpt to include in the session review",
    )
    desktop.set_defaults(func=cmd_desktop_observe)

    personal_native_host = subparsers.add_parser(
        "personal-native-host",
        help="run the Ardur Personal native messaging bridge",
    )
    personal_native_host.add_argument("--hub-url", default=DEFAULT_HUB_URL, help="Hub base URL")
    personal_native_host.add_argument("--hub-token", default=None, help="Hub bearer token (defaults to config/env)")
    personal_native_host.add_argument("--home", type=Path, help="Ardur Personal home directory")
    personal_native_host.add_argument(
        "--once-json",
        type=Path,
        help="development mode: process one JSON message file",
    )
    personal_native_host.set_defaults(func=cmd_personal_native_host)

    personal_native_manifest = subparsers.add_parser(
        "personal-native-manifest",
        help="print a native messaging manifest for the Hub bridge",
    )
    personal_native_manifest.add_argument("--host-path", type=Path, required=True)
    personal_native_manifest.add_argument("--extension-id", required=True)
    personal_native_manifest.add_argument(
        "--browser",
        choices=["chrome", "chrome-for-testing", "chromium", "edge", "firefox"],
        default="chrome",
    )
    personal_native_manifest.set_defaults(func=cmd_personal_native_manifest)

    profile = subparsers.add_parser(
        "profile",
        help="create and inspect plain Markdown Ardur guardrail profiles",
    )
    profile_subparsers = profile.add_subparsers(dest="profile_command", required=True)
    profile_init = profile_subparsers.add_parser(
        "init",
        help="create an ARDUR.md guardrail profile from a built-in template",
    )
    profile_init.add_argument(
        "--template",
        choices=sorted(PROFILE_TEMPLATES),
        default="read-only",
        help="starter profile to write",
    )
    profile_init.add_argument("--path", type=Path, default=Path("ARDUR.md"), help="profile file to create")
    profile_init.add_argument("--force", action="store_true", help="replace an existing profile")
    profile_init.add_argument("--json", action="store_true", help="print machine-readable setup details")
    profile_init.set_defaults(func=cmd_profile_init)

    protect = subparsers.add_parser(
        "protect",
        help="configure local Ardur protection for an AI assistant",
    )
    protect_subparsers = protect.add_subparsers(dest="protect_target", required=True)
    protect_cc = protect_subparsers.add_parser(
        "claude-code",
        help="issue an active Mission Passport and print the Claude Code plugin command",
    )
    protect_cc.add_argument("--scope", type=Path, help="folder Claude Code is allowed to work in")
    protect_cc.add_argument("--profile", type=Path, help="Markdown Ardur profile, such as ARDUR.md")
    protect_cc.add_argument(
        "--mode",
        choices=sorted(CLAUDE_CODE_PROTECT_MODES),
        default=None,
        help="plain-English policy template",
    )
    protect_cc.add_argument("--json", action="store_true", help="print machine-readable setup details")
    protect_cc.add_argument("--home", type=Path, help="Ardur home that receives active_mission.jwt")
    protect_cc.add_argument("--plugin-dir", type=Path, default=_default_claude_plugin_dir(), help="Claude Code plugin directory")
    protect_cc.add_argument("--keys-dir", type=Path, help="signing keys directory")
    protect_cc.add_argument("--agent-id", default="local-user:claude-code", help="Mission Passport subject")
    protect_cc.add_argument("--mission", help="override the default mission text for the selected mode")
    protect_cc.add_argument("--max-tool-calls", type=int, default=250, help="maximum governed tool calls")
    protect_cc.add_argument("--max-duration-s", type=int, default=86400, help="mission duration budget in seconds")
    protect_cc.add_argument("--ttl-s", type=int, help="override token TTL in seconds")
    protect_cc.add_argument(
        "--forbid-rules", type=Path,
        help="JSON file containing forbid_rules policy specifications",
    )
    protect_cc.add_argument(
        "--cedar-policy", type=Path,
        help="Cedar policy file (.cedar)",
    )
    protect_cc.add_argument(
        "--cedar-entities", type=Path,
        help="Cedar entities JSON file (used with --cedar-policy)",
    )
    protect_cc.set_defaults(func=cmd_protect_claude_code)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if getattr(args, "command", None) and args.command[0] == "--":
        args.command = args.command[1:]
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
