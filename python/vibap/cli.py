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
from pathlib import Path
from typing import Sequence

import jwt

from . import __version__
from .ardur_profile import PROFILE_TEMPLATES, ArdurProfile, load_ardur_profile, write_profile_template
from .ardur_personal_native_host import (
    NativeHostManifestValidationError,
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
    status_response_with_next_steps,
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


def _print_report_next_steps(report: dict) -> None:
    next_steps = report.get("next_steps") or []
    if not next_steps:
        return
    print("Next steps:")
    for index, step in enumerate(next_steps, start=1):
        command = step.get("command", "")
        detail = step.get("detail", "")
        print(f"{index}. {command}")
        if detail:
            print(f"   {detail}")


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
        api_token=args.api_token,
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


def _verify_failure_next_steps() -> list[dict[str, str]]:
    return [
        {
            "condition": "invalid_passport_token",
            "action": "verify_a_fresh_passport_token",
            "command": "ardur verify --token <token> --keys-dir <keys-dir>",
            "detail": (
                "Use a Mission Passport JWT issued by this Ardur key directory. "
                "Keep raw tokens out of shared logs and reports."
            ),
        },
        {
            "condition": "invalid_passport_token",
            "action": "issue_a_new_passport_if_needed",
            "command": "ardur issue --agent-id <agent-id> --mission <mission> --keys-dir <keys-dir>",
            "detail": "Issue a fresh local Mission Passport when the old token is malformed, expired, or signed by a different key.",
        },
    ]


def _verify_failure_response(exc: Exception) -> dict:
    detail = str(exc).strip() or exc.__class__.__name__
    return {
        "ok": False,
        "valid": False,
        "error": "invalid_passport_token",
        "condition": "invalid_passport_token",
        "message": "Mission Passport token could not be verified.",
        "detail": detail,
        "next_steps": _verify_failure_next_steps(),
    }


def cmd_verify(args: argparse.Namespace) -> int:
    _, public_key = generate_keypair(keys_dir=args.keys_dir)
    try:
        claims = verify_passport(args.token, public_key)
    except (jwt.PyJWTError, PermissionError, ValueError) as exc:
        _print_json(_verify_failure_response(exc))
        return 1
    _print_json({"valid": True, "claims": claims})
    return 0


def _attest_failure_condition(exc: Exception) -> tuple[str, str]:
    message = str(exc).lower()
    if "invalid session id format" in message:
        return (
            "invalid_session_id",
            "Session identifiers must be UUIDs produced by an Ardur governed session.",
        )
    if "unknown session" in message:
        return (
            "session_not_found",
            "No persisted session was found for the supplied session id in the selected state directory.",
        )
    return (
        "attestation_failed",
        "The session could not be loaded or attested from the selected local state.",
    )


def _attest_failure_next_steps(condition: str) -> list[dict[str, str]]:
    steps = [
        {
            "condition": condition,
            "action": "retry_with_recorded_session_id",
            "command": "ardur attest --session <session-id> --keys-dir <keys-dir> --state-dir <state-dir> --log-path <audit-log>",
            "detail": (
                "Use the exact session_id emitted by the governed session and the same local state directory. "
                "Do not paste raw tokens or local private paths into shared artifacts."
            ),
        }
    ]
    if condition in {"invalid_session_id", "session_not_found"}:
        steps.append(
            {
                "condition": condition,
                "action": "start_or_find_a_governed_session",
                "command": "ardur start --mission <mission.json> --keys-dir <keys-dir> --state-dir <state-dir> --log-path <audit-log>",
                "detail": "Start or locate the governed session first, then attest using its UUID session id.",
            }
        )
    return steps


def _attest_failure_response(exc: Exception) -> dict:
    condition, detail = _attest_failure_condition(exc)
    return {
        "ok": False,
        "valid": False,
        "error": condition,
        "condition": condition,
        "message": "Behavioral attestation could not be issued for the requested session.",
        "detail": detail,
        "next_steps": _attest_failure_next_steps(condition),
    }


def cmd_attest(args: argparse.Namespace) -> int:
    private_key, public_key = generate_keypair(keys_dir=args.keys_dir)
    proxy = GovernanceProxy(
        log_path=args.log_path,
        state_dir=args.state_dir,
        keys_dir=args.keys_dir,
        public_key=public_key,
    )
    try:
        token, claims = proxy.issue_attestation_for_session(args.session, private_key)
    except (ValueError, PermissionError, jwt.PyJWTError) as exc:
        _print_json(_attest_failure_response(exc))
        return 1
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
    _print_report_next_steps(report)
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
    _print_report_next_steps(report)
    return 0


def _codex_app_server_event_input_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "create_codex_app_server_fixture",
            "command": "ardur codex-app-server-fixture --project-dir <your-project>",
            "detail": (
                "Create a local-only Codex app-server fixture and inspect the generated "
                "config/schema before feeding host-event JSON."
            ),
        },
        {
            "condition": condition,
            "action": "rerun_with_event_json_file",
            "command": "ardur codex-app-server-event --keys-dir <keys-dir> < <event-json-file>",
            "detail": (
                "Feed a Codex app-server host-event JSON object from <event-json-file>. "
                "Keep raw tokens and local private paths out of shared logs and reports."
            ),
        },
    ]


def _codex_app_server_event_input_failure_response(exc: Exception) -> dict:
    if isinstance(exc, json.JSONDecodeError):
        condition = "codex_app_server_event_input_malformed"
        message = "Codex app-server host-event input is not valid JSON."
        detail = (
            "Input must be a valid JSON object; "
            f"parsing failed at line {exc.lineno}, column {exc.colno}."
        )
    else:
        condition = "codex_app_server_event_input_not_object"
        message = "Codex app-server host-event input must be a JSON object."
        detail = (
            "Input must be a JSON object from <event-json-file>; arrays, strings, "
            "numbers, booleans, and null are not accepted."
        )
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": message,
        "detail": detail,
        "next_steps": _codex_app_server_event_input_next_steps(condition),
    }


def _load_codex_app_server_event_stdin(raw: str) -> dict:
    if not raw.strip():
        return {}
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Codex app-server host-event payload must be a JSON object")
    return payload


def cmd_codex_app_server_event(args: argparse.Namespace) -> int:
    raw = sys.stdin.read()
    try:
        payload = _load_codex_app_server_event_stdin(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        _print_json(_codex_app_server_event_input_failure_response(exc))
        return 1
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
    _print_report_next_steps(report)
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


def _posture_report_input_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "create_posture_json",
            "command": "ardur posture scan --receipts <chain-dir> --keys-dir <keys-dir> --format json > <posture-json>",
            "detail": (
                "Create a posture JSON document from local Ardur artifacts first. "
                "Keep local paths, private keys, and raw tokens out of shared reports."
            ),
        },
        {
            "condition": condition,
            "action": "rerun_posture_report",
            "command": "ardur posture report --input <posture-json> --format json",
            "detail": "Render the generated posture JSON after the input file exists and parses successfully.",
        },
    ]


def _posture_report_input_failure_response(exc: Exception) -> dict:
    if isinstance(exc, FileNotFoundError):
        condition = "posture_report_input_missing"
        message = "Posture report input file could not be read."
        detail = "No posture JSON file was found at the supplied --input path."
    elif isinstance(exc, json.JSONDecodeError):
        condition = "posture_report_input_malformed"
        message = "Posture report input file is not valid JSON."
        detail = f"JSON parsing failed at line {exc.lineno}, column {exc.colno}."
    elif isinstance(exc, ValueError):
        condition = "posture_report_input_invalid"
        message = "Posture report input file is not a posture JSON object."
        detail = "The supplied --input file must contain a JSON object produced by ardur posture scan."
    else:
        condition = "posture_report_input_unreadable"
        message = "Posture report input file could not be read."
        detail = f"Reading the supplied --input file failed with {exc.__class__.__name__}."
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": message,
        "detail": detail,
        "next_steps": _posture_report_input_next_steps(condition),
    }


def cmd_posture_report(args: argparse.Namespace) -> int:
    try:
        posture = json.loads(args.input.read_text(encoding="utf-8"))
        if not isinstance(posture, dict):
            raise ValueError("posture report input must be a JSON object")
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        response = _posture_report_input_failure_response(exc)
        if args.format == "json":
            _print_json(response)
        else:
            print(f"Error: {response['message']}")
            print(f"Detail: {response['detail']}")
            _print_report_next_steps(response)
        return 1
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


def _kill_switch_invalid_proxy_url_next_steps() -> list[dict[str, str]]:
    return [
        {
            "condition": "proxy_url_invalid",
            "action": "check_proxy_url",
            "command": "ardur kill-switch --proxy-url <proxy-url> --api-token <api-token>",
            "detail": (
                "Use a complete HTTP or HTTPS governance proxy endpoint such as "
                "https://127.0.0.1:<proxy-port>. Keep raw local paths, malformed URLs, "
                "URL credentials, and tokens out of shared logs."
            ),
        },
        {
            "condition": "proxy_url_invalid",
            "action": "start_or_check_governance_proxy",
            "command": "VIBAP_API_TOKEN=<api-token> ardur start --host 127.0.0.1 --port <proxy-port>",
            "detail": (
                "If the proxy is not running, start the local loopback governance proxy "
                "and copy only its scheme, host, and port into <proxy-url>."
            ),
        },
    ]


def _kill_switch_next_steps_for_failure(
    error: str,
    *,
    status: int | None = None,
) -> list[dict[str, str]]:
    """Return placeholder-only remediation hints for kill-switch setup failures."""
    normalized_error = error.strip().lower().replace("_", " ")
    status_text = str(status or "").strip()

    if normalized_error == "proxy url invalid":
        return _kill_switch_invalid_proxy_url_next_steps()

    proxy_unavailable = any(
        marker in normalized_error
        for marker in {
            "connection refused",
            "connection reset",
            "connection aborted",
            "network is unreachable",
            "no route to host",
            "name or service not known",
            "nodename nor servname",
            "timed out",
            "urlopen error",
        }
    )
    tls_problem = any(
        marker in normalized_error
        for marker in {
            "ssl",
            "tls",
            "certificate",
            "wrong version number",
            "handshake",
        }
    )
    token_problem = (
        status_text in {"401", "403"}
        or "authorization" in normalized_error
        or "unauthorized" in normalized_error
        or "bearer token" in normalized_error
        or "invalid bearer" in normalized_error
        or "api token" in normalized_error
    )
    endpoint_problem = status_text in {"404", "405"} or "not found" in normalized_error

    if not proxy_unavailable and not tls_problem and not token_problem and not endpoint_problem:
        return []

    steps: list[dict[str, str]] = []
    if proxy_unavailable or tls_problem or endpoint_problem:
        steps.append(
            {
                "condition": "proxy_tls_setup" if tls_problem else "proxy_unavailable",
                "action": "start_or_check_governance_proxy",
                "command": "VIBAP_API_TOKEN=<api-token> ardur start --host 127.0.0.1 --port <proxy-port>",
                "detail": (
                    "Start the local loopback governance proxy and keep its token private. "
                    "Use --tls-cert/--tls-key if your proxy URL uses https with explicit certs, "
                    "or --no-tls only for local development."
                ),
            }
        )
        steps.append(
            {
                "condition": "proxy_tls_setup" if tls_problem else "proxy_url_check",
                "action": "check_proxy_url_scheme",
                "command": "ardur kill-switch --proxy-url <proxy-url> --api-token <api-token>",
                "detail": (
                    "Use the scheme, host, and port printed by ardur start; keep any URL "
                    "credentials or raw tokens out of logs and shared artifacts."
                ),
            }
        )

    if token_problem:
        steps.append(
            {
                "condition": "proxy_token_required",
                "action": "supply_proxy_api_token",
                "command": "ardur kill-switch --proxy-url <proxy-url> --api-token <api-token>",
                "detail": (
                    "Pass the configured proxy API token with --api-token <api-token> or "
                    "ARDUR_API_TOKEN=<api-token>. Do not paste the raw token into shared logs."
                ),
            }
        )

    steps.append(
        {
            "condition": "kill_switch_proxy_request_failed",
            "action": "rerun_kill_switch_or_health_check",
            "command": "ardur kill-switch --proxy-url <proxy-url> --api-token <api-token>",
            "detail": (
                "After local proxy setup is fixed, rerun ardur kill-switch or check the "
                "loopback proxy health endpoint. These hints are local/no-key setup guidance "
                "only and do not claim external provider visibility or live enforcement beyond "
                "the configured proxy."
            ),
        }
    )
    return steps


def _kill_switch_failure_response(error: str, *, status: int | None = None) -> dict:
    response: dict = {"ok": False, "error": error}
    if status is not None:
        response["status"] = status
    steps = _kill_switch_next_steps_for_failure(error, status=status)
    if steps:
        response["next_steps"] = steps
    return response


def _kill_switch_invalid_proxy_url_response() -> dict:
    return {
        "ok": False,
        "error": "proxy_url_invalid",
        "error_code": "proxy_url_invalid",
        "condition": "proxy_url_invalid",
        "message": "Ardur governance proxy URL is invalid.",
        "detail": (
            "The proxy URL could not be parsed as a complete HTTP or HTTPS endpoint. "
            "Use a loopback URL such as https://127.0.0.1:<proxy-port>."
        ),
        "next_steps": _kill_switch_invalid_proxy_url_next_steps(),
    }


def _validated_kill_switch_proxy_base_url(proxy_url: str) -> str | None:
    """Return a request base URL only for complete HTTP(S) kill-switch endpoints."""
    from urllib.parse import urlsplit

    base_url = str(proxy_url).strip()
    try:
        parsed = urlsplit(base_url)
        if parsed.scheme.lower() not in {"http", "https"}:
            return None
        if not parsed.netloc or not parsed.hostname:
            return None
        _ = parsed.port
    except ValueError:
        return None
    return base_url.rstrip("/")


def _kill_switch_proxy_host_is_loopback(proxy_url: str) -> bool:
    import ipaddress
    from urllib.parse import urlparse

    try:
        host = urlparse(proxy_url).hostname
    except ValueError:
        return False
    if not host:
        return False
    normalized_host = host.strip().lower()
    if normalized_host == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized_host).is_loopback
    except ValueError:
        return False


def _kill_switch_ssl_context(proxy_url: str):
    import ssl

    ctx = ssl.create_default_context()
    if _kill_switch_proxy_host_is_loopback(proxy_url):
        # The local development proxy uses a self-signed certificate by default.
        # Keep that ergonomic localhost path, but do not carry the insecure TLS
        # policy to caller-supplied remote proxy URLs where bearer tokens cross
        # the network.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def cmd_kill_switch(args: argparse.Namespace) -> int:
    import urllib.error as urlerror
    import urllib.request as urlreq

    proxy_url = (
        args.proxy_url
        or os.environ.get("ARDUR_PROXY_URL")
        or "https://127.0.0.1:8443"
    )
    proxy_base_url = _validated_kill_switch_proxy_base_url(proxy_url)
    if proxy_base_url is None:
        _print_json(_kill_switch_invalid_proxy_url_response())
        return 1
    api_token = args.api_token or os.environ.get("ARDUR_API_TOKEN", "")
    payload = json.dumps({"deactivate": args.deactivate}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_token}",
    }
    req = urlreq.Request(f"{proxy_base_url}/admin/kill-switch", data=payload, headers=headers)
    ctx = _kill_switch_ssl_context(proxy_base_url)
    try:
        with urlreq.urlopen(req, timeout=5, context=ctx) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            _print_json(result)
            return 0
    except urlerror.HTTPError as exc:
        error = str(exc)
        try:
            payload = json.loads(exc.read().decode("utf-8"))
        except Exception:
            payload = {}
        if isinstance(payload, dict) and payload.get("error"):
            error = str(payload["error"])
        _print_json(_kill_switch_failure_response(error, status=exc.code))
        return 1
    except Exception as exc:
        _print_json(_kill_switch_failure_response(str(exc)))
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
    response = status_response_with_next_steps(response)
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


def _personal_native_host_once_json_input_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "create_native_message_json",
            "command": "ardur personal-native-host --once-json <native-message.json> --home <ardur-home> --hub-url <hub-url>",
            "detail": (
                "Create a local native-message JSON object before using --once-json. "
                "Keep local private paths and raw Hub tokens out of shared logs and reports."
            ),
        },
        {
            "condition": condition,
            "action": "rerun_personal_native_host_or_doctor",
            "command": "ardur doctor --home <ardur-home> --hub-url <hub-url>",
            "detail": (
                "After the input JSON is valid, check local Ardur Personal setup with doctor "
                "or rerun ardur personal-native-host --once-json <native-message.json>."
            ),
        },
    ]


def _personal_native_host_once_json_failure_response(exc: Exception) -> dict:
    if isinstance(exc, json.JSONDecodeError):
        condition = "personal_native_host_once_json_malformed"
        message = "Native Messaging --once-json input is not valid JSON."
        detail = f"JSON parsing failed at line {exc.lineno}, column {exc.colno}."
    elif isinstance(exc, ValueError):
        condition = "personal_native_host_once_json_not_object"
        message = "Native Messaging --once-json input must be a JSON object."
        detail = (
            "The supplied --once-json file must contain a native-message JSON object; "
            "arrays, strings, numbers, booleans, and null are not accepted."
        )
    elif isinstance(exc, FileNotFoundError):
        condition = "personal_native_host_once_json_missing"
        message = "Native Messaging --once-json input file could not be read."
        detail = "No native-message JSON file was found at the supplied --once-json path."
    else:
        condition = "personal_native_host_once_json_unreadable"
        message = "Native Messaging --once-json input file could not be read."
        detail = f"Reading the supplied --once-json file failed with {exc.__class__.__name__}."
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": message,
        "detail": detail,
        "next_steps": _personal_native_host_once_json_input_next_steps(condition),
    }


def _load_personal_native_host_once_json(path: Path) -> dict:
    message = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(message, dict):
        raise ValueError("native host once-json payload must be a JSON object")
    return message


def cmd_personal_native_host(args: argparse.Namespace) -> int:
    if args.once_json:
        try:
            message = _load_personal_native_host_once_json(args.once_json)
        except (
            FileNotFoundError,
            PermissionError,
            IsADirectoryError,
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            _print_json(_personal_native_host_once_json_failure_response(exc))
            return 1
        response = handle_native_host_message(message, hub_url=args.hub_url, hub_token=args.hub_token, home=args.home)
        _print_json(response)
        return 0 if response.get("ok") else 1
    run_native_host(sys.stdin.buffer, sys.stdout.buffer, hub_url=args.hub_url, hub_token=args.hub_token, home=args.home)
    return 0


def cmd_personal_native_manifest(args: argparse.Namespace) -> int:
    try:
        manifest = build_native_host_manifest(
            args.host_path,
            args.extension_id,
            browser=args.browser,
        )
    except NativeHostManifestValidationError as exc:
        _print_json(exc.response)
        return 1
    _print_json(manifest)
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


def _protect_claude_code_plugin_incomplete_response(
    failed_checks: list[dict[str, object]],
) -> dict[str, object]:
    missing_checks = [str(check["name"]) for check in failed_checks]
    return {
        "ok": False,
        "agent": "claude-code",
        "error": "claude_code_plugin_incomplete",
        "condition": "claude_code_plugin_incomplete",
        "message": "Claude Code plugin directory is missing or incomplete.",
        "detail": "Missing Claude Code plugin checks: " + ", ".join(missing_checks),
        "missing_checks": missing_checks,
        "next_steps": [
            {
                "action": "check_plugin",
                "command": "ardur doctor-claude-code --plugin-dir <claude-code-plugin> --home <ardur-home>",
                "detail": "Verify the local Claude Code plugin files before configuring protection.",
            },
            {
                "action": "rerun_protect",
                "command": "ardur protect claude-code --scope <your-project> --home <ardur-home> --plugin-dir <claude-code-plugin>",
                "detail": "After the plugin path is corrected, rerun protection for the project folder.",
            },
        ],
    }


class _ProtectPolicyInputError(ValueError):
    def __init__(self, option: str, condition: str, detail: str) -> None:
        super().__init__(detail)
        self.option = option
        self.condition = condition
        self.detail = detail


def _protect_policy_input_placeholder(option: str) -> str:
    return {
        "--forbid-rules": "<forbid-rules.json>",
        "--cedar-policy": "<policy.cedar>",
        "--cedar-entities": "<cedar-entities.json>",
    }.get(option, "<policy-input-file>")


def _protect_policy_input_next_steps(option: str, condition: str) -> list[dict[str, str]]:
    placeholder = _protect_policy_input_placeholder(option)
    steps: list[dict[str, str]] = []
    if option in {"--forbid-rules", "--cedar-entities"}:
        steps.append({
            "condition": condition,
            "action": "validate_policy_json",
            "command": f"python -m json.tool {placeholder}",
            "detail": "Validate the local policy JSON file before rerunning Claude Code protection.",
        })
    else:
        steps.append({
            "condition": condition,
            "action": "check_policy_file",
            "command": f"test -r {placeholder}",
            "detail": "Confirm the local policy file exists and is readable before rerunning protection.",
        })

    if option == "--forbid-rules":
        rerun_suffix = "--forbid-rules <forbid-rules.json>"
    elif option == "--cedar-entities":
        rerun_suffix = "--cedar-policy <policy.cedar> --cedar-entities <cedar-entities.json>"
    else:
        rerun_suffix = "--cedar-policy <policy.cedar>"
    steps.append({
        "condition": condition,
        "action": "rerun_protect",
        "command": (
            "ardur protect claude-code --scope <your-project> --home <ardur-home> "
            f"--plugin-dir <claude-code-plugin> {rerun_suffix}"
        ),
        "detail": "Rerun protection after the local policy input file is present, readable, and valid.",
    })
    return steps


def _protect_policy_input_failure_response(exc: _ProtectPolicyInputError) -> dict[str, object]:
    return {
        "ok": False,
        "agent": "claude-code",
        "error": "protect_policy_input_invalid",
        "condition": exc.condition,
        "message": "Policy input file could not be loaded.",
        "detail": exc.detail,
        "policy_input": exc.option,
        "next_steps": _protect_policy_input_next_steps(exc.option, exc.condition),
    }


def _read_protect_policy_text(path: Path, option: str) -> str:
    try:
        return path.expanduser().read_text("utf-8")
    except FileNotFoundError as exc:
        raise _ProtectPolicyInputError(
            option,
            "protect_policy_input_missing",
            f"Could not load {option}: the file was not found.",
        ) from exc
    except (PermissionError, IsADirectoryError, OSError, UnicodeDecodeError) as exc:
        raise _ProtectPolicyInputError(
            option,
            "protect_policy_input_unreadable",
            f"Could not load {option}: reading the file failed with {exc.__class__.__name__}.",
        ) from exc


def _read_protect_policy_json(path: Path, option: str) -> object:
    text = _read_protect_policy_text(path, option)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise _ProtectPolicyInputError(
            option,
            "protect_policy_input_malformed",
            f"Could not load {option}: invalid JSON at line {exc.lineno}, column {exc.colno}.",
        ) from exc


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


def _claude_code_doctor_next_steps(
    checks: list[dict[str, object]],
    plugin: Path,
    active_passport: Path,
) -> list[dict[str, str]]:
    by_name = {str(check["name"]): check for check in checks}
    steps: list[dict[str, str]] = []
    plugin_check_names = [
        "plugin_dir",
        "plugin_manifest",
        "plugin_hooks",
        "pre_tool_use",
        "post_tool_use",
        "subagent_start",
        "subagent_stop",
    ]
    missing_plugin_checks = [
        name for name in plugin_check_names if not bool(by_name.get(name, {}).get("ok"))
    ]
    if missing_plugin_checks:
        steps.append(
            {
                "check": "plugin_files",
                "action": "repair_plugin_path",
                "command": shlex.join(["ardur", "doctor-claude-code", "--plugin-dir", str(plugin)]),
                "detail": "Missing Claude Code plugin checks: " + ", ".join(missing_plugin_checks),
            }
        )

    claude_check = by_name.get("claude_binary", {})
    if not bool(claude_check.get("ok")):
        steps.append(
            {
                "check": "claude_binary",
                "action": "install_claude_code",
                "command": "claude --version",
                "detail": "Install Claude Code CLI and ensure `claude` is on PATH, then rerun doctor.",
            }
        )

    active_passport_check = by_name.get("active_passport", {})
    if not bool(active_passport_check.get("ok")):
        steps.append(
            {
                "check": "active_passport",
                "action": "run_protect_claude_code",
                "command": shlex.join(
                    [
                        "ardur",
                        "protect",
                        "claude-code",
                        "--scope",
                        "<your-project>",
                        "--home",
                        str(active_passport.parent),
                        "--plugin-dir",
                        str(plugin),
                    ]
                ),
                "detail": "Create an active Mission Passport for the local Claude Code plugin.",
            }
        )

    plugin_validate_check = by_name.get("plugin_validate", {})
    if (
        not bool(plugin_validate_check.get("ok"))
        and not missing_plugin_checks
        and bool(claude_check.get("ok"))
    ):
        steps.append(
            {
                "check": "plugin_validate",
                "action": "validate_plugin",
                "command": shlex.join(["claude", "plugin", "validate", str(plugin)]),
                "detail": str(
                    plugin_validate_check.get("detail")
                    or "Claude Code plugin validation failed; inspect the validation output."
                ),
            }
        )
    return steps


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
    ok = all(bool(check["ok"]) for check in checks)
    return {
        "ok": ok,
        "checks": checks,
        "next_steps": [] if ok else _claude_code_doctor_next_steps(checks, plugin, active_passport),
    }


def _resolve_protect_policies(
    args: argparse.Namespace,
    profile: ArdurProfile | None,
    home: Path,
) -> list[dict[str, object]]:
    """Build additional_policies from CLI flags + profile."""
    policies: list[dict[str, object]] = []

    # CLI flags (highest priority)
    if getattr(args, "forbid_rules", None) is not None:
        rules = _read_protect_policy_json(Path(args.forbid_rules), "--forbid-rules")
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
        policy_src = _read_protect_policy_text(Path(args.cedar_policy), "--cedar-policy")
        entities: object = []
        if getattr(args, "cedar_entities", None) is not None:
            entities = _read_protect_policy_json(Path(args.cedar_entities), "--cedar-entities")
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


def _protect_claude_code_missing_scope_response(profile_present: bool) -> dict[str, object]:
    profile_detail = (
        "The selected profile does not define `Protect folder:`."
        if profile_present
        else "No `--scope` was provided and no profile with `Protect folder:` was selected."
    )
    return {
        "ok": False,
        "agent": "claude-code",
        "error": "missing_scope",
        "condition": "missing_scope",
        "message": "ardur protect claude-code requires --scope or a profile with `Protect folder:`.",
        "next_steps": [
            {
                "action": "pass_scope",
                "command": "ardur protect claude-code --scope <your-project>",
                "detail": "Choose the local project folder Claude Code is allowed to work in.",
            },
            {
                "action": "create_profile",
                "command": "ardur profile init --template safe-coding --path ARDUR.md",
                "detail": "Create an editable profile that includes a `Protect folder:` line.",
            },
            {
                "action": "use_profile",
                "command": "ardur protect claude-code --profile ARDUR.md",
                "detail": "Run protection from the profile after setting `Protect folder:`.",
            },
        ],
        "detail": profile_detail,
    }


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
        return _protect_claude_code_missing_scope_response(profile_present=bool(args.profile))
    scope = Path(raw_scope).expanduser().resolve()
    home = Path(args.home).expanduser().resolve() if args.home else DEFAULT_HOME
    home.mkdir(parents=True, exist_ok=True)
    plugin_dir = Path(args.plugin_dir).expanduser().resolve()
    failed_plugin_checks = [check for check in _claude_code_plugin_checks(plugin_dir) if not check["ok"]]
    if failed_plugin_checks:
        return _protect_claude_code_plugin_incomplete_response(failed_plugin_checks)
    # Validate policy input files before issuing keys/tokens so setup failures
    # remain local, structured, and free of unnecessary generated artifacts.
    try:
        additional_policies = _resolve_protect_policies(args, profile, home)
    except _ProtectPolicyInputError as exc:
        return _protect_policy_input_failure_response(exc)
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
    ok = bool(result.get("ok"))
    if args.json:
        _print_json(result)
        return 0 if ok else 1
    if not ok:
        print("Ardur Claude Code protection was not configured.")
        message = result.get("message")
        if message:
            print(str(message))
        detail = result.get("detail")
        if detail:
            print(str(detail))
        _print_report_next_steps(result)
        return 1
    print("Ardur Claude Code protection configured.")
    print(f"mode: {result['mode']}")
    print(f"scope: {result['scope']}")
    print(f"active passport: {result['active_passport']}")
    print(f"run: {result['run_command']}")
    return 0


def _profile_init_existing_profile_response() -> dict[str, object]:
    return {
        "ok": False,
        "error": "profile_exists",
        "condition": "profile_exists",
        "message": "ardur profile init will not overwrite an existing profile without --force.",
        "detail": "Use --force only if you want to replace the current profile, or use the existing profile with protect claude-code.",
        "next_steps": [
            {
                "action": "replace_profile",
                "command": "ardur profile init --path ARDUR.md --force",
                "detail": "Replace the local profile only if you intend to overwrite your current guardrails.",
            },
            {
                "action": "use_existing_profile",
                "command": "ardur protect claude-code --profile ARDUR.md",
                "detail": "Use the existing editable profile when configuring Claude Code protection.",
            },
        ],
    }


def _profile_init_path_failure_response(exc: OSError) -> dict[str, object]:
    if isinstance(exc, IsADirectoryError):
        condition = "profile_path_invalid"
        detail = "The supplied --path points to a directory; choose a Markdown file path such as ARDUR.md."
    else:
        condition = "profile_path_unwritable"
        detail = f"Writing the supplied --path failed with {exc.__class__.__name__}."
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": "Profile path is not a writable Markdown file.",
        "detail": detail,
        "next_steps": [
            {
                "action": "choose_profile_file",
                "command": "ardur profile init --path <profile-file> --force",
                "detail": "Use a writable Markdown file path, not a directory or protected location.",
            },
            {
                "action": "use_profile_file",
                "command": "ardur protect claude-code --profile <profile-file>",
                "detail": "Use the created editable profile when configuring Claude Code protection.",
            },
        ],
    }


def cmd_profile_init(args: argparse.Namespace) -> int:
    try:
        path = write_profile_template(args.path, template=args.template, force=args.force)
    except FileExistsError:
        result = _profile_init_existing_profile_response()
        if args.json:
            _print_json(result)
        else:
            print("Ardur profile was not created.")
            print(str(result["message"]))
            print(str(result["detail"]))
            _print_report_next_steps(result)
        return 1
    except (IsADirectoryError, PermissionError, OSError) as exc:
        result = _profile_init_path_failure_response(exc)
        if args.json:
            _print_json(result)
        else:
            print("Ardur profile was not created.")
            print(str(result["message"]))
            print(str(result["detail"]))
            _print_report_next_steps(result)
        return 1
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
    start.add_argument("--api-token", help="Bearer token for clients; VIBAP_API_TOKEN still takes precedence")
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
    uninstall.add_argument(
        "--dry-run",
        action="store_true",
        help="preview uninstall removals without deleting launch files or local data",
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
    personal_native_manifest.add_argument("--host-path", required=True)
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
