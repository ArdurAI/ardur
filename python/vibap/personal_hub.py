"""Local Ardur Personal Hub for browser, desktop, and CLI adapters.

The Hub is the authority boundary for Ardur Personal. Adapters should send
observations here instead of creating independent policy decisions or receipt
formats. The Hub maps those observations into the existing GovernanceProxy so
standard Ardur Execution Receipts are issued by the same runtime code path as
framework and CLI integrations.
"""

from __future__ import annotations

import argparse
from contextlib import suppress
import hashlib
import html
import json
import logging
import os
import plistlib
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from http import client as httpclient
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from cryptography.hazmat.primitives import serialization

from . import __version__
from .passport import (
    DEFAULT_HOME,
    MissionPassport,
    _ensure_default_home_dir,
    _is_under_default_home,
    generate_keypair,
    issue_passport,
)
from .proxy import Decision, GovernanceProxy
from .metrics import metrics as ardur_metrics
from .rate_limiter import RateLimiter
from .tls import create_ssl_context, resolve_tls_paths

HUB_SCHEMA_VERSION = "ardur.personal.hub.v0.1"
EVENT_SCHEMA_VERSION = "ardur.personal.event.v0.1"
SESSION_REVIEW_SCHEMA_VERSION = "ardur.personal.session_review.v0.1"
DEFAULT_HUB_HOST = "127.0.0.1"
DEFAULT_HUB_PORT = 8765

logger = logging.getLogger(__name__)
DEFAULT_HUB_HOME = Path(
    os.environ.get("ARDUR_PERSONAL_HOME", DEFAULT_HOME / "personal")
).expanduser()
DEFAULT_HUB_URL = os.environ.get(
    "ARDUR_PERSONAL_HUB_URL",
    f"http://{DEFAULT_HUB_HOST}:{DEFAULT_HUB_PORT}",
)
MAX_BODY_BYTES = 1024 * 1024
MAX_EXCERPT_CHARS = 1800
MAX_ACTIONS_PER_REVIEW = 160
MAX_OBSERVATIONS_PER_REVIEW = 240
HUB_TOKEN_ENV_VAR = "ARDUR_PERSONAL_HUB_TOKEN"
HUB_TOKEN_HEADER = "X-Ardur-Hub-Token"
_HUB_TOKEN_COMPARE_MAX_BYTES = 4096
_ALLOWED_HUB_URL_SCHEMES = {"http", "https"}
PERSONAL_HOME_NOT_DIRECTORY_CONDITION = "personal_home_not_directory"
HOME_DANGLING_SYMLINK_PARENT_CONDITION = "home_dangling_symlink_parent"
HOME_PARENT_NOT_DIRECTORY_CONDITION = "home_parent_not_directory"
SETUP_HOME_INVALID_CONDITION = "setup_home_invalid"
SETUP_HOST_INVALID_CONDITION = "setup_host_invalid"
SETUP_PORT_INVALID_CONDITION = "setup_port_invalid"
HUB_TLS_MATERIAL_INVALID_CONDITION = "hub_tls_material_invalid"
_QUERY_TOKEN_LOG_RE = re.compile(
    r"([?&](?:access[-_]?token|api[-_]?key|auth|key|password|secret|token)=)[^\s&\"']+",
    re.I,
)
_SHA256_DIGEST_RE = re.compile(r"^sha-256:[0-9a-f]{64}$")
_SENSITIVE_TARGET_RE = re.compile(
    r"(?<![A-Za-z0-9])(password|secret|token|api[-_ ]?key|ssn)(?![A-Za-z0-9])",
    re.I,
)
_DANGEROUS_CLI_RE = re.compile(
    r"(^|\s)(sudo|su|rm\s+(?=[^\n]*(?:-[^\n]*[rf]|--recursive\b|--force\b))[^\n]*|"
    r"mkfs|diskutil|dd\s+if=\S*|security\s+find|"
    r"launchctl\s+bootout|curl\s+[^|\n]*\|\s*(sh|bash)|wget\s+[^|\n]*\|\s*(sh|bash))"
    r"(?=$|\s|[;&|])",
    re.I,
)


class HubError(ValueError):
    def __init__(
        self, message: str, *, status: int = 400, code: str = "bad_request"
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class HubTLSConfigurationError(HubError):
    """TLS was required but no usable Hub server context could be constructed."""

    def __init__(self) -> None:
        super().__init__(
            "Ardur Personal Hub TLS configuration is unavailable.",
            status=400,
            code=HUB_TLS_MATERIAL_INVALID_CONDITION,
        )


@dataclass(frozen=True)
class HubPaths:
    home: Path
    state_dir: Path
    keys_dir: Path
    governance_log: Path
    receipts_log: Path
    sessions_index: Path
    reviews: Path
    config: Path

    @classmethod
    def from_home(cls, home: str | Path | None = None) -> "HubPaths":
        root = _resolve_personal_home(home)
        return cls(
            home=root,
            state_dir=root / "state",
            keys_dir=root / "keys",
            governance_log=root / "governance_log.jsonl",
            receipts_log=root / "receipts.jsonl",
            sessions_index=root / "sessions_index.json",
            reviews=root / "session_reviews.json",
            config=root / "config.json",
        )


def _is_empty_home_value(home: str | Path | None) -> bool:
    """True when a CLI ``--home`` value is an empty or whitespace-only string.

    ``--home`` uses ``type=str`` so the raw string reaches this helper before
    any ``Path()`` normalisation. A literal empty string ``""`` normalises to
    ``Path(".")`` (the current working directory) and a whitespace-only string
    such as ``"   "`` becomes a literal whitespace-named directory; both must
    be rejected before key/config/plist creation.

    ``None`` (flag omitted) and existing ``Path`` callers (internal, already
    validated) intentionally pass through. An explicit ``--home .`` is a valid
    directory choice and is preserved.
    """

    if home is None:
        return False
    if isinstance(home, Path):
        return False
    return not str(home).strip()


def _resolve_personal_home(home: str | Path | None) -> Path:
    if _is_empty_home_value(home):
        raise HubError(
            "Ardur Personal home must be a non-empty path after trimming whitespace.",
            status=400,
            code=SETUP_HOME_INVALID_CONDITION,
        )
    return Path(home).expanduser() if home is not None else DEFAULT_HUB_HOME


def _personal_home_not_directory_error() -> HubError:
    return HubError(
        "Ardur Personal home exists but is not a directory.",
        status=400,
        code=PERSONAL_HOME_NOT_DIRECTORY_CONDITION,
    )


def validate_personal_home_directory(paths: HubPaths) -> None:
    """Fail closed when the configured Personal home is an existing non-directory."""

    if (paths.home.exists() or paths.home.is_symlink()) and not paths.home.is_dir():
        raise _personal_home_not_directory_error()


def _home_dangling_symlink_parent_error() -> HubError:
    return HubError(
        "Ardur home path has a parent component that is a dangling symlink.",
        status=400,
        code=HOME_DANGLING_SYMLINK_PARENT_CONDITION,
    )


def _home_parent_not_directory_error() -> HubError:
    return HubError(
        "Ardur home path has a parent component that is an existing non-directory.",
        status=400,
        code=HOME_PARENT_NOT_DIRECTORY_CONDITION,
    )


def validate_personal_home_path_components(home: str | Path) -> None:
    """Reject a Personal ``--home`` path whose parent chain crosses a dangling
    symlink or an existing non-directory, BEFORE any ``Path.resolve()`` /
    ``mkdir(parents=True)`` follows the link or materialises the target.

    Why this exists
    ---------------
    Three Ardur commands (``run``, ``setup``, ``protect claude-code``) accept
    ``--home <dangling-symlink>/child``. The previous leaf-only validation
    inspected just the final path component:

    * ``Path(dangling/child).is_symlink()`` returns False (``child`` is the
      leaf, not the symlink).
    * ``Path(dangling/child).resolve()`` follows the symlink and returns the
      missing-target path ``/missing/child``.
    * ``missing.exists()`` returns False, so the resolved-path guard also
      short-circuits.
    * ``home.mkdir(parents=True, exist_ok=True)`` then silently materialises
      the missing target and Ardur writes the Ed25519 private key,
      ``active_mission.jwt``, state, and the governance log there.

    The fix mirrors the 2026-06-28 ``ardur start --state-dir``/``--log-path``
    precedent: walk each *parent* component of the **un-resolved** expanded
    path and reject when any parent is a dangling symlink or an existing
    non-directory. Operating on the un-resolved path is essential because
    ``.resolve()`` collapses the symlink chain before the check can see it.

    What is rejected
    ----------------
    * Any parent component that is a dangling symlink
      (``parent.is_symlink() and not parent.exists()``).
    * Any parent component that exists and is not a directory
      (regular file, socket, block device, etc.).

    What is preserved
    -----------------
    * A direct dangling symlink leaf (``home`` itself) is rejected by the
      existing ``validate_personal_home_directory`` /
      ``protect_claude_code`` leaf checks; this helper deliberately does not
      duplicate that so callers keep firing their own leaf-specific
      structured responses.
    * A symlink whose target is an existing directory proceeds normally —
      ``is_symlink() and not exists()`` is False, and the resolved path is a
      real directory.
    * A plain nonexistent non-symlink path proceeds normally — Ardur creates
      it later with ``mkdir(parents=True, exist_ok=True)``.

    Parameters
    ----------
    home:
        The raw ``--home`` value as supplied by the caller. It is
        ``expanduser()``-ed internally. Empty/whitespace values must already
        have been rejected by ``_resolve_personal_home`` so this helper
        intentionally does not re-check them.

    Raises
    ------
    HubError(HOME_DANGLING_SYMLINK_PARENT_CONDITION)
        If any parent component is a dangling symlink.
    HubError(HOME_PARENT_NOT_DIRECTORY_CONDITION)
        If any parent component exists and is not a directory.
    """

    expanded = Path(home).expanduser()
    # Walk parent components from the immediate parent up to the filesystem
    # root. ``Path.parents`` yields absolute ancestors for an absolute input
    # and CWD-relative ancestors for a relative input; both are correct here
    # because ``mkdir(parents=True)`` operates on the same chain.
    for parent in expanded.parents:
        is_symlink = parent.is_symlink()
        exists = parent.exists()
        if is_symlink and not exists:
            raise _home_dangling_symlink_parent_error()
        if exists and not parent.is_dir():
            raise _home_parent_not_directory_error()


def _ensure_personal_home_directory(paths: HubPaths) -> None:
    validate_personal_home_directory(paths)
    # Reject parent-component dangling symlinks or non-directory parents BEFORE
    # mkdir(parents=True) follows the symlink chain and materialises the missing
    # target. ``paths.home`` is already the expanded path from HubPaths.from_home
    # but it is un-resolved, which is exactly what the parent walk needs: walking
    # parents of the resolved path would already have collapsed the symlink.
    validate_personal_home_path_components(paths.home)
    # When the personal home is under DEFAULT_HOME, materialise the home
    # with 0o700 first so the mkdir(parents=True) doesn't create it with
    # the process umask.
    if _is_under_default_home(paths.home):
        _ensure_default_home_dir()
    try:
        paths.home.mkdir(parents=True, exist_ok=True)
    except FileExistsError as exc:
        if (paths.home.exists() or paths.home.is_symlink()) and not paths.home.is_dir():
            raise _personal_home_not_directory_error() from exc
        raise


def personal_home_failure_next_steps() -> list[dict[str, str]]:
    condition = PERSONAL_HOME_NOT_DIRECTORY_CONDITION
    return [
        {
            "condition": condition,
            "action": "choose_personal_home_directory",
            "command": "ardur setup --home <ardur-home>",
            "detail": (
                "Choose a directory path for the local Ardur Personal home. If the "
                "selected path is an existing file, move it aside or pick a different "
                "directory before setup."
            ),
        },
        {
            "condition": condition,
            "action": "start_personal_hub_after_setup",
            "command": "ardur hub --home <ardur-home>",
            "detail": (
                "Start the loopback Hub only after the Personal home path is a directory. "
                "Keep raw local paths, Hub tokens, and receipt locations out of shared logs."
            ),
        },
        {
            "condition": condition,
            "action": "rerun_doctor",
            "command": "ardur doctor --home <ardur-home>",
            "detail": (
                "Re-run local setup diagnostics after choosing a valid home directory. "
                "This guidance is local/no-key recovery only."
            ),
        },
    ]


def personal_home_failure_response() -> dict[str, Any]:
    condition = PERSONAL_HOME_NOT_DIRECTORY_CONDITION
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Ardur Personal home must be a directory.",
        "detail": (
            "The selected Ardur Personal home path already exists as a file or other "
            "non-directory. Choose a directory path before running setup or starting the Hub."
        ),
        "next_steps": personal_home_failure_next_steps(),
    }


def home_dangling_symlink_parent_next_steps() -> list[dict[str, str]]:
    condition = HOME_DANGLING_SYMLINK_PARENT_CONDITION
    return [
        {
            "condition": condition,
            "action": "remove_or_fix_dangling_symlink_parent",
            "command": "ardur setup --home <ardur-home>",
            "detail": (
                "A parent directory in the supplied --home path is a dangling "
                "symlink (a symlink whose target does not exist). Ardur resolves "
                "the symlink chain and would silently write signing keys, "
                "active_mission.jwt, state, and governance logs at the resolved "
                "target rather than the path you typed. Remove the dangling "
                "symlink or point it at a real directory before retrying."
            ),
        },
        {
            "condition": condition,
            "action": "start_personal_hub_after_setup",
            "command": "ardur hub --home <ardur-home>",
            "detail": (
                "After choosing a valid Ardur Personal home directory whose parent "
                "chain contains no dangling symlinks, start the loopback Hub. "
                "Keep raw local paths and Hub tokens out of shared logs."
            ),
        },
    ]


def home_dangling_symlink_parent_failure_response() -> dict[str, Any]:
    condition = HOME_DANGLING_SYMLINK_PARENT_CONDITION
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": (
            "Ardur home path has a parent component that is a dangling symlink."
        ),
        "detail": (
            "The supplied --home path passes through a dangling symlink in one of "
            "its parent directories. Without this check Ardur follows the symlink, "
            "materialises the missing target, and writes the Ed25519 private key, "
            "active_mission.jwt, state, and governance log at a location you did "
            "not type. Remove the dangling symlink or repoint it at a real "
            "directory before retrying."
        ),
        "next_steps": home_dangling_symlink_parent_next_steps(),
    }


def home_parent_not_directory_next_steps() -> list[dict[str, str]]:
    condition = HOME_PARENT_NOT_DIRECTORY_CONDITION
    return [
        {
            "condition": condition,
            "action": "move_aside_or_choose_directory_parent",
            "command": "ardur setup --home <ardur-home>",
            "detail": (
                "A parent directory in the supplied --home path exists as a "
                "regular file or other non-directory. Ardur cannot create the "
                "home tree inside a file. Move the file aside or choose a "
                "different parent directory before retrying."
            ),
        },
        {
            "condition": condition,
            "action": "start_personal_hub_after_setup",
            "command": "ardur hub --home <ardur-home>",
            "detail": (
                "After choosing a valid Ardur Personal home directory whose parent "
                "chain contains no regular files, start the loopback Hub. "
                "Keep raw local paths and Hub tokens out of shared logs."
            ),
        },
    ]


def home_parent_not_directory_failure_response() -> dict[str, Any]:
    condition = HOME_PARENT_NOT_DIRECTORY_CONDITION
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": (
            "Ardur home path has a parent component that is an existing "
            "non-directory."
        ),
        "detail": (
            "A parent directory in the supplied --home path already exists as a "
            "regular file or other non-directory. Ardur cannot create the home "
            "tree (keys, active_mission.jwt, state, governance log) inside a file. "
            "Move the file aside or choose a different parent directory before "
            "retrying."
        ),
        "next_steps": home_parent_not_directory_next_steps(),
    }


def setup_home_invalid_next_steps() -> list[dict[str, str]]:
    condition = SETUP_HOME_INVALID_CONDITION
    return [
        {
            "condition": condition,
            "action": "choose_personal_home_directory",
            "command": "ardur setup --home <ardur-home>",
            "detail": (
                "Choose a non-empty directory path for the local Ardur Personal home. "
                "Empty strings, whitespace-only values, and unquoted empty environment "
                "variables resolve to the current working directory and are rejected."
            ),
        },
        {
            "condition": condition,
            "action": "start_personal_hub_after_setup",
            "command": "ardur hub --home <ardur-home>",
            "detail": (
                "After choosing a valid Ardur Personal home directory, start the loopback "
                "Hub. Keep raw local paths and Hub tokens out of shared logs."
            ),
        },
        {
            "condition": condition,
            "action": "rerun_doctor",
            "command": "ardur doctor --home <ardur-home>",
            "detail": (
                "Re-run local setup diagnostics after supplying a non-empty home path. "
                "This guidance is local/no-key recovery only."
            ),
        },
    ]


def setup_home_invalid_failure_response() -> dict[str, Any]:
    condition = SETUP_HOME_INVALID_CONDITION
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Ardur Personal home must be a non-empty path after trimming whitespace.",
        "detail": (
            "The supplied --home value is empty or whitespace-only. Pass a real directory "
            "path (for example an absolute path or an explicit '.' for the current directory) "
            "before running setup or Personal Hub commands."
        ),
        "next_steps": setup_home_invalid_next_steps(),
    }


def setup_port_failure_next_steps() -> list[dict[str, str]]:
    condition = SETUP_PORT_INVALID_CONDITION
    return [
        {
            "condition": condition,
            "action": "choose_valid_setup_port",
            "command": "ardur setup --home <ardur-home> --host <loopback-host> --port <setup-port>",
            "detail": (
                "Use an integer TCP port from 1 through 65535 for setup. "
                "Do not include signs, whitespace, or non-numeric text."
            ),
        },
        {
            "condition": condition,
            "action": "retry_with_default_loopback_setup",
            "command": "ardur setup --home <ardur-home> --host 127.0.0.1 --port <setup-port>",
            "detail": (
                "Choose a stable loopback Hub port before generating local config, "
                "tokens, or launch-agent files."
            ),
        },
    ]


def setup_port_failure_response() -> dict[str, Any]:
    condition = SETUP_PORT_INVALID_CONDITION
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Ardur setup port must be a stable TCP port.",
        "detail": "Choose an integer port from 1 through 65535 before running setup.",
        "next_steps": setup_port_failure_next_steps(),
    }


def setup_host_failure_next_steps() -> list[dict[str, str]]:
    condition = SETUP_HOST_INVALID_CONDITION
    return [
        {
            "condition": condition,
            "action": "choose_valid_setup_host",
            "command": "ardur setup --home <ardur-home> --host <loopback-host> --port <setup-port>",
            "detail": (
                "Pass only a bindable host name or IP address. Do not include URL "
                "schemes, ports, paths, credentials, empty values, or surrounding whitespace."
            ),
        },
        {
            "condition": condition,
            "action": "retry_with_loopback_host",
            "command": "ardur setup --home <ardur-home> --host 127.0.0.1 --port <setup-port>",
            "detail": (
                "Use a loopback host for local setup, then run doctor with placeholder-only "
                "diagnostics if setup still fails."
            ),
        },
    ]


def setup_host_failure_response() -> dict[str, Any]:
    condition = SETUP_HOST_INVALID_CONDITION
    return {
        "ok": False,
        "error": condition,
        "error_code": condition,
        "condition": condition,
        "message": "Ardur setup host must be a bindable host name or IP address.",
        "detail": (
            "Choose a host value that can be bound locally before setup. Use --port "
            "for the port; do not include a URL scheme, path, or empty host."
        ),
        "next_steps": setup_host_failure_next_steps(),
    }


def _validated_setup_port(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        port = value
    elif isinstance(value, str):
        stripped = value.strip()
        if not stripped or stripped != value or not re.fullmatch(r"[0-9]+", stripped):
            return None
        port = int(stripped)
    else:
        return None
    if 1 <= port <= 65535:
        return port
    return None


def _setup_host_has_url_shape(host: str) -> bool:
    try:
        parsed = urlparse.urlsplit(host)
    except ValueError:
        return True
    return bool(
        "://" in host
        or host.startswith("//")
        or "/" in host
        or "?" in host
        or "#" in host
        or (parsed.scheme and not host.startswith("["))
        or parsed.netloc
    )


def _setup_host_is_bindable(host: str) -> bool:
    import socket

    try:
        candidates = socket.getaddrinfo(host, 0, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return False
    for family, socktype, proto, _canonname, sockaddr in candidates:
        try:
            with socket.socket(family, socktype, proto) as sock:
                sock.bind(sockaddr)
            return True
        except OSError:
            continue
    return False


def _validated_setup_host(value: Any) -> str | None:
    host_value = str(value)
    stripped = host_value.strip()
    if (
        not stripped
        or stripped != host_value
        or _setup_host_has_url_shape(stripped)
        or not _setup_host_is_bindable(stripped)
    ):
        return None
    return stripped


def _setup_hub_url(host: str, port: int) -> str:
    url_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"http://{url_host}:{port}"


def _is_personal_home_not_directory_error(exc: HubError) -> bool:
    return exc.code == PERSONAL_HOME_NOT_DIRECTORY_CONDITION


def _is_setup_home_invalid_error(exc: HubError) -> bool:
    return exc.code == SETUP_HOME_INVALID_CONDITION


def _personal_home_failure_response_for(exc: HubError) -> dict[str, Any] | None:
    """Map a Personal-home ``HubError`` to its structured response, or None.

    Used by command handlers that already catch ``HubError`` so they can
    uniformly surface the right structured failure for either an empty/whitespace
    home value or an existing non-directory home path.
    """

    if _is_setup_home_invalid_error(exc):
        return setup_home_invalid_failure_response()
    if _is_personal_home_not_directory_error(exc):
        return personal_home_failure_response()
    return None


def _print_json_response(payload: dict[str, Any]) -> None:
    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")


def _emit_json_error_to_stderr(payload: dict[str, Any]) -> None:
    """Emit a structured JSON error to stderr.

    The legacy ``run_under_hub`` path previously emitted human-readable
    summary lines to stderr, which violated the ``--json`` contract
    (stdout = child output, stderr = governance JSON).  This helper
    writes the same error/condition/next_steps structure that the
    governance path uses, but to stderr so JSON consumers can parse
    it without polluting the child's stdout.
    """
    json.dump(payload, sys.stderr, indent=2)
    sys.stderr.write("\n")


_RUN_SUPPORT_CONDITIONS = {
    "hub_auth_required",
    "hub_token_missing",
    "hub_unavailable",
    "hub_url_invalid",
    "unauthorized",
}
_RUN_TOKEN_CONDITIONS = {
    "hub_auth_required",
    "hub_token_missing",
    "unauthorized",
}
_RUN_FAILURE_SUMMARY_LINES = {
    (
        "session_start",
        "hub_token_required",
    ): "Ardur Hub unavailable: hub_token_required",
    ("session_start", "hub_unavailable"): "Ardur Hub unavailable: hub_unavailable",
    ("session_start", "hub_url_invalid"): "Ardur Hub unavailable: hub_url_invalid",
    (
        "session_start",
        "run_session_start_failed",
    ): "Ardur Hub unavailable: run_session_start_failed",
    (
        "policy_check",
        "hub_token_required",
    ): "Ardur policy check failed: hub_token_required",
    ("policy_check", "hub_unavailable"): "Ardur policy check failed: hub_unavailable",
    ("policy_check", "hub_url_invalid"): "Ardur policy check failed: hub_url_invalid",
    (
        "policy_check",
        "run_policy_check_failed",
    ): "Ardur policy check failed: run_policy_check_failed",
}
_RECEIPT_REFERENCE_RE = re.compile(r"^receipt:[0-9a-f]{32}$")


def _normalized_run_support_condition(value: Any) -> str:
    condition = re.sub(
        r"[^a-z0-9_]+",
        "_",
        str(value or "").strip().lower(),
    ).strip("_")
    if condition in _RUN_TOKEN_CONDITIONS:
        return "hub_token_required"
    if condition in _RUN_SUPPORT_CONDITIONS:
        return condition
    return ""


def _run_failure_support_condition(response: dict[str, Any], *, phase: str) -> str:
    """Return a support-safe condition without echoing raw Hub error text."""

    for key in ("condition", "error_code"):
        condition = _normalized_run_support_condition(response.get(key))
        if condition:
            return condition
    hub_unavailable, token_problem = _hub_setup_failure_flags(response)
    if token_problem:
        return "hub_token_required"
    if hub_unavailable:
        return "hub_unavailable"
    return f"run_{phase}_failed"


def _run_failure_summary_line(response: dict[str, Any], *, phase: str) -> str:
    condition = _run_failure_support_condition(response, phase=phase)
    fallback = f"run_{phase}_failed"
    return _RUN_FAILURE_SUMMARY_LINES.get(
        (phase, condition),
        _RUN_FAILURE_SUMMARY_LINES.get(
            (phase, fallback), "Ardur run failed: run_failed"
        ),
    )


def _blocked_command_summary_line(_policy: dict[str, Any]) -> str:
    """Return a support-safe blocked-command line without echoing policy reasons."""

    return "Ardur blocked command: policy_blocked"


def _run_audit_reference_for_user_output(response: dict[str, Any]) -> str:
    reference = str(_dict(response.get("receipt")).get("receipt_id") or "").strip()
    if not reference:
        return ""
    if _RECEIPT_REFERENCE_RE.fullmatch(reference) and not _SENSITIVE_TARGET_RE.search(
        reference
    ):
        return reference
    return "<receipt>"


def _emit_run_audit_reference_for_user_output(response: dict[str, Any]) -> None:
    """Emit the support-safe receipt reference as a local command response.

    The reference is already reduced to either ``receipt:<32 lowercase hex>`` or
    the ``<receipt>`` placeholder. Keep this away from ``print`` so hosted
    CodeQL does not model the already-sanitized support artifact as clear-text
    sensitive logging.
    """

    audit_reference = _run_audit_reference_for_user_output(response)
    if not audit_reference:
        return
    sys.stderr.flush()
    os.write(
        sys.stderr.fileno(), b"receipt: " + audit_reference.encode("ascii") + b"\n"
    )


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_text(value: str) -> str:
    return "sha-256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class StreamedProcessResult:
    returncode: int
    stdout_digest: str
    stderr_digest: str
    stdout_bytes: int
    stderr_bytes: int


def _stream_subprocess(command: list[str]) -> StreamedProcessResult:
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout_hash = hashlib.sha256()
    stderr_hash = hashlib.sha256()
    counts = {"stdout": 0, "stderr": 0}
    errors: list[Exception] = []

    def pump(stream, target, hasher, key: str) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                hasher.update(chunk)
                counts[key] += len(chunk)
                target.write(chunk)
                target.flush()
        except (
            Exception
        ) as exc:  # pragma: no cover - stdout/stderr pipe failures are host-specific
            errors.append(exc)
        finally:
            with suppress(OSError):
                stream.close()

    assert process.stdout is not None
    assert process.stderr is not None
    stdout_thread = threading.Thread(
        target=pump,
        args=(process.stdout, sys.stdout.buffer, stdout_hash, "stdout"),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=pump,
        args=(process.stderr, sys.stderr.buffer, stderr_hash, "stderr"),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    returncode = process.wait()
    stdout_thread.join()
    stderr_thread.join()
    if errors:
        raise errors[0]
    return StreamedProcessResult(
        returncode=returncode,
        stdout_digest="sha-256:" + stdout_hash.hexdigest(),
        stderr_digest="sha-256:" + stderr_hash.hexdigest(),
        stdout_bytes=counts["stdout"],
        stderr_bytes=counts["stderr"],
    )


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except json.JSONDecodeError as exc:
        raise HubError(
            f"{path.name} is not valid JSON", status=500, code="state_corrupt"
        ) from exc


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    replaced = False
    try:
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(path)
        replaced = True
        path.chmod(0o600)
    finally:
        if fd >= 0:
            os.close(fd)
        if not replaced:
            with suppress(FileNotFoundError):
                tmp.unlink()


def _new_hub_token() -> str:
    return secrets.token_urlsafe(32)


def _hub_token_compare_material(token: str) -> bytes | None:
    """Return fixed-length Personal Hub token material for comparison.

    ``secrets.compare_digest`` leaks operand length before comparing content.
    Prefixing the UTF-8 byte length and padding the body makes presented and
    expected Hub tokens the same width before the constant-time comparison.
    """
    token_bytes = token.encode("utf-8")
    if len(token_bytes) > _HUB_TOKEN_COMPARE_MAX_BYTES:
        return None
    return len(token_bytes).to_bytes(4, "big") + token_bytes.ljust(
        _HUB_TOKEN_COMPARE_MAX_BYTES,
        b"\0",
    )


def _hub_tokens_match(supplied: str, expected: str) -> bool:
    if not supplied or not expected:
        return False
    supplied_material = _hub_token_compare_material(supplied)
    expected_material = _hub_token_compare_material(expected)
    if supplied_material is None or expected_material is None:
        return False
    return secrets.compare_digest(supplied_material, expected_material)


def _redact_url_tokens(message: str) -> str:
    return _QUERY_TOKEN_LOG_RE.sub(r"\1<redacted>", message)


def _redact_url_for_user_output(value: str) -> str:
    """Return a user-facing URL with query tokens and credentials redacted."""
    redacted = _redact_url_tokens(value)
    try:
        parsed = urlparse.urlsplit(redacted)
    except ValueError:
        return "<hub-url>"
    if "@" not in parsed.netloc:
        return redacted
    netloc = parsed.netloc.rsplit("@", 1)[1]
    if not netloc:
        return "<hub-url>"
    return urlparse.urlunsplit(parsed._replace(netloc=netloc))


def _load_hub_config(paths: HubPaths) -> dict[str, Any]:
    validate_personal_home_directory(paths)
    return _dict(_read_json(paths.config, {}))


def _ensure_hub_config(
    paths: HubPaths,
    *,
    hub_url: str | None = None,
    browser_extension_path: str | None = None,
    rotate_token: bool = False,
) -> dict[str, Any]:
    config = _load_hub_config(paths)
    if config.get("schema_version") != "ardur.personal.config.v0.1":
        config["schema_version"] = "ardur.personal.config.v0.1"
    if hub_url:
        config["hub_url"] = hub_url
    else:
        config.setdefault("hub_url", DEFAULT_HUB_URL)
    config["home"] = str(paths.home)
    if browser_extension_path is not None:
        config["browser_extension_path"] = browser_extension_path
    if (
        rotate_token
        or not isinstance(config.get("hub_token"), str)
        or not config["hub_token"]
    ):
        config["hub_token"] = _new_hub_token()
    config.setdefault("created_at", _utc_now())
    config["updated_at"] = _utc_now()
    _write_json(paths.config, config)
    with suppress(OSError):
        paths.config.chmod(0o600)
    return config


def resolve_hub_token(
    *,
    home: str | Path | None = None,
    explicit: str | None = None,
) -> str | None:
    paths = HubPaths.from_home(home)
    validate_personal_home_directory(paths)
    if explicit:
        return explicit
    env_token = os.environ.get(HUB_TOKEN_ENV_VAR, "").strip()
    if env_token:
        return env_token
    try:
        token = _load_hub_config(paths).get("hub_token")
    except HubError as exc:
        if _is_personal_home_not_directory_error(exc) or _is_setup_home_invalid_error(
            exc
        ):
            raise
        return None
    return str(token) if token else None


def resolve_hub_url(
    *,
    home: str | Path | None = None,
    explicit: str | None = None,
) -> str:
    """Resolve the Hub base URL mirroring :func:`resolve_hub_token`.

    Resolution order: explicit override → ``ARDUR_PERSONAL_HUB_URL`` env var →
    ``hub_url`` recorded in the Personal home config → :data:`DEFAULT_HUB_URL`.

    ``hub_request`` uses this when a caller passes the unchanged CLI default
    (plain HTTP) so that a Hub which serves TLS is still reached once
    ``ardur hub`` has recorded its real HTTPS URL in config. An explicit
    override that differs from the default is always honoured as-is.
    """

    paths = HubPaths.from_home(home)
    validate_personal_home_directory(paths)
    if explicit:
        return explicit
    env_url = os.environ.get("ARDUR_PERSONAL_HUB_URL", "").strip()
    if env_url:
        return env_url
    try:
        config_url = _load_hub_config(paths).get("hub_url")
    except HubError as exc:
        if _is_personal_home_not_directory_error(exc) or _is_setup_home_invalid_error(
            exc
        ):
            raise
        config_url = None
    if config_url:
        return str(config_url)
    return DEFAULT_HUB_URL


def _clip(value: Any, limit: int = MAX_EXCERPT_CHARS) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def _dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _public_key_pem(public_key: Any) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


class PersonalHub:
    """Local in-process Hub used by the HTTP server and CLI helpers."""

    def __init__(
        self, home: str | Path | None = None, *, hub_url: str | None = None
    ) -> None:
        self.paths = HubPaths.from_home(home)
        _ensure_personal_home_directory(self.paths)
        self.config = _ensure_hub_config(self.paths, hub_url=hub_url)
        self.hub_url = str(self.config.get("hub_url") or hub_url or DEFAULT_HUB_URL)
        self.hub_token = str(self.config["hub_token"])
        private_key, public_key = generate_keypair(keys_dir=self.paths.keys_dir)
        self.private_key = private_key
        self.public_key = public_key
        self.proxy = GovernanceProxy(
            log_path=self.paths.governance_log,
            receipts_log_path=self.paths.receipts_log,
            state_dir=self.paths.state_dir,
            keys_dir=self.paths.keys_dir,
            private_key=private_key,
            public_key=public_key,
        )
        self.verifier_id = self.proxy.verifier_id

    def status(self) -> dict[str, Any]:
        sessions = _read_json(self.paths.sessions_index, {})
        reviews = _read_json(self.paths.reviews, [])
        latest_receipt = self._latest_receipt()
        return {
            "ok": True,
            "schema_version": HUB_SCHEMA_VERSION,
            "version": __version__,
            "home": str(self.paths.home),
            "verifier_id": self.verifier_id,
            "hub_url": self.hub_url,
            "sessions": len(sessions),
            "session_reviews": len(reviews),
            "latest_receipt": latest_receipt,
            "public_key_pem": _public_key_pem(self.public_key),
            "adapters": {
                "browser": "available",
                "desktop": "available_with_macos_permissions",
                "cli": "available",
            },
        }

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "schema_version": HUB_SCHEMA_VERSION,
            "version": __version__,
        }

    def start_session(self, payload: dict[str, Any]) -> dict[str, Any]:
        source = _dict(payload.get("source"))
        session_payload = _dict(payload.get("session"))
        session_key = self._session_key(payload)
        index = _read_json(self.paths.sessions_index, {})
        if session_key in index:
            return {"ok": True, **index[session_key], "existing": True}

        mission_payload = _dict(payload.get("mission"))
        requested_resource_scope = mission_payload.get("resource_scope")
        mission = MissionPassport(
            agent_id=str(mission_payload.get("agent_id") or self._agent_id(source)),
            mission=str(
                mission_payload.get("mission")
                or "Observe and enforce local AI assistant activity through Ardur Personal Hub."
            ),
            allowed_tools=list(
                mission_payload.get("allowed_tools")
                or ["browser_observe", "desktop_observe", "cli_command", "cli_observe"]
            ),
            forbidden_tools=list(mission_payload.get("forbidden_tools") or []),
            resource_scope=(
                ["**"]
                if requested_resource_scope is None
                else list(requested_resource_scope)
            ),
            max_tool_calls=int(mission_payload.get("max_tool_calls") or 5000),
            max_duration_s=int(mission_payload.get("max_duration_s") or 86400),
            allowed_side_effect_classes=list(
                mission_payload.get("allowed_side_effect_classes")
                or ["none", "internal_write", "external_send", "state_change"]
            ),
        )
        token = issue_passport(mission, self.private_key, ttl_s=mission.max_duration_s)
        session = self.proxy.start_session(token)
        record = {
            "session_key": session_key,
            "ardur_session_id": session.jti,
            "agent_id": mission.agent_id,
            "mission": mission.mission,
            "source": source,
            "title": _clip(session_payload.get("title"), 160),
            "started_at": _utc_now(),
            "token": token,
        }
        index[session_key] = record
        _write_json(self.paths.sessions_index, index)
        return {"ok": True, **record, "existing": False}

    def observe(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._validate_event_payload(payload)
        session_record = self.start_session(payload)
        source = _dict(payload.get("source"))
        policy = self.check_policy(payload)
        tool_name = self._tool_name(source, policy)
        arguments = self._arguments(payload, policy)
        session_id = str(session_record["ardur_session_id"])
        decision, reason = self.proxy.evaluate_tool_call(
            session_id, tool_name, arguments
        )
        receipt = self._latest_receipt(session_id)
        review = self._update_session_review(
            payload=payload,
            session_record=session_record,
            receipt=receipt,
            policy=policy,
            decision=decision,
            reason=reason,
        )
        return {
            "ok": True,
            "schema_version": "ardur.personal.hub_observation.v0.1",
            "session_id": session_record["session_key"],
            "ardur_session_id": session_id,
            "policy": policy,
            "decision": decision.value,
            "reason": reason,
            "receipt": receipt,
            "session_review": review,
        }

    def check_policy(self, payload: dict[str, Any]) -> dict[str, Any]:
        source = _dict(payload.get("source"))
        event = _dict(payload.get("event"))
        action_class = str(event.get("action_class") or "observe").lower()
        target = str(event.get("target") or "")
        command = " ".join(str(part) for part in _list(event.get("command")))
        labels = ["observed", "attested"]
        verdict = "allowed"
        reason = "within local Ardur Personal policy"
        evidence_level = "attested"

        if event.get("raw_content_included") is True:
            verdict = "blocked"
            reason = "raw page or app content is not accepted at receipt boundary"
        elif event.get("text_snapshot_included") is True and not _dict(
            event.get("consent")
        ).get("visible_text"):
            verdict = "blocked"
            reason = "visible text snapshot requires explicit user consent"
        elif action_class in {"send", "write"} and _SENSITIVE_TARGET_RE.search(target):
            verdict = "blocked"
            reason = "sensitive target requires explicit stronger policy"
        elif (
            source.get("type") == "cli"
            and command
            and _DANGEROUS_CLI_RE.search(command)
        ):
            verdict = "blocked"
            reason = "command matches default dangerous CLI policy"
            evidence_level = "enforced"

        if verdict == "blocked":
            labels.extend(["blocked", "enforced"])
        else:
            labels.append("allowed")
            if source.get("type") == "cli":
                labels.append("enforced")
                evidence_level = "enforced"

        if (
            source.get("type") in {"browser", "desktop"}
            and event.get("hidden_provider_activity") is True
        ):
            labels.append("insufficient_evidence")
            verdict = "unknown"
            reason = "provider-side activity is not locally visible"
            evidence_level = "insufficient_evidence"

        return {
            "verdict": verdict,
            "reason": reason,
            "labels": labels,
            "evidence_level": evidence_level,
        }

    def attest(self, ardur_session_id: str) -> dict[str, Any]:
        token, claims = self.proxy.issue_attestation_for_session(
            ardur_session_id, self.private_key
        )
        return {"ok": True, "token": token, "claims": claims}

    def export(self) -> dict[str, Any]:
        return {
            "ok": True,
            "schema_version": "ardur.personal.hub_export.v0.1",
            "exported_at": _utc_now(),
            "status": self.status(),
            "sessions": _read_json(self.paths.sessions_index, {}),
            "session_reviews": _read_json(self.paths.reviews, []),
            "receipts": self._receipt_entries(),
        }

    def _validate_event_payload(self, payload: dict[str, Any]) -> None:
        source = _dict(payload.get("source"))
        event = _dict(payload.get("event"))
        source_type = source.get("type")
        if source_type not in {"browser", "desktop", "cli"}:
            raise HubError("source.type must be browser, desktop, or cli")
        digest = event.get("content_digest")
        if digest is not None and not _SHA256_DIGEST_RE.fullmatch(str(digest)):
            raise HubError("event.content_digest must be sha-256:<hex>")
        if event.get("raw_content_included") is True:
            raise HubError(
                "raw_content_included=true is rejected; send digests and consented excerpts"
            )
        if event.get("text_snapshot_included") is True and not _dict(
            event.get("consent")
        ).get("visible_text"):
            raise HubError("text snapshot requires event.consent.visible_text=true")

    def _agent_id(self, source: dict[str, Any]) -> str:
        source_type = _clip(source.get("type") or "unknown", 40)
        app = _clip(
            source.get("app")
            or source.get("origin")
            or source.get("process")
            or "local",
            80,
        )
        return f"ardur-personal:{source_type}:{app}"

    def _session_key(self, payload: dict[str, Any]) -> str:
        source = _dict(payload.get("source"))
        session = _dict(payload.get("session"))
        explicit = session.get("id") or payload.get("tab_session_id")
        if explicit:
            return _clip(explicit, 220)
        basis = {
            "type": source.get("type"),
            "app": source.get("app"),
            "origin": source.get("origin"),
            "process": source.get("process"),
            "title": session.get("title"),
        }
        return (
            "session:"
            + hashlib.sha256(
                json.dumps(basis, sort_keys=True).encode("utf-8")
            ).hexdigest()[:32]
        )

    def _tool_name(self, source: dict[str, Any], policy: dict[str, Any]) -> str:
        if policy["verdict"] == "blocked":
            return f"{source['type']}_blocked_action"
        if source["type"] == "browser":
            return "browser_observe"
        if source["type"] == "desktop":
            return "desktop_observe"
        if source["type"] == "cli":
            return "cli_command"
        return "browser_observe"

    def _arguments(
        self, payload: dict[str, Any], policy: dict[str, Any]
    ) -> dict[str, Any]:
        source = _dict(payload.get("source"))
        event = _dict(payload.get("event"))
        session = _dict(payload.get("session"))
        args: dict[str, Any] = {
            "source_type": source.get("type"),
            "app": source.get("app"),
            "origin": source.get("origin"),
            "process": source.get("process"),
            "title": session.get("title"),
            "target": event.get("target")
            or source.get("origin")
            or source.get("process")
            or "local",
            "capture_mode": event.get("capture_mode") or "digest_only",
            "content_digest": event.get("content_digest"),
            "raw_content_included": False,
            "hub_policy_verdict": policy["verdict"],
            "hub_policy_reason": policy["reason"],
            "evidence_labels": list(policy["labels"]),
        }
        if source.get("type") == "cli":
            args["command"] = _list(event.get("command"))
            args["exit_code"] = event.get("exit_code")
            args["stdout_digest"] = event.get("stdout_digest")
            args["stderr_digest"] = event.get("stderr_digest")
        if event.get("text_snapshot_included"):
            args["text_excerpt_digest"] = _sha256_text(_clip(event.get("text_excerpt")))
        return {
            key: value for key, value in args.items() if value not in (None, "", [])
        }

    def _update_session_review(
        self,
        *,
        payload: dict[str, Any],
        session_record: dict[str, Any],
        receipt: dict[str, Any] | None,
        policy: dict[str, Any],
        decision: Decision,
        reason: str,
    ) -> dict[str, Any]:
        source = _dict(payload.get("source"))
        event = _dict(payload.get("event"))
        session_key = str(session_record["session_key"])
        reviews = _read_json(self.paths.reviews, [])
        review = next(
            (item for item in reviews if item.get("session_id") == session_key), None
        )
        now = _utc_now()
        if review is None:
            review = {
                "schema_version": SESSION_REVIEW_SCHEMA_VERSION,
                "session_id": session_key,
                "ardur_session_id": session_record["ardur_session_id"],
                "source": source,
                "provider": source.get("app")
                or source.get("origin")
                or source.get("process")
                or "Local",
                "title": session_record.get("title") or "",
                "started_at": session_record.get("started_at") or now,
                "updated_at": now,
                "status": "active",
                "policy_labels": [],
                "summary": "",
                "latest_receipt_id": None,
                "latest_action": None,
                "observations": [],
                "actions": [],
            }
            reviews.append(review)

        observation = {
            "observed_at": now,
            "source_type": source.get("type"),
            "target": event.get("target"),
            "capture_mode": event.get("capture_mode") or "digest_only",
            "content_digest": event.get("content_digest"),
            "decision": decision.value,
            "reason": reason,
            "labels": list(policy["labels"]),
            "receipt_id": receipt.get("receipt_id") if receipt else None,
        }
        review["observations"].append(observation)
        review["observations"] = review["observations"][-MAX_OBSERVATIONS_PER_REVIEW:]
        actions = self._derive_actions(source, event, observation)
        if actions:
            review["actions"].extend(actions)
            review["actions"] = review["actions"][-MAX_ACTIONS_PER_REVIEW:]
            review["latest_action"] = review["actions"][-1]
        review["updated_at"] = now
        review["policy_labels"] = sorted(
            set(_list(review.get("policy_labels")) + list(policy["labels"]))
        )
        review["latest_receipt_id"] = receipt.get("receipt_id") if receipt else None
        review["latest_receipt_hash"] = receipt.get("receipt_hash") if receipt else None
        review["summary"] = self._review_summary(review)
        _write_json(self.paths.reviews, reviews)
        return review

    def _derive_actions(
        self,
        source: dict[str, Any],
        event: dict[str, Any],
        observation: dict[str, Any],
    ) -> list[dict[str, Any]]:
        base = {
            "action_id": str(uuid.uuid4()),
            "observed_at": observation["observed_at"],
            "source_type": source.get("type"),
            "receipt_id": observation.get("receipt_id"),
            "policy_labels": observation["labels"],
        }
        actions: list[dict[str, Any]] = []
        for message in _list(event.get("messages"))[-12:]:
            if not isinstance(message, dict):
                continue
            role = str(message.get("role") or "unknown")
            excerpt = _clip(message.get("text_excerpt"), 1200)
            digest = message.get("text_digest") or (
                _sha256_text(excerpt) if excerpt else None
            )
            kind = {
                "user": "user_prompt_observed",
                "assistant": "assistant_response_observed",
                "tool": "tool_output_observed",
            }.get(role, "visible_message_observed")
            actions.append(
                {
                    **base,
                    "action_id": str(uuid.uuid4()),
                    "kind": kind,
                    "role": role,
                    "summary": self._action_summary(kind, excerpt),
                    "text_excerpt": excerpt,
                    "message_digest": digest,
                }
            )
        if actions:
            return actions
        if source.get("type") == "cli":
            command = " ".join(str(part) for part in _list(event.get("command")))
            return [
                {
                    **base,
                    "kind": "cli_command_observed",
                    "role": "local_process",
                    "summary": f"CLI command observed: {_clip(command, 240)}",
                    "command_digest": _sha256_text(command),
                }
            ]
        return [
            {
                **base,
                "kind": f"{source.get('type')}_state_observed",
                "role": "unknown",
                "summary": f"{str(source.get('type') or 'local').title()} state observed.",
                "visible_text_digest": event.get("content_digest"),
                "text_excerpt": _clip(event.get("text_excerpt")),
            }
        ]

    @staticmethod
    def _action_summary(kind: str, excerpt: str) -> str:
        label = {
            "user_prompt_observed": "User prompt observed",
            "assistant_response_observed": "Assistant response observed",
            "tool_output_observed": "Tool output observed",
        }.get(kind, "Visible message observed")
        return f"{label}: {excerpt}" if excerpt else label

    @staticmethod
    def _review_summary(review: dict[str, Any]) -> str:
        latest = (
            _dict(review.get("latest_action")).get("summary")
            or "No readable action text captured yet."
        )
        labels = ", ".join(_list(review.get("policy_labels")) or ["observed"])
        return (
            f"{review.get('provider') or 'Local'} session review: "
            f"{len(_list(review.get('actions')))} action boundary/boundaries, "
            f"{len(_list(review.get('observations')))} receipt(s), labels: {labels}. "
            f"Latest: {latest}"
        )

    def _iter_receipt_entries(self) -> Iterator[dict[str, Any]]:
        try:
            receipt_lines = self.paths.receipts_log.open("r", encoding="utf-8")
        except FileNotFoundError:
            return
        with receipt_lines:
            for line in receipt_lines:
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict):
                    yield entry

    def _receipt_entries(self) -> list[dict[str, Any]]:
        return list(self._iter_receipt_entries())

    def _latest_receipt(self, session_id: str | None = None) -> dict[str, Any] | None:
        latest: dict[str, Any] | None = None
        for entry in self._iter_receipt_entries():
            if session_id is None or entry.get("session_id") == session_id:
                latest = entry
        if latest is None:
            return None
        result = dict(latest)
        jwt_value = str(result.get("jwt") or "")
        if jwt_value:
            result["receipt_hash"] = hashlib.sha256(
                jwt_value.encode("ascii")
            ).hexdigest()
        return result


class _HubRequestHandler(BaseHTTPRequestHandler):
    server_version = "ArdurPersonalHub/0.1"

    @property
    def hub(self) -> PersonalHub:
        return self.server.hub  # type: ignore[attr-defined]

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send_json({"ok": True})

    def do_GET(self) -> None:  # noqa: N802
        path = self._request_path()
        if path in {"/health", "/healthz"}:
            self._send_json(self.hub.health())
            return
        if not self._check_rate_limit():
            return
        if not self._is_authorized(allow_query_token=path in {"/", "/dashboard"}):
            self._send_auth_required()
            return
        if path in {"/", "/dashboard"}:
            self._send_html(self._dashboard_html())
            return
        if path == "/v1/status":
            self._send_json(self.hub.status())
            return
        if path == "/v1/export":
            self._send_json(self.hub.export())
            return
        if path == "/v1/metrics":
            self._send_metrics()
            return
        self._send_json({"ok": False, "error": "not found"}, status=404)

    def do_POST(self) -> None:  # noqa: N802
        if not self._check_rate_limit():
            return
        if not self._is_authorized():
            self._send_auth_required()
            return
        path = self._request_path()
        try:
            payload = self._read_payload()
            if path == "/v1/sessions/start":
                self._send_json(self.hub.start_session(payload))
                return
            if path == "/v1/events/observe":
                self._send_json(self.hub.observe(payload))
                return
            if path == "/v1/policy/check":
                self._send_json({"ok": True, "policy": self.hub.check_policy(payload)})
                return
            match = re.fullmatch(r"/v1/sessions/([^/]+)/attest", path)
            if match:
                self._send_json(self.hub.attest(match.group(1)))
                return
            self._send_json({"ok": False, "error": "not found"}, status=404)
        except HubError as exc:
            self._send_json(
                {"ok": False, "error": str(exc), "error_code": exc.code},
                status=exc.status,
            )
        except Exception:  # pragma: no cover - defensive server boundary
            logger.exception(
                "Unhandled exception in Personal Hub HTTP handler",
                extra={"path": "<request-path-redacted>"},
            )
            self._send_json(
                {"ok": False, "error": "internal server error", "error_code": "internal_error"},
                status=500,
            )

    def log_message(self, fmt: str, *args: Any) -> None:
        message = _redact_url_tokens(fmt % args)
        print(f"ardur-hub: {self.address_string()} - {message}", file=sys.stderr)

    def _check_rate_limit(self) -> bool:
        limiter = getattr(self.server, "rate_limiter", None)
        if limiter is None:
            return True
        client_ip = self.client_address[0] if self.client_address else "unknown"
        if not limiter.allow(client_ip):
            self._send_json({"ok": False, "error": "rate limit exceeded"}, status=429)
            return False
        return True

    def _request_path(self) -> str:
        return urlparse.urlparse(self.path).path

    def _is_authorized(self, *, allow_query_token: bool = False) -> bool:
        expected = self.hub.hub_token
        if not expected:
            return False
        supplied = self.headers.get(HUB_TOKEN_HEADER, "").strip()
        if not supplied:
            auth = self.headers.get("authorization", "").strip()
            if auth.lower().startswith("bearer "):
                supplied = auth[7:].strip()
        if not supplied and allow_query_token:
            query = urlparse.parse_qs(urlparse.urlparse(self.path).query)
            supplied = str((query.get("token") or [""])[0]).strip()
        return _hub_tokens_match(supplied, expected)

    def _send_auth_required(self) -> None:
        self._send_json(
            {
                "ok": False,
                "error": "Ardur Personal Hub token required",
                "error_code": "hub_auth_required",
            },
            status=401,
        )

    def _read_payload(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("content-length") or "0")
        except (TypeError, ValueError) as exc:
            raise HubError(
                "content-length must be a non-negative integer",
                status=400,
                code="invalid_content_length",
            ) from exc
        if length < 0:
            raise HubError(
                "content-length must be a non-negative integer",
                status=400,
                code="invalid_content_length",
            )
        if length > MAX_BODY_BYTES:
            raise HubError("request body too large", status=413, code="body_too_large")
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError as exc:
            raise HubError("request body must be JSON") from exc
        if not isinstance(payload, dict):
            raise HubError("request body must be a JSON object")
        return payload

    def _send_json(self, payload: dict[str, Any], *, status: int = 200) -> None:
        data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("cache-control", "no-store")
        self.send_header("pragma", "no-cache")
        self.send_header("referrer-policy", "no-referrer")
        self.send_header(
            "content-security-policy",
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        origin = self._allowed_cors_origin()
        if origin:
            self.send_header("access-control-allow-origin", origin)
            self.send_header("vary", "Origin")
        self.send_header("access-control-allow-methods", "GET, POST, OPTIONS")
        self.send_header(
            "access-control-allow-headers",
            f"authorization, content-type, {HUB_TOKEN_HEADER}",
        )
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _allowed_cors_origin(self) -> str | None:
        origin = self.headers.get("origin", "").strip()
        if not origin or "\r" in origin or "\n" in origin:
            return None
        parsed = urlparse.urlparse(origin)
        if parsed.scheme in {"chrome-extension", "moz-extension"}:
            if not re.fullmatch(r"[A-Za-z0-9_-]+", parsed.netloc):
                return None
            return "*"
        if parsed.scheme in {"http", "https"} and parsed.hostname in {
            "127.0.0.1",
            "localhost",
        }:
            try:
                parsed.port
            except ValueError:
                return None
            if (
                parsed.path not in {"", "/"}
                or parsed.params
                or parsed.query
                or parsed.fragment
            ):
                return None
            configured = self._configured_loopback_cors_origin()
            if configured and origin == configured:
                return configured
        return None

    def _configured_loopback_cors_origin(self) -> str | None:
        configured = urlparse.urlparse(str(self.hub.hub_url))
        if configured.scheme not in {"http", "https"} or configured.hostname not in {
            "127.0.0.1",
            "localhost",
        }:
            return None
        try:
            port = configured.port
        except ValueError:
            return None
        if (
            configured.path not in {"", "/"}
            or configured.params
            or configured.query
            or configured.fragment
        ):
            return None
        host = configured.hostname
        return (
            f"{configured.scheme}://{host}:{port}"
            if port is not None
            else f"{configured.scheme}://{host}"
        )

    def _send_html(self, content: str, *, status: int = 200) -> None:
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("pragma", "no-cache")
        self.send_header(
            "content-security-policy",
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.send_header("referrer-policy", "no-referrer")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_metrics(self) -> None:
        data = ardur_metrics.render().encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "text/plain; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("pragma", "no-cache")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _dashboard_html(self) -> str:
        export = self.hub.export()
        reviews = export.get("session_reviews") or []
        rows = []
        for review in reviews[-50:]:
            rows.append(
                "<article>"
                f"<h2>{html.escape(str(review.get('provider') or 'Local'))}</h2>"
                f"<p>{html.escape(str(review.get('summary') or ''))}</p>"
                f"<code>{html.escape(str(review.get('latest_receipt_id') or 'no receipt'))}</code>"
                "</article>"
            )
        body = "\n".join(rows) or "<p>No sessions observed yet.</p>"
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Ardur Personal Hub</title>
  <style>
    body {{ margin: 0; font: 15px -apple-system, BlinkMacSystemFont, sans-serif; background: #f7f7f3; color: #202124; }}
    header {{ padding: 24px; background: #12343b; color: white; }}
    main {{ display: grid; gap: 12px; max-width: 960px; margin: 0 auto; padding: 20px; }}
    article {{ background: white; border: 1px solid #d8d6ca; border-radius: 8px; padding: 14px; }}
    h1, h2, p {{ margin: 0; }}
    h2 {{ font-size: 15px; margin-bottom: 8px; }}
    code {{ display: block; margin-top: 10px; color: #47606b; overflow-wrap: anywhere; }}
  </style>
</head>
<body>
  <header><h1>Ardur Personal Hub</h1></header>
  <main>{body}</main>
</body>
</html>"""


def serve_hub(
    *,
    host: str = DEFAULT_HUB_HOST,
    port: int = DEFAULT_HUB_PORT,
    home: str | Path | None = None,
    tls_cert: str | Path | None = None,
    tls_key: str | Path | None = None,
    no_tls: bool = False,
) -> None:
    paths = HubPaths.from_home(home)
    validate_personal_home_directory(paths)

    tls_context = None
    cert_fingerprint = None
    if not no_tls:
        try:
            if (tls_cert is None) != (tls_key is None):
                raise HubTLSConfigurationError()
            # Expand once and pass the SAME resolved paths downstream.
            # ``resolve_tls_paths`` does not expand ``~`` itself, so checking an
            # expanded path here and then handing it the raw one would reject a
            # valid ``~/cert.pem`` pair and echo the raw path to stderr.
            if tls_cert is not None and tls_key is not None:
                tls_cert = Path(tls_cert).expanduser()
                tls_key = Path(tls_key).expanduser()
                if not tls_cert.is_file() or not tls_key.is_file():
                    raise HubTLSConfigurationError()
            tls_result = resolve_tls_paths(
                tls_cert,
                tls_key,
                home=paths.home,
                hostname=host,
            )
            if tls_result is None:
                raise HubTLSConfigurationError()
            cert_path, key_path, cert_fingerprint = tls_result
            tls_context = create_ssl_context(cert_path, key_path)
        except HubTLSConfigurationError:
            raise
        except (OSError, ValueError) as exc:
            raise HubTLSConfigurationError() from exc
    tls_active = tls_context is not None

    server = ThreadingHTTPServer((host, port), _HubRequestHandler)
    server.rate_limiter = RateLimiter()  # type: ignore[attr-defined]

    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
        print(f"[tls] cert fingerprint: {cert_fingerprint}", file=sys.stderr)
    if no_tls:
        print("[tls] WARNING: TLS disabled — plain HTTP only", file=sys.stderr)

    scheme = "https" if tls_active else "http"
    server.hub = PersonalHub(paths.home, hub_url=f"{scheme}://{host}:{port}")  # type: ignore[attr-defined]
    print(f"Ardur Personal Hub listening on {scheme}://{host}:{port}", file=sys.stderr)
    server.serve_forever()


def _hub_url_invalid_response() -> dict[str, Any]:
    return {
        "ok": False,
        "error": "hub_url_invalid",
        "error_code": "hub_url_invalid",
        "condition": "hub_url_invalid",
        "message": "Ardur Personal Hub URL is invalid.",
        "detail": (
            "The configured Hub URL could not be parsed. Use a complete loopback "
            "HTTP or HTTPS endpoint such as http://127.0.0.1:8765."
        ),
    }


def _validated_hub_request_url(hub_url: str, path: str) -> str | None:
    """Return a request URL only for complete HTTP(S) Hub endpoints."""
    base_url = str(hub_url).strip()
    try:
        parsed = urlparse.urlsplit(base_url)
        if parsed.scheme.lower() not in _ALLOWED_HUB_URL_SCHEMES:
            return None
        if not parsed.netloc or not parsed.hostname:
            return None
        _ = parsed.port
    except ValueError:
        return None
    return base_url.rstrip("/") + path


# Loopback hostnames for which the Personal Hub serves a self-signed cert that
# is not present in the system trust store. The Hub's pinned certificate lives
# at ``<home>/tls/cert.pem`` and is the only trust root the client should add.
_LOOPBACK_HUB_HOSTS = frozenset({"127.0.0.1", "localhost"})


def _is_loopback_https_hub(hub_url: str) -> bool:
    """True when ``hub_url`` is an https URL pinned to a loopback host."""

    try:
        parsed = urlparse.urlsplit(str(hub_url).strip())
    except ValueError:
        return False
    if parsed.scheme.lower() != "https":
        return False
    return (parsed.hostname or "").lower() in _LOOPBACK_HUB_HOSTS


def _loopback_hub_ssl_context(
    hub_url: str,
    home: str | Path | None,
) -> ssl.SSLContext | None:
    """Return a client SSL context that trusts only the Hub's pinned cert.

    The Personal Hub auto-generates a self-signed certificate under
    ``<home>/tls/cert.pem`` and serves HTTPS on loopback. That certificate is
    not installed in the system trust store, so the default ``urlopen`` SSL
    context rejects it and the client reports ``hub_unavailable`` even when the
    Hub is healthy.

    This helper builds a strict client context that trusts *only* the pinned
    Hub certificate (CA = ``<home>/tls/cert.pem``) and still validates the
    hostname and certificate chain against that single CA. It is used solely
    for loopback https Hub URLs whose pinned cert file exists. For any other
    case (non-https, non-loopback, http, or missing cert file) it returns
    ``None`` so ``urlopen`` falls back to the default system trust store.
    """

    if not _is_loopback_https_hub(hub_url):
        return None
    try:
        resolved_home = _resolve_personal_home(home)
    except HubError:
        return None
    pinned_cert = resolved_home / "tls" / "cert.pem"
    if not pinned_cert.is_file():
        return None
    try:
        context = ssl.create_default_context(cafile=str(pinned_cert))
    except (OSError, ssl.SSLError):
        return None
    # Keep default strict verification against the pinned CA. Hostname
    # validation stays enabled so only a cert issued for the loopback host
    # is accepted.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def hub_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    hub_url: str = DEFAULT_HUB_URL,
    hub_token: str | None = None,
    home: str | Path | None = None,
) -> dict[str, Any]:
    data = None
    headers = {"accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["content-type"] = "application/json"
    try:
        token = resolve_hub_token(home=home, explicit=hub_token)
    except HubError as exc:
        mapped = _personal_home_failure_response_for(exc)
        if mapped is not None:
            return mapped
        raise
    if token:
        headers["authorization"] = f"Bearer {token}"
        headers[HUB_TOKEN_HEADER] = token
    # When a caller (typically a CLI command whose ``--hub-url`` argument
    # defaults to the plain-HTTP :data:`DEFAULT_HUB_URL`) has not supplied an
    # explicit override, consult the Personal home config so a Hub that is
    # actually serving HTTPS is reached with the correct scheme. ``ardur hub``
    # records the real scheme://host:port it serves on into config, so this
    # mirrors how :func:`resolve_hub_token` already resolves the token.
    if str(hub_url).strip() == DEFAULT_HUB_URL:
        try:
            hub_url = resolve_hub_url(home=home)
        except HubError as exc:
            mapped = _personal_home_failure_response_for(exc)
            if mapped is not None:
                return mapped
            raise
    request_url = _validated_hub_request_url(hub_url, path)
    if request_url is None:
        return _hub_url_invalid_response()
    try:
        req = urlrequest.Request(request_url, data=data, method=method, headers=headers)
    except ValueError:
        return _hub_url_invalid_response()
    # The loopback Personal Hub serves a self-signed cert pinned at
    # ``<home>/tls/cert.pem``; trust only that cert, and only for loopback
    # https. Fall back to the default (system) trust store otherwise.
    ssl_context = _loopback_hub_ssl_context(hub_url, home=home)
    try:
        with urlrequest.urlopen(req, timeout=5, context=ssl_context) as response:
            return json.loads(response.read().decode("utf-8"))
    except httpclient.InvalidURL:
        return _hub_url_invalid_response()
    except urlerror.HTTPError as exc:
        try:
            return json.loads(exc.read().decode("utf-8"))
        except Exception:
            return {"ok": False, "error": "hub_error", "error_code": "hub_error", "status": exc.code}
    except OSError:
        return {
            "ok": False,
            "error": "hub_unavailable",
            "error_code": "hub_unavailable",
        }


def status_response_with_next_steps(response: dict[str, Any]) -> dict[str, Any]:
    """Return ``ardur status`` output with local remediation hints when useful.

    Healthy Hub responses stay unchanged. Failure hints are intentionally
    deterministic and placeholder-only: the raw status response can carry local
    diagnostics, but the remediation guidance must be safe to paste into support
    notes without leaking temp homes, Hub tokens, or generated receipt paths.
    """
    if response.get("ok"):
        return response

    steps = _status_next_steps_for_response(response)
    if not steps:
        return response
    return {**response, "next_steps": steps}


def _hub_setup_failure_flags(response: dict[str, Any]) -> tuple[bool, bool]:
    error_code = str(response.get("error_code") or "").strip().lower()
    status = str(response.get("status") or "").strip()
    error = str(response.get("error") or "").strip().lower()

    hub_unavailable = error_code == "hub_unavailable"
    token_problem = (
        error_code in {"hub_auth_required", "hub_token_missing", "unauthorized"}
        or status == "401"
        or (
            "token" in error
            and ("required" in error or "missing" in error or "unauthorized" in error)
        )
        or (
            "authorization" in error
            and ("required" in error or "missing" in error or "unauthorized" in error)
        )
    )
    return hub_unavailable, token_problem


def _hub_failure_condition(response: dict[str, Any]) -> str:
    """Return a normalized local Hub failure condition without echoing raw input."""
    for key in ("condition", "error_code", "error"):
        value = str(response.get(key) or "").strip().lower()
        if value:
            return value
    return ""


def _hub_url_invalid_next_step() -> dict[str, str]:
    return {
        "condition": "hub_url_invalid",
        "action": "check_hub_url",
        "command": "ardur doctor --home <ardur-home> --hub-url <hub-url>",
        "detail": (
            "Use a complete local Hub endpoint such as http://127.0.0.1:8765. "
            "Keep raw local paths, invalid file URLs, Hub tokens, and payloads out "
            "of shared logs."
        ),
    }


def _status_next_steps_for_response(response: dict[str, Any]) -> list[dict[str, str]]:
    if _hub_failure_condition(response) == "hub_url_invalid":
        return [
            _hub_url_invalid_next_step(),
            {
                "condition": "hub_url_invalid",
                "action": "rerun_status_or_doctor",
                "command": "ardur status --home <ardur-home> --hub-url <hub-url>",
                "detail": (
                    "After correcting the Hub URL, rerun local status or use doctor for "
                    "setup diagnostics. This guidance is local/no-key recovery only; it "
                    "does not call live providers or prove provider-hidden actions."
                ),
            },
        ]

    hub_unavailable, token_problem = _hub_setup_failure_flags(response)

    if not hub_unavailable and not token_problem:
        return []

    steps: list[dict[str, str]] = []
    if hub_unavailable:
        steps.append(
            {
                "condition": "hub_unavailable",
                "action": "run_setup_if_needed",
                "command": "ardur setup --home <ardur-home>",
                "detail": (
                    "Create local Ardur Personal config and Hub token if setup has not run yet. "
                    "Do not paste raw tokens into shared logs."
                ),
            }
        )
        steps.append(
            {
                "condition": "hub_unavailable",
                "action": "start_personal_hub",
                "command": "ardur hub --home <ardur-home>",
                "detail": (
                    "Start the local loopback Ardur Personal Hub. If your config uses a "
                    "non-default endpoint, use host/port settings that match <hub-url>."
                ),
            }
        )

    if hub_unavailable or token_problem:
        steps.append(
            {
                "condition": "hub_token_required"
                if token_problem
                else "check_hub_token",
                "action": "supply_or_rotate_hub_token",
                "command": "ardur status --hub-url <hub-url> --hub-token <hub-token>",
                "detail": (
                    "Supply the existing local Hub token with --hub-token <hub-token> or "
                    "ARDUR_PERSONAL_HUB_TOKEN=<hub-token>; rotate it with "
                    "ardur setup --home <ardur-home> --rotate-token only when needed."
                ),
            }
        )

    steps.append(
        {
            "condition": "status_failed",
            "action": "rerun_status_or_doctor",
            "command": "ardur status --hub-url <hub-url>",
            "detail": (
                "Re-run local status after remediation, or run ardur doctor --home "
                "<ardur-home> --hub-url <hub-url> for setup diagnostics. This guidance "
                "does not call live providers or prove provider-hidden actions."
            ),
        }
    )
    return steps


def desktop_observe_response_with_next_steps(
    response: dict[str, Any],
) -> dict[str, Any]:
    """Return ``ardur desktop-observe`` output with safe local remediation hints."""
    if response.get("ok"):
        return response

    steps = _desktop_observe_next_steps_for_response(response)
    if not steps:
        return response
    return {**response, "next_steps": steps}


def _desktop_observe_invalid_hub_url_next_steps() -> list[dict[str, str]]:
    return [
        _hub_url_invalid_next_step(),
        {
            "condition": "hub_url_invalid",
            "action": "rerun_desktop_observe_or_doctor",
            "command": (
                "ardur desktop-observe --app <app-name> --title <window-title> "
                "--home <ardur-home> --hub-url <hub-url>"
            ),
            "detail": (
                "After correcting the Hub URL, re-run local desktop observation or "
                "use ardur doctor --home <ardur-home> --hub-url <hub-url> for setup "
                "diagnostics. Add --text <visible-text> only when you intentionally "
                "want that visible text recorded. This guidance is local/no-key "
                "recovery only; it does not call live providers or prove "
                "provider-hidden actions."
            ),
        },
    ]


def _desktop_observe_next_steps_for_response(
    response: dict[str, Any],
) -> list[dict[str, str]]:
    if _hub_failure_condition(response) == "hub_url_invalid":
        return _desktop_observe_invalid_hub_url_next_steps()

    hub_unavailable, token_problem = _hub_setup_failure_flags(response)
    if not hub_unavailable and not token_problem:
        return []

    steps: list[dict[str, str]] = []
    if hub_unavailable:
        steps.append(
            {
                "condition": "hub_unavailable",
                "action": "run_setup_if_needed",
                "command": "ardur setup --home <ardur-home>",
                "detail": (
                    "Create local Ardur Personal config and Hub token if setup has not run yet. "
                    "Do not paste raw tokens into shared logs."
                ),
            }
        )
        steps.append(
            {
                "condition": "hub_unavailable",
                "action": "start_personal_hub",
                "command": "ardur hub --home <ardur-home>",
                "detail": (
                    "Start the local loopback Ardur Personal Hub. If your config uses a "
                    "non-default endpoint, use host/port settings that match <hub-url>."
                ),
            }
        )

    if hub_unavailable or token_problem:
        steps.append(
            {
                "condition": "hub_token_required"
                if token_problem
                else "check_hub_token",
                "action": "supply_or_rotate_hub_token",
                "command": (
                    "ardur desktop-observe --app <app-name> --title <window-title> "
                    "--home <ardur-home> --hub-url <hub-url> --hub-token <hub-token>"
                ),
                "detail": (
                    "Supply the existing local Hub token with --hub-token <hub-token> or "
                    "ARDUR_PERSONAL_HUB_TOKEN=<hub-token>; rotate it with "
                    "ardur setup --home <ardur-home> --rotate-token only when needed."
                ),
            }
        )

    steps.append(
        {
            "condition": "desktop_observe_failed",
            "action": "rerun_desktop_observe_or_doctor",
            "command": "ardur doctor --home <ardur-home> --hub-url <hub-url>",
            "detail": (
                "Confirm local setup before re-running ardur desktop-observe --app "
                "<app-name> --title <window-title> --home <ardur-home> --hub-url "
                "<hub-url>. This guidance is local/no-key setup help only; it does "
                "not call live providers, prove provider-hidden actions, or broaden "
                "current Hub policy enforcement."
            ),
        }
    )
    return steps


def run_recovery_next_steps_for_response(
    response: dict[str, Any],
    *,
    phase: str,
) -> list[dict[str, str]]:
    """Return deterministic stderr remediation hints for ``ardur run`` setup failures."""
    hub_unavailable, token_problem = _hub_setup_failure_flags(response)
    if not hub_unavailable and not token_problem and not response.get("error"):
        return []

    steps: list[dict[str, str]] = []
    if hub_unavailable:
        steps.append(
            {
                "condition": "hub_unavailable",
                "action": "run_setup_if_needed",
                "command": "ardur setup --home <ardur-home>",
                "detail": (
                    "Create local Ardur Personal config and Hub token if setup has not run yet. "
                    "Do not paste raw tokens into shared logs."
                ),
            }
        )
        steps.append(
            {
                "condition": "hub_unavailable",
                "action": "start_personal_hub",
                "command": "ardur hub --home <ardur-home>",
                "detail": (
                    "Start the local loopback Ardur Personal Hub. If your config uses a "
                    "non-default endpoint, use host/port settings that match <hub-url>."
                ),
            }
        )

    if hub_unavailable or token_problem:
        steps.append(
            {
                "condition": "hub_token_required"
                if token_problem
                else "check_hub_token",
                "action": "supply_or_rotate_hub_token",
                "command": (
                    "ardur run --home <ardur-home> --hub-url <hub-url> "
                    "--hub-token <hub-token> -- <command>"
                ),
                "detail": (
                    "Supply the existing local Hub token with --hub-token <hub-token> or "
                    "ARDUR_PERSONAL_HUB_TOKEN=<hub-token>; rotate it with "
                    "ardur setup --home <ardur-home> --rotate-token only when needed."
                ),
            }
        )

    steps.append(
        {
            "condition": f"run_{phase}_failed",
            "action": "rerun_doctor_then_run",
            "command": "ardur doctor --home <ardur-home> --hub-url <hub-url>",
            "detail": (
                "Confirm local setup before re-running ardur run --home <ardur-home> "
                "--hub-url <hub-url> -- <command>. This guidance is local/no-key setup "
                "help only; it does not call live providers, prove provider-hidden "
                "actions, or broaden current Hub policy enforcement."
            ),
        }
    )
    return steps


def run_missing_command_next_steps() -> list[dict[str, str]]:
    """Return deterministic stderr remediation hints for malformed ``ardur run`` usage."""
    return [
        {
            "condition": "missing_run_command",
            "action": "pass_command_after_separator",
            "command": "ardur run -- <command>",
            "detail": (
                "Pass one non-interactive local command after --. Keep secrets, raw "
                "Hub tokens, and private paths out of shared command examples."
            ),
        },
        {
            "condition": "missing_run_command",
            "action": "include_hub_options_if_needed",
            "command": (
                "ardur run --home <ardur-home> --hub-url <hub-url> "
                "--hub-token <hub-token> -- <command>"
            ),
            "detail": (
                "Use explicit home, Hub URL, or Hub token placeholders only when your "
                "local setup does not use defaults. Do not paste raw tokens into shared logs."
            ),
        },
        {
            "condition": "missing_run_command",
            "action": "check_local_setup_before_running",
            "command": "ardur doctor --home <ardur-home> --hub-url <hub-url>",
            "detail": (
                "Confirm local setup before re-running ardur run -- <command>. This "
                "guidance is local/no-key setup help only; it does not execute a child "
                "command, call live providers, or broaden current Hub policy enforcement."
            ),
        },
    ]


def _print_run_next_steps(steps: list[dict[str, str]]) -> None:
    if not steps:
        return
    print("Next steps:", file=sys.stderr)
    for index, step in enumerate(steps, start=1):
        command = step.get("command", "")
        detail = step.get("detail", "")
        print(f"{index}. {command}", file=sys.stderr)
        if detail:
            print(f"   {detail}", file=sys.stderr)


def _print_run_recovery_next_steps(response: dict[str, Any], *, phase: str) -> None:
    _print_run_next_steps(run_recovery_next_steps_for_response(response, phase=phase))


def _print_run_missing_command_next_steps() -> None:
    _print_run_next_steps(run_missing_command_next_steps())


def setup_personal(args: argparse.Namespace) -> dict[str, Any]:
    paths = HubPaths.from_home(args.home)
    validate_personal_home_directory(paths)
    port = _validated_setup_port(getattr(args, "port", DEFAULT_HUB_PORT))
    if port is None:
        return setup_port_failure_response()
    host = _validated_setup_host(getattr(args, "host", DEFAULT_HUB_HOST))
    if host is None:
        return setup_host_failure_response()
    _ensure_personal_home_directory(paths)
    config = _ensure_hub_config(
        paths,
        hub_url=_setup_hub_url(host, port),
        browser_extension_path=str(Path(args.extension_path).expanduser())
        if args.extension_path
        else None,
        rotate_token=bool(getattr(args, "rotate_token", False)),
    )
    launch_agent = _write_launch_agent(paths, host, port)
    return {
        "ok": True,
        "home": str(paths.home),
        "config": str(paths.config),
        "hub_url": config["hub_url"],
        "hub_token": config["hub_token"],
        "launch_agent": str(launch_agent),
        "next_steps": [
            "brew services start ardur-personal, or run ardur hub",
            "Paste hub_token into the Ardur Personal browser extension settings",
            "Use ardur protect claude-code --scope . --mode read-only before starting Claude Code",
        ],
    }


def _write_launch_agent(paths: HubPaths, host: str, port: int) -> Path:
    agents = Path.home() / "Library" / "LaunchAgents"
    agents.mkdir(parents=True, exist_ok=True)
    plist_path = agents / "dev.ardur.personal-hub.plist"
    python = sys.executable
    plist = {
        "Label": "dev.ardur.personal-hub",
        "ProgramArguments": [
            python,
            "-m",
            "vibap.cli",
            "hub",
            "--host",
            host,
            "--port",
            str(port),
            "--home",
            str(paths.home),
        ],
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": str(paths.home / "hub.out.log"),
        "StandardErrorPath": str(paths.home / "hub.err.log"),
    }
    plist_path.write_bytes(plistlib.dumps(plist))
    return plist_path


def _doctor_personal_next_steps(
    *,
    home_ok: bool,
    config_ok: bool,
    hub_token_ok: bool,
    hub_ok: bool,
    hub_condition: str = "",
) -> list[dict[str, str]]:
    """Return deterministic local remediation hints for ``ardur doctor``.

    The user-facing doctor JSON intentionally uses placeholders for local setup
    paths and remediation hints so it can be copied into support notes without
    leaking temp homes, Hub tokens, or private receipt locations.
    """
    if home_ok and config_ok and hub_token_ok and hub_ok:
        return []

    steps: list[dict[str, str]] = []
    if not home_ok or not config_ok:
        steps.append(
            {
                "condition": "missing_personal_setup",
                "action": "run_setup",
                "command": "ardur setup --home <ardur-home>",
                "detail": (
                    "Create the local Ardur Personal home, config, and Hub token. "
                    "The setup command prints the Hub token once; do not paste the "
                    "raw token into shared logs."
                ),
            }
        )

    if not hub_token_ok:
        steps.append(
            {
                "condition": "missing_hub_token",
                "action": "supply_or_rotate_hub_token",
                "command": "ardur setup --home <ardur-home> --rotate-token",
                "detail": (
                    "Generate or rotate the local Hub token, then pass an existing "
                    "token with --hub-token <hub-token> or ARDUR_PERSONAL_HUB_TOKEN=<hub-token>."
                ),
            }
        )

    if not hub_ok and hub_condition == "hub_url_invalid":
        steps.append(_hub_url_invalid_next_step())
    elif not hub_ok:
        steps.append(
            {
                "condition": "hub_unavailable",
                "action": "start_personal_hub",
                "command": "ardur hub --home <ardur-home>",
                "detail": (
                    "Start the local loopback Ardur Personal Hub. If your config uses "
                    "a non-default endpoint, use host/port settings that match <hub-url>."
                ),
            }
        )

    steps.append(
        {
            "condition": "doctor_failed",
            "action": "rerun_doctor",
            "command": "ardur doctor --home <ardur-home> --hub-url <hub-url>",
            "detail": (
                "Re-run the local doctor after remediation. This check reads local "
                "setup and Hub status only; it does not call live providers or prove "
                "provider-hidden actions."
            ),
        }
    )
    return steps


def doctor_personal(args: argparse.Namespace) -> dict[str, Any]:
    paths = HubPaths.from_home(args.home)
    try:
        token = resolve_hub_token(
            home=args.home, explicit=getattr(args, "hub_token", None)
        )
    except HubError as exc:
        mapped = _personal_home_failure_response_for(exc)
        if mapped is not None:
            return mapped
        raise
    hub = hub_request(
        "GET", "/v1/status", hub_url=args.hub_url, hub_token=token, home=args.home
    )
    home_ok = paths.home.exists()
    config_ok = paths.config.exists()
    hub_token_ok = bool(token)
    hub_ok = bool(hub.get("ok"))
    # Mirror how hub_request resolves the URL: when the caller passed the
    # plain-HTTP argparse default, consult the Personal home config so the
    # doctor detail shows the real HTTPS URL the Hub serves on instead of the
    # default. Explicit overrides are honoured as-is; hub errors short-circuit
    # the detail below so resolution here is purely for the success display.
    display_hub_url = str(args.hub_url)
    if display_hub_url.strip() == DEFAULT_HUB_URL:
        # Best-effort display resolution: if config resolution fails, keep the
        # pre-try default. This only affects the doctor detail string; the
        # hub_request call above already ran with the resolved or default URL.
        with suppress(HubError):
            display_hub_url = resolve_hub_url(home=args.home)
    checks = [
        {"name": "home", "ok": home_ok, "detail": "<ardur-home>"},
        {"name": "config", "ok": config_ok, "detail": "<ardur-config>"},
        {
            "name": "hub_token",
            "ok": hub_token_ok,
            "detail": "configured" if token else "missing",
        },
        {
            "name": "hub",
            "ok": hub_ok,
            "detail": hub.get("error") or _redact_url_for_user_output(display_hub_url),
        },
        {
            "name": "desktop_permissions",
            "ok": sys.platform == "darwin",
            "detail": "macOS Accessibility/Screen Recording must be granted for desktop capture",
        },
    ]
    return {
        "ok": all(item["ok"] for item in checks[:4]),
        "checks": checks,
        "next_steps": _doctor_personal_next_steps(
            home_ok=home_ok,
            config_ok=config_ok,
            hub_token_ok=hub_token_ok,
            hub_ok=hub_ok,
            hub_condition=_hub_failure_condition(hub),
        ),
    }


def _uninstall_dry_run_next_steps(remove_data: bool) -> list[dict[str, str]]:
    """Return placeholder-only safety guidance for ``ardur uninstall --dry-run``.

    The dry-run preview may intentionally include local paths in ``would_remove``
    so users can verify exactly what would be removed. These hints are designed
    to be copy/paste-safe: they use placeholders instead of raw home paths,
    tokens, or receipt/key locations.
    """
    preview_command = "ardur uninstall --home <ardur-home> --dry-run"
    uninstall_command = "ardur uninstall --home <ardur-home>"
    if remove_data:
        preview_command = "ardur uninstall --home <ardur-home> --remove-data --dry-run"
        uninstall_command = "ardur uninstall --home <ardur-home> --remove-data"

    steps = [
        {
            "condition": "uninstall_dry_run",
            "action": "inspect_previewed_removals",
            "command": preview_command,
            "detail": (
                "Review the would_remove list before deleting anything. Dry-run mode "
                "does not remove the LaunchAgent or local Ardur Personal data."
            ),
        },
        {
            "condition": "launch_agent_may_be_running",
            "action": "stop_local_launch_agent_if_running",
            "command": "launchctl bootout gui/<uid> ~/Library/LaunchAgents/dev.ardur.personal-hub.plist",
            "detail": (
                "If the local Hub is running under the per-user LaunchAgent, unload "
                "that local agent before the real uninstall. This affects only the "
                "Ardur Personal LaunchAgent."
            ),
        },
    ]
    if remove_data:
        steps.append(
            {
                "condition": "remove_data_requested",
                "action": "back_up_or_export_local_data",
                "command": "cp -R <ardur-home> <backup-location>",
                "detail": (
                    "--remove-data deletes local Ardur Personal evidence and key "
                    "material. Back up or export anything you need before running the "
                    "real uninstall."
                ),
            }
        )

    steps.append(
        {
            "condition": "preview_confirmed",
            "action": "rerun_uninstall_intentionally",
            "command": uninstall_command,
            "detail": (
                "After reviewing the dry-run preview, rerun without --dry-run only "
                "if the listed removals match your intent. Without --remove-data, "
                "the Ardur Personal home is kept."
            ),
        }
    )
    return steps


def uninstall_personal(args: argparse.Namespace) -> dict[str, Any]:
    paths = HubPaths.from_home(args.home)
    launch_agent = (
        Path.home() / "Library" / "LaunchAgents" / "dev.ardur.personal-hub.plist"
    )
    would_remove = []
    if launch_agent.exists():
        would_remove.append(str(launch_agent))
    if args.remove_data and paths.home.exists():
        would_remove.append(str(paths.home))

    if getattr(args, "dry_run", False):
        return {
            "ok": True,
            "dry_run": True,
            "would_remove": would_remove,
            "removed": [],
            "data_kept": True,
            "would_keep_data": not args.remove_data,
            "next_steps": _uninstall_dry_run_next_steps(bool(args.remove_data)),
        }

    removed = []
    if launch_agent.exists():
        launch_agent.unlink()
        removed.append(str(launch_agent))
    if args.remove_data and paths.home.exists():
        shutil.rmtree(paths.home)
        removed.append(str(paths.home))
    return {"ok": True, "removed": removed, "data_kept": not args.remove_data}


def run_under_hub(args: argparse.Namespace) -> int:
    json_mode = bool(getattr(args, "json", False))
    command = list(args.command or [])
    if not command:
        if json_mode:
            _emit_json_error_to_stderr(
                {
                    "ok": False,
                    "error": "missing_run_command",
                    "error_code": "missing_run_command",
                    "condition": "missing_run_command",
                    "message": "ardur run requires a command after --",
                    "next_steps": run_missing_command_next_steps(),
                }
            )
            return 1
        print("ardur run requires a command after --", file=sys.stderr)
        _print_run_missing_command_next_steps()
        return 2

    # Validate --home before any Hub I/O.  ``--home`` is ``type=str`` on the
    # CLI parser so an empty or whitespace-only value reaches here as-is
    # (instead of being silently normalised to ``Path('.')`` by argparse).
    # ``None`` means the flag was omitted and the default home should be used.
    home_arg = getattr(args, "home", None)
    if home_arg is not None and not str(home_arg).strip():
        if json_mode:
            _emit_json_error_to_stderr(
                {
                    "ok": False,
                    "error": "home_arg_invalid",
                    "error_code": "home_arg_invalid",
                    "condition": "home_arg_invalid",
                    "message": "ardur run --home must be a non-empty path after trimming whitespace.",
                    "next_steps": [
                        {
                            "condition": "home_arg_invalid",
                            "action": "pass_a_directory_or_nonexistent_path",
                            "command": 'ardur run --home <ardur-home> --mission "..." -- <agent-cmd...>',
                            "detail": (
                                "Pass a path that is either nonexistent (it will be created) or "
                                "an existing directory. Empty or whitespace-only values are rejected."
                            ),
                        }
                    ],
                }
            )
            return 1
        print(
            "ardur run --home must be a non-empty path after trimming whitespace.",
            file=sys.stderr,
        )
        print(
            'usage: ardur run --home <ardur-home> --mission "..." -- <agent-cmd...>',
            file=sys.stderr,
        )
        return 2

    session_id = f"cli:{uuid.uuid4()}"
    start_payload = {
        "source": {"type": "cli", "app": command[0], "process": " ".join(command)},
        "session": {"id": session_id, "title": " ".join(command)},
    }
    try:
        token = resolve_hub_token(
            home=getattr(args, "home", None), explicit=getattr(args, "hub_token", None)
        )
    except HubError as exc:
        mapped = _personal_home_failure_response_for(exc)
        if mapped is not None:
            _print_json_response(mapped)
            return 1
        raise
    start = hub_request(
        "POST",
        "/v1/sessions/start",
        start_payload,
        hub_url=args.hub_url,
        hub_token=token,
        home=getattr(args, "home", None),
    )
    if not start.get("ok"):
        if json_mode:
            condition = _run_failure_support_condition(start, phase="session_start")
            _emit_json_error_to_stderr(
                {
                    "ok": False,
                    "error": condition,
                    "error_code": condition,
                    "condition": condition,
                    "message": _run_failure_summary_line(start, phase="session_start"),
                    "next_steps": run_recovery_next_steps_for_response(
                        start, phase="session_start"
                    ),
                }
            )
            return 1
        print(_run_failure_summary_line(start, phase="session_start"), file=sys.stderr)
        _print_run_recovery_next_steps(start, phase="session_start")
        return 127
    check_payload = {
        **start_payload,
        "event": {
            "kind": "cli_command",
            "action_class": "observe",
            "target": command[0],
            "command": command,
            "raw_content_included": False,
        },
    }
    check = hub_request(
        "POST",
        "/v1/policy/check",
        check_payload,
        hub_url=args.hub_url,
        hub_token=token,
        home=getattr(args, "home", None),
    )
    if not check.get("ok"):
        if json_mode:
            condition = _run_failure_support_condition(check, phase="policy_check")
            _emit_json_error_to_stderr(
                {
                    "ok": False,
                    "error": condition,
                    "error_code": condition,
                    "condition": condition,
                    "message": _run_failure_summary_line(check, phase="policy_check"),
                    "next_steps": run_recovery_next_steps_for_response(
                        check, phase="policy_check"
                    ),
                }
            )
            return 1
        print(_run_failure_summary_line(check, phase="policy_check"), file=sys.stderr)
        _print_run_recovery_next_steps(check, phase="policy_check")
        return 127
    policy = _dict(check.get("policy"))
    if policy.get("verdict") == "blocked":
        observe = hub_request(
            "POST",
            "/v1/events/observe",
            check_payload,
            hub_url=args.hub_url,
            hub_token=token,
            home=getattr(args, "home", None),
        )
        if json_mode:
            _emit_json_error_to_stderr(
                {
                    "ok": False,
                    "error": "policy_blocked",
                    "error_code": "policy_blocked",
                    "condition": "policy_blocked",
                    "message": _blocked_command_summary_line(policy),
                    "receipt": _dict(observe.get("receipt")),
                }
            )
            return 1
        print(_blocked_command_summary_line(policy), file=sys.stderr)
        _emit_run_audit_reference_for_user_output(observe)
        return 126

    started = time.time()
    completed = _stream_subprocess(command)
    duration_ms = int((time.time() - started) * 1000)
    observe_payload = {
        **check_payload,
        "event": {
            **check_payload["event"],
            "exit_code": completed.returncode,
            "duration_ms": duration_ms,
            "stdout_digest": completed.stdout_digest,
            "stderr_digest": completed.stderr_digest,
            "stdout_bytes": completed.stdout_bytes,
            "stderr_bytes": completed.stderr_bytes,
            "content_digest": _sha256_text(
                " ".join(command) + str(completed.returncode)
            ),
        },
    }
    hub_request(
        "POST",
        "/v1/events/observe",
        observe_payload,
        hub_url=args.hub_url,
        hub_token=token,
        home=getattr(args, "home", None),
    )
    return completed.returncode


def desktop_observe(args: argparse.Namespace) -> dict[str, Any]:
    # Validate the Personal home before any macOS Accessibility/Screen Recording
    # probe: an empty/whitespace --home must fail closed with structured JSON
    # rather than blocking on an osascript permission dialog first.
    _resolve_personal_home(getattr(args, "home", None))
    app = args.app
    title = args.title
    permission_note = None
    if sys.platform == "darwin" and (not app or not title):
        script = (
            'tell application "System Events"\n'
            "set frontApp to name of first application process whose frontmost is true\n"
            'set winTitle to ""\n'
            "try\n"
            "set winTitle to name of front window of first application process whose frontmost is true\n"
            "end try\n"
            'return frontApp & "\\n" & winTitle\n'
            "end tell"
        )
        result = subprocess.run(
            ["osascript", "-e", script], capture_output=True, text=True
        )
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            app = app or (lines[0] if lines else "Unknown")
            title = title or (lines[1] if len(lines) > 1 else "")
        else:
            permission_note = (
                result.stderr.strip() or "macOS Accessibility permission unavailable"
            )
    text = args.text or ""
    payload = {
        "source": {
            "type": "desktop",
            "app": app or "Unknown",
            "process": app or "Unknown",
        },
        "session": {
            "id": args.session_id or f"desktop:{app or 'unknown'}",
            "title": title or "",
        },
        "event": {
            "kind": "desktop_observation",
            "action_class": "observe",
            "target": title or app or "desktop",
            "capture_mode": "structured_visible_text" if text else "digest_only",
            "text_snapshot_included": bool(text),
            "text_excerpt": _clip(text),
            "content_digest": _sha256_text(
                text or f"{app}:{title}:{permission_note or ''}"
            ),
            "raw_content_included": False,
            "consent": {"visible_text": bool(text)},
            "hidden_provider_activity": True,
        },
    }
    try:
        token = resolve_hub_token(
            home=getattr(args, "home", None), explicit=getattr(args, "hub_token", None)
        )
    except HubError as exc:
        mapped = _personal_home_failure_response_for(exc)
        if mapped is not None:
            return mapped
        raise
    response = hub_request(
        "POST",
        "/v1/events/observe",
        payload,
        hub_url=args.hub_url,
        hub_token=token,
        home=getattr(args, "home", None),
    )
    response = desktop_observe_response_with_next_steps(response)
    if permission_note:
        response["permission_note"] = permission_note
    return response
