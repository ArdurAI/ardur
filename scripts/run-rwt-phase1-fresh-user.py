#!/usr/bin/env python3
"""Run the Phase 1 fresh-user real-world-test harness for Ardur.

This harness intentionally exercises installed ``ardur`` CLI entrypoints from a
fresh virtualenv and temporary HOME/project/evidence directories. It preserves a
redacted evidence bundle and never copies raw active Mission JWTs, private keys,
provider tokens, real HOME config, or Claude credentials into shareable output.

Covered gates:
- RWT-1: fresh-user source/local-wheel install, ARDUR.md, protect, doctor.
- RWT-2: fixture/integration hook proof through the actual ``ardur`` CLI.
- RWT-3: honest live Claude preflight semantics without login/account changes.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping, Sequence

_REPO_ROOT_FOR_IMPORTS = Path(__file__).resolve().parents[1]


def _load_shareable_redaction_module() -> ModuleType:
    module_path = _REPO_ROOT_FOR_IMPORTS / "python" / "vibap" / "shareable_redaction.py"
    spec = importlib.util.spec_from_file_location("_ardur_shareable_redaction", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load shareable redaction helper from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_SHAREABLE_REDACTION = _load_shareable_redaction_module()
LOCAL_PATH_LEAK_MARKERS = _SHAREABLE_REDACTION.LOCAL_PATH_LEAK_MARKERS
local_path_leak_hits = _SHAREABLE_REDACTION.local_path_leak_hits
local_path_root_marker = _SHAREABLE_REDACTION.local_path_root_marker
canonical_path_aliases = _SHAREABLE_REDACTION.path_aliases
redact_local_path_text = _SHAREABLE_REDACTION.redact_local_path_text
redact_local_paths = _SHAREABLE_REDACTION.redact_local_paths
replace_path_roots = _SHAREABLE_REDACTION.replace_path_roots

SCHEMA_VERSION = "ardur.real_world_test_bundle.v0.1"
STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_SKIP_UNSUPPORTED = "SKIP_UNSUPPORTED"
STATUS_SKIP_GATED = "SKIP_GATED"
STATUS_BLOCKED = "BLOCKED"
STATUS_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"

SECRET_VALUE_PLACEHOLDER = "[REDACTED]"
PRIVATE_KEY_PLACEHOLDER = "[REDACTED PRIVATE KEY]"
JWT_PLACEHOLDER = "[REDACTED JWT]"

AUTHORIZATION_BEARER_PATTERN = re.compile(
    r"(?i)(?P<prefix>[\"']?authorization[\"']?\s*[:=]\s*)(?P<quote>[\"']?)bearer\s+(?P<token>[^\s,\"']+)(?P=quote)",
)
KEY_VALUE_QUOTED_PATTERN = re.compile(
    r"(?P<prefix>[\"']?(?P<key>[A-Za-z0-9_-]+)[\"']?\s*[:=]\s*)(?P<quote>[\"'])(?P<value>.*?)(?P=quote)",
)
KEY_VALUE_UNQUOTED_PATTERN = re.compile(
    r"(?P<prefix>[\"']?(?P<key>[A-Za-z0-9_-]+)[\"']?\s*=\s*)(?P<value>(?![\"'])[^\s,}\]#&]+)",
)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
BARE_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}")
URL_TOKEN_QUERY_PATTERN = re.compile(r"(?i)([?&](?:token|access_token|auth_token|api_key)=)([^&#\s]+)")

REDACTION_PATTERN_NAMES = [
    "secret_key_value",
    "authorization_bearer",
    "private_key",
    "bare_jwt",
    "url_token_query",
]

PATH_REDACTION_PATTERN_NAMES = [
    "context_root_placeholders",
    "generic_local_absolute_paths",
    "local_file_uris",
    "post_write_path_leak_scan",
]

SHAREABLE_ARTIFACT_KEYS = ("fixtures", "reports", "redacted_stdout_files")

PATH_PLACEHOLDER_REPO = "<REPO>"
PATH_PLACEHOLDER_RWT_TEMP = "<RWT_TEMP>"
PATH_PLACEHOLDER_RWT_HOME = "<RWT_HOME>"
PATH_PLACEHOLDER_RWT_ARDUR_HOME = "<RWT_ARDUR_HOME>"
PATH_PLACEHOLDER_RWT_PROJECT = "<RWT_PROJECT>"
PATH_PLACEHOLDER_RWT_EVIDENCE = "<RWT_EVIDENCE>"
PATH_PLACEHOLDER_RWT_OUTPUT = "<RWT_OUTPUT>"
PATH_PLACEHOLDER_PYTHON = "<PYTHON>"
PATH_PLACEHOLDER_ARDUR_BIN = "<ARDUR_BIN>"

ABSOLUTE_PATH_LEAK_MARKERS = LOCAL_PATH_LEAK_MARKERS


@dataclass
class CommandRecord:
    id: str
    cwd: str
    argv_redacted: list[str]
    exit_code: int
    stdout_redacted_path: str
    stderr_redacted_path: str
    elapsed_ms: int


@dataclass
class GateResult:
    rwt_id: str
    classification: list[str]
    status: str
    summary: str
    assertions: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    residual_risk: list[str] = field(default_factory=list)


@dataclass
class HarnessContext:
    repo: Path
    output_dir: Path
    expected_origin_dev: str | None
    allow_dirty: bool
    keep_temp: bool
    operator_profile: str
    started_at: str
    temp_root: Path
    home: Path
    ardur_home: Path
    project: Path
    evidence: Path
    out_dir: Path
    fixtures: Path
    raw_fixtures: Path
    hook_out: Path
    wheelhouse: Path
    venv: Path
    python_bin: str
    ardur_bin: Path
    env: dict[str, str]
    commands: list[CommandRecord] = field(default_factory=list)
    gate_results: list[GateResult] = field(default_factory=list)
    cleanup_temp_root_removed: bool = False
    cleanup_retained_path: str | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[1]


def _normalize_key_name(raw_key: str) -> str:
    key = raw_key.strip().strip("\"'").replace("-", "_").replace(" ", "_")
    key = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)
    key = re.sub(r"_+", "_", key)
    return key.upper()


def _is_secret_key_name(raw_key: str) -> bool:
    key = _normalize_key_name(raw_key)
    if key in {"API_KEY", "TOKEN", "ACCESS_TOKEN", "AUTH_TOKEN", "PASSWORD", "SECRET", "JWT", "PRIVATE_KEY"}:
        return True
    return key.endswith(("_API_KEY", "_TOKEN", "_PASSWORD", "_SECRET", "_JWT"))


def _is_redacted_placeholder(value: str) -> bool:
    cleaned = value.strip().strip("\"'")
    if not cleaned:
        return False
    upper = cleaned.upper()
    if upper in {SECRET_VALUE_PLACEHOLDER, PRIVATE_KEY_PLACEHOLDER, JWT_PLACEHOLDER, "***"}:
        return True
    if upper.startswith(SECRET_VALUE_PLACEHOLDER.rstrip("]")):
        return True
    return upper.startswith(f"BEARER {SECRET_VALUE_PLACEHOLDER}".rstrip("]"))


def _is_authorization_bearer_key(raw_key: str, value: str) -> bool:
    return _normalize_key_name(raw_key) == "AUTHORIZATION" and value.lstrip().lower().startswith("bearer ")


def _redact_key_value_quoted(match: re.Match[str]) -> str:
    key = match.group("key")
    value = match.group("value")
    quote = match.group("quote")
    prefix = match.group("prefix")
    if _is_secret_key_name(key):
        return f"{prefix}{quote}{SECRET_VALUE_PLACEHOLDER}{quote}"
    if _is_authorization_bearer_key(key, value):
        return f"{prefix}{quote}Bearer {SECRET_VALUE_PLACEHOLDER}{quote}"
    return match.group(0)


def _redact_key_value_unquoted(match: re.Match[str]) -> str:
    key = match.group("key")
    value = match.group("value")
    prefix = match.group("prefix")
    if _is_secret_key_name(key):
        return f"{prefix}{SECRET_VALUE_PLACEHOLDER}"
    if _is_authorization_bearer_key(key, value):
        return f"{prefix}Bearer {SECRET_VALUE_PLACEHOLDER}"
    return match.group(0)


def redact_text(text: str) -> str:
    """Redact secret-like material from text destined for shareable evidence."""
    redacted = PRIVATE_KEY_PATTERN.sub(PRIVATE_KEY_PLACEHOLDER, text)
    redacted = AUTHORIZATION_BEARER_PATTERN.sub(
        lambda match: f"{match.group('prefix')}{match.group('quote')}Bearer {SECRET_VALUE_PLACEHOLDER}{match.group('quote')}",
        redacted,
    )
    redacted = URL_TOKEN_QUERY_PATTERN.sub(rf"\1{SECRET_VALUE_PLACEHOLDER}", redacted)
    redacted = KEY_VALUE_QUOTED_PATTERN.sub(_redact_key_value_quoted, redacted)
    redacted = KEY_VALUE_UNQUOTED_PATTERN.sub(_redact_key_value_unquoted, redacted)
    redacted = BARE_JWT_PATTERN.sub(JWT_PLACEHOLDER, redacted)
    return redacted


def secret_scan_hits(text: str) -> list[str]:
    hits: set[str] = set()
    if PRIVATE_KEY_PATTERN.search(text):
        hits.add("private_key")
    for match in AUTHORIZATION_BEARER_PATTERN.finditer(text):
        if not _is_redacted_placeholder(match.group("token")):
            hits.add("authorization_bearer")
    for match in URL_TOKEN_QUERY_PATTERN.finditer(text):
        if not _is_redacted_placeholder(match.group(2)):
            hits.add("url_token_query")
    for match in KEY_VALUE_QUOTED_PATTERN.finditer(text):
        key = match.group("key")
        value = match.group("value")
        if _is_secret_key_name(key) and not _is_redacted_placeholder(value):
            hits.add("secret_key_value")
        if _is_authorization_bearer_key(key, value):
            token = value.split(None, 1)[1] if len(value.split(None, 1)) == 2 else ""
            if token and not _is_redacted_placeholder(token):
                hits.add("authorization_bearer")
    for match in KEY_VALUE_UNQUOTED_PATTERN.finditer(text):
        key = match.group("key")
        value = match.group("value")
        if _is_secret_key_name(key) and not _is_redacted_placeholder(value):
            hits.add("secret_key_value")
        if _is_authorization_bearer_key(key, value):
            token = value.split(None, 1)[1] if len(value.split(None, 1)) == 2 else ""
            if token and not _is_redacted_placeholder(token):
                hits.add("authorization_bearer")
    for match in BARE_JWT_PATTERN.finditer(text):
        if not _is_redacted_placeholder(match.group(0)):
            hits.add("bare_jwt")
    return sorted(hits)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _path_aliases(value: str | Path | None) -> list[str]:
    return canonical_path_aliases(value)


def _path_placeholder_pairs(ctx: HarnessContext | Any) -> list[tuple[str, str]]:
    ordered = [
        (getattr(ctx, "ardur_bin", None), PATH_PLACEHOLDER_ARDUR_BIN),
        (getattr(ctx, "python_bin", None), PATH_PLACEHOLDER_PYTHON),
        (getattr(ctx, "output_dir", None), PATH_PLACEHOLDER_RWT_OUTPUT),
        (getattr(ctx, "ardur_home", None), PATH_PLACEHOLDER_RWT_ARDUR_HOME),
        (getattr(ctx, "home", None), PATH_PLACEHOLDER_RWT_HOME),
        (getattr(ctx, "project", None), PATH_PLACEHOLDER_RWT_PROJECT),
        (getattr(ctx, "evidence", None), PATH_PLACEHOLDER_RWT_EVIDENCE),
        (getattr(ctx, "temp_root", None), PATH_PLACEHOLDER_RWT_TEMP),
        (getattr(ctx, "repo", None), PATH_PLACEHOLDER_REPO),
    ]
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw, placeholder in ordered:
        for alias in _path_aliases(raw):
            if alias in seen:
                continue
            seen.add(alias)
            pairs.append((alias, placeholder))
    pairs.sort(key=lambda item: len(item[0]), reverse=True)
    return pairs


def _replace_path_roots(text: str, pairs: Sequence[tuple[str, str]]) -> str:
    return replace_path_roots(text, pairs)


def redact_path_roots(value: Any, pairs: Sequence[tuple[str, str]]) -> Any:
    return redact_local_paths(value, root_pairs=pairs)


def _path_leak_markers(ctx: HarnessContext | Any) -> list[str]:
    markers: set[str] = set(ABSOLUTE_PATH_LEAK_MARKERS)
    for attr in ["repo", "temp_root", "home", "ardur_home", "project", "evidence", "output_dir", "python_bin", "ardur_bin"]:
        for alias in _path_aliases(getattr(ctx, attr, None)):
            if alias.startswith("/"):
                markers.add(alias)
    return sorted(markers, key=len, reverse=True)


def path_leak_scan_hits(text: str, ctx: HarnessContext | Any) -> list[str]:
    return local_path_leak_hits(text, extra_markers=_path_leak_markers(ctx))


def _ensure_redaction_payload(bundle: dict[str, Any]) -> dict[str, Any]:
    redaction = bundle.setdefault("redaction", {})
    notes = redaction.get("notes")
    if not isinstance(notes, list):
        redaction["notes"] = []
    redaction.setdefault("secret_scan_hits", 0)
    redaction.setdefault("path_scan_hits", 0)
    redaction.setdefault("path_patterns_applied", PATH_REDACTION_PATTERN_NAMES)
    redaction.setdefault(
        "path_redaction_scope",
        "shareable_artifacts_only:local_absolute_paths,configured_context_roots,file_uri_targets",
    )
    return redaction


def _append_redaction_note(bundle: dict[str, Any], note: str) -> None:
    redaction_payload = _ensure_redaction_payload(bundle)
    if note not in redaction_payload["notes"]:
        redaction_payload["notes"].append(note)


def _secret_hit_categories(hits: Sequence[str]) -> list[str]:
    return sorted({f"secret_pattern:{hit}" for hit in hits})


def _path_hit_categories(hits: Sequence[str], ctx: HarnessContext | Any) -> list[str]:
    categories: set[str] = set()
    aliases: dict[str, str] = {}
    for alias, placeholder in _path_placeholder_pairs(ctx):
        aliases[alias] = placeholder
    for hit in hits:
        placeholder = aliases.get(hit)
        if placeholder:
            categories.add(f"ctx_path_marker:{placeholder}")
        elif hit.startswith("file://"):
            categories.add(f"file_uri_marker:{local_path_root_marker(hit)}")
        elif hit.startswith("/private/var/folders"):
            categories.add("absolute_path_marker:/private/var/folders")
        elif hit.startswith("/var/folders"):
            categories.add("absolute_path_marker:/var/folders")
        elif hit.startswith("/private/tmp"):
            categories.add("absolute_path_marker:/private/tmp")
        elif hit.startswith("/tmp"):
            categories.add("absolute_path_marker:/tmp")
        elif hit.startswith("/Users"):
            categories.add("absolute_path_marker:/Users")
        elif hit.startswith("/home"):
            categories.add("absolute_path_marker:/home")
        else:
            categories.add("absolute_path_marker:unknown")
    return sorted(categories)


def _redact_generic_absolute_paths(text: str) -> str:
    return redact_local_path_text(text)


def redact_shareable_text(text: str, ctx: HarnessContext | Any) -> str:
    return redact_local_path_text(redact_text(text), root_pairs=_path_placeholder_pairs(ctx))


def sanitize_shareable_value(value: Any, ctx: HarnessContext | Any) -> Any:
    if isinstance(value, str):
        return redact_shareable_text(value, ctx)
    if isinstance(value, list):
        return [sanitize_shareable_value(item, ctx) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_shareable_value(item, ctx) for item in value)
    if isinstance(value, dict):
        return {key: sanitize_shareable_value(item, ctx) for key, item in value.items()}
    return value


def _safe_failure_bundle(ctx: HarnessContext | Any, notes: Sequence[str], secret_scan_hits_count: int = 0) -> dict[str, Any]:
    safe_notes = sorted({_redact_generic_absolute_paths(redact_text(str(note))) for note in notes})
    bundle = {
        "schema_version": SCHEMA_VERSION,
        "rwt_id": "RWT-1+RWT-2+RWT-3-preflight",
        "status": STATUS_FAIL,
        "public_actions": "none",
        "privileged_actions": "none",
        "redaction": {
            "raw_secret_values_copied": False,
            "patterns_applied": REDACTION_PATTERN_NAMES,
            "path_patterns_applied": PATH_REDACTION_PATTERN_NAMES,
            "path_redaction_scope": "shareable_artifacts_only:local_absolute_paths,configured_context_roots,file_uri_targets",
            "path_scan_hits": 0,
            "secret_scan_hits": secret_scan_hits_count,
            "notes": safe_notes,
        },
    }
    return sanitize_shareable_value(bundle, ctx)


def finalize_shareable_bundle(bundle: dict[str, Any], ctx: HarnessContext | Any, stage: str) -> dict[str, Any]:
    """Return a shareable bundle that contains only redacted paths/secrets.

    If the normal structured payload still trips a leak scan after sanitization,
    fall back to a minimal failure bundle that preserves categorical diagnostics
    without persisting the raw path/secret values that triggered the scan.
    """

    bundle = sanitize_shareable_value(bundle, ctx)
    text = json.dumps(bundle, indent=2, sort_keys=True)
    secret_hits = secret_scan_hits(text)
    path_hits = path_leak_scan_hits(text, ctx)
    if not secret_hits and not path_hits:
        return bundle

    bundle["status"] = STATUS_FAIL
    if secret_hits:
        redaction_payload = _ensure_redaction_payload(bundle)
        try:
            redaction_payload["secret_scan_hits"] = max(int(redaction_payload.get("secret_scan_hits") or 0), len(secret_hits))
        except (TypeError, ValueError):
            redaction_payload["secret_scan_hits"] = len(secret_hits)
        _append_redaction_note(bundle, f"{stage} secret scan categories: {_secret_hit_categories(secret_hits)}")
    if path_hits:
        redaction_payload = _ensure_redaction_payload(bundle)
        try:
            redaction_payload["path_scan_hits"] = max(int(redaction_payload.get("path_scan_hits") or 0), len(path_hits))
        except (TypeError, ValueError):
            redaction_payload["path_scan_hits"] = len(path_hits)
        _append_redaction_note(bundle, f"{stage} path leak scan categories: {_path_hit_categories(path_hits, ctx)}")

    bundle = sanitize_shareable_value(bundle, ctx)
    text = json.dumps(bundle, indent=2, sort_keys=True)
    final_secret_hits = secret_scan_hits(text)
    final_path_hits = path_leak_scan_hits(text, ctx)
    if not final_secret_hits and not final_path_hits:
        return bundle

    redaction_payload = _ensure_redaction_payload(bundle)
    notes = list(redaction_payload.get("notes") or [])
    if final_secret_hits:
        notes.append(f"{stage} safe serialization fallback after secret scan categories: {_secret_hit_categories(final_secret_hits)}")
    if final_path_hits:
        notes.append(f"{stage} safe serialization fallback after path leak categories: {_path_hit_categories(final_path_hits, ctx)}")
    return _safe_failure_bundle(ctx, notes, max(len(secret_hits), len(final_secret_hits)))


def run_capture(
    ctx: HarnessContext,
    command_id: str,
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
    input_path: Path | None = None,
    allowed_exit_codes: set[int] | None = None,
) -> subprocess.CompletedProcess[str]:
    if input_text is not None and input_path is not None:
        raise ValueError("only one of input_text/input_path is allowed")
    allowed = {0} if allowed_exit_codes is None else set(allowed_exit_codes)
    stdout_path = ctx.out_dir / f"{command_id}.stdout.txt"
    stderr_path = ctx.out_dir / f"{command_id}.stderr.txt"
    start = time.perf_counter()
    stdin_payload = input_text
    if input_path is not None:
        stdin_payload = input_path.read_text(encoding="utf-8")
    result = subprocess.run(
        list(argv),
        cwd=str(cwd),
        env=dict(env or ctx.env),
        input=stdin_payload,
        text=True,
        capture_output=True,
        check=False,
    )
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    stdout_path.write_text(redact_shareable_text(result.stdout, ctx), encoding="utf-8")
    stderr_path.write_text(redact_shareable_text(result.stderr, ctx), encoding="utf-8")
    ctx.commands.append(
        CommandRecord(
            id=command_id,
            cwd=redact_shareable_text(str(cwd), ctx),
            argv_redacted=[redact_shareable_text(str(part), ctx) for part in argv],
            exit_code=result.returncode,
            stdout_redacted_path=relpath(stdout_path, ctx.output_dir),
            stderr_redacted_path=relpath(stderr_path, ctx.output_dir),
            elapsed_ms=elapsed_ms,
        )
    )
    if result.returncode not in allowed:
        stderr = redact_shareable_text(result.stderr.strip()[:500], ctx)
        raise RuntimeError(f"{command_id} exited {result.returncode}; stderr={stderr}")
    return result


def run_raw(argv: Sequence[str], *, cwd: Path, allowed_exit_codes: set[int] | None = None) -> subprocess.CompletedProcess[str]:
    allowed = {0} if allowed_exit_codes is None else set(allowed_exit_codes)
    result = subprocess.run(list(argv), cwd=str(cwd), text=True, capture_output=True, check=False)
    if result.returncode not in allowed:
        raise RuntimeError(f"command {argv!r} exited {result.returncode}: {result.stderr.strip()}")
    return result


def short_git(repo: Path, *args: str) -> str:
    return run_raw(["git", *args], cwd=repo).stdout.strip()[:12]


def git_text(repo: Path, *args: str) -> str:
    return run_raw(["git", *args], cwd=repo).stdout.strip()


def git_success(repo: Path, *args: str) -> bool:
    return run_raw(["git", *args], cwd=repo, allowed_exit_codes={0, 1}).returncode == 0


def detect_python(candidate: str | None = None) -> str:
    candidates: list[str] = []
    if candidate:
        candidates.append(candidate)
    if sys.version_info >= (3, 10):
        candidates.append(sys.executable)
    candidates.extend(["python3.13", "python3.12", "python3.11", "python3.10"])
    seen: set[str] = set()
    for item in candidates:
        if item in seen:
            continue
        seen.add(item)
        resolved = shutil.which(item) if not Path(item).is_absolute() else item
        if not resolved:
            continue
        version = subprocess.run(
            [resolved, "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"],
            text=True,
            capture_output=True,
            check=False,
        )
        if version.returncode != 0:
            continue
        major, minor = (int(part) for part in version.stdout.strip().split(".")[:2])
        if (major, minor) >= (3, 10):
            return resolved
    raise RuntimeError("Python >=3.10 is required for the Ardur package")


def build_env(ctx: HarnessContext) -> dict[str, str]:
    keep_keys = ["PATH", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"]
    env = {key: value for key, value in os.environ.items() if key in keep_keys and value}
    env.update(
        {
            "HOME": str(ctx.home),
            "VIBAP_HOME": str(ctx.ardur_home),
            "ARDUR_CC_HOOK_DIR": str(ctx.ardur_home / "claude-code-hook"),
            "ARDUR_TRACE_ID": "rwt2-trace-fixture",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PYTHONIOENCODING": "utf-8",
        }
    )
    return env


def prepare_context(args: argparse.Namespace) -> HarnessContext:
    repo = Path(args.repo).expanduser().resolve()
    started = utc_now()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = (
        Path(args.output_dir).expanduser().resolve()
        if args.output_dir
        else repo / "reports" / "evidence" / f"{stamp}-rwt-phase1-fresh-user"
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    temp_root = Path(tempfile.mkdtemp(prefix="ardur-rwt-phase1.")).resolve()
    ctx = HarnessContext(
        repo=repo,
        output_dir=output_dir,
        expected_origin_dev=args.expected_origin_dev,
        allow_dirty=args.allow_dirty,
        keep_temp=args.keep_temp,
        operator_profile=args.operator_profile,
        started_at=started,
        temp_root=temp_root,
        home=temp_root / "home",
        ardur_home=temp_root / "ardur-home",
        project=temp_root / "project",
        evidence=temp_root / "evidence",
        out_dir=output_dir / "out",
        fixtures=output_dir / "fixtures",
        raw_fixtures=temp_root / "raw-fixtures",
        hook_out=output_dir / "hook-out",
        wheelhouse=temp_root / "wheelhouse",
        venv=temp_root / "venv",
        python_bin=detect_python(args.python),
        ardur_bin=temp_root / "venv" / "bin" / "ardur",
        env={},
    )
    for path in (ctx.home, ctx.ardur_home, ctx.project, ctx.evidence, ctx.out_dir, ctx.fixtures, ctx.raw_fixtures, ctx.hook_out, ctx.wheelhouse):
        path.mkdir(parents=True, exist_ok=True)
    ctx.env = build_env(ctx)
    return ctx


def validate_repo_preflight(ctx: HarnessContext) -> tuple[dict[str, Any], str | None]:
    if not (ctx.repo / ".git").exists():
        return {}, f"repo is not a git worktree: {ctx.repo}"
    head = short_git(ctx.repo, "rev-parse", "HEAD")
    origin_dev = short_git(ctx.repo, "rev-parse", "origin/dev")
    status = git_text(ctx.repo, "status", "--short")
    expected = ctx.expected_origin_dev or origin_dev
    origin_dev_ancestor = head == origin_dev or git_success(ctx.repo, "merge-base", "--is-ancestor", "origin/dev", "HEAD")
    repo_info = {
        "worktree": str(ctx.repo),
        "head": head,
        "origin_dev": origin_dev,
        "expected_origin_dev": expected,
        "origin_dev_ancestor_of_head": origin_dev_ancestor,
        "clean_before": status == "",
        "dirty_paths_before": redact_text(status).splitlines() if status else [],
    }
    if origin_dev != expected:
        return repo_info, f"stale origin/dev: expected {expected} got {origin_dev}"
    if not origin_dev_ancestor and not ctx.allow_dirty:
        return repo_info, f"test worktree does not contain origin/dev: head={head} origin/dev={origin_dev}"
    if head != origin_dev and not status:
        repo_info["preflight_note"] = "clean local candidate commit contains origin/dev; public repository state was not mutated"
    if status and not ctx.allow_dirty:
        return repo_info, f"test worktree is dirty: {status}"
    if status and ctx.allow_dirty:
        repo_info["preflight_note"] = "dirty worktree allowed for in-progress harness development; not release-gate evidence"
    return repo_info, None


def _find_symlinks(root: Path) -> list[Path]:
    links: list[Path] = []
    if root.is_symlink():
        links.append(root)
        return links
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        for name in [*dirnames, *filenames]:
            candidate = base / name
            if candidate.is_symlink():
                links.append(candidate)
    return sorted(links)


def copy_python_source_for_wheel(ctx: HarnessContext) -> Path:
    """Copy the Python package into temp state before building a wheel.

    Setuptools may create ``build/`` or ``*.egg-info`` side effects next to the
    source tree passed to ``pip wheel``. The RWT harness must exercise a source /
    local-wheel install without mutating the tested repo, so build from a temp
    copy and keep all packaging side effects under ``ctx.temp_root``.

    The source copy fails closed when symlinks are present so future tracked or
    dirty symlink paths cannot be silently dereferenced into the wheel context.
    """
    source = ctx.repo / "python"
    symlinks = _find_symlinks(source)
    if symlinks:
        rel_links = [relpath(path, source) for path in symlinks]
        raise RuntimeError(f"refusing to copy python source containing symlinks: {rel_links}")
    destination = ctx.temp_root / "source" / "python"
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns("build", "*.egg-info", "__pycache__", ".pytest_cache"),
    )
    return destination


def install_ardur(ctx: HarnessContext) -> None:
    run_capture(ctx, "venv-create", [ctx.python_bin, "-m", "venv", str(ctx.venv)], cwd=ctx.repo)
    venv_python = ctx.venv / "bin" / "python"
    run_capture(ctx, "pip-upgrade", [str(venv_python), "-m", "pip", "install", "--upgrade", "pip", "wheel", "setuptools"], cwd=ctx.repo)
    package_source = copy_python_source_for_wheel(ctx)
    run_capture(ctx, "pip-wheel-ardur", [str(venv_python), "-m", "pip", "wheel", str(package_source), "-w", str(ctx.wheelhouse)], cwd=ctx.repo)
    run_capture(
        ctx,
        "pip-install-ardur",
        [str(venv_python), "-m", "pip", "install", "--no-index", "--find-links", str(ctx.wheelhouse), "ardur"],
        cwd=ctx.repo,
    )


def run_rwt1(ctx: HarnessContext) -> GateResult:
    assertions: list[str] = []
    notes: list[str] = []
    residual: list[str] = []
    try:
        (ctx.project / "README.md").write_text("# RWT project\n\nThis is a temporary Ardur first-run project.\n", encoding="utf-8")
        run_capture(ctx, "rwt1-ardur-help", [str(ctx.ardur_bin), "--help"], cwd=ctx.project)
        assertions.append("ardur --help exited 0")
        profile_result = run_capture(
            ctx,
            "rwt1-profile-init",
            [str(ctx.ardur_bin), "profile", "init", "--template", "read-only", "--path", str(ctx.project / "ARDUR.md"), "--json"],
            cwd=ctx.project,
        )
        profile = json.loads(profile_result.stdout)
        if Path(profile["path"]).name != "ARDUR.md" or not (ctx.project / "ARDUR.md").is_file():
            raise AssertionError(f"profile did not create ARDUR.md in project: {profile}")
        assertions.append("profile init created temp-project ARDUR.md")
        protect_result = run_capture(
            ctx,
            "rwt1-protect-claude-code",
            [
                str(ctx.ardur_bin),
                "protect",
                "claude-code",
                "--scope",
                str(ctx.project),
                "--profile",
                str(ctx.project / "ARDUR.md"),
                "--mode",
                "read-only",
                "--json",
                "--home",
                str(ctx.ardur_home),
                "--plugin-dir",
                str(ctx.repo / "plugins" / "claude-code"),
                "--keys-dir",
                str(ctx.ardur_home / "keys"),
                "--agent-id",
                "rwt-terminal-user:claude-code",
                "--mission",
                "RWT-1 read-only review of the temporary project",
                "--max-tool-calls",
                "25",
                "--max-duration-s",
                "3600",
            ],
            cwd=ctx.project,
        )
        protect = json.loads(protect_result.stdout)
        active_path = Path(protect.get("active_mission_path") or protect.get("active_passport") or "")
        if not active_path.is_file() or active_path.resolve() != (ctx.ardur_home / "active_mission.jwt").resolve():
            raise AssertionError("protect did not write active Mission Passport under temp Ardur home")
        if Path(protect.get("plugin_dir", "")).resolve() != (ctx.repo / "plugins" / "claude-code").resolve():
            raise AssertionError("protect output did not reference the expected plugin dir")
        assertions.append("protect agent wrote active Mission Passport under temp Ardur home")
        doctor = run_capture(
            ctx,
            "rwt1-doctor-claude-code",
            [str(ctx.ardur_bin), "doctor-claude-code", "--home", str(ctx.ardur_home), "--plugin-dir", str(ctx.repo / "plugins" / "claude-code")],
            cwd=ctx.project,
            allowed_exit_codes={0, 1},
        )
        if "Traceback" in doctor.stderr:
            raise AssertionError("doctor crashed with traceback")
        doctor_json = json.loads(doctor.stdout)
        checks = {check.get("name"): check for check in doctor_json.get("checks", []) if isinstance(check, dict)}
        for required in ["plugin_dir", "plugin_manifest", "plugin_hooks", "pre_tool_use", "post_tool_use", "active_passport"]:
            if not checks.get(required, {}).get("ok"):
                raise AssertionError(f"doctor missing required OK check: {required}: {checks.get(required)}")
        if not checks.get("claude_binary", {}).get("ok"):
            notes.append("doctor reports claude binary missing; allowed for RWT-1 and represented separately in RWT-3")
        assertions.append("doctor produced actionable JSON and found plugin/passport files")
        return GateResult("RWT-1", ["fresh-user", "integration", "matrix"], STATUS_PASS, "fresh-user install/profile/protect/doctor path passed", assertions, notes, residual)
    except Exception as exc:  # noqa: BLE001 - bundle should preserve failure instead of hiding it.
        return GateResult("RWT-1", ["fresh-user", "integration", "matrix"], STATUS_FAIL, f"RWT-1 failed: {redact_text(str(exc))}", assertions, notes, residual)


def _raw_rwt2_fixtures_dir(ctx: HarnessContext | Any) -> Path:
    raw = getattr(ctx, "raw_fixtures", None)
    if raw is not None:
        return Path(raw)
    temp_root = getattr(ctx, "temp_root", None)
    if temp_root is not None:
        return Path(temp_root) / "raw-fixtures"
    return Path(ctx.fixtures)


def _raw_rwt2_fixture_path(ctx: HarnessContext | Any, name: str) -> Path:
    return _raw_rwt2_fixtures_dir(ctx) / name


def write_rwt2_fixtures(ctx: HarnessContext) -> None:
    raw_fixtures = _raw_rwt2_fixtures_dir(ctx)
    raw_fixtures.mkdir(parents=True, exist_ok=True)
    ctx.fixtures.mkdir(parents=True, exist_ok=True)
    transcript = str(raw_fixtures / "transcript.jsonl")
    base: dict[str, Any] = {
        "session_id": "rwt2-claude-session",
        "transcript_path": transcript,
        "cwd": str(ctx.project),
        "permission_mode": "default",
    }
    fixtures: dict[str, dict[str, Any]] = {
        "pre_read.json": {
            **base,
            "hook_event_name": "PreToolUse",
            "tool_use_id": "read-1",
            "tool_name": "Read",
            "tool_input": {"file_path": str(ctx.project / "README.md")},
        },
        "pre_write.json": {
            **base,
            "hook_event_name": "PreToolUse",
            "tool_use_id": "write-1",
            "tool_name": "Write",
            "tool_input": {"file_path": str(ctx.project / "SHOULD_NOT_EXIST.txt"), "content": "should be blocked"},
        },
        "pre_bash.json": {
            **base,
            "hook_event_name": "PreToolUse",
            "tool_use_id": "bash-1",
            "tool_name": "Bash",
            "tool_input": {"command": "pwd"},
        },
        "post_read.json": {
            **base,
            "hook_event_name": "PostToolUse",
            "tool_use_id": "read-1",
            "tool_name": "Read",
            "tool_input": {"file_path": str(ctx.project / "README.md")},
            "tool_response": {"content_digest": "sha-256:" + "0" * 64, "raw_content_included": False},
        },
    }
    for name, payload in fixtures.items():
        (raw_fixtures / name).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        shareable_payload = sanitize_shareable_value(payload, ctx)
        (ctx.fixtures / name).write_text(json.dumps(shareable_payload, indent=2), encoding="utf-8")


def load_hook_output(ctx: HarnessContext, stem: str) -> dict[str, Any]:
    return json.loads((ctx.out_dir / f"rwt2-{stem}.stdout.txt").read_text(encoding="utf-8"))


def run_rwt2(ctx: HarnessContext) -> GateResult:
    assertions: list[str] = []
    notes: list[str] = []
    residual: list[str] = []
    try:
        write_rwt2_fixtures(ctx)
        hook_env = dict(ctx.env)
        hook_env["ARDUR_TRACE_ID"] = "rwt2-trace-fixture"
        for stem, phase, fixture in [
            ("pre-read", "pre", "pre_read.json"),
            ("post-read", "post", "post_read.json"),
            ("pre-write", "pre", "pre_write.json"),
            ("pre-bash", "pre", "pre_bash.json"),
        ]:
            run_capture(
                ctx,
                f"rwt2-{stem}",
                [str(ctx.ardur_bin), "claude-code-hook", phase, "--keys-dir", str(ctx.ardur_home / "keys")],
                cwd=ctx.project,
                env=hook_env,
                input_path=_raw_rwt2_fixture_path(ctx, fixture),
            )
        read = load_hook_output(ctx, "pre-read")
        post = load_hook_output(ctx, "post-read")
        write = load_hook_output(ctx, "pre-write")
        bash = load_hook_output(ctx, "pre-bash")
        if read.get("continue") is not True or "receipt" not in read.get("systemMessage", "").lower():
            raise AssertionError(f"allowed Read did not continue with receipt message: {read}")
        assertions.append("allowed Read PreToolUse returned continue true and receipt message")
        if post.get("continue") is not True:
            raise AssertionError(f"PostToolUse did not continue: {post}")
        assertions.append("PostToolUse returned continue true")
        for label, payload in [("write", write), ("bash", bash)]:
            hso = payload.get("hookSpecificOutput", {})
            if hso.get("hookEventName") != "PreToolUse" or hso.get("permissionDecision") != "deny":
                raise AssertionError(f"{label} was not denied: {payload}")
            if "ardur: blocked" not in hso.get("permissionDecisionReason", "").lower():
                raise AssertionError(f"{label} denial did not include human-readable Ardur reason: {payload}")
        assertions.append("forbidden Write and Bash returned Claude Code deny decisions")
        run_capture(
            ctx,
            "rwt2-claude-code-report",
            [str(ctx.ardur_bin), "claude-code-report", "--home", str(ctx.ardur_home), "--keys-dir", str(ctx.ardur_home / "keys"), "--json"],
            cwd=ctx.project,
        )
        report = json.loads((ctx.out_dir / "rwt2-claude-code-report.stdout.txt").read_text(encoding="utf-8"))
        if report.get("chain_verification", {}).get("ok") is not True:
            raise AssertionError(f"report chain verification not OK: {report.get('chain_verification')}")
        if int(report.get("receipt_count", 0)) < 4:
            raise AssertionError(f"expected at least 4 receipts, got {report.get('receipt_count')}")
        verdicts = report.get("totals", {}).get("verdicts", {})
        if int(verdicts.get("violation", 0)) < 2:
            raise AssertionError(f"expected at least two violation receipts for denied Write/Bash, got {verdicts}")
        assertions.append("claude-code-report verified/summarized the fixture receipt chain")
        return GateResult("RWT-2", ["fixture", "integration"], STATUS_PASS, "fixture hook CLI allow/deny/report path passed", assertions, notes, residual)
    except Exception as exc:  # noqa: BLE001
        return GateResult("RWT-2", ["fixture", "integration"], STATUS_FAIL, f"RWT-2 failed: {redact_text(str(exc))}", assertions, notes, residual)


def run_rwt3_preflight(ctx: HarnessContext) -> GateResult:
    assertions: list[str] = []
    notes: list[str] = []
    residual = ["Automated harness does not perform the manual live Claude prompt sequence or login/account flows."]
    claude = shutil.which("claude", path=ctx.env.get("PATH"))
    if not claude:
        notes.append("claude binary missing on PATH")
        return GateResult(
            "RWT-3",
            ["real-host", "fresh-user", "integration"],
            STATUS_SKIP_UNSUPPORTED,
            "live Claude Code gate skipped because claude binary is missing",
            assertions,
            notes,
            ["No live Claude readiness claim is supported by this run."],
        )
    version = run_capture(ctx, "rwt3-claude-version", [claude, "--version"], cwd=ctx.project, allowed_exit_codes={0, 1, 2, 126, 127})
    if version.returncode != 0:
        notes.append("claude binary exists but version preflight failed; auth/config may be missing or unusable")
        return GateResult(
            "RWT-3",
            ["real-host", "fresh-user", "integration"],
            STATUS_BLOCKED,
            "claude present but version/auth preflight failed; autonomous worker did not log in or change credentials",
            assertions,
            notes,
            ["Human-authenticated Claude Code QA is still required before live readiness claims."],
        )
    assertions.append("claude --version exited 0")
    doctor = run_capture(
        ctx,
        "rwt3-doctor-claude-code",
        [str(ctx.ardur_bin), "doctor-claude-code", "--home", str(ctx.ardur_home), "--plugin-dir", str(ctx.repo / "plugins" / "claude-code")],
        cwd=ctx.project,
        allowed_exit_codes={0, 1},
    )
    if doctor.returncode != 0:
        notes.append("doctor-claude-code returned nonzero with claude present")
        return GateResult(
            "RWT-3",
            ["real-host", "fresh-user", "integration"],
            STATUS_BLOCKED,
            "claude present but Ardur doctor did not validate the plugin/passport path",
            assertions,
            notes,
            ["Human should inspect doctor output before live QA."],
        )
    assertions.append("doctor-claude-code exited 0 with claude present")
    return GateResult(
        "RWT-3",
        ["real-host", "fresh-user", "integration"],
        STATUS_SKIP_GATED,
        "claude preflight passed, but live prompt sequence is not run autonomously",
        assertions,
        notes,
        residual,
    )


def command_records(ctx: HarnessContext) -> list[dict[str, Any]]:
    return [record.__dict__ for record in ctx.commands]


def collect_artifacts(ctx: HarnessContext) -> dict[str, Any]:
    receipt_paths = sorted((ctx.ardur_home / "claude-code-hook").rglob("receipts.jsonl"))
    reports = [path for path in [ctx.out_dir / "rwt2-claude-code-report.stdout.txt"] if path.exists()]
    active = ctx.ardur_home / "active_mission.jwt"
    artifacts: dict[str, Any] = {
        "ardur_md": sha256_file(ctx.project / "ARDUR.md") if (ctx.project / "ARDUR.md").exists() else None,
        # Avoid a scan-self-false-positive key ending in `_jwt`: the bundle records
        # only presence + digest metadata, never the raw active Mission JWT.
        "active_mission_jwt_presence": "present_not_copied" if active.exists() else "missing",
        "active_mission_jwt_sha256": sha256_file(active) if active.exists() else None,
        "receipt_chain_paths": [relpath(path, ctx.ardur_home) for path in receipt_paths],
        "reports": [relpath(path, ctx.output_dir) for path in reports],
        "redacted_stdout_files": sorted(relpath(path, ctx.output_dir) for path in ctx.out_dir.glob("*.stdout.txt")),
        "fixtures": sorted(relpath(path, ctx.output_dir) for path in ctx.fixtures.glob("*.json")),
    }
    return artifacts


def scan_declared_shareable_artifacts(bundle: dict[str, Any], ctx: HarnessContext | Any) -> dict[str, Any]:
    """Scan artifacts that the bundle metadata declares as shareable/redacted."""
    result: dict[str, Any] = {
        "secret_hit_count": 0,
        "path_hit_count": 0,
        "secret_categories": [],
        "path_categories": [],
        "reference_issue_count": 0,
        "reference_categories": [],
    }
    artifacts = bundle.get("artifacts")
    if not isinstance(artifacts, dict):
        return result

    output_dir = Path(ctx.output_dir)
    secret_categories: set[str] = set()
    path_categories: set[str] = set()
    reference_categories: set[str] = set()
    for key in SHAREABLE_ARTIFACT_KEYS:
        values = artifacts.get(key)
        if values is None:
            continue
        refs = [values] if isinstance(values, str) else values
        if not isinstance(refs, list):
            result["reference_issue_count"] += 1
            reference_categories.add(f"artifact_key:{key}:not_a_list")
            continue
        for raw_ref in refs:
            if not isinstance(raw_ref, str) or not raw_ref:
                result["reference_issue_count"] += 1
                reference_categories.add(f"artifact_key:{key}:invalid_ref")
                continue
            rel = Path(raw_ref)
            if rel.is_absolute() or ".." in rel.parts:
                result["reference_issue_count"] += 1
                reference_categories.add(f"artifact_key:{key}:unsafe_ref")
                continue
            artifact_path = output_dir / rel
            if not artifact_path.is_file():
                result["reference_issue_count"] += 1
                reference_categories.add(f"artifact_key:{key}:missing")
                continue
            try:
                text = artifact_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                result["reference_issue_count"] += 1
                reference_categories.add(f"artifact_key:{key}:not_utf8_text")
                continue
            secret_hits = secret_scan_hits(text)
            if secret_hits:
                result["secret_hit_count"] += len(secret_hits)
                secret_categories.update(f"artifact_key:{key}:{category}" for category in _secret_hit_categories(secret_hits))
            path_hits = path_leak_scan_hits(text, ctx)
            if path_hits:
                result["path_hit_count"] += len(path_hits)
                path_categories.update(f"artifact_key:{key}:{category}" for category in _path_hit_categories(path_hits, ctx))

    result["secret_categories"] = sorted(secret_categories)
    result["path_categories"] = sorted(path_categories)
    result["reference_categories"] = sorted(reference_categories)
    return result


def collect_receipts(ctx: HarnessContext) -> dict[str, Any]:
    report_path = ctx.out_dir / "rwt2-claude-code-report.stdout.txt"
    if not report_path.exists():
        return {
            "verify_status": "not_applicable",
            "receipt_count": 0,
            "permit_count": 0,
            "deny_count": 0,
            "insufficient_evidence_count": 0,
            "latest_receipt_ids": [],
        }
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"verify_status": "fail", "receipt_count": 0, "permit_count": 0, "deny_count": 0, "insufficient_evidence_count": 1, "latest_receipt_ids": []}
    verdicts = report.get("totals", {}).get("verdicts", {}) if isinstance(report, dict) else {}
    latest: list[str] = []
    for chain in report.get("chains", []) if isinstance(report, dict) else []:
        # Receipt IDs are not enumerated at top-level for every chain summary;
        # preserve only available dispatch/receipt references, never raw JWTs.
        for dispatch in chain.get("dispatches", []) if isinstance(chain, dict) else []:
            receipt_id = dispatch.get("receipt_id")
            if receipt_id:
                latest.append(str(receipt_id))
    return {
        "verify_status": "pass" if report.get("chain_verification", {}).get("ok") is True else "fail",
        "receipt_count": int(report.get("receipt_count", 0)),
        "permit_count": int(verdicts.get("compliant", 0)),
        "deny_count": int(verdicts.get("violation", 0)),
        "insufficient_evidence_count": 0,
        "latest_receipt_ids": latest[-5:],
    }


def host_info() -> dict[str, str]:
    system = platform.system() or "unknown"
    release = platform.release() or "unknown"
    return {
        "os": system,
        "arch": platform.machine() or "unknown",
        "kernel": release,
        "container": "unknown",
        "wsl": "true" if "microsoft" in release.lower() else "false",
    }


def version_info(ctx: HarnessContext) -> dict[str, str]:
    versions: dict[str, str] = {}
    for key, argv, cwd in [
        ("python", [ctx.python_bin, "--version"], ctx.repo),
        ("ardur", [str(ctx.ardur_bin), "--version"], ctx.repo),
        ("git", ["git", "--version"], ctx.repo),
    ]:
        try:
            result = subprocess.run(argv, cwd=str(cwd), env=ctx.env, text=True, capture_output=True, check=False)
        except FileNotFoundError:
            versions[key] = "missing"
            continue
        versions[key] = redact_text((result.stdout or result.stderr).strip() or f"exit_{result.returncode}")
    claude = shutil.which("claude", path=ctx.env.get("PATH"))
    if not claude:
        versions["claude"] = "missing"
    else:
        result = subprocess.run([claude, "--version"], cwd=str(ctx.project), env=ctx.env, text=True, capture_output=True, check=False)
        if result.returncode == 0:
            versions["claude"] = redact_text((result.stdout or result.stderr).strip())
        else:
            versions["claude"] = "blocked_auth_or_config"
    return versions


def overall_status(gates: Sequence[GateResult]) -> str:
    required = [gate for gate in gates if gate.rwt_id in {"RWT-1", "RWT-2"}]
    if any(gate.status == STATUS_FAIL for gate in required):
        return STATUS_FAIL
    if any(gate.status == STATUS_BLOCKED for gate in required):
        return STATUS_BLOCKED
    if all(gate.status == STATUS_PASS for gate in required):
        return STATUS_PASS
    return STATUS_INSUFFICIENT


def bundle_for(ctx: HarnessContext, repo_info: dict[str, Any], repo_blocker: str | None) -> dict[str, Any]:
    head_after = short_git(ctx.repo, "rev-parse", "HEAD") if (ctx.repo / ".git").exists() else "unknown"
    origin_dev_after = short_git(ctx.repo, "rev-parse", "origin/dev") if (ctx.repo / ".git").exists() else "unknown"
    status_after = git_text(ctx.repo, "status", "--short") if (ctx.repo / ".git").exists() else ""
    repo_payload = dict(repo_info)
    repo_payload.update(
        {
            "head_after": head_after,
            "origin_dev_after": origin_dev_after,
            "clean_after": status_after == "",
            "dirty_paths_after": redact_text(status_after).splitlines() if status_after else [],
        }
    )
    gates = [gate.__dict__ for gate in ctx.gate_results]
    rwt3 = next((gate for gate in ctx.gate_results if gate.rwt_id == "RWT-3"), None)
    residual = [risk for gate in ctx.gate_results for risk in gate.residual_risk]
    if repo_blocker:
        residual.append(repo_blocker)
    if repo_payload.get("clean_before") is False and ctx.allow_dirty:
        residual.append("Worktree was dirty during this development run; rerun after landing from a clean origin/dev worktree for release-gate evidence.")
    bundle = {
        "schema_version": SCHEMA_VERSION,
        "rwt_id": "RWT-1+RWT-2+RWT-3-preflight",
        "classification": ["fresh-user", "integration", "fixture", "real-host-preflight"],
        "status": STATUS_BLOCKED if repo_blocker and not ctx.allow_dirty else overall_status(ctx.gate_results),
        "started_at": ctx.started_at,
        "ended_at": utc_now(),
        "operator_profile": ctx.operator_profile,
        "external_api_usage": "not_used",
        "public_actions": "none",
        "privileged_actions": "none",
        "repo": repo_payload,
        "host": host_info(),
        "versions": version_info(ctx),
        "temp_strategy": {
            "home": str(ctx.home),
            "ardur_home": str(ctx.ardur_home),
            "project": str(ctx.project),
            "evidence": str(ctx.evidence),
            "mutated_real_home": False,
            "mutated_global_config": False,
        },
        "commands": command_records(ctx),
        "gates": gates,
        "artifacts": collect_artifacts(ctx),
        "receipts": collect_receipts(ctx),
        "redaction": {
            "raw_secret_values_copied": False,
            "patterns_applied": REDACTION_PATTERN_NAMES,
            "secret_scan_hits": 0,
            "notes": ["Raw active Mission JWT and signing keys remain only under the temporary Ardur home and are not copied into the evidence bundle."],
        },
        "claim_mapping": {
            "supports_claims": [
                "Source/local-wheel install and first-run ARDUR.md/protect claude-code setup work on the tested host.",
                "The Claude Code hook adapter can enforce and record allowed/denied hook decisions under synthetic Claude hook inputs.",
                "The report path can verify/summarize local hook receipt chains.",
            ],
            "does_not_support_claims": [
                "A real Claude Code terminal session is fully set up and protected." if not rwt3 or rwt3.status != STATUS_PASS else "All Claude Code versions/configurations are supported.",
                "Provider-side hidden actions are visible.",
                "Subprocess/kernel/network side effects are captured.",
                "eBPF/kernel capture works.",
                "Package-manager installation works beyond the tested local wheel/source path.",
            ],
        },
        "cleanup": {
            "temp_root_removed": ctx.cleanup_temp_root_removed,
            "retained_path": ctx.cleanup_retained_path,
            "redacted_bundle_dir": str(ctx.output_dir),
        },
        "residual_risk": sorted(set(residual)),
    }
    bundle = finalize_shareable_bundle(bundle, ctx, "Initial bundle")
    redaction_payload = _ensure_redaction_payload(bundle)
    redaction_payload["secret_scan_hits"] = len(secret_scan_hits(json.dumps(bundle, indent=2, sort_keys=True)))
    return bundle


def write_bundle(ctx: HarnessContext, repo_info: dict[str, Any], repo_blocker: str | None) -> Path:
    bundle = bundle_for(ctx, repo_info, repo_blocker)
    path = ctx.output_dir / "bundle.redacted.json"
    path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    post_write_text = path.read_text(encoding="utf-8")
    rewrite_needed = False

    secret_hits = secret_scan_hits(post_write_text)
    if secret_hits:
        bundle["status"] = STATUS_FAIL
        redaction_payload = _ensure_redaction_payload(bundle)
        redaction_payload["secret_scan_hits"] = len(secret_hits)
        _append_redaction_note(bundle, f"Post-write secret scan categories: {_secret_hit_categories(secret_hits)}")
        rewrite_needed = True

    path_hits = path_leak_scan_hits(post_write_text, ctx)
    if path_hits:
        bundle["status"] = STATUS_FAIL
        redaction_payload = _ensure_redaction_payload(bundle)
        try:
            redaction_payload["path_scan_hits"] = max(int(redaction_payload.get("path_scan_hits") or 0), len(path_hits))
        except (TypeError, ValueError):
            redaction_payload["path_scan_hits"] = len(path_hits)
        _append_redaction_note(bundle, f"Post-write path leak scan categories: {_path_hit_categories(path_hits, ctx)}")
        rewrite_needed = True

    artifact_scan = scan_declared_shareable_artifacts(bundle, ctx)
    if artifact_scan["secret_hit_count"]:
        bundle["status"] = STATUS_FAIL
        redaction_payload = _ensure_redaction_payload(bundle)
        try:
            redaction_payload["secret_scan_hits"] = max(
                int(redaction_payload.get("secret_scan_hits") or 0),
                int(artifact_scan["secret_hit_count"]),
            )
        except (TypeError, ValueError):
            redaction_payload["secret_scan_hits"] = int(artifact_scan["secret_hit_count"])
        _append_redaction_note(bundle, f"Declared shareable artifact secret scan categories: {artifact_scan['secret_categories']}")
        rewrite_needed = True
    if artifact_scan["path_hit_count"]:
        bundle["status"] = STATUS_FAIL
        redaction_payload = _ensure_redaction_payload(bundle)
        try:
            redaction_payload["path_scan_hits"] = max(
                int(redaction_payload.get("path_scan_hits") or 0),
                int(artifact_scan["path_hit_count"]),
            )
        except (TypeError, ValueError):
            redaction_payload["path_scan_hits"] = int(artifact_scan["path_hit_count"])
        _append_redaction_note(bundle, f"Declared shareable artifact path leak scan categories: {artifact_scan['path_categories']}")
        rewrite_needed = True
    if artifact_scan["reference_issue_count"]:
        bundle["status"] = STATUS_FAIL
        _ensure_redaction_payload(bundle)
        _append_redaction_note(bundle, f"Declared shareable artifact reference scan issues: {artifact_scan['reference_categories']}")
        rewrite_needed = True

    if rewrite_needed:
        bundle = finalize_shareable_bundle(bundle, ctx, "Post-write bundle")
        path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def cleanup(ctx: HarnessContext) -> None:
    if ctx.keep_temp:
        ctx.cleanup_retained_path = str(ctx.temp_root)
        ctx.cleanup_temp_root_removed = False
        return
    shutil.rmtree(ctx.temp_root, ignore_errors=True)
    ctx.cleanup_temp_root_removed = not ctx.temp_root.exists()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Ardur RWT-1/RWT-2/RWT-3-preflight in a fresh-user temp environment")
    parser.add_argument("--repo", type=Path, default=repo_root_from_script(), help="Clean Ardur repo/worktree to test (default: this script's repo)")
    parser.add_argument("--output-dir", type=Path, help="Directory for redacted evidence bundle and command outputs")
    parser.add_argument("--expected-origin-dev", help="Expected short origin/dev commit; defaults to current origin/dev")
    parser.add_argument("--allow-dirty", action="store_true", help="Allow a dirty/in-progress worktree; bundle will mark this as non-release-gate evidence")
    parser.add_argument("--keep-temp", action="store_true", help="Retain temp HOME/project/Ardur home for local debugging; default removes it")
    parser.add_argument("--python", help="Python >=3.10 interpreter to use for the fresh virtualenv")
    parser.add_argument("--operator-profile", default="planner", help="Operator profile name to record in the bundle")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    ctx = prepare_context(args)
    repo_info: dict[str, Any] = {}
    repo_blocker: str | None = None
    exit_code = 0
    try:
        repo_info, repo_blocker = validate_repo_preflight(ctx)
        if repo_blocker and not ctx.allow_dirty:
            ctx.gate_results.append(GateResult("RWT-1", ["fresh-user", "integration", "matrix"], STATUS_BLOCKED, repo_blocker))
            ctx.gate_results.append(GateResult("RWT-2", ["fixture", "integration"], STATUS_BLOCKED, "blocked because RWT-1 repo preflight failed"))
            ctx.gate_results.append(GateResult("RWT-3", ["real-host", "fresh-user", "integration"], STATUS_BLOCKED, "blocked because RWT-1 repo preflight failed"))
            exit_code = 90
        else:
            install_ardur(ctx)
            rwt1 = run_rwt1(ctx)
            ctx.gate_results.append(rwt1)
            if rwt1.status == STATUS_PASS:
                ctx.gate_results.append(run_rwt2(ctx))
                ctx.gate_results.append(run_rwt3_preflight(ctx))
            else:
                ctx.gate_results.append(GateResult("RWT-2", ["fixture", "integration"], STATUS_BLOCKED, "blocked because RWT-1 did not pass"))
                ctx.gate_results.append(GateResult("RWT-3", ["real-host", "fresh-user", "integration"], STATUS_BLOCKED, "blocked because RWT-1 did not pass"))
            if any(gate.status in {STATUS_FAIL, STATUS_BLOCKED} for gate in ctx.gate_results if gate.rwt_id in {"RWT-1", "RWT-2"}):
                exit_code = 1
    finally:
        # Build the shareable bundle while the temp HOME/project still exist so
        # artifact hashes, version probes, and receipt summaries can be captured
        # without copying raw JWT/private-key material into the bundle. Then
        # clean up and patch only the cleanup fields.
        bundle_path = write_bundle(ctx, repo_info, repo_blocker)
        cleanup(ctx)
        try:
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            cleanup_payload = {
                "temp_root_removed": ctx.cleanup_temp_root_removed,
                "retained_path": ctx.cleanup_retained_path,
                "redacted_bundle_dir": str(ctx.output_dir),
            }
            bundle["cleanup"] = redact_path_roots(cleanup_payload, _path_placeholder_pairs(ctx))
            bundle = finalize_shareable_bundle(bundle, ctx, "Post-cleanup bundle")
            bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            print(f"warning: failed to patch cleanup metadata in bundle: {redact_text(str(exc))}", file=sys.stderr)
            bundle = {"status": overall_status(ctx.gate_results)}
        print(json.dumps({"status": bundle.get("status", overall_status(ctx.gate_results)), "bundle": str(bundle_path), "output_dir": str(ctx.output_dir)}, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
