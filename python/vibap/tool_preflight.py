"""Static, non-executing preflight analysis for local tool-server configs."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path, PurePath
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker

from ._specs import tool_server_preflight_report_v01_schema


REPORT_SCHEMA_VERSION = "ardur.tool_server_preflight_report.v0.1"
PROFILE_SKELETON_VERSION = "ardur.tool_server_policy_skeleton.v0.1"
MAX_CONFIG_BYTES = 1024 * 1024
MAX_CONFIG_DEPTH = 32
MAX_CONFIG_NODES = 20_000
MAX_SERVERS = 128
MAX_TOOLS = 2_048
MAX_STRING_LENGTH = 16_384
MAX_IDENTIFIER_LENGTH = 256

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "none")

_SECRET_KEY_RE = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|token|secret|password|passwd|credential|cookie|authorization|private[_-]?key)(?:$|[_-])",
    re.IGNORECASE,
)
_ENV_REFERENCE_RE = re.compile(
    r"^(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|%[A-Za-z_][A-Za-z0-9_]*%|\$\{input:[^}]+\})$"
)
_INSTRUCTION_PATTERNS = {
    "ignore_previous": re.compile(r"\bignore\s+(?:all\s+)?previous\b", re.IGNORECASE),
    "system_prompt": re.compile(
        r"\bsystem\s+(?:prompt|message|instruction)s?\b", re.IGNORECASE
    ),
    "concealment": re.compile(
        r"\b(?:do\s+not\s+tell|without\s+(?:the\s+)?user|secretly|silently)\b",
        re.IGNORECASE,
    ),
    "instruction_override": re.compile(
        r"\b(?:hidden\s+instruction|override\s+instruction|before\s+responding|always\s+send)\b",
        re.IGNORECASE,
    ),
    "zero_width": re.compile("[\u200b-\u200f\u2060\ufeff]"),
}
_SHELL_COMMANDS = {
    "bash",
    "sh",
    "zsh",
    "fish",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
}
_SHELL_TOOL_RE = re.compile(
    r"(?:^|[_ .-])(?:shell|terminal|exec|execute|command|bash|powershell)(?:$|[_ .-])",
    re.IGNORECASE,
)
_NETWORK_TOOL_RE = re.compile(
    r"(?:^|[_ .-])(?:http|fetch|request|browser|web|url|network|download|upload|email|slack)(?:$|[_ .-])",
    re.IGNORECASE,
)
_WRITE_TOOL_RE = re.compile(
    r"(?:^|[_ .-])(?:write|create|update|edit|patch|delete|remove|destroy|send|upload|execute|exec|shell)(?:$|[_ .-])",
    re.IGNORECASE,
)
_BROAD_PATH_VALUES = {
    "/",
    "~",
    "~/",
    "$HOME",
    "${HOME}",
    "%USERPROFILE%",
    "*",
    "**",
}
_BROAD_NETWORK_VALUES = {
    "*",
    "**",
    "*.*",
    "0.0.0.0/0",
    "::/0",
    "http://*",
    "https://*",
}
_NPM_EXACT_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SHA256_SRI_RE = re.compile(r"^sha256-[A-Za-z0-9+/]{43}=$")


class ToolPreflightError(ValueError):
    """A bounded, user-facing preflight failure."""

    def __init__(self, condition: str, message: str) -> None:
        super().__init__(message)
        self.condition = condition
        self.message = message


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ToolPreflightError(
                "config_duplicate_key",
                "configuration contains a duplicate object member",
            )
        value[key] = item
    return value


def _reject_nonfinite_constant(value: str) -> None:
    raise ToolPreflightError(
        "config_number_invalid", f"configuration number {value!r} is not finite"
    )


def _validate_tree(value: Any) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_CONFIG_NODES:
            raise ToolPreflightError(
                "config_too_complex",
                f"configuration exceeds {MAX_CONFIG_NODES} parsed values",
            )
        if depth > MAX_CONFIG_DEPTH:
            raise ToolPreflightError(
                "config_too_deep",
                f"configuration exceeds maximum depth {MAX_CONFIG_DEPTH}",
            )
        if isinstance(item, str):
            if len(item) > MAX_STRING_LENGTH:
                raise ToolPreflightError(
                    "config_string_too_long",
                    f"configuration contains a string longer than {MAX_STRING_LENGTH} characters",
                )
        elif isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ToolPreflightError(
                        "config_key_invalid",
                        "configuration object keys must be strings",
                    )
                stack.append((child, depth + 1))
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise ToolPreflightError(
                "config_number_invalid", "configuration numbers must be finite"
            )
        elif item is not None and not isinstance(item, (bool, int, float)):
            raise ToolPreflightError(
                "config_value_invalid",
                f"configuration contains unsupported value type {type(item).__name__}",
            )


def load_tool_server_config(path: str | Path) -> tuple[dict[str, Any], bytes]:
    """Read one strict JSON config without following a final-component symlink."""

    config_path = Path(path).expanduser()
    try:
        metadata = config_path.lstat()
    except FileNotFoundError as exc:
        raise ToolPreflightError(
            "config_missing", "configuration file does not exist"
        ) from exc
    except OSError as exc:
        raise ToolPreflightError(
            "config_unreadable", "configuration metadata could not be read"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ToolPreflightError(
            "config_symlink", "configuration file must not be a symlink"
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise ToolPreflightError(
            "config_not_regular", "configuration must be a regular file"
        )
    if metadata.st_size > MAX_CONFIG_BYTES:
        raise ToolPreflightError(
            "config_too_large",
            f"configuration exceeds the {MAX_CONFIG_BYTES}-byte input limit",
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(config_path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ToolPreflightError(
                "config_not_regular", "configuration must be a regular file"
            )
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ToolPreflightError(
                "config_changed", "configuration changed while it was being opened"
            )
        if opened.st_size > MAX_CONFIG_BYTES:
            raise ToolPreflightError(
                "config_too_large",
                f"configuration exceeds the {MAX_CONFIG_BYTES}-byte input limit",
            )
        chunks: list[bytes] = []
        remaining = MAX_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        finished = os.fstat(descriptor)
        if (
            finished.st_size != opened.st_size
            or finished.st_mtime_ns != opened.st_mtime_ns
            or finished.st_ctime_ns != opened.st_ctime_ns
            or len(payload) != finished.st_size
        ):
            raise ToolPreflightError(
                "config_changed", "configuration changed while it was being read"
            )
    except ToolPreflightError:
        raise
    except OSError as exc:
        condition = (
            "config_symlink" if stat.S_ISLNK(metadata.st_mode) else "config_unreadable"
        )
        raise ToolPreflightError(
            condition, "configuration file could not be opened safely"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > MAX_CONFIG_BYTES:
        raise ToolPreflightError(
            "config_too_large",
            f"configuration exceeds the {MAX_CONFIG_BYTES}-byte input limit",
        )
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ToolPreflightError(
            "config_encoding", "configuration must be UTF-8 JSON"
        ) from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_constant,
        )
    except ToolPreflightError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise ToolPreflightError(
            "config_malformed", "configuration must be strict JSON"
        ) from exc
    if not isinstance(parsed, dict):
        raise ToolPreflightError(
            "config_root_invalid", "configuration root must be an object"
        )
    _validate_tree(parsed)
    return parsed, payload


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _markdown_inline(value: Any) -> str:
    return str(value).replace("`", "\\`").replace("\r", " ").replace("\n", " ")


def _command_name(command: str) -> str:
    normalized = command.replace("\\", "/")
    return PurePath(normalized).name or "<empty>"


def _identifier(value: str, *, condition: str, label: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ToolPreflightError(condition, f"{label} must be non-empty")
    if len(normalized) > MAX_IDENTIFIER_LENGTH:
        raise ToolPreflightError(
            condition, f"{label} exceeds {MAX_IDENTIFIER_LENGTH} characters"
        )
    if "`" in normalized or any(
        ord(character) < 32 or ord(character) == 127 for character in normalized
    ):
        raise ToolPreflightError(
            condition, f"{label} contains unsafe control characters"
        )
    return normalized


def _server_collections(
    config: Mapping[str, Any],
) -> list[tuple[str, Mapping[str, Any]]]:
    collections: list[tuple[str, Mapping[str, Any]]] = []
    for key in ("mcpServers", "servers"):
        raw = config.get(key)
        if raw is None:
            continue
        if not isinstance(raw, Mapping):
            raise ToolPreflightError(
                "server_collection_invalid", f"{key} must be an object"
            )
        if not raw:
            raise ToolPreflightError(
                "server_collection_empty", f"{key} must contain a server"
            )
        collections.append((key, raw))
    if collections:
        return collections
    if "tools" in config:
        name = config.get("name", "manifest")
        if not isinstance(name, str):
            raise ToolPreflightError(
                "server_name_invalid", "manifest name must be a non-empty string"
            )
        name = _identifier(name, condition="server_name_invalid", label="manifest name")
        return [("manifest", {name: config})]
    raise ToolPreflightError(
        "server_collection_missing",
        "configuration must contain mcpServers, servers, or a static tools manifest",
    )


def _tool_entries(
    server: Mapping[str, Any], path: str
) -> list[tuple[str, Mapping[str, Any], str]]:
    source = "tools"
    raw = server.get("tools")
    if raw is None and "tools" not in server:
        source = "includeTools"
        raw = server.get("includeTools", [])
    entries: list[tuple[str, Mapping[str, Any], str]] = []
    if isinstance(raw, Mapping):
        iterator = raw.items()
    elif isinstance(raw, list):
        iterator = enumerate(raw)
    elif raw is None:
        return entries
    else:
        raise ToolPreflightError(
            "tools_invalid", f"{path}.tools must be an array or object"
        )
    seen: set[str] = set()
    for key, item in iterator:
        if isinstance(key, str):
            key = _identifier(
                key,
                condition="tool_name_invalid",
                label=f"{path}.{source} member name",
            )
            tool_path = f"{path}.{source}.{key}"
        else:
            tool_path = f"{path}.{source}[{key}]"
        if isinstance(item, str):
            name = item
            definition: Mapping[str, Any] = {"name": item}
        elif isinstance(item, Mapping):
            definition = item
            raw_name = item.get("name", key if isinstance(key, str) else "")
            if not isinstance(raw_name, str):
                raise ToolPreflightError(
                    "tool_name_invalid", f"{tool_path} needs a non-empty name"
                )
            name = raw_name
        else:
            raise ToolPreflightError(
                "tool_invalid", f"{tool_path} must be a string or object"
            )
        name = _identifier(
            name, condition="tool_name_invalid", label=f"{tool_path} name"
        )
        if name in seen:
            raise ToolPreflightError(
                "tool_name_duplicate",
                "server definition contains a duplicate tool name",
            )
        seen.add(name)
        entries.append((name, definition, tool_path))
    return entries


def _policy_gate(server: Mapping[str, Any], tool: Mapping[str, Any]) -> bool:
    for value in (server.get("ardur"), tool.get("ardur")):
        extension = _mapping(value)
        if (
            extension.get("approval_required") is True
            or extension.get("policy_gate") is True
        ):
            return True
    return (
        server.get("approval_required") is True or tool.get("approval_required") is True
    )


def _network_allowlist(
    server: Mapping[str, Any], config: Mapping[str, Any]
) -> list[str]:
    values: list[str] = []
    for candidate in (
        _mapping(_mapping(server.get("ardur")).get("network")).get("allowed_domains"),
        server.get("allowedDomains"),
        _mapping(_mapping(config.get("sandbox")).get("network")).get("allowedDomains"),
    ):
        values.extend(value.strip() for value in _strings(candidate) if value.strip())
    return sorted(set(values))


def _network_scope_is_open(values: Sequence[str]) -> bool:
    return any(value.lower() in _BROAD_NETWORK_VALUES for value in values)


def _allowlist_covers_url(url: str, values: Sequence[str]) -> tuple[bool, bool]:
    try:
        endpoint = urlsplit(url)
        endpoint_host = endpoint.hostname
    except ValueError:
        return False, False
    if (
        endpoint.scheme.lower() not in {"http", "https", "ws", "wss"}
        or not endpoint_host
    ):
        return False, False
    endpoint_host = endpoint_host.rstrip(".").lower()
    for raw in values:
        candidate = raw.strip().lower()
        try:
            if "://" in candidate:
                parsed = urlsplit(candidate)
                if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                    continue
                candidate_host = parsed.hostname or ""
            else:
                candidate_host = candidate.split(":", 1)[0]
        except ValueError:
            continue
        wildcard = candidate_host.startswith("*.")
        candidate_host = candidate_host.removeprefix("*.").rstrip(".")
        if endpoint_host == candidate_host or (
            wildcard and endpoint_host.endswith(f".{candidate_host}")
        ):
            return True, True
    return False, True


def _has_valid_command_integrity(server: Mapping[str, Any]) -> bool:
    command_sha256 = server.get("command_sha256")
    if isinstance(command_sha256, str) and _SHA256_HEX_RE.fullmatch(command_sha256):
        return True
    integrity = server.get("integrity")
    if not isinstance(integrity, str):
        return False
    if integrity.lower().startswith("sha256:"):
        return _SHA256_HEX_RE.fullmatch(integrity.split(":", 1)[1]) is not None
    return _SHA256_SRI_RE.fullmatch(integrity) is not None


def _filesystem_scope(
    server: Mapping[str, Any], config: Mapping[str, Any]
) -> list[str]:
    values: list[str] = []
    for candidate in (
        _mapping(server.get("ardur")).get("resource_scope"),
        server.get("allowedDirectories"),
        _mapping(_mapping(config.get("sandbox")).get("filesystem")).get("allowRead"),
        _mapping(_mapping(config.get("sandbox")).get("filesystem")).get("allowWrite"),
    ):
        values.extend(_strings(candidate))
    return sorted(set(values))


def _is_broad_path(value: str) -> bool:
    stripped = value.strip().split("=", 1)[-1]
    normalized = stripped.replace("\\", "/")
    if stripped in _BROAD_PATH_VALUES:
        return True
    if normalized in {"/Users", "/Users/", "/home", "/home/", "C:/Users", "C:/Users/"}:
        return True
    if normalized.startswith(("/Users/*", "/home/*", "C:/Users/*")):
        return True
    if ".." in normalized.split("/"):
        return True
    parts = [part for part in normalized.split("/") if part]
    if len(parts) <= 2 and parts[:1] in (["Users"], ["home"]):
        return True
    if len(parts) <= 3 and parts[:2] == ["C:", "Users"]:
        return True
    return normalized in {"..", "../", "../*", "../**"}


def _package_pin(command: str, args: Sequence[str]) -> tuple[str | None, bool]:
    name = _command_name(command).lower()
    positional = [value for value in args if value and not value.startswith("-")]
    if name in {"npx", "npm", "pnpm", "pnpx"}:
        package = positional[0] if positional else None
        if package is None:
            return None, False
        last_at = package.rfind("@")
        version = (
            package[last_at + 1 :]
            if last_at > package.rfind("/") and last_at > 0
            else ""
        )
        return package, _NPM_EXACT_VERSION_RE.fullmatch(version) is not None
    if name in {"uvx", "pipx"}:
        package = positional[0] if positional else None
        version = package.rsplit("==", 1)[-1] if package and "==" in package else ""
        return package, bool(
            version and "*" not in version and not version.startswith(("~", "^"))
        )
    if name == "uv" and positional[:2] == ["tool", "run"]:
        package = positional[2] if len(positional) > 2 else None
        version = package.rsplit("==", 1)[-1] if package and "==" in package else ""
        return package, bool(
            version and "*" not in version and not version.startswith(("~", "^"))
        )
    if name in {"docker", "podman"} and "run" in args:
        value_options = {
            "--add-host",
            "--env",
            "-e",
            "--env-file",
            "--name",
            "--network",
            "--platform",
            "--publish",
            "-p",
            "--user",
            "-u",
            "--volume",
            "-v",
            "--workdir",
            "-w",
        }
        image = None
        index = args.index("run") + 1
        while index < len(args):
            value = args[index]
            if value in value_options:
                index += 2
                continue
            if value.startswith("-"):
                index += 1
                continue
            image = value
            break
        return image, bool(image and "@sha256:" in image)
    return None, True


def _finding(
    rule_id: str,
    category: str,
    severity: str,
    server: str,
    path: str,
    indicators: Sequence[str],
    recommendation: str,
    *,
    tool: str | None = None,
    value: str | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "path": path,
        "indicators": sorted(set(indicators)),
    }
    if value is not None:
        evidence["value_sha256"] = _sha256_text(value)
    result: dict[str, Any] = {
        "rule_id": rule_id,
        "category": category,
        "severity": severity,
        "server": server,
        "evidence": evidence,
        "recommendation": recommendation,
    }
    if tool is not None:
        result["tool"] = tool
    return result


def _instruction_indicators(description: str) -> list[str]:
    indicators = [
        name
        for name, pattern in _INSTRUCTION_PATTERNS.items()
        if pattern.search(description)
    ]
    lowered = description.lower()
    if any(marker in lowered for marker in ("<!--", "-->", "--!>", "<script")):
        indicators.append("markup_concealment")
    return indicators


def _scan_server(
    config: Mapping[str, Any],
    collection: str,
    server_name: str,
    server: Mapping[str, Any],
    findings: list[dict[str, Any]],
    discovered: list[dict[str, Any]],
    approval_tools: set[str],
) -> tuple[int, list[str]]:
    path = f"{collection}.{server_name}"
    command = server.get("command", "")
    if command is not None and not isinstance(command, str):
        raise ToolPreflightError("command_invalid", f"{path}.command must be a string")
    command = command or ""
    command_name = _command_name(command) if command else None
    if command_name:
        command_name = _identifier(
            command_name,
            condition="command_invalid",
            label=f"{path}.command basename",
        )
    args_raw = server.get("args", [])
    if args_raw is None:
        args: list[str] = []
    elif isinstance(args_raw, list) and all(isinstance(item, str) for item in args_raw):
        args = list(args_raw)
    else:
        raise ToolPreflightError(
            "args_invalid", f"{path}.args must be an array of strings"
        )
    url = None
    for key in ("url", "httpUrl"):
        candidate = server.get(key)
        if candidate is not None and not isinstance(candidate, str):
            raise ToolPreflightError("url_invalid", f"{path}.{key} must be a string")
        if candidate and url is None:
            url = candidate
    raw_transport = server.get("type") or (
        "stdio" if command else "http" if url else "manifest"
    )
    if not isinstance(raw_transport, str):
        raise ToolPreflightError(
            "transport_invalid", f"{path}.type must be a short string"
        )
    transport = _identifier(
        raw_transport,
        condition="transport_invalid",
        label=f"{path}.type",
    )
    if len(transport) > 64:
        raise ToolPreflightError(
            "transport_invalid", f"{path}.type must be a short string"
        )
    tools = _tool_entries(server, path)
    if len(tools) > MAX_TOOLS:
        raise ToolPreflightError("too_many_tools", f"{path} exceeds {MAX_TOOLS} tools")
    discovered.append(
        {
            "name": server_name,
            "collection": collection,
            "transport": transport,
            "command": command_name,
            "command_sha256": _sha256_text(command) if command else None,
            "argument_count": len(args),
            "tool_count": len(tools),
        }
    )

    if command_name and command_name.lower() in _SHELL_COMMANDS:
        findings.append(
            _finding(
                "TS001",
                "shell_execution",
                "critical",
                server_name,
                f"{path}.command",
                ["shell_interpreter"],
                "Replace the shell startup command with a directly invoked, content-pinned executable and a minimal argument vector.",
                value=command,
            )
        )
    package, pinned = _package_pin(command, args)
    if package and not pinned:
        severity = "high" if ":latest" in package or "@latest" in package else "medium"
        findings.append(
            _finding(
                "TS002",
                "supply_chain",
                severity,
                server_name,
                f"{path}.args",
                ["package_or_image_not_content_pinned"],
                "Pin packages to an immutable version and lock digest; pin container images by sha256 digest.",
                value=package,
            )
        )
    elif command and package is None and not _has_valid_command_integrity(server):
        integrity_declared = (
            server.get("integrity") is not None
            or server.get("command_sha256") is not None
        )
        findings.append(
            _finding(
                "TS003",
                "supply_chain",
                "medium",
                server_name,
                f"{path}.command",
                [
                    "local_command_integrity_invalid"
                    if integrity_declared
                    else "local_command_integrity_unverified"
                ],
                "Record an expected executable or script digest and verify it before launch.",
                value=command,
            )
        )

    env = server.get("env", {})
    if env is None:
        env = {}
    if not isinstance(env, Mapping):
        raise ToolPreflightError("env_invalid", f"{path}.env must be an object")
    for key, value in env.items():
        if not isinstance(key, str):
            raise ToolPreflightError(
                "env_key_invalid", f"{path}.env keys must be strings"
            )
        key = _identifier(
            key,
            condition="env_key_invalid",
            label=f"{path}.env key",
        )
        if _SECRET_KEY_RE.search(key):
            reference = (
                isinstance(value, str)
                and _ENV_REFERENCE_RE.fullmatch(value.strip()) is not None
            )
            findings.append(
                _finding(
                    "TS004" if reference else "TS005",
                    "secret_exposure",
                    "high" if reference else "critical",
                    server_name,
                    f"{path}.env.{key}",
                    [
                        "secret_like_environment_key",
                        "environment_reference"
                        if reference
                        else "literal_or_computed_value",
                    ],
                    "Remove the secret from the server environment or explicitly allow only the minimum secret reference through a launch-time broker.",
                )
            )
    if server.get("envFile") is not None:
        findings.append(
            _finding(
                "TS006",
                "secret_exposure",
                "high",
                server_name,
                f"{path}.envFile",
                ["environment_file_loaded"],
                "Replace broad environment-file loading with an explicit allowlist of non-secret variables and brokered secret references.",
            )
        )
    trust = server.get("trust")
    if trust is not None and not isinstance(trust, bool):
        raise ToolPreflightError("trust_invalid", f"{path}.trust must be a boolean")
    if trust is True:
        findings.append(
            _finding(
                "TS007",
                "approval_bypass",
                "critical",
                server_name,
                f"{path}.trust",
                ["tool_confirmation_bypass"],
                "Keep server trust disabled and require policy-bound approval for side-effecting tools.",
            )
        )

    resource_scope = _filesystem_scope(server, config)
    broad_scope = [value for value in resource_scope if _is_broad_path(value)]
    broad_args = [value for value in args if _is_broad_path(value)]
    if broad_scope or broad_args:
        findings.append(
            _finding(
                "TS008",
                "filesystem_scope",
                "high",
                server_name,
                f"{path}.filesystem",
                [
                    "broad_filesystem_root",
                    f"matched_values:{len(broad_scope) + len(broad_args)}",
                ],
                "Restrict filesystem access to explicit workspace subdirectories and separate read from write roots.",
            )
        )
    allow_domains = _network_allowlist(server, config)
    network_open = _network_scope_is_open(allow_domains)
    endpoint_allowed, endpoint_valid = (
        _allowlist_covers_url(url, allow_domains) if url else (False, True)
    )
    if url and (
        not allow_domains
        or network_open
        or not endpoint_valid
        or (allow_domains and not network_open and not endpoint_allowed)
        or not url.lower().startswith(("https://", "wss://"))
    ):
        indicators = ["remote_transport"]
        if not allow_domains:
            indicators.append("network_domain_allowlist_missing")
        if network_open:
            indicators.append("network_domain_allowlist_unrestricted")
        if not endpoint_valid:
            indicators.append("remote_transport_url_invalid")
        elif allow_domains and not network_open and not endpoint_allowed:
            indicators.append("remote_transport_not_in_allowlist")
        if not url.lower().startswith(("https://", "wss://")):
            indicators.append("remote_transport_not_tls")
        findings.append(
            _finding(
                "TS009",
                "network_scope",
                "high",
                server_name,
                f"{path}.url",
                indicators,
                "Constrain remote access to explicit HTTPS origins and enforce the allowlist outside the server process.",
                value=url,
            )
        )

    if "tools" not in server and not _strings(server.get("includeTools")):
        findings.append(
            _finding(
                "TS015",
                "tool_metadata",
                "medium",
                server_name,
                f"{path}.tools",
                ["tool_surface_not_declared", "static_analysis_incomplete"],
                "Provide a reviewed static tool manifest or includeTools allowlist so preflight can synthesize a closed capability set.",
            )
        )

    for tool_name, tool, tool_path in tools:
        identifier = f"{server_name}.{tool_name}"
        description = tool.get("description", "")
        if description is not None and not isinstance(description, str):
            raise ToolPreflightError(
                "tool_description_invalid", f"{tool_path}.description must be a string"
            )
        description = description or ""
        instruction_indicators = _instruction_indicators(description)
        if instruction_indicators:
            findings.append(
                _finding(
                    "TS010",
                    "instruction_injection",
                    "high",
                    server_name,
                    f"{tool_path}.description",
                    instruction_indicators,
                    "Remove instruction-like behavior from tool metadata; keep descriptions factual, reviewable, and bound to a trusted manifest digest.",
                    tool=tool_name,
                    value=description,
                )
            )
        annotations = _mapping(tool.get("annotations"))
        if not annotations:
            findings.append(
                _finding(
                    "TS011",
                    "tool_metadata",
                    "medium",
                    server_name,
                    f"{tool_path}.annotations",
                    ["risk_annotations_missing", "pessimistic_protocol_defaults_apply"],
                    "Declare readOnlyHint, destructiveHint, idempotentHint, and openWorldHint, then enforce policy independently of those hints.",
                    tool=tool_name,
                )
            )
        combined = f"{tool_name} {description}"
        shell_tool = _SHELL_TOOL_RE.search(combined) is not None
        network_tool = (
            _NETWORK_TOOL_RE.search(combined) is not None
            or annotations.get("openWorldHint") is True
        )
        write_tool = (
            _WRITE_TOOL_RE.search(combined) is not None
            or annotations.get("destructiveHint") is True
            or annotations.get("readOnlyHint") is False
        )
        gate = _policy_gate(server, tool)
        if shell_tool:
            approval_tools.add(identifier)
            findings.append(
                _finding(
                    "TS012",
                    "shell_execution",
                    "critical" if not gate else "high",
                    server_name,
                    tool_path,
                    [
                        "shell_or_command_tool",
                        "policy_gate_present" if gate else "policy_gate_missing",
                    ],
                    "Remove generic shell tools where possible; otherwise require a closed command vocabulary, argument constraints, and explicit approval.",
                    tool=tool_name,
                )
            )
        if network_tool and (not allow_domains or network_open):
            approval_tools.add(identifier)
            network_indicators = ["open_world_or_network_tool"]
            network_indicators.append(
                "network_domain_allowlist_unrestricted"
                if network_open
                else "network_domain_allowlist_missing"
            )
            findings.append(
                _finding(
                    "TS013",
                    "network_scope",
                    "high",
                    server_name,
                    tool_path,
                    network_indicators,
                    "Deny network by default and allow only explicit domains, methods, and data classes through an external enforcement point.",
                    tool=tool_name,
                )
            )
        if write_tool and not gate:
            approval_tools.add(identifier)
            findings.append(
                _finding(
                    "TS014",
                    "side_effect_gate",
                    "high",
                    server_name,
                    tool_path,
                    ["write_or_destructive_tool", "policy_gate_missing"],
                    "Require an Ardur policy gate and resolved-argument-bound approval before write, delete, send, or execution side effects.",
                    tool=tool_name,
                )
            )
    return len(tools), [name for name, _, _ in tools]


def _report_verdict(findings: Sequence[Mapping[str, Any]]) -> str:
    severities = {str(item["severity"]) for item in findings}
    if "critical" in severities:
        return "deny"
    if "high" in severities:
        return "review"
    if severities:
        return "pass_with_warnings"
    return "pass"


def validate_tool_preflight_report(report: Mapping[str, Any]) -> None:
    schema = tool_server_preflight_report_v01_schema()
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(dict(report))


def scan_tool_server_config(path: str | Path) -> dict[str, Any]:
    """Return a deterministic, schema-validated static risk report."""

    config, payload = load_tool_server_config(path)
    collections = _server_collections(config)
    server_count = sum(len(servers) for _, servers in collections)
    if server_count > MAX_SERVERS:
        raise ToolPreflightError(
            "too_many_servers", f"configuration exceeds {MAX_SERVERS} servers"
        )
    findings: list[dict[str, Any]] = []
    discovered: list[dict[str, Any]] = []
    approval_tools: set[str] = set()
    allowed_tools: set[str] = set()
    server_names: set[str] = set()
    tool_count = 0
    for collection, servers in collections:
        for raw_name, raw_server in servers.items():
            if not isinstance(raw_name, str):
                raise ToolPreflightError(
                    "server_name_invalid",
                    f"{collection} server names must be non-empty strings",
                )
            server_name = _identifier(
                raw_name,
                condition="server_name_invalid",
                label=f"{collection} server name",
            )
            if not isinstance(raw_server, Mapping):
                raise ToolPreflightError(
                    "server_invalid",
                    f"{collection} server definition must be an object",
                )
            if server_name in server_names:
                raise ToolPreflightError(
                    "server_name_duplicate",
                    "configuration contains a duplicate server name",
                )
            server_names.add(server_name)
            count, tool_names = _scan_server(
                config,
                collection,
                server_name,
                raw_server,
                findings,
                discovered,
                approval_tools,
            )
            tool_count += count
            for tool_name in tool_names:
                identifier = f"{server_name}.{tool_name}"
                if identifier in allowed_tools:
                    raise ToolPreflightError(
                        "tool_identifier_duplicate",
                        "configuration contains a duplicate tool identifier",
                    )
                allowed_tools.add(identifier)
    if tool_count > MAX_TOOLS:
        raise ToolPreflightError(
            "too_many_tools", f"configuration exceeds {MAX_TOOLS} tools"
        )
    findings.sort(
        key=lambda item: (
            -SEVERITY_ORDER[str(item["severity"])],
            str(item["rule_id"]),
            str(item["server"]),
            str(item.get("tool", "")),
            str(item["evidence"]["path"]),
        )
    )
    discovered.sort(key=lambda item: (str(item["collection"]), str(item["name"])))
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for item in findings:
        counts[str(item["severity"])] += 1
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "analysis_mode": "static_non_executing",
        "source": {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
            "collections": sorted(collection for collection, _ in collections),
        },
        "summary": {
            "verdict": _report_verdict(findings),
            "server_count": server_count,
            "tool_count": tool_count,
            "finding_count": len(findings),
            "severity_counts": counts,
        },
        "servers": discovered,
        "findings": findings,
        "suggested_controls": {
            "schema_version": PROFILE_SKELETON_VERSION,
            "deny_by_default": True,
            "capability_token": {
                "allowed_tools": sorted(allowed_tools),
                "resource_scope": [],
                "network_allowed_domains": [],
                "delegation_allowed": False,
                "max_tool_calls": 25,
            },
            "policy": {
                "approval_required_tools": sorted(approval_tools),
                "deny_secret_like_environment_keys": True,
                "require_content_pins": True,
                "require_runtime_receipts": True,
            },
        },
        "limitations": [
            "Static configuration analysis does not inspect or execute server implementation code.",
            "Tool annotations and descriptions are untrusted hints and are not runtime enforcement evidence.",
            "No dependency vulnerability lookup, binary signature verification, endpoint probing, or network request is performed.",
            "Package-version pin checks are syntactic and do not verify lockfile integrity or registry content.",
            "A clean report does not demonstrate that a tool server is safe or behaves as declared.",
        ],
    }
    validate_tool_preflight_report(report)
    return report


def fail_threshold_reached(report: Mapping[str, Any], fail_on: str) -> bool:
    if fail_on not in FAIL_ON_CHOICES:
        raise ValueError(f"unknown fail threshold {fail_on!r}")
    if fail_on == "none":
        return False
    threshold = SEVERITY_ORDER[fail_on]
    return any(
        SEVERITY_ORDER[str(item["severity"])] >= threshold
        for item in report["findings"]
    )


def render_tool_preflight_markdown(report: Mapping[str, Any]) -> str:
    validate_tool_preflight_report(report)
    summary = report["summary"]
    counts = summary["severity_counts"]
    lines = [
        "# Ardur Tool-Server Preflight",
        "",
        f"- Verdict: `{summary['verdict']}`",
        f"- Servers/tools: {summary['server_count']}/{summary['tool_count']}",
        f"- Findings: {summary['finding_count']} (critical={counts['critical']}, high={counts['high']}, medium={counts['medium']}, low={counts['low']})",
        f"- Source SHA-256: `{report['source']['sha256']}`",
        "- Analysis: static and non-executing",
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        lines.append(
            "No configured risk indicators matched. This is not a safety certification."
        )
    for item in report["findings"]:
        target = f" / `{_markdown_inline(item['tool'])}`" if item.get("tool") else ""
        indicators = ", ".join(
            f"`{_markdown_inline(value)}`" for value in item["evidence"]["indicators"]
        )
        lines.extend(
            [
                f"### {item['severity'].upper()} {item['rule_id']} - {item['category']}",
                "",
                f"- Server{target}: `{_markdown_inline(item['server'])}`",
                f"- Evidence path: `{_markdown_inline(item['evidence']['path'])}`",
                f"- Indicators: {indicators}",
                f"- Recommendation: {item['recommendation']}",
                "",
            ]
        )
    controls = report["suggested_controls"]
    lines.extend(
        [
            "## Suggested Ardur Controls",
            "",
            "```json",
            json.dumps(controls, indent=2, sort_keys=True),
            "```",
            "",
            "## Limitations",
            "",
            *(f"- {item}" for item in report["limitations"]),
            "",
        ]
    )
    return "\n".join(lines)


def error_response(error: ToolPreflightError) -> dict[str, Any]:
    return {
        "ok": False,
        "error": error.condition,
        "condition": error.condition,
        "message": error.message,
        "analysis_mode": "static_non_executing",
    }
