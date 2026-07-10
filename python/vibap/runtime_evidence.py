"""Offline correlation of verified receipts with imported runtime evidence.

This module treats external sensor JSON as unverified corroboration. It never
mutates signed receipt tokens and never copies raw command, path, destination,
container, event, trace, or process-exec identifiers into its public report.
"""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import secrets
import shlex
import stat
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from ._specs import (
    runtime_evidence_correlation_report_v01_schema,
    runtime_evidence_event_v01_schema,
)
from .canonical_json import canonical_json_bytes


EVENT_SCHEMA_VERSION = "ardur.runtime_evidence_event.v0.1"
REPORT_SCHEMA_VERSION = "ardur.runtime_evidence_correlation_report.v0.1"
SOURCE_ASSURANCE = "imported_unverified"
SUPPORTED_SOURCE_FORMATS = ("normalized", "tetragon", "falco")
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_LINE_BYTES = 2 * 1024 * 1024
MAX_EVENTS = 10_000
MAX_JSON_DEPTH = 40
MAX_JSON_NODES = 100_000
DEFAULT_CORRELATION_WINDOW_S = 30

_EVENT_TYPES = {
    "process_start",
    "process_exit",
    "file_write",
    "file_delete",
    "network_connect",
}
_TETRAGON_FUNCTION_TYPES = {
    "vfs_write": "file_write",
    "vfs_writev": "file_write",
    "vfs_unlink": "file_delete",
    "vfs_rename": "file_write",
    "tcp_connect": "network_connect",
    "tcp_v4_connect": "network_connect",
    "tcp_v6_connect": "network_connect",
}
_TETRAGON_TRACEPOINT_TYPES = {
    "syscalls/sys_enter_write": "file_write",
    "syscalls/sys_enter_pwrite64": "file_write",
    "syscalls/sys_enter_unlink": "file_delete",
    "syscalls/sys_enter_unlinkat": "file_delete",
    "syscalls/sys_enter_connect": "network_connect",
}
_FALCO_PROCESS_START = {"clone", "execve", "execveat", "fork", "vfork"}
_FALCO_PROCESS_EXIT = {"procexit"}
_FALCO_FILE_WRITE = {
    "creat",
    "pwrite",
    "pwrite64",
    "pwritev",
    "rename",
    "renameat",
    "renameat2",
    "write",
    "writev",
}
_FALCO_FILE_DELETE = {"rmdir", "unlink", "unlinkat"}
_FALCO_NETWORK = {"connect"}
_WRITE_FLAG_MARKERS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
_FORMAT_CHECKER = FormatChecker()
_EVENT_VALIDATOR = Draft202012Validator(
    runtime_evidence_event_v01_schema(), format_checker=_FORMAT_CHECKER
)
_REPORT_VALIDATOR = Draft202012Validator(
    runtime_evidence_correlation_report_v01_schema(), format_checker=_FORMAT_CHECKER
)


class RuntimeEvidenceError(ValueError):
    """An evidence input or generated report violated the bounded contract."""

    def __init__(self, code: str, message: str, *, line: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.line = line


@dataclass(frozen=True, slots=True)
class RuntimeEvent:
    """One validated normalized event plus private matching detail."""

    line: int
    line_sha256: str
    record: dict[str, Any]
    observed_at: datetime

    @property
    def source(self) -> Mapping[str, Any]:
        return self.record["source"]

    @property
    def process(self) -> Mapping[str, Any]:
        return self.record["process"]

    @property
    def correlation(self) -> Mapping[str, Any]:
        return self.record["correlation"]

    @property
    def details(self) -> Mapping[str, Any]:
        return self.record["details"]


@dataclass(frozen=True, slots=True)
class EventBatch:
    source_format: str
    source_sha256: str
    events: tuple[RuntimeEvent, ...]


@dataclass(frozen=True, slots=True)
class _Association:
    event: RuntimeEvent
    receipt_id: str | None
    candidate_receipt_ids: tuple[str, ...]
    match_status: str
    confidence: str
    proof_status: str
    reason_codes: tuple[str, ...]


def _duplicate_key_error(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RuntimeEvidenceError(
                "duplicate_json_key", "runtime evidence repeats a JSON object key"
            )
        value[key] = item
    return value


def _nonfinite_error(_value: str) -> None:
    raise RuntimeEvidenceError(
        "nonfinite_json_number", "runtime evidence contains a non-finite JSON number"
    )


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        _nonfinite_error(value)
    return parsed


def _strict_json(raw: str, *, line: int) -> Any:
    try:
        return json.loads(
            raw,
            object_pairs_hook=_duplicate_key_error,
            parse_constant=_nonfinite_error,
            parse_float=_finite_float,
        )
    except RuntimeEvidenceError as exc:
        if exc.line is None:
            exc.line = line
        raise
    except RecursionError as exc:
        raise RuntimeEvidenceError(
            "json_depth_exceeded",
            "runtime evidence JSON nesting exceeds the parser limit",
            line=line,
        ) from exc
    except json.JSONDecodeError as exc:
        raise RuntimeEvidenceError(
            "malformed_json",
            f"runtime evidence line {line} is malformed JSON at column {exc.colno}",
            line=line,
        ) from exc
    except ValueError as exc:
        raise RuntimeEvidenceError(
            "json_number_invalid",
            "runtime evidence contains a numeric literal outside the parser limit",
            line=line,
        ) from exc


def _check_structure(value: Any, *, line: int) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > MAX_JSON_DEPTH:
            raise RuntimeEvidenceError(
                "json_depth_exceeded",
                "runtime evidence JSON nesting exceeds the limit",
                line=line,
            )
        if nodes > MAX_JSON_NODES:
            raise RuntimeEvidenceError(
                "json_node_limit_exceeded",
                "runtime evidence JSON node count exceeds the limit",
                line=line,
            )
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def _read_bounded_regular_file(path: str | Path) -> bytes:
    input_path = Path(path).expanduser()
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(input_path, flags)
    except OSError as exc:
        code = (
            "input_symlink"
            if exc.errno in {errno.ELOOP, errno.EMLINK}
            else "input_unreadable"
        )
        raise RuntimeEvidenceError(
            code, "runtime evidence input could not be opened safely"
        ) from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeEvidenceError(
                "input_not_regular", "runtime evidence input must be a regular file"
            )
        if metadata.st_size <= 0:
            raise RuntimeEvidenceError("input_empty", "runtime evidence input is empty")
        if metadata.st_size > MAX_INPUT_BYTES:
            raise RuntimeEvidenceError(
                "input_too_large", "runtime evidence input exceeds the byte limit"
            )
        chunks: list[bytes] = []
        remaining = MAX_INPUT_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_INPUT_BYTES:
            raise RuntimeEvidenceError(
                "input_too_large", "runtime evidence input exceeds the byte limit"
            )
        return raw
    finally:
        os.close(fd)


def _nfc(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _string(value: Any, *, max_length: int = 8192) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = _nfc(value.strip())
    if not normalized or len(normalized) > max_length:
        return None
    return normalized


def _integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isascii() and value.isdigit():
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, dict) else {}


def _parse_datetime(value: Any, *, line: int, field: str) -> tuple[str, datetime]:
    text = _string(value, max_length=40)
    if text is None:
        raise RuntimeEvidenceError(
            "timestamp_invalid",
            f"runtime evidence {field} must be a bounded RFC 3339 timestamp",
            line=line,
        )
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    if "." in candidate:
        prefix, rest = candidate.split(".", 1)
        offset_index = max(rest.find("+"), rest.find("-"))
        if offset_index >= 0:
            fraction, offset = rest[:offset_index], rest[offset_index:]
        else:
            fraction, offset = rest, ""
        if not fraction.isdigit() or len(fraction) > 9:
            raise RuntimeEvidenceError(
                "timestamp_invalid",
                f"runtime evidence {field} has invalid fractional seconds",
                line=line,
            )
        candidate = f"{prefix}.{fraction[:6].ljust(6, '0')}{offset}"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise RuntimeEvidenceError(
            "timestamp_invalid",
            f"runtime evidence {field} is not a valid RFC 3339 timestamp",
            line=line,
        ) from exc
    if parsed.utcoffset() is None:
        raise RuntimeEvidenceError(
            "timestamp_timezone_missing",
            f"runtime evidence {field} must include a UTC offset",
            line=line,
        )
    return text, parsed.astimezone(timezone.utc)


def _epoch_ns_timestamp(
    value: Any, *, line: int, field: str
) -> tuple[str, datetime] | None:
    raw = _integer(value)
    if raw is None or raw < 0:
        return None
    seconds, nanoseconds = divmod(raw, 1_000_000_000)
    try:
        parsed = datetime.fromtimestamp(seconds, timezone.utc).replace(
            microsecond=nanoseconds // 1000
        )
    except (OverflowError, OSError, ValueError) as exc:
        raise RuntimeEvidenceError(
            "timestamp_invalid",
            f"runtime evidence {field} is outside the supported range",
            line=line,
        ) from exc
    text = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return text, parsed


def _schema_error(exc: ValidationError, *, line: int) -> RuntimeEvidenceError:
    location = ".".join(str(part) for part in exc.absolute_path) or "root"
    return RuntimeEvidenceError(
        "event_schema_invalid",
        f"runtime evidence schema violation at {location} ({exc.validator})",
        line=line,
    )


def _validated_event(
    record: dict[str, Any], *, line: int, line_sha256: str
) -> RuntimeEvent:
    record = dict(record)
    record["source_event_sha256"] = line_sha256
    try:
        _EVENT_VALIDATOR.validate(record)
    except ValidationError as exc:
        raise _schema_error(exc, line=line) from exc
    _text, observed_at = _parse_datetime(
        record["observed_at"], line=line, field="observed_at"
    )
    for field in ("start_time", "parent_start_time"):
        if field in record["process"]:
            _parse_datetime(
                record["process"][field], line=line, field=f"process.{field}"
            )
    return RuntimeEvent(line, line_sha256, record, observed_at)


def _correlation_hints(*values: Mapping[str, Any]) -> dict[str, str]:
    aliases = {
        "receipt_id": ("receipt_id", "ardur.receipt_id", "ai.ardur.receipt_id"),
        "trace_id": ("trace_id", "ardur.trace_id", "ai.ardur.trace_id"),
        "session_id": ("session_id", "ardur.session_id", "ai.ardur.session_id"),
        "actor": ("actor", "ardur.actor", "ai.ardur.actor"),
    }
    result: dict[str, str] = {}
    for output_name, candidates in aliases.items():
        for value in values:
            for candidate in candidates:
                normalized = _string(value.get(candidate), max_length=2048)
                if normalized is not None:
                    result[output_name] = normalized
                    break
            if output_name in result:
                break
    return result


def _container_id(process: Mapping[str, Any]) -> str | None:
    pod = _mapping(process.get("pod"))
    container = _mapping(pod.get("container"))
    return _string(container.get("id"), max_length=2048) or _string(
        process.get("docker"), max_length=2048
    )


def _tetragon_event(
    value: Mapping[str, Any], *, line: int, line_sha256: str
) -> RuntimeEvent:
    block: Mapping[str, Any]
    event_type: str
    if isinstance(value.get("process_exec"), dict):
        block = value["process_exec"]
        event_type = "process_start"
    elif isinstance(value.get("process_exit"), dict):
        block = value["process_exit"]
        event_type = "process_exit"
    elif isinstance(value.get("process_kprobe"), dict):
        block = value["process_kprobe"]
        explicit = _string(block.get("ardur_event_type"), max_length=32)
        function_name = _string(block.get("function_name"), max_length=256)
        event_type = explicit or _TETRAGON_FUNCTION_TYPES.get(function_name or "", "")
    elif isinstance(value.get("process_tracepoint"), dict):
        block = value["process_tracepoint"]
        explicit = _string(block.get("ardur_event_type"), max_length=32)
        subsystem = _string(block.get("subsys"), max_length=128)
        event_name = _string(block.get("event"), max_length=128)
        key = f"{subsystem}/{event_name}" if subsystem and event_name else ""
        event_type = explicit or _TETRAGON_TRACEPOINT_TYPES.get(key, "")
    else:
        raise RuntimeEvidenceError(
            "tetragon_event_unsupported",
            "Tetragon line is not a supported process or explicitly mapped tracing event",
            line=line,
        )
    if event_type not in _EVENT_TYPES:
        raise RuntimeEvidenceError(
            "tetragon_event_unsupported",
            "Tetragon tracing event does not have a supported fail-closed mapping",
            line=line,
        )
    process = _mapping(block.get("process"))
    parent = _mapping(block.get("parent"))
    observed_text, _observed = _parse_datetime(
        value.get("time"), line=line, field="time"
    )
    source: dict[str, Any] = {
        "kind": "tetragon",
        "format": "tetragon-json.v1",
        "assurance": SOURCE_ASSURANCE,
        "coverage": "unknown",
    }
    instance_id = _string(value.get("node_name"), max_length=256)
    if instance_id is not None:
        source["instance_id"] = instance_id
    normalized_process: dict[str, Any] = {}
    for output_name, input_name in (("pid", "pid"), ("ppid", "ppid")):
        parsed = _integer(process.get(input_name))
        if parsed is not None:
            normalized_process[output_name] = parsed
    if "ppid" not in normalized_process:
        parent_pid = _integer(parent.get("pid"))
        if parent_pid is not None:
            normalized_process["ppid"] = parent_pid
    for output_name, raw_value in (
        ("exec_id", process.get("exec_id")),
        ("parent_exec_id", process.get("parent_exec_id") or parent.get("exec_id")),
        ("container_id", _container_id(process)),
    ):
        parsed = _string(raw_value, max_length=2048)
        if parsed is not None:
            normalized_process[output_name] = parsed
    for output_name, raw_value in (
        ("start_time", process.get("start_time")),
        ("parent_start_time", parent.get("start_time")),
    ):
        if raw_value is not None:
            normalized_process[output_name] = _parse_datetime(
                raw_value, line=line, field=f"process.{output_name}"
            )[0]
    pod_labels = _mapping(_mapping(process.get("pod")).get("pod_labels"))
    ardur = _mapping(value.get("ardur"))
    block_ardur = _mapping(block.get("ardur"))
    details: dict[str, str] = {}
    binary = _string(process.get("binary"), max_length=4096)
    arguments = _string(
        process.get("arguments")
        if process.get("arguments") is not None
        else process.get("args"),
        max_length=4096,
    )
    if binary is not None:
        details["command"] = f"{binary} {arguments}".strip() if arguments else binary
    workspace = _string(process.get("cwd"), max_length=8192)
    if workspace is not None:
        details["workspace"] = workspace
    for name in ("path", "destination", "operation"):
        parsed = _string(
            block.get(f"ardur_{name}"), max_length=8192 if name != "operation" else 128
        )
        if parsed is not None:
            details[name] = parsed
    event_id = (
        _string(process.get("exec_id"), max_length=2048) or f"sha256:{line_sha256}"
    )
    record = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": event_id,
        "source": source,
        "event_type": event_type,
        "observed_at": observed_text,
        "process": normalized_process,
        "correlation": _correlation_hints(block_ardur, ardur, pod_labels),
        "details": details,
    }
    return _validated_event(record, line=line, line_sha256=line_sha256)


def _falco_event_type(fields: Mapping[str, Any], *, line: int) -> str:
    raw_type = _string(fields.get("syscall.type"), max_length=64) or _string(
        fields.get("evt.type"), max_length=64
    )
    event_type = (raw_type or "").lower()
    if event_type in _FALCO_PROCESS_START:
        return "process_start"
    if event_type in _FALCO_PROCESS_EXIT:
        return "process_exit"
    if event_type in _FALCO_FILE_WRITE:
        return "file_write"
    if event_type in _FALCO_FILE_DELETE:
        return "file_delete"
    if event_type in _FALCO_NETWORK:
        return "network_connect"
    if event_type in {"open", "openat", "openat2"}:
        flags = _string(fields.get("evt.arg.flags"), max_length=1024) or ""
        if any(marker in flags for marker in _WRITE_FLAG_MARKERS):
            return "file_write"
    raise RuntimeEvidenceError(
        "falco_event_unsupported",
        "Falco alert does not expose a supported syscall event mapping",
        line=line,
    )


def _falco_timestamp(
    value: Mapping[str, Any], fields: Mapping[str, Any], *, line: int
) -> tuple[str, datetime]:
    for raw in (value.get("time"), fields.get("evt.time.iso8601")):
        if raw is not None:
            return _parse_datetime(raw, line=line, field="time")
    for field in ("evt.rawtime", "evt.time"):
        parsed = _epoch_ns_timestamp(fields.get(field), line=line, field=field)
        if parsed is not None:
            return parsed
    raise RuntimeEvidenceError(
        "timestamp_invalid",
        "Falco alert is missing an ISO 8601 or epoch-nanosecond timestamp",
        line=line,
    )


def _falco_event(
    value: Mapping[str, Any], *, line: int, line_sha256: str
) -> RuntimeEvent:
    fields = _mapping(value.get("output_fields"))
    if not fields:
        raise RuntimeEvidenceError(
            "falco_output_fields_missing",
            "Falco JSON alert must include configured output_fields",
            line=line,
        )
    source_name = _string(value.get("source"), max_length=128)
    if source_name is not None and source_name != "syscall":
        raise RuntimeEvidenceError(
            "falco_source_unsupported",
            "Falco adapter supports syscall-source alerts only",
            line=line,
        )
    event_type = _falco_event_type(fields, line=line)
    observed_text, _observed = _falco_timestamp(value, fields, line=line)
    source: dict[str, Any] = {
        "kind": "falco",
        "format": "falco-json-alert.v1",
        "assurance": SOURCE_ASSURANCE,
        "coverage": "alert_only",
    }
    hostname = _string(value.get("hostname"), max_length=256)
    if hostname is not None:
        source["instance_id"] = hostname
    process: dict[str, Any] = {}
    for output_name, input_name in (("pid", "proc.pid"), ("ppid", "proc.ppid")):
        parsed = _integer(fields.get(input_name))
        if parsed is not None:
            process[output_name] = parsed
    for output_name, input_name in (
        ("start_time", "proc.pid.ts"),
        ("parent_start_time", "proc.ppid.ts"),
    ):
        parsed = _epoch_ns_timestamp(
            fields.get(input_name), line=line, field=input_name
        )
        if parsed is not None:
            process[output_name] = parsed[0]
    container_id = _string(fields.get("container.id"), max_length=2048)
    if container_id is not None:
        process["container_id"] = container_id
    details: dict[str, str] = {}
    command = _string(fields.get("proc.cmdline"), max_length=8192) or _string(
        fields.get("proc.exepath"), max_length=8192
    )
    if command is not None:
        details["command"] = command
    path = _string(fields.get("fd.name"), max_length=8192) or _string(
        fields.get("evt.arg.path"), max_length=8192
    )
    if event_type in {"file_write", "file_delete"} and path is not None:
        details["path"] = path
    if event_type == "network_connect" and path is not None:
        details["destination"] = path
    raw_operation = _string(fields.get("syscall.type"), max_length=128) or _string(
        fields.get("evt.type"), max_length=128
    )
    if raw_operation is not None:
        details["operation"] = raw_operation
    event_number = _string(fields.get("evt.num"), max_length=128)
    event_id = f"falco:{event_number}" if event_number else f"sha256:{line_sha256}"
    record = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": event_id,
        "source": source,
        "event_type": event_type,
        "observed_at": observed_text,
        "process": process,
        "correlation": _correlation_hints(fields),
        "details": details,
    }
    return _validated_event(record, line=line, line_sha256=line_sha256)


def load_runtime_events(path: str | Path, *, source_format: str) -> EventBatch:
    """Load bounded JSONL and normalize it under one explicit adapter."""

    if source_format not in SUPPORTED_SOURCE_FORMATS:
        raise RuntimeEvidenceError(
            "source_format_unsupported", "runtime evidence source format is unsupported"
        )
    raw = _read_bounded_regular_file(path)
    source_sha256 = hashlib.sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeEvidenceError(
            "input_not_utf8", "runtime evidence input must be UTF-8"
        ) from exc
    events: list[RuntimeEvent] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if not raw_line.strip():
            continue
        encoded = raw_line.encode("utf-8")
        if len(encoded) > MAX_LINE_BYTES:
            raise RuntimeEvidenceError(
                "line_too_large",
                "runtime evidence line exceeds the byte limit",
                line=line_number,
            )
        value = _strict_json(raw_line, line=line_number)
        _check_structure(value, line=line_number)
        if not isinstance(value, dict):
            raise RuntimeEvidenceError(
                "event_not_object",
                "runtime evidence line must be a JSON object",
                line=line_number,
            )
        line_sha256 = hashlib.sha256(encoded).hexdigest()
        if source_format == "normalized":
            event = _validated_event(
                dict(value), line=line_number, line_sha256=line_sha256
            )
        elif source_format == "tetragon":
            event = _tetragon_event(value, line=line_number, line_sha256=line_sha256)
        else:
            event = _falco_event(value, line=line_number, line_sha256=line_sha256)
        events.append(event)
        if len(events) > MAX_EVENTS:
            raise RuntimeEvidenceError(
                "event_limit_exceeded", "runtime evidence input exceeds the event limit"
            )
    if not events:
        raise RuntimeEvidenceError(
            "input_no_events", "runtime evidence input contains no events"
        )
    return EventBatch(source_format, source_sha256, tuple(events))


def _receipt_time(receipt: Mapping[str, Any]) -> datetime:
    _text, parsed = _parse_datetime(
        receipt.get("timestamp"),
        line=int(receipt.get("index", 0)) + 1,
        field="receipt.timestamp",
    )
    return parsed


def _time_matches(
    event: RuntimeEvent, receipt: Mapping[str, Any], window_s: int
) -> bool:
    return abs((event.observed_at - _receipt_time(receipt)).total_seconds()) <= window_s


def _event_type_matches(event_type: str, receipt: Mapping[str, Any]) -> bool:
    side_effect = str(receipt.get("side_effect_class", ""))
    action = str(receipt.get("action_class", ""))
    if event_type in {"process_start", "process_exit"}:
        return side_effect in {"process_launch", "subagent_launch"} or action in {
            "dispatch",
            "execute",
        }
    if event_type in {"file_write", "file_delete"}:
        return (
            side_effect in {"filesystem_write", "internal_write", "state_change"}
            or action == "write"
        )
    if event_type == "network_connect":
        return side_effect in {"external_send", "network_read"} or action in {
            "fetch",
            "send",
        }
    return False


def _command_token(value: str) -> str:
    try:
        parts = shlex.split(value, posix=True)
    except ValueError:
        parts = value.split()
    return parts[0] if parts else ""


def _target_matches(
    event: RuntimeEvent, receipt: Mapping[str, Any]
) -> tuple[bool, bool]:
    target = _string(receipt.get("target"), max_length=8192) or ""
    tool = _string(receipt.get("tool"), max_length=2048) or ""
    values = [
        _string(event.details.get("path"), max_length=8192),
        _string(event.details.get("destination"), max_length=8192),
        _string(event.details.get("workspace"), max_length=8192),
    ]
    target_match = bool(target and target in {value for value in values if value})
    command = _string(event.details.get("command"), max_length=8192) or ""
    command_token = _command_token(command)
    command_name = Path(command_token).name.casefold() if command_token else ""
    tool_name = Path(tool).name.casefold() if tool else ""
    target_name = Path(target).name.casefold() if target else ""
    command_match = bool(
        command_name
        and command_name
        in {candidate for candidate in (tool_name, target_name) if candidate}
    )
    return target_match, command_match


def _score_candidate(
    event: RuntimeEvent,
    receipt: Mapping[str, Any],
    *,
    window_s: int,
) -> tuple[int, tuple[str, ...]]:
    hints = event.correlation
    receipt_id = str(receipt.get("receipt_id", ""))
    explicit_hint = _string(hints.get("receipt_id"), max_length=2048)
    if explicit_hint is not None and explicit_hint != receipt_id:
        return 0, ()
    score = 0
    reasons: list[str] = []
    time_match = _time_matches(event, receipt, window_s)
    type_match = _event_type_matches(str(event.record["event_type"]), receipt)
    if explicit_hint == receipt_id:
        score += 70
        reasons.append("receipt_id_hint_exact")
    trace_hint = _string(hints.get("trace_id"), max_length=2048) or _string(
        hints.get("session_id"), max_length=2048
    )
    if trace_hint is not None and trace_hint == str(receipt.get("trace_id", "")):
        score += 35
        reasons.append("trace_id_exact")
    actor_hint = _string(hints.get("actor"), max_length=2048)
    if actor_hint is not None and actor_hint == str(receipt.get("actor", "")):
        score += 15
        reasons.append("actor_exact")
    if time_match:
        score += 15
        reasons.append("time_window")
    elif explicit_hint == receipt_id:
        reasons.append("time_outside_window")
    if type_match:
        score += 15
        reasons.append("side_effect_compatible")
    else:
        reasons.append("side_effect_incompatible")
    target_match, command_match = _target_matches(event, receipt)
    if target_match:
        score += 20
        reasons.append("target_exact")
    if command_match:
        score += 10
        reasons.append("command_name_exact")
    if not time_match or not type_match:
        score = min(score, 45)
    return score, tuple(sorted(set(reasons)))


def _direct_association(
    event: RuntimeEvent,
    receipts: Sequence[Mapping[str, Any]],
    *,
    window_s: int,
) -> _Association:
    hint = _string(event.correlation.get("receipt_id"), max_length=2048)
    known_ids = {str(receipt.get("receipt_id", "")) for receipt in receipts}
    if hint is not None and hint not in known_ids:
        return _Association(
            event,
            None,
            (),
            "unmatched",
            "none",
            "no_evidence",
            ("receipt_id_hint_unknown",),
        )
    scored: list[tuple[int, str, tuple[str, ...]]] = []
    for receipt in receipts:
        score, reasons = _score_candidate(event, receipt, window_s=window_s)
        if score:
            scored.append((score, str(receipt["receipt_id"]), reasons))
    if not scored:
        return _Association(
            event,
            None,
            (),
            "unmatched",
            "none",
            "no_evidence",
            ("no_candidate_signals",),
        )
    scored.sort(key=lambda item: (-item[0], item[1]))
    best_score = scored[0][0]
    best = [item for item in scored if item[0] == best_score]
    if len(best) > 1:
        reasons = {
            reason
            for _score, _receipt_id, item_reasons in best
            for reason in item_reasons
        }
        reasons.add("candidate_score_tie")
        return _Association(
            event,
            None,
            tuple(item[1] for item in best),
            "ambiguous",
            "ambiguous",
            "non_proof",
            tuple(sorted(reasons)),
        )
    _score, receipt_id, reasons = best[0]
    if best_score >= 85:
        return _Association(
            event,
            receipt_id,
            (receipt_id,),
            "matched",
            "high",
            "corroborating_unverified",
            reasons,
        )
    if best_score >= 60:
        return _Association(
            event,
            receipt_id,
            (receipt_id,),
            "matched",
            "medium",
            "corroborating_unverified",
            reasons,
        )
    if best_score >= 30:
        return _Association(
            event, receipt_id, (receipt_id,), "weak", "low", "non_proof", reasons
        )
    return _Association(
        event,
        None,
        (),
        "unmatched",
        "none",
        "no_evidence",
        ("candidate_below_threshold",),
    )


def _scope(event: RuntimeEvent) -> tuple[str, str, str]:
    instance = str(event.source.get("instance_id", ""))
    container = str(event.process.get("container_id", ""))
    return str(event.source["kind"]), instance, container


def _strong_process_keys(event: RuntimeEvent) -> tuple[tuple[Any, ...], ...]:
    scope = _scope(event)
    exec_id = _string(event.process.get("exec_id"), max_length=2048)
    if exec_id is not None:
        return ((*scope, "exec", exec_id),)
    pid = _integer(event.process.get("pid"))
    start_time = _string(event.process.get("start_time"), max_length=40)
    if pid is not None and start_time is not None:
        return ((*scope, "pid-start", pid, start_time),)
    return ()


def _strong_parent_keys(event: RuntimeEvent) -> tuple[tuple[Any, ...], ...]:
    scope = _scope(event)
    parent_exec = _string(event.process.get("parent_exec_id"), max_length=2048)
    if parent_exec is not None:
        return ((*scope, "exec", parent_exec),)
    ppid = _integer(event.process.get("ppid"))
    parent_start = _string(event.process.get("parent_start_time"), max_length=40)
    if ppid is not None and parent_start is not None:
        return ((*scope, "pid-start", ppid, parent_start),)
    return ()


def _weak_process_keys(event: RuntimeEvent) -> tuple[tuple[Any, ...], ...]:
    pid = _integer(event.process.get("pid"))
    return ((*_scope(event), "pid-only", pid),) if pid is not None else ()


def _weak_parent_keys(event: RuntimeEvent) -> tuple[tuple[Any, ...], ...]:
    ppid = _integer(event.process.get("ppid"))
    return ((*_scope(event), "pid-only", ppid),) if ppid is not None else ()


def _owner(
    keys: Sequence[tuple[Any, ...]], owners: Mapping[tuple[Any, ...], set[str]]
) -> tuple[str | None, tuple[str, ...]]:
    candidates = tuple(
        sorted({receipt_id for key in keys for receipt_id in owners.get(key, set())})
    )
    return (candidates[0] if len(candidates) == 1 else None), candidates


def _receipt_by_id(
    receipts: Sequence[Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    return {str(receipt["receipt_id"]): receipt for receipt in receipts}


def _propagate_process_ownership(
    associations: list[_Association],
    receipts: Sequence[Mapping[str, Any]],
    *,
    window_s: int,
) -> list[_Association]:
    strong: dict[tuple[Any, ...], set[str]] = {}
    weak: dict[tuple[Any, ...], set[str]] = {}
    receipt_map = _receipt_by_id(receipts)

    def seed(item: _Association) -> None:
        if item.match_status != "matched" or item.receipt_id is None:
            return
        for key in _strong_process_keys(item.event):
            strong.setdefault(key, set()).add(item.receipt_id)
        for key in _weak_process_keys(item.event):
            weak.setdefault(key, set()).add(item.receipt_id)

    for item in associations:
        seed(item)
    current = list(associations)
    for _pass in range(len(current)):
        changed = False
        for index, item in enumerate(current):
            if item.match_status == "matched":
                continue
            explicit_hint = _string(
                item.event.correlation.get("receipt_id"), max_length=2048
            )
            if explicit_hint is not None and explicit_hint not in receipt_map:
                continue
            same_owner, same_candidates = _owner(
                _strong_process_keys(item.event), strong
            )
            parent_owner, parent_candidates = _owner(
                _strong_parent_keys(item.event), strong
            )
            candidates = set((*same_candidates, *parent_candidates))
            process_owner_conflict = len(candidates) > 1
            receipt_process_conflict = bool(
                explicit_hint is not None
                and candidates
                and explicit_hint not in candidates
            )
            if process_owner_conflict or receipt_process_conflict:
                if explicit_hint is not None:
                    candidates.add(explicit_hint)
                reasons = set(item.reason_codes)
                if process_owner_conflict:
                    reasons.add("process_identity_conflict")
                if receipt_process_conflict:
                    reasons.add("receipt_process_conflict")
                current[index] = _Association(
                    item.event,
                    None,
                    tuple(sorted(candidates)),
                    "ambiguous",
                    "ambiguous",
                    "non_proof",
                    tuple(sorted(reasons)),
                )
                continue
            if len(candidates) == 1:
                receipt_id = next(iter(candidates))
                reason = (
                    "same_process_identity" if same_owner else "parent_process_identity"
                )
                if _time_matches(item.event, receipt_map[receipt_id], window_s):
                    current[index] = _Association(
                        item.event,
                        receipt_id,
                        (receipt_id,),
                        "matched",
                        "medium",
                        "corroborating_unverified",
                        (reason, "time_window"),
                    )
                    seed(current[index])
                    changed = True
                    continue
                current[index] = _Association(
                    item.event,
                    receipt_id,
                    (receipt_id,),
                    "weak",
                    "low",
                    "non_proof",
                    (reason, "time_outside_window"),
                )
                continue
            weak_same, weak_same_candidates = _owner(
                _weak_process_keys(item.event), weak
            )
            weak_parent, weak_parent_candidates = _owner(
                _weak_parent_keys(item.event), weak
            )
            weak_candidates = set((*weak_same_candidates, *weak_parent_candidates))
            pid_owner_conflict = len(weak_candidates) > 1
            receipt_pid_conflict = bool(
                explicit_hint is not None
                and weak_candidates
                and explicit_hint not in weak_candidates
            )
            if pid_owner_conflict or receipt_pid_conflict:
                if explicit_hint is not None:
                    weak_candidates.add(explicit_hint)
                reasons: set[str] = set()
                if pid_owner_conflict:
                    reasons.add("pid_only_identity_conflict")
                if receipt_pid_conflict:
                    reasons.add("receipt_process_conflict")
                current[index] = _Association(
                    item.event,
                    None,
                    tuple(sorted(weak_candidates)),
                    "ambiguous",
                    "ambiguous",
                    "non_proof",
                    tuple(sorted(reasons)),
                )
            elif len(weak_candidates) == 1:
                receipt_id = next(iter(weak_candidates))
                current[index] = _Association(
                    item.event,
                    receipt_id,
                    (receipt_id,),
                    "weak",
                    "low",
                    "non_proof",
                    ("pid_only_unstable",),
                )
        if not changed:
            break
    return current


def _event_pointer(event: RuntimeEvent) -> dict[str, Any]:
    redacted: set[str] = {"event_id"}
    if event.process.get("exec_id") is not None:
        redacted.add("exec_id")
    if event.process.get("container_id") is not None:
        redacted.add("container_id")
    for name in ("actor", "session_id", "trace_id"):
        if event.correlation.get(name) is not None:
            redacted.add(name)
    for name in ("command", "destination", "path", "workspace"):
        if event.details.get(name) is not None:
            redacted.add(name)
    return {
        "line": event.line,
        "sha256": event.line_sha256,
        "event_type": event.record["event_type"],
        "source_kind": event.source["kind"],
        "source_assurance": SOURCE_ASSURANCE,
        "coverage": event.source["coverage"],
        "pid_present": event.process.get("pid") is not None,
        "ppid_present": event.process.get("ppid") is not None,
        "stable_process_identity_present": bool(_strong_process_keys(event)),
        "redacted_fields": sorted(redacted),
    }


def _coverage(events: Sequence[RuntimeEvent]) -> str:
    values = {str(event.source["coverage"]) for event in events}
    return next(iter(values)) if len(values) == 1 else "mixed"


def _public_association(item: _Association) -> dict[str, Any]:
    return {
        "event": _event_pointer(item.event),
        "receipt_id": item.receipt_id,
        "match_status": item.match_status,
        "confidence": item.confidence,
        "proof_status": item.proof_status,
        "reason_codes": list(item.reason_codes),
    }


def _receipt_summaries(
    receipts: Sequence[Mapping[str, Any]], associations: Sequence[_Association]
) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for receipt in receipts:
        receipt_id = str(receipt["receipt_id"])
        matched = [
            item
            for item in associations
            if item.match_status == "matched" and item.receipt_id == receipt_id
        ]
        ambiguous = [
            item
            for item in associations
            if item.match_status in {"ambiguous", "weak"}
            and receipt_id in item.candidate_receipt_ids
        ]
        status = (
            "corroborated" if matched else "ambiguous" if ambiguous else "unobserved"
        )
        summaries.append(
            {
                "receipt_id": receipt_id,
                "receipt_index": int(receipt["index"]),
                "evidence_status": status,
                "matched_event_count": len(matched),
                "ambiguous_event_count": len(ambiguous),
                "event_types": sorted(
                    {
                        str(item.event.record["event_type"])
                        for item in (*matched, *ambiguous)
                    }
                ),
            }
        )
    return summaries


def correlate_verified_report(
    receipt_report: Mapping[str, Any],
    event_batch: EventBatch,
    *,
    correlation_window_s: int = DEFAULT_CORRELATION_WINDOW_S,
) -> dict[str, Any]:
    """Correlate a verified offline-explorer report with imported events."""

    if receipt_report.get("valid") is not True or receipt_report.get("result") not in {
        "verified",
        "verified_chain_only",
    }:
        raise RuntimeEvidenceError(
            "receipt_report_unverified",
            "runtime correlation requires a verified receipt report",
        )
    if not isinstance(correlation_window_s, int) or isinstance(
        correlation_window_s, bool
    ):
        raise RuntimeEvidenceError(
            "correlation_window_invalid", "correlation window must be an integer"
        )
    if correlation_window_s < 0 or correlation_window_s > 3600:
        raise RuntimeEvidenceError(
            "correlation_window_invalid",
            "correlation window must be between 0 and 3600 seconds",
        )
    receipts = receipt_report.get("timeline")
    if not isinstance(receipts, list) or not receipts:
        raise RuntimeEvidenceError(
            "receipt_report_empty",
            "verified receipt report contains no timeline entries",
        )
    required = {
        "index",
        "timestamp",
        "receipt_id",
        "trace_id",
        "actor",
        "tool",
        "action_class",
        "target",
        "side_effect_class",
    }
    for receipt in receipts:
        if not isinstance(receipt, dict) or not required <= set(receipt):
            raise RuntimeEvidenceError(
                "receipt_report_invalid",
                "verified receipt report lacks required signed projections",
            )
    ordered_events = sorted(
        event_batch.events, key=lambda event: (event.observed_at, event.line)
    )
    direct = [
        _direct_association(event, receipts, window_s=correlation_window_s)
        for event in ordered_events
    ]
    associations = _propagate_process_ownership(
        direct, receipts, window_s=correlation_window_s
    )
    associations.sort(key=lambda item: item.event.line)
    receipt_summaries = _receipt_summaries(receipts, associations)
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "receipt_verification": {
            "verified": True,
            "result": receipt_report["result"],
            "receipt_count": len(receipts),
            "source_sha256": receipt_report["source"]["sha256"],
        },
        "event_source": {
            "format": event_batch.source_format,
            "sha256": event_batch.source_sha256,
            "assurance": SOURCE_ASSURANCE,
            "coverage": _coverage(event_batch.events),
        },
        "summary": {
            "receipt_count": len(receipts),
            "event_count": len(associations),
            "matched_event_count": sum(
                item.match_status == "matched" for item in associations
            ),
            "ambiguous_event_count": sum(
                item.match_status == "ambiguous" for item in associations
            ),
            "weak_event_count": sum(
                item.match_status == "weak" for item in associations
            ),
            "unmatched_event_count": sum(
                item.match_status == "unmatched" for item in associations
            ),
            "corroborated_receipt_count": sum(
                item["evidence_status"] == "corroborated" for item in receipt_summaries
            ),
            "ambiguous_receipt_count": sum(
                item["evidence_status"] == "ambiguous" for item in receipt_summaries
            ),
            "unobserved_receipt_count": sum(
                item["evidence_status"] == "unobserved" for item in receipt_summaries
            ),
        },
        "associations": [_public_association(item) for item in associations],
        "receipt_summaries": receipt_summaries,
        "sensitive_output_redacted": True,
        "limitations": [
            "imported sensor JSON is not authenticated by this report",
            "correlation confidence measures association strength, not sensor truth or independent proof",
            "weak and ambiguous associations are non-proof",
            "missing events do not prove absence without separately attested sensor coverage",
            "Falco JSON is normally alert-scoped; missing alerts do not imply complete runtime coverage",
            "the report is detached and does not mutate the signed receipt chain",
        ],
    }
    try:
        _REPORT_VALIDATOR.validate(report)
    except ValidationError as exc:
        location = ".".join(str(part) for part in exc.absolute_path) or "root"
        raise RuntimeEvidenceError(
            "report_schema_invalid",
            f"generated runtime evidence report violates its schema at {location} ({exc.validator})",
        ) from exc
    return report


def canonical_report_bytes(report: Mapping[str, Any]) -> bytes:
    """Return deterministic RFC 8785 bytes for storage or fixture comparison."""

    try:
        _REPORT_VALIDATOR.validate(report)
    except ValidationError as exc:
        raise RuntimeEvidenceError(
            "report_schema_invalid", "runtime evidence report failed schema validation"
        ) from exc
    return canonical_json_bytes(dict(report)) + b"\n"


def render_text_report(report: Mapping[str, Any]) -> str:
    """Render a bounded text report without raw sensor details or local paths."""

    summary = report["summary"]
    source = report["event_source"]
    lines = [
        "Ardur runtime evidence correlation",
        (
            f"Receipts: {summary['receipt_count']} verified | Events: {summary['event_count']} "
            f"imported ({source['format']}, {source['assurance']}, coverage={source['coverage']})"
        ),
        (
            f"Associations: matched={summary['matched_event_count']} "
            f"ambiguous={summary['ambiguous_event_count']} weak={summary['weak_event_count']} "
            f"unmatched={summary['unmatched_event_count']}"
        ),
        "Event associations:",
    ]
    for item in report["associations"]:
        event = item["event"]
        receipt_id = item["receipt_id"] or "none"
        lines.append(
            f"  line={event['line']} sha256={event['sha256']} type={event['event_type']} "
            f"receipt={receipt_id} status={item['match_status']} confidence={item['confidence']} "
            f"proof={item['proof_status']} reasons={','.join(item['reason_codes'])}"
        )
    lines.append("Limitations:")
    lines.extend(f"  - {item}" for item in report["limitations"])
    return "\n".join(lines) + "\n"


def write_report(path: str | Path, payload: bytes) -> None:
    """Atomically replace a regular report through a no-follow directory handle."""

    output = Path(path).expanduser()
    output_name = output.name
    if output_name in {"", ".", ".."}:
        raise RuntimeEvidenceError(
            "output_name_invalid", "runtime evidence report output name is invalid"
        )

    parent_fd = -1
    temporary_fd = -1
    temporary_name: str | None = None
    try:
        parent_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            parent_fd = os.open(output.parent, parent_flags)
        except OSError as exc:
            raise RuntimeEvidenceError(
                "output_parent_invalid",
                "runtime evidence report parent must be a real directory",
            ) from exc
        if not stat.S_ISDIR(os.fstat(parent_fd).st_mode):
            raise RuntimeEvidenceError(
                "output_parent_invalid",
                "runtime evidence report parent must be a real directory",
            )

        try:
            existing = os.stat(output_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if stat.S_ISLNK(existing.st_mode):
                raise RuntimeEvidenceError(
                    "output_symlink",
                    "runtime evidence report output must not be a symlink",
                )
            if not stat.S_ISREG(existing.st_mode):
                raise RuntimeEvidenceError(
                    "output_not_regular",
                    "runtime evidence report output must be a regular file",
                )

        create_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        for _ in range(32):
            candidate = f".{output_name}.{secrets.token_hex(8)}"
            try:
                temporary_fd = os.open(candidate, create_flags, 0o600, dir_fd=parent_fd)
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        else:
            raise RuntimeEvidenceError(
                "output_temporary_unavailable",
                "runtime evidence report temporary output could not be created safely",
            )

        os.fchmod(temporary_fd, 0o600)
        handle = os.fdopen(temporary_fd, "wb")
        temporary_fd = -1
        with handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            temporary_name,
            output_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temporary_name = None
        os.fsync(parent_fd)
    except RuntimeEvidenceError:
        raise
    except OSError as exc:
        raise RuntimeEvidenceError(
            "output_write_failed",
            "runtime evidence report could not be written safely",
        ) from exc
    finally:
        if temporary_fd >= 0:
            try:
                os.close(temporary_fd)
            except OSError:
                pass
        if temporary_name is not None and parent_fd >= 0:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except OSError:
                pass
        if parent_fd >= 0:
            try:
                os.close(parent_fd)
            except OSError:
                pass
