"""Verified, redacted Execution Receipt telemetry export."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib import error, parse, request

from cryptography.hazmat.primitives.asymmetric import ec
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from . import __version__
from ._specs import governance_telemetry_v01_schema
from .canonical_json import canonical_json_bytes
from .offline_verification import (
    OfflineVerificationError,
    load_offline_input,
    verify_offline_input,
)
from .runtime_evidence import RuntimeEvidenceError, write_report
from .shareable_redaction import redact_local_paths

EVENT_SCHEMA_VERSION = "ardur.governance_telemetry_event.v0.1"
EVENT_NAME = "ardur.governance.decision"
SCOPE_NAME = "io.ardur.governance"
MAX_RESPONSE_BYTES = 1024 * 1024
DEFAULT_TIMEOUT_S = 10
_UINT64_MAX = (1 << 64) - 1
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+$")
_RFC3339_RE = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?"
    r"(?P<zone>Z|[+-]\d{2}:\d{2})$"
)
_FORBIDDEN_HEADERS = {
    "connection",
    "content-length",
    "content-type",
    "host",
    "transfer-encoding",
}
_VALIDATOR = Draft202012Validator(
    governance_telemetry_v01_schema(),
    format_checker=FormatChecker(),
)


class TelemetryExportError(ValueError):
    """A verified telemetry projection or delivery failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _schema_error(exc: ValidationError, *, index: int) -> TelemetryExportError:
    location = ".".join(str(part) for part in exc.absolute_path) or "root"
    return TelemetryExportError(
        "event_schema_invalid",
        f"governance telemetry event {index} violates its schema at {location}",
    )


def _budget_decision(item: Mapping[str, Any]) -> str:
    if item["reason_code"] == "budget_exhausted":
        return "denied"
    if item["decision"] == "PERMIT":
        return "allowed"
    return "not_applicable"


def _policy_projection(item: Mapping[str, Any]) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for decision in item.get("policy_outcomes", []):
        if not isinstance(decision, Mapping):
            continue
        projected.append(
            {
                "backend": str(decision.get("backend") or "unknown"),
                "decision": str(decision.get("decision") or "unknown"),
                "rule_id": (
                    str(decision["rule_id"])
                    if decision.get("rule_id") is not None
                    else None
                ),
            }
        )
    return projected


def verified_governance_events(
    journal: str | Path,
    *,
    receipt_public_key: ec.EllipticCurvePublicKey,
    verify_expiry: bool = False,
) -> list[dict[str, Any]]:
    """Verify a receipt journal and return conservative telemetry events."""

    try:
        report = verify_offline_input(
            load_offline_input(journal),
            receipt_public_key=receipt_public_key,
            chain_only=True,
            verify_expiry=verify_expiry,
            redact=True,
            include_correlation_fields=True,
        )
    except OfflineVerificationError as exc:
        raise TelemetryExportError(exc.code, str(exc)) from exc

    events: list[dict[str, Any]] = []
    source_sha256 = str(report["source"]["sha256"])
    for index, item in enumerate(report["timeline"]):
        authority = item["authority"]
        event = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "event_name": EVENT_NAME,
            "timestamp": item["timestamp"],
            "receipt_id": item["receipt_id"],
            "parent_receipt_hash": item["parent_receipt_hash"],
            "trace_id": item["trace_id"],
            "actor": item["actor"],
            "verifier_id": item["verifier_id"],
            "grant_id": item["grant_id"],
            "decision": item["decision"],
            "verdict": item["verdict"],
            "reason_code": item["reason_code"],
            "policy_decisions": _policy_projection(item),
            "budget": {
                "decision": _budget_decision(item),
                "remaining": authority["budget_remaining"],
                "delta": authority["budget_delta"],
            },
            "risk": {
                "tool": item["tool"],
                "action_class": item["action_class"],
                "resource_family": item["resource_family"],
                "side_effect_class": item["side_effect_class"],
                "sensitivity": item["sensitivity"],
                "instruction_bearing": item["instruction_bearing"],
            },
            "invocation": {
                "digest": item["invocation_digest"],
                "arguments_sha256": item["arguments_hash"],
                "raw_content_exported": False,
            },
            "verification": {
                "receipt_signature_valid": True,
                "chain_link_valid": True,
                "identity_claims_signed": True,
                "spiffe_workload_identity_verified": False,
                "mode": "verified_chain_only",
                "source_sha256": source_sha256,
            },
        }
        event = redact_local_paths(event)
        try:
            _VALIDATOR.validate(event)
        except ValidationError as exc:
            raise _schema_error(exc, index=index) from exc
        events.append(event)
    return events


def jsonl_bytes(events: Sequence[Mapping[str, Any]]) -> bytes:
    """Return deterministic RFC 8785 JSONL after schema validation."""

    lines: list[bytes] = []
    for index, event in enumerate(events):
        try:
            _VALIDATOR.validate(event)
        except ValidationError as exc:
            raise _schema_error(exc, index=index) from exc
        lines.append(canonical_json_bytes(dict(event)) + b"\n")
    return b"".join(lines)


def _any_value(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, str):
        return {"stringValue": value}
    if isinstance(value, Mapping):
        return {
            "kvlistValue": {
                "values": [
                    {"key": str(key), "value": _any_value(item)}
                    for key, item in sorted(value.items())
                    if item is not None
                ]
            }
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return {"arrayValue": {"values": [_any_value(item) for item in value]}}
    raise TelemetryExportError(
        "otlp_attribute_invalid",
        f"unsupported OTLP attribute value type {type(value).__name__}",
    )


def _attributes(values: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {"key": key, "value": _any_value(value)}
        for key, value in sorted(values.items())
        if value is not None
    ]


def _epoch_ns(timestamp: str) -> str:
    match = _RFC3339_RE.fullmatch(timestamp)
    if match is None:
        raise TelemetryExportError(
            "timestamp_invalid", "telemetry timestamp must be RFC 3339 with an offset"
        )
    zone = "+00:00" if match.group("zone") == "Z" else match.group("zone")
    try:
        base = datetime.fromisoformat(match.group("base") + zone)
    except ValueError as exc:
        raise TelemetryExportError(
            "timestamp_invalid", "telemetry timestamp is outside the supported range"
        ) from exc
    fraction = (match.group("fraction") or "").ljust(9, "0")
    epoch_ns = int(base.timestamp()) * 1_000_000_000 + int(fraction or "0")
    if not 0 <= epoch_ns <= _UINT64_MAX:
        raise TelemetryExportError(
            "timestamp_out_of_range",
            "telemetry timestamp is outside the OTLP uint64 nanosecond range",
        )
    return str(epoch_ns)


def _otel_id(domain: str, value: str, size: int) -> str:
    return hashlib.sha256(f"{domain}:{value}".encode("utf-8")).hexdigest()[: size * 2]


def _event_attributes(event: Mapping[str, Any]) -> dict[str, Any]:
    policies = event["policy_decisions"]
    invocation = event["invocation"]
    risk = event["risk"]
    budget = event["budget"]
    return {
        "ardur.receipt.id": event["receipt_id"],
        "ardur.receipt.parent_hash": event["parent_receipt_hash"],
        "ardur.trace.id": event["trace_id"],
        "ardur.agent.id": event["actor"],
        "ardur.verifier.id": event["verifier_id"],
        "ardur.grant.id": event["grant_id"],
        "ardur.decision": event["decision"],
        "ardur.verdict": event["verdict"],
        "ardur.reason.code": event["reason_code"],
        "ardur.policy.backends": [item["backend"] for item in policies],
        "ardur.policy.decisions": [item["decision"] for item in policies],
        "ardur.policy.rule_ids": [
            item["rule_id"] for item in policies if item["rule_id"] is not None
        ],
        "ardur.budget.decision": budget["decision"],
        "ardur.budget.remaining": budget["remaining"],
        "ardur.tool.name": risk["tool"],
        "ardur.action.class": risk["action_class"],
        "ardur.resource.family": risk["resource_family"],
        "ardur.side_effect.class": risk["side_effect_class"],
        "ardur.risk.sensitivity": risk["sensitivity"],
        "ardur.risk.instruction_bearing": risk["instruction_bearing"],
        "ardur.invocation.digest": invocation["digest"].get("value"),
        "ardur.arguments.sha256": invocation["arguments_sha256"],
        "ardur.raw_content_exported": False,
        "ardur.verification.receipt_signature_valid": True,
        "ardur.verification.chain_link_valid": True,
        "ardur.verification.identity_claims_signed": event["verification"][
            "identity_claims_signed"
        ],
        "ardur.verification.spiffe_workload_identity_verified": event[
            "verification"
        ]["spiffe_workload_identity_verified"],
        "ardur.source.sha256": event["verification"]["source_sha256"],
    }


def otlp_payloads(
    events: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Build OTLP/HTTP JSON trace and log service requests."""

    spans: list[dict[str, Any]] = []
    logs: list[dict[str, Any]] = []
    previous_span_id: str | None = None
    for index, event in enumerate(events):
        try:
            _VALIDATOR.validate(event)
        except ValidationError as exc:
            raise _schema_error(exc, index=index) from exc
        trace_id = _otel_id("trace", str(event["trace_id"]), 16)
        span_id = _otel_id("receipt", str(event["receipt_id"]), 8)
        timestamp_ns = _epoch_ns(str(event["timestamp"]))
        attributes = _attributes(_event_attributes(event))
        span: dict[str, Any] = {
            "traceId": trace_id,
            "spanId": span_id,
            "name": EVENT_NAME,
            "kind": 1,
            "startTimeUnixNano": timestamp_ns,
            "endTimeUnixNano": timestamp_ns,
            "attributes": attributes,
        }
        if event["parent_receipt_hash"] is not None:
            if previous_span_id is None:
                raise TelemetryExportError(
                    "parent_span_missing",
                    "non-root receipt does not have a previous verified span",
                )
            span["parentSpanId"] = previous_span_id
        spans.append(span)

        severity_number, severity_text = {
            "PERMIT": (9, "INFO"),
            "DENY": (13, "WARN"),
            "ERROR": (17, "ERROR"),
            "UNKNOWN": (17, "ERROR"),
        }[str(event["decision"])]
        logs.append(
            {
                "timeUnixNano": timestamp_ns,
                "observedTimeUnixNano": timestamp_ns,
                "severityNumber": severity_number,
                "severityText": severity_text,
                "traceId": trace_id,
                "spanId": span_id,
                "eventName": EVENT_NAME,
                "body": {
                    "stringValue": f"Ardur governance decision {event['decision']}"
                },
                "attributes": attributes,
            }
        )
        previous_span_id = span_id

    resource = _attributes(
        {
            "service.name": "ardur",
            "service.version": __version__,
        }
    )
    scope = {"name": SCOPE_NAME, "version": __version__}
    return {
        "traces": {
            "resourceSpans": [
                {
                    "resource": {"attributes": resource},
                    "scopeSpans": [{"scope": scope, "spans": spans}],
                }
            ]
        },
        "logs": {
            "resourceLogs": [
                {
                    "resource": {"attributes": resource},
                    "scopeLogs": [{"scope": scope, "logRecords": logs}],
                }
            ]
        },
    }


def otlp_bundle_bytes(payloads: Mapping[str, Mapping[str, Any]]) -> bytes:
    """Return a deterministic inspection bundle containing both OTLP requests."""

    return canonical_json_bytes(dict(payloads)) + b"\n"


def _is_loopback(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def signal_endpoint(base: str, signal: str) -> str:
    """Validate an OTLP base endpoint and append the standard signal path."""

    try:
        parsed = parse.urlsplit(base)
        port = parsed.port
    except ValueError as exc:
        raise TelemetryExportError(
            "otlp_endpoint_invalid", "OTLP endpoint is malformed"
        ) from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise TelemetryExportError(
            "otlp_endpoint_invalid",
            "OTLP endpoint must be an http(s) URL without credentials, query, or fragment",
        )
    if parsed.scheme == "http" and not _is_loopback(parsed.hostname):
        raise TelemetryExportError(
            "otlp_endpoint_insecure",
            "plain HTTP OTLP is allowed only for loopback collectors",
        )
    if port is not None and not 1 <= port <= 65535:
        raise TelemetryExportError(
            "otlp_endpoint_invalid", "OTLP endpoint port is invalid"
        )
    if signal not in {"traces", "logs"}:
        raise TelemetryExportError("otlp_signal_invalid", "unsupported OTLP signal")
    path = parsed.path.rstrip("/") + f"/v1/{signal}"
    return parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _parse_header_string(raw: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    if not raw.strip():
        return headers
    for entry in raw.split(","):
        if "=" not in entry:
            raise TelemetryExportError(
                "otlp_headers_invalid",
                "OTLP headers must use comma-separated name=value entries",
            )
        encoded_name, encoded_value = entry.split("=", 1)
        name = parse.unquote(encoded_name).strip()
        value = parse.unquote(encoded_value).strip()
        if (
            not _HEADER_NAME_RE.fullmatch(name)
            or name.lower() in _FORBIDDEN_HEADERS
            or "\r" in value
            or "\n" in value
        ):
            raise TelemetryExportError(
                "otlp_headers_invalid", "OTLP header name or value is unsafe"
            )
        headers[name] = value
    return headers


def _signal_headers(signal: str, environ: Mapping[str, str]) -> dict[str, str]:
    headers = _parse_header_string(environ.get("OTEL_EXPORTER_OTLP_HEADERS", ""))
    specific = environ.get(f"OTEL_EXPORTER_OTLP_{signal.upper()}_HEADERS", "")
    headers.update(_parse_header_string(specific))
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"
    return headers


def _check_response(signal: str, body: bytes) -> None:
    if len(body) > MAX_RESPONSE_BYTES:
        raise TelemetryExportError(
            "otlp_response_too_large", "OTLP collector response exceeds 1 MiB"
        )
    if not body:
        return
    try:
        response = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TelemetryExportError(
            "otlp_response_invalid", "OTLP collector returned invalid JSON"
        ) from exc
    if not isinstance(response, dict):
        raise TelemetryExportError(
            "otlp_response_invalid", "OTLP collector response must be an object"
        )
    partial = response.get("partialSuccess")
    if not isinstance(partial, dict):
        return
    field = "rejectedSpans" if signal == "traces" else "rejectedLogRecords"
    rejected_raw = partial.get(field, 0)
    if isinstance(rejected_raw, bool) or not isinstance(rejected_raw, (int, str)):
        raise TelemetryExportError(
            "otlp_response_invalid", "OTLP partial-success count is invalid"
        )
    try:
        rejected = int(rejected_raw)
    except ValueError as exc:
        raise TelemetryExportError(
            "otlp_response_invalid", "OTLP partial-success count is invalid"
        ) from exc
    if rejected < 0:
        raise TelemetryExportError(
            "otlp_response_invalid", "OTLP partial-success count is invalid"
        )
    if rejected:
        raise TelemetryExportError(
            "otlp_partial_rejection",
            f"OTLP collector rejected {rejected} {signal} records",
        )


def export_otlp_http(
    payloads: Mapping[str, Mapping[str, Any]],
    *,
    endpoint: str,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    environ: Mapping[str, str] | None = None,
    urlopen: Callable[..., Any] = request.urlopen,
) -> list[dict[str, Any]]:
    """Send one trace and one log request without automatic retry."""

    if (
        not isinstance(timeout_s, int)
        or isinstance(timeout_s, bool)
        or not 1 <= timeout_s <= 60
    ):
        raise TelemetryExportError(
            "otlp_timeout_invalid",
            "OTLP timeout must be an integer from 1 to 60 seconds",
        )
    environment = os.environ if environ is None else environ
    results: list[dict[str, Any]] = []
    for signal in ("traces", "logs"):
        url = signal_endpoint(endpoint, signal)
        payload = canonical_json_bytes(dict(payloads[signal]))
        req = request.Request(
            url,
            data=payload,
            headers=_signal_headers(signal, environment),
            method="POST",
        )
        try:
            with urlopen(req, timeout=timeout_s) as response:
                status_value = getattr(response, "status", None)
                status = int(
                    response.getcode() if status_value is None else status_value
                )
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except error.HTTPError as exc:
            raise TelemetryExportError(
                "otlp_http_error",
                f"OTLP {signal} collector returned HTTP {exc.code}",
            ) from exc
        except (error.URLError, TimeoutError, OSError) as exc:
            raise TelemetryExportError(
                "otlp_delivery_failed", f"OTLP {signal} delivery failed"
            ) from exc
        if status != 200:
            raise TelemetryExportError(
                "otlp_http_error",
                f"OTLP {signal} collector returned HTTP {status}",
            )
        _check_response(signal, body)
        results.append({"signal": signal, "status": status})
    return results


def write_export(path: str | Path, payload: bytes) -> None:
    """Atomically write an owner-only export through the shared hardened writer."""

    try:
        write_report(path, payload)
    except RuntimeEvidenceError as exc:
        raise TelemetryExportError(exc.code, str(exc)) from exc
