from __future__ import annotations

import copy
import hashlib
import json
import stat
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from vibap.cli import main as cli_main
from vibap.denial import DenialReason
from vibap.proxy import Decision, GovernanceProxy, PolicyEvent
from vibap.receipt import build_receipt, sign_receipt
from vibap.receipt_telemetry import (
    TelemetryExportError,
    export_otlp_http,
    jsonl_bytes,
    otlp_bundle_bytes,
    otlp_payloads,
    signal_endpoint,
    verified_governance_events,
    write_export,
)

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = (
    ROOT
    / "docs"
    / "specs"
    / "conformance"
    / "governance-telemetry-v0.1"
    / "events.jsonl"
)


def _event(
    *,
    step: int,
    decision: Decision,
    target: str,
    reason: str,
    denial_reason: DenialReason | None = None,
) -> PolicyEvent:
    return PolicyEvent(
        timestamp=f"2030-01-01T00:00:0{step}Z",
        step_id=f"step:telemetry:{step}",
        actor="spiffe://example.test/agent/telemetry",
        verifier_id="spiffe://example.test/verifier/telemetry",
        tool_name="Bash",
        arguments={
            "command": target,
            "token": "telemetry-private-token",
        },
        action_class="execute",
        target=target,
        resource_family="process",
        side_effect_class="process_launch",
        decision=decision,
        reason=reason,
        passport_jti="grant:telemetry",
        trace_id="trace:telemetry",
        run_nonce="telemetry_fixture_nonce_0123456789",
        denial_reason=denial_reason,
        budget_delta={
            "operation": "consume" if decision is Decision.PERMIT else "reject",
            "resource": "tool_call",
            "unit": "tool_call",
            "amount": 1 if decision is Decision.PERMIT else 0,
            "remaining_after": 1 if decision is Decision.PERMIT else 0,
        },
    )


def _signed_journal(
    tmp_path: Path,
) -> tuple[Path, Path, ec.EllipticCurvePrivateKey]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    permit_event = _event(
        step=1,
        decision=Decision.PERMIT,
        target="cat /Users/alice/private.txt token=telemetry-private-target",
        reason="allowed token=telemetry-private-reason",
    )
    permit = build_receipt(
        Decision.PERMIT,
        permit_event,
        policy_decisions=[
            {
                "backend": "cedar",
                "decision": "Allow",
                "reason": permit_event.reason,
                "rule_id": "workspace_scope",
            }
        ],
        budget_remaining={"tool_call": 1},
    )
    permit_token = sign_receipt(permit, private_key)

    deny_event = _event(
        step=2,
        decision=Decision.DENY,
        target="rm -rf /Users/alice/private",
        reason="budget denied secret=telemetry-private-denial",
        denial_reason=DenialReason.BUDGET_EXHAUSTED,
    )
    deny = build_receipt(
        Decision.DENY,
        deny_event,
        parent_receipt_hash=hashlib.sha256(permit_token.encode("ascii")).hexdigest(),
        policy_decisions=[
            {
                "backend": "native",
                "decision": "Deny",
                "reason": deny_event.reason,
                "rule_id": "session_budget",
            }
        ],
        budget_remaining={"tool_call": 0},
    )
    deny_token = sign_receipt(deny, private_key)

    journal = tmp_path / "receipts.jsonl"
    journal.write_text(
        json.dumps({"jwt": permit_token})
        + "\n"
        + json.dumps({"jwt": deny_token})
        + "\n",
        encoding="utf-8",
    )
    public_key = tmp_path / "receipt-public.pem"
    public_key.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return journal, public_key, private_key


def _golden_event() -> dict[str, Any]:
    return json.loads(GOLDEN.read_text(encoding="utf-8"))


def _attributes_by_key(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {item["key"]: item["value"] for item in items}


def test_golden_event_is_schema_valid_and_canonical() -> None:
    raw = GOLDEN.read_bytes()
    event = _golden_event()
    assert jsonl_bytes([event]) == raw


def test_proxy_preserves_configured_policy_label_as_signed_rule_id() -> None:
    event = _event(
        step=1,
        decision=Decision.PERMIT,
        target="fixture",
        reason="allowed",
    )
    event.policy_decisions = [
        {
            "backend": "cedar",
            "label": "workspace_scope",
            "decision": "Allow",
            "reasons": ["within workspace"],
        }
    ]

    assert GovernanceProxy._signed_policy_decisions(
        event, Decision.PERMIT, event.reason
    ) == [
        {
            "backend": "cedar",
            "decision": "Allow",
            "reason": "within workspace",
            "rule_id": "workspace_scope",
        }
    ]


def test_verified_export_links_receipts_and_omits_sensitive_content(
    tmp_path: Path,
) -> None:
    journal, _public_path, private_key = _signed_journal(tmp_path)

    events = verified_governance_events(
        journal,
        receipt_public_key=private_key.public_key(),
    )

    assert [item["decision"] for item in events] == ["PERMIT", "DENY"]
    assert events[0]["parent_receipt_hash"] is None
    assert events[1]["parent_receipt_hash"] is not None
    assert events[0]["policy_decisions"] == [
        {
            "backend": "cedar",
            "decision": "Allow",
            "rule_id": "workspace_scope",
        }
    ]
    assert events[1]["reason_code"] == "budget_exhausted"
    assert events[1]["budget"]["decision"] == "denied"
    serialized = jsonl_bytes(events).decode("utf-8")
    for private_value in (
        "telemetry-private-token",
        "telemetry-private-target",
        "telemetry-private-reason",
        "telemetry-private-denial",
        "/Users/alice",
        "rm -rf",
        "cat ",
    ):
        assert private_value not in serialized
    assert '"raw_content_exported":false' in serialized
    assert '"target"' not in serialized
    assert '"reason"' not in serialized


def test_tampered_journal_is_rejected_before_export(tmp_path: Path) -> None:
    journal, _public_path, private_key = _signed_journal(tmp_path)
    records = [json.loads(line) for line in journal.read_text().splitlines()]
    token = records[0]["jwt"]
    records[0]["jwt"] = token[:-1] + ("A" if token[-1] != "A" else "B")
    journal.write_text(
        "".join(json.dumps(item) + "\n" for item in records),
        encoding="utf-8",
    )

    with pytest.raises(TelemetryExportError) as exc_info:
        verified_governance_events(
            journal,
            receipt_public_key=private_key.public_key(),
        )
    assert exc_info.value.code == "receipt_chain_invalid"


def test_otlp_payload_has_fixed_ids_parent_link_and_redacted_attributes() -> None:
    root = _golden_event()
    child = copy.deepcopy(root)
    child["receipt_id"] = "receipt:fixture-v02-deny"
    child["parent_receipt_hash"] = "c" * 64
    child["timestamp"] = "2026-07-10T00:00:01.123456789Z"
    child["decision"] = "DENY"
    child["verdict"] = "violation"
    child["reason_code"] = "policy_denied"
    child["budget"]["decision"] = "not_applicable"

    payloads = otlp_payloads([root, child])
    spans = payloads["traces"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    logs = payloads["logs"]["resourceLogs"][0]["scopeLogs"][0]["logRecords"]

    assert len(spans[0]["traceId"]) == 32
    assert len(spans[0]["spanId"]) == 16
    assert spans[1]["traceId"] == spans[0]["traceId"]
    assert spans[1]["parentSpanId"] == spans[0]["spanId"]
    assert spans[1]["startTimeUnixNano"].endswith("123456789")
    assert spans[1]["kind"] == 1
    assert "status" not in spans[1]
    assert logs[0]["severityNumber"] == 9
    assert logs[1]["severityNumber"] == 13
    attributes = _attributes_by_key(spans[0]["attributes"])
    assert attributes["ardur.receipt.id"]["stringValue"] == root["receipt_id"]
    assert attributes["ardur.raw_content_exported"]["boolValue"] is False
    encoded = json.dumps(payloads, sort_keys=True)
    assert "target" not in encoded
    assert "policy-reason" not in encoded


def test_otlp_bundle_is_deterministic() -> None:
    payloads = otlp_payloads([_golden_event()])
    assert otlp_bundle_bytes(payloads) == otlp_bundle_bytes(payloads)
    parsed = json.loads(otlp_bundle_bytes(payloads))
    assert set(parsed) == {"logs", "traces"}


@pytest.mark.parametrize(
    "timestamp",
    [
        "1969-12-31T23:59:59.999999999Z",
        "9999-12-31T23:59:59.999999999Z",
    ],
)
def test_otlp_timestamp_outside_uint64_range_is_rejected(timestamp: str) -> None:
    event = _golden_event()
    event["timestamp"] = timestamp

    with pytest.raises(TelemetryExportError) as exc_info:
        otlp_payloads([event])
    assert exc_info.value.code == "timestamp_out_of_range"


@pytest.mark.parametrize(
    ("endpoint", "code"),
    [
        ("http://collector.example.test:4318", "otlp_endpoint_insecure"),
        ("https://user:password@example.test", "otlp_endpoint_invalid"),
        ("file:///tmp/collector", "otlp_endpoint_invalid"),
        ("https://example.test?token=secret", "otlp_endpoint_invalid"),
    ],
)
def test_endpoint_validation_fails_closed(endpoint: str, code: str) -> None:
    with pytest.raises(TelemetryExportError) as exc_info:
        signal_endpoint(endpoint, "traces")
    assert exc_info.value.code == code


def test_loopback_endpoint_preserves_prefix_and_adds_signal_path() -> None:
    assert (
        signal_endpoint("http://127.0.0.1:4318/otel", "logs")
        == "http://127.0.0.1:4318/otel/v1/logs"
    )


class _Response:
    def __init__(self, body: bytes = b"{}", status: int = 200) -> None:
        self.body = body
        self.status = status

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.body[:limit]

    def getcode(self) -> int:
        return self.status


def test_otlp_http_sends_trace_and_log_requests_with_env_headers() -> None:
    seen: list[tuple[str, bytes, dict[str, str], int]] = []

    def open_request(req: Any, *, timeout: int) -> _Response:
        seen.append(
            (
                req.full_url,
                req.data,
                dict(req.header_items()),
                timeout,
            )
        )
        return _Response()

    result = export_otlp_http(
        otlp_payloads([_golden_event()]),
        endpoint="http://localhost:4318",
        timeout_s=7,
        environ={
            "OTEL_EXPORTER_OTLP_HEADERS": "Authorization=Bearer%20fixture",
            "OTEL_EXPORTER_OTLP_LOGS_HEADERS": "X-Signal=logs",
        },
        urlopen=open_request,
    )

    assert result == [
        {"signal": "traces", "status": 200},
        {"signal": "logs", "status": 200},
    ]
    assert [item[0] for item in seen] == [
        "http://localhost:4318/v1/traces",
        "http://localhost:4318/v1/logs",
    ]
    assert all(json.loads(item[1]) for item in seen)
    assert all(item[2]["Content-type"] == "application/json" for item in seen)
    assert all(item[2]["Authorization"] == "Bearer fixture" for item in seen)
    assert seen[1][2]["X-signal"] == "logs"
    assert all(item[3] == 7 for item in seen)


def test_otlp_partial_rejection_fails_without_retry() -> None:
    calls = 0

    def open_request(_req: Any, *, timeout: int) -> _Response:
        nonlocal calls
        calls += 1
        assert timeout == 10
        if calls == 1:
            return _Response()
        return _Response(
            b'{"partialSuccess":{"rejectedLogRecords":"1","errorMessage":"bad"}}'
        )

    with pytest.raises(TelemetryExportError) as exc_info:
        export_otlp_http(
            otlp_payloads([_golden_event()]),
            endpoint="http://[::1]:4318",
            environ={},
            urlopen=open_request,
        )
    assert exc_info.value.code == "otlp_partial_rejection"
    assert calls == 2


@pytest.mark.parametrize("rejected", [-1, True, 1.5, "invalid"])
def test_otlp_invalid_partial_rejection_count_fails(rejected: object) -> None:
    calls = 0

    def open_request(_req: Any, *, timeout: int) -> _Response:
        nonlocal calls
        calls += 1
        assert timeout == 10
        field = "rejectedSpans" if calls == 1 else "rejectedLogRecords"
        return _Response(json.dumps({"partialSuccess": {field: rejected}}).encode())

    with pytest.raises(TelemetryExportError) as exc_info:
        export_otlp_http(
            otlp_payloads([_golden_event()]),
            endpoint="http://localhost:4318",
            environ={},
            urlopen=open_request,
        )
    assert exc_info.value.code == "otlp_response_invalid"


@pytest.mark.parametrize(
    "headers",
    [
        {"OTEL_EXPORTER_OTLP_HEADERS": "invalid"},
        {"OTEL_EXPORTER_OTLP_HEADERS": "Host=evil.example"},
        {"OTEL_EXPORTER_OTLP_HEADERS": "X-Test=ok%0d%0aInjected=yes"},
    ],
)
def test_otlp_header_injection_is_rejected(headers: dict[str, str]) -> None:
    with pytest.raises(TelemetryExportError) as exc_info:
        export_otlp_http(
            otlp_payloads([_golden_event()]),
            endpoint="http://localhost:4318",
            environ=headers,
            urlopen=lambda *_args, **_kwargs: _Response(),
        )
    assert exc_info.value.code == "otlp_headers_invalid"


def test_owner_only_output_and_symlink_rejection(tmp_path: Path) -> None:
    output = tmp_path / "events.jsonl"
    write_export(output, jsonl_bytes([_golden_event()]))
    assert stat.S_IMODE(output.stat().st_mode) == 0o600

    target = tmp_path / "target"
    target.write_text("unchanged\n", encoding="utf-8")
    output.unlink()
    output.symlink_to(target)
    with pytest.raises(TelemetryExportError) as exc_info:
        write_export(output, b"changed\n")
    assert exc_info.value.code == "output_symlink"
    assert target.read_text(encoding="utf-8") == "unchanged\n"


def test_cli_exports_verified_jsonl_to_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal, public_key, _private_key = _signed_journal(tmp_path)

    exit_code = cli_main(
        [
            "telemetry",
            "export",
            str(journal),
            "--receipt-public-key",
            str(public_key),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    events = [json.loads(line) for line in captured.out.splitlines()]
    assert [item["decision"] for item in events] == ["PERMIT", "DENY"]


def test_cli_writes_otlp_inspection_bundle_owner_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal, public_key, _private_key = _signed_journal(tmp_path)
    output = tmp_path / "otlp.json"

    exit_code = cli_main(
        [
            "telemetry",
            "export",
            str(journal),
            "--receipt-public-key",
            str(public_key),
            "--format",
            "otlp-json",
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    summary = json.loads(captured.out)
    assert summary["ok"] is True
    assert summary["event_count"] == 2
    assert summary["raw_content_exported"] is False
    assert set(json.loads(output.read_bytes())) == {"logs", "traces"}
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
