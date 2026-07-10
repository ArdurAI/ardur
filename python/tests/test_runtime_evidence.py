from __future__ import annotations

import json
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jsonschema import Draft202012Validator

import vibap.runtime_evidence as runtime
from vibap._specs import (
    runtime_evidence_correlation_report_v01_schema,
    runtime_evidence_event_v01_schema,
)
from vibap.cli import main as cli_main
from vibap.offline_verification import verify_offline_path
from vibap.proxy import Decision, PolicyEvent
from vibap.receipt import build_receipt, sign_receipt


RECEIPT_SHA = "a" * 64
BASE_TIME = "2030-01-01T00:00:00Z"


def _receipt(
    receipt_id: str = "receipt:one",
    *,
    index: int = 0,
    timestamp: str = BASE_TIME,
    trace_id: str = "trace:one",
    actor: str = "spiffe://example.test/agent",
    tool: str = "curl",
    action_class: str = "execute",
    target: str = "/usr/bin/curl",
    side_effect_class: str = "process_launch",
) -> dict[str, Any]:
    return {
        "index": index,
        "timestamp": timestamp,
        "receipt_id": receipt_id,
        "trace_id": trace_id,
        "actor": actor,
        "tool": tool,
        "action_class": action_class,
        "target": target,
        "side_effect_class": side_effect_class,
    }


def _verified_report(*receipts: dict[str, Any]) -> dict[str, Any]:
    return {
        "valid": True,
        "result": "verified_chain_only",
        "source": {"kind": "journal", "sha256": RECEIPT_SHA},
        "timeline": list(receipts or (_receipt(),)),
    }


def _normalized_event(
    *,
    event_type: str = "process_start",
    observed_at: str = "2030-01-01T00:00:01Z",
    process: dict[str, Any] | None = None,
    correlation: dict[str, str] | None = None,
    details: dict[str, str] | None = None,
    coverage: str = "complete",
) -> dict[str, Any]:
    return {
        "schema_version": runtime.EVENT_SCHEMA_VERSION,
        "event_id": "private-event-id",
        "source": {
            "kind": "normalized",
            "format": "fixture-json.v1",
            "instance_id": "private-host-name",
            "assurance": runtime.SOURCE_ASSURANCE,
            "coverage": coverage,
        },
        "event_type": event_type,
        "observed_at": observed_at,
        "process": dict(process or {}),
        "correlation": dict(correlation or {}),
        "details": dict(details or {}),
    }


def _write_jsonl(path: Path, *values: dict[str, Any]) -> None:
    path.write_text(
        "".join(json.dumps(value, separators=(",", ":")) + "\n" for value in values),
        encoding="utf-8",
    )


def _correlate(
    path: Path,
    receipt_report: dict[str, Any] | None = None,
    *,
    source_format: str = "normalized",
) -> dict[str, Any]:
    batch = runtime.load_runtime_events(path, source_format=source_format)
    return runtime.correlate_verified_report(
        receipt_report or _verified_report(), batch
    )


def _signed_journal(tmp_path: Path) -> tuple[Path, Path, str]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    observed_epoch = int(datetime(2030, 1, 1, tzinfo=timezone.utc).timestamp())
    event = PolicyEvent(
        timestamp=BASE_TIME,
        step_id="step:runtime-evidence:1",
        actor="spiffe://example.test/agent",
        verifier_id="spiffe://example.test/verifier",
        tool_name="curl",
        arguments={"url": "https://private.example.test", "token": "fixture-private"},
        action_class="execute",
        target="/usr/bin/curl",
        resource_family="process",
        side_effect_class="process_launch",
        decision=Decision.PERMIT,
        reason="allowed by fixture policy",
        passport_jti="grant:runtime-evidence",
        trace_id="trace:one",
        run_nonce="runtime_evidence_fixture_nonce_0123456789",
    )
    receipt = build_receipt(
        Decision.PERMIT,
        event,
        policy_decisions=[
            {"backend": "native", "decision": "Allow", "reason": event.reason}
        ],
        budget_remaining={"tool_calls": 9},
    )
    receipt.iat = observed_epoch
    receipt.exp = observed_epoch + 300
    token = sign_receipt(receipt, private_key)
    journal = tmp_path / "receipts.jsonl"
    journal.write_text(json.dumps({"jwt": token}) + "\n", encoding="utf-8")
    public_key = tmp_path / "receipt-public.pem"
    public_key.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return journal, public_key, receipt.receipt_id


def test_schemas_are_valid_and_embedded_copies_match_canonical() -> None:
    root = Path(__file__).resolve().parents[2]
    pairs = (
        (
            root / "docs/specs/runtime-evidence-event-v0.1.schema.json",
            root / "python/vibap/_specs/runtime_evidence_event_v01.schema.json",
            runtime_evidence_event_v01_schema(),
        ),
        (
            root / "docs/specs/runtime-evidence-correlation-report-v0.1.schema.json",
            root
            / "python/vibap/_specs/runtime_evidence_correlation_report_v01.schema.json",
            runtime_evidence_correlation_report_v01_schema(),
        ),
    )
    for canonical, embedded, loaded in pairs:
        assert canonical.read_bytes() == embedded.read_bytes()
        assert json.loads(canonical.read_text(encoding="utf-8")) == loaded
        Draft202012Validator.check_schema(loaded)


def test_normalized_exact_receipt_hint_is_high_confidence_and_redacted(
    tmp_path: Path,
) -> None:
    raw_command = "/private/home/reviewer/bin/curl --header token=fixture-value"
    raw_workspace = "/private/home/reviewer/project"
    path = tmp_path / "events.jsonl"
    _write_jsonl(
        path,
        _normalized_event(
            process={
                "pid": 101,
                "ppid": 1,
                "start_time": BASE_TIME,
                "exec_id": "private-exec-id",
                "container_id": "private-container-id",
            },
            correlation={
                "receipt_id": "receipt:one",
                "trace_id": "trace:one",
                "session_id": "private-session",
                "actor": "spiffe://example.test/agent",
            },
            details={"command": raw_command, "workspace": raw_workspace},
        ),
    )

    report = _correlate(path)

    association = report["associations"][0]
    assert association["match_status"] == "matched"
    assert association["confidence"] == "high"
    assert association["proof_status"] == "corroborating_unverified"
    assert association["receipt_id"] == "receipt:one"
    assert report["receipt_summaries"][0]["evidence_status"] == "corroborated"
    rendered = json.dumps(report, sort_keys=True)
    text = runtime.render_text_report(report)
    for private_value in (
        raw_command,
        raw_workspace,
        "private-event-id",
        "private-exec-id",
        "private-container-id",
        "private-host-name",
        "private-session",
    ):
        assert private_value not in rendered
        assert private_value not in text
    assert report["sensitive_output_redacted"] is True
    assert set(association["event"]["redacted_fields"]) >= {
        "actor",
        "command",
        "container_id",
        "event_id",
        "exec_id",
        "session_id",
        "trace_id",
        "workspace",
    }


def test_stable_process_identity_propagates_seeded_receipt(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    _write_jsonl(
        path,
        _normalized_event(
            process={"pid": 101, "start_time": BASE_TIME, "exec_id": "exec:root"},
            correlation={"receipt_id": "receipt:one"},
            details={"command": "/usr/bin/curl"},
        ),
        _normalized_event(
            event_type="file_write",
            observed_at="2030-01-01T00:00:02Z",
            process={"pid": 101, "start_time": BASE_TIME, "exec_id": "exec:root"},
            details={"path": "/private/output.txt"},
        ),
    )

    report = _correlate(path)

    inherited = report["associations"][1]
    assert inherited["match_status"] == "matched"
    assert inherited["confidence"] == "medium"
    assert inherited["reason_codes"] == ["same_process_identity", "time_window"]
    assert "/private/output.txt" not in json.dumps(report)


def test_parent_exec_identity_propagates_to_child_effect(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    _write_jsonl(
        path,
        _normalized_event(
            process={"pid": 101, "start_time": BASE_TIME, "exec_id": "exec:root"},
            correlation={"receipt_id": "receipt:one"},
            details={"command": "/usr/bin/curl"},
        ),
        _normalized_event(
            event_type="network_connect",
            observed_at="2030-01-01T00:00:02Z",
            process={
                "pid": 202,
                "ppid": 101,
                "start_time": "2030-01-01T00:00:01Z",
                "exec_id": "exec:child",
                "parent_exec_id": "exec:root",
            },
            details={"destination": "private.example.test:443"},
        ),
    )

    report = _correlate(path)

    inherited = report["associations"][1]
    assert inherited["match_status"] == "matched"
    assert inherited["reason_codes"] == ["parent_process_identity", "time_window"]
    assert "private.example.test" not in json.dumps(report)


def test_pid_only_inheritance_remains_weak_non_proof(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    _write_jsonl(
        path,
        _normalized_event(
            process={"pid": 101},
            correlation={"receipt_id": "receipt:one"},
            details={"command": "/usr/bin/curl"},
        ),
        _normalized_event(
            event_type="file_write",
            observed_at="2030-01-01T00:00:02Z",
            process={"pid": 101},
            details={"path": "/private/reused-pid.txt"},
        ),
    )

    report = _correlate(path)

    weak = report["associations"][1]
    assert weak["match_status"] == "weak"
    assert weak["confidence"] == "low"
    assert weak["proof_status"] == "non_proof"
    assert weak["reason_codes"] == ["pid_only_unstable"]


def test_equal_candidates_are_ambiguous_non_proof(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    _write_jsonl(
        path,
        _normalized_event(details={"command": "/usr/bin/curl"}),
    )
    receipts = _verified_report(
        _receipt("receipt:one", index=0),
        _receipt("receipt:two", index=1),
    )

    report = _correlate(path, receipts)

    association = report["associations"][0]
    assert association["match_status"] == "ambiguous"
    assert association["confidence"] == "ambiguous"
    assert association["receipt_id"] is None
    assert association["proof_status"] == "non_proof"
    assert "candidate_score_tie" in association["reason_codes"]
    assert {item["evidence_status"] for item in report["receipt_summaries"]} == {
        "ambiguous"
    }


def test_unknown_receipt_hint_does_not_fall_back_to_weak_match(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    _write_jsonl(
        path,
        _normalized_event(
            correlation={"receipt_id": "receipt:not-present"},
            details={"command": "/usr/bin/curl"},
        ),
    )

    report = _correlate(path)

    assert report["associations"][0]["match_status"] == "unmatched"
    assert report["associations"][0]["reason_codes"] == ["receipt_id_hint_unknown"]


def test_unknown_receipt_hint_is_not_overridden_by_process_ownership(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    _write_jsonl(
        path,
        _normalized_event(
            process={"exec_id": "exec:root"},
            correlation={"receipt_id": "receipt:one"},
        ),
        _normalized_event(
            event_type="file_write",
            observed_at="2030-01-01T00:00:02Z",
            process={"exec_id": "exec:root"},
            correlation={"receipt_id": "receipt:not-present"},
        ),
    )

    report = _correlate(path)

    association = report["associations"][1]
    assert association["match_status"] == "unmatched"
    assert association["reason_codes"] == ["receipt_id_hint_unknown"]


def test_process_owner_conflict_is_counted_for_every_candidate(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    _write_jsonl(
        path,
        _normalized_event(
            process={"exec_id": "exec:shared"},
            correlation={"receipt_id": "receipt:one"},
        ),
        _normalized_event(
            observed_at="2030-01-01T00:00:02Z",
            process={"exec_id": "exec:shared"},
            correlation={"receipt_id": "receipt:two"},
        ),
        _normalized_event(
            event_type="file_write",
            observed_at="2030-01-01T00:00:03Z",
            process={"exec_id": "exec:shared"},
        ),
    )
    receipts = _verified_report(
        _receipt("receipt:one", index=0),
        _receipt("receipt:two", index=1),
    )

    report = _correlate(path, receipts)

    association = report["associations"][2]
    assert association["match_status"] == "ambiguous"
    assert "process_identity_conflict" in association["reason_codes"]
    assert {
        item["receipt_id"]: item["ambiguous_event_count"]
        for item in report["receipt_summaries"]
    } == {"receipt:one": 1, "receipt:two": 1}


def test_receipt_hint_and_process_owner_conflict_remains_ambiguous(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    _write_jsonl(
        path,
        _normalized_event(
            process={"exec_id": "exec:root"},
            correlation={"receipt_id": "receipt:one"},
        ),
        _normalized_event(
            event_type="file_write",
            observed_at="2030-01-01T00:00:02Z",
            process={"exec_id": "exec:root"},
            correlation={"receipt_id": "receipt:two"},
        ),
    )
    receipts = _verified_report(
        _receipt("receipt:one", index=0),
        _receipt(
            "receipt:two",
            index=1,
            timestamp="2030-01-01T01:00:00Z",
            action_class="write",
            side_effect_class="filesystem_write",
        ),
    )

    report = _correlate(path, receipts)

    association = report["associations"][1]
    assert association["match_status"] == "ambiguous"
    assert association["proof_status"] == "non_proof"
    assert "receipt_process_conflict" in association["reason_codes"]
    assert "process_identity_conflict" not in association["reason_codes"]


def test_out_of_window_receipt_hint_is_weak_non_proof(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    _write_jsonl(
        path,
        _normalized_event(
            observed_at="2030-01-01T01:00:00Z",
            correlation={"receipt_id": "receipt:one", "trace_id": "trace:one"},
            details={"command": "/usr/bin/curl"},
        ),
    )

    report = _correlate(path)

    association = report["associations"][0]
    assert association["match_status"] == "weak"
    assert association["confidence"] == "low"
    assert association["proof_status"] == "non_proof"
    assert "time_outside_window" in association["reason_codes"]


def test_type_incompatible_receipt_hint_is_weak_non_proof(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    _write_jsonl(
        path,
        _normalized_event(correlation={"receipt_id": "receipt:one"}),
    )
    receipts = _verified_report(
        _receipt(
            action_class="write",
            target="/private/output.txt",
            side_effect_class="filesystem_write",
        )
    )

    report = _correlate(path, receipts)

    association = report["associations"][0]
    assert association["match_status"] == "weak"
    assert association["confidence"] == "low"
    assert association["proof_status"] == "non_proof"
    assert "side_effect_incompatible" in association["reason_codes"]


def test_tetragon_process_exec_adapter_maps_current_json_shape(tmp_path: Path) -> None:
    path = tmp_path / "tetragon.jsonl"
    _write_jsonl(
        path,
        {
            "time": "2030-01-01T00:00:01.123456789Z",
            "node_name": "private-node",
            "ardur": {"receipt_id": "receipt:one", "trace_id": "trace:one"},
            "process_exec": {
                "process": {
                    "exec_id": "private-tetragon-exec",
                    "parent_exec_id": "private-parent-exec",
                    "pid": 101,
                    "start_time": BASE_TIME,
                    "binary": "/usr/bin/curl",
                    "arguments": "https://private.example.test",
                    "cwd": "/private/workspace",
                    "pod": {"container": {"id": "private-container"}},
                }
            },
        },
    )

    report = _correlate(path, source_format="tetragon")

    assert report["event_source"]["format"] == "tetragon"
    assert report["event_source"]["coverage"] == "unknown"
    assert report["associations"][0]["match_status"] == "matched"
    rendered = json.dumps(report)
    for value in (
        "private-node",
        "private-tetragon-exec",
        "private-parent-exec",
        "private.example.test",
        "/private/workspace",
        "private-container",
    ):
        assert value not in rendered


@pytest.mark.parametrize(
    ("function_name", "expected_type", "detail_name"),
    [
        ("vfs_write", "file_write", "ardur_path"),
        ("tcp_connect", "network_connect", "ardur_destination"),
    ],
)
def test_tetragon_allowlisted_side_effect_adapters(
    tmp_path: Path,
    function_name: str,
    expected_type: str,
    detail_name: str,
) -> None:
    path = tmp_path / "tetragon.jsonl"
    _write_jsonl(
        path,
        {
            "time": "2030-01-01T00:00:01Z",
            "process_kprobe": {
                "function_name": function_name,
                "process": {"pid": 101, "exec_id": "private-exec"},
                detail_name: "/private/side-effect",
            },
        },
    )

    batch = runtime.load_runtime_events(path, source_format="tetragon")

    assert batch.events[0].record["event_type"] == expected_type
    assert batch.events[0].record["source"]["coverage"] == "unknown"


def test_tetragon_unsupported_tracing_function_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "tetragon.jsonl"
    _write_jsonl(
        path,
        {
            "time": BASE_TIME,
            "process_kprobe": {
                "function_name": "unclassified_function",
                "process": {"pid": 101},
            },
        },
    )

    with pytest.raises(runtime.RuntimeEvidenceError) as exc_info:
        runtime.load_runtime_events(path, source_format="tetragon")

    assert exc_info.value.code == "tetragon_event_unsupported"
    assert exc_info.value.line == 1


def test_falco_alert_adapter_is_always_alert_only_and_redacted(tmp_path: Path) -> None:
    path = tmp_path / "falco.jsonl"
    event_time = "2030-01-01T00:00:01Z"
    _write_jsonl(
        path,
        {
            "time": event_time,
            "hostname": "private-falco-host",
            "source": "syscall",
            "rule": "fixture connect",
            "priority": "Notice",
            "output": "private formatted output",
            "output_fields": {
                "evt.type": "connect",
                "evt.num": "17",
                "proc.pid": 101,
                "proc.ppid": 1,
                "proc.pid.ts": 1893456000000000000,
                "proc.cmdline": "curl --header token=private-value",
                "fd.name": "private.example.test:443",
                "ardur.receipt_id": "receipt:network",
                "ardur.trace_id": "trace:network",
            },
        },
    )
    receipts = _verified_report(
        _receipt(
            "receipt:network",
            trace_id="trace:network",
            action_class="fetch",
            target="private.example.test:443",
            side_effect_class="network_read",
        )
    )

    report = _correlate(path, receipts, source_format="falco")

    assert report["event_source"]["coverage"] == "alert_only"
    assert report["associations"][0]["match_status"] == "matched"
    rendered = json.dumps(report)
    for value in (
        "private-falco-host",
        "private formatted output",
        "private-value",
        "private.example.test",
    ):
        assert value not in rendered
    assert any("alert-scoped" in item for item in report["limitations"])


@pytest.mark.parametrize(
    ("syscall_name", "expected_type"),
    [("write", "file_write"), ("unlinkat", "file_delete")],
)
def test_falco_allowlisted_file_alert_adapters(
    tmp_path: Path, syscall_name: str, expected_type: str
) -> None:
    path = tmp_path / "falco.jsonl"
    _write_jsonl(
        path,
        {
            "time": "2030-01-01T00:00:01Z",
            "source": "syscall",
            "output_fields": {
                "evt.type": syscall_name,
                "proc.pid": 101,
                "fd.name": "/private/side-effect",
            },
        },
    )

    batch = runtime.load_runtime_events(path, source_format="falco")

    assert batch.events[0].record["event_type"] == expected_type
    assert batch.events[0].record["source"]["coverage"] == "alert_only"


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ('{"a":1,"a":2}\n', "duplicate_json_key"),
        ('{"value":NaN}\n', "nonfinite_json_number"),
        ('{"value":1e999}\n', "nonfinite_json_number"),
        ('{"value":' + "9" * 5000 + "}\n", "json_number_invalid"),
        ('{"value":}\n', "malformed_json"),
        ("[]\n", "event_not_object"),
    ],
)
def test_invalid_jsonl_fails_with_bounded_codes(
    tmp_path: Path, raw: str, code: str
) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(raw, encoding="utf-8")

    with pytest.raises(runtime.RuntimeEvidenceError) as exc_info:
        runtime.load_runtime_events(path, source_format="normalized")

    assert exc_info.value.code == code
    assert exc_info.value.line == 1
    assert str(tmp_path) not in str(exc_info.value)


def test_deep_json_fails_before_schema_recursion(tmp_path: Path) -> None:
    value: dict[str, Any] = {"leaf": True}
    for index in range(runtime.MAX_JSON_DEPTH + 2):
        value = {f"level_{index}": value}
    path = tmp_path / "events.jsonl"
    _write_jsonl(path, value)

    with pytest.raises(runtime.RuntimeEvidenceError) as exc_info:
        runtime.load_runtime_events(path, source_format="normalized")

    assert exc_info.value.code == "json_depth_exceeded"


def test_final_component_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "real.jsonl"
    link = tmp_path / "link.jsonl"
    _write_jsonl(target, _normalized_event())
    link.symlink_to(target)

    with pytest.raises(runtime.RuntimeEvidenceError) as exc_info:
        runtime.load_runtime_events(link, source_format="normalized")

    assert exc_info.value.code == "input_symlink"
    assert str(tmp_path) not in str(exc_info.value)


def test_line_and_file_limits_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    line_path = tmp_path / "line.jsonl"
    _write_jsonl(line_path, _normalized_event())
    monkeypatch.setattr(runtime, "MAX_LINE_BYTES", 10)
    with pytest.raises(runtime.RuntimeEvidenceError) as line_error:
        runtime.load_runtime_events(line_path, source_format="normalized")
    assert line_error.value.code == "line_too_large"

    monkeypatch.setattr(runtime, "MAX_LINE_BYTES", 2 * 1024 * 1024)
    monkeypatch.setattr(runtime, "MAX_INPUT_BYTES", 10)
    with pytest.raises(runtime.RuntimeEvidenceError) as file_error:
        runtime.load_runtime_events(line_path, source_format="normalized")
    assert file_error.value.code == "input_too_large"


def test_report_bytes_are_deterministic_and_schema_valid(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    _write_jsonl(
        path,
        _normalized_event(
            correlation={"receipt_id": "receipt:one"},
            details={"command": "/usr/bin/curl"},
        ),
    )

    first = _correlate(path)
    second = _correlate(path)

    assert first == second
    assert runtime.canonical_report_bytes(first) == runtime.canonical_report_bytes(
        second
    )
    runtime_evidence_correlation_report_v01_schema()
    Draft202012Validator(runtime_evidence_correlation_report_v01_schema()).validate(
        first
    )


def test_atomic_report_write_is_owner_only_and_rejects_symlink(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    runtime.write_report(output, b"{}\n")
    assert output.read_bytes() == b"{}\n"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600

    target = tmp_path / "target.json"
    target.write_text("unchanged\n", encoding="utf-8")
    output.unlink()
    output.symlink_to(target)
    with pytest.raises(runtime.RuntimeEvidenceError) as exc_info:
        runtime.write_report(output, b"changed\n")
    assert exc_info.value.code == "output_symlink"
    assert target.read_text(encoding="utf-8") == "unchanged\n"


def test_atomic_report_write_rejects_hostile_output_shapes(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(runtime.RuntimeEvidenceError) as parent_error:
        runtime.write_report(linked_parent / "report.json", b"{}\n")
    assert parent_error.value.code == "output_parent_invalid"
    assert str(tmp_path) not in str(parent_error.value)

    directory_target = real_parent / "report.json"
    directory_target.mkdir()
    with pytest.raises(runtime.RuntimeEvidenceError) as target_error:
        runtime.write_report(directory_target, b"{}\n")
    assert target_error.value.code == "output_not_regular"
    assert str(tmp_path) not in str(target_error.value)

    with pytest.raises(runtime.RuntimeEvidenceError) as name_error:
        runtime.write_report(Path("."), b"{}\n")
    assert name_error.value.code == "output_name_invalid"


@pytest.mark.parametrize("window", [-1, 3601, True, 1.5])
def test_invalid_correlation_window_is_rejected(tmp_path: Path, window: Any) -> None:
    path = tmp_path / "events.jsonl"
    _write_jsonl(path, _normalized_event())
    batch = runtime.load_runtime_events(path, source_format="normalized")
    with pytest.raises(runtime.RuntimeEvidenceError) as exc_info:
        runtime.correlate_verified_report(
            _verified_report(), batch, correlation_window_s=window
        )
    assert exc_info.value.code == "correlation_window_invalid"


def test_unverified_receipt_report_is_rejected_before_correlation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    _write_jsonl(path, _normalized_event())
    batch = runtime.load_runtime_events(path, source_format="normalized")
    with pytest.raises(runtime.RuntimeEvidenceError) as exc_info:
        runtime.correlate_verified_report({"valid": False, "result": "invalid"}, batch)
    assert exc_info.value.code == "receipt_report_unverified"


def test_cli_verifies_signed_journal_and_emits_canonical_redacted_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal, public_key, receipt_id = _signed_journal(tmp_path)
    events = tmp_path / "events.jsonl"
    private_command = "/private/home/reviewer/curl --header token=fixture-private"
    _write_jsonl(
        events,
        _normalized_event(
            correlation={"receipt_id": receipt_id, "trace_id": "trace:one"},
            details={"command": private_command},
        ),
    )
    journal_before = journal.read_bytes()

    exit_code = cli_main(
        [
            "evidence",
            "correlate",
            str(journal),
            str(events),
            "--source-format",
            "normalized",
            "--receipt-public-key",
            str(public_key),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["receipt_verification"]["verified"] is True
    assert report["receipt_verification"]["result"] == "verified_chain_only"
    assert report["associations"][0]["receipt_id"] == receipt_id
    assert report["associations"][0]["match_status"] == "matched"
    assert private_command not in captured.out
    assert str(tmp_path) not in captured.out
    assert "fixture-private" not in captured.out
    assert journal.read_bytes() == journal_before


def test_offline_explorer_hides_correlation_fields_unless_explicitly_requested(
    tmp_path: Path,
) -> None:
    journal, public_key_path, _receipt_id = _signed_journal(tmp_path)
    public_key = serialization.load_pem_public_key(public_key_path.read_bytes())

    default_report = verify_offline_path(
        journal,
        receipt_public_key=public_key,
        chain_only=True,
        redact=False,
    )
    correlation_report = verify_offline_path(
        journal,
        receipt_public_key=public_key,
        chain_only=True,
        redact=False,
        include_correlation_fields=True,
    )

    assert "trace_id" not in default_report["timeline"][0]
    assert "arguments_hash" not in default_report["timeline"][0]
    assert correlation_report["timeline"][0]["trace_id"] == "trace:one"
    assert len(correlation_report["timeline"][0]["arguments_hash"]) == 64


def test_cli_text_and_file_outputs_are_redacted_and_owner_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal, public_key, receipt_id = _signed_journal(tmp_path)
    events = tmp_path / "events.jsonl"
    _write_jsonl(
        events,
        _normalized_event(
            correlation={"receipt_id": receipt_id},
            details={"command": "/private/curl token=fixture-private"},
        ),
    )

    assert (
        cli_main(
            [
                "evidence",
                "correlate",
                str(journal),
                str(events),
                "--source-format",
                "normalized",
                "--receipt-public-key",
                str(public_key),
                "--format",
                "text",
            ]
        )
        == 0
    )
    text_output = capsys.readouterr().out
    assert "Ardur runtime evidence correlation" in text_output
    assert "fixture-private" not in text_output
    assert str(tmp_path) not in text_output

    output = tmp_path / "report.json"
    assert (
        cli_main(
            [
                "evidence",
                "correlate",
                str(journal),
                str(events),
                "--source-format",
                "normalized",
                "--receipt-public-key",
                str(public_key),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    summary = capsys.readouterr().out
    assert json.loads(summary)["condition"] == "runtime_evidence_report_written"
    assert str(output) not in summary
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    stored = json.loads(output.read_text(encoding="utf-8"))
    assert stored["associations"][0]["receipt_id"] == receipt_id
    assert "fixture-private" not in output.read_text(encoding="utf-8")


def test_cli_verifies_receipts_before_parsing_events(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal, public_key, _receipt_id = _signed_journal(tmp_path)
    journal.write_text(json.dumps({"jwt": "header.payload.invalid"}) + "\n")
    events = tmp_path / "events.jsonl"
    events.write_text("{malformed\n", encoding="utf-8")

    exit_code = cli_main(
        [
            "evidence",
            "correlate",
            str(journal),
            str(events),
            "--source-format",
            "normalized",
            "--receipt-public-key",
            str(public_key),
        ]
    )

    captured = capsys.readouterr()
    response = json.loads(captured.out)
    assert exit_code == 1
    assert captured.err == ""
    assert response["error"] == "receipt_chain_invalid"
    assert response.get("event_line") is None
    assert str(tmp_path) not in captured.out
    assert "header.payload.invalid" not in captured.out


def test_cli_sensor_failure_returns_safe_line_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal, public_key, _receipt_id = _signed_journal(tmp_path)
    events = tmp_path / "events.jsonl"
    events.write_text('{"secret":"private","secret":"again"}\n', encoding="utf-8")

    exit_code = cli_main(
        [
            "evidence",
            "correlate",
            str(journal),
            str(events),
            "--source-format",
            "normalized",
            "--receipt-public-key",
            str(public_key),
        ]
    )

    captured = capsys.readouterr()
    response = json.loads(captured.out)
    assert exit_code == 1
    assert response["error"] == "duplicate_json_key"
    assert response["event_line"] == 1
    assert "private" not in captured.out
    assert "again" not in captured.out
    assert str(tmp_path) not in captured.out


def test_cli_missing_public_key_failure_does_not_echo_paths(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal, _public_key, _receipt_id = _signed_journal(tmp_path)
    events = tmp_path / "events.jsonl"
    _write_jsonl(events, _normalized_event())
    missing_key = tmp_path / "private-directory" / "missing-public-key.pem"

    exit_code = cli_main(
        [
            "evidence",
            "correlate",
            str(journal),
            str(events),
            "--source-format",
            "normalized",
            "--receipt-public-key",
            str(missing_key),
        ]
    )

    captured = capsys.readouterr()
    response = json.loads(captured.out)
    assert exit_code == 1
    assert captured.err == ""
    assert response["error"] == "runtime_evidence_io_failed"
    assert str(tmp_path) not in captured.out
    assert "missing-public-key.pem" not in captured.out


def test_public_fixture_generator_persists_public_material_only(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[2]
    output = tmp_path / "runtime-evidence-fixtures"

    generated = subprocess.run(
        [
            sys.executable,
            str(root / "scripts/generate-runtime-evidence-fixtures.py"),
            "--output-dir",
            str(output),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert generated.returncode == 0, generated.stdout + generated.stderr
    expected = {
        "receipt-public.pem",
        "receipts.jsonl",
        "normalized.jsonl",
        "tetragon.jsonl",
        "falco.jsonl",
        "report-normalized.json",
        "report-tetragon.json",
        "report-falco.json",
    }
    assert {path.name for path in output.iterdir()} == expected
    for path in output.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert b"PRIVATE KEY" not in path.read_bytes()
    for source_format in ("normalized", "tetragon", "falco"):
        report = json.loads(
            (output / f"report-{source_format}.json").read_text(encoding="utf-8")
        )
        assert report["receipt_verification"]["verified"] is True
        assert report["event_source"]["format"] == source_format
        assert report["summary"]["matched_event_count"] == 1
        assert report["summary"]["corroborated_receipt_count"] == 1
        assert report["summary"]["unobserved_receipt_count"] == 2
