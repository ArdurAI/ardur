#!/usr/bin/env python3
"""Generate public runtime-evidence fixtures with an ephemeral receipt key."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from vibap.offline_verification import verify_offline_path
from vibap.proxy import Decision, PolicyEvent
from vibap.receipt import build_receipt, sign_receipt
from vibap.runtime_evidence import (
    EVENT_SCHEMA_VERSION,
    SOURCE_ASSURANCE,
    canonical_report_bytes,
    correlate_verified_report,
    load_runtime_events,
    write_report,
)


UTC = timezone.utc
BASE_TIME = datetime(2030, 1, 1, 0, 0, tzinfo=UTC)
ACTOR = "spiffe://fixture.ardur.dev/agent/runtime-evidence"
TRACE_ID = "trace:runtime-evidence-public-fixture"
RUN_NONCE = "runtime_evidence_public_fixture_nonce_0123456789"


def _jsonl(values: Sequence[Mapping[str, Any]]) -> bytes:
    return "".join(
        json.dumps(
            dict(value),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
        for value in values
    ).encode("utf-8")


def _receipt_event(
    index: int,
    *,
    tool: str,
    action_class: str,
    target: str,
    side_effect_class: str,
) -> PolicyEvent:
    observed = BASE_TIME + timedelta(seconds=index * 10)
    return PolicyEvent(
        timestamp=observed.isoformat().replace("+00:00", "Z"),
        step_id=f"step:runtime-evidence:{index}",
        actor=ACTOR,
        verifier_id="spiffe://fixture.ardur.dev/verifier",
        tool_name=tool,
        arguments={"fixture_index": index, "target": target},
        action_class=action_class,
        target=target,
        resource_family="runtime",
        side_effect_class=side_effect_class,
        decision=Decision.PERMIT,
        reason="allowed by public runtime-evidence fixture policy",
        passport_jti="grant:runtime-evidence-public-fixture",
        trace_id=TRACE_ID,
        run_nonce=RUN_NONCE,
    )


def _receipt_chain(
    private_key: ec.EllipticCurvePrivateKey,
) -> tuple[list[str], list[str]]:
    specifications = (
        {
            "tool": "curl",
            "action_class": "execute",
            "target": "/usr/bin/curl",
            "side_effect_class": "process_launch",
        },
        {
            "tool": "write_file",
            "action_class": "write",
            "target": "/workspace/output.txt",
            "side_effect_class": "filesystem_write",
        },
        {
            "tool": "http_fetch",
            "action_class": "fetch",
            "target": "api.fixture.invalid:443",
            "side_effect_class": "network_read",
        },
    )
    tokens: list[str] = []
    receipt_ids: list[str] = []
    previous: str | None = None
    for index, specification in enumerate(specifications):
        event = _receipt_event(index, **specification)
        parent_hash = (
            hashlib.sha256(previous.encode("ascii")).hexdigest()
            if previous is not None
            else None
        )
        receipt = build_receipt(
            Decision.PERMIT,
            event,
            parent_receipt_hash=parent_hash,
            policy_decisions=[
                {
                    "backend": "native",
                    "decision": "Allow",
                    "reason": event.reason,
                }
            ],
            budget_remaining={"tool_calls": 10 - index},
        )
        receipt.iat = int((BASE_TIME + timedelta(seconds=index * 10)).timestamp())
        receipt.exp = receipt.iat + 300
        previous = sign_receipt(receipt, private_key)
        tokens.append(previous)
        receipt_ids.append(receipt.receipt_id)
    return tokens, receipt_ids


def _normalized_event(receipt_id: str) -> dict[str, Any]:
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": "fixture-normalized-file-write",
        "source": {
            "kind": "normalized",
            "format": "fixture-json.v1",
            "instance_id": "fixture-host",
            "assurance": SOURCE_ASSURANCE,
            "coverage": "complete",
        },
        "event_type": "file_write",
        "observed_at": "2030-01-01T00:00:11Z",
        "process": {
            "pid": 4202,
            "ppid": 4201,
            "start_time": "2030-01-01T00:00:10Z",
        },
        "correlation": {"receipt_id": receipt_id, "trace_id": TRACE_ID, "actor": ACTOR},
        "details": {"path": "/workspace/output.txt", "operation": "write"},
    }


def _tetragon_event(receipt_id: str) -> dict[str, Any]:
    return {
        "time": "2030-01-01T00:00:01.123456789Z",
        "node_name": "fixture-node",
        "ardur": {"receipt_id": receipt_id, "trace_id": TRACE_ID, "actor": ACTOR},
        "process_exec": {
            "process": {
                "exec_id": "fixture-node:4201:1",
                "parent_exec_id": "fixture-node:1:1",
                "pid": 4201,
                "ppid": 1,
                "start_time": "2030-01-01T00:00:01Z",
                "binary": "/usr/bin/curl",
                "arguments": "https://api.fixture.invalid",
                "cwd": "/workspace",
                "pod": {"container": {"id": "fixture-container"}},
            }
        },
    }


def _falco_event(receipt_id: str) -> dict[str, Any]:
    return {
        "time": "2030-01-01T00:00:21Z",
        "hostname": "fixture-falco-host",
        "source": "syscall",
        "rule": "Ardur fixture outbound connection",
        "priority": "Notice",
        "output": "fixture outbound connection",
        "output_fields": {
            "evt.type": "connect",
            "evt.num": "33",
            "proc.pid": 4203,
            "proc.ppid": 4202,
            "proc.pid.ts": 1893456020000000000,
            "proc.cmdline": "curl https://api.fixture.invalid",
            "fd.name": "api.fixture.invalid:443",
            "ardur.receipt_id": receipt_id,
            "ardur.trace_id": TRACE_ID,
            "ardur.actor": ACTOR,
        },
    }


def generate(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    private_key = ec.generate_private_key(ec.SECP256R1())
    tokens, receipt_ids = _receipt_chain(private_key)
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    write_report(output_dir / "receipt-public.pem", public_key)
    write_report(
        output_dir / "receipts.jsonl", _jsonl([{"jwt": token} for token in tokens])
    )
    event_sets = {
        "normalized": [_normalized_event(receipt_ids[1])],
        "tetragon": [_tetragon_event(receipt_ids[0])],
        "falco": [_falco_event(receipt_ids[2])],
    }
    for source_format, events in event_sets.items():
        write_report(output_dir / f"{source_format}.jsonl", _jsonl(events))

    receipt_report = verify_offline_path(
        output_dir / "receipts.jsonl",
        receipt_public_key=private_key.public_key(),
        chain_only=True,
        redact=False,
        include_correlation_fields=True,
    )
    for source_format in event_sets:
        batch = load_runtime_events(
            output_dir / f"{source_format}.jsonl", source_format=source_format
        )
        report = correlate_verified_report(receipt_report, batch)
        write_report(
            output_dir / f"report-{source_format}.json",
            canonical_report_bytes(report),
        )

    for path in output_dir.iterdir():
        if path.is_file() and b"PRIVATE KEY" in path.read_bytes():
            raise ValueError("fixture output contains private key material")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate Ardur runtime-evidence public fixtures"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("docs/specs/conformance/runtime-evidence-v0.1"),
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        generate(args.output_dir)
    except (OSError, TypeError, ValueError) as exc:
        print(f"runtime-evidence fixture generation failed: {exc}", file=sys.stderr)
        return 1
    print(f"generated runtime-evidence fixtures in {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
