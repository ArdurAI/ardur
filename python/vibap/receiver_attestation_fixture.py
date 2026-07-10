"""No-key end-to-end MCP receiver-attestation fixture."""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .canonical_json import canonical_json_bytes
from .proxy import Decision, PolicyEvent
from .receipt import build_receipt, sign_receipt
from .receiver_attestation import (
    MCP_ATTESTATION_META_KEY,
    MCP_RECEIPT_META_KEY,
    ReceiverAttestationShim,
    verify_receiver_envelope,
)


RECEIVER_ID = "spiffe://fixture.ardur.dev/tool/read-file"
RECEIVER_KEY_ID = "fixture-read-file:v1"


def _atomic_write(path: Path, data: bytes) -> None:
    if path.is_symlink():
        raise ValueError(f"fixture artifact must not be a symlink: {path.name}")
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    fd: int | None = None
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        path.chmod(0o600)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _write_json(path: Path, value: Any) -> None:
    _atomic_write(path, canonical_json_bytes(value) + b"\n")


def _fixture_event(timestamp: int) -> PolicyEvent:
    observed = datetime.fromtimestamp(timestamp, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    arguments = {"path": "workspace/public-fixture.txt", "limit": 1}
    return PolicyEvent(
        timestamp=observed,
        step_id="step:mcp-receiver-attestation-fixture",
        actor="spiffe://fixture.ardur.dev/agent/reviewer",
        verifier_id="spiffe://fixture.ardur.dev/ardur/verifier",
        tool_name="read_file",
        arguments=arguments,
        action_class="read",
        target="workspace/public-fixture.txt",
        resource_family="filesystem",
        side_effect_class="none",
        decision=Decision.PERMIT,
        reason="synthetic no-key receiver-attestation fixture",
        passport_jti="passport:mcp-receiver-attestation-fixture",
        trace_id="trace:mcp-receiver-attestation-fixture",
        run_nonce="mcp_receiver_fixture_nonce_0123456789",
    )


def run_receiver_attestation_fixture(
    output: str | Path,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    """Create and verify one synthetic MCP ``tools/call`` evidence bundle."""

    output_path = Path(output).expanduser()
    if output_path.is_symlink():
        raise ValueError("fixture output directory must not be a symlink")
    output_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not output_path.is_dir():
        raise ValueError("fixture output path must be a directory")
    output_path.chmod(0o700)

    timestamp = int(time.time() if now is None else now)
    receipt_private_key = ec.generate_private_key(ec.SECP256R1())
    receiver_private_key = ec.generate_private_key(ec.SECP256R1())
    event = _fixture_event(timestamp)
    receipt = build_receipt(Decision.PERMIT, event)
    receipt.iat = timestamp
    receipt.exp = timestamp + 300
    receipt_jwt = sign_receipt(receipt, receipt_private_key)

    request = {
        "jsonrpc": "2.0",
        "id": "fixture-call-1",
        "method": "tools/call",
        "params": {
            "name": event.tool_name,
            "arguments": dict(event.arguments),
            "_meta": {MCP_RECEIPT_META_KEY: receipt_jwt},
        },
    }
    unsigned_response = {
        "jsonrpc": "2.0",
        "id": request["id"],
        "result": {
            "content": [{"type": "text", "text": "synthetic public fixture result"}],
            "structuredContent": {"count": 1},
            "isError": False,
        },
    }
    shim = ReceiverAttestationShim(
        receiver_private_key=receiver_private_key,
        receipt_public_key=receipt_private_key.public_key(),
        receiver_id=RECEIVER_ID,
        key_id=RECEIVER_KEY_ID,
    )
    attested_response = shim.attach_to_mcp_response(
        request=request,
        response=unsigned_response,
        observed_at=timestamp + 1,
    )
    envelope = attested_response["result"]["_meta"][MCP_ATTESTATION_META_KEY]
    verification = verify_receiver_envelope(
        envelope,
        receipt_public_key=receipt_private_key.public_key(),
        receiver_public_key=receiver_private_key.public_key(),
        expected_request=request,
        expected_response=attested_response,
    )

    receipt_public_pem = receipt_private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    receiver_public_pem = receiver_private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    artifacts = {
        "receiver-attestation.json": envelope,
        "mcp-request.json": request,
        "mcp-response.unsigned.json": unsigned_response,
        "mcp-response.attested.json": attested_response,
    }
    for name, value in artifacts.items():
        _write_json(output_path / name, value)
    _atomic_write(output_path / "receipt-public.pem", receipt_public_pem)
    _atomic_write(output_path / "receiver-public.pem", receiver_public_pem)

    report = {
        "ok": True,
        "schema_version": "ardur.receiver_attestation_fixture.v0.1",
        "claim_boundary": "synthetic local MCP tools/call receiver co-signature only",
        "private_keys_persisted": False,
        "artifacts": [
            *artifacts.keys(),
            "receipt-public.pem",
            "receiver-public.pem",
            "report.json",
        ],
        "verification": verification,
        "not_claimed": [
            "live third-party MCP server integration",
            "receiver correctness",
            "action-set completeness",
            "suppression resistance",
            "receiver non-collusion",
        ],
    }
    _write_json(output_path / "report.json", report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic MCP receiver-attestation evidence fixture."
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = run_receiver_attestation_fixture(args.output)
    except (OSError, TypeError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
