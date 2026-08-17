"""No-key full-evidence fixture for the offline verification product."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from .canonical_json import canonical_json_bytes
from .offline_verification import (
    BUNDLE_SCHEMA_VERSION,
    verify_offline_path,
    write_html_report,
)
from .proxy import Decision, PolicyEvent
from .receipt import build_receipt, sign_receipt
from .receiver_attestation import (
    MCP_ATTESTATION_META_KEY,
    MCP_RECEIPT_META_KEY,
    ReceiverAttestationShim,
    self_attested_envelope,
)
from .transparency import (
    BACKEND_LOCAL_SIGNED,
    LocalSignedLogBackend,
    pending_anchor_bundle,
)


FIXTURE_SCHEMA_VERSION = "ardur.offline_verification_fixture.v0.1"
RECEIVER_ID = "spiffe://fixture.ardur.dev/tool/offline"
RECEIVER_KEY_ID = "offline-fixture-receiver:v1"


def _atomic_write(path: Path, data: bytes) -> None:
    if path.is_symlink():
        raise ValueError(f"fixture artifact must not be a symlink: {path.name}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    fd: int | None = None
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            # The atomic replace already consumed the temporary path.
            pass


def _write_json(path: Path, value: Any) -> None:
    _atomic_write(path, canonical_json_bytes(value) + b"\n")


def _event(index: int, timestamp: int, decision: Decision) -> PolicyEvent:
    observed = datetime.fromtimestamp(timestamp, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    tool = "read_file" if decision == Decision.PERMIT else "write_file"
    return PolicyEvent(
        timestamp=observed,
        step_id=f"step:offline-fixture:{index}",
        actor="spiffe://fixture.ardur.dev/agent/reviewer",
        verifier_id="spiffe://fixture.ardur.dev/verifier",
        tool_name=tool,
        arguments={"path": f"workspace/public-fixture-{index}.txt", "index": index},
        action_class="read" if decision == Decision.PERMIT else "write",
        target=(
            "https://example.test/items?api_key=synthetic-secret&view=<script>fixture</script>"
            if index == 0
            else f"workspace/public-fixture-{index}.txt"
        ),
        resource_family="filesystem",
        side_effect_class="none" if decision == Decision.PERMIT else "filesystem_write",
        decision=decision,
        reason=(
            "synthetic permit token=fixture-secret"
            if decision == Decision.PERMIT
            else "synthetic policy denial password=fixture-secret"
        ),
        passport_jti="grant:offline-verification-fixture",
        trace_id="trace:offline-verification-fixture",
        run_nonce="offline_verification_fixture_nonce_0123456789",
        budget_delta=(
            {
                "operation": "consume",
                "resource": "tool_calls",
                "amount": 1,
                "unit": "invocations",
                "remaining_after": 9 - index,
            }
            if index > 0
            else None
        ),
    )


class OfflineVerificationFixtureOutputError(ValueError):
    """Raised when the ``--output`` argument fails pre-validation.

    A ``ValueError`` subclass so it is still caught by the generic handler in
    ``main()`` / ``cmd_offline_verification_fixture()``, but distinct enough for
    the CLI to emit a structured, sanitized failure response instead of the raw
    exception text.
    """

    def __init__(self, detail: str, *, condition: str) -> None:
        super().__init__(detail)
        self.detail = detail
        self.condition = condition


def run_offline_verification_fixture(
    output: str | Path,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    """Generate and verify a synthetic full-evidence receipt chain."""

    output_raw = str(output)
    output_str = output_raw.strip()
    if not output_str:
        raise OfflineVerificationFixtureOutputError(
            "fixture output path must not be empty or whitespace-only",
            condition="offline_verification_fixture_output_empty",
        )
    output_path = Path(output_str).expanduser()
    if output_path.is_symlink():
        raise OfflineVerificationFixtureOutputError(
            "fixture output directory must not be a symlink",
            condition="offline_verification_fixture_output_symlink",
        )
    if output_path.exists() and not output_path.is_dir():
        raise OfflineVerificationFixtureOutputError(
            "fixture output path must be a directory, not a regular file",
            condition="offline_verification_fixture_output_not_directory",
        )
    output_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not output_path.is_dir():
        raise ValueError("fixture output path must be a directory")
    output_path.chmod(0o700)

    base_time = int(time.time() if now is None else now)
    if base_time < 0:
        raise ValueError("fixture time must be non-negative")
    receipt_key = ec.generate_private_key(ec.SECP256R1())
    receiver_key = ec.generate_private_key(ec.SECP256R1())
    log_key = ed25519.Ed25519PrivateKey.generate()
    shim = ReceiverAttestationShim(
        receiver_private_key=receiver_key,
        receipt_public_key=receipt_key.public_key(),
        receiver_id=RECEIVER_ID,
        key_id=RECEIVER_KEY_ID,
    )
    clock = [base_time]
    with tempfile.TemporaryDirectory(
        prefix="ardur-offline-fixture-", dir=output_path
    ) as work:
        log = LocalSignedLogBackend(
            Path(work) / "transparency.jsonl",
            log_key,
            origin="fixture.ardur.dev/offline",
            clock=lambda: clock[0],
        )
        journal: list[dict[str, Any]] = []
        previous_token: str | None = None
        for index, decision in enumerate(
            (Decision.PERMIT, Decision.DENY, Decision.PERMIT)
        ):
            timestamp = base_time + index * 10
            clock[0] = timestamp + 2
            event = _event(index, timestamp, decision)
            parent_hash = (
                hashlib.sha256(previous_token.encode("ascii")).hexdigest()
                if previous_token is not None
                else None
            )
            receipt = build_receipt(
                decision,
                event,
                parent_receipt_hash=parent_hash,
                policy_decisions=[
                    {
                        "backend": "native",
                        "decision": "Allow" if decision == Decision.PERMIT else "Deny",
                        "reason": event.reason,
                    }
                ],
                budget_remaining={"tool_calls": 9 - index},
            )
            receipt.iat = timestamp
            receipt.exp = timestamp + 300
            receipt.measurements = {
                "cost_usd": round(0.001 * (index + 1), 3),
                "token_count": 100 * (index + 1),
            }
            receipt_jwt = sign_receipt(receipt, receipt_key)
            anchor = log.submit(
                pending_anchor_bundle(receipt_jwt, backend_kind=BACKEND_LOCAL_SIGNED)
            )
            if decision == Decision.PERMIT:
                request = {
                    "jsonrpc": "2.0",
                    "id": f"offline-fixture-{index}",
                    "method": "tools/call",
                    "params": {
                        "name": event.tool_name,
                        "arguments": dict(event.arguments),
                        "_meta": {MCP_RECEIPT_META_KEY: receipt_jwt},
                    },
                }
                response = {
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "result": {
                        "content": [
                            {"type": "text", "text": f"synthetic result {index}"}
                        ],
                        "isError": False,
                    },
                }
                attested = shim.attach_to_mcp_response(
                    request=request,
                    response=response,
                    observed_at=timestamp + 1,
                )
                receiver_envelope = attested["result"]["_meta"][
                    MCP_ATTESTATION_META_KEY
                ]
            else:
                receiver_envelope = self_attested_envelope(receipt_jwt)
            journal.append(
                {
                    "receipt_jwt": receipt_jwt,
                    "transparency_anchor": anchor,
                    "receiver_attestation": receiver_envelope,
                }
            )
            previous_token = receipt_jwt

    bundle_path = output_path / "offline-verification-v0.1.json"
    receipt_public_path = output_path / "offline-verification-v0.1-receipt-public.pem"
    log_public_path = output_path / "offline-verification-v0.1-log-public.pem"
    receiver_public_path = output_path / "offline-verification-v0.1-receiver-public.pem"
    json_report_path = output_path / "offline-verification-v0.1-report.json"
    html_report_path = output_path / "offline-verification-v0.1-report.html"
    bundle = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "profile": "full-evidence",
        "journal": journal,
    }
    _write_json(bundle_path, bundle)
    for path, public_key in (
        (receipt_public_path, receipt_key.public_key()),
        (log_public_path, log_key.public_key()),
        (receiver_public_path, receiver_key.public_key()),
    ):
        _atomic_write(
            path,
            public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
    verification = verify_offline_path(
        bundle_path,
        receipt_public_key=receipt_key.public_key(),
        log_public_key=log_key.public_key(),
        receiver_public_key=receiver_key.public_key(),
        max_registration_delay_s=60,
    )
    _write_json(json_report_path, verification)
    write_html_report(html_report_path, verification)

    artifacts = [
        bundle_path.name,
        receipt_public_path.name,
        log_public_path.name,
        receiver_public_path.name,
        json_report_path.name,
        html_report_path.name,
    ]
    return {
        "ok": True,
        "schema_version": FIXTURE_SCHEMA_VERSION,
        "claim_boundary": "synthetic local offline receipt/evidence verification only",
        "private_keys_persisted": False,
        "artifacts": artifacts,
        "verification": {
            "result": verification["result"],
            "summary": verification["summary"],
        },
        "not_claimed": [
            "online revocation freshness",
            "receiver correctness",
            "action-set completeness",
            "suppression resistance",
            "receiver non-collusion",
            "live third-party MCP deployment",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic full-evidence offline verification fixture."
    )
    parser.add_argument("--output", type=str, required=True)
    args = parser.parse_args(argv)
    try:
        report = run_offline_verification_fixture(args.output)
    except OfflineVerificationFixtureOutputError as exc:
        print(
            json.dumps(
                {"ok": False, "error": exc.condition, "condition": exc.condition},
                sort_keys=True,
            )
        )
        return 1
    except (OSError, TypeError, ValueError) as exc:
        # Inline a local classifier (mirrors ``vibap.cli._classify_fixture_error``)
        # to avoid a cross-module import cycle. Never leak ``str(exc)``: raw
        # ``OSError`` text carries filesystem paths / errno details and
        # ``TypeError`` / ``ValueError`` text carries Python internals.
        if isinstance(exc, OSError):
            safe_message = "Filesystem error writing fixture output."
        else:
            safe_message = "Invalid input type or value for fixture generation."
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "offline_verification_fixture_failed",
                    "message": safe_message,
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
