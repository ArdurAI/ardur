"""Run portable Ardur agentic-policy conformance fixtures offline."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import stat
import sys
import time
import uuid
import unicodedata
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import best_match

from ._specs import (
    policy_conformance_bundle_v01_schema,
    policy_conformance_report_v01_schema,
)
from .canonical_json import canonical_json_bytes
from .denial import DenialReason
from .passport import MissionPassport, derive_child_passport, issue_passport
from .proxy import (
    Decision,
    GovernanceSession,
    PolicyEvent,
    _policy_action_class,
    _policy_resource_family,
    _policy_side_effect_class,
    _receipt_step_id,
)
from .receipt import verify_receipt


BUNDLE_SCHEMA_VERSION = "ardur.policy_conformance_bundle.v0.1"
REPORT_SCHEMA_VERSION = "ardur.policy_conformance_report.v0.1"
EVIDENCE_CLASS = "implementation-self-test"
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 250_000
FIXTURE_RUN_NONCE = "ardurPolicyFixtureNonceV01"
VERIFIER_ID = "ardur-policy-conformance-v0.1"


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise ValueError(f"bundle JSON contains duplicate name {name!r}")
        value[name] = item
    return value


def _reject_nonfinite(token: str) -> None:
    raise ValueError(f"bundle JSON contains non-finite number {token}")


def _assert_json_bounds_and_nfc(value: Any) -> None:
    stack: list[tuple[Any, str, int]] = [(value, "$", 0)]
    nodes = 0
    while stack:
        item, path, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValueError("bundle exceeds the JSON node limit")
        if depth > MAX_JSON_DEPTH:
            raise ValueError("bundle exceeds the JSON nesting-depth limit")
        if isinstance(item, str):
            if unicodedata.normalize("NFC", item) != item:
                raise ValueError(f"bundle string is not Unicode NFC at {path}")
        elif isinstance(item, Mapping):
            for name, child in item.items():
                if unicodedata.normalize("NFC", name) != name:
                    raise ValueError(f"bundle object name is not Unicode NFC at {path}")
                stack.append((child, f"{path}.{name}", depth + 1))
        elif isinstance(item, list):
            stack.extend(
                (child, f"{path}[{index}]", depth + 1)
                for index, child in enumerate(item)
            )


def _schema_error(error: Any) -> str:
    if error is None:
        return "unknown schema violation"
    path = "$" + "".join(
        f"[{part}]" if isinstance(part, int) else f".{part}" for part in error.path
    )
    return f"{path}: {error.message}"


def _validate(value: dict[str, Any], schema: dict[str, Any], label: str) -> None:
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    error = best_match(validator.iter_errors(value))
    if error is not None:
        raise ValueError(f"{label} schema violation: {_schema_error(error)}")


class PolicyConformancePathError(ValueError):
    """Raised when a ``--bundle`` or ``--output`` argument fails pre-validation.

    A ``ValueError`` subclass so it is still caught by a generic handler, but
    distinct enough for the CLI ``main()`` to emit a structured, sanitized
    failure response (with a stable ``condition`` field) instead of the raw
    exception text.
    """

    def __init__(self, detail: str, *, condition: str) -> None:
        super().__init__(detail)
        self.detail = detail
        self.condition = condition


def load_policy_conformance_bundle(path: str | Path) -> dict[str, Any]:
    """Read a bounded, duplicate-safe, no-follow fixture bundle."""

    bundle_raw = str(path)
    if not bundle_raw.strip():
        raise PolicyConformancePathError(
            "bundle path must not be empty or whitespace-only",
            condition="policy_conformance_bundle_empty",
        )
    bundle_path = Path(bundle_raw).expanduser()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(bundle_path, flags)
    except OSError as exc:
        raise ValueError("bundle path must be a regular file, not a symlink") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("bundle path must be a regular file, not a symlink")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(MAX_BUNDLE_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > MAX_BUNDLE_BYTES:
        raise ValueError("bundle exceeds the 8 MiB input limit")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("bundle is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("bundle must be a JSON object")
    _assert_json_bounds_and_nfc(value)
    _validate(value, policy_conformance_bundle_v01_schema(), "bundle")
    scenario_ids = [item["scenario_id"] for item in value["scenarios"]]
    if len(scenario_ids) != len(set(scenario_ids)):
        raise ValueError("bundle scenario_id values must be unique")
    return value


def _load_public_key(encoded: str) -> ec.EllipticCurvePublicKey:
    try:
        key = serialization.load_pem_public_key(encoded.encode("ascii"))
    except (UnicodeEncodeError, ValueError, TypeError) as exc:
        raise ValueError("bundle receipt_public_key is invalid") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError("bundle receipt_public_key is not P-256")
    return key


def _reason_code(decision: Decision, event: PolicyEvent) -> str:
    if decision == Decision.PERMIT:
        return "within_scope"
    if event.denial_reason is not None:
        return event.denial_reason.value
    return DenialReason.POLICY_DENIED.value


def _delegation_event(
    scenario: Mapping[str, Any], decision: Decision, reason: str
) -> PolicyEvent:
    action = scenario["action"]
    tool_name = str(action["tool_name"])
    arguments = dict(action["arguments"])
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    passport_claims = scenario["passport_claims"]
    action_class = _policy_action_class(tool_name)
    target = str(arguments.get("child_agent_id", tool_name))
    resource_family = _policy_resource_family(
        tool_name, arguments, target, action_class
    )
    return PolicyEvent(
        timestamp=timestamp,
        step_id=_receipt_step_id(
            str(passport_claims["jti"]), timestamp, tool_name, arguments
        ),
        actor=str(passport_claims["sub"]),
        verifier_id=VERIFIER_ID,
        tool_name=tool_name,
        arguments=arguments,
        action_class=action_class,
        target=target,
        resource_family=resource_family,
        side_effect_class=_policy_side_effect_class(
            tool_name, action_class, resource_family
        ),
        decision=decision,
        reason=reason,
        passport_jti=str(passport_claims["jti"]),
        trace_id=str(passport_claims["jti"]),
        run_nonce=FIXTURE_RUN_NONCE,
        denial_reason=(
            DenialReason.POLICY_DENIED if decision != Decision.PERMIT else None
        ),
        policy_decisions=[
            {
                "backend": "delegation_attenuation",
                "decision": "Allow" if decision == Decision.PERMIT else "Deny",
                "reason": reason,
            }
        ],
    )


def _evaluate_delegation_scenario(
    scenario: Mapping[str, Any],
) -> tuple[Decision, str, str, PolicyEvent]:
    claims = scenario["passport_claims"]
    request = scenario["delegation_request"]
    private_key = ec.generate_private_key(ec.SECP256R1())
    parent = MissionPassport(
        agent_id=str(claims["sub"]),
        mission=str(claims["mission"]),
        allowed_tools=list(claims["allowed_tools"]),
        forbidden_tools=list(claims["forbidden_tools"]),
        resource_scope=list(claims["resource_scope"]),
        max_tool_calls=int(claims["max_tool_calls"]),
        max_duration_s=int(claims["max_duration_s"]),
        delegation_allowed=bool(claims["delegation_allowed"]),
        max_delegation_depth=int(claims["max_delegation_depth"]),
        cwd=claims.get("cwd"),
    )
    parent_token = issue_passport(
        parent,
        private_key,
        ttl_s=300,
        jti_override=str(uuid.uuid5(uuid.NAMESPACE_URL, str(claims["jti"]))),
    )
    try:
        derive_child_passport(
            parent_token,
            private_key.public_key(),
            private_key,
            child_agent_id=str(request["child_agent_id"]),
            child_allowed_tools=list(request["child_allowed_tools"]),
            child_mission=str(request["child_mission"]),
            child_ttl_s=int(request["child_ttl_s"]),
            child_max_tool_calls=int(request["child_max_tool_calls"]),
            child_resource_scope=list(request["child_resource_scope"]),
            child_cwd=request.get("child_cwd"),
        )
    except PermissionError as exc:
        decision = Decision.DENY
        reason = str(exc)
    else:
        decision = Decision.PERMIT
        reason = "delegation within parent authority"
    event = _delegation_event(scenario, decision, reason)
    return decision, _reason_code(decision, event), reason, event


def evaluate_policy_scenario(
    scenario: Mapping[str, Any],
) -> tuple[Decision, str, str, PolicyEvent]:
    """Evaluate one scenario through its declared production policy path."""

    if scenario["policy_path"] == "derive_child_passport":
        return _evaluate_delegation_scenario(scenario)

    session = GovernanceSession(
        passport_token="public-policy-conformance-fixture",
        passport_claims=copy.deepcopy(scenario["passport_claims"]),
        run_nonce=FIXTURE_RUN_NONCE,
    )
    for setup_call in scenario["setup_calls"]:
        setup_decision, setup_reason, _ = session.check_and_record(
            str(setup_call["tool_name"]), dict(setup_call["arguments"])
        )
        if setup_decision != Decision.PERMIT:
            raise ValueError(
                f"scenario setup call denied before target action: {setup_reason}"
            )
    action = scenario["action"]
    decision, reason, event = session.check_and_record(
        str(action["tool_name"]), dict(action["arguments"]), verifier_id=VERIFIER_ID
    )
    event.run_nonce = FIXTURE_RUN_NONCE
    return decision, _reason_code(decision, event), reason, event


def _receipt_binding_failures(
    scenario: Mapping[str, Any],
    claims: Mapping[str, Any],
    decision: Decision,
    reason_code: str,
    reason: str,
) -> list[str]:
    action = scenario["action"]
    expected_verdict = "compliant" if decision == Decision.PERMIT else "violation"
    expected_arguments_hash = hashlib.sha256(
        canonical_json_bytes(dict(action["arguments"]))
    ).hexdigest()
    expected = {
        "grant_id": scenario["passport_claims"]["jti"],
        "trace_id": scenario["passport_claims"]["jti"],
        "run_nonce": FIXTURE_RUN_NONCE,
        "verifier_id": VERIFIER_ID,
        "tool": action["tool_name"],
        "arguments_hash": expected_arguments_hash,
        "verdict": expected_verdict,
        "reason": reason,
    }
    failures = [
        f"receipt {name} mismatch"
        for name, value in expected.items()
        if claims.get(name) != value
    ]
    if (
        decision != Decision.PERMIT
        and claims.get("internal_denial_code") != reason_code
    ):
        failures.append("receipt internal_denial_code mismatch")
    if (
        decision != Decision.PERMIT
        and claims.get("public_denial_reason") != reason_code
    ):
        failures.append("receipt public_denial_reason mismatch")
    provenance = scenario["provenance"]
    receipt_provenance = claims.get("content_provenance")
    expected_provenance = {"source": provenance["source"]}
    if receipt_provenance != expected_provenance:
        failures.append("receipt content_provenance mismatch")
    for name in ("content_class", "sensitivity", "instruction_bearing"):
        if claims.get(name) != provenance[name]:
            failures.append(f"receipt {name} mismatch")
    return failures


def _run_scenario(
    scenario: Mapping[str, Any], public_key: ec.EllipticCurvePublicKey
) -> dict[str, Any]:
    failures: list[str] = []
    receipt_id: str | None = None
    receipt_status = "failed"
    decision_text = "ERROR"
    reason_code = "evaluation_error"
    reason: str | None = None
    try:
        decision, reason_code, reason, _event = evaluate_policy_scenario(scenario)
        decision_text = decision.value
    except (KeyError, TypeError, ValueError) as exc:
        failures.append(f"{scenario['policy_path']} evaluation failed: {exc}")
        decision = None
    try:
        claims = verify_receipt(
            str(scenario["receipt_jwt"]),
            public_key,
            verify_expiry=False,
            iat_future_skew_s=None,
            iat_past_skew_s=None,
        )
        receipt_id = str(claims["receipt_id"])
        receipt_status = "verified"
    except (jwt.PyJWTError, TypeError, ValueError) as exc:
        failures.append(f"receipt verification failed: {exc}")
        claims = None

    expected = scenario["expected"]
    if decision_text != expected["decision"]:
        failures.append("decision mismatch")
    if reason_code != expected["reason_code"]:
        failures.append("reason_code mismatch")
    if claims is not None and decision is not None and reason is not None:
        failures.extend(
            _receipt_binding_failures(scenario, claims, decision, reason_code, reason)
        )
    return {
        "scenario_id": scenario["scenario_id"],
        "risk_class": scenario["risk_class"],
        "policy_path": scenario["policy_path"],
        "decision": decision_text,
        "reason_code": reason_code,
        "receipt_id": receipt_id,
        "receipt_verification": receipt_status,
        "verifier_status": "pass" if not failures else "fail",
        "failures": failures,
    }


def run_policy_conformance_bundle(path: str | Path) -> dict[str, Any]:
    """Run all scenarios and return a deterministic, schema-checked report."""

    bundle = load_policy_conformance_bundle(path)
    public_key = _load_public_key(bundle["receipt_public_key"])
    scenarios = [_run_scenario(item, public_key) for item in bundle["scenarios"]]
    failures = sum(item["verifier_status"] != "pass" for item in scenarios)
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "bundle_schema_version": bundle["schema_version"],
        "bundle_id": bundle["bundle_id"],
        "bundle_sha256": hashlib.sha256(canonical_json_bytes(bundle)).hexdigest(),
        "evidence_class": EVIDENCE_CLASS,
        "claim_boundary": bundle["claim_boundary"],
        "ok": failures == 0,
        "summary": {
            "total": len(scenarios),
            "passed": len(scenarios) - failures,
            "failed": failures,
        },
        "scenarios": scenarios,
        "not_claimed": list(bundle["not_claimed"]),
    }
    _validate(report, policy_conformance_report_v01_schema(), "generated report")
    return report


def write_policy_conformance_report(
    path: str | Path, report: Mapping[str, Any]
) -> None:
    """Atomically write a canonical report without following a target symlink."""

    output_raw = str(path)
    if not output_raw.strip():
        raise PolicyConformancePathError(
            "report output path must not be empty or whitespace-only",
            condition="policy_conformance_output_empty",
        )
    output = Path(output_raw).expanduser()
    if output.is_symlink():
        raise ValueError("report output must not be a symlink")
    if not output.parent.is_dir():
        raise ValueError("report output parent must be an existing directory")
    temporary = output.with_name(f".{output.name}.{os.getpid()}.{time.time_ns()}.tmp")
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(canonical_json_bytes(dict(report)) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            # Successful replacement consumes the temporary path.
            pass


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run portable Ardur agentic-policy conformance fixtures."
    )
    parser.add_argument("--bundle", type=str, required=True)
    parser.add_argument("--output", type=str)
    args = parser.parse_args(argv)
    try:
        report = run_policy_conformance_bundle(args.bundle)
        if args.output is not None:
            write_policy_conformance_report(args.output, report)
    except PolicyConformancePathError as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "policy_conformance_path_invalid",
                    "condition": exc.condition,
                    "message": exc.detail,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    except (OSError, TypeError, ValueError) as exc:
        print(
            json.dumps({"ok": False, "error": str(exc)}, sort_keys=True),
            file=sys.stderr,
        )
        return 2
    print(canonical_json_bytes(report).decode("utf-8"))
    return 0 if report["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
