#!/usr/bin/env python3
"""Offline verifier for Ardur multiagent lifecycle evidence bundles."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vibap.attestation import compute_log_digest, verify_attestation
from vibap.proxy import Decision, GovernanceSession
from vibap.receipt import ReceiptChainError, verify_chain

LIFECYCLE_SCHEMA = "ardur.lifecycle.attestation.v1"
LIFECYCLE_KEYS = {
    "lifecycle_schema",
    "children_spawned",
    "children_closed",
    "child_jtis",
    "delegation_count",
    "delegation_attempt_count",
    "delegation_denial_count",
    "delegated_budget_reserved",
    "children",
}


@dataclass
class BundleVerification:
    bundle: Path
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)
    claims: dict[str, Any] = field(default_factory=dict)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_public_key(path: Path):
    return serialization.load_pem_public_key(path.read_bytes())


def _load_attestation(path: Path) -> tuple[str, dict[str, Any]]:
    payload = _load_json(path)
    if isinstance(payload, str):
        return payload, {}
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} must be a JSON object or token string")
    token = payload.get("token")
    if not isinstance(token, str) or not token:
        raise ValueError(f"{path.name} missing non-empty token")
    sidecar = payload.get("claims", {})
    if sidecar is not None and not isinstance(sidecar, dict):
        raise ValueError(f"{path.name} claims sidecar must be an object")
    return token, dict(sidecar or {})


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            raise ValueError(f"{path.name}:{line_no} is not a JSON object")
        entries.append(obj)
    return entries


def _session_from_path(path: Path) -> GovernanceSession:
    payload = _load_json(path)
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} must contain a session object")
    payload = dict(payload)
    forbidden_authority = {"passport_token", "attestation_token"} & payload.keys()
    if forbidden_authority:
        names = ", ".join(sorted(forbidden_authority))
        raise ValueError(f"{path.name} leaks authority-bearing fields: {names}")
    payload.pop("receipt_chain_integrity", None)
    # GovernanceSession's parser expects its live-runtime shape.  The offline
    # verifier injects a non-authorizing sentinel only in memory; exported
    # evidence deliberately contains neither child passport nor attestation.
    payload["passport_token"] = "<redacted-offline-evidence>"
    return GovernanceSession.from_dict(payload)


def _llm_spawn_calls(path: Path) -> list[dict[str, Any]]:
    calls = _read_jsonl(path)
    return [
        call
        for call in calls
        if call.get("tool_name", call.get("name")) == "spawn_subagent"
        and call.get("origin", call.get("source")) == "llm"
    ]


def _receipt_groups(receipts: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for entry in receipts:
        session_id = entry.get("session_id")
        if isinstance(session_id, str) and session_id:
            groups.setdefault(session_id, []).append(entry)
    return groups


def _permitted_out_of_scope_events(session: GovernanceSession) -> list[str]:
    allowed = set(session.passport_claims.get("allowed_tools", []) or [])
    forbidden = set(session.passport_claims.get("forbidden_tools", []) or [])
    out: list[str] = []
    for event in session.events:
        if event.decision != Decision.PERMIT:
            continue
        if event.tool_name in forbidden or event.tool_name not in allowed:
            out.append(event.tool_name)
    return out


def _append_error(errors: list[str], prefix: str, exc: Exception) -> None:
    errors.append(f"{prefix}: {type(exc).__name__}: {exc}")


def verify_bundle(bundle: str | Path, *, expected_children: int = 3) -> BundleVerification:
    root = Path(bundle).resolve()
    errors: list[str] = []
    warnings: list[str] = []
    lines: list[str] = []
    claims: dict[str, Any] = {}

    required = {
        "manifest": root / "manifest.json",
        "public_key": root / "public_key.pem",
        "parent_attestation": root / "parent.attestation.json",
        "parent_tool_calls": root / "parent_tool_calls.jsonl",
        "lifecycle_rollup": root / "lifecycle_rollup.json",
        "receipts": root / "receipts.jsonl",
        "children_dir": root / "children",
    }
    for label, path in required.items():
        if not path.exists():
            errors.append(f"missing {label}: {path}")
    if errors:
        return BundleVerification(root, False, errors, warnings, lines, claims)

    try:
        public_key = _load_public_key(required["public_key"])
    except Exception as exc:
        _append_error(errors, "public key load failed", exc)
        return BundleVerification(root, False, errors, warnings, lines, claims)

    try:
        manifest = _load_json(required["manifest"])
        if not isinstance(manifest, dict):
            raise ValueError("manifest must be a JSON object")
    except Exception as exc:
        _append_error(errors, "manifest.json load failed", exc)
        return BundleVerification(root, False, errors, warnings, lines, claims)

    try:
        parent_token, parent_sidecar = _load_attestation(required["parent_attestation"])
        claims = verify_attestation(parent_token, public_key)
        if parent_sidecar and parent_sidecar != claims:
            errors.append("parent attestation sidecar claims do not match signed token")
    except Exception as exc:
        _append_error(errors, "parent attestation verification failed", exc)
        return BundleVerification(root, False, errors, warnings, lines, claims)

    lifecycle_claims = {key: claims.get(key) for key in LIFECYCLE_KEYS if key in claims}
    try:
        lifecycle_rollup = _load_json(required["lifecycle_rollup"])
    except Exception as exc:
        _append_error(errors, "lifecycle_rollup.json load failed", exc)
        lifecycle_rollup = {}
    if lifecycle_claims and lifecycle_rollup != lifecycle_claims:
        errors.append("lifecycle_rollup.json does not match parent attestation lifecycle claims")

    if claims.get("lifecycle_schema") != LIFECYCLE_SCHEMA:
        errors.append("parent attestation missing lifecycle_schema")
    children = claims.get("children")
    child_jtis = claims.get("child_jtis")
    if not isinstance(children, list):
        errors.append("parent attestation children must be a list")
        children = []
    if not isinstance(child_jtis, list):
        errors.append("parent attestation child_jtis must be a list")
        child_jtis = []
    if len(set(child_jtis)) != len(child_jtis):
        errors.append("parent attestation child_jtis contains duplicates")
    if claims.get("children_spawned") != expected_children:
        errors.append(f"children_spawned must be {expected_children}")
    if len(child_jtis) != expected_children or len(children) != expected_children:
        errors.append("child_jtis and children lengths must match expected child count")

    try:
        spawn_calls = _llm_spawn_calls(required["parent_tool_calls"])
        if len(spawn_calls) != expected_children:
            errors.append(
                f"parent transcript must contain exactly {expected_children} "
                f"LLM-originated spawn_subagent calls"
            )
    except Exception as exc:
        _append_error(errors, "parent tool-call transcript verification failed", exc)

    try:
        receipts = _read_jsonl(required["receipts"])
    except Exception as exc:
        _append_error(errors, "receipts load failed", exc)
        receipts = []
    receipt_groups = _receipt_groups(receipts)
    for session_id, entries in receipt_groups.items():
        try:
            verify_chain(entries, public_key)
        except (ReceiptChainError, TypeError, ValueError) as exc:
            errors.append(f"receipt chain invalid for session {session_id}: {exc}")

    parent_passport_claims = manifest.get("parent_passport_claims")
    if not isinstance(parent_passport_claims, dict):
        errors.append("manifest missing parent_passport_claims object")
        parent_passport_claims = {}
    parent_allowed = set(parent_passport_claims.get("allowed_tools", []) or [])
    if not parent_allowed:
        errors.append("manifest parent_passport_claims.allowed_tools is empty; cannot prove child attenuation")
    parent_passport_jti = claims.get("passport_jti")
    delegated_budget_sum = 0
    child_lines: list[str] = []
    child_claims_by_jti = {
        str(child.get("child_jti")): child
        for child in children
        if isinstance(child, dict) and child.get("child_jti")
    }

    for child_jti in child_jtis:
        child_jti = str(child_jti)
        child_att_path = required["children_dir"] / f"{child_jti}.attestation.json"
        child_session_path = required["children_dir"] / f"{child_jti}.session.json"
        if not child_att_path.exists():
            errors.append(f"missing child attestation for {child_jti}")
            continue
        if not child_session_path.exists():
            errors.append(f"missing child session for {child_jti}")
            continue

        try:
            child_token, child_sidecar = _load_attestation(child_att_path)
            child_att_claims = verify_attestation(child_token, public_key)
            if child_sidecar and child_sidecar != child_att_claims:
                errors.append(f"{child_jti}: attestation sidecar claims mismatch")
        except Exception as exc:
            _append_error(errors, f"{child_jti}: child attestation verification failed", exc)
            continue

        try:
            child_session = _session_from_path(child_session_path)
        except Exception as exc:
            _append_error(errors, f"{child_jti}: child session load failed", exc)
            continue

        if child_att_claims.get("passport_jti") != child_jti:
            errors.append(f"{child_jti}: child attestation passport_jti mismatch")
        if child_session.jti != child_jti:
            errors.append(f"{child_jti}: child session jti mismatch")
        if child_session.passport_claims.get("parent_jti") != parent_passport_jti:
            errors.append(f"{child_jti}: child session parent_jti mismatch")

        child_allowed = set(child_session.passport_claims.get("allowed_tools", []) or [])
        child_record = child_claims_by_jti.get(child_jti, {})
        record_allowed = set(child_record.get("allowed_tools", []) or [])
        if child_allowed != record_allowed:
            errors.append(f"{child_jti}: child allowed_tools disagree with parent rollup")
        if parent_allowed and not child_allowed.issubset(parent_allowed):
            errors.append(f"{child_jti}: child allowed_tools widen parent authority")

        out_of_scope = _permitted_out_of_scope_events(child_session)
        if out_of_scope:
            errors.append(f"{child_jti}: out-of-scope permitted events: {out_of_scope}")
        if child_att_claims.get("log_digest_sha256") != compute_log_digest(child_session.to_log()):
            errors.append(f"{child_jti}: attestation log_digest_sha256 mismatch")

        receipt_count = len(receipt_groups.get(child_jti, []))
        if receipt_count != len(child_session.events):
            errors.append(f"{child_jti}: receipt count does not match child session events")

        child_record_hash = child_record.get("attestation_sha256")
        actual_hash = hashlib.sha256(child_token.encode("utf-8")).hexdigest()
        if not child_record_hash:
            errors.append(f"{child_jti}: parent child attestation hash missing")
        elif child_record_hash != actual_hash:
            errors.append(f"{child_jti}: parent child attestation hash mismatch")

        try:
            delegated_budget_sum += int(
                child_session.passport_claims.get(
                    "reserved_budget_share",
                    child_record.get("delegated_budget_reserved", 0),
                )
            )
        except (TypeError, ValueError):
            errors.append(f"{child_jti}: delegated budget is not an integer")

        denied_tools = sorted(
            {
                event.tool_name
                for event in child_session.events
                if event.decision != Decision.PERMIT
            }
        )
        child_lines.append(
            "child "
            f"{child_record.get('child_agent_id', child_jti)}: "
            "authority=valid receipts=valid attestation=valid "
            f"no_out_of_scope_permits={not out_of_scope}"
            + (f" denied_tools={json.dumps(denied_tools)}" if denied_tools else "")
        )

    expected_budget = claims.get("delegated_budget_reserved")
    if expected_budget != delegated_budget_sum:
        errors.append(
            "parent delegated_budget_reserved does not equal sum of child budgets "
            f"({expected_budget} != {delegated_budget_sum})"
        )

    ok = not errors
    lines.append(
        "MULTIAGENT LIFECYCLE VERIFY: " + ("PASS" if ok else "FAIL")
    )
    lines.append(f"children_spawned={claims.get('children_spawned')}")
    lines.append(f"delegation_count={claims.get('delegation_count')}")
    lines.append(f"delegated_budget_reserved={claims.get('delegated_budget_reserved')}")
    lines.extend(child_lines)
    return BundleVerification(root, ok, errors, warnings, lines, claims)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--expected-children", type=int, default=3)
    args = parser.parse_args(argv)

    result = verify_bundle(args.bundle, expected_children=args.expected_children)
    for line in result.lines:
        print(line)
    for warning in result.warnings:
        print(f"WARNING: {warning}", file=sys.stderr)
    for error in result.errors:
        print(f"ERROR: {error}", file=sys.stderr)
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
