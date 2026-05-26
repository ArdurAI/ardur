"""Read-only Claude Code posture detector.

This detector consumes Claude Code hook receipt chains and adjacent subagent
registry logs as derived evidence. It classifies governance-relevant signals for
shareable posture/discovery reports, but it does not mutate traces or enforce
policy.
"""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any, Mapping, Sequence, cast

from ..posture_index import (
    _Redactor,
    _aggregate_verification,
    _decode_unverified,
    _load_public_key_read_only,
    _read_receipt_tokens,
    _receipt_files,
)
from ..receipt import ReceiptChainError, verify_chain

SCHEMA_VERSION = "ardur.claude_posture_detector.v0"
POSITIONING = "read_only_observation"
CLAIM_SCOPE = (
    "Derived local Claude Code receipt/log posture signals only; read-only "
    "observation, not runtime governance, policy enforcement, provider-hidden "
    "visibility, or kernel/process capture."
)

SIGNAL_NAMES: tuple[str, ...] = (
    "file_writes",
    "command_executions",
    "tool_denials",
    "subagent_spawns",
    "network_activity_markers",
)

_FILE_WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
_COMMAND_TOOLS = {"Bash", "Shell"}
_NETWORK_TOOLS = {"WebFetch", "WebSearch"}
_SUBAGENT_TOOLS = {"Task", "Agent", "SubagentStart"}
_DENY_DECISIONS = {"deny", "denied", "violation", "block", "blocked"}


def _counter_dict(values: Sequence[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def _claude_code_meta(claim: Mapping[str, Any]) -> dict[str, Any]:
    measurements = claim.get("measurements")
    if not isinstance(measurements, Mapping):
        return {}
    meta = measurements.get("claude_code")
    return dict(meta) if isinstance(meta, Mapping) else {}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    records: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            records.append(decoded)
    return records


def _policy_denied(claim: Mapping[str, Any]) -> bool:
    for item in claim.get("policy_decisions", []) or []:
        if not isinstance(item, Mapping):
            continue
        decision = str(item.get("decision", "")).strip().lower()
        if decision in _DENY_DECISIONS:
            return True
    return False


def _matches_signal(signal: str, claim: Mapping[str, Any]) -> bool:
    tool = str(claim.get("tool", ""))
    action_class = str(claim.get("action_class", ""))
    side_effect_class = str(claim.get("side_effect_class", ""))
    resource_family = str(claim.get("resource_family", ""))
    verdict = str(claim.get("verdict", ""))

    if signal == "file_writes":
        return side_effect_class == "filesystem_write" or action_class == "write" or tool in _FILE_WRITE_TOOLS
    if signal == "command_executions":
        return side_effect_class == "process_launch" or action_class == "execute" or tool in _COMMAND_TOOLS
    if signal == "tool_denials":
        return verdict == "violation" or _policy_denied(claim)
    if signal == "subagent_spawns":
        return side_effect_class == "subagent_launch" or action_class == "dispatch" or tool in _SUBAGENT_TOOLS
    if signal == "network_activity_markers":
        return side_effect_class == "network_read" or resource_family == "network" or tool in _NETWORK_TOOLS
    return False


def _event_ref(
    *,
    claim: Mapping[str, Any],
    redactor: _Redactor,
    chain_index: int,
    receipt_index: int,
) -> dict[str, Any]:
    meta = _claude_code_meta(claim)
    return {
        "chain_index": chain_index,
        "receipt_index": receipt_index,
        "receipt_id": redactor.text(str(claim.get("receipt_id", ""))),
        "trace_id": redactor.text(str(claim.get("trace_id", ""))),
        "tool": redactor.text(str(claim.get("tool", ""))),
        "action_class": redactor.text(str(claim.get("action_class", ""))),
        "side_effect_class": redactor.text(str(claim.get("side_effect_class", ""))),
        "resource_family": redactor.text(str(claim.get("resource_family", ""))),
        "target": redactor.text(str(claim.get("target", ""))),
        "verdict": redactor.text(str(claim.get("verdict", ""))),
        "actor_kind": redactor.text(str(meta.get("actor_kind", "unknown"))),
        "hook_event_name": redactor.text(str(meta.get("hook_event_name", ""))),
    }


def _chain_trace_id(receipt_file: Path, claims: Sequence[Mapping[str, Any]]) -> str:
    for claim in claims:
        trace_id = claim.get("trace_id")
        if trace_id:
            return str(trace_id)
    return receipt_file.parent.name


def _chain_summary(
    *,
    receipt_file: Path,
    tokens: list[str],
    claims: list[dict[str, Any]],
    verification: dict[str, Any],
    redactor: _Redactor,
) -> dict[str, Any]:
    subagent_file = receipt_file.parent / "subagents.jsonl"
    subagent_records = _read_jsonl(subagent_file)
    return {
        "trace_id": redactor.text(_chain_trace_id(receipt_file, claims)),
        "receipt_file": redactor.text(str(receipt_file)),
        "receipt_count": len(claims),
        "raw_entry_count": len(tokens),
        "verification": verification,
        "tools": _counter_dict([str(claim.get("tool", "")) for claim in claims]),
        "verdicts": _counter_dict([str(claim.get("verdict", "")) for claim in claims]),
        "action_classes": _counter_dict([str(claim.get("action_class", "")) for claim in claims]),
        "side_effect_classes": _counter_dict([str(claim.get("side_effect_class", "")) for claim in claims]),
        "subagent_registry": {
            "present": subagent_file.is_file(),
            "path": redactor.text(str(subagent_file)),
            "record_count": len(subagent_records),
            "started": sum(1 for record in subagent_records if record.get("event") == "start"),
            "stopped": sum(1 for record in subagent_records if record.get("event") == "stop"),
        },
    }


def _signal_sections(
    claims_by_chain: Sequence[tuple[int, list[dict[str, Any]]]],
    redactor: _Redactor,
) -> dict[str, dict[str, Any]]:
    sections: dict[str, dict[str, Any]] = {}
    for signal in SIGNAL_NAMES:
        events: list[dict[str, Any]] = []
        for chain_index, claims in claims_by_chain:
            for receipt_index, claim in enumerate(claims):
                if _matches_signal(signal, claim):
                    events.append(
                        _event_ref(
                            claim=claim,
                            redactor=redactor,
                            chain_index=chain_index,
                            receipt_index=receipt_index,
                        )
                    )
        sections[signal] = {"count": len(events), "events": events}
    return sections


def _narrative(signal_counts: Mapping[str, int], *, receipt_count: int, chain_count: int, verification_status: str) -> str:
    return (
        "A read-only Claude Code posture scan observed "
        f"{receipt_count} receipts across {chain_count} chains with "
        f"verification status {verification_status}. It detected "
        f"{signal_counts.get('file_writes', 0)} file-write signal(s), "
        f"{signal_counts.get('command_executions', 0)} command-execution signal(s), "
        f"{signal_counts.get('tool_denials', 0)} tool-denial signal(s), "
        f"{signal_counts.get('subagent_spawns', 0)} subagent-spawn signal(s), and "
        f"{signal_counts.get('network_activity_markers', 0)} network-activity marker(s). "
        "This detector summarizes evidence and does not enforce policy."
    )


def build_claude_posture_summary(
    *,
    receipts: Path,
    keys_dir: Path | None = None,
    verify_expiry: bool = False,
) -> dict[str, Any]:
    """Build a deterministic, shareable posture summary for Claude Code traces.

    ``receipts`` may be a receipt-chain directory or a single ``receipts.jsonl``
    file. ``keys_dir`` is read-only and must already contain
    ``passport_public.pem`` when signature verification is desired.
    """
    roots = [receipts]
    if keys_dir is not None:
        roots.append(keys_dir)
    redactor = _Redactor(roots)
    public_key, key_warning = _load_public_key_read_only(keys_dir)

    receipt_paths = _receipt_files(receipts)
    coverage_gaps: set[str] = set()
    if not receipt_paths:
        coverage_gaps.add("missing_claude_receipt_telemetry")

    chains: list[dict[str, Any]] = []
    claims_by_chain: list[tuple[int, list[dict[str, Any]]]] = []
    all_claims: list[dict[str, Any]] = []

    for chain_index, receipt_file in enumerate(receipt_paths):
        tokens = _read_receipt_tokens(receipt_file)
        if not tokens:
            verification = {"status": "missing", "ok": False, "reason": "receipt_file_empty"}
            claims: list[dict[str, Any]] = []
            coverage_gaps.add("missing_claude_receipt_telemetry")
        elif public_key is None:
            verification = {"status": "not_verified", "ok": None, **(key_warning or {})}
            claims = _decode_unverified(tokens)
            coverage_gaps.add("receipt_chain_not_verified")
        else:
            try:
                claims = verify_chain(cast(list[str | dict[str, Any]], tokens), public_key, verify_expiry=verify_expiry)
                verification = {"status": "pass", "ok": True, "verify_expiry": verify_expiry}
            except ReceiptChainError as exc:
                verification = {
                    "status": "fail",
                    "ok": False,
                    "error": redactor.text(str(exc)),
                    "verify_expiry": verify_expiry,
                }
                claims = _decode_unverified(tokens)
                coverage_gaps.add("broken_receipt_chain")
        all_claims.extend(claims)
        claims_by_chain.append((chain_index, claims))
        chains.append(
            _chain_summary(
                receipt_file=receipt_file,
                tokens=tokens,
                claims=claims,
                verification=verification,
                redactor=redactor,
            )
        )

    signals = _signal_sections(claims_by_chain, redactor)
    signal_counts = {name: int(signals[name]["count"]) for name in sorted(SIGNAL_NAMES)}
    chain_verification = _aggregate_verification(chains)
    verification_status = str(chain_verification.get("status", "unknown"))
    subagent_registry_records = sum(
        int(chain.get("subagent_registry", {}).get("record_count", 0))
        for chain in chains
        if isinstance(chain.get("subagent_registry"), Mapping)
    )

    narrative_fields = {
        **signal_counts,
        "receipt_count": len(all_claims),
        "chain_count": len(chains),
        "verification_status": verification_status,
    }
    summary = {
        "schema_version": SCHEMA_VERSION,
        "positioning": POSITIONING,
        "claim_scope": CLAIM_SCOPE,
        "inputs": {
            "receipts": redactor.text(str(receipts)),
            "keys_dir": redactor.text(str(keys_dir)) if keys_dir is not None else None,
        },
        "chain_verification": chain_verification,
        "summary": {
            "chain_count": len(chains),
            "receipt_count": len(all_claims),
            "trace_count": len({str(claim.get("trace_id", "")) for claim in all_claims if claim.get("trace_id")}),
            "signal_counts": signal_counts,
            "subagent_registry_records": subagent_registry_records,
        },
        "observed_tools": _counter_dict([str(claim.get("tool", "")) for claim in all_claims]),
        "observed_actions": _counter_dict([str(claim.get("action_class", "")) for claim in all_claims]),
        "observed_side_effects": _counter_dict([str(claim.get("side_effect_class", "")) for claim in all_claims]),
        "observed_verdicts": _counter_dict([str(claim.get("verdict", "")) for claim in all_claims]),
        "signals": signals,
        "chains": chains,
        "coverage_gaps": sorted(coverage_gaps),
        "narrative_template": (
            "A read-only Claude Code posture scan observed {receipt_count} receipts across "
            "{chain_count} chains with verification status {verification_status}. It detected "
            "{file_writes} file-write signal(s), {command_executions} command-execution signal(s), "
            "{tool_denials} tool-denial signal(s), {subagent_spawns} subagent-spawn signal(s), and "
            "{network_activity_markers} network-activity marker(s). This detector summarizes evidence "
            "and does not enforce policy."
        ),
        "narrative_fields": narrative_fields,
        "narrative": _narrative(
            signal_counts,
            receipt_count=len(all_claims),
            chain_count=len(chains),
            verification_status=verification_status,
        ),
        "redaction": {
            "local_absolute_paths": "hashed_placeholders",
            "credential_like_values": "[REDACTED]",
            "raw_secret_values_copied": False,
        },
    }
    return redactor.value(summary)
