"""Receipt-chain observability reports for Ardur Claude Code sessions."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from .passport import DEFAULT_HOME, load_public_key
from .receipt import verify_chain


def _counter_dict(values: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def _is_dispatch_claim(claim: Mapping[str, Any]) -> bool:
    return (
        claim.get("side_effect_class") == "subagent_launch"
        or claim.get("action_class") == "dispatch"
        or claim.get("tool") in {"Agent", "Task"}
    )


def _is_dispatch_launch(claim: Mapping[str, Any]) -> bool:
    return _is_dispatch_claim(claim) and claim.get("reason") != "post-call observation"


def _claude_code_meta(claim: Mapping[str, Any]) -> dict[str, Any]:
    measurements = claim.get("measurements")
    if not isinstance(measurements, dict):
        return {}
    meta = measurements.get("claude_code")
    return dict(meta) if isinstance(meta, dict) else {}


def _is_lifecycle_claim(claim: Mapping[str, Any]) -> bool:
    return str(claim.get("tool", "")) in {"SubagentStart", "SubagentStop"}


def _is_child_tool_claim(claim: Mapping[str, Any]) -> bool:
    if _is_lifecycle_claim(claim):
        return False
    if _is_dispatch_claim(claim):
        return False
    return bool(claim.get("tool"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    records: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def _transcript_contains_tool_use_id(path: str, tool_use_id: str) -> bool:
    if not path or not tool_use_id:
        return False
    transcript = Path(path).expanduser()
    try:
        with transcript.open("r", encoding="utf-8", errors="replace") as handle:
            return any(tool_use_id in line for line in handle)
    except OSError:
        return False


def _subagents_from_records(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    subagents: dict[str, dict[str, Any]] = {}
    for record in records:
        child_id = str(record.get("ardur_child_id", "") or "")
        if not child_id:
            continue
        current = subagents.setdefault(
            child_id,
            {
                "ardur_child_id": child_id,
                "claude_agent_id": str(record.get("claude_agent_id", "") or ""),
                "agent_type": str(record.get("agent_type", "") or ""),
                "started_at": None,
                "stopped_at": None,
                "agent_transcript_path": "",
                "tool_receipt_count": 0,
                "tools": {},
                "violations": 0,
                "attribution_modes": {},
            },
        )
        if record.get("claude_agent_id"):
            current["claude_agent_id"] = str(record["claude_agent_id"])
        if record.get("agent_type"):
            current["agent_type"] = str(record["agent_type"])
        if record.get("agent_transcript_path"):
            current["agent_transcript_path"] = str(record["agent_transcript_path"])
        if record.get("started_at"):
            current["started_at"] = str(record["started_at"])
        if record.get("stopped_at"):
            current["stopped_at"] = str(record["stopped_at"])
    return subagents


def _attribute_child_tool(
    claim: Mapping[str, Any],
    subagents: Mapping[str, dict[str, Any]],
) -> tuple[str | None, str]:
    meta = _claude_code_meta(claim)
    child_id = str(meta.get("ardur_child_id", "") or "")
    if child_id and child_id in subagents and meta.get("claude_agent_id"):
        return child_id, "exact"

    transcript_path = str(meta.get("transcript_path", "") or "")
    transcript_matches = [
        candidate
        for candidate, subagent in subagents.items()
        if transcript_path and transcript_path == subagent.get("agent_transcript_path")
    ]
    if len(transcript_matches) == 1:
        return transcript_matches[0], "derived"
    if len(transcript_matches) > 1:
        return None, "ambiguous"

    tool_use_id = str(meta.get("tool_use_id", "") or "")
    transcript_tool_matches = [
        candidate
        for candidate, subagent in subagents.items()
        if _transcript_contains_tool_use_id(str(subagent.get("agent_transcript_path", "") or ""), tool_use_id)
    ]
    if len(transcript_tool_matches) == 1:
        return transcript_tool_matches[0], "derived"
    if len(transcript_tool_matches) > 1:
        return None, "ambiguous"
    return None, "trace_only"


def _merge_attribution_mode(modes: list[str]) -> str:
    if not modes:
        return "trace_only"
    if "ambiguous" in modes:
        return "ambiguous"
    if "trace_only" in modes:
        return "trace_only"
    if "derived" in modes:
        return "derived"
    return "exact"


def _chain_report(
    *,
    trace_id: str,
    receipt_file: Path,
    claims: list[dict[str, Any]],
) -> dict[str, Any]:
    subagent_records = _read_jsonl(receipt_file.parent / "subagents.jsonl")
    subagents_by_child = _subagents_from_records(subagent_records)
    attribution_modes: list[str] = []
    unattributed_tool_receipts: list[dict[str, Any]] = []
    ambiguous_tool_receipts: list[dict[str, Any]] = []
    for claim in claims:
        if not _is_child_tool_claim(claim):
            continue
        child_id, mode = _attribute_child_tool(claim, subagents_by_child)
        attribution_modes.append(mode)
        if child_id:
            subagent = subagents_by_child[child_id]
            subagent["tool_receipt_count"] = int(subagent.get("tool_receipt_count", 0)) + 1
            tools = dict(subagent.get("tools", {}) or {})
            tool = str(claim.get("tool", ""))
            tools[tool] = tools.get(tool, 0) + 1
            subagent["tools"] = dict(sorted(tools.items()))
            if claim.get("verdict") == "violation":
                subagent["violations"] = int(subagent.get("violations", 0)) + 1
            mode_counts = dict(subagent.get("attribution_modes", {}) or {})
            mode_counts[mode] = mode_counts.get(mode, 0) + 1
            subagent["attribution_modes"] = dict(sorted(mode_counts.items()))
            continue
        receipt_ref = {
            "receipt_id": str(claim.get("receipt_id", "")),
            "tool": str(claim.get("tool", "")),
            "tool_use_id": str(_claude_code_meta(claim).get("tool_use_id", "") or ""),
            "attribution": mode,
        }
        if mode == "ambiguous":
            ambiguous_tool_receipts.append(receipt_ref)
        else:
            unattributed_tool_receipts.append(receipt_ref)

    dispatches = [
        {
            "receipt_id": str(claim.get("receipt_id", "")),
            "timestamp": str(claim.get("timestamp", "")),
            "tool": str(claim.get("tool", "")),
            "target": str(claim.get("target", "")),
            "verdict": str(claim.get("verdict", "")),
            "reason": str(claim.get("reason", "")),
            "side_effect_class": str(claim.get("side_effect_class", "")),
        }
        for claim in claims
        if _is_dispatch_claim(claim)
    ]
    dispatch_launches = [
        dispatch
        for dispatch in dispatches
        if dispatch["reason"] != "post-call observation"
    ]
    dispatch_observations = [
        dispatch
        for dispatch in dispatches
        if dispatch["reason"] == "post-call observation"
    ]
    first_dispatch_index = next(
        (
            idx
            for idx, claim in enumerate(claims)
            if _is_dispatch_claim(claim)
        ),
        None,
    )
    after_dispatch = claims[first_dispatch_index + 1 :] if first_dispatch_index is not None else []
    return {
        "trace_id": trace_id,
        "receipt_file": str(receipt_file),
        "receipt_count": len(claims),
        "first_timestamp": str(claims[0].get("timestamp", "")) if claims else None,
        "last_timestamp": str(claims[-1].get("timestamp", "")) if claims else None,
        "tools": _counter_dict([str(claim.get("tool", "")) for claim in claims]),
        "verdicts": _counter_dict([str(claim.get("verdict", "")) for claim in claims]),
        "action_classes": _counter_dict([str(claim.get("action_class", "")) for claim in claims]),
        "side_effect_classes": _counter_dict([str(claim.get("side_effect_class", "")) for claim in claims]),
        "dispatches": dispatches,
        "dispatch_launches": dispatch_launches,
        "dispatch_observations": dispatch_observations,
        "dispatch_receipt_count": len(dispatches),
        "dispatch_launch_count": len(dispatch_launches),
        "dispatch_observation_count": len(dispatch_observations),
        "receipt_count_after_first_dispatch": len(after_dispatch),
        "tools_after_first_dispatch": _counter_dict([str(claim.get("tool", "")) for claim in after_dispatch]),
        "subagent_registry_file": str(receipt_file.parent / "subagents.jsonl"),
        "subagent_registry_records": len(subagent_records),
        "subagents_started": sum(1 for record in subagent_records if record.get("event") == "start"),
        "subagents_stopped": sum(1 for record in subagent_records if record.get("event") == "stop"),
        "subagents": list(subagents_by_child.values()),
        "per_child_attribution": _merge_attribution_mode(attribution_modes),
        "unattributed_tool_receipts": unattributed_tool_receipts,
        "ambiguous_tool_receipts": ambiguous_tool_receipts,
        "unattributed_tool_receipt_count": len(unattributed_tool_receipts),
        "ambiguous_tool_receipt_count": len(ambiguous_tool_receipts),
    }


def build_claude_code_report(
    *,
    home: Path | None = None,
    chain_dir: Path | None = None,
    keys_dir: Path | None = None,
    verify_expiry: bool = False,
) -> dict[str, Any]:
    """Verify Claude Code hook receipt chains and summarize observability.

    Receipt expiry is disabled by default because this command is an evidence
    report: old signed receipts should remain auditable after their runtime
    freshness window has passed.
    """
    resolved_home = (home or DEFAULT_HOME).expanduser().resolve()
    resolved_chain_dir = (chain_dir or (resolved_home / "claude-code-hook")).expanduser().resolve()
    resolved_keys_dir = (keys_dir or (resolved_home / "keys")).expanduser().resolve()
    receipt_files = sorted(resolved_chain_dir.rglob("receipts.jsonl"))
    public_key = load_public_key(resolved_keys_dir)

    chains: list[dict[str, Any]] = []
    all_claims: list[dict[str, Any]] = []
    for receipt_file in receipt_files:
        tokens = [
            line.strip()
            for line in receipt_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        claims = verify_chain(tokens, public_key, verify_expiry=verify_expiry)
        all_claims.extend(claims)
        trace_id = receipt_file.parent.name
        chains.append(_chain_report(trace_id=trace_id, receipt_file=receipt_file, claims=claims))

    dispatch_receipt_count = sum(len(chain["dispatches"]) for chain in chains)
    dispatch_launch_count = sum(chain["dispatch_launch_count"] for chain in chains)
    dispatch_observation_count = sum(chain["dispatch_observation_count"] for chain in chains)
    subagents_started = sum(int(chain["subagents_started"]) for chain in chains)
    subagents_stopped = sum(int(chain["subagents_stopped"]) for chain in chains)
    unattributed_tool_receipt_count = sum(int(chain["unattributed_tool_receipt_count"]) for chain in chains)
    ambiguous_tool_receipt_count = sum(int(chain["ambiguous_tool_receipt_count"]) for chain in chains)
    per_child_attribution = _merge_attribution_mode(
        [str(chain["per_child_attribution"]) for chain in chains if chain["subagents"] or chain["unattributed_tool_receipts"]]
    )
    return {
        "ok": True,
        "home": str(resolved_home),
        "chain_dir": str(resolved_chain_dir),
        "keys_dir": str(resolved_keys_dir),
        "chain_verification": {"ok": True, "verify_expiry": verify_expiry},
        "chain_count": len(chains),
        "receipt_count": len(all_claims),
        "totals": {
            "tools": _counter_dict([str(claim.get("tool", "")) for claim in all_claims]),
            "verdicts": _counter_dict([str(claim.get("verdict", "")) for claim in all_claims]),
            "action_classes": _counter_dict([str(claim.get("action_class", "")) for claim in all_claims]),
            "side_effect_classes": _counter_dict([str(claim.get("side_effect_class", "")) for claim in all_claims]),
            "dispatch_count": dispatch_launch_count,
            "dispatch_launch_count": dispatch_launch_count,
            "dispatch_observation_count": dispatch_observation_count,
            "dispatch_receipt_count": dispatch_receipt_count,
            "violation_count": sum(1 for claim in all_claims if claim.get("verdict") == "violation"),
            "subagents_started": subagents_started,
            "subagents_stopped": subagents_stopped,
            "unattributed_tool_receipt_count": unattributed_tool_receipt_count,
            "ambiguous_tool_receipt_count": ambiguous_tool_receipt_count,
        },
        "coverage": {
            "has_subagent_dispatch": dispatch_launch_count > 0,
            "subagent_launch_count": dispatch_launch_count,
            "subagents_started": subagents_started,
            "subagents_stopped": subagents_stopped,
            "per_child_attribution": per_child_attribution,
            "unattributed_tool_receipt_count": unattributed_tool_receipt_count,
            "ambiguous_tool_receipt_count": ambiguous_tool_receipt_count,
            "has_receipts_after_dispatch": any(
                chain["receipt_count_after_first_dispatch"] > 0 for chain in chains
            ),
            "attribution": (
                "exact when Claude Code hook payloads carry agent_id; derived when "
                "transcript_path or transcript tool_use_id binds one child; trace_only "
                "when Ardur can prove only parent-trace membership"
            ),
        },
        "chains": chains,
    }
