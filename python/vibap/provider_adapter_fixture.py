"""No-key provider-adapter proof fixtures for provider and host semantic surfaces.

The fixture simulates provider-visible tool-dispatch or host-semantic boundaries
for OpenAI Agents SDK, Google ADK, and Claude Code project-context evidence,
evaluates mapped calls through Ardur's native policy backend, emits signed
execution receipts, and verifies the resulting receipt chain locally. It
deliberately does not call provider APIs or claim visibility into
provider-hidden reasoning, host-side RAG internals, or server-side tool
dispatch.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .denial import DenialReason
from .passport import generate_keypair, issue_passport, load_mission_file, verify_passport
from .policy_backend import compose_decisions, get_backend, timed_evaluate
from .proxy import Decision, PolicyEvent, _receipt_step_id
from .receipt import build_receipt, sign_receipt, verify_chain
from .shareable_redaction import path_aliases, redact_local_paths

CHAIN_FILENAME = "receipts.jsonl"
REPORT_FILENAME = "report.json"
PASSPORT_CLAIMS_FILENAME = "passport.claims.redacted.json"
HOOK_VERIFIER_ID = "ardur-provider-adapter-no-key-fixture"

NOT_CLAIMED = [
    "live provider API enforcement",
    "provider-hidden reasoning visibility",
    "server-side tool-call capture",
    "kernel/subprocess/network side-effect capture",
]

COVERAGE_GAPS = [
    "provider_hidden_reasoning",
    "provider_server_side_tool_calls",
    "live_provider_api_enforcement",
    "kernel_subprocess_network_side_effect_capture",
]

CLAUDE_PROJECT_CONTEXT_ADAPTER = "claude-code-projects"
CLAUDE_PROJECT_UNKNOWN_BOUNDARIES = (
    "provider_hidden_upload_internals",
    "provider_hidden_rag_internals",
    "sync_source_internals",
    "artifact_content_internals",
    "network_fetch_internals",
    "actual_provider_model_internals",
)
CLAUDE_PROJECT_METHODS = (
    "project_info",
    "project_read",
    "project_search",
    "project_write",
    "project_delete",
)
CLAUDE_REMOTE_TRIGGER_OUTPUT_VERSION_OBSERVED = {
    "2.1.175": False,
    "2.1.176": False,
    "2.1.177": False,
    "2.1.198": False,
}
CLAUDE_REMOTE_TRIGGER_OUTPUT_METADATA_FIELDS_BY_VERSION = {
    "2.1.198": ["capabilities", "stored.contract", "stored.capabilities"],
}


@dataclass(frozen=True)
class AdapterConfig:
    adapter_id: str
    display_name: str
    schema_slug: str
    visible_boundary: str
    sdk_surface: dict[str, Any]
    not_claimed: tuple[str, ...] = ()
    coverage_gaps: tuple[str, ...] = ()


ADAPTERS: dict[str, AdapterConfig] = {
    "openai-agents-sdk": AdapterConfig(
        adapter_id="openai-agents-sdk",
        display_name="OpenAI Agents SDK",
        schema_slug="openai_agents_sdk",
        visible_boundary="OpenAI Agents SDK function_tool dispatch fixture",
        sdk_surface={
            "package": "openai-agents",
            "tool_registration": "function_tool",
            "runner": "Runner.run fixture transcript",
            "model": "example-model-name-placeholder",
        },
    ),
    "google-adk": AdapterConfig(
        adapter_id="google-adk",
        display_name="Google ADK",
        schema_slug="google_adk",
        visible_boundary="Google ADK Python callable and BaseTool.run_async fixture",
        sdk_surface={
            "package": "google-adk",
            "tool_registration": "Python callable / FunctionTool",
            "agent": "LlmAgent fixture transcript",
            "model": "example-model-name-placeholder",
        },
    ),
    CLAUDE_PROJECT_CONTEXT_ADAPTER: AdapterConfig(
        adapter_id=CLAUDE_PROJECT_CONTEXT_ADAPTER,
        display_name="Claude Code project context",
        schema_slug="claude_code_projects",
        visible_boundary="Claude Code ProjectsInput and ProjectsOutput no-key semantic fixture",
        sdk_surface={
            "package": "@anthropic-ai/claude-code",
            "checked_versions": ["2.1.175", "2.1.176", "2.1.177", "2.1.198"],
            "project_methods": list(CLAUDE_PROJECT_METHODS),
            "source_file": "sdk-tools.d.ts",
            "model": "example-model-name-placeholder",
        },
        not_claimed=(
            "live Claude account/project mutation",
            "provider-side project upload capture",
            "provider-side RAG or sync-source inspection",
            "artifact-content or network-fetch internals visibility",
            "actual provider model attestation",
        ),
        coverage_gaps=CLAUDE_PROJECT_UNKNOWN_BOUNDARIES,
    ),
}

MAPPED_TOOLS: dict[str, dict[str, str]] = {
    "read_file": {
        "action_class": "read",
        "resource_family": "filesystem",
        "side_effect_class": "none",
        "content_class": "filesystem_path",
    },
    "write_file": {
        "action_class": "write",
        "resource_family": "filesystem",
        "side_effect_class": "internal_write",
        "content_class": "filesystem_path",
    },
    "summarize_text": {
        "action_class": "summarize",
        "resource_family": "computation",
        "side_effect_class": "none",
        "content_class": "text_snippet",
    },
    "project_info": {
        "action_class": "observe",
        "resource_family": "claude_project_context",
        "side_effect_class": "none",
        "content_class": "claude_project_context",
    },
    "project_read": {
        "action_class": "read",
        "resource_family": "claude_project_context",
        "side_effect_class": "none",
        "content_class": "claude_project_document",
    },
    "project_search": {
        "action_class": "query",
        "resource_family": "claude_project_context",
        "side_effect_class": "none",
        "content_class": "claude_project_rag_result",
    },
    "project_write": {
        "action_class": "write",
        "resource_family": "claude_project_context",
        "side_effect_class": "internal_write",
        "content_class": "claude_project_document",
    },
    "project_delete": {
        "action_class": "write",
        "resource_family": "claude_project_context",
        "side_effect_class": "state_change",
        "content_class": "claude_project_document",
    },
}


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest_payload(payload: Any) -> dict[str, str]:
    return {
        "alg": "sha-256",
        "canonicalization": "jcs-rfc8785",
        "value": hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest(),
    }


def _digest_file(path: Path) -> dict[str, str]:
    return {"alg": "sha-256", "value": hashlib.sha256(path.read_bytes()).hexdigest()}


def _digest_string(value: str, *, scope: str = "custom") -> dict[str, str]:
    return {
        "alg": "sha-256",
        "canonicalization": "none",
        "scope": scope,
        "value": hashlib.sha256(value.encode("utf-8")).hexdigest(),
    }


def _redact_local_path_value(value: str, *, roots: Mapping[str, str | Path | None]) -> dict[str, Any]:
    redacted = _redact_shareable(value, roots=roots)
    if not isinstance(redacted, str):
        redacted = "<LOCAL_PATH>"
    if redacted == value and value.startswith("/"):
        redacted = f"<LOCAL_PATH>/{Path(value).name}"
    return {
        "redacted_path": redacted,
        "path_sha256": _digest_string(value, scope="local_path"),
        "path_visibility": "redacted_local_path",
    }


def _redact_content_value(value: str) -> dict[str, Any]:
    return {
        "content_present": True,
        "content_sha256": _digest_string(value, scope="content"),
        "content_bytes": len(value.encode("utf-8")),
    }


def _sanitize_claude_project_value(value: Any, *, key: str | None, roots: Mapping[str, str | Path | None]) -> Any:
    if key in {"local_path", "local_file"} and isinstance(value, str):
        return _redact_local_path_value(value, roots=roots)
    if key == "content" and isinstance(value, str):
        return _redact_content_value(value)
    if key == "config" and isinstance(value, Mapping):
        return {
            "redacted": True,
            "config_sha256": _digest_payload(dict(value)),
            "config_visibility": "opaque_sync_config",
        }
    if isinstance(value, Mapping):
        return {
            str(child_key): _sanitize_claude_project_value(child_value, key=str(child_key), roots=roots)
            for child_key, child_value in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_claude_project_value(item, key=key, roots=roots) for item in value]
    return value


def normalize_claude_project_context_call(
    call: Mapping[str, Any],
    *,
    roots: Mapping[str, str | Path | None],
) -> dict[str, Any]:
    """Return a shareable Claude project-context call with local payloads redacted.

    The fixture models host-reported Claude project knowledge semantics only. It
    never carries raw local upload paths, local-file output paths, opaque sync
    config, or document content into receipts or shareable reports.
    """

    normalized = deepcopy(dict(call))
    raw_arguments = normalized.get("arguments")
    if not isinstance(raw_arguments, Mapping):
        return normalized
    arguments = deepcopy(dict(raw_arguments))
    event = arguments.get("host_semantic_event")
    if isinstance(event, Mapping):
        event_dict = deepcopy(dict(event))
        requested_input = event_dict.get("requested_input")
        if isinstance(requested_input, Mapping):
            requested = dict(requested_input)
            if requested.get("method") == "project_write" and "content" in requested and "local_path" in requested:
                raise ValueError("project_write.content and project_write.local_path are mutually exclusive")
        event_dict.setdefault("event_class", "host_semantic_event")
        event_dict.setdefault("evidence_class", ["policy_input", "session_context", "host_semantic_event"])
        event_dict.setdefault("unknown_boundaries", list(CLAUDE_PROJECT_UNKNOWN_BOUNDARIES))
        event_dict["requested_input"] = _sanitize_claude_project_value(
            event_dict.get("requested_input", {}),
            key=None,
            roots=roots,
        )
        event_dict["host_reported_output"] = _sanitize_claude_project_value(
            event_dict.get("host_reported_output", {}),
            key=None,
            roots=roots,
        )
        arguments["host_semantic_event"] = event_dict
    normalized["arguments"] = arguments
    return normalized


def _status_from_verdict(verdict: str) -> str:
    if verdict == "compliant":
        return "allow"
    if verdict == "insufficient_evidence":
        return "unknown"
    return "deny"


def _policy_decision_dicts(decisions: Sequence[Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in decisions:
        if hasattr(item, "to_dict"):
            result.append(dict(item.to_dict()))
        elif isinstance(item, Mapping):
            result.append(dict(item))
    return result


def _target_from_args(tool_name: str, args: Mapping[str, Any]) -> str:
    for key in ("path", "file_path", "filename", "target", "resource", "destination", "opaque_target"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return tool_name


def _map_tool_call(adapter: AdapterConfig, tool_name: str, raw_args: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    normalized = str(tool_name or "").strip()
    key = normalized.lower().replace("-", "_")
    target = _target_from_args(normalized, raw_args)
    if adapter.adapter_id == CLAUDE_PROJECT_CONTEXT_ADAPTER:
        base = {
            str(arg_key): arg_value
            for arg_key, arg_value in raw_args.items()
            if arg_key in {"method", "path", "query", "force"}
        }
    else:
        base = dict(raw_args)
    mapping = MAPPED_TOOLS.get(key)
    if mapping is None:
        return (
            {
                **base,
                "tool_name": normalized,
                "target": target,
                "action_class": "observe",
                "resource_family": "general",
                "content_class": "unknown_tool_invocation",
                "content_provenance": adapter.visible_boundary,
                "side_effect_class": "none",
                "visibility": "tool_boundary_only",
                "sensitivity": "unknown",
                "instruction_bearing": False,
            },
            "unknown",
        )
    return (
        {
            **base,
            "tool_name": normalized,
            "target": target,
            "action_class": mapping["action_class"],
            "resource_family": mapping["resource_family"],
            "content_class": mapping["content_class"],
            "content_provenance": adapter.visible_boundary,
            "side_effect_class": mapping["side_effect_class"],
            "visibility": "full" if mapping["resource_family"] == "filesystem" else "tool_boundary_only",
            "sensitivity": "unknown",
            "instruction_bearing": False,
        },
        "mapped",
    )


def _build_policy_event(
    *,
    adapter: AdapterConfig,
    claims: Mapping[str, Any],
    call_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    trace_id: str,
    decision: Decision = Decision.PERMIT,
    reason: str = "pending policy evaluation",
    denial_reason: DenialReason | None = None,
) -> PolicyEvent:
    timestamp = _utc_timestamp()
    step_id = _receipt_step_id(str(claims.get("jti", "")), timestamp, f"{adapter.schema_slug}:{tool_name}", arguments)
    return PolicyEvent(
        timestamp=timestamp,
        step_id=f"{step_id}:{adapter.schema_slug}:{call_id}",
        actor=str(claims.get("sub", "unknown")),
        verifier_id=HOOK_VERIFIER_ID,
        tool_name=tool_name,
        arguments=arguments,
        action_class=str(arguments["action_class"]),
        target=str(arguments["target"]),
        resource_family=str(arguments["resource_family"]),
        side_effect_class=str(arguments["side_effect_class"]),
        decision=decision,
        reason=reason,
        passport_jti=str(claims.get("jti", "")),
        trace_id=trace_id,
        denial_reason=denial_reason,
        budget_delta=None,
    )


def _evaluate_native_policy(event: PolicyEvent, claims: Mapping[str, Any]) -> tuple[str, list[Any]]:
    backend = get_backend("native")
    decision = timed_evaluate(
        backend,
        tool_name=event.tool_name,
        arguments=event.arguments,
        principal=event.actor,
        target=event.target,
        context={
            "passport": dict(claims),
            "session": {},
            "policy_metadata": {
                "action_class": event.action_class,
                "resource_family": event.resource_family,
                "side_effect_class": event.side_effect_class,
            },
        },
        policy_spec={},
    )
    decisions = [decision]
    final, _denier = compose_decisions(decisions)
    return final, decisions


def _set_receipt_metadata(receipt_obj: Any, arguments: Mapping[str, Any], adapter_key: str, metadata: Mapping[str, Any]) -> None:
    content_class = arguments.get("content_class")
    if content_class:
        receipt_obj.content_class = str(content_class)
    provenance = arguments.get("content_provenance")
    if provenance:
        receipt_obj.content_provenance = {"source": str(provenance)}
    sensitivity = arguments.get("sensitivity")
    if sensitivity:
        receipt_obj.sensitivity = str(sensitivity)
    instruction_bearing = arguments.get("instruction_bearing")
    if instruction_bearing is not None:
        receipt_obj.instruction_bearing = bool(instruction_bearing)
    receipt_obj.measurements = {adapter_key: dict(metadata)}


def _emit_receipt(
    *,
    private_key: Any,
    chain_tokens: list[str],
    chain_path: Path,
    decision_enum: Decision,
    event: PolicyEvent,
    reason: str,
    adapter: AdapterConfig,
    arguments: Mapping[str, Any],
    measurements: Mapping[str, Any],
    policy_decisions: list[dict[str, Any]] | None = None,
) -> Any:
    parent_hash = hashlib.sha256(chain_tokens[-1].encode("ascii")).hexdigest() if chain_tokens else None
    safe_policy_decisions = None
    if policy_decisions is not None:
        safe_policy_decisions = []
        for item in policy_decisions:
            reasons = item.get("reasons")
            reason_text = item.get("reason")
            if not reason_text and isinstance(reasons, list):
                reason_text = "; ".join(str(entry) for entry in reasons) or None
            safe_policy_decisions.append(
                {
                    "backend": str(item.get("backend", "unknown")),
                    "decision": str(item.get("decision", "Abstain")),
                    "reason": str(reason_text) if reason_text else None,
                }
            )
    receipt_obj = build_receipt(
        decision_enum,
        event,
        parent_hash,
        policy_decisions=safe_policy_decisions,
        reason=reason,
    )
    metadata = dict(measurements)
    metadata["verdict"] = receipt_obj.verdict
    metadata["receipt_id"] = receipt_obj.receipt_id
    _set_receipt_metadata(receipt_obj, arguments, adapter.schema_slug, metadata)
    signed = sign_receipt(receipt_obj, private_key)
    chain_tokens.append(signed)
    chain_path.write_text("\n".join(chain_tokens) + "\n", encoding="utf-8")
    from .transparency import queue_receipt_anchor_best_effort

    queue_receipt_anchor_best_effort(signed, chain_path)
    return receipt_obj


def _fixture_calls(adapter: AdapterConfig, *, output: Path | None = None) -> list[dict[str, Any]]:
    if adapter.adapter_id == "openai-agents-sdk":
        surface = {
            "dispatch_kind": "function_tool",
            "decorator": "function_tool",
            "runner_event": "Runner.run tool_call",
            "model": "example-model-name-placeholder",
        }
    elif adapter.adapter_id == "google-adk":
        surface = {
            "dispatch_kind": "adk_function_tool",
            "tool_boundary": "BaseTool.run_async",
            "agent_type": "LlmAgent",
            "model": "example-model-name-placeholder",
        }
    else:
        output_root = output or Path(".")
        local_upload = output_root / "host-local" / "project-upload-source.md"
        local_read = output_root / "host-local" / "project-read-result.md"
        surface = {
            "dispatch_kind": "claude_projects_tool",
            "tool_boundary": "ProjectsInput / ProjectsOutput",
            "package": "@anthropic-ai/claude-code",
            "checked_versions": ["2.1.175", "2.1.176", "2.1.177"],
            "model": "example-model-name-placeholder",
            "resolvedModel": "example-resolved-model-placeholder",
        }

        def project_call(
            call_id: str,
            method: str,
            requested_input: Mapping[str, Any],
            host_reported_output: Mapping[str, Any],
        ) -> dict[str, Any]:
            return {
                "call_id": call_id,
                "tool_name": method,
                "arguments": {
                    "method": method,
                    "path": str(requested_input.get("path", "claude/project-context")),
                    "query": requested_input.get("query"),
                    "force": requested_input.get("force"),
                    "host_semantic_event": {
                        "method": method,
                        "requested_input": dict(requested_input),
                        "host_reported_output": dict(host_reported_output),
                    },
                },
                "provider_visible": surface,
            }

        return [
            project_call(
                "claude-project-info",
                "project_info",
                {"method": "project_info"},
                {
                    "method": "project_info",
                    "name": "No-key fixture project",
                    "description": "Local Claude project-context fixture; no provider account used.",
                    "instructions": "Treat project knowledge as host-reported context, not Ardur-observed truth.",
                    "files": [
                        {"path": "claude/instructions.md", "file_kind": "instruction", "created_at": "2026-06-13T00:00:00Z"},
                        {"path": "claude/customer-notes.md", "file_kind": "document", "created_at": "2026-06-13T00:00:00Z"},
                    ],
                    "sync_sources": [
                        {
                            "type": "git",
                            "config": {
                                "repo": "example/private-project-context",
                                "branch": "main",
                                "opaque_material": "raw-config-value-that-must-not-leak",
                            },
                        }
                    ],
                    "knowledge_budget": {"used_bytes": 2048, "limit_bytes": 100000},
                    "rag_state": "host_reported_unknown_to_ardur",
                },
            ),
            project_call(
                "claude-project-read",
                "project_read",
                {"method": "project_read", "path": "claude/customer-notes.md"},
                {
                    "method": "project_read",
                    "path": "claude/customer-notes.md",
                    "file_kind": "document",
                    "content": "host-reported project note body",
                    "local_file": str(local_read),
                    "created_at": "2026-06-13T00:00:00Z",
                },
            ),
            project_call(
                "claude-project-search",
                "project_search",
                {"method": "project_search", "query": "customer deployment context", "n": 3},
                {
                    "method": "project_search",
                    "query": "customer deployment context",
                    "rag_state": "host_reported_unknown_to_ardur",
                    "hits": [
                        {"path": "claude/customer-notes.md", "score": 0.82, "file_kind": "document"},
                    ],
                },
            ),
            project_call(
                "claude-project-write-content",
                "project_write",
                {
                    "method": "project_write",
                    "path": "claude/inline-context.md",
                    "content": "inline host-supplied project context",
                },
                {
                    "method": "project_write",
                    "path": "claude/inline-context.md",
                    "doc_uuid": "doc-inline-placeholder",
                    "replaced": False,
                    "rag_state": "host_reported_unknown_to_ardur",
                },
            ),
            project_call(
                "claude-project-write-local-path",
                "project_write",
                {
                    "method": "project_write",
                    "path": "claude/uploaded-context.md",
                    "local_path": str(local_upload),
                    "force": True,
                },
                {
                    "method": "project_write",
                    "path": "claude/uploaded-context.md",
                    "doc_uuid": "doc-upload-placeholder",
                    "replaced": True,
                    "rag_state": "host_reported_unknown_to_ardur",
                },
            ),
            project_call(
                "claude-project-delete",
                "project_delete",
                {"method": "project_delete", "path": "claude/old-context.md"},
                {"method": "project_delete", "path": "claude/old-context.md", "deleted": True},
            ),
        ]
    return [
        {
            "call_id": "call-allow-read",
            "tool_name": "read_file",
            "arguments": {"path": "workspace/customer-notes.md"},
            "provider_visible": surface,
        },
        {
            "call_id": "call-deny-write",
            "tool_name": "write_file",
            "arguments": {"path": "workspace/customer-notes.md", "content": "draft overwrite"},
            "provider_visible": surface,
        },
        {
            "call_id": "call-unknown-opaque",
            "tool_name": "provider_opaque_tool",
            "arguments": {"opaque_target": "provider-managed-state", "schema": "not-enough-visible-fields"},
            "provider_visible": surface,
        },
    ]


def _call_measurements(
    *,
    adapter: AdapterConfig,
    call: Mapping[str, Any],
    arguments: Mapping[str, Any],
    mapping_confidence: str,
    trace_id: str,
    status: str | None = None,
    receipt_id: str | None = None,
) -> dict[str, Any]:
    unknown_boundaries = list(COVERAGE_GAPS) + list(adapter.coverage_gaps)
    if mapping_confidence == "unknown":
        unknown_boundaries.append("unmapped_provider_tool_schema")
    result = {
        "schema_version": f"ardur.{adapter.schema_slug}.no_key_fixture.measurements.v0.1",
        "adapter_id": adapter.adapter_id,
        "visible_boundary": adapter.visible_boundary,
        "sdk_surface": adapter.sdk_surface,
        "provider_visible_call": {
            "call_id": str(call["call_id"]),
            "tool_name": str(call["tool_name"]),
            "arguments_digest": _digest_payload(dict(call.get("arguments", {}))),
            "provider_visible": dict(call.get("provider_visible", {})),
        },
        "mapped_policy_tool": str(arguments.get("tool_name", call["tool_name"])),
        "mapping_confidence": mapping_confidence,
        "trace_id": trace_id,
        "status": status,
        "receipt_id": receipt_id,
        "unknown_boundaries": unknown_boundaries,
        "claim_boundary": "visible local provider-adapter tool-dispatch fixture evidence only",
    }
    call_arguments = call.get("arguments", {})
    if isinstance(call_arguments, Mapping):
        host_semantic_event = call_arguments.get("host_semantic_event")
        if isinstance(host_semantic_event, Mapping):
            result["host_semantic_event"] = dict(host_semantic_event)
            result["claim_boundary"] = "host-reported Claude project-context semantics from no-key local fixture only"
    return result


def _result_with_host_semantic_event(result: dict[str, Any], call: Mapping[str, Any]) -> dict[str, Any]:
    call_arguments = call.get("arguments", {})
    if isinstance(call_arguments, Mapping):
        host_semantic_event = call_arguments.get("host_semantic_event")
        if isinstance(host_semantic_event, Mapping):
            result["host_semantic_event"] = dict(host_semantic_event)
    return result


def _handle_call(
    *,
    adapter: AdapterConfig,
    call: Mapping[str, Any],
    claims: Mapping[str, Any],
    private_key: Any,
    chain_tokens: list[str],
    chain_path: Path,
    trace_id: str,
    roots: Mapping[str, str | Path | None],
) -> dict[str, Any]:
    safe_call = (
        normalize_claude_project_context_call(call, roots=roots)
        if adapter.adapter_id == CLAUDE_PROJECT_CONTEXT_ADAPTER
        else dict(call)
    )
    tool_name = str(safe_call["tool_name"])
    arguments, mapping_confidence = _map_tool_call(adapter, tool_name, dict(safe_call.get("arguments", {})))
    base_event = _build_policy_event(
        adapter=adapter,
        claims=claims,
        call_id=str(safe_call["call_id"]),
        tool_name=tool_name,
        arguments=arguments,
        trace_id=trace_id,
    )
    measurements = _call_measurements(
        adapter=adapter,
        call=safe_call,
        arguments=arguments,
        mapping_confidence=mapping_confidence,
        trace_id=trace_id,
    )

    if mapping_confidence == "unknown":
        reason = "insufficient evidence: unmapped provider tool schema at visible dispatch boundary"
        unknown_event = _build_policy_event(
            adapter=adapter,
            claims=claims,
            call_id=str(safe_call["call_id"]),
            tool_name=tool_name,
            arguments=arguments,
            trace_id=trace_id,
            decision=Decision.INSUFFICIENT_EVIDENCE,
            reason=reason,
            denial_reason=DenialReason.TELEMETRY_MISSING,
        )
        receipt_obj = _emit_receipt(
            private_key=private_key,
            chain_tokens=chain_tokens,
            chain_path=chain_path,
            decision_enum=Decision.INSUFFICIENT_EVIDENCE,
            event=unknown_event,
            reason=reason,
            adapter=adapter,
            arguments=arguments,
            measurements={**measurements, "status": "unknown"},
            policy_decisions=[
                {
                    "backend": "adapter_mapping",
                    "label": adapter.visible_boundary,
                    "decision": "Abstain",
                    "reasons": ["unmapped provider-visible tool schema"],
                    "eval_ms": 0.0,
                }
            ],
        )
        return _result_with_host_semantic_event(
            {
                "call_id": str(safe_call["call_id"]),
                "tool_name": tool_name,
                "status": "unknown",
                "block": True,
                "mapping_confidence": mapping_confidence,
                "receipt_id": receipt_obj.receipt_id,
                "reason": reason,
            },
            safe_call,
        )

    final, decisions = _evaluate_native_policy(base_event, claims)
    decision_dicts = _policy_decision_dicts(decisions)
    if final == "Deny":
        denier = next((d for d in decisions if getattr(d, "decision", None) == "Deny"), None)
        reasons = list(getattr(denier, "reasons", ()) or ["denied by composed policy"])
        reason = "; ".join(str(item) for item in reasons)
        deny_event = _build_policy_event(
            adapter=adapter,
            claims=claims,
            call_id=str(safe_call["call_id"]),
            tool_name=tool_name,
            arguments=arguments,
            trace_id=trace_id,
            decision=Decision.DENY,
            reason=reason,
            denial_reason=DenialReason.POLICY_DENIED,
        )
        receipt_obj = _emit_receipt(
            private_key=private_key,
            chain_tokens=chain_tokens,
            chain_path=chain_path,
            decision_enum=Decision.DENY,
            event=deny_event,
            reason=reason,
            adapter=adapter,
            arguments=arguments,
            measurements={**measurements, "status": "deny"},
            policy_decisions=decision_dicts,
        )
        return _result_with_host_semantic_event(
            {
                "call_id": str(safe_call["call_id"]),
                "tool_name": tool_name,
                "status": "deny",
                "block": True,
                "mapping_confidence": mapping_confidence,
                "receipt_id": receipt_obj.receipt_id,
                "reason": reason,
            },
            safe_call,
        )

    base_event.policy_decisions = decision_dicts
    receipt_obj = _emit_receipt(
        private_key=private_key,
        chain_tokens=chain_tokens,
        chain_path=chain_path,
        decision_enum=Decision.PERMIT,
        event=base_event,
        reason="allowed by composed native policy",
        adapter=adapter,
        arguments=arguments,
        measurements={**measurements, "status": "allow"},
        policy_decisions=decision_dicts,
    )
    return _result_with_host_semantic_event(
        {
            "call_id": str(safe_call["call_id"]),
            "tool_name": tool_name,
            "status": "allow",
            "block": False,
            "mapping_confidence": mapping_confidence,
            "receipt_id": receipt_obj.receipt_id,
            "reason": "allowed by composed native policy",
        },
        safe_call,
    )


def _root_pairs(mapping: Mapping[str, str | Path | None]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for label, path in mapping.items():
        placeholder = f"<{label}>"
        for alias in path_aliases(path):
            pairs.append((alias, placeholder))
    return sorted(set(pairs), key=lambda item: len(item[0]), reverse=True)


def _redact_shareable(value: Any, *, roots: Mapping[str, str | Path | None]) -> Any:
    return redact_local_paths(value, root_pairs=_root_pairs(roots))


def run_fixture(*, adapter_id: str, out_dir: Path, mission_path: Path, verify_expiry: bool = False) -> dict[str, Any]:
    adapter = ADAPTERS[adapter_id]
    output = out_dir.expanduser().resolve(strict=False)
    mission_file = mission_path.expanduser().resolve(strict=False)
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        output.chmod(0o700)
    except OSError:
        # Best-effort fixture-directory hardening; mkdir(mode=0o700) already
        # created new directories privately, but some existing or unusual
        # filesystems can reject chmod after a successful mkdir.
        pass
    keys_dir = output / "keys"
    chain_path = output / CHAIN_FILENAME
    report_path = output / REPORT_FILENAME
    passport_claims_path = output / PASSPORT_CLAIMS_FILENAME

    mission, ttl_s, mission_payload = load_mission_file(mission_file)
    private_key, public_key = generate_keypair(keys_dir=keys_dir)
    passport_token = issue_passport(mission, private_key, ttl_s=ttl_s or mission.max_duration_s)
    passport_claims = verify_passport(passport_token, public_key)

    trace_id = f"{adapter.adapter_id}:no-key-fixture"
    chain_tokens: list[str] = []
    roots = {
        "OUTPUT_DIR": output,
        "MISSION_TEMPLATE": mission_file,
        "ARDUR_KEYS": keys_dir,
    }
    call_results = [
        _handle_call(
            adapter=adapter,
            call=call,
            claims=passport_claims,
            private_key=private_key,
            chain_tokens=chain_tokens,
            chain_path=chain_path,
            trace_id=trace_id,
            roots=roots,
        )
        for call in _fixture_calls(adapter, output=output)
    ]

    verified_claims = verify_chain(list(chain_tokens), public_key, verify_expiry=verify_expiry)
    counts = {"allow": 0, "deny": 0, "unknown": 0}
    coverage_gaps: set[str] = set()
    for claims in verified_claims:
        counts[_status_from_verdict(str(claims.get("verdict", "")))] += 1
        measurements = claims.get("measurements", {})
        adapter_measurements = measurements.get(adapter.schema_slug, {}) if isinstance(measurements, Mapping) else {}
        if isinstance(adapter_measurements, Mapping):
            for gap in adapter_measurements.get("unknown_boundaries", []) or []:
                coverage_gaps.add(str(gap))

    passport_public = {
        key: value
        for key, value in passport_claims.items()
        if key not in {"cnf", "parent_token_hash", "delegation_chain"}
    }
    passport_claims_path.write_text(
        json.dumps(_redact_shareable(passport_public, roots=roots), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    report = {
        "schema_version": f"ardur.{adapter.schema_slug}.no_key_fixture_report.v0.1",
        "generated_at": _utc_timestamp(),
        "adapter": {
            "id": adapter.adapter_id,
            "name": adapter.display_name,
            "visible_boundary": adapter.visible_boundary,
            "sdk_surface": adapter.sdk_surface,
        },
        "mission": {
            "template_path": str(mission_file),
            "template_sha256": _digest_file(mission_file),
            "payload_digest": _digest_payload(mission_payload),
            "agent_id": mission.agent_id,
            "mission": mission.mission,
            "allowed_tools": mission.allowed_tools,
            "forbidden_tools": mission.forbidden_tools,
            "resource_scope": mission.resource_scope,
        },
        "passport": {
            "issued_from_checked_in_mission_template": True,
            "claims_path": str(passport_claims_path),
            "mission_id": passport_claims.get("mission_id"),
            "jti": passport_claims.get("jti"),
        },
        "artifacts": {
            "output_dir": str(output),
            "receipt_chain": str(chain_path),
            "report": str(report_path),
            "passport_claims": str(passport_claims_path),
        },
        "receipt_chain_verified": True,
        "receipt_count": len(verified_claims),
        "policy_verdict_counts": counts,
        "visible_tool_calls": call_results,
        "coverage_gaps": sorted(coverage_gaps),
        "not_claimed": list(NOT_CLAIMED) + list(adapter.not_claimed),
        "verification": {
            "chain_file": str(chain_path),
            "valid": True,
            "receipt_count": len(verified_claims),
            "verify_expiry": verify_expiry,
        },
        "receipts": verified_claims,
    }
    if adapter.adapter_id == CLAUDE_PROJECT_CONTEXT_ADAPTER:
        report["claude_project_context"] = {
            "schema_version": "ardur.claude_code_projects.project_context.v0.1",
            "host_semantic_methods": list(CLAUDE_PROJECT_METHODS),
            "model_provenance": {
                "requested_model": "example-model-name-placeholder",
                "resolvedModel": "example-resolved-model-placeholder",
                "actual_provider_model": "unknown",
                "fork_subagent": {
                    "subagent_type": "fork",
                    "requested_override": "example-ignored-model-override-placeholder",
                    "override_honored": False,
                    "effective_model_source": "inherited_parent_model",
                    "boundary": "host SDK type/comment surface only; live provider execution remains unknown",
                },
            },
            "source_boundaries": {
                "artifact_output": {
                    "source_type": "ArtifactOutput",
                    "version": "artifact-version-placeholder",
                    "boundary": "host-reported artifact version only",
                },
                "web_fetch_output": {
                    "source_type": "WebFetchOutput",
                    "artifactRead": {
                        "slug": "project-context-artifact-placeholder",
                        "ver": "artifact-version-placeholder",
                    },
                    "boundary": "does not prove artifact content or network-fetch internals",
                },
                "remote_trigger_output": {
                    "fields_observed": ["status", "json", "summary"],
                    "version_field_observed_by_version": dict(CLAUDE_REMOTE_TRIGGER_OUTPUT_VERSION_OBSERVED),
                    "metadata_fields_observed_by_version": dict(
                        CLAUDE_REMOTE_TRIGGER_OUTPUT_METADATA_FIELDS_BY_VERSION
                    ),
                    "boundary": "2.1.175/2.1.176/2.1.177 source surfaces did not expose a version field here",
                    "source_metadata_boundary": (
                        "2.1.198 source surface exposes capabilities and stored contract metadata only; "
                        "no live remote-trigger execution is claimed"
                    ),
                },
            },
            "unknown_boundaries": list(CLAUDE_PROJECT_UNKNOWN_BOUNDARIES),
            "claim_boundary": "no-key/local fixture for Claude project-context source semantics; no live Claude claim",
        }
    redacted_report = _redact_shareable(report, roots=roots)
    report_path.write_text(json.dumps(redacted_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return redacted_report


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a no-key Ardur provider-adapter proof fixture")
    parser.add_argument("--adapter", choices=sorted(ADAPTERS), required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--mission", type=Path, required=True)
    parser.add_argument("--verify-expiry", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None, *, adapter_id: str | None = None) -> int:
    args = parse_args(argv)
    selected_adapter = adapter_id or args.adapter
    if selected_adapter != args.adapter:
        raise ValueError(f"adapter mismatch: wrapper requested {selected_adapter!r}, argv requested {args.adapter!r}")
    report = run_fixture(
        adapter_id=selected_adapter,
        out_dir=args.out_dir,
        mission_path=args.mission,
        verify_expiry=args.verify_expiry,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI wrapper
    raise SystemExit(main(sys.argv[1:]))
