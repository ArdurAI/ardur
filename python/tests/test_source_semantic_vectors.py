from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


REPO_ROOT = Path(__file__).resolve().parents[2]
VECTOR_DIR = REPO_ROOT / "docs" / "specs" / "source-semantic-vectors"
SCHEMA_PATH = VECTOR_DIR / "host-adoption-governance-v0.1.schema.json"
VECTORS_PATH = VECTOR_DIR / "host-adoption-governance-v0.1.jsonl"
README_PATH = VECTOR_DIR / "README.md"

ALLOWED_EVIDENCE_CLASSES = {
    "policy_input",
    "session_context",
    "host_runtime_event",
    "cloud_agent_run",
    "deployment_context",
    "sdk_output_metadata",
    "unknown",
}

REQUIRED_VECTOR_CLASSES = {
    "codex-import-claude-code-context": {"policy_input", "session_context", "unknown"},
    "codex-deletion-retained-ardur-receipts": {"host_runtime_event", "policy_input", "unknown"},
    "claude-permission-grammar-nested-precedence": {"policy_input", "session_context", "unknown"},
    "claude-action-allowed-tools-parser": {"cloud_agent_run", "policy_input", "session_context", "unknown"},
    "gemini-at-file-placeholder-redaction": {"host_runtime_event", "session_context", "unknown"},
    "gemini-tools-core-config-migration": {"policy_input", "session_context", "unknown"},
    "openai-agents-sdk-0176-preapproval-custom-data": {
        "host_runtime_event",
        "policy_input",
        "sdk_output_metadata",
        "unknown",
    },
    "toolhive-mcpauthz-no-client-auth-remote-proxy": {"deployment_context", "policy_input", "unknown"},
}

REQUIRED_UNKNOWN_BOUNDARIES = {
    "raw_imported_chats",
    "provider_hidden_behavior",
    "credentials",
    "attachment_contents",
    "live_file_reads",
    "live_provider_behavior",
    "server_side_tool_calls",
    "runtime_kernel_side_effects",
    "live_enforcement",
    "action_runner_side_effects",
    "toolhive_mcp_enforcement",
}

FORBIDDEN_SHAREABLE_MARKERS = (
    str(REPO_ROOT),
    str(Path.home()),
    "/Users/",
    "/private/",
    "/home/",
    "sk-",
    "ghp_",
    "github_pat_",
    "BEGIN PRIVATE KEY",
    "raw imported chat",
    "raw file content",
    "raw-secret-value",
)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        parsed = json.loads(line)
        assert isinstance(parsed, dict), f"line {line_no} is not an object"
        rows.append(parsed)
    return rows


def test_host_adoption_source_semantic_vectors_validate_against_schema() -> None:
    """No-key host-adoption vectors must be schema-backed and class-explicit."""

    assert README_PATH.is_file()
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    rows = _read_jsonl(VECTORS_PATH)
    assert len(rows) >= len(REQUIRED_VECTOR_CLASSES)
    ids = [str(row["vector_id"]) for row in rows]
    assert len(ids) == len(set(ids))
    assert set(REQUIRED_VECTOR_CLASSES).issubset(ids)

    for row in rows:
        validator.validate(row)
        classes = set(row["evidence_classes"])
        assert classes.issubset(ALLOWED_EVIDENCE_CLASSES)
        assert "unknown" in classes
        assert row["source_confidence"] == "source_semantic_only"
        assert row["claim_boundary"].startswith("Source-semantic no-key vector only")
        assert any("live" in item.lower() for item in row["not_claimed"])

    by_id = {str(row["vector_id"]): row for row in rows}
    for vector_id, required_classes in REQUIRED_VECTOR_CLASSES.items():
        assert set(by_id[vector_id]["evidence_classes"]) == required_classes


def test_host_adoption_vectors_preserve_unknown_boundaries_and_redaction() -> None:
    """Persisted source-semantic artifacts must not leak local paths or broaden claims."""

    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in (README_PATH, SCHEMA_PATH, VECTORS_PATH)
    )
    for marker in FORBIDDEN_SHAREABLE_MARKERS:
        assert marker not in combined

    rows = _read_jsonl(VECTORS_PATH)
    all_unknowns = {str(boundary) for row in rows for boundary in row["unknown_boundaries"]}
    assert REQUIRED_UNKNOWN_BOUNDARIES.issubset(all_unknowns)

    toolhive = next(row for row in rows if row["vector_id"] == "toolhive-mcpauthz-no-client-auth-remote-proxy")
    assert toolhive["ardur_mapping"]["proof_role"] == "deployment_context_only"
    assert "runtime proof" in " ".join(toolhive["not_claimed"]).lower()

    gemini_path = next(row for row in rows if row["vector_id"] == "gemini-at-file-placeholder-redaction")
    assert gemini_path["ardur_mapping"]["path_material"] == "placeholder_and_digest_only"
    assert "live_file_reads" in gemini_path["unknown_boundaries"]

    codex_delete = next(row for row in rows if row["vector_id"] == "codex-deletion-retained-ardur-receipts")
    assert codex_delete["ardur_mapping"]["receipt_policy"] == "retain_ardur_receipts_after_host_delete_request"


def test_openai_agents_sdk_0176_vector_preserves_source_semantic_boundaries() -> None:
    """OpenAI Agents SDK 0.17.6 semantics must stay source-only and non-live."""

    rows = _read_jsonl(VECTORS_PATH)
    row = next(
        item for item in rows if item["vector_id"] == "openai-agents-sdk-0176-preapproval-custom-data"
    )

    assert row["source_family"] == "openai-agents-sdk"
    assert row["source_pin"]["kind"] == "package-release"
    assert "openai-agents==0.17.6" in row["source_pin"]["value"]
    assert "v0.17.6" in row["source_pin"]["value"]
    assert row["source_pin"]["source_snapshot_sha256"] == (
        "7d1aa2ea30e8706a87e4a5d4687a640876561dfcaf175158e0d2fe91f54dc6b3"
    )
    assert row["source_pin"]["source_matrix_sha256"] == (
        "c3a7b8bde12883798d61a218de6ae68da3165b72a18bf3f458a14758c9ac07a7"
    )
    assert row["source_pin"]["review_sha256"] == (
        "7639d3fae48357ab707765f38e977c5525d31eee52a1cfbbddc0212d9f14aac0"
    )

    signal = row["source_semantic_signal"]
    assert "ToolExecutionConfig.pre_approval_tool_input_guardrails" in signal
    assert "custom_data" in signal

    mapping = row["ardur_mapping"]
    assert mapping["proof_role"] == "source_semantic_conformance_only"
    assert mapping["approval_context"] == "pre_approval_guardrail_policy_context_only"
    assert mapping["custom_data_visibility"] == "sdk_only_not_model_replayed"
    assert mapping["custom_data_contract"] == "json_compatible_mapping_only"
    assert mapping["model_visible_output_material"] == "separate_from_sdk_only_custom_data"
    assert mapping["fixture_boundary"] == "does_not_change_openai_no_key_fixture_receipt_count"
    assert set(mapping["custom_data_paths"]) == {
        "function_tool",
        "mcp",
        "custom_tool",
        "computer_tool",
        "apply_patch_tool",
    }

    assert set(row["unknown_boundaries"]).issuperset(
        {
            "live_provider_behavior",
            "provider_hidden_behavior",
            "server_side_tool_calls",
            "runtime_kernel_side_effects",
            "live_enforcement",
        }
    )
    not_claimed = " ".join(row["not_claimed"]).lower()
    for phrase in (
        "live openai provider",
        "provider-hidden",
        "server-side tool-call",
        "runtime/kernel side-effect",
        "live enforcement",
    ):
        assert phrase in not_claimed
    assert "not prove live openai" in row["claim_boundary"].lower()
