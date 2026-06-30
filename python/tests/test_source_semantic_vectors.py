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
    "codex-142-rollout-budget-multiagent-websearch-time": {
        "policy_input",
        "session_context",
        "host_runtime_event",
        "unknown",
    },
    "codex-1422-mcp-tool-search-proxy-context": {
        "policy_input",
        "session_context",
        "deployment_context",
        "unknown",
    },
    "codex-action-user-sandbox-policy-context": {
        "cloud_agent_run",
        "policy_input",
        "session_context",
        "deployment_context",
        "unknown",
    },
    "claude-permission-grammar-nested-precedence": {"policy_input", "session_context", "unknown"},
    "claude-code-mcp-directory-resource-listing-v2186": {
        "host_runtime_event",
        "session_context",
        "deployment_context",
        "unknown",
    },
    "claude-code-glob-count-notebook-old-source-v2191": {
        "host_runtime_event",
        "sdk_output_metadata",
        "unknown",
    },
    "claude-code-watchsource-websocket-stream-v2195": {
        "policy_input",
        "session_context",
        "host_runtime_event",
        "unknown",
    },
    "claude-code-reportfindings-review-output-v2196": {
        "cloud_agent_run",
        "host_runtime_event",
        "sdk_output_metadata",
        "unknown",
    },
    "claude-action-allowed-tools-parser": {"cloud_agent_run", "policy_input", "session_context", "unknown"},
    "claude-action-token-cleanup-timeout-best-effort": {
        "cloud_agent_run",
        "session_context",
        "deployment_context",
        "unknown",
    },
    "claude-action-actor-plugin-policy-context": {
        "cloud_agent_run",
        "policy_input",
        "session_context",
        "deployment_context",
        "unknown",
    },
    "gemini-at-file-placeholder-redaction": {"host_runtime_event", "session_context", "unknown"},
    "gemini-tools-core-config-migration": {"policy_input", "session_context", "unknown"},
    "gemini-cli-tool-output-trust-governance-v0490": {
        "policy_input",
        "session_context",
        "host_runtime_event",
        "deployment_context",
        "sdk_output_metadata",
        "unknown",
    },
    "openai-agents-sdk-0176-preapproval-custom-data": {
        "host_runtime_event",
        "policy_input",
        "sdk_output_metadata",
        "unknown",
    },
    "openai-agents-sdk-0177-streaming-output-approval-sandbox": {
        "host_runtime_event",
        "policy_input",
        "session_context",
        "sdk_output_metadata",
        "unknown",
    },
    "toolhive-mcpauthz-no-client-auth-remote-proxy": {"deployment_context", "policy_input", "unknown"},
    "toolhive-0301-network-authz-obo-events": {
        "deployment_context",
        "policy_input",
        "session_context",
        "host_runtime_event",
        "unknown",
    },
    "toolhive-0310-oidc-vmcp-authz-chain-governance": {
        "deployment_context",
        "policy_input",
        "session_context",
        "host_runtime_event",
        "unknown",
    },
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


def test_claude_action_token_cleanup_vector_preserves_source_only_boundaries() -> None:
    """Claude Code Action token cleanup semantics must stay no-key and non-live."""

    rows = _read_jsonl(VECTORS_PATH)
    row = next(
        item
        for item in rows
        if item["vector_id"] == "claude-action-token-cleanup-timeout-best-effort"
    )

    assert row["source_family"] == "claude-code-action"
    assert row["source_pin"]["kind"] == "action-manifest-blob"
    assert "b18daa77b5805daf4872269eaa6c74a07c3d8236" in row["source_pin"]["value"]
    assert "f48353f08afa8cfd0c19a0727e1b27574f6a6f5b" in row["source_pin"]["value"]
    assert "87ca609725e2a8dbbffa82c3610b6ff741d7fcabf54c74d69a7a11c0123bdbde" in (
        row["source_pin"]["value"]
    )
    assert row["source_pin"]["source_snapshot_sha256"] == (
        "ad35c62e9c295b49c27510a494ed37973865641b87fc226a97eaefc8cc5492cb"
    )
    assert row["source_pin"]["source_matrix_sha256"] == (
        "605235355115e21676cd2695aabf87d89a4748479a7be5336f4df0fbae2f0476"
    )
    assert row["source_pin"]["review_sha256"] == (
        "f0efe920244a37ac3ffabe3926d68ecb4c20cc3149678db8874daa92fff6757c"
    )

    signal = row["source_semantic_signal"]
    for phrase in (
        "GitHub installation-token cleanup",
        "--connect-timeout 5",
        "--max-time 10",
        "${GITHUB_API_URL:-https://api.github.com}/installation/token",
        "best-effort via || true",
    ):
        assert phrase in signal

    assert set(row["evidence_classes"]) == REQUIRED_VECTOR_CLASSES[
        "claude-action-token-cleanup-timeout-best-effort"
    ]

    mapping = row["ardur_mapping"]
    assert mapping["proof_role"] == "source_semantic_cloud_agent_cleanup_context"
    assert mapping["cloud_cleanup_surface"] == "github_installation_token_delete_manifest_step"
    assert mapping["timeout_policy"] == "curl_connect_timeout_5_and_max_time_10"
    assert mapping["failure_semantics"] == "best_effort_delete_failure_ignored_via_or_true"
    assert mapping["token_material"] == "placeholder_and_digest_only_no_token_values"
    assert mapping["previous_action_yml_blob"] == "b18daa77b5805daf4872269eaa6c74a07c3d8236"
    assert mapping["previous_action_yml_sha256"] == (
        "2763fabf777e37a40bf06cc93b544dfe12d7d1144a450d6331a4a009f151b501"
    )
    assert mapping["current_action_yml_blob"] == "f48353f08afa8cfd0c19a0727e1b27574f6a6f5b"
    assert mapping["current_action_yml_sha256"] == (
        "87ca609725e2a8dbbffa82c3610b6ff741d7fcabf54c74d69a7a11c0123bdbde"
    )
    assert mapping["focused_probe_sha256"] == (
        "d4b7945aec4f9ee7b92462316de9a98ab8fc7f137960f3df4222bfc5e67e69bf"
    )
    assert mapping["source_index_sha256"] == (
        "ea26c3607f4d282547dc6f09e166d6467d8b86200b91975f8028682fef2a8e08"
    )
    assert mapping["matrix_review_boundary"] == "no_live_claude_action_or_token_revocation_validation"

    serialized = json.dumps(row, sort_keys=True)
    for forbidden in ("Bearer", "github_pat_", "raw-secret-value"):
        assert forbidden not in serialized

    assert set(row["unknown_boundaries"]).issuperset(
        {
            "live_claude_action_execution",
            "actual_github_token_deletion",
            "actual_token_revocation",
            "provider_hidden_behavior",
            "server_side_actions",
            "workflow_network_behavior",
            "token_value_handling",
            "retry_backoff_behavior_beyond_manifest",
            "runtime_kernel_side_effects",
            "live_policy_enforcement",
            "public_readiness",
            "growth_proof",
            "action_metadata_trust_root",
            "credentials",
        }
    )
    not_claimed = " ".join(row["not_claimed"]).lower()
    for phrase in (
        "no live claude code action",
        "actual github token deletion",
        "token revocation",
        "provider-hidden/server-side",
        "workflow network",
        "runtime/kernel",
        "live policy enforcement",
        "public readiness",
        "growth proof",
        "ardur trust root",
        "credential or token value",
    ):
        assert phrase in not_claimed
    claim_boundary = row["claim_boundary"].lower()
    assert "does not prove live claude code action" in claim_boundary
    assert "actual github token deletion/revocation" in claim_boundary
    assert "provider-hidden/server-side" in claim_boundary
    assert "workflow network behavior" in claim_boundary
    assert "runtime/kernel side effects" in claim_boundary
    assert "public readiness/growth proof" in claim_boundary
    assert "ardur trust root" in claim_boundary
    assert "credential/token handling" in claim_boundary


def test_action_manifest_actor_plugin_policy_vectors_preserve_source_boundaries() -> None:
    """Action manifest actor/plugin/user policy context must stay no-key and non-live."""

    rows = _read_jsonl(VECTORS_PATH)
    by_id = {str(row["vector_id"]): row for row in rows}
    common_unknowns = {
        "live_github_action_execution",
        "actual_actor_identity",
        "permission_enforcement",
        "repository_write_permission_state",
        "token_values",
        "credential_values",
        "workflow_secret_values",
        "network_side_effects",
        "provider_hidden_behavior",
        "server_side_actions",
        "runtime_kernel_side_effects",
        "action_runner_side_effects",
        "public_readiness",
        "growth_proof",
        "action_metadata_trust_root",
    }
    expected = {
        "claude-action-actor-plugin-policy-context": {
            "source_family": "claude-code-action",
            "blob": "f48353f08afa8cfd0c19a0727e1b27574f6a6f5b",
            "content_sha256": "87ca609725e2a8dbbffa82c3610b6ff741d7fcabf54c74d69a7a11c0123bdbde",
            "proof_role": "source_semantic_cloud_action_policy_context",
            "terms": {
                "allowed_bots",
                "allowed_non_write_users",
                "include_comments_by_actor",
                "exclude_comments_by_actor",
                "trigger_phrase",
                "assignee_trigger",
                "label_trigger",
                "plugins",
                "plugin_marketplaces",
                "path_to_claude_code_executable",
                "path_to_bun_executable",
                "execution_file",
                "branch_name",
                "structured_output",
                "session_id",
                "output-boundary context",
            },
            "unknowns": {
                "live_claude_action_execution",
                "actual_comment_author_identity",
                "plugin_marketplace_fetch_contents",
                "plugin_execution",
            },
            "not_claimed_phrases": {
                "no live github action",
                "claude code action",
                "comment-author identity",
                "plugin marketplace",
                "plugin execution",
                "trust root",
            },
            "boundary_phrases": {
                "does not prove live claude code action",
                "plugin marketplace contents/execution",
                "action metadata as ardur trust root",
            },
        },
        "codex-action-user-sandbox-policy-context": {
            "source_family": "codex",
            "blob": "da0cef2e1b64267612b860993cae3680fff08dd1",
            "content_sha256": "100645601a99d1c432997b3f656d4dba11b7af66e79e269c5d7fac38ed4c3a66",
            "proof_role": "source_semantic_codex_action_policy_context",
            "terms": {
                "codex-user",
                "allow-users",
                "allow-bots",
                "allow-bot-users",
                "sandbox",
                "safety-strategy",
                "output-schema",
                "output-schema-file",
                "codex-home",
                "working-directory",
                "responses-api-endpoint",
                "prompt",
                "prompt-file",
                "output-file",
                "final-message",
                "output-boundary context",
            },
            "unknowns": {
                "live_codex_action_execution",
                "live_sandbox_enforcement",
                "live_output_schema_validation",
                "universal_cli_capture",
            },
            "not_claimed_phrases": {
                "no live github action",
                "codex action",
                "sandbox enforcement",
                "output-schema validation",
                "universal cli",
                "trust root",
            },
            "boundary_phrases": {
                "does not prove live codex action",
                "sandbox or output-schema enforcement",
                "package/release readiness",
                "action metadata as ardur trust root",
            },
        },
    }

    for vector_id, expected_values in expected.items():
        row = by_id[vector_id]
        assert row["source_family"] == expected_values["source_family"]
        assert row["source_pin"]["kind"] == "action-manifest-blob"
        assert expected_values["blob"] in row["source_pin"]["value"]
        assert expected_values["content_sha256"] in row["source_pin"]["value"]
        assert row["source_pin"]["source_snapshot_sha256"] == (
            "3e116a585fca2d28c0ec676ec1f0aaf23d4c34f9dd4df6468d7761552771afe6"
        )
        assert row["source_pin"]["source_matrix_sha256"] == (
            "be6971e4ec5dbccd194c05ccedbf2a4cc00aaa8d01bf03a786f69a922f4e4d9f"
        )
        assert row["source_pin"]["review_sha256"] == (
            "aa6cd8737f37df61488ba2521597eca795cb46f0000a179db38c26badf18e212"
        )
        assert set(row["evidence_classes"]) == REQUIRED_VECTOR_CLASSES[vector_id]

        serialized = json.dumps(row, sort_keys=True)
        for term in expected_values["terms"]:
            assert term in serialized
        mapping = row["ardur_mapping"]
        assert mapping["proof_role"] == expected_values["proof_role"]
        assert mapping["source_index_sha256"] == (
            "3e116a585fca2d28c0ec676ec1f0aaf23d4c34f9dd4df6468d7761552771afe6"
        )
        assert mapping["parent_matrix_sha256"] == (
            "be6971e4ec5dbccd194c05ccedbf2a4cc00aaa8d01bf03a786f69a922f4e4d9f"
        )
        assert mapping["review_sha256"] == (
            "aa6cd8737f37df61488ba2521597eca795cb46f0000a179db38c26badf18e212"
        )
        assert "not_live" in mapping["output_material"] or "not_live" in mapping["matrix_review_boundary"]
        assert mapping["credential_material"] == "field_names_or_placeholders_only_no_secret_values"
        assert set(row["unknown_boundaries"]).issuperset(
            common_unknowns | expected_values["unknowns"]
        )
        not_claimed = " ".join(row["not_claimed"]).lower()
        for phrase in (
            expected_values["not_claimed_phrases"]
            | {"actor identity", "permission enforcement", "token", "credential", "workflow-secret"}
        ):
            assert phrase in not_claimed
        claim_boundary = row["claim_boundary"].lower()
        for phrase in expected_values["boundary_phrases"]:
            assert phrase in claim_boundary
        for forbidden in ("Bearer", "github_pat_", "raw-secret-value"):
            assert forbidden not in serialized


def test_gemini_cli_0490_tool_output_trust_governance_vector_preserves_source_boundaries() -> None:
    """Gemini CLI 0.49.0 governance/output context must stay source-semantic only."""

    rows = _read_jsonl(VECTORS_PATH)
    row = next(
        item
        for item in rows
        if item["vector_id"] == "gemini-cli-tool-output-trust-governance-v0490"
    )

    assert row["source_family"] == "gemini-cli"
    assert row["source_pin"]["kind"] == "package-release"
    assert "@google/gemini-cli@0.49.0" in row["source_pin"]["value"]
    assert "release v0.49.0" in row["source_pin"]["value"]
    assert row["source_pin"]["source_snapshot_sha256"] == (
        "ad35c62e9c295b49c27510a494ed37973865641b87fc226a97eaefc8cc5492cb"
    )
    assert row["source_pin"]["source_matrix_sha256"] == (
        "29d0f2b1d7b846d2e770acb9a7cf85a4d46599137e2b0eec3a1a7b11c1e23729"
    )
    assert row["source_pin"]["review_sha256"] == (
        "ac6e8494a85fc444752ba4232978545a22fb6de74a2b7f97827fa40f3b485032"
    )

    signal = row["source_semantic_signal"]
    for phrase in (
        "standardized tool output formatting",
        "workflow/policy configuration",
        "zero-quota fail-fast",
        "shell-wrapper normalization",
        "skill-install path traversal prevention",
        "pending tools/trust overrides",
        "GDC air-gapped Service Identity",
        "tmux/background detection",
        "static eval source analyzer",
        "eval inventory JSON output",
    ):
        assert phrase in signal

    assert "tool_output_metadata" not in row["evidence_classes"]
    assert "sdk_output_metadata" in row["evidence_classes"]
    assert set(row["evidence_classes"]) == REQUIRED_VECTOR_CLASSES[
        "gemini-cli-tool-output-trust-governance-v0490"
    ]

    mapping = row["ardur_mapping"]
    assert mapping["proof_role"] == "source_semantic_governance_output_context_only"
    assert mapping["output_metadata"] == (
        "standardized_tool_output_formatting_and_eval_inventory_json_output_source_context"
    )
    assert mapping["policy_material"] == (
        "workflow_policy_configuration_pending_tools_and_trust_overrides_source_context"
    )
    assert mapping["runtime_event_context"] == (
        "zero_quota_fail_fast_shell_wrapper_tmux_background_and_skill_install_source_signals"
    )
    assert mapping["deployment_context"] == "gdc_air_gapped_service_identity_source_context"
    assert mapping["eval_context"] == "static_eval_source_analyzer_and_inventory_output_metadata"
    assert mapping["release_body_sha256"] == (
        "6c360acafbd49f4a1aff37ed816905f2316ef522fabeb27887c9f535652ceac5"
    )
    assert mapping["npm_integrity"] == (
        "sha512-S0b6nfAf+lHbSPMKRuQziU1/710a7f/Jag2mZ7N1J1b48qxoCmjwNCJJ7XPEv/ropvDqkCjJupE32qcw+ym3jQ=="
    )
    assert mapping["npm_shasum"] == "14e8295a8eb31188402f09747116161b63a8353e"
    assert mapping["tarball_sha256"] == (
        "ce07c3ab62de761efa92c0cd16b5efcb869a16ce0cb04befed8f1f22b1d1379a"
    )
    assert mapping["focused_probe_sha256"] == (
        "88d598100f907bd74862d0f95a25ba57e6ec71f78bf1549322c6b3b8d0779a0f"
    )
    assert mapping["source_index_sha256"] == (
        "a89787881e0b1f2382fc0b9911c8fddbc2fa564f2b68cb5c9ae262b6d67abd31"
    )
    assert mapping["matrix_review_boundary"] == "no_live_gemini_fixture_or_provider_behavior_change"

    assert set(row["unknown_boundaries"]).issuperset(
        {
            "live_gemini_cli_behavior",
            "live_gemini_account_behavior",
            "live_provider_behavior",
            "provider_hidden_behavior",
            "server_side_tool_calls",
            "actual_shell_behavior",
            "path_traversal_exploitability",
            "live_tool_behavior",
            "live_mcp_behavior",
            "auth_service_identity_behavior",
            "quota_behavior",
            "network_side_effects",
            "runtime_side_effects",
            "live_policy_enforcement",
            "live_eval_execution",
            "benchmark_public_readiness",
            "growth_proof",
            "ebpf_kernel_capture",
            "universal_cli_capture",
            "credentials",
            "gemini_settings_trust_root",
        }
    )

    not_claimed = " ".join(row["not_claimed"]).lower()
    for phrase in (
        "no live gemini cli",
        "provider-hidden",
        "server-side tool calls",
        "path traversal",
        "tool/mcp behavior",
        "service identity",
        "quota",
        "network/runtime side effects",
        "policy enforcement",
        "eval execution",
        "public readiness",
        "growth proof",
        "ebpf/kernel",
        "universal cli",
        "trust root",
    ):
        assert phrase in not_claimed

    claim_boundary = row["claim_boundary"].lower()
    assert "does not prove live gemini cli" in claim_boundary
    assert "provider-hidden/server-side" in claim_boundary
    assert "shell/path traversal/tool/mcp/auth/quota/network/runtime/policy/eval" in claim_boundary
    assert "public readiness/growth" in claim_boundary
    assert "ebpf/kernel/universal cli" in claim_boundary
    assert "trust overrides as ardur trust root" in claim_boundary


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


def test_openai_agents_sdk_0177_vector_preserves_source_only_runtime_boundaries() -> None:
    """OpenAI Agents SDK 0.17.7 source deltas must not become live-provider claims."""

    rows = _read_jsonl(VECTORS_PATH)
    row = next(
        item
        for item in rows
        if item["vector_id"] == "openai-agents-sdk-0177-streaming-output-approval-sandbox"
    )

    assert row["source_family"] == "openai-agents-sdk"
    assert row["source_pin"]["kind"] == "package-release"
    assert "openai-agents==0.17.7" in row["source_pin"]["value"]
    assert "openai-agents-python v0.17.7" in row["source_pin"]["value"]
    assert row["source_pin"]["source_snapshot_sha256"] == (
        "45ac104d707c39537de9c8e2edaff0b665eb225619cef7ae5dfd2ca9cf22175f"
    )
    assert row["source_pin"]["source_matrix_sha256"] == (
        "a855bd8d906908c11f098ddbcecbd4a8d2279375db63c49426814772f8fbcdc1"
    )
    assert row["source_pin"]["review_sha256"] == (
        "2e68a3b5e175242e2d9854e1ecf7d3c74a44b667f536422d1b3dde193c8fce2b"
    )

    signal = row["source_semantic_signal"]
    for phrase in (
        "buffered Chat Completions tool-call streaming",
        "empty list/tuple tool output",
        "needs_approval_checker",
        "sandbox sink buffering",
        "PTY output collection",
    ):
        assert phrase in signal

    mapping = row["ardur_mapping"]
    assert mapping["proof_role"] == "source_semantic_runtime_metadata_only"
    assert mapping["streaming_tool_calls"] == "buffered_chat_completions_tool_call_streaming"
    assert mapping["tool_output_preservation"] == "empty_list_tuple_output_model_visible_metadata"
    assert mapping["approval_lifecycle"] == "needs_approval_checker_guardrail_resolution_context"
    assert mapping["sandbox_output_collection"] == "sandbox_sink_and_pty_output_buffering_context"
    assert mapping["fixture_boundary"] == "does_not_change_openai_no_key_fixture_receipt_count"
    assert mapping["release_body_sha256"] == (
        "37d1c3575bb729f6f2ace552466c2ab14d0acdfc8f5d0cd5854a584ea6ee66b3"
    )
    assert mapping["compare_sha256"] == (
        "07c5f33cea6838638e649dc3c8ea33d99face4d5d9aad988ad74f0253adbbe32"
    )
    assert mapping["pypi_wheel_sha256"] == (
        "51b5ae43756eea37032e430f95979ba3999af6b1ade397df6c0ffeaf1939646a"
    )
    assert mapping["pypi_sdist_sha256"] == (
        "ca76e7f882c9d8f06e3dfb8064cc33bcb5a5f34a29816cb9af863f395964ff0c"
    )

    assert set(row["unknown_boundaries"]).issuperset(
        {
            "live_provider_behavior",
            "provider_hidden_behavior",
            "server_side_tool_calls",
            "runtime_kernel_side_effects",
            "live_enforcement",
            "provider_api_calls",
            "live_streaming_behavior",
            "live_sandbox_execution",
        }
    )
    not_claimed = " ".join(row["not_claimed"]).lower()
    for phrase in ("no live openai", "server-side", "provider-hidden", "sandbox", "receipt_count"):
        assert phrase in not_claimed
    assert "does not prove live openai" in row["claim_boundary"].lower()
    assert "toolhive" not in row["claim_boundary"].lower()


def test_toolhive_0301_vector_preserves_deployment_only_boundaries() -> None:
    """ToolHive 0.30.1 source deltas must stay deployment context, not runtime proof."""

    rows = _read_jsonl(VECTORS_PATH)
    row = next(item for item in rows if item["vector_id"] == "toolhive-0301-network-authz-obo-events")

    assert row["source_family"] == "toolhive"
    assert row["source_pin"]["kind"] == "release"
    assert row["source_pin"]["value"] == "v0.30.1"
    assert row["source_pin"]["source_snapshot_sha256"] == (
        "45ac104d707c39537de9c8e2edaff0b665eb225619cef7ae5dfd2ca9cf22175f"
    )
    assert row["source_pin"]["source_matrix_sha256"] == (
        "a855bd8d906908c11f098ddbcecbd4a8d2279375db63c49426814772f8fbcdc1"
    )
    assert row["source_pin"]["review_sha256"] == (
        "2e68a3b5e175242e2d9854e1ecf7d3c74a44b667f536422d1b3dde193c8fce2b"
    )

    signal = row["source_semantic_signal"]
    for phrase in (
        "network isolation",
        "authzConfigRef",
        "OBO SecretEnvVars",
        "config-controller events",
    ):
        assert phrase in signal

    mapping = row["ardur_mapping"]
    assert mapping["proof_role"] == "deployment_context_only"
    assert mapping["network_policy"] == "default_network_isolation_for_local_mcp_servers"
    assert mapping["authz_reference"] == "authz_config_ref_enforcement_context"
    assert mapping["secret_material"] == "obo_secret_env_vars_presence_digest_only"
    assert mapping["event_material"] == "config_controller_event_metadata_only"
    assert mapping["release_body_sha256"] == (
        "f0f1bf098d7e82efa99bea938051b3b4fd82dfb536ba75d3d75943c3b628ce9d"
    )
    assert mapping["compare_sha256"] == (
        "6f8620ff51491411ad6132a2ef50d2e42898c2061b0a71d5a1ed004b1e868988"
    )

    assert set(row["unknown_boundaries"]).issuperset(
        {
            "toolhive_mcp_enforcement",
            "actual_client_identity",
            "live_deployment_configuration",
            "credentials",
            "live_toolhive_execution",
            "kubernetes_runtime_behavior",
            "mcp_authorization_effectiveness",
            "secret_values",
        }
    )
    not_claimed = " ".join(row["not_claimed"]).lower()
    for phrase in ("no live toolhive", "kubernetes", "secret values", "runtime enforcement"):
        assert phrase in not_claimed
    assert "does not prove live toolhive" in row["claim_boundary"].lower()
    assert "openai" not in row["claim_boundary"].lower()


def test_toolhive_0310_vector_preserves_source_only_governance_boundaries() -> None:
    """ToolHive 0.31.0 source deltas must stay no-key deployment context."""

    rows = _read_jsonl(VECTORS_PATH)
    row = next(
        item
        for item in rows
        if item["vector_id"] == "toolhive-0310-oidc-vmcp-authz-chain-governance"
    )

    assert row["source_family"] == "toolhive"
    assert row["source_pin"]["kind"] == "release"
    assert "v0.31.0" in row["source_pin"]["value"]
    assert "ac1f5b499212b03da4b7eb3c5d75d796e2ba580f3aa8eedb4e8e29319ff24445" in (
        row["source_pin"]["value"]
    )
    assert row["source_pin"]["source_snapshot_sha256"] == (
        "ae6e8916f1828b7c758bc9800d91bede9b6a802012478ea3252a695009a2cd2c"
    )
    assert row["source_pin"]["source_matrix_sha256"] == (
        "5554a51be706bf157372f29b03ceafe29d7b9cbc296cf03451c7e986610c03d2"
    )
    assert row["source_pin"]["review_sha256"] == (
        "988a18bc74cf0bbb5e3274cd2dae6c210d8bf689d26bbc41dad9fb61062649c7"
    )

    signal = row["source_semantic_signal"]
    for phrase in (
        "MCPOIDCConfig",
        "level-triggered operator reconciliation",
        "embedded auth server",
        "private IPs",
        "multi-upstream authorization chain",
    ):
        assert phrase in signal

    mapping = row["ardur_mapping"]
    assert mapping["proof_role"] == "deployment_context_only"
    assert mapping["oidc_oauth_config_context"] == "mcpoidcconfig_referencing_workload_indexes"
    assert mapping["operator_reconciliation"] == "level_triggered_reconciliation_rules_source_context"
    assert mapping["vmcp_auth_update_loop"] == "embedded_auth_server_update_loop_source_context"
    assert mapping["private_ip_upstream_allowance"] == "in_cluster_oidc_oauth_private_ip_source_context"
    assert mapping["multi_upstream_authorization_chain"] == "multi_upstream_authorization_chain_flow_fix_context"
    assert mapping["release_body_sha256"] == (
        "ac1f5b499212b03da4b7eb3c5d75d796e2ba580f3aa8eedb4e8e29319ff24445"
    )
    assert mapping["compare_sha256"] == (
        "a119ff354e989b8f375879f2ba307abcebf394e0c0a07b76d57a558f1ea67e59"
    )

    assert set(row["unknown_boundaries"]).issuperset(
        {
            "live_toolhive_execution",
            "kubernetes_runtime_behavior",
            "mcp_authorization_effectiveness",
            "oidc_oauth_provider_behavior",
            "private_ip_upstream_reachability",
            "multi_upstream_authorization_effectiveness",
            "credentials",
            "secret_values",
        }
    )
    not_claimed = " ".join(row["not_claimed"]).lower()
    for phrase in (
        "live toolhive",
        "oidc/oauth provider behavior",
        "mcp authorization enforcement",
        "kubernetes runtime behavior",
        "private-ip reachability",
        "credential validity",
        "runtime proof",
    ):
        assert phrase in not_claimed
    assert row["claim_boundary"].startswith("Source-semantic no-key vector only;")
    assert "does not prove live toolhive" in row["claim_boundary"].lower()
    assert "oidc/oauth provider behavior" in row["claim_boundary"].lower()
    assert "mcp authorization enforcement" in row["claim_boundary"].lower()
    assert "private-ip reachability" in row["claim_boundary"].lower()
    assert "runtime proof" in row["claim_boundary"].lower()
    assert "openai" not in row["claim_boundary"].lower()


def test_codex_142_vector_preserves_source_governance_boundaries() -> None:
    """Codex v0.142 governance/control semantics must stay source-only and bounded."""

    rows = _read_jsonl(VECTORS_PATH)
    row = next(
        item for item in rows if item["vector_id"] == "codex-142-rollout-budget-multiagent-websearch-time"
    )

    assert row["source_family"] == "codex"
    assert row["source_pin"]["kind"] == "release"
    assert "rust-v0.142.0" in row["source_pin"]["value"]
    assert "fe64939a212da5d9bea2fa3f3b7aa55c4a173f0b298c3be597de3d521788fdd1" in (
        row["source_pin"]["value"]
    )
    assert row["source_pin"]["source_snapshot_sha256"] == (
        "742c3f9a6da3726eb25446d94570910d7aa88da660b6e711430a53f162aa4f6c"
    )
    assert row["source_pin"]["source_matrix_sha256"] == (
        "3b0962096849f80c68636842cbe002fa848613ec5648ccdbf218cdc18c2bfd9d"
    )
    assert row["source_pin"]["review_sha256"] == (
        "5c7fa3bf3ac986eaa811d771dcffd525f133c60615ea77bc03fc78b4263795fb"
    )

    signal = row["source_semantic_signal"]
    for phrase in ("rollout token budgets", "multi-agent mode", "indexed web-search", "current-time"):
        assert phrase in signal

    mapping = row["ardur_mapping"]
    assert mapping["proof_role"] == "source_semantic_governance_context"
    assert mapping["release_body_sha256"] == (
        "fe64939a212da5d9bea2fa3f3b7aa55c4a173f0b298c3be597de3d521788fdd1"
    )
    assert mapping["policy_material"] == "rollout_budget_multiagent_mode_and_indexed_web_search_policy_digest"
    assert mapping["session_material"] == "time_context_and_reminder_surface_digest"

    assert set(row["unknown_boundaries"]).issuperset(
        {
            "live_codex_cli_behavior",
            "provider_hidden_behavior",
            "server_side_tool_calls",
            "live_web_search_results",
            "network_side_effects",
            "clock_source_accuracy",
            "runtime_kernel_side_effects",
            "plugin_execution",
            "credentials",
        }
    )
    not_claimed = " ".join(row["not_claimed"]).lower()
    for phrase in ("no live codex", "provider-hidden", "search result contents", "runtime/kernel"):
        assert phrase in not_claimed
    assert "does not prove live codex" in row["claim_boundary"].lower()


def test_codex_1422_mcp_proxy_vector_preserves_source_only_boundaries() -> None:
    """Codex 0.142.2 MCP/proxy context must stay source-semantic and non-live."""

    rows = _read_jsonl(VECTORS_PATH)
    row = next(
        item for item in rows if item["vector_id"] == "codex-1422-mcp-tool-search-proxy-context"
    )

    assert row["source_family"] == "codex"
    assert row["source_pin"]["kind"] == "release"
    assert "rust-v0.142.2" in row["source_pin"]["value"]
    assert "7fda5587a0f79e004d899960fbc9b910f7028c6d34b04789765e36223887a564" in (
        row["source_pin"]["value"]
    )
    assert row["source_pin"]["source_snapshot_sha256"] == (
        "7f7953775b321ec6fa513de82452d0c1d550dd9bb6ed4b215540f2466836e801"
    )
    assert row["source_pin"]["source_matrix_sha256"] == (
        "21567d29050b0c90d29566100adec6601199cb43127398a2a378effb70b40df6"
    )
    assert row["source_pin"]["review_sha256"] == (
        "8265f3f80b4a40816c2542dcbfd3b91442fce88b9f40494b175f8b2cebcabe69"
    )

    signal = row["source_semantic_signal"]
    for phrase in (
        "MCP tools use tool search by default",
        "respect_system_proxy",
        "system proxy",
        "PAC",
        "WPAD",
        "dark-mode logos",
        "safety-buffering",
        "faster-model metadata",
    ):
        assert phrase in signal

    mapping = row["ardur_mapping"]
    assert mapping["proof_role"] == "source_semantic_mcp_proxy_context"
    assert mapping["mcp_tool_search_default"] == "host_managed_tool_search_default_when_supported"
    assert mapping["tool_discovery_context"] == "mcp_tool_discovery_policy_context_only"
    assert mapping["proxy_policy_context"] == "respect_system_proxy_pac_wpad_placeholder_and_digest_only"
    assert mapping["plugin_catalog_context"] == "dark_mode_logo_and_catalog_display_metadata_only"
    assert mapping["safety_ui_context"] == (
        "server_provided_visibility_and_faster_model_metadata_ui_session_context_only"
    )
    assert mapping["release_body_sha256"] == (
        "7fda5587a0f79e004d899960fbc9b910f7028c6d34b04789765e36223887a564"
    )
    assert mapping["matrix_review_boundary"] == "no_runtime_fixture_or_live_codex_mcp_proxy_validation"

    assert set(row["unknown_boundaries"]).issuperset(
        {
            "live_codex_cli_behavior",
            "provider_hidden_behavior",
            "server_side_tool_calls",
            "live_mcp_server_behavior",
            "mcp_tool_catalog_completeness",
            "live_tool_search_behavior",
            "actual_proxy_resolution",
            "pac_wpad_network_behavior",
            "proxy_credentials",
            "plugin_catalog_fetch_contents",
            "plugin_execution",
            "live_ui_visibility_behavior",
            "faster_model_selection_effects",
            "network_side_effects",
            "runtime_kernel_side_effects",
            "credentials",
        }
    )
    assert "sdk_output_metadata" not in row["evidence_classes"]
    not_claimed = " ".join(row["not_claimed"]).lower()
    for phrase in (
        "no live codex",
        "provider-hidden",
        "tool catalog completeness",
        "proxy routing",
        "pac/wpad",
        "plugin catalog",
        "safety-buffering",
        "runtime/kernel",
    ):
        assert phrase in not_claimed
    assert "does not prove live codex" in row["claim_boundary"].lower()
    assert "tool catalog completeness" in row["claim_boundary"].lower()
    assert "actual proxy/pac/wpad routing" in row["claim_boundary"].lower()


def test_claude_2186_mcp_directory_vector_preserves_placeholder_boundaries() -> None:
    """Claude Code MCP directory resource listing must not become raw content proof."""

    rows = _read_jsonl(VECTORS_PATH)
    row = next(
        item for item in rows if item["vector_id"] == "claude-code-mcp-directory-resource-listing-v2186"
    )

    assert row["source_family"] == "claude-code"
    assert row["source_pin"]["kind"] == "package"
    assert "@anthropic-ai/claude-code@2.1.186" in row["source_pin"]["value"]
    assert "70522e2891269edd035b5f0e97f262d371957420ae3692c44004276f73d56667" in (
        row["source_pin"]["value"]
    )
    assert row["source_pin"]["source_snapshot_sha256"] == (
        "742c3f9a6da3726eb25446d94570910d7aa88da660b6e711430a53f162aa4f6c"
    )
    assert row["source_pin"]["source_matrix_sha256"] == (
        "3b0962096849f80c68636842cbe002fa848613ec5648ccdbf218cdc18c2bfd9d"
    )
    assert row["source_pin"]["review_sha256"] == (
        "5c7fa3bf3ac986eaa811d771dcffd525f133c60615ea77bc03fc78b4263795fb"
    )

    signal = row["source_semantic_signal"]
    for phrase in ("ReadMcpResourceDirInput", "ReadMcpResourceDirOutput", "mimeType", "error"):
        assert phrase in signal

    mapping = row["ardur_mapping"]
    assert mapping["proof_role"] == "source_semantic_mcp_resource_listing_context"
    assert mapping["resource_identifier_material"] == "placeholder_uri_and_digest_only"
    assert mapping["child_resource_metadata"] == "uri_name_optional_mimetype_without_raw_contents"
    assert mapping["package_shasum"] == "1db1b0a986c733f147d7f030b1b7a555384d674e"
    assert mapping["tarball_sha256"] == "b39db8b69e2b4b751f26b9b77f19bf1155339132ca5ede4795247331b5a7f992"

    assert set(row["unknown_boundaries"]).issuperset(
        {
            "live_claude_code_behavior",
            "live_mcp_server_behavior",
            "raw_resource_contents",
            "directory_traversal_completeness",
            "provider_hidden_behavior",
            "credentials",
            "local_filesystem_side_effects",
            "network_side_effects",
            "action_runner_side_effects",
        }
    )
    not_claimed = " ".join(row["not_claimed"]).lower()
    for phrase in ("no live claude code", "raw mcp resource contents", "filesystem effects"):
        assert phrase in not_claimed
    assert "does not prove live claude code" in row["claim_boundary"].lower()


def test_claude_2191_glob_notebook_vector_preserves_count_and_source_boundaries() -> None:
    """Claude Code 2.1.191 Glob/Notebook output metadata must stay source-only."""

    rows = _read_jsonl(VECTORS_PATH)
    row = next(
        item
        for item in rows
        if item["vector_id"] == "claude-code-glob-count-notebook-old-source-v2191"
    )

    assert row["source_family"] == "claude-code"
    assert row["source_pin"]["kind"] == "package"
    assert "@anthropic-ai/claude-code@2.1.191" in row["source_pin"]["value"]
    assert "12afc4ea26757be14f01cd58eacc9d64353a4ffe0d318e36146497bcab297f14" in (
        row["source_pin"]["value"]
    )
    assert "4f06a2ce5a4f1ef1764db0d42ec9db9d530c0279ed9b0fdbca008c236535062a" in (
        row["source_pin"]["value"]
    )
    assert row["source_pin"]["source_snapshot_sha256"] == (
        "26fcaec2cbf1f0a5d094d9e59842107c475452a9fb4cc2b6349b92f5bfc58410"
    )
    assert row["source_pin"]["source_matrix_sha256"] == (
        "443f6d7950bd90dd31d78272ba33096c753c738ca808a69b0341b42c937dfcdc"
    )
    assert row["source_pin"]["review_sha256"] == (
        "a942b91a17e3f7412b7b6c3b94c858fe0c9b8142efda72cd8d44a4e708ee54d4"
    )

    signal = row["source_semantic_signal"]
    for phrase in (
        "GlobOutput.numFiles",
        "returned file paths after truncation",
        "totalMatches",
        "countIsComplete",
        "older persisted results",
        "NotebookEditOutput.old_source",
        "previous-cell source",
    ):
        assert phrase in signal

    mapping = row["ardur_mapping"]
    assert mapping["proof_role"] == "source_semantic_output_metadata_boundary"
    assert mapping["glob_num_files"] == "returned_paths_after_truncation"
    assert mapping["glob_total_matches"] == "exact_or_lower_bound_depending_on_count_is_complete"
    assert mapping["legacy_glob_count_metadata"] == (
        "total_matches_and_count_is_complete_may_be_absent_on_older_persisted_results"
    )
    assert mapping["notebook_old_source"] == "previous_cell_source_digest_or_placeholder_only"
    assert mapping["runtime_receipt_boundary"] == (
        "posttooluse_result_hash_without_raw_response_field_expansion"
    )
    assert mapping["sdk_tools_d_ts_sha256"] == (
        "12afc4ea26757be14f01cd58eacc9d64353a4ffe0d318e36146497bcab297f14"
    )
    assert mapping["tarball_sha256"] == (
        "4f06a2ce5a4f1ef1764db0d42ec9db9d530c0279ed9b0fdbca008c236535062a"
    )

    assert set(row["unknown_boundaries"]).issuperset(
        {
            "live_claude_code_behavior",
            "raw_search_results",
            "exact_result_completeness_when_count_is_complete_absent_or_false",
            "raw_notebook_cell_source",
            "provider_hidden_behavior",
            "local_filesystem_side_effects",
            "runtime_kernel_side_effects",
            "credentials",
            "action_runner_side_effects",
            "universal_cli_capture",
        }
    )
    not_claimed = " ".join(row["not_claimed"]).lower()
    for phrase in (
        "no live claude code",
        "raw search results",
        "exact live result completeness",
        "raw notebook cell",
        "provider-hidden",
        "filesystem side effects",
        "runtime/ebpf",
        "universal cli",
        "codex rust-v0.142.1 proxy/auth",
    ):
        assert phrase in not_claimed
    assert "does not prove live claude code" in row["claim_boundary"].lower()
    assert "raw search results" in row["claim_boundary"].lower()
    assert "countiscomplete is absent or false" in row["claim_boundary"].lower()
    assert "codex proxy/auth" in row["claim_boundary"].lower()


def test_claude_2195_watchsource_websocket_vector_preserves_source_only_boundaries() -> None:
    """Claude Code WatchSource WebSocket semantics must stay no-key and non-live."""

    rows = _read_jsonl(VECTORS_PATH)
    row = next(
        item
        for item in rows
        if item["vector_id"] == "claude-code-watchsource-websocket-stream-v2195"
    )

    assert row["source_family"] == "claude-code"
    assert row["source_pin"]["kind"] == "package"
    assert "@anthropic-ai/claude-code@2.1.195" in row["source_pin"]["value"]
    assert "a7b63ca639f1691c4e8eb92d7e12a9267c5eb96f9352765b5f5acdbea2a8ffea" in (
        row["source_pin"]["value"]
    )
    assert "a531d520e9ef0844c9883765aa7b4f83ea2f8fe914a7392accd4c249e1aec9e5" in (
        row["source_pin"]["value"]
    )
    assert row["source_pin"]["source_snapshot_sha256"] == (
        "95379be46a5d091a80617507a94b0a7f66d047ff5cd30dd092643de3d58e3ffe"
    )
    assert row["source_pin"]["source_matrix_sha256"] == (
        "d9c0e3a31d836fb4d5cd7a98668d457314baa94445b436ed5c5a3de015bba010"
    )
    assert row["source_pin"]["review_sha256"] == (
        "ae838af8b0b66b081035ddfa3dae1b42e1adf0caee04b55064021a42677accf9"
    )

    signal = row["source_semantic_signal"]
    for phrase in (
        "WatchSource.command",
        "optional",
        "WatchSource.ws",
        "protocols",
        "WebSocket text frames are events",
        "binary frames are emitted as placeholder lines",
        "socket close ends the watch",
        "ws cannot be combined with command",
    ):
        assert phrase in signal

    assert set(row["evidence_classes"]) == REQUIRED_VECTOR_CLASSES[
        "claude-code-watchsource-websocket-stream-v2195"
    ]

    mapping = row["ardur_mapping"]
    assert mapping["proof_role"] == "source_semantic_watchsource_stream_context"
    assert mapping["source_selection_policy"] == "watch_source_command_or_websocket_mutual_exclusion"
    assert mapping["command_source_context"] == "optional_command_source_config_digest_only"
    assert mapping["websocket_source_context"] == "placeholder_url_and_protocols_digest_only"
    assert mapping["text_frame_event_boundary"] == (
        "text_frames_as_source_level_events_without_payload_persistence"
    )
    assert mapping["binary_frame_boundary"] == (
        "binary_frames_as_placeholder_lines_without_binary_payloads"
    )
    assert mapping["stream_termination_boundary"] == "socket_close_as_watch_end_source_semantics_only"
    assert mapping["sdk_tools_d_ts_sha256"] == (
        "a7b63ca639f1691c4e8eb92d7e12a9267c5eb96f9352765b5f5acdbea2a8ffea"
    )
    assert mapping["tarball_sha256"] == (
        "a531d520e9ef0844c9883765aa7b4f83ea2f8fe914a7392accd4c249e1aec9e5"
    )
    assert mapping["source_index_sha256"] == (
        "95379be46a5d091a80617507a94b0a7f66d047ff5cd30dd092643de3d58e3ffe"
    )
    assert mapping["parent_matrix_sha256"] == (
        "d9c0e3a31d836fb4d5cd7a98668d457314baa94445b436ed5c5a3de015bba010"
    )
    assert mapping["review_sha256"] == (
        "ae838af8b0b66b081035ddfa3dae1b42e1adf0caee04b55064021a42677accf9"
    )
    assert mapping["matrix_review_boundary"] == "no_live_claude_websocket_network_or_provider_validation"

    assert set(row["unknown_boundaries"]).issuperset(
        {
            "live_claude_code_behavior",
            "live_websocket_connection",
            "websocket_network_side_effects",
            "websocket_endpoint_identity",
            "websocket_protocol_negotiation",
            "text_frame_payloads",
            "binary_frame_contents",
            "frame_delivery_completeness",
            "socket_close_timing",
            "provider_hidden_behavior",
            "runtime_kernel_side_effects",
            "credentials",
            "public_readiness",
            "universal_cli_capture",
        }
    )

    serialized = json.dumps(row, sort_keys=True)
    for forbidden in ("Bearer", "github_pat_", "raw-secret-value", "ws://", "wss://"):
        assert forbidden not in serialized

    not_claimed = " ".join(row["not_claimed"]).lower()
    for phrase in (
        "no live claude code",
        "no live websocket",
        "provider-hidden/server-side",
        "websocket endpoint identity",
        "runtime/ebpf",
        "public readiness",
        "universal cli",
        "credential values",
        "frame payloads",
    ):
        assert phrase in not_claimed

    claim_boundary = row["claim_boundary"].lower()
    assert "does not prove live claude code" in claim_boundary
    assert "live websocket connection/capture" in claim_boundary
    assert "provider-hidden/server-side" in claim_boundary
    assert "websocket network side effects" in claim_boundary
    assert "runtime/ebpf" in claim_boundary
    assert "public readiness/growth" in claim_boundary
    assert "universal cli" in claim_boundary
    assert "credential/endpoint/frame-payload handling" in claim_boundary


def test_claude_code_reportfindings_vector_preserves_host_reported_boundaries() -> None:
    """Claude Code ReportFindings labels must stay host-reported source semantics."""

    rows = _read_jsonl(VECTORS_PATH)
    row = next(
        item
        for item in rows
        if item["vector_id"] == "claude-code-reportfindings-review-output-v2196"
    )

    assert row["source_family"] == "claude-code"
    assert row["source_pin"]["kind"] == "package"
    assert "@anthropic-ai/claude-code@2.1.196" in row["source_pin"]["value"]
    assert "376a93553a539a3c323d2a54846cae30ace4f242f5d6355064c644634603f725" in (
        row["source_pin"]["value"]
    )
    assert "e264ff2991e0d29b2d956bedd842385180e1d41183417b0bb77c8b808beda206" in (
        row["source_pin"]["value"]
    )
    assert row["source_pin"]["source_snapshot_sha256"] == (
        "cffab7cbde0814528868ff85ac5c8b30a10671c95910f7039d2cacda30404490"
    )
    assert row["source_pin"]["source_matrix_sha256"] == (
        "0c2c6026c6585b23e506ee1ff8caf8bde366eef6ee17885c06f324e3754a27b2"
    )
    assert row["source_pin"]["review_sha256"] == (
        "a632285f12510810b550270ff065480011071876f006bca50ad38b1fe90a7834"
    )

    signal = row["source_semantic_signal"]
    for phrase in (
        "ReportFindingsInput",
        "ReportFindingsOutput",
        "effort level",
        "repo-relative finding anchors",
        "failure_scenario",
        "host-reported CONFIRMED or PLAUSIBLE",
        "host-reported fixed/skipped/no_change_needed",
        "Pretext artifact description",
    ):
        assert phrase in signal

    assert set(row["evidence_classes"]) == REQUIRED_VECTOR_CLASSES[
        "claude-code-reportfindings-review-output-v2196"
    ]

    mapping = row["ardur_mapping"]
    assert mapping["proof_role"] == "source_semantic_reviewer_output_metadata_boundary"
    assert mapping["review_findings_surface"] == "ReportFindingsInput_and_ReportFindingsOutput"
    assert mapping["host_verdict_boundary"] == "CONFIRMED_or_PLAUSIBLE_are_host_reported_labels_only"
    assert mapping["host_outcome_boundary"] == (
        "fixed_skipped_no_change_needed_are_host_reported_labels_only"
    )
    assert mapping["sdk_tools_d_ts_sha256"] == (
        "376a93553a539a3c323d2a54846cae30ace4f242f5d6355064c644634603f725"
    )
    assert mapping["tarball_sha256"] == (
        "e264ff2991e0d29b2d956bedd842385180e1d41183417b0bb77c8b808beda206"
    )
    assert mapping["source_index_sha256"] == (
        "cffab7cbde0814528868ff85ac5c8b30a10671c95910f7039d2cacda30404490"
    )
    assert mapping["parent_matrix_sha256"] == (
        "0c2c6026c6585b23e506ee1ff8caf8bde366eef6ee17885c06f324e3754a27b2"
    )
    assert mapping["review_sha256"] == (
        "a632285f12510810b550270ff065480011071876f006bca50ad38b1fe90a7834"
    )
    assert mapping["matrix_review_boundary"] == (
        "no_live_claude_provider_action_runner_or_independent_fix_validation"
    )

    assert set(row["unknown_boundaries"]).issuperset(
        {
            "live_claude_code_behavior",
            "live_reportfindings_emission",
            "provider_hidden_behavior",
            "action_runner_side_effects",
            "github_action_runner_side_effects",
            "runtime_kernel_side_effects",
            "raw_file_contents",
            "raw_review_text",
            "local_absolute_paths",
            "credentials",
            "provider_api_calls",
            "independent_defect_verification",
            "actual_fix_verification",
            "public_readiness",
            "growth_proof",
            "universal_cli_capture",
        }
    )

    serialized = json.dumps(row, sort_keys=True)
    for forbidden in (
        "Bearer",
        "github_pat_",
        "raw-secret-value",
        "BEGIN PRIVATE KEY",
        "/Users/",
        "raw file content",
    ):
        assert forbidden not in serialized

    not_claimed = " ".join(row["not_claimed"]).lower()
    for phrase in (
        "no live claude code",
        "provider call",
        "github action run",
        "host-reported confirmed",
        "do not prove independent ardur defect verification",
        "do not prove code changed",
        "raw review text",
        "local absolute paths",
        "provider-hidden/server-side",
        "runtime/kernel",
        "public readiness",
        "universal cli",
    ):
        assert phrase in not_claimed

    claim_boundary = row["claim_boundary"].lower()
    assert "does not prove live claude code" in claim_boundary
    assert "reportfindings emission" in claim_boundary
    assert "independent defect verification" in claim_boundary
    assert "actual fix status" in claim_boundary
    assert "provider-hidden/server-side" in claim_boundary
    assert "action-runner side effects" in claim_boundary
    assert "runtime/kernel" in claim_boundary
    assert "public readiness/growth" in claim_boundary
    assert "universal cli" in claim_boundary
    assert "credential/file-body handling" in claim_boundary
