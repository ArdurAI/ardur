"""Tests for the Ardur Claude Code hook adapter."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from cryptography.hazmat.primitives.asymmetric import ec

from vibap.claude_code_hook import (
    ChainState,
    DEFAULT_CHAIN_DIR,
    append_receipt,
    load_active_passport,
    MissionLoadError,
    previous_receipt_hash,
)
from vibap.passport import (
    MissionPassport,
    generate_keypair,
    issue_passport,
)


_FAKE_DAEMON_ACCEPT_TIMEOUT_S = 10.0
_TEST_DAEMON_TIMEOUT_MS = "1000"


def _issue_test_passport(tmp_path: Path) -> tuple[str, ec.EllipticCurvePrivateKey]:
    private_key, _public_key = generate_keypair(keys_dir=tmp_path)
    mission = MissionPassport(
        agent_id="alice",
        mission="test mission",
        allowed_tools=["Read"],
        forbidden_tools=["Bash"],
        resource_scope=["/tmp/*"],
        max_tool_calls=10,
        max_duration_s=600,
    )
    token = issue_passport(mission, private_key, ttl_s=3600)
    return token, private_key


def _deny_reason(output: dict) -> str:
    hook_output = output["hookSpecificOutput"]
    assert hook_output["hookEventName"] == "PreToolUse"
    assert hook_output["permissionDecision"] == "deny"
    return hook_output["permissionDecisionReason"]


def _issue_wildcard_test_passport(
    tmp_path: Path,
    *,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    private_key, _public_key = generate_keypair(keys_dir=tmp_path)
    mission = MissionPassport(
        agent_id="alice",
        mission="test Claude Code trace path containment",
        allowed_tools=["*"],
        forbidden_tools=[],
        resource_scope=[],
        max_tool_calls=20,
        max_duration_s=600,
    )
    return issue_passport(mission, private_key, ttl_s=3600, extra_claims=extra_claims)


def _exercise_receipt_lock_and_subagent_sinks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    token: str,
) -> Path:
    chain_dir = tmp_path / "chain"
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(chain_dir))

    from vibap.claude_code_hook import handle_post_tool_use, handle_pre_tool_use, handle_subagent_start

    pre_output = handle_pre_tool_use(
        {
            "session_id": "sess-1",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_use_id": "toolu_read_1",
            "tool_input": {"file_path": str(tmp_path / "README.md")},
        },
        keys_dir=tmp_path,
    )
    assert pre_output["continue"] is True

    post_output = handle_post_tool_use(
        {
            "session_id": "sess-1",
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_use_id": "toolu_read_1",
            "tool_input": {"file_path": str(tmp_path / "README.md")},
            "tool_response": {"content": "hello"},
        },
        keys_dir=tmp_path,
    )
    assert post_output == {"continue": True}

    start_output = handle_subagent_start(
        {
            "session_id": "sess-1",
            "hook_event_name": "SubagentStart",
            "agent_id": "agent-child-1",
            "agent_type": "Explore",
        },
        keys_dir=tmp_path,
    )
    assert start_output["hookSpecificOutput"]["hookEventName"] == "SubagentStart"
    return chain_dir


def _assert_chain_artifacts_are_single_nested_trace(chain_dir: Path) -> Path:
    receipts = list(chain_dir.rglob("receipts.jsonl"))
    locks = list(chain_dir.rglob(".lock"))
    registries = list(chain_dir.rglob("subagents.jsonl"))
    assert len(receipts) == 1
    assert len(locks) == 1
    assert len(registries) == 1

    trace_dir = receipts[0].parent
    assert trace_dir.resolve().parent == chain_dir.resolve()
    assert locks[0].parent == trace_dir
    assert registries[0].parent == trace_dir
    assert (chain_dir / "receipts.jsonl").exists() is False
    assert (chain_dir / ".lock").exists() is False
    assert (chain_dir / "subagents.jsonl").exists() is False
    assert len(receipts[0].read_text(encoding="utf-8").splitlines()) == 3
    assert len(registries[0].read_text(encoding="utf-8").splitlines()) == 1
    return trace_dir


def test_loads_passport_from_env_var_path(tmp_path, monkeypatch):
    token, _ = _issue_test_passport(tmp_path)
    passport_file = tmp_path / "active.jwt"
    passport_file.write_text(token, encoding="utf-8")
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", str(passport_file))
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))

    claims = load_active_passport(keys_dir=tmp_path)
    assert claims["sub"] == "alice"
    assert claims["mission"] == "test mission"


def test_loads_passport_from_literal_jwt_in_env_var(tmp_path, monkeypatch):
    token, _ = _issue_test_passport(tmp_path)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))

    claims = load_active_passport(keys_dir=tmp_path)
    assert claims["sub"] == "alice"


def test_returns_error_when_no_passport_anywhere(tmp_path, monkeypatch):
    # Pre-generate the keypair so the missing-keys path is not the failure
    # mode being tested; the failure being tested here is "no passport".
    generate_keypair(keys_dir=tmp_path)
    monkeypatch.delenv("ARDUR_MISSION_PASSPORT", raising=False)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))

    with pytest.raises(MissionLoadError) as exc_info:
        load_active_passport(keys_dir=tmp_path)
    assert "no active mission passport" in str(exc_info.value).lower()


def test_returns_error_on_signature_mismatch(tmp_path, monkeypatch):
    token, _ = _issue_test_passport(tmp_path)
    # Pre-generate a DIFFERENT keypair under other_keys so load_public_key
    # returns a non-matching public key. (VIBAP_HOME is not load-bearing
    # here because the passport is delivered as a literal JWT via the env
    # var; only keys_dir affects which public key verify_passport sees.)
    other_keys = tmp_path / "other"
    other_keys.mkdir()
    generate_keypair(keys_dir=other_keys)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(other_keys))

    with pytest.raises(MissionLoadError) as exc_info:
        load_active_passport(keys_dir=other_keys)
    assert "signature" in str(exc_info.value).lower() or "verify" in str(exc_info.value).lower()


def test_empty_vibap_home_falls_back_to_default_home(tmp_path, monkeypatch):
    # VIBAP_HOME="" must NOT be interpreted as "use cwd"; the loader should
    # treat it the same as unset and fall through to DEFAULT_HOME.
    generate_keypair(keys_dir=tmp_path)
    monkeypatch.delenv("ARDUR_MISSION_PASSPORT", raising=False)
    monkeypatch.setenv("VIBAP_HOME", "")  # explicit empty string

    with pytest.raises(MissionLoadError) as exc_info:
        load_active_passport(keys_dir=tmp_path)
    # The error here is "no passport" (the loader didn't crash on empty
    # string and didn't find a passport in CWD/.vibap).
    assert "no active mission passport" in str(exc_info.value).lower()


def test_jwt_heuristic_does_not_misclassify_path_starting_with_ey(tmp_path, monkeypatch):
    # A path-like value starting with "ey" but not "eyJ" must be treated
    # as a path, not a literal JWT. Without keys we expect either a
    # missing-keys MissionLoadError or a no-passport MissionLoadError —
    # never an "all candidate passports failed verification" error
    # (which would mean the loader tried to decode the path as a JWT).
    generate_keypair(keys_dir=tmp_path)
    fake_path = tmp_path / "eya_relative_file.json"
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", str(fake_path))
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))

    with pytest.raises(MissionLoadError) as exc_info:
        load_active_passport(keys_dir=tmp_path)
    msg = str(exc_info.value).lower()
    assert "no active mission passport" in msg
    assert "failed verification" not in msg


def test_empty_chain_returns_none(tmp_path):
    state = ChainState(chain_dir=tmp_path, trace_id="trace-1")
    assert previous_receipt_hash(state) is None


def test_single_entry_returns_its_hash(tmp_path):
    state = ChainState(chain_dir=tmp_path, trace_id="trace-1")
    fake_jwt = "fake.signed.jwt"
    append_receipt(state, fake_jwt)
    expected = "sha-256:" + hashlib.sha256(fake_jwt.encode("utf-8")).hexdigest()
    assert previous_receipt_hash(state) == expected


def test_multi_entry_returns_last_hash(tmp_path):
    state = ChainState(chain_dir=tmp_path, trace_id="trace-1")
    append_receipt(state, "first.jwt.x")
    append_receipt(state, "second.jwt.y")
    append_receipt(state, "third.jwt.z")
    expected = "sha-256:" + hashlib.sha256("third.jwt.z".encode("utf-8")).hexdigest()
    assert previous_receipt_hash(state) == expected


def test_chain_per_trace_does_not_collide(tmp_path):
    state_a = ChainState(chain_dir=tmp_path, trace_id="trace-a")
    state_b = ChainState(chain_dir=tmp_path, trace_id="trace-b")
    append_receipt(state_a, "a-only.jwt")
    append_receipt(state_b, "b-only.jwt")
    assert previous_receipt_hash(state_a) == "sha-256:" + hashlib.sha256("a-only.jwt".encode()).hexdigest()
    assert previous_receipt_hash(state_b) == "sha-256:" + hashlib.sha256("b-only.jwt".encode()).hexdigest()


@pytest.mark.parametrize(
    "bad_trace_id",
    [".", "..", "bad/trace", r"bad\trace", "/tmp/absolute-out", "bad trace"],
)
def test_unsafe_env_trace_ids_do_not_escape_or_collapse_chain_paths_across_hook_sinks(
    tmp_path,
    monkeypatch,
    bad_trace_id: str,
):
    token = _issue_wildcard_test_passport(tmp_path)
    monkeypatch.setenv("ARDUR_TRACE_ID", bad_trace_id)

    chain_dir = _exercise_receipt_lock_and_subagent_sinks(tmp_path, monkeypatch, token)

    assert not (tmp_path / "receipts.jsonl").exists()
    assert not (tmp_path / ".lock").exists()
    assert not (tmp_path / "subagents.jsonl").exists()
    trace_dir = _assert_chain_artifacts_are_single_nested_trace(chain_dir)
    assert trace_dir.name != bad_trace_id
    assert "/" not in trace_dir.name
    assert "\\" not in trace_dir.name


def test_unsafe_passport_jti_fallback_material_is_contained_and_single_segment(tmp_path, monkeypatch):
    cases = {
        "dotdot": "../passport-out",
        "slash": "bad/trace",
        "backslash": r"bad\trace",
        "absolute": str(tmp_path / "absolute-out"),
        "space": "bad trace",
    }
    for name, bad_jti in cases.items():
        case_dir = tmp_path / name
        case_dir.mkdir()
        token = _issue_wildcard_test_passport(case_dir, extra_claims={"jti": bad_jti})
        monkeypatch.delenv("ARDUR_TRACE_ID", raising=False)

        chain_dir = _exercise_receipt_lock_and_subagent_sinks(case_dir, monkeypatch, token)

        assert not (case_dir / "receipts.jsonl").exists()
        assert not (case_dir / ".lock").exists()
        assert not (case_dir / "subagents.jsonl").exists()
        trace_dir = _assert_chain_artifacts_are_single_nested_trace(chain_dir)
        assert trace_dir.name.startswith("trace-")
        assert "/" not in trace_dir.name
        assert "\\" not in trace_dir.name
        assert trace_dir.name not in {".", "..", "bad", "trace", "passport-out", "absolute-out"}


def test_safe_dot_containing_env_trace_id_is_preserved_as_single_segment(tmp_path, monkeypatch):
    token = _issue_wildcard_test_passport(tmp_path)
    monkeypatch.setenv("ARDUR_TRACE_ID", "trace.v1-alpha_2")

    chain_dir = _exercise_receipt_lock_and_subagent_sinks(tmp_path, monkeypatch, token)

    trace_dir = _assert_chain_artifacts_are_single_nested_trace(chain_dir)
    assert trace_dir.name == "trace.v1-alpha_2"


def test_resolve_chain_state_rejects_path_material_before_artifact_creation(tmp_path, monkeypatch):
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))
    from vibap.claude_code_hook import resolve_chain_state

    unsafe_trace_ids = [
        ".",
        "..",
        "bad/trace",
        r"bad\trace",
        str(tmp_path / "absolute-out"),
        "bad trace",
    ]
    for trace_id in unsafe_trace_ids:
        with pytest.raises(ValueError):
            resolve_chain_state(trace_id=trace_id)

    assert not (tmp_path / "receipts.jsonl").exists()
    assert not (tmp_path / ".lock").exists()
    assert not (tmp_path / "subagents.jsonl").exists()
    assert not (tmp_path / "chain").exists()


def test_allow_path_returns_continue_true_and_chains_receipt(tmp_path, monkeypatch):
    token, _ = _issue_test_passport(tmp_path)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))

    from vibap.claude_code_hook import handle_pre_tool_use

    hook_input = {
        "session_id": "sess-1",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/tmp/x.txt"},
    }
    output = handle_pre_tool_use(hook_input, keys_dir=tmp_path)

    assert output["continue"] is True
    assert "receipt" in output["systemMessage"].lower()

    # Receipt was appended to the chain.
    receipts = list((tmp_path / "chain").rglob("receipts.jsonl"))
    assert len(receipts) == 1
    lines = receipts[0].read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    # First receipt in a fresh chain must have parent_receipt_hash=None
    # (signals "root receipt"). Inspect the JWT claims without verifying
    # the signature — the test isn't asserting receipt validity here, just
    # the chain semantics.
    import jwt as pyjwt
    claims = pyjwt.decode(lines[0].strip(), options={"verify_signature": False})
    assert claims.get("parent_receipt_hash") is None

    # C1: content-class telemetry fields are backfilled into the signed
    # receipt payload. content_class and content_provenance survive from the
    # mapper; instruction_bearing is the bool from the mapper.
    assert claims.get("content_class") == "user_input"
    assert claims.get("content_provenance") == {"source": "claude_code_tool_input"}
    assert claims.get("instruction_bearing") is False

    # C2: step_id carries the ":pre" phase suffix to disambiguate from
    # the Post receipt for the same call.
    assert claims.get("step_id", "").endswith(":pre")


def test_wildcard_allowed_tools_permits_agent_dispatch_and_reports_it(tmp_path, monkeypatch):
    private_key, _public_key = generate_keypair(keys_dir=tmp_path)
    mission = MissionPassport(
        agent_id="alice",
        mission="observe subagent launch",
        allowed_tools=["*"],
        forbidden_tools=[],
        resource_scope=[],
        max_tool_calls=10,
        max_duration_s=600,
    )
    token = issue_passport(mission, private_key, ttl_s=3600)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))

    from vibap.claude_code_hook import handle_pre_tool_use
    from vibap.claude_code_report import build_claude_code_report

    output = handle_pre_tool_use(
        {
            "session_id": "sess-1",
            "hook_event_name": "PreToolUse",
            "tool_name": "Agent",
            "tool_input": {
                "agent_type": "general-purpose",
                "description": "Read README title",
                "prompt": "Use Read to inspect README.md",
            },
        },
        keys_dir=tmp_path,
    )

    assert output["continue"] is True
    report = build_claude_code_report(
        home=tmp_path,
        chain_dir=tmp_path / "chain",
        keys_dir=tmp_path,
        verify_expiry=False,
    )
    assert report["totals"]["dispatch_count"] == 1
    assert report["totals"]["dispatch_launch_count"] == 1
    assert report["totals"]["dispatch_observation_count"] == 0
    assert report["totals"]["dispatch_receipt_count"] == 1
    assert report["totals"]["tools"] == {"Agent": 1}
    assert report["totals"]["side_effect_classes"] == {"subagent_launch": 1}


def test_subagent_lifecycle_receipts_and_report_derived_tool_attribution(tmp_path, monkeypatch):
    private_key, _public_key = generate_keypair(keys_dir=tmp_path)
    mission = MissionPassport(
        agent_id="alice",
        mission="observe child lifecycle",
        allowed_tools=["*"],
        forbidden_tools=[],
        resource_scope=[],
        max_tool_calls=20,
        max_duration_s=600,
    )
    token = issue_passport(mission, private_key, ttl_s=3600)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))

    child_transcript = tmp_path / "subagents" / "agent-child-1.jsonl"
    child_transcript.parent.mkdir()
    child_transcript.write_text('{"tool_use_id":"toolu_read_1"}\n', encoding="utf-8")
    parent_transcript = tmp_path / "parent.jsonl"
    parent_transcript.write_text("{}\n", encoding="utf-8")

    from vibap.claude_code_hook import (
        handle_pre_tool_use,
        handle_post_tool_use,
        handle_subagent_start,
        handle_subagent_stop,
    )
    from vibap.claude_code_report import build_claude_code_report

    start_output = handle_subagent_start(
        {
            "session_id": "sess-1",
            "transcript_path": str(parent_transcript),
            "cwd": str(tmp_path),
            "hook_event_name": "SubagentStart",
            "agent_id": "agent-child-1",
            "agent_type": "Explore",
        },
        keys_dir=tmp_path,
    )
    assert start_output["hookSpecificOutput"]["hookEventName"] == "SubagentStart"
    assert "child:" in start_output["hookSpecificOutput"]["additionalContext"]

    handle_pre_tool_use(
        {
            "session_id": "sess-1",
            "transcript_path": str(child_transcript),
            "cwd": str(tmp_path),
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_use_id": "toolu_read_1",
            "tool_input": {"file_path": str(tmp_path / "README.md")},
        },
        keys_dir=tmp_path,
    )
    handle_post_tool_use(
        {
            "session_id": "sess-1",
            "transcript_path": str(child_transcript),
            "cwd": str(tmp_path),
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_use_id": "toolu_read_1",
            "tool_input": {"file_path": str(tmp_path / "README.md")},
            "tool_response": {"content": "hello"},
        },
        keys_dir=tmp_path,
    )
    stop_output = handle_subagent_stop(
        {
            "session_id": "sess-1",
            "transcript_path": str(parent_transcript),
            "cwd": str(tmp_path),
            "hook_event_name": "SubagentStop",
            "agent_id": "agent-child-1",
            "agent_type": "Explore",
            "agent_transcript_path": str(child_transcript),
            "last_assistant_message": "done",
        },
        keys_dir=tmp_path,
    )
    assert stop_output == {"continue": True}

    receipts = list((tmp_path / "chain").rglob("receipts.jsonl"))
    assert len(receipts) == 1
    lines = [line.strip() for line in receipts[0].read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 4
    import jwt as pyjwt
    claims = [pyjwt.decode(line, options={"verify_signature": False}) for line in lines]
    assert [claim["tool"] for claim in claims] == ["SubagentStart", "Read", "Read", "SubagentStop"]
    start_meta = claims[0]["measurements"]["claude_code"]
    assert start_meta["claude_agent_id"] == "agent-child-1"
    assert start_meta["actor_kind"] == "subagent"
    assert start_meta["attribution"]["mode"] == "exact"
    read_meta = claims[1]["measurements"]["claude_code"]
    assert read_meta["tool_use_id"] == "toolu_read_1"
    assert read_meta["actor_kind"] == "unattributed"
    stop_meta = claims[-1]["measurements"]["claude_code"]
    assert stop_meta["final_response_hash"]["alg"] == "sha-256"
    assert stop_meta["child_receipt_summary"]["receipt_count"] == 2

    registry = list((tmp_path / "chain").rglob("subagents.jsonl"))
    assert len(registry) == 1
    assert len(registry[0].read_text(encoding="utf-8").splitlines()) == 2

    report = build_claude_code_report(
        home=tmp_path,
        chain_dir=tmp_path / "chain",
        keys_dir=tmp_path,
        verify_expiry=False,
    )
    assert report["chain_verification"]["ok"] is True
    assert report["totals"]["subagents_started"] == 1
    assert report["totals"]["subagents_stopped"] == 1
    assert report["coverage"]["per_child_attribution"] == "derived"
    assert report["totals"]["unattributed_tool_receipt_count"] == 0
    subagent = report["chains"][0]["subagents"][0]
    assert subagent["claude_agent_id"] == "agent-child-1"
    assert subagent["tool_receipt_count"] == 2
    assert subagent["tools"] == {"Read": 2}
    assert subagent["attribution_modes"] == {"derived": 2}


def test_report_keeps_unmatched_child_tools_trace_only(tmp_path, monkeypatch):
    private_key, _public_key = generate_keypair(keys_dir=tmp_path)
    mission = MissionPassport(
        agent_id="alice",
        mission="do not guess child attribution",
        allowed_tools=["*"],
        forbidden_tools=[],
        resource_scope=[],
        max_tool_calls=20,
        max_duration_s=600,
    )
    token = issue_passport(mission, private_key, ttl_s=3600)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))

    child_transcript = tmp_path / "subagents" / "agent-child-2.jsonl"
    child_transcript.parent.mkdir()
    child_transcript.write_text('{"tool_use_id":"different_tool"}\n', encoding="utf-8")
    parent_transcript = tmp_path / "parent.jsonl"
    parent_transcript.write_text("{}\n", encoding="utf-8")

    from vibap.claude_code_hook import handle_pre_tool_use, handle_subagent_start, handle_subagent_stop
    from vibap.claude_code_report import build_claude_code_report

    handle_subagent_start(
        {
            "session_id": "sess-1",
            "transcript_path": str(parent_transcript),
            "cwd": str(tmp_path),
            "hook_event_name": "SubagentStart",
            "agent_id": "agent-child-2",
            "agent_type": "Explore",
        },
        keys_dir=tmp_path,
    )
    handle_pre_tool_use(
        {
            "session_id": "sess-1",
            "transcript_path": str(parent_transcript),
            "cwd": str(tmp_path),
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_use_id": "toolu_unmatched",
            "tool_input": {"file_path": str(tmp_path / "README.md")},
        },
        keys_dir=tmp_path,
    )
    handle_subagent_stop(
        {
            "session_id": "sess-1",
            "transcript_path": str(parent_transcript),
            "cwd": str(tmp_path),
            "hook_event_name": "SubagentStop",
            "agent_id": "agent-child-2",
            "agent_type": "Explore",
            "agent_transcript_path": str(child_transcript),
        },
        keys_dir=tmp_path,
    )

    report = build_claude_code_report(
        home=tmp_path,
        chain_dir=tmp_path / "chain",
        keys_dir=tmp_path,
        verify_expiry=False,
    )
    assert report["coverage"]["per_child_attribution"] == "trace_only"
    assert report["totals"]["unattributed_tool_receipt_count"] == 1
    assert report["chains"][0]["unattributed_tool_receipts"][0]["tool_use_id"] == "toolu_unmatched"


def test_long_scoped_bash_command_is_not_denied_by_truncated_target(tmp_path, monkeypatch):
    private_key, _public_key = generate_keypair(keys_dir=tmp_path)
    scope = tmp_path / "scope"
    nested = scope / "a" / "b" / "c" / "d"
    nested.mkdir(parents=True)
    mission = MissionPassport(
        agent_id="alice",
        mission="allow long scoped bash",
        allowed_tools=["Bash"],
        forbidden_tools=[],
        resource_scope=[str(scope), f"{scope}/*"],
        max_tool_calls=10,
        max_duration_s=600,
    )
    token = issue_passport(mission, private_key, ttl_s=3600)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))

    from vibap.claude_code_hook import handle_pre_tool_use

    command = f"ls -la {nested} {nested} {nested} {nested}"
    assert len(command) > 128
    output = handle_pre_tool_use(
        {
            "session_id": "sess-1",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        },
        keys_dir=tmp_path,
    )

    assert output["continue"] is True


def test_parallel_pre_tool_use_processes_serialize_receipt_chain(tmp_path):
    import json
    import os
    import subprocess
    import sys

    private_key, public_key = generate_keypair(keys_dir=tmp_path)
    mission = MissionPassport(
        agent_id="alice",
        mission="parallel subagent launch",
        allowed_tools=["Agent"],
        forbidden_tools=[],
        resource_scope=[],
        max_tool_calls=20,
        max_duration_s=600,
    )
    token = issue_passport(mission, private_key, ttl_s=3600)
    repo_root = Path(__file__).resolve().parents[2]
    env = {
        **os.environ,
        "ARDUR_MISSION_PASSPORT": token,
        "VIBAP_HOME": str(tmp_path),
        "ARDUR_CC_HOOK_DIR": str(tmp_path / "chain"),
        "PYTHONPATH": str(repo_root / "python"),
    }

    processes = []
    for index in range(5):
        hook_input = json.dumps(
            {
                "session_id": "sess-1",
                "hook_event_name": "PreToolUse",
                "tool_name": "Agent",
                "tool_input": {
                    "agent_type": "general-purpose",
                    "description": f"parallel agent {index}",
                    "prompt": "Use a tool and write a short report.",
                },
            }
        )
        processes.append(
            subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "vibap.claude_code_hook",
                    "pre",
                    "--keys-dir",
                    str(tmp_path),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
        )
        processes[-1].stdin.write(hook_input)
        processes[-1].stdin.close()

    for process in processes:
        stdout = process.stdout.read()
        stderr = process.stderr.read()
        assert process.wait(timeout=10) == 0, stderr
        assert json.loads(stdout)["continue"] is True

    receipts = list((tmp_path / "chain").rglob("receipts.jsonl"))
    assert len(receipts) == 1
    lines = [line.strip() for line in receipts[0].read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 5

    from vibap.receipt import verify_chain

    verify_chain(lines, public_key, verify_expiry=False)


def test_deny_path_returns_continue_false_with_stop_reason(tmp_path, monkeypatch):
    # Reuse the canonical test helper; it already sets forbidden_tools=["Bash"].
    token, _ = _issue_test_passport(tmp_path)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))

    from vibap.claude_code_hook import handle_pre_tool_use
    output = handle_pre_tool_use(
        {
            "session_id": "sess-1",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
        },
        keys_dir=tmp_path,
    )

    assert "ardur:" in _deny_reason(output).lower()
    receipts = list((tmp_path / "chain").rglob("receipts.jsonl"))
    assert len(receipts) == 1
    lines = receipts[0].read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    # Audit trail: the appended receipt MUST carry a non-compliant verdict.
    # Inspect without verifying signature — we only care about chain semantics.
    import jwt as pyjwt
    claims = pyjwt.decode(lines[0].strip(), options={"verify_signature": False})
    assert claims.get("verdict") == "violation"


def test_post_tool_use_chains_to_pre_and_records_result_hash(tmp_path, monkeypatch):
    token, _ = _issue_test_passport(tmp_path)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))

    # First, run PreToolUse to seed the chain.
    from vibap.claude_code_hook import handle_pre_tool_use, handle_post_tool_use
    handle_pre_tool_use(
        {
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/x.txt"},
        },
        keys_dir=tmp_path,
    )

    # Then PostToolUse for the same call.
    output = handle_post_tool_use(
        {
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/x.txt"},
            "tool_response": {"content": "file body", "exit_code": 0},
        },
        keys_dir=tmp_path,
    )
    assert output == {"continue": True}
    receipts = list((tmp_path / "chain").rglob("receipts.jsonl"))
    assert len(receipts) == 1
    lines = receipts[0].read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2  # pre + post

    # Chain integrity: the post receipt must reference the pre receipt's
    # JWT hash as its parent. This is the core invariant the receipt chain
    # is built around — without it, an auditor cannot verify ordering.
    # parent_receipt_hash is stored as bare 64-char hex (no "sha-256:" prefix)
    # so that verify_chain can compare it directly against its own computed hash.
    import hashlib as _hashlib
    import jwt as pyjwt
    pre_jwt = lines[0].strip()
    post_jwt = lines[1].strip()
    expected_parent = _hashlib.sha256(pre_jwt.encode("utf-8")).hexdigest()
    pre_claims = pyjwt.decode(pre_jwt, options={"verify_signature": False})
    post_claims = pyjwt.decode(post_jwt, options={"verify_signature": False})
    assert post_claims.get("parent_receipt_hash") == expected_parent
    assert post_claims.get("verdict") == "compliant"
    # Result hash present and well-formed.
    rh = post_claims.get("result_hash")
    assert isinstance(rh, dict)
    assert rh.get("alg") == "sha-256"
    assert isinstance(rh.get("value"), str) and len(rh["value"]) == 64

    # C2: Pre and Post receipts MUST have distinct step_ids — the deterministic
    # base derivation hashes the same inputs, so without the phase suffix
    # they would collide on calls that fall in the same wall-clock second.
    assert pre_claims.get("step_id", "").endswith(":pre")
    assert post_claims.get("step_id", "").endswith(":post")
    assert pre_claims["step_id"] != post_claims["step_id"]

    # C1: content-class telemetry fields appear on the post receipt too.
    assert post_claims.get("content_class") == "user_input"
    assert post_claims.get("content_provenance") == {"source": "claude_code_tool_input"}
    assert post_claims.get("instruction_bearing") is False


def test_main_pre_reads_stdin_writes_stdout(tmp_path, monkeypatch):
    import json
    import os
    import subprocess
    import sys

    token, _ = _issue_test_passport(tmp_path)
    env = {**os.environ}
    env["ARDUR_MISSION_PASSPORT"] = token
    env["VIBAP_HOME"] = str(tmp_path)
    env["ARDUR_CC_HOOK_DIR"] = str(tmp_path / "chain")

    hook_input = json.dumps({
        "tool_name": "Read",
        "tool_input": {"file_path": "/tmp/x.txt"},
    })
    repo_root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "-m", "vibap.claude_code_hook", "pre",
         "--keys-dir", str(tmp_path)],
        input=hook_input,
        capture_output=True,
        text=True,
        env={**env, "PYTHONPATH": str(repo_root / "python")},
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    output = json.loads(result.stdout)
    assert output["continue"] is True


def test_pre_daemon_first_uses_daemon_output(tmp_path, monkeypatch):
    from vibap import claude_code_daemon as daemon_module
    from vibap import claude_code_hook as hook_module

    monkeypatch.setattr(
        daemon_module,
        "dispatch_pre_tool_use",
        lambda hook_input, *, keys_dir=None: {
            "continue": True,
            "systemMessage": "ardur: daemon pre hook",
        },
    )

    def _local_should_not_run(*_args, **_kwargs):
        raise AssertionError("local pre handler should not run when daemon returns output")

    monkeypatch.setattr(hook_module, "handle_pre_tool_use", _local_should_not_run)
    output = hook_module._handle_pre_tool_use_daemon_first(
        {"tool_name": "Read", "tool_input": {"file_path": "/tmp/x.txt"}},
        keys_dir=tmp_path,
    )
    assert output["continue"] is True
    assert output["systemMessage"] == "ardur: daemon pre hook"


def test_pre_daemon_first_falls_back_when_daemon_unavailable(tmp_path, monkeypatch):
    from vibap import claude_code_daemon as daemon_module
    from vibap import claude_code_hook as hook_module

    monkeypatch.setattr(
        daemon_module,
        "dispatch_pre_tool_use",
        lambda hook_input, *, keys_dir=None: None,
    )

    observed: dict[str, Any] = {}

    def _local_fallback(hook_input, *, keys_dir=None):
        observed["tool_name"] = hook_input["tool_name"]
        observed["keys_dir"] = keys_dir
        return {"continue": True, "systemMessage": "ardur: local fallback"}

    monkeypatch.setattr(hook_module, "handle_pre_tool_use", _local_fallback)
    output = hook_module._handle_pre_tool_use_daemon_first(
        {"tool_name": "Read", "tool_input": {"file_path": "/tmp/fallback.txt"}},
        keys_dir=tmp_path,
    )
    assert output == {"continue": True, "systemMessage": "ardur: local fallback"}
    assert observed == {"tool_name": "Read", "keys_dir": tmp_path}


def test_pre_daemon_first_falls_back_when_daemon_output_is_malformed(tmp_path, monkeypatch):
    from vibap import claude_code_daemon as daemon_module
    from vibap import claude_code_hook as hook_module

    monkeypatch.setattr(
        daemon_module,
        "dispatch_pre_tool_use",
        lambda hook_input, *, keys_dir=None: {"ok": True, "output": {"not": "hook-output"}},
    )

    observed: dict[str, Any] = {}

    def _local_fallback(hook_input, *, keys_dir=None):
        observed["tool_name"] = hook_input["tool_name"]
        observed["keys_dir"] = keys_dir
        return {"continue": True, "systemMessage": "ardur: local fallback from malformed daemon output"}

    monkeypatch.setattr(hook_module, "handle_pre_tool_use", _local_fallback)
    output = hook_module._handle_pre_tool_use_daemon_first(
        {"tool_name": "Read", "tool_input": {"file_path": "/tmp/malformed.txt"}},
        keys_dir=tmp_path,
    )
    assert output == {
        "continue": True,
        "systemMessage": "ardur: local fallback from malformed daemon output",
    }
    assert observed == {"tool_name": "Read", "keys_dir": tmp_path}


def test_daemon_benchmark_helper_returns_duration_samples(tmp_path, monkeypatch):
    from vibap import claude_code_daemon as daemon_module

    token, _ = _issue_test_passport(tmp_path)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))

    result = daemon_module.benchmark_pre_tool_use_hot_path(
        hook_input={"tool_name": "Read", "tool_input": {"file_path": "/tmp/bench.txt"}},
        keys_dir=tmp_path,
        iterations=3,
    )
    samples = result["durations_ms"]
    assert isinstance(samples, list)
    assert len(samples) == 3
    assert all(sample >= 0 for sample in samples)
    assert result["p95_ms"] >= 0


def test_dispatch_pre_tool_use_rejects_malformed_ok_envelope(tmp_path, monkeypatch):
    import os
    import socket
    import threading
    import uuid

    from vibap import claude_code_daemon as daemon_module

    token, _ = _issue_test_passport(tmp_path)
    socket_parent = Path(f"/tmp/ardur-daemon-malformed-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "hook.sock"

    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))
    monkeypatch.setenv("ARDUR_CC_HOOK_DAEMON", "1")
    monkeypatch.setenv("ARDUR_CC_HOOK_DAEMON_SOCKET", str(socket_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS", _TEST_DAEMON_TIMEOUT_MS)

    ready = threading.Event()
    failures: list[Exception] = []
    observed = {"requests": 0}

    def _serve_malformed_response() -> None:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(socket_path))
                server.listen(2)
                # Allow enough time for client connect under CI scheduling jitter.
                server.settimeout(_FAKE_DAEMON_ACCEPT_TIMEOUT_S)
                ready.set()
                while observed["requests"] < 1:
                    try:
                        conn, _ = server.accept()
                    except TimeoutError:
                        break
                    with conn:
                        _ = conn.recv(8192)
                        observed["requests"] += 1
                        conn.sendall(b'{"ok":true,"output":{"not":"hook-output"}}\\n')
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            failures.append(exc)

    thread = threading.Thread(target=_serve_malformed_response, daemon=True)
    thread.start()

    try:
        assert ready.wait(timeout=2)
        output = daemon_module.dispatch_pre_tool_use(
            {
                "session_id": "daemon-malformed-envelope-session",
                "tool_name": "Read",
                "tool_input": {"file_path": "/tmp/daemon-malformed-envelope.txt"},
                "tool_use_id": "daemon-malformed-envelope-call",
            },
            keys_dir=tmp_path,
        )

        thread.join(timeout=3)
        assert not failures
        assert observed["requests"] == 1
        assert output is None
    finally:
        if socket_path.exists():
            socket_path.unlink()
        if socket_parent.exists():
            socket_parent.rmdir()


def test_pre_daemon_first_end_to_end_unix_socket(tmp_path, monkeypatch):
    import os
    import threading
    import time
    import uuid

    from vibap import claude_code_daemon as daemon_module

    token, _ = _issue_test_passport(tmp_path)
    socket_parent = Path(f"/tmp/ardur-daemon-e2e-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "hook.sock"
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))
    monkeypatch.setenv("ARDUR_CC_HOOK_DAEMON", "1")
    monkeypatch.setenv("ARDUR_CC_HOOK_DAEMON_SOCKET", str(socket_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS", _TEST_DAEMON_TIMEOUT_MS)

    observed: dict[str, Any] = {}
    failures: list[Exception] = []

    def _serve() -> None:
        try:
            observed["handled"] = daemon_module.serve_pre_tool_use_daemon(
                socket_path=socket_path,
                keys_dir=tmp_path,
                max_requests=1,
            )
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            failures.append(exc)

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()

    for _ in range(100):
        if socket_path.exists():
            break
        time.sleep(0.01)
    assert socket_path.exists()

    output = None
    for _ in range(100):
        output = daemon_module.dispatch_pre_tool_use(
            {
                "session_id": "daemon-e2e-session",
                "tool_name": "Read",
                "tool_input": {"file_path": "/tmp/daemon-e2e.txt"},
                "tool_use_id": "daemon-e2e-call",
            },
            keys_dir=tmp_path,
        )
        if output is not None:
            break
        time.sleep(0.01)
    assert output is not None
    assert output["continue"] is True
    assert "ardur:" in output["systemMessage"].lower()

    thread.join(timeout=5)
    assert not failures
    assert not thread.is_alive()
    assert observed["handled"] == 1

    if socket_path.exists():
        socket_path.unlink()
    if socket_parent.exists():
        socket_parent.rmdir()


def test_daemon_ignores_response_write_failures(tmp_path, monkeypatch):
    import os
    import socket
    import threading
    import time
    import uuid

    from vibap import claude_code_daemon as daemon_module

    token, _ = _issue_test_passport(tmp_path)
    socket_parent = Path(f"/tmp/ardur-daemon-broken-pipe-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "hook.sock"
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))
    monkeypatch.setenv("ARDUR_CC_HOOK_DAEMON_SOCKET", str(socket_path))

    def _always_raise(*_args, **_kwargs):
        raise BrokenPipeError("simulated client disconnect")

    monkeypatch.setattr(daemon_module, "_write_json_line", _always_raise)

    observed: dict[str, Any] = {}
    failures: list[Exception] = []

    def _serve() -> None:
        try:
            observed["handled"] = daemon_module.serve_pre_tool_use_daemon(
                socket_path=socket_path,
                keys_dir=tmp_path,
                max_requests=1,
            )
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            failures.append(exc)

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()

    for _ in range(100):
        if socket_path.exists():
            break
        time.sleep(0.01)
    assert socket_path.exists()

    connected = False
    for _ in range(100):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.connect(str(socket_path))
                conn.sendall(
                    b'{"phase":"pre","hook_input":{"tool_name":"Read","tool_input":{"file_path":"/tmp/disconnect.txt"}}}\n'
                )
            connected = True
            break
        except ConnectionRefusedError:
            time.sleep(0.01)
    assert connected, "daemon socket never accepted connections"

    thread.join(timeout=5)
    assert not failures
    assert not thread.is_alive()
    assert observed["handled"] == 1

    if socket_path.exists():
        socket_path.unlink()
    if socket_parent.exists():
        socket_parent.rmdir()


def test_daemon_refuses_to_unlink_non_socket_stale_path(tmp_path):
    from vibap import claude_code_daemon as daemon_module

    stale_path = tmp_path / "not-a-socket.sock"
    stale_path.write_text("this is not a unix socket", encoding="utf-8")

    with pytest.raises(RuntimeError, match="non-socket"):
        daemon_module.serve_pre_tool_use_daemon(
            socket_path=stale_path,
            max_requests=1,
        )


def test_daemon_unlinks_stale_unix_socket_path(tmp_path):
    import os
    import socket
    import uuid

    from vibap import claude_code_daemon as daemon_module

    # AF_UNIX paths are short on macOS, so use /tmp rather than pytest's deep
    # tmp_path for this socket-specific regression.
    stale_path = Path(f"/tmp/ardur-stale-socket-{os.getpid()}-{uuid.uuid4().hex[:8]}.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(stale_path))
    finally:
        server.close()

    try:
        assert stale_path.exists()
        daemon_module._unlink_only_if_socket(stale_path)
        assert not stale_path.exists()
    finally:
        if stale_path.exists():
            stale_path.unlink()


def test_daemon_creates_private_socket_parent_when_missing(tmp_path, monkeypatch):
    import os
    import stat as stat_module
    import threading
    import time
    import uuid

    from vibap import claude_code_daemon as daemon_module

    token, _ = _issue_test_passport(tmp_path)
    socket_parent = Path(f"/tmp/ardur-daemon-private-created-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    socket_path = socket_parent / "hook.sock"
    assert not socket_parent.exists()

    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))
    monkeypatch.setenv("ARDUR_CC_HOOK_DAEMON", "1")
    monkeypatch.setenv("ARDUR_CC_HOOK_DAEMON_SOCKET", str(socket_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS", _TEST_DAEMON_TIMEOUT_MS)

    observed: dict[str, Any] = {}
    failures: list[Exception] = []

    def _serve() -> None:
        try:
            observed["handled"] = daemon_module.serve_pre_tool_use_daemon(
                socket_path=socket_path,
                keys_dir=tmp_path,
                max_requests=1,
            )
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            failures.append(exc)

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()

    try:
        for _ in range(100):
            if socket_path.exists():
                break
            time.sleep(0.01)
        assert socket_path.exists()

        parent_mode = stat_module.S_IMODE(socket_parent.stat().st_mode)
        socket_mode = stat_module.S_IMODE(socket_path.stat().st_mode)
        assert parent_mode == 0o700
        assert socket_mode == 0o600

        output = daemon_module.dispatch_pre_tool_use(
            {
                "session_id": "daemon-private-session",
                "tool_name": "Read",
                "tool_input": {"file_path": "/tmp/daemon-private.txt"},
                "tool_use_id": "daemon-private-call",
            },
            keys_dir=tmp_path,
        )
        assert output is not None
        assert output["continue"] is True

        thread.join(timeout=5)
        assert not failures
        assert not thread.is_alive()
        assert observed["handled"] == 1
    finally:
        if socket_path.exists():
            socket_path.unlink()
        if socket_parent.exists():
            socket_parent.rmdir()


def test_daemon_refuses_preexisting_shared_socket_parent_without_chmod(tmp_path):
    import os
    import stat as stat_module
    import uuid

    from vibap import claude_code_daemon as daemon_module

    socket_path = Path(f"/tmp/ardur-daemon-shared-{os.getpid()}-{uuid.uuid4().hex[:8]}.sock")
    tmp_dir = Path("/tmp")
    original_mode = stat_module.S_IMODE(tmp_dir.stat().st_mode)

    chmod_calls: list[tuple[str, int]] = []
    real_chmod = daemon_module.os.chmod

    def _tracking_chmod(path: os.PathLike[str] | str, mode: int) -> None:
        chmod_calls.append((str(path), mode))
        real_chmod(path, mode)

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(daemon_module.os, "chmod", _tracking_chmod)
    try:
        with pytest.raises(RuntimeError, match="must already be private"):
            daemon_module.serve_pre_tool_use_daemon(
                socket_path=socket_path,
                keys_dir=tmp_path,
                max_requests=1,
            )
    finally:
        monkeypatch.undo()

    assert not socket_path.exists()
    assert stat_module.S_IMODE(tmp_dir.stat().st_mode) == original_mode
    assert not chmod_calls


def test_daemon_refuses_to_replace_active_socket(tmp_path, monkeypatch):
    import os
    import threading
    import time
    import uuid

    from vibap import claude_code_daemon as daemon_module

    token, _ = _issue_test_passport(tmp_path)
    socket_parent = Path(f"/tmp/ardur-daemon-active-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "hook.sock"

    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))
    monkeypatch.setenv("ARDUR_CC_HOOK_DAEMON", "1")
    monkeypatch.setenv("ARDUR_CC_HOOK_DAEMON_SOCKET", str(socket_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS", _TEST_DAEMON_TIMEOUT_MS)

    observed: dict[str, Any] = {}
    failures: list[Exception] = []

    def _serve() -> None:
        try:
            observed["handled"] = daemon_module.serve_pre_tool_use_daemon(
                socket_path=socket_path,
                keys_dir=tmp_path,
                max_requests=2,
            )
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            failures.append(exc)

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()

    try:
        for _ in range(100):
            if socket_path.exists():
                break
            time.sleep(0.01)
        assert socket_path.exists()

        with pytest.raises(RuntimeError, match="active daemon socket"):
            daemon_module.serve_pre_tool_use_daemon(
                socket_path=socket_path,
                keys_dir=tmp_path,
                max_requests=1,
            )

        output = daemon_module.dispatch_pre_tool_use(
            {
                "session_id": "daemon-active-session",
                "tool_name": "Read",
                "tool_input": {"file_path": "/tmp/daemon-active.txt"},
                "tool_use_id": "daemon-active-call",
            },
            keys_dir=tmp_path,
        )
        assert output is not None
        assert output["continue"] is True

        thread.join(timeout=5)
        assert not failures
        assert not thread.is_alive()
        assert observed["handled"] == 2
    finally:
        if socket_path.exists():
            socket_path.unlink()
        if socket_parent.exists():
            socket_parent.rmdir()


def test_wrapper_accepts_native_client_env_alias_before_python_fallback(tmp_path):
    import json
    import os
    import socket
    import subprocess
    import uuid

    repo_root = Path(__file__).resolve().parents[2]
    wrapper = repo_root / "plugins" / "claude-code" / "hooks" / "pre_tool_use"

    socket_parent = Path(f"/tmp/ardur-wrapper-native-alias-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "hook.sock"
    capture_path = tmp_path / "native-stdin.txt"
    native_client = tmp_path / "fake-native-client"
    native_client.write_text(
        "#!/usr/bin/env sh\n"
        "cat > \"$ARDUR_NATIVE_ALIAS_CAPTURE\"\n"
        "printf '{\"continue\":true}\\n'\n",
        encoding="utf-8",
    )
    native_client.chmod(0o700)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(socket_path))
        assert socket_path.exists()

        hook_input = {
            "session_id": "native-alias-session",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/native-alias.txt"},
            "tool_use_id": "native-alias-call",
        }
        env = {
            "HOME": str(tmp_path / "user-home"),
            "PATH": os.environ.get("PATH", ""),
            "VIBAP_HOME": str(tmp_path / "home"),
            "ARDUR_CC_HOOK_DIR": str(tmp_path / "chain"),
            "ARDUR_CC_HOOK_DAEMON": "1",
            "ARDUR_CC_HOOK_DAEMON_SOCKET": str(socket_path),
            "ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS": _TEST_DAEMON_TIMEOUT_MS,
            "ARDUR_CC_HOOK_NATIVE_CLIENT": str(native_client),
            "ARDUR_HOOK_PYTHON": "/bin/false",
            "ARDUR_NATIVE_ALIAS_CAPTURE": str(capture_path),
        }

        result = subprocess.run(
            [str(wrapper)],
            input=json.dumps(hook_input),
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"continue": True}
        assert json.loads(capture_path.read_text(encoding="utf-8")) == hook_input
    finally:
        server.close()
        if socket_path.exists():
            socket_path.unlink()
        if socket_parent.exists():
            socket_parent.rmdir()



def test_wrapper_accepts_pretty_printed_hook_json_when_daemon_disabled(tmp_path):
    import json
    import os
    import subprocess
    import sys

    repo_root = Path(__file__).resolve().parents[2]
    wrapper = repo_root / "plugins" / "claude-code" / "hooks" / "pre_tool_use"

    hook_input = {
        "session_id": "wrapper-pretty-json-session",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/tmp/wrapper-pretty-json.txt"},
        "tool_use_id": "wrapper-pretty-json-call",
    }

    env = {**os.environ}
    env["VIBAP_HOME"] = str(tmp_path)
    env["VIBAP_KEYS_DIR"] = str(tmp_path)
    env["ARDUR_CC_HOOK_DIR"] = str(tmp_path / "chain")
    env["ARDUR_CC_HOOK_DAEMON"] = "0"
    env["ARDUR_HOOK_PYTHON"] = sys.executable
    env["PYTHONPATH"] = (
        str(repo_root / "python")
        if not env.get("PYTHONPATH")
        else str(repo_root / "python") + os.pathsep + env["PYTHONPATH"]
    )

    result = subprocess.run(
        [str(wrapper)],
        input=json.dumps(hook_input, indent=2),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "invalid hook input json" not in result.stderr.lower()
    output = json.loads(result.stdout)
    assert output["hookSpecificOutput"]["hookEventName"] == "PreToolUse"



def test_wrapper_falls_back_when_daemon_returns_error_payload(tmp_path):
    import json
    import os
    import socket
    import subprocess
    import sys
    import threading
    import uuid

    from vibap import claude_code_daemon as daemon_module

    token, _ = _issue_test_passport(tmp_path)
    repo_root = Path(__file__).resolve().parents[2]
    wrapper = repo_root / "plugins" / "claude-code" / "hooks" / "pre_tool_use"

    native_pre_tool_use_command = daemon_module.install_native_pre_tool_use_command(home=tmp_path, force=True)
    if native_pre_tool_use_command is None:
        pytest.xfail("native PreToolUse daemon client could not be built on this host")

    socket_parent = Path(f"/tmp/ardur-wrapper-error-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "hook.sock"

    ready = threading.Event()
    failures: list[Exception] = []
    observed = {"requests": 0}

    def _serve_bad_response() -> None:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(socket_path))
                server.listen(2)
                # Wrapper invocation includes shell + Python startup overhead;
                # keep accept timeout comfortably above typical client latency.
                server.settimeout(_FAKE_DAEMON_ACCEPT_TIMEOUT_S)
                ready.set()
                while observed["requests"] < 1:
                    try:
                        conn, _ = server.accept()
                    except TimeoutError:
                        break
                    with conn:
                        _ = conn.recv(8192)
                        observed["requests"] += 1
                        conn.sendall(b'{"ok":false,"error":"simulated daemon failure"}\\n')
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            failures.append(exc)

    thread = threading.Thread(target=_serve_bad_response, daemon=True)
    thread.start()

    try:
        assert ready.wait(timeout=2)
        env = {**os.environ}
        env["ARDUR_MISSION_PASSPORT"] = token
        env["VIBAP_HOME"] = str(tmp_path)
        env["VIBAP_KEYS_DIR"] = str(tmp_path)
        env["ARDUR_CC_HOOK_DIR"] = str(tmp_path / "chain")
        env["ARDUR_CC_HOOK_DAEMON"] = "1"
        env["ARDUR_CC_HOOK_DAEMON_SOCKET"] = str(socket_path)
        env["ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS"] = "100"
        env["ARDUR_HOOK_PYTHON"] = sys.executable
        env["ARDUR_CC_HOOK_NATIVE_PRE_TOOL_USE"] = str(native_pre_tool_use_command)
        env["PYTHONPATH"] = (
            str(repo_root / "python")
            if not env.get("PYTHONPATH")
            else str(repo_root / "python") + os.pathsep + env["PYTHONPATH"]
        )

        hook_input = json.dumps(
            {
                "session_id": "wrapper-daemon-error-session",
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "/tmp/wrapper-daemon-error.txt"},
                "tool_use_id": "wrapper-daemon-error-call",
            }
        )
        result = subprocess.run(
            [str(wrapper)],
            input=hook_input,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

        thread.join(timeout=3)
        assert not failures
        assert observed["requests"] == 1
        assert result.returncode == 0, result.stderr

        output = json.loads(result.stdout)
        assert output.get("continue") is True
        assert output.get("ok") is None
    finally:
        if socket_path.exists():
            socket_path.unlink()
        if socket_parent.exists():
            socket_parent.rmdir()


@pytest.mark.parametrize(
    "malformed_daemon_response",
    [
        b'{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":5}}\\n',
        b'{"hookSpecificOutput":"oops","hookEventName":"PreToolUse"}\\n',
    ],
)
def test_wrapper_and_python_fallback_rejects_malformed_pretooluse_shape(
    tmp_path,
    malformed_daemon_response,
):
    import json
    import os
    import socket
    import subprocess
    import sys
    import threading
    import uuid

    from vibap import claude_code_daemon as daemon_module

    token, _ = _issue_test_passport(tmp_path)
    repo_root = Path(__file__).resolve().parents[2]
    wrapper = repo_root / "plugins" / "claude-code" / "hooks" / "pre_tool_use"

    native_pre_tool_use_command = daemon_module.install_native_pre_tool_use_command(home=tmp_path, force=True)
    if native_pre_tool_use_command is None:
        pytest.xfail("native PreToolUse daemon client could not be built on this host")

    socket_parent = Path(f"/tmp/ardur-wrapper-invalid-output-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "hook.sock"

    ready = threading.Event()
    failures: list[Exception] = []
    observed = {"requests": 0}

    def _serve_invalid_hook_output() -> None:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(socket_path))
                server.listen(2)
                # Wrapper invocation includes shell + Python startup overhead;
                # keep accept timeout comfortably above typical client latency.
                server.settimeout(_FAKE_DAEMON_ACCEPT_TIMEOUT_S)
                ready.set()
                while observed["requests"] < 1:
                    try:
                        conn, _ = server.accept()
                    except TimeoutError:
                        break
                    with conn:
                        _ = conn.recv(8192)
                        observed["requests"] += 1
                        conn.sendall(malformed_daemon_response)
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            failures.append(exc)

    thread = threading.Thread(target=_serve_invalid_hook_output, daemon=True)
    thread.start()

    try:
        assert ready.wait(timeout=2)
        env = {**os.environ}
        env["ARDUR_MISSION_PASSPORT"] = token
        env["VIBAP_HOME"] = str(tmp_path)
        env["VIBAP_KEYS_DIR"] = str(tmp_path)
        env["ARDUR_CC_HOOK_DIR"] = str(tmp_path / "chain")
        env["ARDUR_CC_HOOK_DAEMON"] = "1"
        env["ARDUR_CC_HOOK_DAEMON_SOCKET"] = str(socket_path)
        env["ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS"] = "100"
        env["ARDUR_HOOK_PYTHON"] = sys.executable
        env["ARDUR_CC_HOOK_NATIVE_PRE_TOOL_USE"] = str(native_pre_tool_use_command)
        env["PYTHONPATH"] = (
            str(repo_root / "python")
            if not env.get("PYTHONPATH")
            else str(repo_root / "python") + os.pathsep + env["PYTHONPATH"]
        )

        hook_input = json.dumps(
            {
                "session_id": "wrapper-invalid-output-session",
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "/tmp/wrapper-invalid-output.txt"},
                "tool_use_id": "wrapper-invalid-output-call",
            }
        )
        result = subprocess.run(
            [str(wrapper)],
            input=hook_input,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

        thread.join(timeout=3)
        assert not failures
        assert observed["requests"] == 1
        assert result.returncode == 0, result.stderr

        output = json.loads(result.stdout)
        assert output.get("continue") is True
        assert output.get("hookSpecificOutput", {}).get("permissionDecision") != 5
    finally:
        if socket_path.exists():
            socket_path.unlink()
        if socket_parent.exists():
            socket_parent.rmdir()


def test_native_pre_tool_use_client_rejects_truncated_ok_envelope(tmp_path):
    import json
    import os
    import socket
    import subprocess
    import threading
    import uuid

    from vibap import claude_code_daemon as daemon_module

    native_pre_tool_use_command = daemon_module.install_native_pre_tool_use_command(home=tmp_path, force=True)
    if native_pre_tool_use_command is None:
        pytest.xfail("native PreToolUse daemon client could not be built on this host")

    # Exercise the installed non-force path: legacy installs can predate current
    # source and miss provenance metadata. Removing the stamp here ensures this
    # test covers reinstalling a stale/unstamped command before probe execution.
    command_stamp = native_pre_tool_use_command.parent / f"{native_pre_tool_use_command.name}.sha256"
    if command_stamp.exists():
        command_stamp.unlink()
    native_pre_tool_use_command = daemon_module.install_native_pre_tool_use_command(home=tmp_path, force=False)
    assert native_pre_tool_use_command is not None

    socket_parent = Path(f"/tmp/ardur-native-malformed-envelope-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "hook.sock"

    ready = threading.Event()
    failures: list[Exception] = []
    observed = {"requests": 0}
    malformed_envelope = b'{"ok":true,"output":{"continue":true}\\n'

    def _serve_truncated_envelope() -> None:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(socket_path))
                server.listen(2)
                server.settimeout(_FAKE_DAEMON_ACCEPT_TIMEOUT_S)
                ready.set()
                while observed["requests"] < 1:
                    try:
                        conn, _ = server.accept()
                    except TimeoutError:
                        break
                    with conn:
                        _ = conn.recv(8192)
                        observed["requests"] += 1
                        conn.sendall(malformed_envelope)
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            failures.append(exc)

    thread = threading.Thread(target=_serve_truncated_envelope, daemon=True)
    thread.start()

    try:
        assert ready.wait(timeout=2)
        hook_input = json.dumps(
            {
                "session_id": "native-malformed-envelope-session",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo bypass-attempt"},
                "tool_use_id": "native-malformed-envelope-call",
            }
        )
        result = subprocess.run(
            [str(native_pre_tool_use_command), str(socket_path), "100"],
            input=hook_input,
            capture_output=True,
            text=True,
            check=False,
        )

        thread.join(timeout=3)
        assert not failures
        assert observed["requests"] == 1
        assert result.returncode != 0
        assert result.stdout.strip() != '{"continue":true}'
    finally:
        if socket_path.exists():
            socket_path.unlink()
        if socket_parent.exists():
            socket_parent.rmdir()


def test_native_pre_tool_use_client_rejects_spaced_false_ok_envelope_with_hook_output(tmp_path):
    import json
    import os
    import socket
    import subprocess
    import threading
    import uuid

    from vibap import claude_code_daemon as daemon_module

    native_pre_tool_use_command = daemon_module.install_native_pre_tool_use_command(home=tmp_path, force=True)
    if native_pre_tool_use_command is None:
        pytest.xfail("native PreToolUse daemon client could not be built on this host")

    socket_parent = Path(f"/tmp/ardur-native-spaced-ok-false-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "hook.sock"

    ready = threading.Event()
    failures: list[Exception] = []
    observed = {"requests": 0}
    malformed_envelope = b'{"ok": false, "hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}\n'

    def _serve_spaced_false_ok_envelope() -> None:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(socket_path))
                server.listen(2)
                server.settimeout(_FAKE_DAEMON_ACCEPT_TIMEOUT_S)
                ready.set()
                while observed["requests"] < 1:
                    try:
                        conn, _ = server.accept()
                    except TimeoutError:
                        break
                    with conn:
                        _ = conn.recv(8192)
                        observed["requests"] += 1
                        conn.sendall(malformed_envelope)
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            failures.append(exc)

    thread = threading.Thread(target=_serve_spaced_false_ok_envelope, daemon=True)
    thread.start()

    try:
        assert ready.wait(timeout=2)
        hook_input = json.dumps(
            {
                "session_id": "native-spaced-ok-false-session",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo bypass-attempt"},
                "tool_use_id": "native-spaced-ok-false-call",
            }
        )
        result = subprocess.run(
            [str(native_pre_tool_use_command), str(socket_path), "100"],
            input=hook_input,
            capture_output=True,
            text=True,
            check=False,
        )

        thread.join(timeout=3)
        assert not failures
        assert observed["requests"] == 1
        assert result.returncode != 0
        assert '"permissionDecision":"allow"' not in result.stdout
    finally:
        if socket_path.exists():
            socket_path.unlink()
        if socket_parent.exists():
            socket_parent.rmdir()


def test_install_native_pre_tool_use_command_rebuilds_tampered_executable_with_intact_stamp(tmp_path):
    from vibap import claude_code_daemon as daemon_module

    native_pre_tool_use_command = daemon_module.install_native_pre_tool_use_command(home=tmp_path, force=True)
    if native_pre_tool_use_command is None:
        pytest.xfail("native PreToolUse daemon client could not be built on this host")

    command_stamp = native_pre_tool_use_command.parent / f"{native_pre_tool_use_command.name}.sha256"
    assert command_stamp.exists()

    tampered = b"#!/bin/sh\necho tampered\n"
    native_pre_tool_use_command.write_bytes(tampered)
    native_pre_tool_use_command.chmod(0o700)
    assert native_pre_tool_use_command.read_bytes() == tampered

    rebuilt = daemon_module.install_native_pre_tool_use_command(home=tmp_path, force=False)
    assert rebuilt is not None
    assert rebuilt == native_pre_tool_use_command
    assert native_pre_tool_use_command.read_bytes() != tampered



def test_wrapper_local_fallback_denies_forbidden_tool_after_truncated_ok_envelope(tmp_path):
    import json
    import os
    import socket
    import subprocess
    import sys
    import threading
    import uuid

    from vibap import claude_code_daemon as daemon_module

    token, _ = _issue_test_passport(tmp_path)
    repo_root = Path(__file__).resolve().parents[2]
    wrapper = repo_root / "plugins" / "claude-code" / "hooks" / "pre_tool_use"

    native_pre_tool_use_command = daemon_module.install_native_pre_tool_use_command(home=tmp_path, force=True)
    if native_pre_tool_use_command is None:
        pytest.xfail("native PreToolUse daemon client could not be built on this host")

    # Ensure wrapper coverage uses the installed command refresh path as well.
    command_stamp = native_pre_tool_use_command.parent / f"{native_pre_tool_use_command.name}.sha256"
    if command_stamp.exists():
        command_stamp.unlink()
    native_pre_tool_use_command = daemon_module.install_native_pre_tool_use_command(home=tmp_path, force=False)
    assert native_pre_tool_use_command is not None

    socket_parent = Path(f"/tmp/ardur-wrapper-truncated-envelope-deny-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "hook.sock"

    ready = threading.Event()
    failures: list[Exception] = []
    observed = {"requests": 0}
    malformed_envelope = b'{"ok":true,"output":{"continue":true}\\n'

    def _serve_invalid_hook_output() -> None:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(socket_path))
                server.listen(2)
                # Wrapper invocation includes shell + Python startup overhead;
                # keep accept timeout comfortably above typical client latency.
                server.settimeout(_FAKE_DAEMON_ACCEPT_TIMEOUT_S)
                ready.set()
                while observed["requests"] < 1:
                    try:
                        conn, _ = server.accept()
                    except TimeoutError:
                        break
                    with conn:
                        _ = conn.recv(8192)
                        observed["requests"] += 1
                        conn.sendall(malformed_envelope)
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            failures.append(exc)

    thread = threading.Thread(target=_serve_invalid_hook_output, daemon=True)
    thread.start()

    try:
        assert ready.wait(timeout=2)
        env = {**os.environ}
        env["ARDUR_MISSION_PASSPORT"] = token
        env["VIBAP_HOME"] = str(tmp_path)
        env["VIBAP_KEYS_DIR"] = str(tmp_path)
        env["ARDUR_CC_HOOK_DIR"] = str(tmp_path / "chain")
        env["ARDUR_CC_HOOK_DAEMON"] = "1"
        env["ARDUR_CC_HOOK_DAEMON_SOCKET"] = str(socket_path)
        env["ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS"] = "100"
        env["ARDUR_HOOK_PYTHON"] = sys.executable
        env["ARDUR_CC_HOOK_NATIVE_PRE_TOOL_USE"] = str(native_pre_tool_use_command)
        env["PYTHONPATH"] = (
            str(repo_root / "python")
            if not env.get("PYTHONPATH")
            else str(repo_root / "python") + os.pathsep + env["PYTHONPATH"]
        )

        hook_input = json.dumps(
            {
                "session_id": "wrapper-truncated-envelope-deny-session",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo bypass-attempt"},
                "tool_use_id": "wrapper-truncated-envelope-deny-call",
            }
        )
        result = subprocess.run(
            [str(wrapper)],
            input=hook_input,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

        thread.join(timeout=3)
        assert not failures
        assert observed["requests"] == 1
        assert result.returncode == 0, result.stderr

        output = json.loads(result.stdout)
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "ardur:" in output["hookSpecificOutput"]["permissionDecisionReason"].lower()
    finally:
        if socket_path.exists():
            socket_path.unlink()
        if socket_parent.exists():
            socket_parent.rmdir()


def test_wrapper_local_fallback_denies_forbidden_tool_after_spaced_false_ok_envelope(tmp_path):
    import json
    import os
    import socket
    import subprocess
    import sys
    import threading
    import uuid

    from vibap import claude_code_daemon as daemon_module

    token, _ = _issue_test_passport(tmp_path)
    repo_root = Path(__file__).resolve().parents[2]
    wrapper = repo_root / "plugins" / "claude-code" / "hooks" / "pre_tool_use"

    native_pre_tool_use_command = daemon_module.install_native_pre_tool_use_command(home=tmp_path, force=True)
    if native_pre_tool_use_command is None:
        pytest.xfail("native PreToolUse daemon client could not be built on this host")

    socket_parent = Path(f"/tmp/ardur-wrapper-spaced-ok-false-deny-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "hook.sock"

    ready = threading.Event()
    failures: list[Exception] = []
    observed = {"requests": 0}
    malformed_envelope = b'{"ok": false, "hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}\n'

    def _serve_spaced_false_ok_envelope() -> None:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(socket_path))
                server.listen(2)
                # Wrapper invocation includes shell + Python startup overhead;
                # keep accept timeout comfortably above typical client latency.
                server.settimeout(_FAKE_DAEMON_ACCEPT_TIMEOUT_S)
                ready.set()
                while observed["requests"] < 1:
                    try:
                        conn, _ = server.accept()
                    except TimeoutError:
                        break
                    with conn:
                        _ = conn.recv(8192)
                        observed["requests"] += 1
                        conn.sendall(malformed_envelope)
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            failures.append(exc)

    thread = threading.Thread(target=_serve_spaced_false_ok_envelope, daemon=True)
    thread.start()

    try:
        assert ready.wait(timeout=2)
        env = {**os.environ}
        env["ARDUR_MISSION_PASSPORT"] = token
        env["VIBAP_HOME"] = str(tmp_path)
        env["VIBAP_KEYS_DIR"] = str(tmp_path)
        env["ARDUR_CC_HOOK_DIR"] = str(tmp_path / "chain")
        env["ARDUR_CC_HOOK_DAEMON"] = "1"
        env["ARDUR_CC_HOOK_DAEMON_SOCKET"] = str(socket_path)
        env["ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS"] = "100"
        env["ARDUR_HOOK_PYTHON"] = sys.executable
        env["ARDUR_CC_HOOK_NATIVE_PRE_TOOL_USE"] = str(native_pre_tool_use_command)
        env["PYTHONPATH"] = (
            str(repo_root / "python")
            if not env.get("PYTHONPATH")
            else str(repo_root / "python") + os.pathsep + env["PYTHONPATH"]
        )

        hook_input = json.dumps(
            {
                "session_id": "wrapper-spaced-ok-false-deny-session",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo bypass-attempt"},
                "tool_use_id": "wrapper-spaced-ok-false-deny-call",
            }
        )
        result = subprocess.run(
            [str(wrapper)],
            input=hook_input,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

        thread.join(timeout=3)
        assert not failures
        assert observed["requests"] == 1
        assert result.returncode == 0, result.stderr

        output = json.loads(result.stdout)
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "ardur:" in output["hookSpecificOutput"]["permissionDecisionReason"].lower()
    finally:
        if socket_path.exists():
            socket_path.unlink()
        if socket_parent.exists():
            socket_parent.rmdir()


def test_wrapper_local_fallback_still_denies_forbidden_tool_after_malformed_daemon_output(tmp_path):
    import json
    import os
    import socket
    import subprocess
    import sys
    import threading
    import uuid

    from vibap import claude_code_daemon as daemon_module

    token, _ = _issue_test_passport(tmp_path)
    repo_root = Path(__file__).resolve().parents[2]
    wrapper = repo_root / "plugins" / "claude-code" / "hooks" / "pre_tool_use"

    native_pre_tool_use_command = daemon_module.install_native_pre_tool_use_command(home=tmp_path, force=True)
    if native_pre_tool_use_command is None:
        pytest.xfail("native PreToolUse daemon client could not be built on this host")

    socket_parent = Path(f"/tmp/ardur-wrapper-malformed-deny-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "hook.sock"

    ready = threading.Event()
    failures: list[Exception] = []
    observed = {"requests": 0}

    def _serve_invalid_hook_output() -> None:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(socket_path))
                server.listen(2)
                # Wrapper invocation includes shell + Python startup overhead;
                # keep accept timeout comfortably above typical client latency.
                server.settimeout(_FAKE_DAEMON_ACCEPT_TIMEOUT_S)
                ready.set()
                while observed["requests"] < 1:
                    try:
                        conn, _ = server.accept()
                    except TimeoutError:
                        break
                    with conn:
                        _ = conn.recv(8192)
                        observed["requests"] += 1
                        conn.sendall(b'{"ok":true,"output":{"not":"hook-output"}}\\n')
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            failures.append(exc)

    thread = threading.Thread(target=_serve_invalid_hook_output, daemon=True)
    thread.start()

    try:
        assert ready.wait(timeout=2)
        env = {**os.environ}
        env["ARDUR_MISSION_PASSPORT"] = token
        env["VIBAP_HOME"] = str(tmp_path)
        env["VIBAP_KEYS_DIR"] = str(tmp_path)
        env["ARDUR_CC_HOOK_DIR"] = str(tmp_path / "chain")
        env["ARDUR_CC_HOOK_DAEMON"] = "1"
        env["ARDUR_CC_HOOK_DAEMON_SOCKET"] = str(socket_path)
        env["ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS"] = "100"
        env["ARDUR_HOOK_PYTHON"] = sys.executable
        env["ARDUR_CC_HOOK_NATIVE_PRE_TOOL_USE"] = str(native_pre_tool_use_command)
        env["PYTHONPATH"] = (
            str(repo_root / "python")
            if not env.get("PYTHONPATH")
            else str(repo_root / "python") + os.pathsep + env["PYTHONPATH"]
        )

        hook_input = json.dumps(
            {
                "session_id": "wrapper-malformed-deny-session",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo bypass-attempt"},
                "tool_use_id": "wrapper-malformed-deny-call",
            }
        )
        result = subprocess.run(
            [str(wrapper)],
            input=hook_input,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

        thread.join(timeout=3)
        assert not failures
        assert observed["requests"] == 1
        assert result.returncode == 0, result.stderr

        output = json.loads(result.stdout)
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "ardur:" in output["hookSpecificOutput"]["permissionDecisionReason"].lower()
    finally:
        if socket_path.exists():
            socket_path.unlink()
        if socket_parent.exists():
            socket_parent.rmdir()


def test_wrapper_stalled_daemon_socket_respects_millisecond_timeout(tmp_path):
    import json
    import os
    import socket
    import subprocess
    import sys
    import threading
    import time
    import uuid

    token, _ = _issue_test_passport(tmp_path)
    repo_root = Path(__file__).resolve().parents[2]
    wrapper = repo_root / "plugins" / "claude-code" / "hooks" / "pre_tool_use"

    socket_parent = Path(f"/tmp/ardur-wrapper-stall-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "hook.sock"

    ready = threading.Event()
    release = threading.Event()
    failures: list[Exception] = []
    observed = {"requests": 0}

    def _serve_stalled_response() -> None:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(socket_path))
                server.listen(2)
                # Wrapper invocation includes shell + Python startup overhead;
                # keep accept timeout comfortably above typical client latency.
                server.settimeout(_FAKE_DAEMON_ACCEPT_TIMEOUT_S)
                ready.set()
                while observed["requests"] < 1:
                    try:
                        conn, _ = server.accept()
                    except TimeoutError:
                        break
                    with conn:
                        _ = conn.recv(8192)
                        observed["requests"] += 1
                        if observed["requests"] == 1:
                            # Simulate a daemon that stalls before sending a line.
                            release.wait(timeout=2)
                        else:
                            conn.sendall(b'{"ok":false,"error":"unexpected second daemon attempt"}\\n')
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            failures.append(exc)

    thread = threading.Thread(target=_serve_stalled_response, daemon=True)
    thread.start()

    try:
        assert ready.wait(timeout=2)
        env = {**os.environ}
        env["ARDUR_MISSION_PASSPORT"] = token
        env["VIBAP_HOME"] = str(tmp_path)
        env["VIBAP_KEYS_DIR"] = str(tmp_path)
        env["ARDUR_CC_HOOK_DIR"] = str(tmp_path / "chain")
        env["ARDUR_CC_HOOK_DAEMON"] = "1"
        env["ARDUR_CC_HOOK_DAEMON_SOCKET"] = str(socket_path)
        env["ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS"] = "50"
        env["ARDUR_HOOK_PYTHON"] = sys.executable
        env["PYTHONPATH"] = (
            str(repo_root / "python")
            if not env.get("PYTHONPATH")
            else str(repo_root / "python") + os.pathsep + env["PYTHONPATH"]
        )

        hook_input = json.dumps(
            {
                "session_id": "wrapper-stall-session",
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "/tmp/wrapper-stall.txt"},
                "tool_use_id": "wrapper-stall-call",
            }
        )

        baseline_env = {**env, "ARDUR_CC_HOOK_DAEMON": "0"}
        baseline_started = time.perf_counter()
        baseline_result = subprocess.run(
            [str(wrapper)],
            input=hook_input,
            capture_output=True,
            text=True,
            env=baseline_env,
            check=False,
        )
        baseline_elapsed_ms = (time.perf_counter() - baseline_started) * 1000.0
        assert baseline_result.returncode == 0, baseline_result.stderr

        started = time.perf_counter()
        result = subprocess.run(
            [str(wrapper)],
            input=hook_input,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0

        release.set()
        thread.join(timeout=3)

        assert not failures
        assert observed["requests"] == 1
        assert result.returncode == 0, result.stderr
        output = json.loads(result.stdout)
        assert output.get("continue") is True
        assert elapsed_ms < baseline_elapsed_ms + 1000, (
            "stalled daemon fallback added too much overhead: "
            f"baseline={baseline_elapsed_ms:.2f}ms stalled={elapsed_ms:.2f}ms"
        )
    finally:
        release.set()
        if socket_path.exists():
            socket_path.unlink()
        if socket_parent.exists():
            socket_parent.rmdir()


def test_three_call_session_chain_verifies(tmp_path, monkeypatch):
    private_key, public_key = generate_keypair(keys_dir=tmp_path)
    # Mission allows Read but forbids Bash.
    mission = MissionPassport(
        agent_id="alice",
        mission="test mission",
        allowed_tools=["Read"],
        forbidden_tools=["Bash"],
        resource_scope=["/tmp/*"],
        max_tool_calls=10,
        max_duration_s=600,
    )
    token = issue_passport(mission, private_key, ttl_s=3600)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))

    from vibap.claude_code_hook import handle_pre_tool_use, handle_post_tool_use

    # Call 1: Read (allowed) — pre + post.
    handle_pre_tool_use({"tool_name": "Read", "tool_input": {"file_path": "/tmp/a.txt"}}, keys_dir=tmp_path)
    handle_post_tool_use({"tool_name": "Read", "tool_input": {"file_path": "/tmp/a.txt"}, "tool_response": {"content": "a", "exit_code": 0}}, keys_dir=tmp_path)

    # Call 2: Bash (denied) — pre only (post never fires when blocked).
    out = handle_pre_tool_use({"tool_name": "Bash", "tool_input": {"command": "echo hi"}}, keys_dir=tmp_path)
    assert "ardur:" in _deny_reason(out).lower()

    # Call 3: Read (allowed) — pre + post.
    handle_pre_tool_use({"tool_name": "Read", "tool_input": {"file_path": "/tmp/b.txt"}}, keys_dir=tmp_path)
    handle_post_tool_use({"tool_name": "Read", "tool_input": {"file_path": "/tmp/b.txt"}, "tool_response": {"content": "b", "exit_code": 0}}, keys_dir=tmp_path)

    receipts = list((tmp_path / "chain").rglob("receipts.jsonl"))
    assert len(receipts) == 1
    lines = [l.strip() for l in receipts[0].read_text(encoding="utf-8").splitlines() if l.strip()]
    # 5 entries: Pre1 + Post1 + Deny2 + Pre3 + Post3
    assert len(lines) == 5

    from vibap.receipt import verify_chain
    verify_chain(lines, public_key)  # raises ReceiptChainError if chain is broken
