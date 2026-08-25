from __future__ import annotations

import copy
import json
import os
import socket
import stat
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from vibap.canonical_json import canonical_json_bytes
from vibap.policy_conformance import (
    PolicyConformancePathError,
    load_policy_conformance_bundle,
    main as fixture_main,
    run_policy_conformance_bundle,
    write_policy_conformance_report,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLE = REPO_ROOT / "docs" / "specs" / "conformance" / "policy-v0.1" / "bundle.json"
REPORT = BUNDLE.with_name("report.json")
REQUIRED_RISKS = {
    "baseline",
    "indirect_prompt_injection",
    "confidential_exfiltration",
    "tool_misuse",
    "authority_widening",
    "budget_cost_runaway",
    "unsafe_network_action",
    "untrusted_artifact_influence",
}


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(canonical_json_bytes(value) + b"\n")


def test_committed_bundle_matches_report_and_required_risks() -> None:
    bundle = load_policy_conformance_bundle(BUNDLE)
    actual = run_policy_conformance_bundle(BUNDLE)
    expected = json.loads(REPORT.read_text(encoding="utf-8"))

    assert actual == expected
    assert actual["ok"] is True
    assert actual["summary"] == {"total": 8, "passed": 8, "failed": 0}
    assert {item["risk_class"] for item in actual["scenarios"]} == REQUIRED_RISKS
    assert {item["decision"] for item in actual["scenarios"]} == {"PERMIT", "DENY"}
    assert all(
        item["receipt_verification"] == "verified" for item in actual["scenarios"]
    )
    assert bundle["claim_boundary"].endswith("not semantic-content detection.")


def test_runner_is_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    def reject_network(*_args, **_kwargs):
        raise AssertionError("policy conformance runner attempted network access")

    monkeypatch.setattr(socket, "create_connection", reject_network)
    monkeypatch.setattr(urllib.request, "urlopen", reject_network)

    assert run_policy_conformance_bundle(BUNDLE)["ok"] is True


def test_bundle_rejects_duplicate_names_non_nfc_depth_and_non_p256_key(
    tmp_path: Path,
) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":"first","schema_version":"second"}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate name"):
        load_policy_conformance_bundle(duplicate)

    bundle = load_policy_conformance_bundle(BUNDLE)
    non_nfc = copy.deepcopy(bundle)
    non_nfc["scenarios"][0]["description"] = "cafe\u0301"
    non_nfc_path = tmp_path / "non-nfc.json"
    _write_json(non_nfc_path, non_nfc)
    with pytest.raises(ValueError, match="Unicode NFC"):
        load_policy_conformance_bundle(non_nfc_path)

    nested: object = "leaf"
    for _ in range(66):
        nested = [nested]
    too_deep = copy.deepcopy(bundle)
    too_deep["scenarios"][0]["action"]["arguments"] = {"nested": nested}
    deep_path = tmp_path / "too-deep.json"
    _write_json(deep_path, too_deep)
    with pytest.raises(ValueError, match="nesting-depth limit"):
        load_policy_conformance_bundle(deep_path)

    wrong_key = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    untrusted = copy.deepcopy(bundle)
    untrusted["receipt_public_key"] = wrong_key
    untrusted_path = tmp_path / "wrong-key.json"
    _write_json(untrusted_path, untrusted)
    with pytest.raises(ValueError, match="not P-256"):
        run_policy_conformance_bundle(untrusted_path)


def test_tampered_receipt_and_binding_mismatch_fail_with_diagnostics(
    tmp_path: Path,
) -> None:
    bundle = load_policy_conformance_bundle(BUNDLE)
    tampered = copy.deepcopy(bundle)
    token = tampered["scenarios"][0]["receipt_jwt"]
    header, payload, signature = token.split(".")
    replacement = "A" if signature[0] != "A" else "B"
    tampered["scenarios"][0]["receipt_jwt"] = (
        f"{header}.{payload}.{replacement}{signature[1:]}"
    )
    tampered_path = tmp_path / "tampered.json"
    _write_json(tampered_path, tampered)
    report = run_policy_conformance_bundle(tampered_path)
    assert report["ok"] is False
    assert report["scenarios"][0]["receipt_verification"] == "failed"
    assert "receipt verification failed" in report["scenarios"][0]["failures"][0]

    rebound = copy.deepcopy(bundle)
    rebound["scenarios"][0]["action"]["arguments"]["path"] = "/workspace/other.txt"
    rebound_path = tmp_path / "rebound.json"
    _write_json(rebound_path, rebound)
    report = run_policy_conformance_bundle(rebound_path)
    assert report["ok"] is False
    assert "receipt arguments_hash mismatch" in report["scenarios"][0]["failures"]


def test_expected_mismatch_fails_report_and_cli(tmp_path: Path, capsys) -> None:
    bundle = load_policy_conformance_bundle(BUNDLE)
    bundle["scenarios"][0]["expected"]["decision"] = "DENY"
    path = tmp_path / "mismatch.json"
    output = tmp_path / "report.json"
    _write_json(path, bundle)

    report = run_policy_conformance_bundle(path)
    assert report["ok"] is False
    assert report["summary"] == {"total": 8, "passed": 7, "failed": 1}
    assert fixture_main(["--bundle", str(path), "--output", str(output)]) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False
    assert json.loads(output.read_text(encoding="utf-8")) == report


def test_reader_and_writer_reject_symlinks(tmp_path: Path) -> None:
    bundle_link = tmp_path / "bundle.json"
    bundle_link.symlink_to(BUNDLE)
    with pytest.raises(ValueError, match="regular file"):
        load_policy_conformance_bundle(bundle_link)

    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    report_link = tmp_path / "report.json"
    report_link.symlink_to(target)
    with pytest.raises(ValueError, match="must not be a symlink"):
        write_policy_conformance_report(report_link, {"ok": True})
    assert target.read_text(encoding="utf-8") == "{}"


def test_committed_bundle_contains_no_private_key_or_raw_attack_payload() -> None:
    text = BUNDLE.read_text(encoding="utf-8")
    assert "BEGIN PRIVATE KEY" not in text
    assert "BEGIN EC PRIVATE KEY" not in text
    assert "ignore previous" not in text.lower()
    assert text.count("BEGIN PUBLIC KEY") == 1


def test_generator_emits_public_self_verifying_bundle(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.json"
    report = tmp_path / "report.json"
    environment = os.environ.copy()
    environment["TMPDIR"] = str(tmp_path)
    generated = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "generate-policy-conformance-fixtures.py"),
            "--bundle",
            str(bundle),
            "--report",
            str(report),
        ],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert generated.returncode == 0, generated.stdout + generated.stderr
    actual = run_policy_conformance_bundle(bundle)
    assert actual == json.loads(report.read_text(encoding="utf-8"))
    assert actual["summary"] == {"total": 8, "passed": 8, "failed": 0}
    assert stat.S_IMODE(bundle.stat().st_mode) == 0o600
    assert stat.S_IMODE(report.stat().st_mode) == 0o600
    fixture_text = bundle.read_text(encoding="utf-8")
    assert "BEGIN PRIVATE KEY" not in fixture_text
    assert "BEGIN EC PRIVATE KEY" not in fixture_text


def test_bundle_empty_string_is_structured(
    tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Empty --bundle must produce a clean JSON error, no traceback, no CWD writes."""
    monkeypatch.chdir(tmp_path)

    code = fixture_main(["--bundle", ""])
    captured = capsys.readouterr()
    report = json.loads(captured.err)

    assert code == 2
    assert captured.out == ""
    assert report["ok"] is False
    assert report["error"] == "policy_conformance_path_invalid"
    assert report["condition"] == "policy_conformance_bundle_empty"
    assert "Traceback" not in captured.err
    assert not any(tmp_path.iterdir()), "no files written to CWD on empty --bundle"


def test_bundle_whitespace_only_is_structured(
    tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Whitespace-only --bundle must produce a clean JSON error, no CWD writes."""
    monkeypatch.chdir(tmp_path)

    code = fixture_main(["--bundle", "   "])
    captured = capsys.readouterr()
    report = json.loads(captured.err)

    assert code == 2
    assert captured.out == ""
    assert report["ok"] is False
    assert report["error"] == "policy_conformance_path_invalid"
    assert report["condition"] == "policy_conformance_bundle_empty"
    assert "Traceback" not in captured.err
    assert not any(tmp_path.iterdir()), "no files written to CWD on whitespace --bundle"


def test_output_empty_string_is_structured(
    tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Empty --output must produce a clean JSON error, no CWD writes."""
    monkeypatch.chdir(tmp_path)

    code = fixture_main(["--bundle", str(BUNDLE), "--output", ""])
    captured = capsys.readouterr()
    report = json.loads(captured.err)

    assert code == 2
    assert report["ok"] is False
    assert report["error"] == "policy_conformance_path_invalid"
    assert report["condition"] == "policy_conformance_output_empty"
    assert "Traceback" not in captured.err
    assert not any(tmp_path.iterdir()), "no report written to CWD on empty --output"


def test_output_whitespace_only_is_structured(
    tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Whitespace-only --output must produce a clean JSON error, no CWD writes."""
    monkeypatch.chdir(tmp_path)

    code = fixture_main(["--bundle", str(BUNDLE), "--output", "   "])
    captured = capsys.readouterr()
    report = json.loads(captured.err)

    assert code == 2
    assert report["ok"] is False
    assert report["error"] == "policy_conformance_path_invalid"
    assert report["condition"] == "policy_conformance_output_empty"
    assert "Traceback" not in captured.err
    assert not any(p.name.strip() == "" or p.name == "   " for p in tmp_path.iterdir()), (
        "no whitespace-named file created on whitespace-only --output"
    )


def test_bundle_empty_raises_specialized_error() -> None:
    with pytest.raises(PolicyConformancePathError) as exc_info:
        load_policy_conformance_bundle("")
    assert exc_info.value.condition == "policy_conformance_bundle_empty"


def test_output_empty_raises_specialized_error() -> None:
    with pytest.raises(PolicyConformancePathError) as exc_info:
        write_policy_conformance_report("   ", {"ok": True})
    assert exc_info.value.condition == "policy_conformance_output_empty"
