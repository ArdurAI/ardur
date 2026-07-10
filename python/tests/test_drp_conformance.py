from __future__ import annotations

import copy
import hashlib
import json
import os
import socket
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from vibap.canonical_json import canonical_json_bytes
from vibap.drp_conformance import (
    load_drp_conformance_bundle,
    main as fixture_main,
    run_drp_conformance_bundle,
    write_drp_conformance_report,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLE = REPO_ROOT / "docs" / "specs" / "conformance" / "drp-v0.1" / "bundle.json"
REPORT = BUNDLE.with_name("report.json")
REQUIRED_SCENARIOS = {
    "DRP-VALID-CHAIN",
    "DRP-DENY-RESOURCE-WIDENING",
    "DRP-DENY-EXPIRED",
    "DRP-DENY-REVOKED",
    "DRP-DENY-NO-REDELEGATION",
    "DRP-DENY-DEPTH-EXHAUSTED",
    "DRP-DENY-AUTHPROOF-AE1C56-WIRE",
}


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(canonical_json_bytes(value) + b"\n")


def test_committed_bundle_matches_report_and_required_scenarios() -> None:
    bundle = load_drp_conformance_bundle(BUNDLE)
    actual = run_drp_conformance_bundle(BUNDLE)
    expected = json.loads(REPORT.read_text(encoding="utf-8"))

    assert actual == expected
    assert actual["ok"] is True
    assert actual["summary"] == {"total": 7, "passed": 7, "failed": 0}
    assert {item["scenario_id"] for item in actual["scenarios"]} == REQUIRED_SCENARIOS
    assert all(item["verifier_status"] == "pass" for item in actual["scenarios"])
    assert all(
        item["evidence_class"] == "implementation-self-test"
        for item in actual["scenarios"]
    )
    assert actual["scenarios"][0]["receipt_id_status"] == "verified"
    assert all(
        item["receipt_id_status"] in {"untrusted-input", "absent"}
        for item in actual["scenarios"][1:]
    )
    assert (
        actual["bundle_sha256"]
        == hashlib.sha256(canonical_json_bytes(bundle)).hexdigest()
    )
    statuses = {
        item["name"]: item["status"] for item in actual["external_implementations"]
    }
    assert statuses == {
        "authproof-sdk": "incompatible-wire",
        "independent-verifier": "not-demonstrated",
    }


def test_runner_does_not_use_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def reject_network(*_args, **_kwargs):
        raise AssertionError("fixture runner attempted network access")

    monkeypatch.setattr(socket, "create_connection", reject_network)
    monkeypatch.setattr(urllib.request, "urlopen", reject_network)

    assert run_drp_conformance_bundle(BUNDLE)["ok"] is True


def test_bundle_rejects_duplicate_names_non_nfc_and_non_p256_trust(
    tmp_path: Path,
) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":"first","schema_version":"second"}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate name"):
        load_drp_conformance_bundle(duplicate)

    bundle = load_drp_conformance_bundle(BUNDLE)
    non_nfc = copy.deepcopy(bundle)
    non_nfc["scenarios"][0]["description"] = "cafe\u0301"
    non_nfc_path = tmp_path / "non-nfc.json"
    _write_json(non_nfc_path, non_nfc)
    with pytest.raises(ValueError, match="Unicode NFC"):
        load_drp_conformance_bundle(non_nfc_path)

    too_deep: object = "leaf"
    for _ in range(66):
        too_deep = [too_deep]
    deep_bundle = copy.deepcopy(bundle)
    deep_bundle["scenarios"][0]["action"]["arguments"] = {"nested": too_deep}
    deep_path = tmp_path / "too-deep.json"
    _write_json(deep_path, deep_bundle)
    with pytest.raises(ValueError, match="nesting-depth limit"):
        load_drp_conformance_bundle(deep_path)

    parser_deep = tmp_path / "parser-deep.json"
    marker = '"arguments":{"calendar_id":"team"}'
    replacement = (
        '"arguments":{"nested":' + ("[" * 2000) + '"leaf"' + ("]" * 2000) + "}"
    )
    parser_deep.write_text(
        BUNDLE.read_text(encoding="utf-8").replace(marker, replacement, 1),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="valid UTF-8 JSON|nesting-depth limit"):
        load_drp_conformance_bundle(parser_deep)

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
    issuer = next(iter(untrusted["scenarios"][0]["context"]["signer_keys"]))
    untrusted["scenarios"][0]["context"]["signer_keys"][issuer] = wrong_key
    untrusted_path = tmp_path / "wrong-key.json"
    _write_json(untrusted_path, untrusted)
    with pytest.raises(ValueError, match="is not P-256"):
        run_drp_conformance_bundle(untrusted_path)


def test_bundle_rejects_duplicate_external_evidence_identity(tmp_path: Path) -> None:
    bundle = load_drp_conformance_bundle(BUNDLE)
    logs = bundle["scenarios"][0]["context"]["log_evidence"]
    logs.append(copy.deepcopy(logs[0]))
    path = tmp_path / "duplicate-evidence.json"
    _write_json(path, bundle)

    with pytest.raises(ValueError, match="duplicate log receipt_id"):
        run_drp_conformance_bundle(path)


def test_expected_mismatch_fails_report_and_cli(tmp_path: Path, capsys) -> None:
    bundle = load_drp_conformance_bundle(BUNDLE)
    bundle["scenarios"][0]["expected"]["reason_code"] = "UNEXPECTED_RESULT"
    path = tmp_path / "mismatch.json"
    output = tmp_path / "report.json"
    _write_json(path, bundle)

    report = run_drp_conformance_bundle(path)
    assert report["ok"] is False
    assert report["summary"] == {"total": 7, "passed": 6, "failed": 1}
    assert report["scenarios"][0]["verifier_status"] == "fail"
    assert fixture_main(["--bundle", str(path), "--output", str(output)]) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False
    assert json.loads(output.read_text(encoding="utf-8")) == report


def test_report_writer_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "report.json"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="must not be a symlink"):
        write_drp_conformance_report(link, {"ok": True})
    assert target.read_text(encoding="utf-8") == "{}"


def test_bundle_reader_rejects_symlink(tmp_path: Path) -> None:
    link = tmp_path / "bundle.json"
    link.symlink_to(BUNDLE)

    with pytest.raises(ValueError, match="regular file"):
        load_drp_conformance_bundle(link)


def test_committed_bundle_contains_no_private_key_material() -> None:
    text = BUNDLE.read_text(encoding="utf-8")
    assert "BEGIN PRIVATE KEY" not in text
    assert "BEGIN EC PRIVATE KEY" not in text
    assert text.count("BEGIN PUBLIC KEY") > 0


def test_generator_emits_public_self_verifying_bundle(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.json"
    report = tmp_path / "report.json"
    environment = os.environ.copy()
    environment["TMPDIR"] = str(tmp_path)
    generated = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "generate-drp-implementation-fixtures.py"),
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
    actual = run_drp_conformance_bundle(bundle)
    assert actual == json.loads(report.read_text(encoding="utf-8"))
    assert actual["summary"] == {"total": 7, "passed": 7, "failed": 0}
    fixture_text = bundle.read_text(encoding="utf-8")
    assert "BEGIN PRIVATE KEY" not in fixture_text
    assert "BEGIN EC PRIVATE KEY" not in fixture_text
