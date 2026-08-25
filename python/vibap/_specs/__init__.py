"""Embedded specification schemas for runtime validation.

The JSON files in this directory are copies of the canonical specs under
``/docs/specs/``. They live inside the ``vibap`` package so the runtime
can validate untrusted inputs against the spec without depending on the
docs directory existing on disk (e.g. after ``pip install ardur`` from
PyPI). A CI check enforces that they stay in sync with ``/docs/specs/``.

To re-sync after editing the canonical doc:

    cp docs/specs/mission-declaration-v0.1.schema.json \\
       python/vibap/_specs/mission_declaration_v01.schema.json
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files


@lru_cache(maxsize=1)
def mission_declaration_v01_schema() -> dict:
    """Return the parsed Mission Declaration v0.1 JSON Schema.

    Cached after first load. Returns a plain dict suitable for
    :func:`jsonschema.validate`.
    """
    raw = (
        files(__package__)
        .joinpath("mission_declaration_v01.schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(raw)


@lru_cache(maxsize=1)
def transparency_anchor_v01_schema() -> dict:
    """Return the parsed Transparency Anchor v0.1 JSON Schema."""
    raw = (
        files(__package__)
        .joinpath("transparency_anchor_v01.schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(raw)


@lru_cache(maxsize=1)
def receiver_attestation_v01_schema() -> dict:
    """Return the parsed Receiver Attestation v0.1 JSON Schema."""
    raw = (
        files(__package__)
        .joinpath("receiver_attestation_v01.schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(raw)


@lru_cache(maxsize=1)
def offline_verification_bundle_v01_schema() -> dict:
    """Return the parsed Offline Verification Bundle v0.1 JSON Schema."""
    raw = (
        files(__package__)
        .joinpath("offline_verification_bundle_v01.schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(raw)


@lru_cache(maxsize=1)
def offline_verification_report_v01_schema() -> dict:
    """Return the parsed Offline Verification Report v0.1 JSON Schema."""
    raw = (
        files(__package__)
        .joinpath("offline_verification_report_v01.schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(raw)


@lru_cache(maxsize=1)
def ardur_drp_profile_v01_schema() -> dict:
    """Return the parsed Ardur DRP Profile v0.1 JSON Schema."""
    raw = (
        files(__package__)
        .joinpath("ardur_drp_profile_v01.schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(raw)


@lru_cache(maxsize=1)
def drp_conformance_bundle_v01_schema() -> dict:
    """Return the parsed DRP implementation fixture bundle v0.1 schema."""
    raw = (
        files(__package__)
        .joinpath("drp_conformance_bundle_v01.schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(raw)


@lru_cache(maxsize=1)
def drp_implementation_fixture_report_v01_schema() -> dict:
    """Return the parsed DRP implementation fixture report v0.1 schema."""
    raw = (
        files(__package__)
        .joinpath("drp_implementation_fixture_report_v01.schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(raw)


@lru_cache(maxsize=1)
def policy_conformance_bundle_v01_schema() -> dict:
    """Return the Agentic Policy Conformance Bundle v0.1 schema."""
    raw = (
        files(__package__)
        .joinpath("policy_conformance_bundle_v01.schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(raw)


@lru_cache(maxsize=1)
def policy_conformance_report_v01_schema() -> dict:
    """Return the Agentic Policy Conformance Report v0.1 schema."""
    raw = (
        files(__package__)
        .joinpath("policy_conformance_report_v01.schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(raw)


@lru_cache(maxsize=1)
def runtime_evidence_event_v01_schema() -> dict:
    """Return the parsed Runtime Evidence Event v0.1 JSON Schema."""
    raw = (
        files(__package__)
        .joinpath("runtime_evidence_event_v01.schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(raw)


@lru_cache(maxsize=1)
def runtime_evidence_correlation_report_v01_schema() -> dict:
    """Return the parsed Runtime Evidence Correlation Report v0.1 schema."""
    raw = (
        files(__package__)
        .joinpath("runtime_evidence_correlation_report_v01.schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(raw)


@lru_cache(maxsize=1)
def linux_governance_benchmark_report_v01_schema() -> dict:
    """Return the parsed Linux Governance Benchmark Report v0.1 schema."""
    raw = (
        files(__package__)
        .joinpath("linux_governance_benchmark_report_v01.schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(raw)


@lru_cache(maxsize=1)
def governance_telemetry_v01_schema() -> dict:
    """Return the parsed Governance Telemetry Event v0.1 schema."""
    raw = (
        files(__package__)
        .joinpath("governance_telemetry_v01.schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(raw)


@lru_cache(maxsize=1)
def tool_server_preflight_report_v01_schema() -> dict:
    """Return the Tool-Server Preflight Report v0.1 schema."""
    raw = (
        files(__package__)
        .joinpath("tool_server_preflight_report_v01.schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(raw)
