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
    raw = files(__package__).joinpath(
        "mission_declaration_v01.schema.json"
    ).read_text(encoding="utf-8")
    return json.loads(raw)


@lru_cache(maxsize=1)
def transparency_anchor_v01_schema() -> dict:
    """Return the parsed Transparency Anchor v0.1 JSON Schema."""
    raw = files(__package__).joinpath(
        "transparency_anchor_v01.schema.json"
    ).read_text(encoding="utf-8")
    return json.loads(raw)


@lru_cache(maxsize=1)
def receiver_attestation_v01_schema() -> dict:
    """Return the parsed Receiver Attestation v0.1 JSON Schema."""
    raw = files(__package__).joinpath(
        "receiver_attestation_v01.schema.json"
    ).read_text(encoding="utf-8")
    return json.loads(raw)
