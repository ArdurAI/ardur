"""Shared cryptographic hashing and canonical-serialisation utilities.

Used across the vibap package to eliminate 30+ duplicated inline
``hashlib.sha256(x.encode("utf-8")).hexdigest()`` calls and 10+
duplicated ``json.dumps(..., sort_keys=True, separators=(",", ":"))``
calls.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def sha256_hex(data: str | bytes) -> str:
    """Return the SHA-256 hex digest of ``data``.

    When ``data`` is a ``str``, it is encoded as UTF-8 before hashing.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> str:
    """Return a canonical JSON representation of ``obj``.

    Uses ``sort_keys=True``, compact separators, and
    ``ensure_ascii=False`` so non-ASCII bytes survive round-trips.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
