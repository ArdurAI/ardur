"""RFC 8785 JSON Canonicalization Scheme helpers."""

from __future__ import annotations

import json
from typing import Any

try:
    import rfc8785
except ModuleNotFoundError as exc:
    if exc.name != "rfc8785":
        raise
    from ._vendor import rfc8785


def canonical_json_bytes(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 representation of ``value``."""

    return rfc8785.dumps(value)


def canonical_json_text(value: Any) -> str:
    """Return the RFC 8785 canonical representation as text."""

    return canonical_json_bytes(value).decode("utf-8")


class RFC8785JSONEncoder(json.JSONEncoder):
    """Adapter that lets PyJWT sign RFC 8785 canonical payload bytes."""

    def encode(self, value: Any) -> str:
        return canonical_json_text(value)
