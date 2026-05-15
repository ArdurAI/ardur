"""Governance proxy and lightweight HTTP service for VIBAP."""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import copy
import fcntl
import fnmatch
import hashlib
import hmac
import json
import logging
import os
import posixpath
import re
import secrets
import signal

import sys
import threading
import time
import unicodedata
import uuid
import weakref
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .log_rotation import RotatingJSONLLog
from .metrics import metrics as ardur_metrics
from .rate_limiter import RateLimiter
from .tls import create_ssl_context, resolve_tls_paths

# Session IDs are UUIDs — reject anything else to prevent path traversal
_SESSION_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
MAX_REQUEST_BODY = 1024 * 1024  # 1 MiB

# Per-session in-process coordination for shared state_dir access. ``flock``
# closes the cross-process hole, but same-process proxies can still share a
# PID, so we need a process-local lock keyed by the absolute lockfile path.
class _SessionCoordinationLock:
    """Weakref-able wrapper for a per-session reentrant process lock."""

    __slots__ = ("lock", "__weakref__")

    def __init__(self) -> None:
        self.lock = threading.RLock()


_SESSION_COORDINATION_LOCKS: weakref.WeakValueDictionary[str, _SessionCoordinationLock] = (
    weakref.WeakValueDictionary()
)
_SESSION_COORDINATION_LOCKS_GUARD = threading.Lock()

from .aat_adapter import (  # noqa: E402
    AAT_CREDENTIAL_FORMAT,
    decode_aat_claims,
    material_from_aat_grant,
)
from .approvals import ApprovalRateTracker
from .attestation import issue_attestation, verify_attestation
from .backends.native import NativeBackend
from .denial import DenialReason
from .lineage_budget import (
    FileLineageBudgetLedger,
    LineageBudgetConflictError,
    LineageBudgetLedger,
)
from .mission import (
    MissionBindingError,
    MissionCache,
    MissionStatusUnavailableError,
    fetch_mission_declaration,
    mission_is_revoked,
    parse_mission_ref,
)
from .memory import (
    MEMORY_STORE_READ_TOOL,
    MEMORY_STORE_WRITE_TOOL,
    GovernedMemoryStore,
    MemoryIntegrityError,
)
from .passport import (
    DEFAULT_HOME,
    MAX_DELEGATION_DEPTH,
    MissionPassport,
    delegation_chain_entries,
    derive_child_passport,
    generate_keypair,
    issue_passport,
    load_private_key,
    resolve_keys_dir,
    verify_passport,
)
# NOTE: ``from .receipt import build_receipt, sign_receipt`` was a top-level
# import here, but proxy ↔ receipt forms a cycle (receipt.py uses ``PolicyEvent``
# from this module under ``TYPE_CHECKING``). Although the cycle is safe at
# runtime — receipt.py uses ``from __future__ import annotations`` so all
# annotations are strings, and the proxy import in receipt.py is gated by
# ``TYPE_CHECKING`` — CodeQL's ``py/unsafe-cyclic-import`` rule flags the
# topology regardless. The two consumers (build_receipt + sign_receipt) are
# called in exactly one method (``_build_receipt_log_entry``), so a deferred
# local import there breaks the topological cycle without changing semantics.
# See ``_build_receipt_log_entry`` for the deferred import.
from .policy_backend import PolicyDecision, compose_decisions, get_backend, register_backend, timed_evaluate

DEFAULT_STATE_DIR = Path(os.environ.get("VIBAP_STATE_DIR", DEFAULT_HOME / "state")).expanduser()
DEFAULT_LOG_PATH = DEFAULT_HOME / "governance_log.jsonl"
DEFAULT_RECEIPTS_LOG_PATH = DEFAULT_HOME / "receipts_log.jsonl"

logger = logging.getLogger(__name__)
API_VERSION = "0.1.0"
REPLAY_CACHE_MAX_ENTRIES = 4096
REPLAY_CACHE_WARN_ENTRIES = max(1, int(REPLAY_CACHE_MAX_ENTRIES * 0.9))
LINEAGE_PARENT_CACHE_MAX_ENTRIES = 4096
_PASSPORT_STATE_SCHEMA_VERSION = 1
_SESSION_RECEIPT_INTEGRITY_VERSION = 1
LIFECYCLE_ATTESTATION_SCHEMA = "ardur.lifecycle.attestation.v1"
LineageEdge = tuple[str | None, str | None]

# B.2 fail-closed precondition (PLAN E.8). Declared telemetry fields MUST be
# present and non-empty in the tool-call arguments dict or the verifier returns
# INSUFFICIENT_EVIDENCE. Attested fields (actor=passport.sub, grant_id=passport.jti)
# are sourced from the signed passport and are NOT listed here — they cannot be
# ablated by manipulating the arguments dict.
DECLARED_TELEMETRY_FIELDS: tuple[str, ...] = (
    "action_class",
    "tool_name",
    "target",
    "resource_family",
    "content_class",
    "content_provenance",
    "side_effect_class",
    "visibility",
    "sensitivity",
    "instruction_bearing",
    "budget_delta",
    "envelope_signature_valid",
    "observed_manifest_digest",
)


def _missing_declared_telemetry(
    arguments: Mapping[str, Any],
    required_fields: Sequence[str],
) -> list[str]:
    """Return the declared-telemetry fields absent (or empty) from ``arguments``.

    ``required_fields`` is the intersection of the mission's ``required_telemetry``
    claim with :data:`DECLARED_TELEMETRY_FIELDS`. Attested fields (actor, grant_id)
    must be filtered out before calling — they cannot be ablated by the caller.

    A field counts as present when the key exists and the value is not ``None``
    and not an empty string. Boolean ``False`` and integer ``0`` count as
    present (they're legitimate values for instruction_bearing / budget_delta).
    """
    missing: list[str] = []
    for field_name in required_fields:
        if field_name not in arguments:
            missing.append(field_name)
            continue
        value = arguments[field_name]
        if value is None:
            missing.append(field_name)
            continue
        if isinstance(value, str) and not value.strip():
            missing.append(field_name)
            continue
        if field_name == "visibility" and (
            not isinstance(value, str) or value.strip().lower() != "full"
        ):
            missing.append(field_name)
    return missing


def _declared_required_telemetry(
    passport_claims: Mapping[str, Any],
) -> list[str]:
    """Extract the mission's declared required-telemetry list, intersected with
    :data:`DECLARED_TELEMETRY_FIELDS`. Returns an empty list if the mission did
    not declare ``required_telemetry`` — in which case the fail-closed gate is a
    no-op (back-compat with pre-E.8 passports)."""
    declared = passport_claims.get("required_telemetry")
    if not isinstance(declared, (list, tuple)):
        return []
    return [
        field_name
        for field_name in declared
        if isinstance(field_name, str) and field_name in DECLARED_TELEMETRY_FIELDS
    ]


def _is_memory_store_tool(name: str) -> bool:
    return name in (MEMORY_STORE_WRITE_TOOL, MEMORY_STORE_READ_TOOL)


# ---------------------------------------------------------------------------
# resource_scope enforcement helpers
# ---------------------------------------------------------------------------
# A value is treated as a "resource reference" if it's a non-empty string that
# either contains '/' (file/object path) or starts with a URL scheme. We err on
# the side of flagging too many values: a false-positive DENY is recoverable
# (widen resource_scope); a false-negative PERMIT is a governance bypass.
_URL_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)

# Windows path shape detectors — used by _sanitize_value to normalize
# backslashes to forward slashes before POSIX normalization. Without this,
# `C:\Users\secret.csv` bypasses scope checks entirely (B2).
# Drive-letter form:   `C:\...`, `c:/...`, or a bare `C:` (no trailing path).
# UNC form:            `\\server\share\...`
_WINDOWS_DRIVE_RE = re.compile(r"^([A-Za-z]):([\\/].*)?$")
_WINDOWS_UNC_RE = re.compile(r"^\\\\[^\\]+\\")

# Phase-3.1a C-4 + Phase-3.2 R2-01 (external-review-X F4 / external-review-G round-2): the set of
# codepoints that render as a slash but are not ASCII ``/``. Without folding
# these on input, a value like ``／etc／passwd`` (FULLWIDTH SOLIDUS, U+FF0F)
# or ``⁄etc⁄passwd`` (FRACTION SLASH, U+2044) is not matched by
# ``_looks_like_resource``, never enters the scope scanner, and governance
# is silently bypassed.
#
# Hand-picked (NOT NFKC-derived): NFKC folds U+FF0F → ``/`` but leaves
# U+29F8, U+2215, and U+2044 unchanged (empirically verified). The earlier
# Phase-3.1a comment claimed NFKC folds all three of the picks; that was
# wrong. We do a surgical replace on exactly these codepoints instead, so
# we keep the precision of an explicit fold without coupling to NFKC's
# other aggressive compatibility decompositions (e.g. fullwidth Latin).
#
# Members (all visually confusable with ASCII ``/``):
#   U+002F SOLIDUS             — ASCII ``/`` (the canonical; identity fold)
#   U+FF0F FULLWIDTH SOLIDUS   — common CJK-keyboard source
#   U+2044 FRACTION SLASH      — typography (``1⁄2``); missed in 3.1a
#   U+29F8 BIG SOLIDUS         — math font
#   U+2215 DIVISION SLASH      — math
#
# We intentionally exclude U+2571 BOX DRAWINGS LIGHT DIAGONAL (decorative
# line-drawing, very rare in real paths) and backslash variants — ASCII
# ``\`` has its own dedicated handling (Windows shape + bare-backslash).
_SLASH_LIKE_CODEPOINTS = frozenset({"/", "\uFF0F", "\u2044", "\u29F8", "\u2215"})

# Phase-3.2 C-5: Unicode dot-like codepoints that render visually as "." but
# escape the literal ".." segment checks and posixpath.normpath's traversal
# collapsing. Folding them to ASCII "." is surgical \u2014 same rationale as
# _SLASH_LIKE_CODEPOINTS. NFC preserves these codepoints as-is.
_DOT_LIKE_CODEPOINTS = frozenset({
    "\u2024",  # ONE DOT LEADER (\u2024)  \u2014 visually indistinguishable from "."
    "\uFF0E",  # FULLWIDTH FULL STOP (\uFF0E) \u2014 wide "."
})


def _contains_slash_like(s: str) -> bool:
    """True if ``s`` contains any codepoint that renders as ``/`` — ASCII
    or a Unicode confusable (see ``_SLASH_LIKE_CODEPOINTS``).

    Consolidating this check into one helper keeps ``_looks_like_resource``
    and ``_is_path_shaped_token`` in sync. Phase-3.1 drifted them apart
    (R2-02); the unknown-key branch of ``_extract_path_tokens`` exposed
    the drift, permitting values like ``{"pattern": "／etc／passwd"}``.
    """
    return any(ch in _SLASH_LIKE_CODEPOINTS for ch in s)


def _passport_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# Regex splitter for segment analysis across the slash-like class — used in
# ``_is_path_shaped_token`` so its segment-based grammar check doesn't miss
# pre-sanitization values that come in with a Unicode solidus variant.
_SLASH_LIKE_SPLIT_RE = re.compile(
    "[" + "".join(re.escape(c) for c in _SLASH_LIKE_CODEPOINTS) + "]"
)

# Bounds on the argument scan to keep worst-case cost predictable.
_RESOURCE_SCAN_MAX_VALUES = 1024
_RESOURCE_SCAN_MAX_DEPTH = 16

# ---------------------------------------------------------------------------
# Tokenizer hint sets (C3)
# ---------------------------------------------------------------------------
# The tokenizer uses key-name hints to decide how to extract resource
# references from a raw argument value. Two classes of hints:
#
#   - PATH hints: the author labeled this key as carrying a file/URL. Under
#     a path hint, a bare value (no whitespace) is treated as one token
#     even if it doesn't match the usual path shape (e.g. ``q1.csv``). If
#     the value contains whitespace (e.g. ``command`` → ``cat /etc/passwd``),
#     we split and keep only path-shaped tokens — this is B6 closure.
#
#   - PROSE hints: the author labeled this key as carrying free-form text.
#     Tokens are extracted by whitespace split + path-shape filter. The
#     shape rule uses the punctuation-vs-separator heuristic: ``/``
#     surrounded by letters-only segments on both sides (``and/or``,
#     ``his/her``) is grammatical and NOT extracted. This is B3 closure.
#     A real path under a prose key (``see /etc/passwd for details``) is
#     extracted because ``/etc/passwd`` has an empty leading segment — B5
#     closure.
#
# Env-var extension:
#   - ``VIBAP_SCOPE_PATH_HINTS`` and ``VIBAP_SCOPE_PROSE_HINTS`` (comma-
#     separated key names) EXTEND the defaults — callers cannot shrink the
#     defaults, only add to them. This matches the "false-DENY is
#     recoverable, false-PERMIT is a bypass" design principle.
#   - Conflict resolution: if a key appears in both env vars, PATH wins
#     (more aggressive scanning). Per unified delegation §1 decision 6.
#
# Hints are resolved per-check (not cached at import time) so tests and
# operators can flip env vars without reimporting the module.
_DEFAULT_PATH_HINTS = frozenset({
    "path", "file", "filepath", "filename", "url", "uri",
    "src", "source", "dst", "dest", "destination",
    "location", "object_key", "cwd", "directory", "dir",
    "target", "resource",
    "command", "script", "cmd", "file_path",
    # Phase-3.1b M-1 (external-review-G F1): `pattern` was previously a PATH hint,
    # but grep / ripgrep / find / SQL LIKE wrappers all use `pattern`
    # for a REGEX / GLOB / LIKE expression, not a filesystem path.
    # Treating it as a path produced false-DENYs on in-memory-only
    # operations (e.g. `{"pattern": "foo/bar", "path": "ok.txt"}`
    # denied on `pattern`). Dropped from PATH_HINTS. A caller who
    # really does want `pattern` scoped can re-add it via the
    # `VIBAP_SCOPE_PATH_HINTS` env var — the defaults now optimize
    # for the common case.
})
_DEFAULT_PROSE_HINTS = frozenset({
    "content", "body", "text", "message", "note", "summary",
    "description", "old_string", "new_string", "prompt",
    "markdown", "response", "stdout", "stderr", "log",
    "comment", "memo", "answer", "output", "instruction",
    "query", "sql", "html",
})

# Cap on raw token input. An attacker who can stuff an MB-sized blob into
# one arg shouldn't be able to make us do MB-sized splits per call. Values
# above this are not tokenized; resource-shaped oversize values instead
# trip the fail-closed exhaustion path in ``_check_resource_scope``.
_RESOURCE_TOKEN_MAX_LEN = 4096

# Minimal prose-only allowlist of grammatical slash compounds that must not
# be reclassified as resource references by the embedded-path rule below.
# ``_is_path_shaped_token`` remains the primary grammar guard; this set only
# fences the extra pure-alpha path recovery added for round-3 C1.
_GRAMMATICAL_PROSE_SLASH_TOKENS = frozenset({
    "and/or",
    "either/or",
    "he/she",
    "her/him",
    "her/his",
    "him/her",
    "his/her",
    "s/he",
    "she/he",
})


def _sanitize_value(value: str) -> tuple[str, str | None]:
    """Canonicalize a resource candidate for scope matching.

    Returns ``(normalized_value, error_reason)``:

    - If ``error_reason`` is ``None``, ``normalized_value`` is the canonical
      form the caller should match against ``resource_scope`` patterns.
    - If ``error_reason`` is non-None, the caller should DENY with that
      reason; ``normalized_value`` is the *raw* input (for error messages).

    The processing order matters — each step guards the next:

    1. Null-byte rejection — a null byte in a path is never legitimate and
       has been used historically to truncate paths inside C stdlib calls.
    2. NFC Unicode normalization — macOS and Linux filesystems disagree on
       NFD vs NFC for composed characters. We pick NFC as the canonical
       form so a passport issued on one host matches on another.
    3. Pre-normalization ``..`` segment check — catches *lateral* escape
       (``sales/../hr/secret.csv``) that ``posixpath.normpath`` would
       silently collapse to ``hr/secret.csv`` and let past a
       ``sales/*``-scoped glob. This is B7. We have to check *before*
       normalization because normalization erases the evidence.
    4. Windows shape detection — drive letters (``C:\\...``) and UNC paths
       (``\\\\server\\share\\...``) have their backslashes normalized to
       forward slashes so POSIX-style scope patterns can match them. Drive
       letter is lowercased for case-insensitive matching on Windows
       volumes. This closes B2.
    5. URL scheme short-circuit — ``https://api.example.com/v1`` must not
       go through ``posixpath.normpath`` (which would collapse the ``//``
       in the scheme to a single ``/``).
    6. POSIX ``normpath`` — canonical form for matching.
    7. Post-normalization ``..`` check — catches the classic B1 traversal
       (``../../../etc/passwd`` or patterns ending in ``/..``).
    """
    # 0. Percent-decode loop (path traversal catalog finding #1, #2, #5).
    #    Without this, %2E%2E/%2F bypasses the step-3 '..' check because
    #    the literal '%2E%2E' does not contain '..'. Iterative decode handles
    #    double-encoding (%252E → %2E → .). Max 3 iterations to prevent DoS.
    import urllib.parse
    for _ in range(3):
        decoded = urllib.parse.unquote(value)
        if decoded == value:
            break
        value = decoded

    # 1. Null-byte rejection (also catches %00 after percent-decode above).
    if "\x00" in value:
        return value, "contains null byte"

    # 2. NFC Unicode normalization.
    value = unicodedata.normalize("NFC", value)

    # 2a. Phase-3.1a C-4 + Phase-3.2 R2-01 (external-review-X F4 / external-review-G round-2): fold
    #     Unicode slash-like variants to ASCII ``/``. NFC (Layer 2) preserves
    #     these codepoints as distinct from ``/``. NFKC would fold U+FF0F only
    #     — empirically verified that U+29F8, U+2215, and U+2044 stay put —
    #     AND NFKC is an aggressive compatibility decomposition that also
    #     alters valid filenames (fullwidth Latin letters etc.). An explicit
    #     fold on ``_SLASH_LIKE_CODEPOINTS`` is surgical: it canonicalizes
    #     exactly the attack vector without any NFKC coupling.
    for _sol in _SLASH_LIKE_CODEPOINTS:
        if _sol == "/":
            continue  # identity fold; skip to save an O(n) replace
        if _sol in value:
            value = value.replace(_sol, "/")

    # 2b. Phase-3.2 C-5: fold Unicode dot-like variants to ASCII "." so the
    #     literal ".." checks in steps 3 and 7 catch traversal segments
    #     written with confusable dots (e.g. ONE DOT LEADER U+2024).
    for _dot in _DOT_LIKE_CODEPOINTS:
        if _dot in value:
            value = value.replace(_dot, ".")

    # 3. Pre-normalization '..' segment check (B7 — lateral escape).
    #    Split on both '/' and '\\' so a Windows-shaped traversal is caught
    #    before we rewrite slashes in step 4.
    raw_value = value
    for segment in re.split(r"[\\/]", value):
        if segment == "..":
            return raw_value, "contains '..' segment (pre-normalize)"

    # 4. Windows shape detection + slash normalization.
    drive_match = _WINDOWS_DRIVE_RE.match(value)
    if drive_match:
        drive_letter = drive_match.group(1).lower()
        remainder = value[2:].replace("\\", "/")
        value = f"{drive_letter}:{remainder}"
    elif _WINDOWS_UNC_RE.match(value):
        value = value.replace("\\", "/")

    # 5. URL scheme short-circuit — normpath would collapse 'https://' to
    #    'https:/', breaking scheme-prefix matching.
    if _URL_SCHEME_RE.match(value):
        return value, None

    # 6. POSIX path normalization — canonical form for scope matching.
    normalized = posixpath.normpath(value)

    # 7. Post-normalization '..' escape check (B1 — classic traversal).
    if (
        normalized == ".."
        or normalized.startswith("../")
        or "/../" in normalized
        or normalized.endswith("/..")
    ):
        return raw_value, "escapes scope root after normalization ('..' in path)"

    return normalized, None


def _resolve_hint_sets() -> tuple[frozenset[str], frozenset[str]]:
    """Return ``(path_hints, prose_hints)`` for the current environment.

    Reads ``VIBAP_SCOPE_PATH_HINTS`` and ``VIBAP_SCOPE_PROSE_HINTS`` (each a
    comma-separated list of key names) and EXTENDS the defaults — operators
    can add hints but never remove them. Conflict resolution: if a key
    appears in both env vars, PATH wins (it's added to the path set and
    stripped from the prose set). This matches the unified delegation §1
    decision 6 ("false-DENY is recoverable, false-PERMIT is a bypass").

    Resolved on every call (not cached) so tests can flip env vars without
    reimporting the module. The cost is a tiny set union per check.
    """
    def _parse(raw: str | None) -> set[str]:
        if not raw:
            return set()
        return {piece.strip().lower() for piece in raw.split(",") if piece.strip()}

    extra_path = _parse(os.environ.get("VIBAP_SCOPE_PATH_HINTS"))
    extra_prose = _parse(os.environ.get("VIBAP_SCOPE_PROSE_HINTS"))

    path_hints = _DEFAULT_PATH_HINTS | extra_path
    # PATH wins on env-var collision: anything in extra_path is stripped
    # from prose even if the operator listed it there too.
    prose_hints = (_DEFAULT_PROSE_HINTS | extra_prose) - path_hints
    return frozenset(path_hints), frozenset(prose_hints)


def _is_path_shaped_token(s: str) -> bool:
    """True if ``s`` looks like a filesystem path or URL (not grammatical prose).

    Rules, in order:

    1. Length must be > 1 (a bare ``/`` or single char is never a useful
       path reference).
    2. URL scheme (``https://``, ``s3://``, ``file://``) → path-shaped.
    3. Windows drive (``C:\\...``, ``C:/...``) or UNC (``\\\\server\\share``)
       → path-shaped. (These get normalized to forward slashes by
       ``_sanitize_value`` but are valid path shapes on input.)
    4. Must contain a slash-like character — ASCII ``/`` or any member of
       ``_SLASH_LIKE_CODEPOINTS`` (fullwidth, fraction, big, division).
       Phase-3.2 R2-02: this function receives RAW (pre-sanitize) values in
       the unknown-key branch of ``_extract_path_tokens``, so the check
       must handle Unicode solidus variants before they get folded.
    5. Punctuation-vs-separator heuristic: split on the slash-like class.
       If EVERY resulting segment is non-empty AND pure letters (e.g.
       ``and/or``, ``his/her``), this is grammatical English, NOT a path.
       If ANY segment is empty (leading/trailing/consecutive slash) OR
       contains a non-letter character (digit, dot, dash, underscore,
       colon, etc.), this is path-shaped. This is the rule that closes B3
       while still accepting ``/etc/passwd`` (empty leading segment) and
       ``sales/q1.csv`` (``q1.csv`` has digit+dot).
    """
    if len(s) <= 1:
        return False
    if _URL_SCHEME_RE.match(s):
        return True
    if _WINDOWS_DRIVE_RE.match(s) or _WINDOWS_UNC_RE.match(s):
        return True
    # Phase-3.2 R2-02: bare backslash (no drive / no UNC prefix) must also
    # be treated as path-shaped so the unknown-key branch of
    # ``_extract_path_tokens`` doesn't silently permit values like
    # ``{"resource": r"Program\Files\secrets"}``. Mirrors the bare-``\``
    # heuristic already in ``_looks_like_resource``. No grammar check
    # here because ``\`` is exclusively a separator in the shapes this
    # function is meant to catch — it has no grammatical English use.
    if "\\" in s:
        return True
    if not _contains_slash_like(s):
        return False
    # Split on ALL slash-like codepoints, not just ASCII ``/``. If we split
    # on only ASCII ``/`` here, a value like ``foo／bar`` (U+FF0F) would
    # yield a single segment ``foo／bar``, which is not pure-alpha (the
    # non-ASCII char is neither a letter for ``isalpha`` in all locales nor
    # a separator we've honored) and would wrongly be classified as a path
    # even when its callers intended the solidus to separate prose words.
    # Splitting on the full class gives the grammar rule consistent input.
    for segment in _SLASH_LIKE_SPLIT_RE.split(s):
        # Empty segment = leading/trailing/consecutive slash — path, not word.
        # Non-empty segment with any non-letter char — also path, not word.
        if segment == "" or not segment.isalpha():
            return True
    # All segments were pure-letters — this is grammatical punctuation,
    # e.g. ``and/or``, ``either/or``, ``his/her``. Not a path.
    return False


def _is_path_like_under_hint(s: str) -> bool:
    """Looser "path-shaped" check for use under a PATH hint.

    Phase-3.1a C-1 (cursor F1 + SF-P3-01): under a path hint the caller has
    declared the key carries a filesystem / URL reference, so we should not
    apply the grammatical ``and/or``-style rule — that rule is tuned for
    PROSE where the default assumption is "this is English, not a path".
    Under a path hint the assumption flips: "this is a path, unless it
    clearly cannot be one".

    A substring is treated as a path-like token if ANY of the following
    holds:
      - contains a slash-like codepoint — ASCII ``/`` or any member of
        ``_SLASH_LIKE_CODEPOINTS`` (``／`` U+FF0F, ``⁄`` U+2044, ``⧸``
        U+29F8, ``∕`` U+2215). Phase-3.1a C-4 + Phase-3.2 R2-01
        defense-in-depth so a Unicode-solidus attack cannot sneak past
        the tokenizer layer either.
      - contains ASCII ``\\`` (Windows separator, including bare
        ``sales\\q1.csv`` which has no drive letter)
      - matches a URL scheme (``https://``, ``s3://``, ...)
      - matches a Windows drive (``C:\\...`` / ``C:/...``) or UNC
        (``\\\\server\\share``) shape

    Length ≤ 1 is always rejected (a bare ``/`` is never a useful token).
    """
    if len(s) <= 1:
        return False
    if _contains_slash_like(s) or "\\" in s:
        return True
    if _URL_SCHEME_RE.match(s):
        return True
    if _WINDOWS_DRIVE_RE.match(s) or _WINDOWS_UNC_RE.match(s):
        return True
    return False


def _iter_whitespace_tokens(value: str):
    """Yield non-whitespace substrings without building an eager split list."""
    for match in re.finditer(r"\S+", value):
        yield match.group(0)


def _is_embedded_resource_token(s: str) -> bool:
    """True if ``s`` should be extracted from prose as a resource token.

    ``_is_path_shaped_token`` stays unchanged to preserve the B3 grammar rule.
    This helper adds a narrow recovery path for embedded pure-alpha resources
    like ``etc/passwd`` in prose, while keeping known grammatical compounds
    like ``and/or`` and short prose compounds like ``file/docs`` out of the
    token stream.
    """
    if len(s) <= 1:
        return False
    if _is_path_shaped_token(s):
        return True
    if not _looks_like_resource(s):
        return False
    if _is_short_pure_alpha_slash_compound(s):
        return False
    return s.casefold() not in _GRAMMATICAL_PROSE_SLASH_TOKENS


def _is_short_pure_alpha_slash_compound(s: str) -> bool:
    """True for short two-segment alpha compounds like ``foo/bar``.

    This carve-out is intentionally PROSE-only. Unknown keys must treat these
    as resource references because a key-name typo should not silently bypass
    ``resource_scope`` for values like ``bin/sh`` or ``usr/bin``.
    """
    if "\\" in s or not _contains_slash_like(s):
        return False
    segments = _SLASH_LIKE_SPLIT_RE.split(s)
    if len(segments) != 2:
        return False
    return all(segment and segment.isalpha() and len(segment) <= 4 for segment in segments)


def _extract_path_tokens(
    value: Any,
    key: str | None = None,
    exhausted: dict[str, bool] | None = None,
) -> list[str]:
    """Extract path/URL tokens from a raw argument value.

    Returns a list of substrings that should be matched against
    ``resource_scope``. Returns ``[]`` for non-string, empty, or over-long
    inputs, and for values that don't look like resources under the
    current key hint.

    Behavior by key class:

    - **Path hint** (``key.lower()`` in the resolved path hint set, e.g.
      ``path``, ``file``, ``url``, ``command``):

      - If ``value`` has no whitespace: the whole value is one token, no
        shape check. This lets bare filenames like ``q1.csv`` be scoped
        even though they lack ``/``.
      - If ``value`` has whitespace (e.g. ``cat /etc/passwd`` under
        ``command``): split on whitespace and keep only path-shaped
        substrings. Closes B6 — previously the whole value was one opaque
        token so ``/etc/*`` globs never matched.

    - **Prose hint** (``content``, ``body``, ``message``, ...):
      split on whitespace and keep path-shaped substrings. A narrow
      embedded-path rule also keeps pure-alpha path tokens like
      ``etc/passwd`` while still rejecting the known grammatical
      compounds pinned by the B3 regressions (``and/or``, ``his/her``).

    - **Unknown / missing key:** check the WHOLE value against the shape
      rule. If resource-shaped, return it as a single token; otherwise
      ``[]``.

    DoS bound: values longer than ``_RESOURCE_TOKEN_MAX_LEN`` (4096) are not
    split. Instead, if an oversize value still looks resource-shaped under
    its hint class, ``exhausted["v"]`` is set so the caller can fail closed.
    """
    if not isinstance(value, str) or not value:
        return []

    path_hints, prose_hints = _resolve_hint_sets()
    key_lower = key.lower() if isinstance(key, str) else None

    if len(value) > _RESOURCE_TOKEN_MAX_LEN:
        oversize_resource = False
        if key_lower is not None and key_lower in path_hints:
            if any(ch.isspace() for ch in value):
                oversize_resource = any(
                    _is_path_like_under_hint(token)
                    for token in _iter_whitespace_tokens(value)
                )
            else:
                oversize_resource = True
        elif key_lower is not None and key_lower in prose_hints:
            oversize_resource = any(
                _is_embedded_resource_token(token)
                for token in _iter_whitespace_tokens(value)
            )
        else:
            oversize_resource = _looks_like_resource(value)
        if oversize_resource and exhausted is not None:
            exhausted["v"] = True
        return []

    if key_lower is not None and key_lower in path_hints:
        # Path hint: bare value → one token; whitespace → split + loose shape
        # filter. The whitespace branch closes B6: ``cat /etc/passwd`` used to
        # match as one opaque token, so a scope like ``/etc/*`` would fail.
        #
        # Phase-3.1a C-1 (cursor F1 + SF-P3-01): under a PATH hint, the caller
        # has explicitly declared "this key carries a path". The grammatical
        # `and/or`-style rule used in the prose branch is wrong here — it
        # rejects pure-alpha segments like ``etc/hosts`` (from ``cat etc/hosts``)
        # because every segment is alpha, even though the caller clearly meant
        # a path. The path-hint whitespace branch must use a looser filter:
        # accept any substring that contains ``/``, ``\``, a URL scheme, or
        # Windows shape — no grammatical check. The prose branch still uses
        # the full grammatical rule (B3 closure stays intact).
        if any(ch.isspace() for ch in value):
            return [w for w in value.split() if _is_path_like_under_hint(w)]
        return [value]

    if key_lower is not None and key_lower in prose_hints:
        # Prose hint: only extract substrings that pass the punctuation-vs-
        # separator rule OR the embedded-path recovery rule. ``and/or`` stays
        # out (B3), while ``/etc/passwd`` and ``etc/passwd`` come out.
        return [w for w in value.split() if _is_embedded_resource_token(w)]

    # Unknown or missing key: a key-name typo must not recover the prose-only
    # short-compound carve-out. If the whole value looks resource-shaped,
    # scope-check it.
    if _looks_like_resource(value):
        return [value]
    return []


def _looks_like_resource(value: Any) -> bool:
    """True if `value` is a string that looks like a file path or URL.

    Recognized shapes:
      - Any string containing a slash-like codepoint — ASCII ``/`` or any
        Unicode confusable in ``_SLASH_LIKE_CODEPOINTS`` (U+FF0F, U+2044,
        U+29F8, U+2215). Phase-3.1a C-4 + Phase-3.2 R2-01.
      - URL-scheme prefix (``https://``, ``s3://``, ...)
      - Windows drive (``C:\\...``, ``C:/...``) or UNC (``\\\\server\\share``)
      - Bare backslash (``Program\\Files\\readme``) — Phase-3.1a C-1
        defense-in-depth

    The Windows shapes are required so B2 (backslash-only paths like
    ``C:\\Users\\secret.csv``) are caught by the scanner — without them the
    value would never reach ``_extract_path_tokens`` or ``_sanitize_value``.
    """
    if not isinstance(value, str) or not value:
        return False
    # Phase-3.2 R2-02: use the shared slash-like helper so this function
    # and ``_is_path_shaped_token`` can't drift out of sync. (Phase 3.1
    # had separate ASCII-``/`` + Unicode-loop checks here, which meant the
    # tokenizer's unknown-key branch missed Unicode solidus values.)
    if _contains_slash_like(value):
        return True
    if _URL_SCHEME_RE.match(value):
        return True
    if _WINDOWS_DRIVE_RE.match(value):
        return True
    if _WINDOWS_UNC_RE.match(value):
        return True
    # Phase-3.1a C-1 defense-in-depth (cursor F4): a bare-backslash-only
    # value like ``Program\Files\readme`` has no drive letter or UNC
    # prefix but is clearly a path separator shape. The sanitizer's Layer 4
    # only rewrites backslashes on drive/UNC shapes, so a bare backslash
    # value would fall through to posixpath.normpath AS-IS and fail to
    # match scope patterns written with forward slashes. We accept it at
    # the detection layer so it at least REACHES the scope check — a
    # mismatched scope is a (recoverable) false-DENY, which is the safer
    # failure mode per the Phase-3 design principle.
    if "\\" in value:
        return True
    return False


def _iter_resource_values(
    arguments: Any,
    key: str | None = None,
    depth: int = 0,
    budget: list[int] | None = None,
    exhausted: dict | None = None,
):
    """Yield ``(key, value)`` tuples for every string in ``arguments`` that
    looks like a resource reference.

    `key` is the immediate dict key the string was the value of, or `None`
    for strings that came from a list/tuple position or as the top-level
    argument. C6's orchestrator uses this context to apply the path-hint /
    prose-hint policy from `_extract_path_tokens`.

    Depth- and count-bounded. Recurses through dicts/lists/tuples.
    Non-string scalars (int/float/bool/None) are never yielded.

    Phase-3.1a C-2 changes (cursor F2/F3 + external-review-X F1/F2 + SF-P3-02/03):

    - **Budget decrement only on yield.** The budget counts RESOURCE-LIKE
      strings, not every string scanned. Pre-3.1a, a non-resource string
      burned budget on the same footing as a real candidate, so an attacker
      could stuff 1024 noise strings into ``args`` and exhaust the budget
      before the real payload was ever considered → scanner silently
      returned → PERMIT. Post-3.1a, only a yielded resource decrements
      budget, so non-resource padding is effectively free and cannot starve
      the real candidates out of the scan.

    - **Exhaustion signaling.** Callers that care whether the scan
      completed pass ``exhausted={"v": False}`` and then check
      ``exhausted["v"]`` after the loop. On depth overflow or budget
      exhaustion we set ``exhausted["v"] = True`` BEFORE returning so the
      orchestrator can fail closed. Default None preserves back-compat for
      existing test consumers that don't care.
    """
    if budget is None:
        budget = [_RESOURCE_SCAN_MAX_VALUES]
    if depth > _RESOURCE_SCAN_MAX_DEPTH or budget[0] <= 0:
        # Signal exhaustion so the orchestrator can distinguish
        # "scan ran to completion and found nothing" from "scan aborted
        # after hitting a DoS bound". Pre-3.1a these looked the same from
        # outside the function, which is the root cause of cursor F2/F3.
        if exhausted is not None:
            exhausted["v"] = True
        return
    if isinstance(arguments, str):
        # Budget decrement moved inside the resource-check: only real
        # candidates cost budget. Non-resource strings (tool names, pure
        # text, numbers-as-strings, etc.) are free. This is the core fix
        # for the "noise padding starves the scan" bypass.
        #
        # ARDUR-finding-bare-token-scope-bypass (2026-04-15): a bare
        # string like ``"hr"`` under a path-hint key like ``directory``
        # does NOT pass ``_looks_like_resource`` (no slash, no URL scheme,
        # no Windows shape), so pre-fix it was silently skipped — and
        # ``list_files({"directory": "hr"})`` returned PERMIT even when
        # ``resource_scope`` was ``["sales/*"]``. Claude + LangChain/
        # LangGraph on the Apr-15 honest-local-test policy-drift
        # scenario triggered this 12 times. Fix: when the parent key is
        # a declared path-hint, yield the bare value even without path
        # shape. The downstream tokenizer (``_extract_path_tokens``)
        # already returns the whole value as one token under a path
        # hint, so no additional logic is needed there.
        if _looks_like_resource(arguments):
            budget[0] -= 1
            yield (key, arguments)
            return
        if key is not None and arguments:
            path_hints, _prose_hints = _resolve_hint_sets()
            if key.lower() in path_hints:
                budget[0] -= 1
                yield (key, arguments)
        return
    if isinstance(arguments, dict):
        for k, val in arguments.items():
            if budget[0] <= 0:
                if exhausted is not None:
                    exhausted["v"] = True
                return
            yield from _iter_resource_values(
                val, key=str(k), depth=depth + 1, budget=budget, exhausted=exhausted,
            )
        return
    if isinstance(arguments, (list, tuple)):
        for item in arguments:
            if budget[0] <= 0:
                if exhausted is not None:
                    exhausted["v"] = True
                return
            # Key context doesn't carry through list/tuple boundaries —
            # a list member is unkeyed from the scope-matcher's viewpoint.
            yield from _iter_resource_values(
                item, key=None, depth=depth + 1, budget=budget, exhausted=exhausted,
            )
        return
    # Non-string scalars (int/float/bool/None) are never resources.


def _check_resource_scope(
    arguments: dict[str, Any],
    resource_scope: list[str],
    cwd: str | None = None,
) -> tuple[bool, str]:
    """Verify every resource-like value in `arguments` matches at least one glob in
    `resource_scope`. Returns (ok, reason).

    If `resource_scope` is empty, returns (True, "") for backwards compatibility
    with passports that don't declare scope. Matching is case-sensitive
    (fnmatchcase) because real-world paths/URLs are case-sensitive on Linux, S3,
    GCS, etc.

    The optional ``cwd`` is a passport-declared anchor used to resolve
    *relative* candidate values. When a candidate token does not match any
    scope pattern verbatim AND does not look absolute, we try one extra
    match against ``posixpath.join(cwd, candidate)`` (re-sanitized so a
    ``..`` introduced by the candidate can't escape ``cwd``). This closes
    the CC-2 class of "passport declares ``/workspace/*`` but the tool
    emits ``./file.txt``". If ``cwd`` is ``None``, behavior is identical
    to pre-C8.

    Pipeline (C6 — the 3-layer orchestrator):

    1. **Layer 1 — iterate** candidate ``(key, raw_value)`` pairs via
       ``_iter_resource_values`` (depth/count-bounded recursion through
       dicts/lists).
    2. **Layer 2 — tokenize** each value via ``_extract_path_tokens(value, key)``
       to apply the path-hint / prose-hint policy. Prose with ``and/or`` yields
       no tokens (B3). ``cat /etc/passwd`` under ``command`` yields
       ``['/etc/passwd']`` (B6). ``/etc/passwd`` under ``markdown`` yields
       ``['/etc/passwd']`` (B5).
    3. **Layer 3 — sanitize + match** each token via ``_sanitize_value`` (NFC,
       Windows shapes, pre+post ``..`` escape check, ``posixpath.normpath``)
       then ``fnmatchcase`` against NFC-normalized scope patterns. If no
       pattern matches, try a two-way absolute/relative coercion (candidate
       relative + any absolute pattern → prepend ``/``; candidate absolute +
       any relative pattern → strip leading ``/``). Coerced forms still go
       through escape-check via re-sanitization so coercion can never mask
       traversal.
    """
    if not resource_scope:
        # No scope declared — legacy "unrestricted" semantics. PERMIT.
        return True, ""
    patterns = [p for p in resource_scope if isinstance(p, str) and p]
    if not patterns:
        # Phase-3.1b M-2 (external-review-G F4): scope WAS declared but every entry
        # was invalid (None / non-string / empty string). Pre-3.1b this
        # silently devolved to "unrestricted" — the same PERMIT path as
        # "no scope declared" — so a passport with
        # `resource_scope: [None, 42, ""]` granted filesystem-wide access
        # without warning. Fix: distinguish "not declared" from "declared
        # but all-invalid" and fail CLOSED on the latter so an operator
        # sees a clear error at the first tool call instead of discovering
        # the bypass via incident response.
        return False, (
            "resource_scope declared but contains no valid patterns "
            "(all entries were None / non-string / empty) — "
            "fix the passport's resource_scope field"
        )

    # NFC-normalize scope patterns once per call. Memoized here rather than
    # at module import time so operators can ship passports authored on
    # NFD-producing filesystems (macOS HFS+) without a pre-match mismatch.
    # Computing once per call, not per token, keeps the cost proportional
    # to scope size rather than candidate count.
    nfc_patterns = [unicodedata.normalize("NFC", p) for p in patterns]

    def _is_absolute_pattern(p: str) -> bool:
        # "Absolute" here means: a pattern that would match a fully-qualified
        # resource reference, not a relative path. Three shapes qualify:
        #   - POSIX-absolute: leading '/'
        #   - URL: has a scheme (https://, s3://, ...)
        #   - Windows drive: C:/... (post-NFC; raw backslash is unusual in
        #     a scope pattern but handled conservatively)
        if p.startswith("/"):
            return True
        if _URL_SCHEME_RE.match(p):
            return True
        if _WINDOWS_DRIVE_RE.match(p):
            return True
        return False

    any_absolute = any(_is_absolute_pattern(p) for p in nfc_patterns)
    any_relative = any(not _is_absolute_pattern(p) for p in nfc_patterns)

    def _matches_any(candidate: str) -> bool:
        return any(fnmatch.fnmatchcase(candidate, pat) for pat in nfc_patterns)

    def _preview(s: str) -> str:
        return s if len(s) <= 120 else s[:117] + "..."

    # cwd anchor: when a candidate is relative and cwd is declared, we
    # resolve candidate-relative-to-cwd before the fallback coercions. The
    # resolved form is re-sanitized so a '..' in the candidate (e.g. cwd
    # '/workspace' + './../etc/passwd') is rejected by the sanitizer's
    # post-normalize '..' check rather than silently escaping via
    # posixpath.join.
    cwd_anchor: str | None = None
    if cwd is not None and isinstance(cwd, str) and cwd.startswith("/"):
        cwd_normalized, cwd_err = _sanitize_value(cwd)
        # If the declared cwd itself is invalid (e.g. contains '..'), treat
        # as if no cwd were declared. A malformed cwd claim shouldn't make
        # scope checks unsafe; it just loses the relative-resolution bonus.
        if cwd_err is None and cwd_normalized.startswith("/"):
            cwd_anchor = cwd_normalized

    # Phase-3.1a C-2 (cursor F2/F3 + external-review-X F1/F2 + SF-P3-02/03): pass an
    # out-parameter to the iterator so we can detect DoS-bound exhaustion
    # (depth > MAX_DEPTH or budget <= 0) and FAIL CLOSED. Pre-3.1a, the
    # iterator silently returned early on exhaustion, so a deeply-nested
    # or noise-padded payload caused zero tokens to be checked and the
    # orchestrator returned (True, "") — a governance bypass dressed up
    # as "no candidates found".
    exhausted: dict[str, bool] = {"v": False}
    for key, raw_value in _iter_resource_values(arguments, exhausted=exhausted):
        tokens = _extract_path_tokens(raw_value, key, exhausted=exhausted)
        # Empty token list = this value produced nothing path-shaped worth
        # checking (e.g. prose with grammatical 'and/or'). Skip without
        # denying. The tokenizer is the single point that decides what
        # counts as a resource reference.
        for token in tokens:
            normalized, error_reason = _sanitize_value(token)
            if error_reason is not None:
                return False, (
                    f"resource '{_preview(token)}' rejected: {error_reason}"
                )

            if _matches_any(normalized):
                continue

            token_is_absolute = (
                normalized.startswith("/")
                or bool(_URL_SCHEME_RE.match(normalized))
                or bool(_WINDOWS_DRIVE_RE.match(normalized))
            )

            matched = False

            # cwd resolution (C8): if a cwd is declared and the candidate is
            # relative, resolve against cwd and re-sanitize. We run the join
            # through _sanitize_value so a '..' in the candidate cannot
            # silently escape cwd (posixpath.join('/workspace', '../etc')
            # would normalize to '/etc' without the check).
            if cwd_anchor is not None and not token_is_absolute:
                joined_raw = posixpath.join(cwd_anchor, normalized)
                joined, join_err = _sanitize_value(joined_raw)
                if join_err is None:
                    # Guard: the resolved path must still live under cwd.
                    # posixpath.normpath on a join that contains '..' would
                    # already be flagged by the sanitizer, but we defend in
                    # depth against any future helper change.
                    if joined == cwd_anchor or joined.startswith(cwd_anchor.rstrip("/") + "/"):
                        if _matches_any(joined):
                            matched = True

            # Fallback: two-way absolute/relative coercion (partial CC-2 fix).
            # Claude Code and similar clients sometimes send './in_scope/file'
            # while the passport declares '/in_scope/*' — or vice versa.
            # Coerced forms are re-sanitized so a '..' introduced by the
            # original value (already denied above) cannot sneak through,
            # and more importantly the sanitizer's invariants hold on the
            # shape we're actually matching.
            if not matched and not token_is_absolute and any_absolute:
                coerced_raw = "/" + normalized
                coerced, coerce_err = _sanitize_value(coerced_raw)
                if coerce_err is None and _matches_any(coerced):
                    matched = True

            if not matched and token_is_absolute and any_relative and normalized.startswith("/"):
                coerced_raw = normalized.lstrip("/")
                if coerced_raw:
                    coerced, coerce_err = _sanitize_value(coerced_raw)
                    if coerce_err is None and _matches_any(coerced):
                        matched = True

            if not matched:
                return False, (
                    f"resource '{_preview(token)}' is outside resource_scope {patterns}"
                )

    if exhausted["v"]:
        # Phase-3.1a C-2 fail-closed: the iterator aborted before finishing.
        # Any un-examined suffix of the payload could have carried an
        # out-of-scope resource. We must deny rather than imply PERMIT.
        return False, "resource scan exhausted (possible DoS) — fail-closed"

    return True, ""


class Decision(str, Enum):
    """Tri-state governance decision for tool-call evaluation (B.2).

    The verifier MUST return exactly one of these for every evaluation.
    Callers MUST treat only PERMIT as allowing execution; all other
    states MUST block the tool call (Phase 3.3k fail-closed discipline).

    PERMIT
        The tool call is within declared scope, budget, and delegation
        policy. Safe to execute.

    DENY
        The tool call violates a mission-declared boundary:
        - tool not in allowed_tools / tool in forbidden_tools
        - resource path outside resource_scope patterns
        - budget exceeded (max_tool_calls / max_duration_s)
        - delegation not allowed or depth exhausted

    VIOLATION
        A governance invariant is broken:
        - Mission Declaration tampered (chain_invalid)
        - Passport revoked via status list
        - Memory integrity failure
        - Delegation chain splice detected
        These are MORE severe than DENY — they indicate the session's
        credentials are compromised, not just that one call is out of scope.

    INSUFFICIENT_EVIDENCE
        The verifier cannot make a confident decision:
        - Approval operator unavailable
        - State file corrupted / unavailable
        - Network error fetching Mission Declaration or status list
        Callers MUST treat this as DENY (fail-closed). The distinction
        exists so audit trails can separate "known bad" (DENY) from
        "uncertain" (INSUFFICIENT_EVIDENCE) for post-hoc analysis.
    """

    PERMIT = "PERMIT"
    DENY = "DENY"
    VIOLATION = "VIOLATION"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


def _coerce_denial_reason(value: Any) -> DenialReason | None:
    if value is None or value == "":
        return None
    if isinstance(value, DenialReason):
        return value
    if isinstance(value, str):
        try:
            return DenialReason(value)
        except ValueError:
            return None
    return None


def _legacy_denial_reason(decision: Decision, reason: str) -> DenialReason | None:
    if decision == Decision.PERMIT:
        return None

    normalized = reason.strip().lower()
    if normalized == "approval_fatigue_threshold":
        return DenialReason.APPROVAL_FATIGUE_THRESHOLD
    if normalized == "approval_operator_unavailable":
        return DenialReason.APPROVAL_OPERATOR_UNAVAILABLE
    if normalized == "approval_policy_invalid":
        return DenialReason.TELEMETRY_MISSING
    if normalized in {"passport_revoked", "revoked"}:
        return DenialReason.REVOKED
    if normalized in {"revocation_unavailable", "status_list_too_large"}:
        return DenialReason.REVOCATION_UNAVAILABLE
    if normalized == "chain_invalid":
        return DenialReason.CHAIN_INVALID
    if normalized == "memory_integrity_failure":
        return DenialReason.MEMORY_INTEGRITY_FAILURE
    if normalized == "memory_compromise_boundary":
        return DenialReason.MEMORY_COMPROMISE_BOUNDARY
    if (
        normalized.startswith("budget exceeded:")
        or normalized.startswith("duration exceeded:")
        or normalized.startswith("per-class budget exhausted")
    ):
        return DenialReason.BUDGET_EXHAUSTED
    if decision == Decision.INSUFFICIENT_EVIDENCE:
        return DenialReason.TELEMETRY_MISSING
    return DenialReason.POLICY_DENIED


def _receipt_step_id(
    passport_jti: str,
    timestamp: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> str:
    material = json.dumps(
        {
            "passport_jti": passport_jti,
            "timestamp": timestamp,
            "tool_name": tool_name,
            "arguments": arguments,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hmac.new(b"vibap-receipt-step", material.encode("utf-8"), "sha256").hexdigest()[:32]
    return f"step:{digest}"


def _policy_event_target(tool_name: str, arguments: dict[str, Any]) -> str:
    for key in (
        "path",
        "file_path",
        "filename",
        "url",
        "uri",
        "target",
        "resource",
        "destination",
        "dest",
        "to",
        "store_id",
        "record_id",
        "query",
        "expression",
    ):
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    if len(arguments) == 1:
        only_value = next(iter(arguments.values()))
        if isinstance(only_value, (str, int, float, bool)):
            return str(only_value)
    return tool_name


def _policy_action_class(tool_name: str) -> str:
    lowered = tool_name.lower()
    if "delegat" in lowered:
        return "delegate"
    if any(token in lowered for token in ("send", "email", "mail", "post", "notify", "message", "share")):
        return "send"
    if any(token in lowered for token in ("search", "find", "lookup", "grep")):
        return "search"
    if any(token in lowered for token in ("query", "sql", "select", "calc", "compute")):
        return "query"
    if any(token in lowered for token in ("write", "create", "append", "save", "upload")):
        return "write"
    if any(token in lowered for token in ("summar", "analy", "report")):
        return "summarize"
    if any(token in lowered for token in ("read", "get", "fetch", "view", "list", "download", "open")):
        return "read"
    if any(token in lowered for token in ("update", "edit", "modify", "delete", "remove")):
        return "write"
    return "observe"


def _policy_resource_family(
    tool_name: str,
    arguments: dict[str, Any],
    target: str,
    action_class: str,
) -> str:
    lowered_tool = tool_name.lower()
    lowered_target = target.lower()
    if _is_memory_store_tool(tool_name) or any(key in arguments for key in ("store_id", "record_id")):
        return "memory_store"
    if any(key in arguments for key in ("path", "file_path", "filename", "directory", "cwd")):
        return "filesystem"
    if any(key in arguments for key in ("url", "uri")):
        return "network_resource"
    if any(key in arguments for key in ("to", "recipient")):
        return "external_comms"
    if action_class == "delegate":
        return "delegation"
    if action_class in {"query", "summarize", "observe"}:
        return "computation"
    if any(token in lowered_tool for token in ("memory", "store")):
        return "memory_store"
    if any(token in lowered_target for token in ("/", ".txt", ".md", ".json", ".csv", ".pdf")):
        return "filesystem"
    return "general"


def _policy_side_effect_class(
    tool_name: str,
    action_class: str,
    resource_family: str,
) -> str:
    lowered = tool_name.lower()
    if action_class in {"search", "read", "query", "summarize", "observe"}:
        return "none"
    if action_class == "send":
        return "external_send"
    if _is_memory_store_tool(tool_name) or (
        action_class == "write" and resource_family in {"filesystem", "memory_store"}
    ):
        return "internal_write"
    if action_class in {"delegate", "write"} or any(
        token in lowered
        for token in (
            "delete",
            "remove",
            "update",
            "grant",
            "approve",
            "execute",
            "run",
            "lock",
            "unlock",
            "cancel",
            "transfer",
            "pay",
        )
    ):
        return "state_change"
    return "none"


@dataclass(slots=True)
class PolicyEvent:
    timestamp: str
    step_id: str
    actor: str
    verifier_id: str
    tool_name: str
    arguments: dict[str, Any]
    action_class: str
    target: str
    resource_family: str
    side_effect_class: str
    decision: Decision
    reason: str
    passport_jti: str
    trace_id: str | None = None
    run_nonce: str | None = None
    denial_reason: DenialReason | None = None
    response: Optional[str] = None
    duration_ms: float = 0.0
    budget_delta: dict[str, Any] | None = None
    evidence_proof_ref: dict[str, Any] | None = None
    # Ordered list of per-backend decisions (native + additional_policies).
    # Empty for missions without additional_policies. Each dict carries
    # {"backend", "label", "decision", "reasons", "eval_ms"}.
    policy_decisions: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "step_id": self.step_id,
            "actor": self.actor,
            "verifier_id": self.verifier_id,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "action_class": self.action_class,
            "target": self.target,
            "resource_family": self.resource_family,
            "side_effect_class": self.side_effect_class,
            "decision": self.decision.value,
            "reason": self.reason,
            "denial_reason": self.denial_reason.value if self.denial_reason is not None else None,
            "passport_jti": self.passport_jti,
            "trace_id": self.trace_id,
            "run_nonce": self.run_nonce,
            "response": self.response,
            "duration_ms": self.duration_ms,
            "budget_delta": dict(self.budget_delta) if self.budget_delta is not None else None,
            "evidence_proof_ref": copy.deepcopy(self.evidence_proof_ref),
            "policy_decisions": list(self.policy_decisions),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicyEvent":
        tool_name = data["tool_name"]
        arguments = dict(data.get("arguments", {}))
        target = data.get("target") or _policy_event_target(tool_name, arguments)
        action_class = data.get("action_class") or _policy_action_class(tool_name)
        resource_family = data.get("resource_family") or _policy_resource_family(
            tool_name, arguments, target, action_class
        )
        actor_value = data.get("actor")
        if not isinstance(actor_value, str) or not actor_value.strip():
            raise ValueError(
                "PolicyEvent.from_dict: 'actor' is required and must be a non-empty string"
            )
        return cls(
            timestamp=data["timestamp"],
            step_id=data.get("step_id")
            or _receipt_step_id(
                str(data.get("passport_jti", "")),
                data["timestamp"],
                tool_name,
                arguments,
            ),
            actor=actor_value,
            verifier_id=data.get("verifier_id", "vibap-governance-proxy"),
            tool_name=tool_name,
            arguments=arguments,
            action_class=action_class,
            target=target,
            resource_family=resource_family,
            side_effect_class=data.get("side_effect_class")
            or _policy_side_effect_class(tool_name, action_class, resource_family),
            decision=Decision(data["decision"]),
            reason=data["reason"],
            denial_reason=_coerce_denial_reason(data.get("denial_reason"))
            or _legacy_denial_reason(Decision(data["decision"]), data["reason"]),
            passport_jti=data["passport_jti"],
            trace_id=data.get("trace_id"),
            run_nonce=data.get("run_nonce"),
            response=data.get("response"),
            duration_ms=float(data.get("duration_ms", 0.0)),
            budget_delta=dict(data["budget_delta"]) if isinstance(data.get("budget_delta"), dict) else None,
            evidence_proof_ref=copy.deepcopy(data.get("evidence_proof_ref")),
            policy_decisions=list(data.get("policy_decisions", []) or []),
        )


class PassportStateUnavailableError(RuntimeError):
    """Fail-closed error for replay/revocation state that can't be trusted."""

    def __init__(self, error_code: str, detail: str) -> None:
        super().__init__(f"{error_code}: {detail}")
        self.error_code = error_code


class _MissionPolicyResolutionError(RuntimeError):
    def __init__(self, decision: Decision, reason: str, denial_reason: DenialReason) -> None:
        super().__init__(reason)
        self.decision = decision
        self.reason = reason
        self.denial_reason = denial_reason


@dataclass
class GovernanceSession:
    passport_token: str
    passport_claims: dict[str, Any]
    events: list[PolicyEvent] = field(default_factory=list)
    tool_call_count: int = 0
    tool_call_count_by_class: dict[str, int] = field(default_factory=dict)
    delegated_budget_reserved: int = 0
    delegated_children: list[dict[str, Any]] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: float | None = None
    summary: Optional[dict[str, Any]] = None
    attestation_token: str | None = None
    memory_stores: dict[str, GovernedMemoryStore] = field(default_factory=dict)
    memory_compromised_stores: set[str] = field(default_factory=set)
    last_memory_record_id: str | None = None
    last_receipt_id: str | None = None
    last_receipt_full_hash: str | None = None
    run_nonce: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)

    @property
    def elapsed_s(self) -> float:
        reference_time = self.end_time if self.end_time is not None else time.time()
        return reference_time - self.start_time

    @property
    def jti(self) -> str:
        return str(self.passport_claims["jti"])

    def check_and_record(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        policy_claims: dict[str, Any] | None = None,
        verifier_id: str = "vibap-governance-proxy",
    ) -> tuple[Decision, str, PolicyEvent]:
        """Atomically check a tool call and record the event under the session lock."""
        with self._lock:
            active_policy = policy_claims if policy_claims is not None else self.passport_claims
            actor = str(self.passport_claims.get("sub", "unknown"))
            target = _policy_event_target(tool_name, arguments)
            action_class = _policy_action_class(tool_name)
            resource_family = _policy_resource_family(tool_name, arguments, target, action_class)
            sec = _policy_side_effect_class(tool_name, action_class, resource_family)
            shared_context = {
                "passport": dict(active_policy),
                "session": {
                    "tool_call_count": self.tool_call_count,
                    "tool_call_count_by_class": dict(self.tool_call_count_by_class),
                    "side_effect_counts": dict(self.tool_call_count_by_class),
                    "delegated_budget_reserved": self.delegated_budget_reserved,
                    "delegation_depth": len(active_policy.get("delegation_chain", []) or []),
                    "elapsed_s": self.elapsed_s,
                    "cwd": active_policy.get("cwd"),
                },
                "elapsed_s": self.elapsed_s,
                "tool_call_count": self.tool_call_count,
                "action_class": action_class,
                "side_effect_class": sec,
            }

            decisions: list[PolicyDecision] = []
            policy_decisions_dicts: list[dict[str, Any]] = []
            additional = active_policy.get("additional_policies") or []

            try:
                native_backend = get_backend("native")
            except KeyError:
                native_decision = PolicyDecision(
                    backend="native",
                    label="ardur_builtin",
                    decision="Deny",
                    reasons=("native backend not registered",),
                    eval_ms=0.0,
                )
            else:
                native_decision = timed_evaluate(
                    native_backend,
                    tool_name=tool_name,
                    arguments=arguments,
                    principal=actor,
                    target=target,
                    context=shared_context,
                    policy_spec={},
                )
            decisions.append(native_decision)
            if additional:
                policy_decisions_dicts.append(GovernanceProxy._event_policy_decision_dict(native_decision))

            # Always evaluate every registered backend — no short-circuit on
            # Deny. §1 claims "all three evaluate on every call" and the audit
            # trail promise requires every backend's verdict in the receipt's
            # policy_decisions. compose_decisions() handles the deny-wins
            # semantics when given the full list. Removing the short-circuit
            # costs ~ms per additional backend but preserves the audit contract.
            # (Phase 3 external-review-G review CRITICAL #1, 2026-04-17.)
            for spec in additional:
                backend_name = str(spec.get("backend", "?"))
                policy_label = str(spec.get("label", ""))
                try:
                    backend = get_backend(backend_name)
                except KeyError:
                    policy_decision = PolicyDecision(
                        backend=backend_name,
                        label=policy_label,
                        decision="Deny",
                        reasons=(f"unknown policy backend: {backend_name}",),
                        eval_ms=0.0,
                    )
                else:
                    policy_decision = timed_evaluate(
                        backend,
                        tool_name=tool_name,
                        arguments=arguments,
                        principal=actor,
                        target=target,
                        context=shared_context,
                        policy_spec=dict(spec),
                    )
                    if policy_label and not policy_decision.label:
                        policy_decision = PolicyDecision(
                            backend=policy_decision.backend,
                            label=policy_label,
                            decision=policy_decision.decision,
                            reasons=policy_decision.reasons,
                            eval_ms=policy_decision.eval_ms,
                        )
                decisions.append(policy_decision)
                policy_decisions_dicts.append(GovernanceProxy._event_policy_decision_dict(policy_decision))

            final_decision, first_denier = compose_decisions(decisions)
            denial_reason: DenialReason | None = None
            if final_decision == "Allow":
                decision = Decision.PERMIT
                reason = "within scope"
            elif first_denier is None:
                decision = Decision.DENY
                reason = "composition fail-closed: all backends abstained"
                denial_reason = DenialReason.POLICY_DENIED
            elif first_denier.backend == "native":
                decision = Decision.DENY
                reason = "; ".join(first_denier.reasons) if first_denier.reasons else "native policy denied"
                denial_reason = _legacy_denial_reason(decision, reason)
            elif (
                first_denier.reasons
                and first_denier.reasons[0].startswith("unknown policy backend:")
            ):
                decision = Decision.DENY
                reason = first_denier.reasons[0]
                denial_reason = DenialReason.POLICY_DENIED
            else:
                decision = Decision.DENY
                denier_label = first_denier.label or first_denier.backend
                reason = (
                    f"{denier_label} ({first_denier.backend}): "
                    f"{', '.join(first_denier.reasons) if first_denier.reasons else 'denied'}"
                )
                denial_reason = DenialReason.POLICY_DENIED

            timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            event = PolicyEvent(
                timestamp=timestamp,
                step_id=_receipt_step_id(self.jti, timestamp, tool_name, arguments),
                actor=actor,
                verifier_id=verifier_id,
                tool_name=tool_name,
                arguments=arguments,
                action_class=action_class,
                target=target,
                resource_family=resource_family,
                side_effect_class=_policy_side_effect_class(
                    tool_name, action_class, resource_family
                ),
                decision=decision,
                reason=reason,
                passport_jti=self.jti,
                trace_id=self.jti,
                run_nonce=self.run_nonce,
                denial_reason=denial_reason,
                policy_decisions=policy_decisions_dicts,
            )
            self.events.append(event)
            if decision == Decision.PERMIT:
                self.tool_call_count += 1
                sec = event.side_effect_class
                self.tool_call_count_by_class[sec] = (
                    self.tool_call_count_by_class.get(sec, 0) + 1
                )

            return decision, reason, event

    def to_log(self) -> list[dict[str, Any]]:
        return [
            {
                "timestamp": event.timestamp,
                "step_id": event.step_id,
                "actor": event.actor,
                "verifier_id": event.verifier_id,
                "tool": event.tool_name,
                "action_class": event.action_class,
                "target": event.target,
                "resource_family": event.resource_family,
                "arguments": event.arguments,
                "side_effect_class": event.side_effect_class,
                "decision": event.decision.value,
                "reason": event.reason,
                "denial_reason": event.denial_reason.value if event.denial_reason is not None else None,
                "passport_jti": event.passport_jti,
                "trace_id": event.trace_id,
                "run_nonce": event.run_nonce,
                "response_preview": (event.response or "")[:200],
                "duration_ms": event.duration_ms,
                "budget_delta": dict(event.budget_delta) if event.budget_delta is not None else None,
            }
            for event in self.events
        ]

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "passport_token": self.passport_token,
            "passport_claims": self.passport_claims,
            "events": [event.to_dict() for event in self.events],
            "tool_call_count": self.tool_call_count,
            "tool_call_count_by_class": dict(self.tool_call_count_by_class),
            "delegated_budget_reserved": self.delegated_budget_reserved,
            "delegated_children": list(self.delegated_children),
            "run_nonce": self.run_nonce,
            "start_time": self.start_time,
            "summary": self.summary,
        }
        if self.end_time is not None:
            payload["end_time"] = self.end_time
        if self.attestation_token is not None:
            payload["attestation_token"] = self.attestation_token
        if self.memory_compromised_stores:
            payload["memory_compromised_stores"] = sorted(self.memory_compromised_stores)
        if self.last_receipt_id is not None:
            payload["last_receipt_id"] = self.last_receipt_id
        if self.last_receipt_full_hash is not None:
            payload["last_receipt_full_hash"] = self.last_receipt_full_hash
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GovernanceSession":
        session = cls(
            passport_token=data["passport_token"],
            passport_claims=dict(data["passport_claims"]),
        )
        session.events = [PolicyEvent.from_dict(item) for item in data.get("events", [])]
        session.tool_call_count = int(data.get("tool_call_count", 0))
        session.tool_call_count_by_class = dict(data.get("tool_call_count_by_class", {}))
        session.delegated_budget_reserved = int(data.get("delegated_budget_reserved", 0))
        session.delegated_children = list(data.get("delegated_children", []))
        raw_run_nonce = data.get("run_nonce")
        if isinstance(raw_run_nonce, str) and raw_run_nonce:
            session.run_nonce = raw_run_nonce
        session.start_time = float(data.get("start_time", time.time()))
        session.summary = data.get("summary")
        raw_end_time = data.get("end_time")
        if raw_end_time is None and isinstance(session.summary, dict):
            elapsed_s = session.summary.get("elapsed_s")
            if elapsed_s is not None:
                try:
                    raw_end_time = session.start_time + float(elapsed_s)
                except (TypeError, ValueError):
                    raw_end_time = None
        session.end_time = float(raw_end_time) if raw_end_time is not None else None
        session.attestation_token = data.get("attestation_token")
        session.memory_compromised_stores = set(data.get("memory_compromised_stores", []))
        session.last_receipt_id = data.get("last_receipt_id")
        session.last_receipt_full_hash = data.get("last_receipt_full_hash")
        session.memory_stores = {}
        return session


class GovernanceProxy:
    def __init__(
        self,
        log_path: str | Path | None = None,
        state_dir: str | Path | None = None,
        keys_dir: str | Path | None = None,
        public_key: ec.EllipticCurvePublicKey | None = None,
        private_key: ec.EllipticCurvePrivateKey | None = None,
        receipts_log_path: str | Path | None = None,
        policy_store: Any | None = None,
        lineage_budget_ledger: LineageBudgetLedger | None = None,
        biscuit_issuer_public_key: Any | None = None,
    ) -> None:
        # policy_store: optional PolicyStore (see vibap.policy_store).
        # When provided, the proxy resolves additional_policies from
        # the store at session-start time, keyed by the credential's
        # mission_id (the agent_id claim). When None, the proxy
        # honors whatever additional_policies are already in the
        # claims — the legacy behavior. The demo uses the store;
        # tests that want to bypass it pass None and populate
        # additional_policies directly in a mission dict.
        self.policy_store = policy_store
        self.log_path = Path(log_path).expanduser() if log_path is not None else DEFAULT_LOG_PATH
        if receipts_log_path is not None:
            self.receipts_log_path = Path(receipts_log_path).expanduser()
        elif log_path is not None:
            self.receipts_log_path = self.log_path.with_name("receipts_log.jsonl")
        else:
            self.receipts_log_path = DEFAULT_RECEIPTS_LOG_PATH
        self._governance_log = RotatingJSONLLog(self.log_path)
        self._receipts_log = RotatingJSONLLog(self.receipts_log_path)
        self.state_dir = Path(state_dir).expanduser() if state_dir is not None else DEFAULT_STATE_DIR
        self.state_dir.mkdir(parents=True, exist_ok=True)
        if self.policy_store is None:
            from vibap.backed_policy_store import FileBackedPolicyStore
            self.policy_store = FileBackedPolicyStore(self.state_dir)
        self.sessions_dir = self.state_dir / "sessions"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.receipts_log_path.parent.mkdir(parents=True, exist_ok=True)
        self.replay_cache_path = self.state_dir / "replay_cache.json"
        self.revoked_path = self.state_dir / "revoked.json"
        self.lineage_hashes_path = self.state_dir / "lineage_hashes.json"
        self.lineage_budget_ledger = lineage_budget_ledger or FileLineageBudgetLedger(
            self.state_dir
        )
        self._biscuit_issuer_public_key = biscuit_issuer_public_key
        self.receipt_private_key = private_key or load_private_key(keys_dir=keys_dir)
        self.receipt_public_key = self.receipt_private_key.public_key()
        self._session_receipt_integrity_key = hashlib.sha256(
            b"vibap-session-receipt-integrity-v1"
            + self.receipt_private_key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        ).digest()
        if public_key is None:
            _, public_key = generate_keypair(keys_dir=keys_dir)
        self.public_key = public_key
        self._keys_dir = resolve_keys_dir(keys_dir)
        self.verifier_id = "vibap-governance-proxy"
        self.sessions: dict[str, GovernanceSession] = {}
        # Proxy-level lock protects sessions dict + _log writes.
        # Per-session mutations still use GovernanceSession._lock for finer granularity.
        self._sessions_lock = threading.Lock()
        self._kill_switch_active = False
        self._kill_switch_lock = threading.Lock()
        # Cryptographer R2 #2: KB-JWT nonce replay store. Prevents the same
        # KB-JWT from being presented multiple times within the freshness window.
        # OrderedDict for LRU eviction; max 4096 entries.
        # _nonce_lock guards check-then-insert under ThreadingHTTPServer:
        # CPython GIL makes single dict ops atomic but releases between them,
        # so `nonce in dict; dict[nonce] = ts` is racy without an explicit lock.
        self._seen_kb_nonces: OrderedDict[str, float] = OrderedDict()
        self._KB_NONCE_MAX = 4096
        self._nonce_lock = threading.Lock()
        self._log_lock = threading.Lock()
        self._receipts_log_lock = threading.Lock()
        self._lineage_parent_cache_lock = threading.Lock()
        self._lineage_parent_cache: OrderedDict[str, str | None] = OrderedDict()
        self._replay_cache_sentinel: str | None = None
        self._revoked_sentinel: str | None = None
        self._lineage_hashes_sentinel: str | None = None
        self._approval_trackers_lock = threading.Lock()
        self._approval_trackers: dict[tuple[int, float], ApprovalRateTracker] = {}
        self._last_seen_receipts: dict[str, str] = {}
        self._last_seen_receipts_lock = threading.Lock()
        self.mission_cache = MissionCache(max_entries=256)
        try:
            get_backend("native")
        except KeyError:
            register_backend(NativeBackend())
        self._initialize_passport_state_files()

    def _approval_tracker(self, max_ap: int, window_s: float) -> ApprovalRateTracker:
        key = (max_ap, window_s)
        with self._approval_trackers_lock:
            existing = self._approval_trackers.get(key)
            if existing is None:
                existing = ApprovalRateTracker(max_ap, window_s)
                self._approval_trackers[key] = existing
            return existing

    @staticmethod
    def _approval_operator_id(
        passport_claims: dict[str, Any],
        arguments: dict[str, Any],
    ) -> str | None:
        for raw_value in (passport_claims.get("operator_id"), arguments.get("operator_id")):
            if isinstance(raw_value, str):
                normalized = raw_value.strip()
                if normalized:
                    return normalized
        return None

    def _missing_required_telemetry(
        policy_claims: dict[str, Any],
        arguments: dict[str, Any],
    ) -> list[str]:
        required = _declared_required_telemetry(policy_claims)
        if not required:
            return []
        return _missing_declared_telemetry(arguments, required)

    @staticmethod
    def _record_tool_policy_event(
        session: GovernanceSession,
        tool_name: str,
        arguments: dict[str, Any],
        decision: Decision,
        reason: str,
        denial_reason: DenialReason | None,
        *,
        verifier_id: str = "vibap-governance-proxy",
    ) -> None:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        actor = str(session.passport_claims.get("sub", "unknown"))
        target = _policy_event_target(tool_name, arguments)
        action_class = _policy_action_class(tool_name)
        resource_family = _policy_resource_family(tool_name, arguments, target, action_class)
        session.events.append(
            PolicyEvent(
                timestamp=timestamp,
                step_id=_receipt_step_id(session.jti, timestamp, tool_name, arguments),
                actor=actor,
                verifier_id=verifier_id,
                tool_name=tool_name,
                arguments=arguments,
                action_class=action_class,
                target=target,
                resource_family=resource_family,
                side_effect_class=_policy_side_effect_class(
                    tool_name, action_class, resource_family
                ),
                decision=decision,
                reason=reason,
                passport_jti=session.jti,
                trace_id=session.jti,
                run_nonce=session.run_nonce,
                denial_reason=denial_reason,
            )
        )

    @staticmethod
    def _downgrade_last_permit(
        session: GovernanceSession,
        new_decision: Decision,
        new_reason: str,
        new_denial_reason: DenialReason | None,
    ) -> None:
        if not session.events:
            return
        last = session.events[-1]
        if last.decision != Decision.PERMIT:
            return
        last.decision = new_decision
        last.reason = new_reason
        last.denial_reason = new_denial_reason
        session.tool_call_count -= 1

    def _synthetic_policy_event(
        self,
        session: GovernanceSession,
        tool_name: str,
        arguments: dict[str, Any],
        decision: Decision,
        reason: str,
        denial_reason: DenialReason | None,
    ) -> PolicyEvent:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        target = _policy_event_target(tool_name, arguments)
        action_class = _policy_action_class(tool_name)
        resource_family = _policy_resource_family(tool_name, arguments, target, action_class)
        return PolicyEvent(
            timestamp=timestamp,
            step_id=_receipt_step_id(session.jti, timestamp, tool_name, arguments),
            actor=str(session.passport_claims.get("sub", "unknown")),
            verifier_id=self.verifier_id,
            tool_name=tool_name,
            arguments=arguments,
            action_class=action_class,
            target=target,
            resource_family=resource_family,
            side_effect_class=_policy_side_effect_class(tool_name, action_class, resource_family),
            decision=decision,
            reason=reason,
            passport_jti=session.jti,
            trace_id=session.jti,
            run_nonce=session.run_nonce,
            denial_reason=denial_reason,
        )

    @staticmethod
    def _event_policy_decision_dict(decision: PolicyDecision) -> dict[str, Any]:
        backend = decision.backend
        label = decision.label
        if backend == "native":
            backend = "native_claims"
            label = "ardur_builtin"
        return {
            "backend": backend,
            "label": label,
            "decision": decision.decision,
            "reasons": list(decision.reasons),
            "eval_ms": decision.eval_ms,
        }

    @staticmethod
    def _signed_policy_decisions(
        event: PolicyEvent,
        decision: Decision,
        audit_reason: str,
    ) -> list[dict[str, Any]]:
        if not event.policy_decisions:
            return [{
                "backend": "native",
                "decision": "Allow" if decision == Decision.PERMIT else "Deny",
                "reason": audit_reason or None,
            }]
        compact: list[dict[str, Any]] = []
        for item in event.policy_decisions:
            backend = str(item.get("backend", "unknown"))
            if backend == "native_claims":
                backend = "native"
            reasons = tuple(str(entry) for entry in item.get("reasons", []) or [])
            compact.append(
                {
                    "backend": backend,
                    "decision": str(item.get("decision", "Abstain")),
                    "reason": "; ".join(reasons) if reasons else None,
                }
            )
        return compact

    @staticmethod
    def _receipt_budget_remaining(
        session: GovernanceSession,
        policy_claims: dict[str, Any],
    ) -> dict[str, int]:
        remaining: dict[str, int] = {}
        for key, raw_cap in dict(policy_claims.get("max_tool_calls_per_class", {}) or {}).items():
            try:
                cap = int(raw_cap)
            except (TypeError, ValueError):
                continue
            used = int(session.tool_call_count_by_class.get(str(key), 0))
            remaining[str(key)] = max(0, cap - used)
        return remaining

    @staticmethod
    def _receipt_budget_delta(
        session: GovernanceSession,
        event: PolicyEvent,
        decision: Decision,
        policy_claims: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            ceiling = int(policy_claims.get("max_tool_calls", 0))
        except (TypeError, ValueError):
            ceiling = 0
        if decision == Decision.PERMIT:
            operation = "consume"
            amount = 1
            used_before = max(0, int(session.tool_call_count) - amount)
        else:
            operation = "reject"
            amount = 0
            used_before = int(session.tool_call_count)
        remaining_before = (
            max(0, ceiling - used_before - int(session.delegated_budget_reserved))
            if ceiling > 0
            else 0
        )
        remaining_after = (
            max(
                0,
                ceiling
                - int(session.tool_call_count)
                - int(session.delegated_budget_reserved),
            )
            if ceiling > 0
            else 0
        )
        return {
            "operation": operation,
            "resource": "tool_call",
            "amount": amount,
            "unit": "tool_call",
            "remaining_for_parent": remaining_before,
            "remaining_after": remaining_after,
            "used_total": used_before,
            "reserved_total": int(session.delegated_budget_reserved),
            "side_effect_class": event.side_effect_class,
        }

    def _build_receipt_log_entry(
        self,
        session: GovernanceSession,
        event: PolicyEvent,
        decision: Decision,
        audit_reason: str,
        policy_claims: dict[str, Any],
    ) -> dict[str, Any]:
        # Deferred local import to break the proxy ↔ receipt module-load cycle
        # (CodeQL py/unsafe-cyclic-import). receipt.py only references this
        # module under ``TYPE_CHECKING``, so the cycle is type-only at the
        # runtime level — but moving this import out of module scope removes
        # the static topology cycle that the linter flags. Cost is one
        # ``sys.modules`` cache lookup per call to this method.
        from .receipt import build_receipt, sign_receipt

        signed_policy_decisions = self._signed_policy_decisions(event, decision, audit_reason)
        if event.budget_delta is None:
            event.budget_delta = self._receipt_budget_delta(
                session,
                event,
                decision,
                policy_claims,
            )
        if (
            getattr(event, "evidence_proof_ref", None) is None
            and policy_claims.get("mission_digest") is not None
        ):
            event.evidence_proof_ref = {
                "type": "mission_binding",
                "mission_ref": copy.deepcopy(policy_claims.get("mission_ref")),
                "mission_digest": policy_claims.get("mission_digest"),
            }
        receipt = build_receipt(
            decision,
            event,
            parent_receipt_hash=session.last_receipt_full_hash,
            policy_decisions=signed_policy_decisions,
            reason=audit_reason,
            budget_remaining=self._receipt_budget_remaining(session, policy_claims),
        )
        signed_jwt = sign_receipt(receipt, self.receipt_private_key)
        session.last_receipt_id = receipt.receipt_id
        session.last_receipt_full_hash = hashlib.sha256(
            signed_jwt.encode("ascii")
        ).hexdigest()
        with self._last_seen_receipts_lock:
            self._last_seen_receipts[receipt.grant_id] = receipt.receipt_id
        entry = {
            "type": "execution_receipt",
            "session_id": session.jti,
            "receipt_id": receipt.receipt_id,
            "parent_receipt_hash": receipt.parent_receipt_hash,
            "parent_receipt_id": receipt.parent_receipt_id,
            "grant_id": receipt.grant_id,
            "step_id": receipt.step_id,
            "tool": receipt.tool,
            "verdict": receipt.verdict,
            "evidence_level": receipt.evidence_level,
            "trace_id": receipt.trace_id,
            "run_nonce": receipt.run_nonce,
            "invocation_digest": receipt.invocation_digest,
            "jwt": signed_jwt,
            "audit_reason": audit_reason,
        }
        if receipt.public_denial_reason is not None:
            entry["public_denial_reason"] = receipt.public_denial_reason
        if receipt.internal_denial_code is not None:
            entry["internal_denial_code"] = receipt.internal_denial_code
        return entry

    def _resolve_authoritative_policy_claims(
        self,
        passport_claims: dict[str, Any],
    ) -> dict[str, Any]:
        mission_ref_raw = passport_claims.get("mission_ref")
        if mission_ref_raw is None:
            return passport_claims
        try:
            mission_ref = parse_mission_ref(mission_ref_raw)
            mission = self.mission_cache.resolve(
                mission_ref,
                lambda: fetch_mission_declaration(mission_ref, self.public_key),
            )
            if mission_is_revoked(mission, self.public_key):
                raise _MissionPolicyResolutionError(
                    Decision.VIOLATION,
                    "revoked",
                    DenialReason.REVOKED,
            )
            claims = mission.policy_claims()
            claims["mission_ref"] = copy.deepcopy(mission_ref_raw)
            claims["mission_digest"] = mission.payload_digest
            # H5 (2026-04-19): propagate mission_id from the session
            # claims AND consult the PolicyStore for this mission's
            # authoritative additional_policies on every call.
            #
            # Why per-call (vs session-start only):
            #   - mission_ref sessions re-resolve the mission declaration
            #     from the mission registry on every evaluation (via
            #     mission_cache above), which rebuilds ``claims`` from
            #     scratch. If we don't re-seed additional_policies from
            #     the store here, the mission_ref path silently drops
            #     store-authoritative policies that start_session
            #     loaded — i.e. Cedar/forbid_rules composition for
            #     mission_ref sessions degrades to native-only.
            #   - Ops typically rotate PolicyStore content (security-
            #     team patches a forbid-rule, compliance updates a
            #     Cedar policy). For mission_ref sessions the
            #     intention is that the NEXT eval sees the new policy;
            #     per-call resolution delivers that.
            # We do NOT re-read the store for non-mission_ref sessions:
            # those had additional_policies snapshotted into
            # passport_claims at start_session (H3/H1 fix), and that
            # snapshot is the intentional semantic (stable per-session).
            #
            # Empty-list authoritativeness (H3) is preserved — `is not
            # None` means an empty list from the store still overwrites
            # any additional_policies the mission declaration carried.
            mission_id = (
                passport_claims.get("mission_id")
                or claims.get("mission_id")
                or passport_claims.get("sub")
            )
            if mission_id:
                claims["mission_id"] = str(mission_id)
            if self.policy_store is not None and mission_id:
                stored_policies = self.policy_store.get_policies(
                    mission_id=str(mission_id),
                    agent_id=str(passport_claims.get("sub", "")),
                )
                if stored_policies is not None:
                    claims["additional_policies"] = list(stored_policies)
            return claims
        except MissionStatusUnavailableError as exc:
            raise _MissionPolicyResolutionError(
                Decision.INSUFFICIENT_EVIDENCE,
                exc.reason,
                DenialReason.REVOCATION_UNAVAILABLE,
            ) from exc
        except MissionBindingError as exc:
            raise _MissionPolicyResolutionError(
                Decision.VIOLATION,
                exc.reason,
                DenialReason.CHAIN_INVALID,
            ) from exc

    def _get_or_create_memory_store(
        self,
        session: GovernanceSession,
        arguments: dict[str, Any],
    ) -> GovernedMemoryStore:
        store_id = arguments["store_id"]
        if not isinstance(store_id, str) or not store_id:
            raise ValueError("memory operation requires non-empty store_id")
        existing = session.memory_stores.get(store_id)
        if existing is not None:
            return existing
        ttl_s = int(arguments.get("ttl_s", 3600))
        resource_family = str(arguments.get("resource_family", "vibap.memory.generic"))
        integrity_policy = arguments.get("integrity_policy", "default")
        store = GovernedMemoryStore(store_id, resource_family, ttl_s, integrity_policy)
        session.memory_stores[store_id] = store
        return store

    def _proxy_memory_write(self, session: GovernanceSession, arguments: dict[str, Any]) -> None:
        store_id = arguments.get("store_id")
        content = arguments.get("content")
        if not isinstance(store_id, str) or not store_id:
            raise ValueError("memory_store_write requires store_id")
        if not isinstance(content, str):
            raise ValueError("memory_store_write requires content (str)")
        # FIX-8 (2026-04-28): caller-supplied actor_private_key_pem is
        # rejected. Before this, any caller could pass an arbitrary EC
        # private key as the signer for a memory-store write, producing
        # records that verified with the caller's matching public key —
        # an attacker who could call this tool could write records under
        # any identity they liked. The signer is now bound to the
        # proxy's session-anchored key so receipts are always
        # attributable to the governing proxy.
        if "actor_private_key_pem" in arguments:
            raise ValueError(
                "memory_store_write no longer accepts caller-supplied "
                "actor_private_key_pem; the proxy's session-bound key is "
                "the canonical signer (FIX-8, 2026-04-28). Remove the "
                "argument from your tool-call payload."
            )
        actor_key = load_private_key(self._keys_dir)
        store = self._get_or_create_memory_store(session, arguments)
        session.last_memory_record_id = store.write(content, actor_key)

    def _proxy_memory_read(self, session: GovernanceSession, arguments: dict[str, Any]) -> None:
        store_id = arguments.get("store_id")
        record_id = arguments.get("record_id")
        if not isinstance(store_id, str) or not store_id:
            raise ValueError("memory_store_read requires store_id")
        if not isinstance(record_id, str) or not record_id:
            raise ValueError("memory_store_read requires record_id")
        store = session.memory_stores.get(store_id)
        if store is None:
            raise MemoryIntegrityError("memory store not initialized in this session")
        # FIX-8 (2026-04-28): caller-supplied verifier_public_key_pem is
        # rejected. Before this, a caller could specify any EC public
        # key against which stored records would be validated — an
        # attacker who controlled both the writer and the read path
        # could substitute their own key to make forged records verify.
        # The proxy's session-anchored public key is now the canonical
        # verifier, matching the writer-side binding above.
        if "verifier_public_key_pem" in arguments:
            raise ValueError(
                "memory_store_read no longer accepts caller-supplied "
                "verifier_public_key_pem; the proxy's session-bound public "
                "key is the canonical verifier (FIX-8, 2026-04-28). Remove "
                "the argument from your tool-call payload."
            )
        verifier_key = self.public_key
        store.read(record_id, verifier_key)

    def _apply_memory_post_permit(
        self,
        session: GovernanceSession,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[Decision, str]:
        if tool_name not in (MEMORY_STORE_WRITE_TOOL, MEMORY_STORE_READ_TOOL):
            return Decision.PERMIT, "within scope"
        try:
            if tool_name == MEMORY_STORE_WRITE_TOOL:
                self._proxy_memory_write(session, arguments)
            else:
                self._proxy_memory_read(session, arguments)
            return Decision.PERMIT, "within scope"
        except ValueError as exc:
            self._downgrade_last_permit(
                session,
                Decision.DENY,
                str(exc),
                DenialReason.POLICY_DENIED,
            )
            return Decision.DENY, str(exc)
        except MemoryIntegrityError:
            sid = arguments.get("store_id")
            if isinstance(sid, str) and sid:
                session.memory_compromised_stores.add(sid)
            self._downgrade_last_permit(
                session,
                Decision.VIOLATION,
                "memory_integrity_failure",
                DenialReason.MEMORY_INTEGRITY_FAILURE,
            )
            return Decision.VIOLATION, "memory_integrity_failure"

    def verify_passport_token(
        self,
        token: str,
        *,
        parent_token: str | None = None,
    ) -> dict[str, Any]:
        # If the parent session is live, pass its raw JWT so
        # verify_passport can anchor the immediate delegation hash. If the
        # parent is not cached, fall back to the persisted lineage hash
        # index: it is an authoritative jti -> token_hash registry written
        # when sessions start, so cold lineage checks can fail closed without
        # loading ancestor session blobs.
        if parent_token is None:
            parent_token = self._resolve_cached_parent_token(token)
        needs_trusted_hashes = (
            parent_token is None and self._unverified_parent_jti(token) is not None
        )
        with self._passport_state_lock():
            trusted_hashes = None
            trusted_lineage = None
            if needs_trusted_hashes:
                trusted_hashes, trusted_lineage = self._load_lineage_index_locked()
            claims = verify_passport(
                token,
                self.public_key,
                parent_token=parent_token,
                trusted_parent_token_hashes=trusted_hashes,
                trusted_parent_lineage=trusted_lineage,
            )
            self._seed_lineage_parent_cache(claims)
            self._assert_passport_lineage_not_revoked_locked(claims)
        return claims

    @staticmethod
    def _unverified_parent_jti(token: str) -> str | None:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        padding = "=" * (-len(parts[1]) % 4)
        try:
            payload_bytes = base64.urlsafe_b64decode(
                (parts[1] + padding).encode("ascii")
            )
            unverified = json.loads(payload_bytes.decode("utf-8"))
        except (
            UnicodeEncodeError,
            UnicodeDecodeError,
            binascii.Error,
            json.JSONDecodeError,
        ):
            return None
        if not isinstance(unverified, dict):
            return None
        parent_jti = unverified.get("parent_jti")
        return parent_jti if isinstance(parent_jti, str) and parent_jti else None

    def _resolve_cached_parent_token(self, child_token: str) -> str | None:
        """Return the raw JWT of the cached parent session, if present.

        Takes an unverified peek at the child token's ``parent_jti`` claim
        (signature validation is re-done by :func:`verify_passport` a few
        lines later; this peek only needs to resolve a dict lookup). If
        the token isn't delegated, or the parent isn't currently in
        ``self.sessions``, returns ``None`` and the verifier falls back to
        the persisted lineage hash index.
        """
        parent_jti = self._unverified_parent_jti(child_token)
        if parent_jti is None:
            return None
        with self._sessions_lock:
            parent_session = self.sessions.get(parent_jti)
        if parent_session is None:
            return None
        return parent_session.passport_token

    def revoke(self, jti: str) -> None:
        if not _SESSION_ID_RE.match(jti):
            raise ValueError("revoked passport jti must be a UUID")
        with self._passport_state_lock():
            revoked = self._load_revoked_locked()
            revoked.setdefault(jti, int(time.time()))
            self._persist_revoked_locked(revoked)

    @property
    def kill_switch_active(self) -> bool:
        with self._kill_switch_lock:
            return self._kill_switch_active

    def activate_kill_switch(self) -> None:
        with self._kill_switch_lock:
            self._kill_switch_active = True
        ardur_metrics.kill_switch_active.set(1)
        self._log_event("kill_switch_activate", {"timestamp": int(time.time())})

    def deactivate_kill_switch(self) -> None:
        with self._kill_switch_lock:
            self._kill_switch_active = False
        ardur_metrics.kill_switch_active.set(0)
        self._log_event("kill_switch_deactivate", {"timestamp": int(time.time())})

    def _log_event(self, event_type: str, detail: dict, correlation_id: str | None = None) -> None:
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "event_type": event_type,
            "severity": "INFO",
            "correlation_id": correlation_id or "",
            "detail": detail,
        }
        self._governance_log.write(entry)

    def start_session(
        self,
        passport_token: str,
        holder_public_key: "ec.EllipticCurvePublicKey | None" = None,
        kb_jwt: str | None = None,
    ) -> GovernanceSession:
        """Start a governed session from a passport token.

        If the passport carries a ``cnf`` claim (Proof of Possession), the
        caller MUST supply both ``holder_public_key`` AND ``kb_jwt``. The
        proxy verifies:
        1. Key binding: cnf.jkt matches holder's thumbprint
        2. Key possession: KB-JWT is signed by holder's private key,
           references this specific passport, and is fresh

        Without ``cnf``, the passport is a bearer token (backward compatible).

        Phase 3.3m → 3.3o (K2 / Round 11 I6 + cryptographer review #07).
        """
        claims = self.verify_passport_token(passport_token)

        # K2 (I6): full Proof of Possession — key binding + KB-JWT.
        # Cryptographer review #07 identified that key binding alone
        # (thumbprint match) is insufficient: an attacker with the passport
        # JWT and the public key passes trivially. The KB-JWT proves the
        # presenter holds the PRIVATE key right now.
        from .passport import verify_pop
        # 2026-04-21 audit fix: `claims.get("cnf")` previously used a
        # truthy check, which treated `cnf={}`, `cnf=""`, `cnf=0`,
        # `cnf=False`, `cnf=[]` as bearer mode and silently skipped PoP.
        # A token signed with a malformed-but-present cnf now correctly
        # routes through verify_pop, which rejects anything that isn't a
        # dict carrying a non-empty jkt.
        if "cnf" in claims and claims["cnf"] is not None:
            verify_pop(claims, passport_token, holder_public_key, kb_jwt)
            # Cryptographer R2 #2: nonce replay defense. Reject KB-JWTs with
            # previously-seen nonces within the freshness window.
            if kb_jwt is not None:
                import jwt as _jwt
                from .passport import assert_iat_in_window
                # Decode outside the nonce lock — decoding touches no shared
                # state. Failure here is fail-closed: a malformed KB-JWT must
                # not be accepted just because verify_pop already passed (the
                # signature/freshness path validates a different code path).
                try:
                    kb_claims = _jwt.decode(
                        kb_jwt, holder_public_key, algorithms=["ES256"],
                        options={"verify_aud": False, "verify_iat": False},
                    )
                except _jwt.PyJWTError as exc:
                    raise PermissionError(
                        f"KB-JWT decode failed during nonce extraction: {exc}"
                    ) from exc
                # FIX-R6-9 (round-6, 2026-04-29): defense-in-depth iat bound
                # on this second KB-JWT decode. verify_pop above already
                # bounds the same JWT, but a future refactor that splits
                # the lock acquisition or removes verify_pop while keeping
                # this nonce-extraction path would silently re-open the
                # iat-future bypass. Apply the canonical helper with a
                # tight window matching verify_pop's 30s clock-drift
                # tolerance for short-lived KB-JWTs.
                try:
                    assert_iat_in_window(
                        kb_claims.get("iat"),
                        future_skew_s=30,
                        past_skew_s=300,
                        field_name="KB-JWT iat",
                    )
                except _jwt.InvalidTokenError as exc:
                    raise PermissionError(str(exc)) from exc
                nonce = kb_claims.get("nonce", "")
                if not isinstance(nonce, str) or not nonce:
                    raise PermissionError("KB-JWT nonce must be a non-empty string")
                # H1 fix: check-then-insert under a dedicated lock to defeat
                # concurrent KB-JWT replay under ThreadingHTTPServer. The
                # _session_coordination_lock(jti) below is keyed by jti and
                # would not serialize same-nonce different-jti requests; the
                # nonce store is global, so it needs its own lock.
                with self._nonce_lock:
                    if nonce in self._seen_kb_nonces:
                        raise PermissionError(
                            "KB-JWT nonce replay detected — this KB-JWT was already presented"
                        )
                    self._seen_kb_nonces[nonce] = time.time()
                    # LRU eviction
                    while len(self._seen_kb_nonces) > self._KB_NONCE_MAX:
                        self._seen_kb_nonces.popitem(last=False)
        jti = str(claims["jti"])

        # Passport replay defense (external-review-X audit C-1): reject re-use of a jti
        # that already has a live or persisted session. A passport is a
        # single-use credential — once started, it can't be restarted to
        # reset the budget. Use /issue to mint a fresh passport instead.
        with self._session_coordination_lock(jti):
            with self._sessions_lock:
                if jti in self.sessions:
                    raise ValueError(
                        f"passport jti '{jti}' already has an active session; passports are single-use"
                    )
            if self._session_path(jti).exists():
                raise ValueError(
                    f"passport jti '{jti}' has a persisted session on disk; passports are single-use"
                )
            with self._passport_state_lock():
                self._assert_passport_lineage_not_revoked_locked(claims)
            self._record_passport_use(claims, passport_token)

            # Resolve additional_policies from the authoritative
            # PolicyStore for this mission before the session is
            # cached. See start_session_from_biscuit for the full
            # rationale — same mechanism, both paths.
            #
            # Empty-list semantics: the store returns None when the
            # mission is unknown (fall back to credential-supplied
            # policies), an empty list when the mission is registered
            # with zero extra policies (authoritative "no policies"
            # signal — MUST overwrite any credential-supplied
            # additional_policies, otherwise an attacker who forged
            # additional_policies into the credential would silently
            # escalate).
            if self.policy_store is not None:
                # H1: look up by mission_id, NOT by sub. sub is the
                # agent identifier; two different missions for the
                # same agent MUST land on distinct store keys. For
                # legacy tokens that lack mission_id, fall back to
                # sub so pre-H1 credentials in flight don't lose
                # policy resolution.
                mission_id_lookup = str(
                    claims.get("mission_id")
                    or claims.get("sub", "")
                )
                stored_policies = self.policy_store.get_policies(
                    mission_id=mission_id_lookup,
                    agent_id=str(claims.get("sub", "")),
                )
                if stored_policies is not None:
                    claims["additional_policies"] = list(stored_policies)

            session = GovernanceSession(passport_token=passport_token, passport_claims=claims)
            with self._sessions_lock:
                # Double-check under lock (TOCTOU defense)
                if jti in self.sessions:
                    raise ValueError(
                        f"passport jti '{jti}' already has an active session; passports are single-use"
                    )
                self.sessions[jti] = session
            self._persist_session(session)
        self._log(
            {
                "type": "session_start",
                "jti": session.jti,
                "agent": claims["sub"],
                "mission": claims["mission"],
            }
        )
        return session

    def start_session_from_aat(
        self,
        aat_token: str,
        *,
        signing_key: ec.EllipticCurvePrivateKey | None = None,
        parent_aat_token: str | None = None,
        holder_public_key: "ec.EllipticCurvePublicKey | None" = None,
        kb_jwt: str | None = None,
        require_pop: bool = True,
    ) -> GovernanceSession:
        """Start a governed session from a minimal AAT-compatible JWT grant.

        The AAT grant remains the external authorization artifact. The proxy
        maps it to an internal passport token with the same ``jti`` so receipts
        and delegated children keep the AAT grant id as their lineage anchor.

        Proof-of-possession (default ``True`` since 2026-04-28): if the AAT
        carries a ``cnf`` claim, the caller MUST supply ``holder_public_key``
        + ``kb_jwt`` so the adapter can verify the presenter holds the matching
        private key (RFC 7800 confirmation-bound AAT semantics). Bearer AATs
        (no ``cnf``) bypass PoP regardless of the flag. Library callers that
        legitimately need bearer-style acceptance of a cnf-bearing AAT MUST
        opt out with ``require_pop=False`` so the security-relevant choice is
        visible at the call site. See :func:`material_from_aat_grant` for the
        H2 remediation rationale and the 2026-04-28 default flip.
        """
        parent_claims = (
            decode_aat_claims(parent_aat_token, self.public_key)
            if parent_aat_token is not None
            else None
        )
        material = material_from_aat_grant(
            aat_token,
            self.public_key,
            self.mission_cache,
            parent_claims=parent_claims,
            holder_public_key=holder_public_key,
            kb_jwt=kb_jwt,
            require_pop=require_pop,
        )
        internal_token = issue_passport(
            material.mission,
            signing_key or self.receipt_private_key,
            ttl_s=material.ttl_s,
            extra_claims=material.extra_claims,
        )
        return self.start_session(internal_token)

    def start_session_from_biscuit(
        self,
        biscuit_token: bytes,
        issuer_public_key,
        *,
        audience: str = "ardur-proxy",
        now: int | None = None,
        peer_jwt_svid: str | None = None,
        peer_trust_bundle=None,
        svid_audience: str | None = None,
    ) -> GovernanceSession:
        """Start a governed session from a Biscuit mission passport.

        Phase 4 integration (2026-04-17): verifies a Biscuit credential
        offline with the issuer's public key, translates its
        :class:`PassportContext` into the same claims shape the JWT path
        produces, and runs the rest of the session-start machinery
        (single-use jti check, lineage revocation check, persistence).

        Phase 5 integration (A1, 2026-04-17): when ``peer_jwt_svid`` and
        ``peer_trust_bundle`` are supplied, this also performs SPIFFE
        peer-identity binding. The JWT-SVID is verified against the
        trust bundle (signature, expiry, audience) and the SVID's
        SPIFFE ID is compared to the passport's ``holder_spiffe_id``
        claim. Mismatch raises PermissionError. This closes the
        bearer-token gap: a stolen Biscuit can no longer be replayed
        by a party who doesn't also possess the holder's SVID.

        After this call the session behaves identically to one started
        via :meth:`start_session` — every subsequent ``evaluate_tool_call``
        goes through the composed backend path and produces a
        chain-hashed signed receipt. The session is flagged
        ``credential_format="biscuit-v1"`` in its claims so downstream
        code can tell it apart from JWT-backed sessions. When SVID
        binding is enforced, the session additionally records
        ``svid_bound=True`` and the verified ``holder_spiffe_id``.

        Args:
            biscuit_token: the serialized Biscuit bytes.
            issuer_public_key: the ``biscuit_auth.PublicKey`` that signed
                the authority block. Verifier must already trust this
                key (e.g. by reading it from a SPIFFE federation trust
                bundle).
            audience: conventional ``aud`` claim for the synthesized
                session; defaults to ``"ardur-proxy"``.
            now: optional unix timestamp override for expiry checking.
            peer_jwt_svid: (optional) the JWT-SVID presented by the
                peer agent at connection time. If supplied, SPIFFE
                peer-identity binding is enforced.
            peer_trust_bundle: (optional, required when
                ``peer_jwt_svid`` is supplied) the SPIFFE
                :class:`TrustBundle` against which the SVID is
                verified.
            svid_audience: (optional) expected ``aud`` claim on the
                JWT-SVID. Defaults to ``audience`` if not supplied.

        Raises:
            BiscuitVerifyError: the credential does not verify.
            PermissionError: SVID binding requested but the SVID
                doesn't match the passport's holder_spiffe_id, or the
                SVID fails its own verification.
            ValueError: if the jti is already in use (single-use rule),
                or if only one of (peer_jwt_svid, peer_trust_bundle) is
                supplied without the other.
        """
        # Validate SVID binding args up-front.
        if (peer_jwt_svid is None) != (peer_trust_bundle is None):
            raise ValueError(
                "peer_jwt_svid and peer_trust_bundle must be supplied "
                "together or not at all"
            )

        from .biscuit_passport import (
            verify_biscuit_passport,
            encode_biscuit_b64,
        )

        context = verify_biscuit_passport(
            biscuit_token, issuer_public_key, now=now
        )

        # Phase 5 A1: SPIFFE peer-identity binding.
        #
        # If the caller supplied a peer JWT-SVID, verify it against the
        # trust bundle and require its SPIFFE ID to equal the
        # passport's holder_spiffe_id claim. This closes the bearer-
        # token gap — a stolen Biscuit can't be replayed without the
        # holder's SVID.
        svid_bound = False
        if peer_jwt_svid is not None:
            from .spiffe_identity import verify_jwt_svid

            expected_audience = svid_audience or audience
            try:
                svid_claims = verify_jwt_svid(
                    peer_jwt_svid,
                    peer_trust_bundle,
                    expected_audience,
                )
            except Exception as exc:
                raise PermissionError(
                    f"peer JWT-SVID verification failed: {exc}"
                ) from exc

            if context.spiffe_id is None or context.spiffe_id == "":
                raise PermissionError(
                    "passport has no holder_spiffe_id but SVID binding "
                    "was requested — cannot bind"
                )
            if svid_claims.spiffe_id != context.spiffe_id:
                raise PermissionError(
                    f"SVID SPIFFE ID {svid_claims.spiffe_id!r} does not "
                    f"match passport's holder_spiffe_id "
                    f"{context.spiffe_id!r} — presenter is not the "
                    f"credential's intended holder"
                )
            svid_bound = True

        # Translate PassportContext → the claims dict the rest of the
        # proxy consumes. Fields match the JWT passport's claims shape
        # so downstream code (budget checks, scope checks, receipt
        # rendering) needs no changes.
        claims: dict[str, Any] = {
            "iss": context.issuer_spiffe_id,
            "sub": context.agent_id,
            "aud": audience,
            "jti": context.jti,
            "iat": context.issued_at,
            "exp": context.expires_at,
            "mission": context.mission,
            # H1: stable mission identifier for PolicyStore lookup.
            # Populated by biscuit_passport._context_from_blocks from
            # the mission_id fact (or derived deterministically from
            # (agent_id, mission) for legacy tokens that predate the
            # fact). Mirrors the shape the JWT path produces.
            "mission_id": context.mission_id,
            "allowed_tools": list(context.allowed_tools),
            "forbidden_tools": list(context.forbidden_tools),
            "resource_scope": list(context.resource_scope),
            "allowed_side_effect_classes": list(
                context.allowed_side_effect_classes
            ),
            "max_tool_calls": context.max_tool_calls,
            "max_duration_s": context.max_duration_s,
            "delegation_allowed": context.delegation_allowed,
            "max_delegation_depth": context.max_delegation_depth,
            "credential_format": "biscuit-v1",
            "holder_spiffe_id": context.spiffe_id,
            "svid_bound": svid_bound,
        }
        if context.max_tool_calls_per_class:
            claims["max_tool_calls_per_class"] = dict(
                context.max_tool_calls_per_class
            )
        if context.cwd is not None:
            claims["cwd"] = context.cwd
        if context.parent_jti is not None:
            # Child passport: include ancestor chain, matching the JWT
            # delegation_chain convention: immediate parent first, then its
            # ancestors. Biscuit contexts carry the full authority chain from
            # root to current block, so translate order and parent edges here.
            claims["parent_jti"] = context.parent_jti
            if len(context.delegation_chain) < 2:
                raise PermissionError(
                    "biscuit delegated passport missing parent lineage"
                )
            immediate_parent = context.delegation_chain[-2]
            parent_token_hash = immediate_parent.get("token_hash")
            if not isinstance(parent_token_hash, str) or not _SHA256_HEX_RE.match(
                parent_token_hash
            ):
                raise PermissionError(
                    "biscuit delegated passport missing parent token hash"
                )
            claims["parent_token_hash"] = parent_token_hash.lower()
            ancestors: list[dict[str, str]] = []
            ancestor_blocks = context.delegation_chain[:-1]
            for index in range(len(ancestor_blocks) - 1, -1, -1):
                entry = ancestor_blocks[index]
                token_hash = entry.get("token_hash")
                if not isinstance(token_hash, str) or not _SHA256_HEX_RE.match(
                    token_hash
                ):
                    raise PermissionError(
                        "biscuit delegated passport ancestor token hash is malformed"
                    )
                anc: dict[str, str] = {
                    "jti": str(entry["jti"]),
                    "token_hash": token_hash.lower(),
                }
                if index > 0:
                    parent_entry = ancestor_blocks[index - 1]
                    parent_hash = parent_entry.get("token_hash")
                    if not isinstance(parent_hash, str) or not _SHA256_HEX_RE.match(
                        parent_hash
                    ):
                        raise PermissionError(
                            "biscuit delegated passport ancestor parent hash is malformed"
                        )
                    anc["parent_jti"] = str(parent_entry["jti"])
                    anc["parent_token_hash"] = parent_hash.lower()
                ancestors.append(anc)
            if ancestors:
                claims["delegation_chain"] = ancestors
        # else: root passport — do NOT include delegation_chain at all;
        # passport.delegation_chain_entries treats its presence on a
        # root passport as a security violation.

        # Resolve additional_policies from the authoritative PolicyStore
        # (if one is configured). This is the server-state-not-credential-
        # state point external-review-X flagged in the 2026-04-17 review: policies
        # are loaded at session start, keyed by mission_id, BEFORE the
        # session is cached — so downstream check_and_record sees
        # authoritative policy every call. A caller who got a session
        # handle cannot swap this by mutating passport_claims, because
        # evaluate_tool_call copies from passport_claims into a fresh
        # shared_context per call under the session lock (see
        # GovernanceSession.check_and_record).
        if self.policy_store is not None:
            # H1: keyed by mission_id, not sub. context.mission_id was
            # deterministically derived at Biscuit encode time from
            # (agent_id, mission) or set explicitly by the issuer;
            # either way it's stable across re-issuances and distinct
            # from per-agent identity.
            stored_policies = self.policy_store.get_policies(
                mission_id=str(claims.get("mission_id") or claims.get("sub", "")),
                agent_id=str(claims.get("sub", "")),
            )
            if stored_policies is not None:
                # Store is authoritative — overrides anything a caller
                # might have crammed into the credential or claims.
                # ``is not None`` (not truthiness) is deliberate: an
                # empty list from the store is an authoritative
                # "no additional policies" signal and MUST overwrite
                # any credential-supplied additional_policies.
                # ``None`` means the mission is unknown to the store;
                # fall through to whatever the credential carries.
                claims["additional_policies"] = list(stored_policies)

        # The "passport_token" field for the session stores the base64
        # Biscuit string — so persisted sessions round-trip, and audit
        # tooling can show the original credential alongside the
        # synthesized claims.
        stored_token = encode_biscuit_b64(biscuit_token)

        jti = str(claims["jti"])
        with self._session_coordination_lock(jti):
            with self._sessions_lock:
                if jti in self.sessions:
                    raise ValueError(
                        f"passport jti '{jti}' already has an active session; "
                        "passports are single-use"
                    )
            if self._session_path(jti).exists():
                raise ValueError(
                    f"passport jti '{jti}' has a persisted session on disk; "
                    "passports are single-use"
                )
            with self._passport_state_lock():
                self._assert_passport_lineage_not_revoked_locked(claims)
            self._record_passport_use(claims, stored_token)

            session = GovernanceSession(
                passport_token=stored_token,
                passport_claims=claims,
            )
            with self._sessions_lock:
                if jti in self.sessions:
                    raise ValueError(
                        f"passport jti '{jti}' already has an active session; "
                        "passports are single-use"
                    )
                self.sessions[jti] = session
            self._persist_session(session)
        self._log(
            {
                "type": "session_start",
                "jti": session.jti,
                "agent": claims["sub"],
                "mission": claims["mission"],
                "credential_format": "biscuit-v1",
            }
        )
        return session

    def get_session(self, session_id: str) -> GovernanceSession:
        with self._sessions_lock:
            if session_id in self.sessions:
                return self.sessions[session_id]

        loaded = self._load_session_from_disk(session_id)
        # Publish under lock; another thread may have raced ahead of us.
        with self._sessions_lock:
            if session_id in self.sessions:
                return self.sessions[session_id]
            self.sessions[session_id] = loaded
            return loaded

    def evaluate_tool_call(
        self,
        session: GovernanceSession | str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[Decision, str]:
        arguments_snapshot = copy.deepcopy(arguments)
        receipt_entry: dict[str, Any] | None = None
        # Refresh persisted state under a per-session coordination lock before
        # mutating. Without this, separate proxies that share a state_dir can
        # both approve from stale in-memory snapshots and last-writer-wins the
        # JSON file, effectively resurrecting budget.
        with self._locked_persisted_session(session) as target:
            with target._lock:
                receipt_policy_claims = dict(target.passport_claims)
                blocked_reason = self._blocked_session_reason(target)
                declared_required = _declared_required_telemetry(target.passport_claims)
                missing_declared = (
                    _missing_declared_telemetry(arguments_snapshot, declared_required)
                    if declared_required
                    else []
                )
                if blocked_reason is not None:
                    decision, reason = Decision.DENY, blocked_reason
                    event = self._synthetic_policy_event(
                        target,
                        tool_name,
                        arguments_snapshot,
                        decision,
                        reason,
                        DenialReason.REVOKED
                        if blocked_reason == "passport_revoked"
                        else DenialReason.POLICY_DENIED,
                    )
                elif missing_declared:
                    # B.2 fail-closed: the caller did not supply required declared
                    # telemetry. Emit INSUFFICIENT_EVIDENCE before any policy runs
                    # so the audit trail cleanly distinguishes "no evidence" from
                    # "evidence says deny" (PLAN E.8 telemetry-ablation gate).
                    decision = Decision.INSUFFICIENT_EVIDENCE
                    reason = f"declared_telemetry_missing:{','.join(missing_declared)}"
                    self._record_tool_policy_event(
                        target,
                        tool_name,
                        arguments_snapshot,
                        decision,
                        reason,
                        DenialReason.TELEMETRY_MISSING,
                        verifier_id=self.verifier_id,
                    )
                    event = target.events[-1]
                    self._persist_session(target)
                elif (
                    tool_name == MEMORY_STORE_READ_TOOL
                    and isinstance(arguments_snapshot.get("store_id"), str)
                    and arguments_snapshot["store_id"] in target.memory_compromised_stores
                ):
                    self._record_tool_policy_event(
                        target,
                        tool_name,
                        arguments_snapshot,
                        Decision.INSUFFICIENT_EVIDENCE,
                        "memory_compromise_boundary",
                        DenialReason.MEMORY_COMPROMISE_BOUNDARY,
                        verifier_id=self.verifier_id,
                    )
                    decision = Decision.INSUFFICIENT_EVIDENCE
                    reason = "memory_compromise_boundary"
                    event = target.events[-1]
                    self._persist_session(target)
                else:
                    mic_failure = self._pre_policy_integrity_check(target, arguments_snapshot)
                    if mic_failure is not None:
                        decision, reason, denial_reason = mic_failure
                        self._record_tool_policy_event(
                            target, tool_name, arguments_snapshot,
                            decision, reason, denial_reason,
                            verifier_id=self.verifier_id,
                        )
                        event = target.events[-1]
                        self._persist_session(target)
                    else:
                        try:
                            policy_claims = self._resolve_authoritative_policy_claims(
                                target.passport_claims
                            )
                        except _MissionPolicyResolutionError as exc:
                            decision, reason = exc.decision, exc.reason
                            self._record_tool_policy_event(
                                target,
                                tool_name,
                                arguments_snapshot,
                                decision,
                                reason,
                                exc.denial_reason,
                                verifier_id=self.verifier_id,
                            )
                            event = target.events[-1]
                            self._persist_session(target)
                        else:
                            receipt_policy_claims = dict(policy_claims)
                            ts = time.time()
                            ap = policy_claims.get("approval_policy")
                            need_rate = (
                                isinstance(ap, dict)
                                and ap.get("max_approvals_per_hour_per_operator") is not None
                            )
                            if need_rate:
                                try:
                                    max_ap = int(ap["max_approvals_per_hour_per_operator"])
                                    window_s = float(ap.get("window_s", 3600.0))
                                    tracker = self._approval_tracker(max_ap, window_s)
                                except (TypeError, ValueError):
                                    decision, reason = (
                                        Decision.INSUFFICIENT_EVIDENCE,
                                        "approval_policy_invalid",
                                    )
                                    self._record_tool_policy_event(
                                        target,
                                        tool_name,
                                        arguments_snapshot,
                                        decision,
                                        reason,
                                        DenialReason.TELEMETRY_MISSING,
                                        verifier_id=self.verifier_id,
                                    )
                                    event = target.events[-1]
                                    self._persist_session(target)
                                else:
                                    operator_id = self._approval_operator_id(
                                        policy_claims, arguments_snapshot
                                    )
                                    if operator_id is None:
                                        decision, reason = (
                                            Decision.INSUFFICIENT_EVIDENCE,
                                            "approval_operator_unavailable",
                                        )
                                        self._record_tool_policy_event(
                                            target,
                                            tool_name,
                                            arguments_snapshot,
                                            decision,
                                            reason,
                                            DenialReason.APPROVAL_OPERATOR_UNAVAILABLE,
                                            verifier_id=self.verifier_id,
                                        )
                                        event = target.events[-1]
                                        self._persist_session(target)
                                    elif not tracker.check(operator_id, ts):
                                        decision, reason = (
                                            Decision.INSUFFICIENT_EVIDENCE,
                                            "approval_fatigue_threshold",
                                        )
                                        self._record_tool_policy_event(
                                            target,
                                            tool_name,
                                            arguments_snapshot,
                                            decision,
                                            reason,
                                            DenialReason.APPROVAL_FATIGUE_THRESHOLD,
                                            verifier_id=self.verifier_id,
                                        )
                                        event = target.events[-1]
                                        self._persist_session(target)
                                    else:
                                        decision, reason, _event = target.check_and_record(
                                            tool_name,
                                            arguments_snapshot,
                                            policy_claims=policy_claims,
                                            verifier_id=self.verifier_id,
                                        )
                                        if decision == Decision.PERMIT:
                                            decision, reason = self._apply_memory_post_permit(
                                                target, tool_name, arguments_snapshot
                                            )
                                        if decision == Decision.PERMIT:
                                            tracker.record_approval(operator_id, ts)
                                        event = target.events[-1]
                                        self._persist_session(target)
                            else:
                                decision, reason, _event = target.check_and_record(
                                    tool_name,
                                    arguments_snapshot,
                                    policy_claims=policy_claims,
                                    verifier_id=self.verifier_id,
                                )
                                if decision == Decision.PERMIT:
                                    decision, reason = self._apply_memory_post_permit(
                                        target, tool_name, arguments_snapshot
                                    )
                                event = target.events[-1]
                                self._persist_session(target)
                receipt_entry = self._build_receipt_log_entry(
                    target,
                    event,
                    decision,
                    reason,
                    receipt_policy_claims,
                )
                self._persist_session(target)
                call_number = target.tool_call_count
        self._log(
            {
                "type": "tool_call",
                "jti": target.jti,
                "tool": tool_name,
                "decision": decision.value,
                "reason": reason,
                "call_number": call_number,
            }
        )
        if receipt_entry is not None:
            self._log_receipt(receipt_entry)
        return decision, reason

    def record_tool_result(
        self,
        session: GovernanceSession | str,
        response: str,
        duration_ms: float,
    ) -> None:
        with self._locked_persisted_session(session) as target:
            with target._lock:
                if target.summary is not None:
                    raise PermissionError("session already ended")
                if not target.events:
                    raise ValueError("cannot record tool result without a prior tool event")
                target.events[-1].response = response
                target.events[-1].duration_ms = duration_ms
                self._persist_session(target)

    def summarize_session(self, session: GovernanceSession | str) -> dict[str, Any]:
        with self._locked_persisted_session(session) as target:
            with target._lock:
                return self._build_summary(target)

    def end_session(self, session: GovernanceSession | str) -> dict[str, Any]:
        created_summary = False
        with self._locked_persisted_session(session) as target:
            with target._lock:
                summary, created_summary = self._finalize_session_locked(target)
                if created_summary:
                    self._persist_session(target)
        if created_summary:
            self._log(summary)
        return dict(summary)

    def issue_attestation_for_session(
        self,
        session_id: str,
        private_key: ec.EllipticCurvePrivateKey,
    ) -> tuple[str, dict[str, Any]]:
        created_summary = False
        token = ""
        with self._locked_persisted_session(session_id) as target:
            with target._lock:
                summary, created_summary = self._finalize_session_locked(target)
                if target.attestation_token is None:
                    lifecycle_claims = self._lifecycle_rollup_for_session_unlocked(target)
                    extra_claims = (
                        lifecycle_claims
                        if int(lifecycle_claims["delegation_count"]) > 0
                        else None
                    )
                    target.attestation_token = issue_attestation(
                        passport_jti=target.jti,
                        agent_id=target.passport_claims["sub"],
                        mission=target.passport_claims["mission"],
                        events=target.to_log(),
                        permits=int(summary["permits"]),
                        denials=int(summary["denials"]),
                        elapsed_s=float(summary["elapsed_s"]),
                        private_key=private_key,
                        extra_claims=extra_claims,
                    )
                    self._persist_session(target)
                elif created_summary:
                    self._persist_session(target)
                token = target.attestation_token
        if created_summary:
            self._log(summary)
        claims = verify_attestation(token, self.public_key)
        return token, claims

    def _resolve_session(self, session: GovernanceSession | str) -> GovernanceSession:
        if isinstance(session, GovernanceSession):
            return session
        return self.get_session(session)

    def lifecycle_rollup_for_session(self, session_id: str) -> dict[str, Any]:
        with self._locked_persisted_session(session_id) as target:
            with target._lock:
                return self._lifecycle_rollup_for_session_unlocked(target)

    def _finalize_session_locked(self, session: GovernanceSession) -> tuple[dict[str, Any], bool]:
        if session.summary is not None:
            return dict(session.summary), False
        session.end_time = time.time()
        summary = self._build_summary(session)
        session.summary = summary
        return dict(summary), True

    def _build_summary(self, session: GovernanceSession) -> dict[str, Any]:
        events = list(session.events)
        permits = sum(1 for e in events if e.decision == Decision.PERMIT)
        denials = sum(
            1
            for e in events
            if e.decision
            in (Decision.DENY, Decision.INSUFFICIENT_EVIDENCE, Decision.VIOLATION)
        )
        return {
            "type": "session_end",
            "jti": session.jti,
            "agent": session.passport_claims["sub"],
            "mission": session.passport_claims["mission"],
            "total_events": len(events),
            "permits": permits,
            "denials": denials,
            "elapsed_s": round(session.elapsed_s, 3),
            "scope_compliance": "full" if denials == 0 else "violated",
            "delegation_count": len(session.delegated_children),
            "children_spawned": len(
                {
                    str(child.get("child_jti"))
                    for child in session.delegated_children
                    if child.get("child_jti")
                }
            ),
            "child_jtis": [
                str(child.get("child_jti"))
                for child in session.delegated_children
                if child.get("child_jti")
            ],
            "delegated_budget_reserved": session.delegated_budget_reserved,
        }

    def _lifecycle_rollup_for_session_unlocked(
        self,
        session: GovernanceSession,
    ) -> dict[str, Any]:
        children = [
            self._child_lifecycle_summary(record)
            for record in session.delegated_children
        ]
        child_jtis = [
            str(child["child_jti"])
            for child in children
            if child.get("child_jti")
        ]
        closed_child_count = sum(
            1
            for child in children
            if child["session_started"]
            and child["session_closed"]
            and child["attestation_present"]
        )
        delegation_attempts = [
            event
            for event in session.events
            if event.tool_name == "delegate_passport"
        ]
        delegation_denials = sum(
            1
            for event in delegation_attempts
            if event.decision != Decision.PERMIT
        )
        return {
            "lifecycle_schema": LIFECYCLE_ATTESTATION_SCHEMA,
            "children_spawned": closed_child_count,
            "children_closed": sum(1 for child in children if child["session_closed"]),
            "child_jtis": child_jtis,
            "delegation_count": len(session.delegated_children),
            "delegation_attempt_count": len(delegation_attempts),
            "delegation_denial_count": delegation_denials,
            "delegated_budget_reserved": session.delegated_budget_reserved,
            "children": children,
        }

    def _child_lifecycle_summary(self, record: dict[str, Any]) -> dict[str, Any]:
        child_jti = str(record.get("child_jti", ""))
        summary: dict[str, Any] = {
            "delegation_request_id": record.get("delegation_request_id"),
            "child_jti": child_jti,
            "parent_jti": record.get("parent_jti"),
            "child_agent_id": record.get("child_agent_id"),
            "mission": record.get("child_mission"),
            "allowed_tools": list(record.get("child_allowed_tools", [])),
            "tool_scope_mode": record.get("child_tool_scope_mode", "allowlist"),
            "forbidden_tools": list(record.get("child_forbidden_tools", [])),
            "max_tool_calls": record.get("child_max_tool_calls"),
            "delegated_budget_reserved": record.get("delegated_budget_reserved"),
            "session_started": False,
            "session_closed": False,
            "attestation_present": False,
            "no_out_of_scope_permits": False,
            "receipt_count": 0,
            "permits": 0,
            "denials": 0,
            "total_events": 0,
            "scope_compliance": "unknown",
        }
        if not child_jti:
            summary["error"] = "missing child_jti"
            return summary

        try:
            child_session = self.get_session(child_jti)
        except Exception as exc:  # pragma: no cover - defensive audit metadata
            summary["error"] = f"child session unavailable: {exc}"
            return summary

        child_summary = (
            dict(child_session.summary)
            if isinstance(child_session.summary, dict)
            else self._build_summary(child_session)
        )
        summary.update(
            {
                "session_started": True,
                "session_closed": child_session.summary is not None,
                "receipt_count": len(child_session.events),
                "permits": int(child_summary.get("permits", 0)),
                "denials": int(child_summary.get("denials", 0)),
                "total_events": int(child_summary.get("total_events", len(child_session.events))),
                "scope_compliance": child_summary.get("scope_compliance", "unknown"),
                "no_out_of_scope_permits": self._session_no_out_of_scope_permits(
                    child_session
                ),
            }
        )
        if child_session.attestation_token:
            attestation_claims = verify_attestation(
                child_session.attestation_token,
                self.public_key,
            )
            summary.update(
                {
                    "attestation_present": True,
                    "attestation_jti": attestation_claims.get("jti"),
                    "attestation_sha256": hashlib.sha256(
                        child_session.attestation_token.encode("utf-8")
                    ).hexdigest(),
                    "log_digest_sha256": attestation_claims.get("log_digest_sha256"),
                }
            )
        return summary

    @staticmethod
    def _session_no_out_of_scope_permits(session: GovernanceSession) -> bool:
        claims = session.passport_claims
        forbidden = set(claims.get("forbidden_tools", []) or [])
        allowed = set(claims.get("allowed_tools", []) or [])
        tool_scope_mode = str(claims.get("tool_scope_mode", "allowlist"))
        for event in session.events:
            if event.decision != Decision.PERMIT:
                continue
            if event.tool_name in forbidden:
                return False
            if tool_scope_mode != "unrestricted" and event.tool_name not in allowed:
                return False
        return True

    def _session_path(self, session_id: str) -> Path:
        if not _SESSION_ID_RE.match(session_id):
            raise ValueError(f"invalid session ID format: must be UUID")
        return self.sessions_dir / f"{session_id}.json"

    def _session_lock_path(self, session_id: str) -> Path:
        self._session_path(session_id)
        return self.sessions_dir / f"{session_id}.lock"

    def _passport_state_lock_path(self) -> Path:
        return self.state_dir / "passport_state.lock"

    def _passport_state_can_bootstrap(self) -> bool:
        return self._passport_state_can_bootstrap_locked(ignore_lockfile=False)

    def _passport_state_can_bootstrap_locked(self, *, ignore_lockfile: bool) -> bool:
        return (
            (ignore_lockfile or not self._passport_state_lock_path().exists())
            and not self.replay_cache_path.exists()
            and not self.revoked_path.exists()
            and not self.lineage_hashes_path.exists()
            and not any(self.sessions_dir.glob("*.json"))
        )

    def _session_receipt_integrity_mac(
        self,
        session_id: str,
        last_receipt_id: str,
        last_receipt_full_hash: str,
    ) -> str:
        material = json.dumps(
            {
                "session_id": session_id,
                "last_receipt_id": last_receipt_id,
                "last_receipt_full_hash": last_receipt_full_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(self._session_receipt_integrity_key, material, "sha256").hexdigest()

    def _add_session_receipt_integrity(
        self,
        session_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        last_receipt_id = payload.get("last_receipt_id")
        last_receipt_full_hash = payload.get("last_receipt_full_hash")
        if last_receipt_id is None and last_receipt_full_hash is None:
            payload.pop("receipt_chain_integrity", None)
            return payload
        if (
            not isinstance(last_receipt_id, str)
            or not last_receipt_id
            or not isinstance(last_receipt_full_hash, str)
            or not last_receipt_full_hash
        ):
            raise ValueError("session receipt-chain anchor is malformed")
        payload["receipt_chain_integrity"] = {
            "version": _SESSION_RECEIPT_INTEGRITY_VERSION,
            "mac": self._session_receipt_integrity_mac(
                session_id,
                last_receipt_id,
                last_receipt_full_hash,
            ),
        }
        return payload

    def _validate_session_receipt_integrity(
        self,
        session_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        validated = dict(payload)
        last_receipt_id = validated.get("last_receipt_id")
        last_receipt_full_hash = validated.get("last_receipt_full_hash")
        integrity = validated.pop("receipt_chain_integrity", None)
        if last_receipt_id is None and last_receipt_full_hash is None:
            return validated
        if (
            not isinstance(last_receipt_id, str)
            or not last_receipt_id
            or not isinstance(last_receipt_full_hash, str)
            or not last_receipt_full_hash
        ):
            raise ValueError("session receipt-chain anchor is malformed")
        if not isinstance(integrity, dict):
            raise ValueError("session receipt-chain anchor is missing its integrity tag")
        if integrity.get("version") != _SESSION_RECEIPT_INTEGRITY_VERSION:
            raise ValueError("session receipt-chain integrity version mismatch")
        mac = integrity.get("mac")
        if not isinstance(mac, str) or not mac:
            raise ValueError("session receipt-chain integrity tag is malformed")
        expected = self._session_receipt_integrity_mac(
            session_id,
            last_receipt_id,
            last_receipt_full_hash,
        )
        if not hmac.compare_digest(mac, expected):
            raise ValueError("session receipt-chain integrity check failed")
        return validated

    def _load_session_from_disk(self, session_id: str) -> GovernanceSession:
        path = self._session_path(session_id)
        if not path.exists():
            raise ValueError(f"unknown session '{session_id}'")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("session file must contain a JSON object")
        return GovernanceSession.from_dict(
            self._validate_session_receipt_integrity(session_id, payload)
        )

    def _process_lock_for_path(self, lock_path: Path) -> _SessionCoordinationLock:
        lock_key = str(lock_path.resolve())
        with _SESSION_COORDINATION_LOCKS_GUARD:
            lock = _SESSION_COORDINATION_LOCKS.get(lock_key)
            if lock is None:
                lock = _SessionCoordinationLock()
                _SESSION_COORDINATION_LOCKS[lock_key] = lock
            return lock

    def _process_session_lock(self, session_id: str) -> _SessionCoordinationLock:
        return self._process_lock_for_path(self._session_lock_path(session_id))

    @contextlib.contextmanager
    def _session_coordination_lock(self, session_id: str):
        process_lock = self._process_session_lock(session_id)
        lock_path = self._session_lock_path(session_id)
        lock_path.touch(exist_ok=True)
        with process_lock.lock:
            with lock_path.open("a+b") as lock_handle:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    @contextlib.contextmanager
    def _passport_state_lock(self):
        lock_path = self._passport_state_lock_path()
        lock_path.touch(exist_ok=True)
        process_lock = self._process_lock_for_path(lock_path)
        with process_lock.lock:
            with lock_path.open("a+b") as lock_handle:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    def _initialize_passport_state_files(self) -> None:
        with self._passport_state_lock():
            can_bootstrap = self._passport_state_can_bootstrap_locked(ignore_lockfile=True)
            try:
                self._replay_cache_sentinel = self._initialize_replay_cache_locked(
                    can_bootstrap=can_bootstrap
                )
            except PassportStateUnavailableError:
                self._replay_cache_sentinel = None
            try:
                self._revoked_sentinel = self._initialize_revoked_locked(
                    can_bootstrap=can_bootstrap
                )
            except PassportStateUnavailableError:
                self._revoked_sentinel = None
            try:
                self._lineage_hashes_sentinel = self._initialize_lineage_hashes_locked(
                    can_bootstrap=can_bootstrap
                )
            except PassportStateUnavailableError:
                self._lineage_hashes_sentinel = None

    def _initialize_replay_cache_locked(self, *, can_bootstrap: bool) -> str | None:
        if self.replay_cache_path.exists():
            payload = self._load_state_json_locked(
                self.replay_cache_path,
                error_code="replay_cache_unavailable",
            )
            sentinel, entries = self._parse_replay_cache_payload(
                payload,
                expected_sentinel=None,
                allow_legacy=True,
            )
            if sentinel is None:
                sentinel = uuid.uuid4().hex
                self._persist_replay_cache_locked(entries, sentinel=sentinel)
            return sentinel
        if not can_bootstrap:
            return None
        sentinel = uuid.uuid4().hex
        self._persist_replay_cache_locked({}, sentinel=sentinel)
        return sentinel

    def _initialize_revoked_locked(self, *, can_bootstrap: bool) -> str | None:
        if self.revoked_path.exists():
            payload = self._load_state_json_locked(
                self.revoked_path,
                error_code="revocation_list_unavailable",
            )
            sentinel, revoked = self._parse_revoked_payload(
                payload,
                expected_sentinel=None,
                allow_legacy=True,
            )
            if sentinel is None:
                sentinel = uuid.uuid4().hex
                self._persist_revoked_locked(revoked, sentinel=sentinel)
            return sentinel
        if not can_bootstrap:
            return None
        sentinel = uuid.uuid4().hex
        self._persist_revoked_locked({}, sentinel=sentinel)
        return sentinel

    def _initialize_lineage_hashes_locked(self, *, can_bootstrap: bool) -> str | None:
        if self.lineage_hashes_path.exists():
            payload = self._load_state_json_locked(
                self.lineage_hashes_path,
                error_code="lineage_hashes_unavailable",
            )
            sentinel, token_hashes, lineage_edges = self._parse_lineage_hashes_payload(
                payload,
                expected_sentinel=None,
                allow_legacy=True,
            )
            # 2026-04-21 review comment #9: pre-ADR-016 lineage files
            # written by origin/dev carried ``token_hashes`` but no
            # ``parents`` map. After upgrade, cold delegated
            # verification looks up ``trusted_parent_lineage[jti]``,
            # gets None, and rejects every ancestor with
            # "lineage edge is not trusted". Detect the schema drift
            # (non-empty token_hashes, empty parents) and reconstruct
            # edges from on-disk sessions — same path used for the
            # fresh-bootstrap migration. Sessions whose claims can't be
            # read cleanly stay out of the index and fail closed on
            # re-presentation.
            needs_edge_migration = bool(token_hashes) and not lineage_edges
            if needs_edge_migration:
                # 2026-04-21 PR-#13 external-review-G + augment ("High"): the
                # prior ``setdefault(jti, (None, None))`` fallback
                # silently promoted every token_hash jti whose session
                # couldn't be reconstructed to a ROOT lineage edge.
                # That contradicted fail-closed — a delegated session
                # with a missing/corrupt session file would appear to
                # the verifier as a valid root and bypass ancestor
                # revocation. Drop the fallback: only jtis that
                # ``_reconstruct_lineage_from_sessions`` could rebuild
                # from signed claims enter the new index. Legacy
                # token_hashes entries whose session is gone are not
                # in the index and fail-closed on re-presentation.
                token_hashes, lineage_edges = self._reconstruct_lineage_from_sessions()
            if sentinel is None or needs_edge_migration:
                sentinel = sentinel or uuid.uuid4().hex
                self._persist_lineage_hashes_locked(
                    token_hashes,
                    lineage_edges,
                    sentinel=sentinel,
                )
            return sentinel
        if not can_bootstrap:
            # Upgrade path for state dirs created before lineage_hashes.json
            # existed. We MUST reconstruct the lineage edges from on-disk
            # sessions rather than bootstrapping an empty index: otherwise
            # every pre-migration intermediate session gets a (None, None)
            # edge and is indistinguishable from a root, which breaks
            # grandchild re-parenting detection for any chain that
            # straddles the migration boundary (2026-04-21 audit finding).
            if (
                self.replay_cache_path.exists()
                or self.revoked_path.exists()
                or any(self.sessions_dir.glob("*.json"))
            ):
                sentinel = uuid.uuid4().hex
                token_hashes, lineage_edges = self._reconstruct_lineage_from_sessions()
                self._persist_lineage_hashes_locked(
                    token_hashes, lineage_edges, sentinel=sentinel
                )
                return sentinel
            return None
        sentinel = uuid.uuid4().hex
        self._persist_lineage_hashes_locked({}, {}, sentinel=sentinel)
        return sentinel

    def _reconstruct_lineage_from_sessions(
        self,
    ) -> tuple[dict[str, str], dict[str, LineageEdge]]:
        """Walk sessions_dir and rebuild a (token_hashes, lineage_edges) pair.

        Called only from the migration path when a pre-lineage state_dir
        contains sessions but no lineage_hashes.json. Each session file
        carries the raw ``passport_token`` and signed ``passport_claims``
        dict, which is sufficient to compute the same (token_hash,
        lineage_edge) that ``_record_passport_use`` would have written if
        lineage tracking had existed at issuance time.

        Sessions whose on-disk claims are malformed (or declare delegation
        without a parent hash ``_lineage_edge_from_claims`` accepts) are
        intentionally skipped — leaving them out of the index makes them
        fail closed on re-presentation, which is better than fabricating
        a (None, None) "root" edge that would silently mask the
        inconsistency.
        """
        token_hashes: dict[str, str] = {}
        lineage_edges: dict[str, LineageEdge] = {}
        for session_file in sorted(self.sessions_dir.glob("*.json")):
            try:
                raw = session_file.read_text(encoding="utf-8")
                data = json.loads(raw)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                # Fail-closed posture preserved (skip), but surface the skip so
                # operators can spot corruption trends. Without this, decay in
                # the state dir is invisible until replay cache misbehaves.
                logger.warning(
                    "skipping corrupt session file %s during lineage reindex: %s",
                    session_file.name,
                    exc.__class__.__name__,
                    exc_info=True,
                )
                continue
            if not isinstance(data, dict):
                continue
            passport_token = data.get("passport_token")
            passport_claims = data.get("passport_claims")
            if not isinstance(passport_token, str) or not passport_token:
                continue
            if not isinstance(passport_claims, dict):
                continue
            jti = passport_claims.get("jti")
            if not isinstance(jti, str) or not jti:
                continue
            try:
                lineage_edge = self._lineage_edge_from_claims(passport_claims)
            except PassportStateUnavailableError:
                # Pre-PR-10 delegated session without parent_token_hash on
                # its signed claims. Skip — re-presentation will fail
                # closed via the same path.
                continue
            token_hashes[jti] = _passport_token_hash(passport_token)
            lineage_edges[jti] = lineage_edge
        return token_hashes, lineage_edges

    def _load_state_json_locked(self, path: Path, *, error_code: str) -> dict[str, Any]:
        if not path.exists():
            raise PassportStateUnavailableError(error_code, f"{path.name} is missing")
        raw = path.read_text(encoding="utf-8")
        if not raw.strip():
            raise PassportStateUnavailableError(error_code, f"{path.name} is empty")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PassportStateUnavailableError(error_code, f"{path.name} is invalid JSON") from exc
        if not isinstance(payload, dict):
            raise PassportStateUnavailableError(error_code, f"{path.name} must contain a JSON object")
        return payload

    def _parse_replay_cache_payload(
        self,
        payload: dict[str, Any],
        *,
        expected_sentinel: str | None,
        allow_legacy: bool,
    ) -> tuple[str | None, dict[str, dict[str, int]]]:
        now = int(time.time())
        sentinel: str | None = None
        if allow_legacy and "sentinel" not in payload and "version" not in payload:
            raw_entries = payload.get("entries", {})
        else:
            if payload.get("version") != _PASSPORT_STATE_SCHEMA_VERSION:
                raise PassportStateUnavailableError(
                    "replay_cache_unavailable",
                    "replay_cache.json schema version mismatch",
                )
            sentinel = payload.get("sentinel")
            if not isinstance(sentinel, str) or not sentinel:
                raise PassportStateUnavailableError(
                    "replay_cache_unavailable",
                    "replay_cache.json sentinel missing",
                )
            if expected_sentinel is not None and sentinel != expected_sentinel:
                raise PassportStateUnavailableError(
                    "replay_cache_unavailable",
                    "replay_cache.json sentinel mismatch",
                )
            raw_entries = payload.get("entries", {})

        if not isinstance(raw_entries, dict):
            raise PassportStateUnavailableError(
                "replay_cache_unavailable",
                "replay_cache.json entries must be a JSON object",
            )

        entries: dict[str, dict[str, int]] = {}
        for jti, meta in raw_entries.items():
            if not isinstance(jti, str) or not isinstance(meta, dict):
                raise PassportStateUnavailableError(
                    "replay_cache_unavailable",
                    "replay_cache.json contains malformed entry metadata",
                )
            try:
                exp = int(meta["exp"])
                first_seen = int(meta.get("first_seen", meta.get("last_seen", 0)))
            except (KeyError, TypeError, ValueError) as exc:
                raise PassportStateUnavailableError(
                    "replay_cache_unavailable",
                    f"replay_cache.json entry for {jti!r} is malformed",
                ) from exc
            if exp > now:
                entries[jti] = {"first_seen": first_seen, "exp": exp}
        return sentinel, entries

    def _parse_revoked_payload(
        self,
        payload: dict[str, Any],
        *,
        expected_sentinel: str | None,
        allow_legacy: bool,
    ) -> tuple[str | None, dict[str, int]]:
        sentinel: str | None = None
        if allow_legacy and "sentinel" not in payload and "version" not in payload:
            raw_entries = payload.get("jtis", {})
        else:
            if payload.get("version") != _PASSPORT_STATE_SCHEMA_VERSION:
                raise PassportStateUnavailableError(
                    "revocation_list_unavailable",
                    "revoked.json schema version mismatch",
                )
            sentinel = payload.get("sentinel")
            if not isinstance(sentinel, str) or not sentinel:
                raise PassportStateUnavailableError(
                    "revocation_list_unavailable",
                    "revoked.json sentinel missing",
                )
            if expected_sentinel is not None and sentinel != expected_sentinel:
                raise PassportStateUnavailableError(
                    "revocation_list_unavailable",
                    "revoked.json sentinel mismatch",
                )
            raw_entries = payload.get("jtis", {})

        revoked: dict[str, int] = {}
        if isinstance(raw_entries, dict):
            items = raw_entries.items()
        elif allow_legacy and isinstance(raw_entries, list):
            items = ((jti, 0) for jti in raw_entries)
        else:
            raise PassportStateUnavailableError(
                "revocation_list_unavailable",
                "revoked.json jtis must be a JSON object",
            )

        for jti, revoked_at in items:
            if not isinstance(jti, str):
                raise PassportStateUnavailableError(
                    "revocation_list_unavailable",
                    "revoked.json contains a non-string jti",
                )
            try:
                revoked[jti] = int(revoked_at)
            except (TypeError, ValueError) as exc:
                raise PassportStateUnavailableError(
                    "revocation_list_unavailable",
                    f"revoked.json entry for {jti!r} is malformed",
                ) from exc
        return sentinel, revoked

    def _parse_lineage_hashes_payload(
        self,
        payload: dict[str, Any],
        *,
        expected_sentinel: str | None,
        allow_legacy: bool,
    ) -> tuple[str | None, dict[str, str], dict[str, LineageEdge]]:
        sentinel: str | None = None
        if allow_legacy and "sentinel" not in payload and "version" not in payload:
            raw_entries = payload.get("token_hashes", {})
            raw_parents = payload.get("parents", {})
        else:
            if payload.get("version") != _PASSPORT_STATE_SCHEMA_VERSION:
                raise PassportStateUnavailableError(
                    "lineage_hashes_unavailable",
                    "lineage_hashes.json schema version mismatch",
                )
            sentinel = payload.get("sentinel")
            if not isinstance(sentinel, str) or not sentinel:
                raise PassportStateUnavailableError(
                    "lineage_hashes_unavailable",
                    "lineage_hashes.json sentinel missing",
                )
            if expected_sentinel is not None and sentinel != expected_sentinel:
                raise PassportStateUnavailableError(
                    "lineage_hashes_unavailable",
                    "lineage_hashes.json sentinel mismatch",
                )
            raw_entries = payload.get("token_hashes", {})
            raw_parents = payload.get("parents", {})

        if not isinstance(raw_entries, dict):
            raise PassportStateUnavailableError(
                "lineage_hashes_unavailable",
                "lineage_hashes.json token_hashes must be a JSON object",
            )
        if not isinstance(raw_parents, dict):
            raise PassportStateUnavailableError(
                "lineage_hashes_unavailable",
                "lineage_hashes.json parents must be a JSON object",
            )

        token_hashes: dict[str, str] = {}
        for jti, token_hash in raw_entries.items():
            if (
                not isinstance(jti, str)
                or not jti
                or not isinstance(token_hash, str)
                or not _SHA256_HEX_RE.match(token_hash)
            ):
                raise PassportStateUnavailableError(
                    "lineage_hashes_unavailable",
                    "lineage_hashes.json contains malformed token hash metadata",
                )
            token_hashes[jti] = token_hash.lower()

        lineage_edges: dict[str, LineageEdge] = {}
        for jti, parent_meta in raw_parents.items():
            if not isinstance(jti, str) or not jti or not isinstance(parent_meta, dict):
                raise PassportStateUnavailableError(
                    "lineage_hashes_unavailable",
                    "lineage_hashes.json contains malformed parent metadata",
                )
            parent_jti = parent_meta.get("parent_jti")
            parent_hash = parent_meta.get("parent_token_hash")
            if parent_jti is not None and (
                not isinstance(parent_jti, str) or not parent_jti
            ):
                raise PassportStateUnavailableError(
                    "lineage_hashes_unavailable",
                    "lineage_hashes.json contains malformed parent_jti metadata",
                )
            if parent_hash is not None and (
                not isinstance(parent_hash, str) or not _SHA256_HEX_RE.match(parent_hash)
            ):
                raise PassportStateUnavailableError(
                    "lineage_hashes_unavailable",
                    "lineage_hashes.json contains malformed parent hash metadata",
                )
            if parent_jti is None and parent_hash is not None:
                raise PassportStateUnavailableError(
                    "lineage_hashes_unavailable",
                    "lineage_hashes.json root parent metadata must not carry a parent hash",
                )
            lineage_edges[jti] = (
                parent_jti,
                parent_hash.lower() if isinstance(parent_hash, str) else None,
            )
        return sentinel, token_hashes, lineage_edges

    def _blocked_session_reason(self, session: GovernanceSession) -> str | None:
        if session.summary is not None or session.end_time is not None:
            return "session already ended"
        with self._passport_state_lock():
            if self._first_revoked_jti_in_lineage_locked(session.passport_claims) is not None:
                return "passport_revoked"
        return None

    @staticmethod
    def _active_conformance_profile(policy_claims: dict[str, Any]) -> str:
        profile = policy_claims.get("conformance_profile")
        if isinstance(profile, str) and profile:
            return profile
        return "Delegation-Core"

    def _detect_hidden_hop(self, session: GovernanceSession) -> bool:
        claims = session.passport_claims
        parent_jti = claims.get("parent_jti")
        if parent_jti is None:
            return False
        parent_jti_str = str(parent_jti)
        with self._lineage_parent_cache_lock:
            return parent_jti_str not in self._lineage_parent_cache

    def _detect_missing_parent_receipt(self, session: GovernanceSession) -> bool:
        claims = session.passport_claims
        parent_jti = claims.get("parent_jti")
        if parent_jti is None:
            return False
        parent_jti_str = str(parent_jti)
        with self._last_seen_receipts_lock:
            return parent_jti_str not in self._last_seen_receipts

    def _pre_policy_integrity_check(
        self,
        session: GovernanceSession,
        arguments: dict[str, Any],
    ) -> tuple[Decision, str, DenialReason] | None:
        profile = self._active_conformance_profile(session.passport_claims)
        if profile == "Delegation-Core":
            return None

        # Visibility check (§6.4)
        visibility = arguments.get("visibility")
        if visibility != "full":
            return (
                Decision.INSUFFICIENT_EVIDENCE,
                "visibility_not_full",
                DenialReason.TELEMETRY_MISSING,
            )

        # Envelope signature verification (§9.5) — fail-closed
        if arguments.get("envelope_signature_valid") is not True:
            return (
                Decision.VIOLATION,
                "envelope_tampered",
                DenialReason.ENVELOPE_TAMPERED,
            )

        # Manifest digest comparison (§9.6)
        expected_digest = session.passport_claims.get("tool_manifest_digest")
        if isinstance(expected_digest, str) and expected_digest:
            observed = arguments.get("observed_manifest_digest")
            if not isinstance(observed, str) or observed != expected_digest:
                return (
                    Decision.VIOLATION,
                    "manifest_drift",
                    DenialReason.MANIFEST_DRIFT,
                )

        if profile == "MIC-Evidence":
            if self._detect_hidden_hop(session):
                return (
                    Decision.INSUFFICIENT_EVIDENCE,
                    "hidden_hop_detected",
                    DenialReason.TELEMETRY_MISSING,
                )
            if self._detect_missing_parent_receipt(session):
                return (
                    Decision.INSUFFICIENT_EVIDENCE,
                    "missing_parent_receipt",
                    DenialReason.TELEMETRY_MISSING,
                )

        return None

    def _try_initialize_replay_cache_locked(self) -> str | None:
        can_bootstrap = self._passport_state_can_bootstrap_locked(ignore_lockfile=True)
        try:
            return self._initialize_replay_cache_locked(can_bootstrap=can_bootstrap)
        except PassportStateUnavailableError:
            return None

    def _try_initialize_revoked_locked(self) -> str | None:
        can_bootstrap = self._passport_state_can_bootstrap_locked(ignore_lockfile=True)
        try:
            return self._initialize_revoked_locked(can_bootstrap=can_bootstrap)
        except PassportStateUnavailableError:
            return None

    def _try_initialize_lineage_hashes_locked(self) -> str | None:
        can_bootstrap = self._passport_state_can_bootstrap_locked(ignore_lockfile=True)
        try:
            return self._initialize_lineage_hashes_locked(can_bootstrap=can_bootstrap)
        except PassportStateUnavailableError:
            return None

    def _remember_lineage_parent(self, jti: str, parent_jti: str | None) -> None:
        with self._lineage_parent_cache_lock:
            self._lineage_parent_cache[jti] = parent_jti
            self._lineage_parent_cache.move_to_end(jti)
            while len(self._lineage_parent_cache) > LINEAGE_PARENT_CACHE_MAX_ENTRIES:
                self._lineage_parent_cache.popitem(last=False)

    def _cached_lineage_parent(self, jti: str) -> str | None:
        with self._lineage_parent_cache_lock:
            parent_jti = self._lineage_parent_cache[jti]
            self._lineage_parent_cache.move_to_end(jti)
            return parent_jti

    def _seed_lineage_parent_cache(self, claims: dict[str, Any]) -> None:
        current_jti = str(claims["jti"])
        parent_jti = claims.get("parent_jti")
        self._remember_lineage_parent(
            current_jti,
            str(parent_jti) if parent_jti is not None else None,
        )
        for link in delegation_chain_entries(claims):
            next_parent = link.get("parent_jti")
            self._remember_lineage_parent(
                str(link["jti"]),
                str(next_parent) if next_parent is not None else None,
            )

    def _passport_lineage_jtis(self, claims: dict[str, Any]) -> list[str]:
        self._seed_lineage_parent_cache(claims)
        lineage: list[str] = []
        seen: set[str] = set()
        current_jti = str(claims["jti"])
        while True:
            if current_jti in seen:
                raise PassportStateUnavailableError(
                    "revocation_list_unavailable",
                    f"passport lineage cycle detected at '{current_jti}'",
                )
            seen.add(current_jti)
            lineage.append(current_jti)
            if len(lineage) - 1 > MAX_DELEGATION_DEPTH:
                raise PermissionError("delegation depth exceeded")
            try:
                parent_jti = self._cached_lineage_parent(current_jti)
            except KeyError as exc:
                raise PassportStateUnavailableError(
                    "revocation_list_unavailable",
                    f"passport lineage metadata missing for '{current_jti}'",
                ) from exc
            if parent_jti is None:
                return lineage
            current_jti = parent_jti

    def _first_revoked_jti_in_lineage_locked(self, claims: dict[str, Any]) -> str | None:
        revoked = self._load_revoked_locked()
        for lineage_jti in self._passport_lineage_jtis(claims):
            if lineage_jti in revoked:
                return lineage_jti
        return None

    def _assert_passport_lineage_not_revoked_locked(self, claims: dict[str, Any]) -> None:
        if self._first_revoked_jti_in_lineage_locked(claims) is not None:
            raise PermissionError("passport_revoked")

    def _copy_session_state(self, target: GovernanceSession, source: GovernanceSession) -> None:
        # B.9: in-process memory store state is not fully rehydrated from disk
        # (dict-backed prototype). Refreshing from JSON must not wipe live
        # GovernedMemoryStore instances or compromise flags mid-session.
        preserved_stores = target.memory_stores
        preserved_compromised = set(target.memory_compromised_stores)
        preserved_last = target.last_memory_record_id
        target.passport_token = source.passport_token
        target.passport_claims = dict(source.passport_claims)
        target.events = list(source.events)
        target.tool_call_count = source.tool_call_count
        target.tool_call_count_by_class = dict(source.tool_call_count_by_class)
        target.delegated_budget_reserved = source.delegated_budget_reserved
        target.delegated_children = list(source.delegated_children)
        target.start_time = source.start_time
        target.end_time = source.end_time
        target.summary = source.summary
        target.attestation_token = source.attestation_token
        target.memory_stores = preserved_stores if preserved_stores else getattr(source, "memory_stores", {})
        target.memory_compromised_stores = preserved_compromised | set(
            getattr(source, "memory_compromised_stores", ())
        )
        target.last_receipt_id = getattr(source, "last_receipt_id", None)
        target.last_receipt_full_hash = getattr(source, "last_receipt_full_hash", None)
        target.run_nonce = getattr(source, "run_nonce", target.run_nonce)
        target.last_memory_record_id = (
            preserved_last if preserved_last is not None else getattr(source, "last_memory_record_id", None)
        )

    def _install_or_refresh_session(
        self,
        session_id: str,
        fresh: GovernanceSession,
        preferred: GovernanceSession | None = None,
    ) -> GovernanceSession:
        with self._sessions_lock:
            target = self.sessions.get(session_id)
            if target is None and preferred is not None:
                target = preferred
                self.sessions[session_id] = target
            elif target is None:
                self.sessions[session_id] = fresh
                return fresh
        with target._lock:
            self._copy_session_state(target, fresh)
        return target

    @contextlib.contextmanager
    def _locked_persisted_session(self, session: GovernanceSession | str):
        session_id = session.jti if isinstance(session, GovernanceSession) else str(session)
        preferred = session if isinstance(session, GovernanceSession) else None
        with self._session_coordination_lock(session_id):
            fresh = self._load_session_from_disk(session_id)
            yield self._install_or_refresh_session(session_id, fresh, preferred=preferred)

    def _delegation_parent_token_and_claims(
        self,
        parent_token: str,
    ) -> tuple[str, dict[str, Any]]:
        try:
            return parent_token, self.verify_passport_token(parent_token)
        except jwt.PyJWTError as passport_err:
            # Fall back to AAT decode. Preserve the original passport error so
            # audits can distinguish "expired legacy passport" from "malformed
            # AAT grant" — without ``from``, an expired passport appears as an
            # AAT validation failure in the audit log, misleading responders.
            try:
                aat_claims = decode_aat_claims(parent_token, self.public_key)
            except jwt.PyJWTError:
                # Token is unparseable as either format. Re-raise PyJWTError so
                # the outer HTTP handler responds 401 (not 403).
                raise
            except PermissionError as aat_err:
                # Token parses as AAT but fails shape validation. Include the
                # original passport error in the message so responders see both
                # decode attempts, not just the AAT-specific failure.
                raise PermissionError(
                    f"parent token failed passport decode ({passport_err}) "
                    f"and AAT validation ({aat_err})"
                ) from aat_err
            session = self.get_session(str(aat_claims["jti"]))
            if session.passport_claims.get("credential_format") != AAT_CREDENTIAL_FORMAT:
                raise PermissionError(
                    "AAT delegation parent session is not active"
                ) from passport_err
            return session.passport_token, dict(session.passport_claims)

    def delegate_passport(
        self,
        parent_token: str,
        private_key: ec.EllipticCurvePrivateKey,
        child_agent_id: str,
        child_allowed_tools: list[str],
        child_mission: str,
        child_ttl_s: int | None = None,
        child_max_tool_calls: int | None = None,
        child_resource_scope: list[str] | None = None,
        delegation_request_id: str | None = None,
    ) -> tuple[str, dict[str, Any], int]:
        derivation_parent_token, parent_claims = self._delegation_parent_token_and_claims(
            parent_token
        )
        parent_jti = str(parent_claims["jti"])
        request_id = delegation_request_id or uuid.uuid4().hex
        receipt_entry: dict[str, Any] | None = None
        child_budget = 0
        parent_calls_remaining = 0
        with self._locked_persisted_session(parent_jti) as parent_session:
            with parent_session._lock:
                if parent_session.summary is not None:
                    raise PermissionError(
                        "parent session is ended; cannot delegate from a completed session"
                    )
                used = parent_session.tool_call_count
                ceiling = int(parent_session.passport_claims.get("max_tool_calls", 50))
                reserved = self.lineage_budget_ledger.reserved_total(
                    parent_jti,
                    floor_reserved_total=parent_session.delegated_budget_reserved,
                )
                existing_reservation = self.lineage_budget_ledger.reservation(
                    parent_jti,
                    request_id,
                )
                existing_amount = None
                if existing_reservation is not None:
                    existing_agent = existing_reservation.get("child_agent_id")
                    if existing_agent != child_agent_id:
                        raise LineageBudgetConflictError(
                            "delegation_request_id already used for a different reservation"
                        )
                    existing_amount = int(existing_reservation.get("amount", 0))
                parent_calls_remaining = max(0, ceiling - used - reserved)
                derivation_remaining = (
                    existing_amount
                    if existing_amount is not None
                    else parent_calls_remaining
                )
                reserved_for_derivation = (
                    max(0, reserved - existing_amount)
                    if existing_amount is not None
                    else reserved
                )
                child_token = derive_child_passport(
                    parent_token=derivation_parent_token,
                    public_key=self.public_key,
                    private_key=private_key,
                    child_agent_id=child_agent_id,
                    child_allowed_tools=child_allowed_tools,
                    child_mission=child_mission,
                    child_ttl_s=child_ttl_s,
                    child_max_tool_calls=child_max_tool_calls,
                    parent_calls_remaining=derivation_remaining,
                    # Escrow-rights defense in depth (sprint #17, April 15
                    # 2026). The proxy already subtracts ``reserved`` from
                    # the live remaining count; passing the same value as
                    # ``parent_reserved_for_descendants`` re-enforces the
                    # invariant inside the cryptographic boundary so callers
                    # that accidentally inflate ``parent_calls_remaining``
                    # still cannot mint a child that violates the lineage
                    # conservation rule.
                    parent_reserved_for_descendants=reserved_for_derivation,
                    child_resource_scope=child_resource_scope,
                )
                child_claims = self.verify_passport_token(
                    child_token,
                    parent_token=derivation_parent_token,
                )
                child_jti = str(child_claims.get("jti"))
                child_budget = int(child_claims["max_tool_calls"])
                reservation = self.lineage_budget_ledger.reserve(
                    parent_jti=parent_jti,
                    request_id=request_id,
                    amount=child_budget,
                    ceiling=ceiling,
                    used_total=used,
                    child_agent_id=child_agent_id,
                    child_jti=str(child_claims.get("jti")),
                    floor_reserved_total=parent_session.delegated_budget_reserved,
                )
                if (
                    not reservation.accepted
                    or (
                        not reservation.idempotent
                        and child_budget > reservation.remaining_before
                    )
                ):
                    raise PermissionError("child delegation would over-reserve parent budget")
                parent_session.delegated_budget_reserved = reservation.reserved_total
                child_record = {
                    "delegation_request_id": request_id,
                    "parent_jti": parent_jti,
                    "child_jti": child_jti,
                    "child_agent_id": child_agent_id,
                    "child_mission": child_mission,
                    "child_allowed_tools": list(child_claims.get("allowed_tools", [])),
                    "child_tool_scope_mode": child_claims.get(
                        "tool_scope_mode",
                        "allowlist",
                    ),
                    "child_forbidden_tools": list(child_claims.get("forbidden_tools", [])),
                    "child_max_tool_calls": child_budget,
                    "delegated_budget_reserved": reservation.amount,
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
                parent_session.delegated_children = [
                    child
                    for child in parent_session.delegated_children
                    if child.get("delegation_request_id") != request_id
                ]
                parent_session.delegated_children.append(child_record)
                parent_calls_remaining = reservation.remaining_before
                timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                audit_reason = (
                    f"reserved {reservation.amount} delegated call budget "
                    f"for child {child_agent_id}"
                )
                event = PolicyEvent(
                    timestamp=timestamp,
                    step_id=_receipt_step_id(
                        parent_session.jti,
                        timestamp,
                        "delegate_passport",
                        {
                            "child_agent_id": child_agent_id,
                            "child_allowed_tools": child_allowed_tools,
                            "child_jti": child_jti,
                            "child_tool_scope_mode": child_claims.get(
                                "tool_scope_mode",
                                "allowlist",
                            ),
                            "requested_child_max_tool_calls": child_max_tool_calls,
                        },
                    ),
                    actor=str(parent_session.passport_claims.get("sub", "unknown")),
                    verifier_id=self.verifier_id,
                    tool_name="delegate_passport",
                    arguments={
                        "child_agent_id": child_agent_id,
                        "child_allowed_tools": list(child_allowed_tools),
                        "child_jti": child_jti,
                        "child_tool_scope_mode": child_claims.get(
                            "tool_scope_mode",
                            "allowlist",
                        ),
                        "requested_child_max_tool_calls": child_max_tool_calls,
                        "child_max_tool_calls": child_budget,
                        "delegation_request_id": request_id,
                    },
                    action_class="delegate",
                    target=child_agent_id,
                    resource_family="delegation",
                    side_effect_class="state_change",
                    decision=Decision.PERMIT,
                    reason=audit_reason,
                    passport_jti=parent_session.jti,
                    trace_id=parent_session.jti,
                    run_nonce=parent_session.run_nonce,
                    budget_delta={
                        "operation": "reserve",
                        "resource": "lineage_budget",
                        "amount": reservation.amount,
                        "unit": "tool_call",
                        "remaining_for_parent": reservation.remaining_after,
                        "reserved_total": reservation.reserved_total,
                        "delegation_request_id": request_id,
                        "idempotent": reservation.idempotent,
                    },
                )
                parent_session.events.append(event)
                receipt_entry = self._build_receipt_log_entry(
                    parent_session,
                    event,
                    Decision.PERMIT,
                    audit_reason,
                    parent_session.passport_claims,
                )
                self._persist_session(parent_session)
        self._log(
            {
                "type": "delegation",
                "jti": parent_jti,
                "child_agent_id": child_agent_id,
                "child_budget": child_budget,
                "parent_calls_remaining_at_delegation": parent_calls_remaining,
            }
        )
        if receipt_entry is not None:
            self._log_receipt(receipt_entry)
        return child_token, child_claims, parent_calls_remaining

    def _load_replay_cache_locked(self) -> dict[str, dict[str, int]]:
        if self._replay_cache_sentinel is None:
            self._replay_cache_sentinel = self._try_initialize_replay_cache_locked()
            if self._replay_cache_sentinel is None:
                raise PassportStateUnavailableError(
                    "replay_cache_unavailable",
                    "replay_cache.json requires operator re-initialization",
                )
        payload = self._load_state_json_locked(
            self.replay_cache_path,
            error_code="replay_cache_unavailable",
        )
        try:
            _sentinel, entries = self._parse_replay_cache_payload(
                payload,
                expected_sentinel=self._replay_cache_sentinel,
                allow_legacy=False,
            )
        except PassportStateUnavailableError as exc:
            if "sentinel mismatch" not in str(exc):
                raise
            self._replay_cache_sentinel = None
            self._replay_cache_sentinel = self._try_initialize_replay_cache_locked()
            if self._replay_cache_sentinel is None:
                raise PassportStateUnavailableError(
                    "replay_cache_unavailable",
                    "replay_cache.json requires operator re-initialization",
                ) from exc
            payload = self._load_state_json_locked(
                self.replay_cache_path,
                error_code="replay_cache_unavailable",
            )
            _sentinel, entries = self._parse_replay_cache_payload(
                payload,
                expected_sentinel=self._replay_cache_sentinel,
                allow_legacy=False,
            )
        return entries

    def _persist_replay_cache_locked(
        self,
        entries: dict[str, dict[str, int]],
        *,
        sentinel: str | None = None,
    ) -> None:
        active_sentinel = sentinel or self._replay_cache_sentinel
        if active_sentinel is None:
            raise PassportStateUnavailableError(
                "replay_cache_unavailable",
                "replay_cache.json requires operator re-initialization",
            )
        ordered_entries = dict(
            sorted(entries.items(), key=lambda item: (item[1]["exp"], item[1]["first_seen"]))
        )
        self._persist_json_file(
            self.replay_cache_path,
            {
                "version": _PASSPORT_STATE_SCHEMA_VERSION,
                "sentinel": active_sentinel,
                "entries": ordered_entries,
            },
        )

    def _record_passport_use(self, claims: dict[str, Any], passport_token: str) -> None:
        jti = str(claims["jti"])
        now = int(time.time())
        cache_size = 0
        warn_threshold_crossed = False
        with self._passport_state_lock():
            entries = self._load_replay_cache_locked()
            if jti in entries:
                raise PermissionError(f"passport jti '{jti}' replay detected")
            if len(entries) >= REPLAY_CACHE_MAX_ENTRIES:
                self._log(
                    {
                        "type": "warning",
                        "warning": "replay_cache_full",
                        "entries": len(entries),
                        "limit": REPLAY_CACHE_MAX_ENTRIES,
                    }
                )
                raise PassportStateUnavailableError(
                    "replay_cache_full",
                    (
                        "replay cache is full of unexpired JTIs; "
                        "no new sessions can start until entries expire or an operator rotates state"
                    ),
                )
            entries[jti] = {"first_seen": now, "exp": int(claims["exp"])}
            self._persist_replay_cache_locked(entries)
            token_hashes, lineage_edges = self._load_lineage_index_locked()
            existing_hash = token_hashes.get(jti)
            token_hash = _passport_token_hash(passport_token)
            if existing_hash is not None and existing_hash != token_hash:
                raise PassportStateUnavailableError(
                    "lineage_hashes_unavailable",
                    f"lineage_hashes.json has conflicting token hash for {jti!r}",
                )
            lineage_edge = self._lineage_edge_from_claims(claims)
            existing_edge = lineage_edges.get(jti)
            if existing_edge is not None and existing_edge != lineage_edge:
                raise PassportStateUnavailableError(
                    "lineage_hashes_unavailable",
                    f"lineage_hashes.json has conflicting parent metadata for {jti!r}",
                )
            token_hashes[jti] = token_hash
            lineage_edges[jti] = lineage_edge
            self._persist_lineage_hashes_locked(token_hashes, lineage_edges)
            cache_size = len(entries)
            warn_threshold_crossed = cache_size == REPLAY_CACHE_WARN_ENTRIES
        if warn_threshold_crossed:
            self._log(
                {
                    "type": "warning",
                    "warning": "replay_cache_near_capacity",
                    "entries": cache_size,
                    "limit": REPLAY_CACHE_MAX_ENTRIES,
                }
            )

    def _load_revoked_locked(self) -> dict[str, int]:
        if self._revoked_sentinel is None:
            self._revoked_sentinel = self._try_initialize_revoked_locked()
            if self._revoked_sentinel is None:
                raise PassportStateUnavailableError(
                    "revocation_list_unavailable",
                    "revoked.json requires operator re-initialization",
                )
        payload = self._load_state_json_locked(
            self.revoked_path,
            error_code="revocation_list_unavailable",
        )
        try:
            _sentinel, revoked = self._parse_revoked_payload(
                payload,
                expected_sentinel=self._revoked_sentinel,
                allow_legacy=False,
            )
        except PassportStateUnavailableError as exc:
            if "sentinel mismatch" not in str(exc):
                raise
            self._revoked_sentinel = None
            self._revoked_sentinel = self._try_initialize_revoked_locked()
            if self._revoked_sentinel is None:
                raise PassportStateUnavailableError(
                    "revocation_list_unavailable",
                    "revoked.json requires operator re-initialization",
                ) from exc
            payload = self._load_state_json_locked(
                self.revoked_path,
                error_code="revocation_list_unavailable",
            )
            _sentinel, revoked = self._parse_revoked_payload(
                payload,
                expected_sentinel=self._revoked_sentinel,
                allow_legacy=False,
            )
        return revoked

    def _persist_revoked_locked(
        self,
        revoked: dict[str, int],
        *,
        sentinel: str | None = None,
    ) -> None:
        active_sentinel = sentinel or self._revoked_sentinel
        if active_sentinel is None:
            raise PassportStateUnavailableError(
                "revocation_list_unavailable",
                "revoked.json requires operator re-initialization",
            )
        self._persist_json_file(
            self.revoked_path,
            {
                "version": _PASSPORT_STATE_SCHEMA_VERSION,
                "sentinel": active_sentinel,
                "jtis": dict(sorted(revoked.items())),
            },
        )

    @staticmethod
    def _lineage_edge_from_claims(claims: dict[str, Any]) -> LineageEdge:
        parent_jti = claims.get("parent_jti")
        parent_hash = claims.get("parent_token_hash")
        normalized_parent_jti = (
            str(parent_jti) if isinstance(parent_jti, str) and parent_jti else None
        )
        if normalized_parent_jti is None:
            return None, None
        if not isinstance(parent_hash, str) or not _SHA256_HEX_RE.match(parent_hash):
            raise PassportStateUnavailableError(
                "lineage_hashes_unavailable",
                "delegated passport parent hash is missing from lineage metadata",
            )
        return normalized_parent_jti, parent_hash.lower()

    def _load_lineage_index_locked(self) -> tuple[dict[str, str], dict[str, LineageEdge]]:
        if self._lineage_hashes_sentinel is None:
            self._lineage_hashes_sentinel = self._try_initialize_lineage_hashes_locked()
            if self._lineage_hashes_sentinel is None:
                raise PassportStateUnavailableError(
                    "lineage_hashes_unavailable",
                    "lineage_hashes.json requires operator re-initialization",
                )
        payload = self._load_state_json_locked(
            self.lineage_hashes_path,
            error_code="lineage_hashes_unavailable",
        )
        try:
            _sentinel, token_hashes, lineage_edges = self._parse_lineage_hashes_payload(
                payload,
                expected_sentinel=self._lineage_hashes_sentinel,
                allow_legacy=False,
            )
        except PassportStateUnavailableError as exc:
            if "sentinel mismatch" not in str(exc):
                raise
            self._lineage_hashes_sentinel = None
            self._lineage_hashes_sentinel = self._try_initialize_lineage_hashes_locked()
            if self._lineage_hashes_sentinel is None:
                raise PassportStateUnavailableError(
                    "lineage_hashes_unavailable",
                    "lineage_hashes.json requires operator re-initialization",
                ) from exc
            payload = self._load_state_json_locked(
                self.lineage_hashes_path,
                error_code="lineage_hashes_unavailable",
            )
            _sentinel, token_hashes, lineage_edges = self._parse_lineage_hashes_payload(
                payload,
                expected_sentinel=self._lineage_hashes_sentinel,
                allow_legacy=False,
            )
        return token_hashes, lineage_edges

    def _persist_lineage_hashes_locked(
        self,
        token_hashes: dict[str, str],
        lineage_edges: dict[str, LineageEdge],
        *,
        sentinel: str | None = None,
    ) -> None:
        active_sentinel = sentinel or self._lineage_hashes_sentinel
        if active_sentinel is None:
            raise PassportStateUnavailableError(
                "lineage_hashes_unavailable",
                "lineage_hashes.json requires operator re-initialization",
            )
        self._persist_json_file(
            self.lineage_hashes_path,
            {
                "version": _PASSPORT_STATE_SCHEMA_VERSION,
                "sentinel": active_sentinel,
                "token_hashes": dict(sorted(token_hashes.items())),
                "parents": {
                    jti: {
                        "parent_jti": edge[0],
                        "parent_token_hash": edge[1],
                    }
                    for jti, edge in sorted(lineage_edges.items())
                },
            },
        )

    def _persist_json_file(self, path: Path, payload: dict[str, Any]) -> None:
        tmp = path.with_name(f"{path.stem}.{uuid.uuid4().hex}.tmp")
        try:
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            os.replace(tmp, path)
        except Exception:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise

    def _persist_session(self, session: GovernanceSession) -> None:
        # Atomic write: write to a unique .tmp in same dir, fsync-adjacent rename.
        # Unique filename (uuid4) prevents two concurrent writes for the same
        # session from fighting over the same tmp file. os.replace is atomic
        # on POSIX and makes concurrent writes last-writer-wins rather than
        # interleave-corruption. Prevents SIGKILL-mid-write corruption too.
        payload = self._add_session_receipt_integrity(session.jti, session.to_dict())
        self._persist_json_file(self._session_path(session.jti), payload)

    def _log(self, entry: dict[str, Any]) -> None:
        self._governance_log.write(entry)

    def _log_receipt(self, entry: dict[str, Any]) -> None:
        self._receipts_log.write(entry)


PUBLIC_PATHS = frozenset({"/health", "/healthz", "/.well-known/jwks.json"})


def _public_key_to_jwk(public_key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    """Serialize an ES256 (P-256) public key to JWK format per RFC 7517/7518.

    External verifiers fetch this from /.well-known/jwks.json to verify
    passport and attestation JWTs without out-of-band key distribution."""
    numbers = public_key.public_numbers()
    # P-256 coordinates are 32 bytes each, big-endian, left-padded with zeros.
    x_bytes = numbers.x.to_bytes(32, "big")
    y_bytes = numbers.y.to_bytes(32, "big")
    return {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "kid": "vibap-primary",
        "x": base64.urlsafe_b64encode(x_bytes).rstrip(b"=").decode("ascii"),
        "y": base64.urlsafe_b64encode(y_bytes).rstrip(b"=").decode("ascii"),
    }


def _generate_api_token() -> str:
    """Generate a 32-byte random token, base64-encoded (urlsafe, no padding)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def _redact_token(token: str) -> str:
    """Return a short fingerprint of a token safe to print or log."""
    if not token:
        return "<empty>"
    if len(token) <= 12:
        return f"{token[:4]}...{token[-4:]}"
    return f"{token[:8]}...{token[-4:]}"


def _display_token(token: str) -> str:
    """Return the token value for the startup banner, redacted by default."""
    if os.environ.get("VIBAP_PRINT_FULL_TOKEN") == "1":
        return token
    return _redact_token(token)


def serve_proxy(
    proxy: GovernanceProxy,
    private_key: ec.EllipticCurvePrivateKey,
    host: str = "127.0.0.1",
    port: int = 8080,
    initial_session_id: str | None = None,
    require_auth: bool = True,
    api_token: str | None = None,
    tls_cert: str | Path | None = None,
    tls_key: str | Path | None = None,
    no_tls: bool = False,
) -> None:
    # Resolve auth token: env var overrides explicit arg per product requirement
    # ("token from env var should override the generated one"). If neither is set,
    # generate a fresh 32-byte random token.
    # FIX-R9-1 (round-9, 2026-04-29): TrimSpace the env-loaded token,
    # mirroring the Go-side R8-3 closure. Round-8 audit (MED-NEW-1)
    # flagged that R8-3 closed the Go path but missed Python — same
    # Python/Go asymmetry pattern round-7 raised against the bearer
    # length-leak. Without this, an operator who sets
    # ``VIBAP_API_TOKEN=" my-token "`` (e.g. via a YAML-quoted secret)
    # creates a proxy where NO client can authenticate, because
    # ``_check_auth`` strips the bearer payload but the env-loaded
    # token retains its whitespace.
    env_token_raw = os.environ.get("VIBAP_API_TOKEN")
    env_token = env_token_raw.strip() if env_token_raw is not None else None
    if env_token:
        api_token = env_token
        token_source = "env:VIBAP_API_TOKEN"
    elif api_token:
        # FIX-R10-4 (round-10, 2026-04-29): strip the CLI-supplied
        # token symmetric with the env-loaded path (R9-1) and the Go
        # binaries' TrimSpace. Round-9 audit (LOW-NEW-3) caught the
        # asymmetry: an operator running ``--api-token "  abc  "`` (e.g.
        # from a YAML ``command:`` block) would create the same
        # operator-confusion failure mode R9-1 closed for env vars.
        api_token = api_token.strip()
        token_source = "argument"
    else:
        api_token = _generate_api_token()
        token_source = "generated"

    # Pre-encode once for the hot path. Round-8 (FIX-R8-1, 2026-04-29):
    # the bearer-auth comparison now hashes both presented and expected
    # tokens through SHA-256 before ``hmac.compare_digest``, normalizing
    # both inputs to a fixed 32-byte length. CPython's ``_tscmp`` (the
    # C function backing ``hmac.compare_digest``) iterates ``min(len_a,
    # len_b)`` and short-circuits on length mismatch, leaking the
    # expected token's length to a remote attacker. Round-7 closed this
    # for the Go control-plane services (cmd/authority + pkg/governance);
    # round-8 closes the symmetric Python proxy gap that round-7 audit
    # flagged as MED-NEW-1.
    api_token_bytes = api_token.encode("ascii")
    api_token_hash = hashlib.sha256(api_token_bytes).digest()

    active_session_ref = {"id": initial_session_id}
    active_session_lock = threading.Lock()

    def active_session_count() -> int:
        # Snapshot under the proxy-level lock to avoid RuntimeError on
        # "dictionary changed size during iteration" when /health fires
        # while a /session/start is mid-flight.
        with proxy._sessions_lock:
            snapshot = list(proxy.sessions.values())
        return sum(1 for s in snapshot if s.summary is None)

    def get_active_session_id() -> str:
        with active_session_lock:
            active_session_id = active_session_ref["id"]
            if active_session_id is not None:
                session = proxy.get_session(active_session_id)
                if session.summary is None:
                    return active_session_id
                active_session_ref["id"] = None

            # Snapshot under proxy._sessions_lock — same reason as active_session_count
            with proxy._sessions_lock:
                active_session_ids = [sid for sid, s in proxy.sessions.items() if s.summary is None]
            if not active_session_ids:
                raise ValueError("no active session; call POST /session/start first")
            if len(active_session_ids) > 1:
                raise ValueError("multiple active sessions; specify session_id explicitly")

            active_session_ref["id"] = active_session_ids[0]
            return active_session_ids[0]

    def set_active_session_id(session_id: str | None) -> None:
        with active_session_lock:
            active_session_ref["id"] = session_id

    rate_limiter = RateLimiter()

    class Handler(BaseHTTPRequestHandler):
        server_version = f"VIBAPProxy/{API_VERSION}"

        def _check_rate_limit(self) -> bool:
            """Return True if the request is within rate limits, emit 429 otherwise."""
            client_ip = self.client_address[0] if self.client_address else "unknown"
            if not rate_limiter.allow(client_ip):
                self._send_json(429, {"error": "rate limit exceeded"}, headers={"Retry-After": "1"})
                return False
            return True

        def log_message(self, format: str, *args: object) -> None:  # noqa: A003
            duration_ms = 0
            if hasattr(self, "_request_start_time"):
                duration_ms = (time.time() - self._request_start_time) * 1000  # type: ignore[has-attr]
            remote = self.client_address[0] if self.client_address else "-"
            entry = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
                "remote_addr": remote,
                "method": self.command,
                "path": self._sanitize_path_for_log(),
                "status": self.responses.get(self.command, (None,))[0] if hasattr(self, "responses") else None,
                "response_size": 0,
                "duration_ms": round(duration_ms, 3),
                "correlation_id": getattr(self, "_correlation_id", "-"),
                "session_id": getattr(self, "_active_session", "-"),
            }
            print(json.dumps(entry), file=sys.stderr, flush=True)

        def _sanitize_path_for_log(self) -> str:
            path = self.path.split("?", 1)[0] if hasattr(self, "path") else "?"
            # Redact session-ids / tokens from query strings
            return path[:256]

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_REQUEST_BODY:
                raise ValueError(f"request body too large ({length} bytes, max {MAX_REQUEST_BODY})")
            if length < 0:
                raise ValueError("invalid Content-Length")
            raw = self.rfile.read(length) if length else b"{}"
            if not raw:
                return {}
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
            return payload

        def _request_path(self) -> str:
            return self.path.split("?", 1)[0]

        def _require_field(self, payload: dict[str, Any], field_name: str) -> Any:
            if field_name not in payload:
                raise ValueError(f"missing field: {field_name}")
            return payload[field_name]

        def _require_string_field(
            self,
            payload: dict[str, Any],
            field_name: str,
        ) -> str:
            value = self._require_field(payload, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
            return value

        @staticmethod
        def _string_list_field(
            value: Any,
            field_name: str,
            *,
            allow_empty: bool = False,
        ) -> list[str]:
            if not isinstance(value, list):
                raise ValueError(
                    f"{field_name} must be a JSON array of non-empty strings"
                )
            if not allow_empty and not value:
                raise ValueError(
                    f"{field_name} must be a JSON array of non-empty strings"
                )
            if any(not isinstance(item, str) or not item for item in value):
                raise ValueError(
                    f"{field_name} must be a JSON array of non-empty strings"
                )
            return list(value)

        def _send_json(
            self,
            status: int,
            payload: dict[str, Any],
            headers: dict[str, str] | None = None,
        ) -> None:
            body = json.dumps(payload, indent=2).encode("utf-8")
            extra_headers = dict(headers or {})
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            # Security headers
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'none'")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            if tls_active:
                self.send_header("Strict-Transport-Security", "max-age=31536000")
            corr_id = getattr(self, "_correlation_id", None)
            if corr_id:
                self.send_header("X-Correlation-ID", corr_id)
            if status == 401:
                self.send_header(
                    "WWW-Authenticate",
                    extra_headers.pop("WWW-Authenticate", 'Bearer realm="vibap"'),
                )
            for header_name, header_value in extra_headers.items():
                self.send_header(header_name, header_value)
            self.end_headers()
            self.wfile.write(body)
            # Metrics
            method = getattr(self, "command", "?")
            path = self._request_path()
            ardur_metrics.requests_total.inc(method=method, path=path, status=str(status))
            if hasattr(self, "_request_start_time"):
                dur = time.time() - self._request_start_time
                ardur_metrics.request_duration_seconds.observe(dur)

        def _check_auth(self) -> bool:
            """Return True if the request is authorized (or auth is disabled / path is public).

            Emits a 401 response and returns False otherwise.
            """
            if not require_auth:
                return True
            if self._request_path() in PUBLIC_PATHS:
                return True
            header = self.headers.get("Authorization", "")
            if not header or not header.lower().startswith("bearer "):
                self._send_json(401, {"error": "missing or malformed Authorization header"})
                return False
            # FIX-R9-5 (round-9, 2026-04-29): symmetric ASCII handling.
            # Round-8 audit (LOW-NEW-4) flagged asymmetric error
            # handling — the operator-supplied token used strict ASCII
            # (fail-loud at startup), the client-presented token used
            # ``errors="replace"`` (fail-quiet, mapping non-ASCII to
            # `?`). A client with a UTF-8 token had its bytes silently
            # mutated before comparison. Now both sides use strict
            # ASCII; non-ASCII bytes in the Authorization header
            # produce an explicit 401 instead of a silent mismap.
            try:
                provided = header[7:].strip().encode("ascii")
            except UnicodeEncodeError:
                self._send_json(401, {"error": "bearer token must be ASCII"})
                return False
            # FIX-R8-1: hash-then-compare normalizes lengths and defeats
            # the length oracle; see api_token_hash construction above.
            provided_hash = hashlib.sha256(provided).digest()
            if not hmac.compare_digest(provided_hash, api_token_hash):
                self._send_json(401, {"error": "invalid bearer token"})
                return False
            return True

        def do_GET(self) -> None:  # noqa: N802
            self._request_start_time = time.time()
            self._correlation_id = self.headers.get("X-Correlation-ID", str(uuid.uuid4()))
            path = self._request_path()
            # Public endpoints respond without auth.
            if path in {"/health", "/healthz"}:
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "version": API_VERSION,
                        "sessions": active_session_count(),
                    },
                )
                return
            if path == "/.well-known/jwks.json":
                self._send_json(200, {"keys": [_public_key_to_jwk(proxy.public_key)]})
                return
            if not self._check_rate_limit():
                return
            if not self._check_auth():
                return
            if path == "/metrics":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(ardur_metrics.render().encode("utf-8"))
                return
            if path != "/":
                self._send_json(404, {"error": "not found"})
                return
            self._send_json(
                200,
                {
                    "status": "ok",
                    "version": API_VERSION,
                    "sessions": active_session_count(),
                },
            )

        def do_POST(self) -> None:  # noqa: N802
            self._request_start_time = time.time()
            self._correlation_id = self.headers.get("X-Correlation-ID", str(uuid.uuid4()))
            if not self._check_rate_limit():
                return
            if not self._check_auth():
                return
            try:
                payload = self._read_json()
                path = self._request_path()

                if path == "/admin/kill-switch":
                    if payload.get("deactivate", False):
                        proxy.deactivate_kill_switch()
                        self._send_json(200, {"kill_switch": "deactivated"})
                    else:
                        proxy.activate_kill_switch()
                        self._send_json(200, {"kill_switch": "activated"})
                    return

                # Kill-switch guard: deny state-changing endpoints when active
                if proxy.kill_switch_active and path in {"/session/start", "/sessions", "/evaluate", "/delegate", "/issue"}:
                    self._send_json(503, {"error": "kill_switch_active"})
                    return

                if path == "/issue":
                    mission_payload = payload.get("mission", payload)
                    if not isinstance(mission_payload, dict):
                        raise ValueError("mission must be a JSON object")
                    mission = MissionPassport.from_dict(mission_payload)
                    token = issue_passport(mission, private_key, ttl_s=payload.get("ttl_s"))
                    claims = verify_passport(token, proxy.public_key)
                    self._send_json(200, {"token": token, "claims": claims})
                    return

                if path == "/verify":
                    claims = proxy.verify_passport_token(str(self._require_field(payload, "token")))
                    self._send_json(200, {"claims": claims})
                    return

                if path in {"/session/start", "/sessions"}:
                    token = str(self._require_field(payload, "token"))
                    token_type = str(payload.get("token_type", "passport")).lower()
                    if token_type == "aat":
                        parent_aat_token = payload.get("parent_token")
                        if parent_aat_token is not None and not isinstance(parent_aat_token, str):
                            raise ValueError("parent_token must be a string when token_type=aat")
                        # PoP plumbing — defaults secure (require_pop=True). The
                        # adapter only enforces PoP for AATs that actually carry
                        # a `cnf` claim, so bearer-mode AATs continue to work
                        # without any new fields. Callers who legitimately need
                        # bearer acceptance of a cnf-bearing AAT must pass
                        # "require_pop": false explicitly so the security
                        # downgrade is visible in request logs.
                        require_pop_field = payload.get("require_pop", True)
                        if not isinstance(require_pop_field, bool):
                            raise ValueError(
                                "require_pop must be a boolean when token_type=aat"
                            )
                        holder_pem = payload.get("holder_public_key_pem")
                        if holder_pem is not None and not isinstance(holder_pem, str):
                            raise ValueError(
                                "holder_public_key_pem must be a PEM-encoded string"
                            )
                        kb_jwt_field = payload.get("kb_jwt")
                        if kb_jwt_field is not None and not isinstance(kb_jwt_field, str):
                            raise ValueError("kb_jwt must be a string when provided")
                        # Round 3 (2026-04-28) DoS guard: a well-formed
                        # KB-JWT is small (<2KB). Bound the field length
                        # so an attacker cannot ship a 1MB string and
                        # force the server to allocate / parse it before
                        # verify_pop rejects it. Anything larger than
                        # MAX_KB_JWT_BYTES is rejected at the HTTP edge.
                        MAX_KB_JWT_BYTES = 8 * 1024
                        if (
                            isinstance(kb_jwt_field, str)
                            and len(kb_jwt_field.encode("utf-8")) > MAX_KB_JWT_BYTES
                        ):
                            raise ValueError(
                                f"kb_jwt exceeds MAX_KB_JWT_BYTES={MAX_KB_JWT_BYTES}; "
                                "well-formed RFC 7800 key-binding JWTs are small"
                            )
                        holder_pubkey: ec.EllipticCurvePublicKey | None = None
                        if holder_pem is not None:
                            from cryptography.hazmat.primitives.serialization import (
                                load_pem_public_key,
                            )
                            try:
                                loaded = load_pem_public_key(
                                    holder_pem.encode("utf-8")
                                )
                            except Exception as exc:  # noqa: BLE001
                                raise ValueError(
                                    f"invalid holder_public_key_pem: {exc}"
                                ) from exc
                            if not isinstance(loaded, ec.EllipticCurvePublicKey):
                                raise ValueError(
                                    "holder_public_key_pem must encode an EC public key"
                                )
                            holder_pubkey = loaded
                        session = proxy.start_session_from_aat(
                            token,
                            signing_key=private_key,
                            parent_aat_token=parent_aat_token,
                            holder_public_key=holder_pubkey,
                            kb_jwt=kb_jwt_field,
                            require_pop=require_pop_field,
                        )
                    elif token_type in {"passport", "mcep", "vibap"}:
                        session = proxy.start_session(token)
                    elif token_type == "biscuit":
                        if proxy._biscuit_issuer_public_key is None:
                            self._send_json(
                                501,
                                {"error": "Biscuit issuer public key not configured"},
                            )
                            return
                        from .biscuit_passport import decode_biscuit_b64

                        biscuit_bytes = decode_biscuit_b64(token)
                        peer_jwt_svid = payload.get("peer_jwt_svid")
                        if peer_jwt_svid is not None:
                            if not isinstance(peer_jwt_svid, str):
                                raise ValueError("peer_jwt_svid must be a string")
                            # Peer trust bundle must be provided as a JWKS dict
                            # in the payload. In Docker, the SPIRE agent
                            # provides this via the Workload API.
                            peer_trust_jwks = payload.get("peer_trust_jwks")
                            if not isinstance(peer_trust_jwks, dict):
                                raise ValueError(
                                    "peer_trust_jwks is required when "
                                    "peer_jwt_svid is supplied"
                                )
                            from vibap.spiffe_identity import TrustBundle

                            peer_trust_domain = str(
                                payload.get("peer_trust_domain", "ardur.dev")
                            )
                            peer_trust_bundle = TrustBundle(
                                trust_domain=peer_trust_domain,
                                jwks=peer_trust_jwks,
                                federated_bundles={},
                            )
                            svid_audience = payload.get("svid_audience")
                            kwargs: dict[str, Any] = {
                                "peer_jwt_svid": peer_jwt_svid,
                                "peer_trust_bundle": peer_trust_bundle,
                            }
                            if svid_audience is not None:
                                if not isinstance(svid_audience, str):
                                    raise ValueError("svid_audience must be a string")
                                kwargs["svid_audience"] = svid_audience
                            session = proxy.start_session_from_biscuit(
                                biscuit_bytes,
                                proxy._biscuit_issuer_public_key,
                                **kwargs,
                            )
                        else:
                            session = proxy.start_session_from_biscuit(
                                biscuit_bytes,
                                proxy._biscuit_issuer_public_key,
                            )
                    else:
                        raise ValueError(f"unsupported token_type: {token_type}")
                    set_active_session_id(session.jti)
                    if path == "/session/start":
                        self._send_json(
                            200,
                            {
                                "session_id": session.jti,
                                "agent_id": session.passport_claims["sub"],
                                "allowed_tools": list(session.passport_claims.get("allowed_tools", [])),
                                "credential_format": session.passport_claims.get(
                                    "credential_format",
                                    "passport",
                                ),
                            },
                        )
                        return
                    self._send_json(200, {"session_id": session.jti, "claims": session.passport_claims})
                    return

                if path == "/evaluate":
                    arguments = payload.get("arguments", {})
                    if arguments is None:
                        arguments = {}
                    if not isinstance(arguments, dict):
                        raise ValueError("arguments must be a JSON object")

                    session_id = payload.get("session_id") or payload.get("session")
                    if session_id is None:
                        session_id = get_active_session_id()
                    decision, reason = proxy.evaluate_tool_call(
                        str(session_id),
                        str(self._require_field(payload, "tool_name")),
                        dict(arguments),
                    )
                    if reason == "passport_revoked":
                        self._send_json(403, {"error": "passport_revoked"})
                        return
                    response: dict[str, Any] = {
                        "decision": decision.value,
                        "session_id": str(session_id),
                    }
                    if decision == Decision.PERMIT:
                        response["findings"] = []
                    else:
                        response["reason"] = reason
                    self._send_json(200, response)
                    return

                if path == "/result":
                    proxy.record_tool_result(
                        str(payload.get("session_id") or self._require_field(payload, "session")),
                        str(payload.get("response", "")),
                        float(payload.get("duration_ms", 0.0)),
                    )
                    self._send_json(200, {"status": "recorded"})
                    return

                if path in {"/session/end", "/end"}:
                    session_id = str(payload.get("session_id") or self._require_field(payload, "session"))
                    summary = proxy.end_session(session_id)
                    with active_session_lock:
                        if active_session_ref["id"] == session_id:
                            active_session_ref["id"] = None
                    if path == "/session/end":
                        token, _ = proxy.issue_attestation_for_session(session_id, private_key)
                        self._send_json(200, {"attestation_token": token, "summary": summary})
                        return
                    self._send_json(200, {"summary": summary})
                    return

                if path == "/attest":
                    token, claims = proxy.issue_attestation_for_session(
                        str(payload.get("session_id") or self._require_field(payload, "session")),
                        private_key,
                    )
                    self._send_json(200, {"token": token, "claims": claims})
                    return

                if path == "/delegate":
                    parent_token = self._require_string_field(payload, "parent_token")
                    child_agent_id = self._require_string_field(payload, "child_agent_id")
                    child_mission = self._require_string_field(payload, "child_mission")
                    child_tools = self._string_list_field(
                        self._require_field(payload, "child_allowed_tools"),
                        "child_allowed_tools",
                    )
                    child_ttl = payload.get("child_ttl_s")
                    child_max_calls = payload.get("child_max_tool_calls")
                    child_scope = payload.get("child_resource_scope")
                    delegation_request_id = payload.get("delegation_request_id")
                    if delegation_request_id is not None and (
                        not isinstance(delegation_request_id, str)
                        or not delegation_request_id.strip()
                    ):
                        raise ValueError(
                            "delegation_request_id must be a non-empty string"
                        )
                    child_ttl_int = int(child_ttl) if child_ttl is not None else None
                    child_max_calls_int = (
                        int(child_max_calls) if child_max_calls is not None else None
                    )
                    child_scope_list = (
                        self._string_list_field(
                            child_scope,
                            "child_resource_scope",
                            allow_empty=True,
                        )
                        if child_scope is not None
                        else None
                    )

                    try:
                        child_token, child_claims, parent_calls_remaining = proxy.delegate_passport(
                            parent_token=parent_token,
                            private_key=private_key,
                            child_agent_id=child_agent_id,
                            child_allowed_tools=child_tools,
                            child_mission=child_mission,
                            child_ttl_s=child_ttl_int,
                            child_max_tool_calls=child_max_calls_int,
                            child_resource_scope=child_scope_list,
                            delegation_request_id=delegation_request_id,
                        )
                    except LineageBudgetConflictError as exc:
                        self._send_json(409, {"error": str(exc)})
                    except ValueError:
                        parent_jti = str(verify_passport(parent_token, proxy.public_key)["jti"])
                        self._send_json(403, {"error": (
                            f"delegation requires parent session to exist; "
                            f"start the parent passport via /session/start before delegating "
                            f"(parent_jti={parent_jti})"
                        )})
                    except PermissionError as exc:
                        self._send_json(403, {"error": str(exc)})
                    else:
                        self._send_json(200, {
                            "child_token": child_token,
                            "child_claims": child_claims,
                            "parent_jti": child_claims.get("parent_jti"),
                            "parent_calls_remaining_at_delegation": parent_calls_remaining,
                            "delegation_request_id": delegation_request_id,
                        })
                    return

                self._send_json(404, {"error": "not found"})
            except json.JSONDecodeError as exc:
                self._send_json(400, {"error": f"invalid JSON: {exc.msg}"})
            except jwt.PyJWTError:
                self._send_json(
                    401,
                    {"error": "invalid_token"},
                    headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                )
            except PassportStateUnavailableError as exc:
                self._send_json(503, {"error": exc.error_code})
            except PermissionError as exc:
                self._send_json(403, {"error": str(exc)})
            except (TypeError, AttributeError, ValueError, KeyError) as exc:
                self._send_json(400, {"error": str(exc)})
            except Exception:  # noqa: BLE001
                # Catch-all: log with full traceback so operators can triage.
                # Without this, cryptography faults / invariant trips / disk I/O
                # errors become anonymous 500s with no audit signal.
                logger.exception(
                    "Unhandled exception in VIBAP proxy HTTP handler",
                    extra={
                        "method": getattr(self, "command", "?"),
                        "path": getattr(self, "path", "?"),
                    },
                )
                self._send_json(500, {"error": "internal server error"})

    httpd = ThreadingHTTPServer((host, port), Handler)

    tls_active = False
    if not no_tls:
        tls_result = resolve_tls_paths(tls_cert, tls_key, hostname=host)
        if tls_result:
            cert_path, key_path, cert_fingerprint = tls_result
            ssl_ctx = create_ssl_context(cert_path, key_path)
            httpd.socket = ssl_ctx.wrap_socket(httpd.socket, server_side=True)
            tls_active = True
            print(f"[tls] cert fingerprint: {cert_fingerprint}", file=sys.stderr)
    if no_tls:
        print("[tls] WARNING: TLS disabled — plain HTTP only", file=sys.stderr)

    def _shutdown_handler(signum: int, _frame: Any) -> None:
        print(f"\nReceived signal {signum}, shutting down VIBAP proxy.")
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown_handler)

    scheme = "https" if tls_active else "http"
    print(f"VIBAP proxy listening on {scheme}://{host}:{port}")
    print(
        "Endpoints: GET /health, /healthz; POST /issue, /verify, /session/start, /session/end, "
        "/sessions, /evaluate, /result, /end, /attest, /delegate"
    )
    if require_auth:
        display_token = _display_token(api_token)
        print("")
        print("=" * 72)
        print(f"Bearer auth REQUIRED on all endpoints except: {', '.join(sorted(PUBLIC_PATHS))}")
        print(f"API token ({token_source}):")
        print(f"    {display_token}")
        if display_token != api_token:
            print("Set VIBAP_PRINT_FULL_TOKEN=1 to print the full token once on stdout.")
        print("Copy this value and send it as:  Authorization: Bearer <token>")
        print("Export for hooks/clients:        export VIBAP_API_TOKEN='<token>'")
        print("=" * 72)
        print("")
        # Log-safe fingerprint only (never the full token).
        # The proxy's log_message is suppressed; emit a structured stderr line for audit.
        print(
            f"[vibap] auth=on source={token_source} token_fp={_redact_token(api_token)}",
            file=sys.stderr,
        )
    else:
        warning = (
            "\n" + "!" * 72 + "\n"
            "!! WARNING: VIBAP proxy is running WITHOUT authentication.            !!\n"
            "!! All endpoints are exposed to anyone who can reach this port.       !!\n"
            "!! DO NOT use --no-require-auth in production or on untrusted networks.!!\n"
            + "!" * 72 + "\n"
        )
        print(warning)
        print(warning, file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down VIBAP proxy.")
    finally:
        httpd.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Ardur governance proxy")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--log-path")
    parser.add_argument("--state-dir")
    parser.add_argument("--keys-dir")
    parser.add_argument("--api-token")
    parser.add_argument("--initial-session")
    parser.add_argument("--no-require-auth", action="store_true")
    parser.add_argument("--revoke", metavar="JTI")
    parser.add_argument("--tls-cert", help="TLS certificate PEM file")
    parser.add_argument("--tls-key", help="TLS private key PEM file")
    parser.add_argument("--no-tls", action="store_true", help="disable TLS (plain HTTP only)")
    args = parser.parse_args(argv)

    private_key, public_key = generate_keypair(keys_dir=args.keys_dir)
    proxy = GovernanceProxy(
        log_path=args.log_path,
        state_dir=args.state_dir,
        keys_dir=args.keys_dir,
        public_key=public_key,
    )

    if args.revoke is not None:
        proxy.revoke(args.revoke)
        print(f"revoked passport jti {args.revoke} in {proxy.revoked_path}")
        return 0

    serve_proxy(
        proxy=proxy,
        private_key=private_key,
        host=args.host,
        port=args.port,
        initial_session_id=args.initial_session,
        require_auth=not args.no_require_auth,
        api_token=args.api_token,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
        no_tls=args.no_tls,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
