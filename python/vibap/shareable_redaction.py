"""Shareable-artifact redaction helpers.

These helpers are intentionally scoped to public/shareable summaries. They do
not claim universal secret removal or runtime capture. Their job is to keep
local absolute paths, file:// targets, and configured private roots out of JSON
or text artifacts that are meant to be copied out of the machine that generated
them.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

PATH_PLACEHOLDER_LOCAL = "<ABSOLUTE_PATH:local>"

LOCAL_PATH_ROOT_MARKERS = (
    "/private/var/folders",
    "/var/folders",
    "/private/tmp",
    "/tmp",
    "/Users",
    "/home",
)

LOCAL_PATH_LEAK_MARKERS = tuple(marker + "/" for marker in LOCAL_PATH_ROOT_MARKERS) + tuple(
    "file://" + marker + "/" for marker in LOCAL_PATH_ROOT_MARKERS
)

# Delimiters are tuned for JSON/log strings. Unicode path components are allowed
# because the negated character class only excludes whitespace and common string
# punctuation.
_PATH_CHARS = r"[^\s\]})>'\",;`]+"
FILE_URI_RE = re.compile(rf"\bfile://(?:localhost)?(?P<path>/{_PATH_CHARS})", re.IGNORECASE)
ABSOLUTE_PATH_RE = re.compile(rf"(?<![A-Za-z0-9_:.~-])(?P<path>/{_PATH_CHARS})")


def path_aliases(value: str | Path | None) -> list[str]:
    """Return textual aliases for a local path without requiring it to exist."""
    if value is None:
        return []
    raw = str(value)
    if not raw:
        return []
    variants: set[str] = {raw}
    try:
        variants.add(str(Path(raw).expanduser().resolve(strict=False)))
    except Exception:  # noqa: BLE001 - best-effort redaction helper
        pass
    for candidate in list(variants):
        if candidate.startswith("/private/"):
            variants.add(candidate.removeprefix("/private"))
        elif candidate.startswith("/var/folders") or candidate.startswith("/tmp"):
            variants.add("/private" + candidate)
    return sorted((item for item in variants if item), key=len, reverse=True)


def local_path_root_marker(value: str) -> str:
    """Return the stable public marker for a local path or file URI."""
    text = value
    match = FILE_URI_RE.match(text)
    if match:
        text = match.group("path")
    lower = text.lower()
    for marker in LOCAL_PATH_ROOT_MARKERS:
        marker_lower = marker.lower()
        if lower == marker_lower or lower.startswith(marker_lower + "/"):
            return marker
    return "local"


def absolute_path_placeholder(value: str) -> str:
    marker = local_path_root_marker(value)
    return PATH_PLACEHOLDER_LOCAL if marker == "local" else f"<ABSOLUTE_PATH:{marker}>"


def file_uri_placeholder(value: str) -> str:
    marker = local_path_root_marker(value)
    return "<FILE_URI:local>" if marker == "local" else f"<FILE_URI:{marker}>"


def _is_url_path_match(text: str, start: int) -> bool:
    # Preserve URL path portions such as https://host/path. file:// URLs are
    # handled by FILE_URI_RE because their target is local.
    return start >= 2 and text[start - 2 : start] == ":/"


def _is_placeholder_relative_path(text: str, start: int) -> bool:
    """Return true for suffixes after redaction placeholders.

    Context-root replacement intentionally turns local absolute paths into
    shareable placeholder-relative paths such as ``<RWT_PROJECT>/ARDUR.md``.
    The subsequent generic absolute-path pass must not consume the ``/ARDUR.md``
    suffix as another host-local absolute path.
    """

    prefix = text[:start]
    return re.search(r"<[A-Z0-9_:/-]+>$", prefix) is not None


def replace_path_roots(text: str, pairs: Sequence[tuple[str, str]]) -> str:
    redacted = text
    for source, placeholder in pairs:
        if source:
            redacted = redacted.replace(source, placeholder)
    return redacted


def redact_local_path_text(
    text: str,
    *,
    root_pairs: Sequence[tuple[str, str]] = (),
    absolute_replacement: Callable[[str], str] = absolute_path_placeholder,
    file_uri_replacement: Callable[[str], str] = file_uri_placeholder,
) -> str:
    """Redact configured roots, file:// targets, and local absolute paths."""
    redacted = replace_path_roots(text, root_pairs)
    redacted = FILE_URI_RE.sub(lambda match: file_uri_replacement(match.group(0)), redacted)

    def replace_absolute(match: re.Match[str]) -> str:
        start = match.start("path")
        value = match.group("path")
        # Preserve URL path portions such as https://host/path. file:// URLs are
        # handled by FILE_URI_RE before this pass because their target is local.
        if _is_url_path_match(redacted, start) or _is_placeholder_relative_path(redacted, start):
            return value
        if value.startswith("//"):
            return value
        return absolute_replacement(value)

    return ABSOLUTE_PATH_RE.sub(replace_absolute, redacted)


def redact_local_paths(value: Any, *, root_pairs: Sequence[tuple[str, str]] = ()) -> Any:
    """Recursively redact local paths in shareable JSON-like values."""
    if isinstance(value, str):
        return redact_local_path_text(value, root_pairs=root_pairs)
    if isinstance(value, list):
        return [redact_local_paths(item, root_pairs=root_pairs) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_local_paths(item, root_pairs=root_pairs) for item in value)
    if isinstance(value, Mapping):
        return {key: redact_local_paths(item, root_pairs=root_pairs) for key, item in value.items()}
    return value


def local_path_leak_hits(text: str, *, extra_markers: Iterable[str] = ()) -> list[str]:
    """Return raw local path/file URI leak strings found in text."""
    hits: set[str] = set()
    for marker in (*LOCAL_PATH_LEAK_MARKERS, *tuple(extra_markers)):
        if marker and marker in text:
            hits.add(marker)
    for match in FILE_URI_RE.finditer(text):
        hits.add(match.group(0))
    for match in ABSOLUTE_PATH_RE.finditer(text):
        value = match.group("path")
        if (
            not value.startswith("//")
            and not _is_url_path_match(text, match.start("path"))
            and not _is_placeholder_relative_path(text, match.start("path"))
        ):
            hits.add(value)
    return sorted(hits, key=len, reverse=True)
