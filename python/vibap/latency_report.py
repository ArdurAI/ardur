"""Machine-readable latency evidence reports for Claude hook benchmark paths.

This module emits versioned JSON reports for the informational latency-bench
CI job (``.github/workflows/tests.yml`` job ``latency-bench``). The reports
replace pytest-stdout-only percentiles with a machine-readable artifact that
reviewers can independently recompute, compare across runner classes, and
audit for partial failures.

Design invariants
-----------------

1.  The raw ``samples_ms`` distribution is the source of truth. Reported
    median/p95/p99 must be exactly recomputable from it using the declared
    ``nearest_rank`` method.
2.  Sample validation is deterministic and fails closed: non-finite,
    negative, ``None``, duplicated, or out-of-order samples are rejected and
    recorded in the ``validation`` block rather than silently dropped.
3.  Metadata comes from an explicit environment-variable allowlist only.
    There is no ``os.environ`` dump, no token/passport/request/tool-arg
    capture, no absolute executable/socket/temp paths.
4.  Functional failures (warmup, native call, threshold assertion) are
    recorded as structured entries with stage + stable native exit/errno
    classification, never with request data, and are separate from the
    threshold result.
5.  Atomic writes via ``os.O_EXCL`` + ``os.replace`` with ``0o600`` perms,
    mirroring :mod:`vibap.policy_conformance`.
"""

from __future__ import annotations

import math
import os
import platform
import re
import statistics
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .canonical_json import canonical_json_bytes

#: Schema version for the persisted report. Bump when the JSON shape changes
#: in a way that breaks consumers; ``validation`` / ``runner_metadata`` field
#: additions within the same major version are non-breaking.
REPORT_SCHEMA_VERSION = "ardur.latency_report.v1.0"
PERCENTILE_METHOD = "nearest_rank"
#: Directory name used under ``$RUNNER_TEMP`` (or a fallback tmp parent) to
#: collect all latency reports for a single benchmark run.
DEFAULT_REPORT_DIR_NAME = "ardur-latency-reports"

#: Environment-variable allowlist for ``runner_metadata``. Keys not in this
#: set are never serialized, even if they would be convenient. This is the
#: sole source of runner metadata; do not extend it with anything that could
#: carry user identity, account, token, or host-path data.
_RUNNER_METADATA_ENV_ALLOWLIST: dict[str, str] = {
    "GITHUB_SHA": "source_sha",
    "GITHUB_EVENT_NAME": "event",
    "GITHUB_RUN_ID": "run_id",
    "GITHUB_RUN_ATTEMPT": "run_attempt",
    "RUNNER_OS": "runner_os",
    "RUNNER_ARCH": "runner_architecture",
    "ImageOS": "image_os",
    "ImageVersion": "image_version",
}

#: Stable symbolic classification for native client exit codes. Values that
#: are not in this table are recorded as ``"unclassified"`` so a future exit
#: code never silently rounds to a wrong bucket. See the native exit-code
#: contract in :mod:`vibap.claude_code_daemon` for the authoritative list.
_NATIVE_EXIT_STAGE: dict[int, str] = {
    2: "missing-socket-argument",
    3: "stdin-read",
    4: "stdin-read",
    5: "stdin-read",
    6: "socket-create",
    7: "socket-connect",
    8: "request-write",
    9: "response-read",
    10: "response-read",
    11: "response-read",
    12: "response-read",
    13: "malformed-envelope",
    14: "malformed-envelope",
    15: "malformed-envelope",
    16: "malformed-envelope",
    17: "malformed-envelope",
    18: "malformed-envelope",
    19: "stdout-write",
    20: "stdout-write",
    21: "setsockopt-rcvtimeo",
}

#: Diagnostic line shape emitted by the native client on stderr:
#: ``ardur-native: stage=<s> errno=<n> name=<sym> desc=<...>``. Used to
#: extract a stable errno classification without request data.
_NATIVE_DIAG_RE = re.compile(
    r"stage=(?P<stage>\S+)\s+errno=(?P<errno>-?\d+)\s+name=(?P<name>\S+)"
)

#: Redaction boundary for any free-form message field. We strip:
#:   * absolute POSIX paths (``/Users/...``, ``/tmp/...``, ``/home/...``)
#:   * Windows-style paths (``C:\\...``)
#:   * ``file://`` URIs
#:   * JWT-shaped tokens (three base64url segments)
#:   * bearer tokens
_PATH_RE = re.compile(r"(?:/Users|/tmp|/home|/private/var|/var|/opt|/usr|/etc)/[^\s'\"<>]+")
_WIN_PATH_RE = re.compile(r"\b[A-Z]:\\[^\s'\"<>]+")
_FILE_URI_RE = re.compile(r"file://[^\s'\"<>]+")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_BEARER_RE = re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-/+=]{8,}")


class LatencyReportError(ValueError):
    """Raised when a latency report cannot be built or validated.

    A ``ValueError`` subclass for generic-handler compatibility, distinct so
    callers can format a stable ``condition`` field.
    """


@dataclass(frozen=True)
class ValidatedSamples:
    """Outcome of :func:`validate_samples`.

    ``accepted`` is the validated, ordinality-preserving sample list. It is
    always a fresh list; mutating it does not affect the caller's input.
    ``rejected`` records each rejected sample's ordinal index, value, and
    reason so a reviewer can see exactly which samples were dropped and why.
    """

    accepted: list[float]
    rejected: list[dict[str, Any]] = field(default_factory=list)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)


@dataclass(frozen=True)
class FunctionalFailure:
    """A single functional failure recorded in a (possibly partial) report.

    ``stage`` identifies where in the benchmark path the failure happened
    (``warmup``, ``measured``, ``threshold``) and ``native_exit_code`` /
    ``native_errno_classification`` carry the stable native-client
    classification without request data. ``message`` is sanitized via
    :func:`_sanitize_message`.
    """

    stage: str
    message: str
    native_exit_code: int | None = None
    native_errno_classification: str | None = None
    native_stage: str | None = None


@dataclass(frozen=True)
class LatencyReport:
    """Versioned, machine-readable latency evidence report.

    Field order is stable for deterministic serialization via
    :func:`canonical_json_bytes`.
    """

    schema_version: str
    benchmark_name: str
    percentile_method: str
    created_at_epoch_s: float
    created_at_iso: str
    samples_ms: list[float]
    sample_count: int
    median_ms: float | None
    p95_ms: float | None
    p99_ms: float | None
    threshold_ms: float | None
    threshold_result: str
    functional_failures: list[dict[str, Any]]
    runner_metadata: dict[str, Any]
    validation: dict[str, Any]


def validate_samples(samples_ms: Any) -> ValidatedSamples:
    """Validate a raw sample distribution.

    Rejects, with a deterministic reason:

    * ``None`` (missing sample)
    * non-finite values (``NaN``, ``+inf``, ``-inf``)
    * negative values
    * non-numeric values that cannot be coerced to ``float``
    * duplicate adjacent samples (only exact-equality adjacency is rejected,
      to catch duplicated-feeding bugs while tolerating legitimate repeated
      timings)

    "Out-of-order" samples in the issue sense (samples that break the
    deterministic measurement sequence) are detected structurally by list
    position, not by value comparison: latency samples legitimately
    fluctuate (e.g. 2ms, 5ms, 2ms is a normal distribution, not a bug), so
    value-based monotonicity would corrupt real benchmark data. The
    ``ordinal`` field in each rejection record preserves the deterministic
    measurement index so a reviewer can see exactly where in the sequence a
    sample was dropped.

    Returns a :class:`ValidatedSamples` whose ``accepted`` list preserves the
    original ordinal order of the accepted samples.
    """

    if samples_ms is None:
        raise LatencyReportError("samples_ms must not be None")
    if isinstance(samples_ms, (str, bytes, bytearray)):
        raise LatencyReportError("samples_ms must be an iterable of numbers, not a string/bytes")
    try:
        iterable = list(samples_ms)
    except TypeError as exc:  # not iterable
        raise LatencyReportError("samples_ms must be iterable") from exc

    accepted: list[float] = []
    rejected: list[dict[str, Any]] = []
    for index, raw in enumerate(iterable):
        ordinal = index + 1
        if raw is None:
            rejected.append({"ordinal": ordinal, "value": None, "reason": "missing"})
            continue
        try:
            value = float(raw)
        except (TypeError, ValueError):
            rejected.append({"ordinal": ordinal, "value": str(raw)[:64], "reason": "non_numeric"})
            continue
        if not math.isfinite(value):
            rejected.append({"ordinal": ordinal, "value": str(raw)[:64], "reason": "non_finite"})
            continue
        if value < 0:
            rejected.append({"ordinal": ordinal, "value": value, "reason": "negative"})
            continue
        # Duplicate-adjacency check: an exact-equality repeat of the
        # immediately preceding accepted sample is a feeding-bug signal
        # (e.g. the same timestamp captured twice). Legitimate near-equal
        # timings differ in at least the last float bit.
        if accepted and value == accepted[-1]:
            rejected.append({"ordinal": ordinal, "value": value, "reason": "duplicate"})
            continue
        accepted.append(value)
    return ValidatedSamples(accepted=accepted, rejected=rejected)


def nearest_rank(values: list[float], percentile: int) -> float | None:
    """Nearest-rank percentile. Returns ``None`` for an empty distribution.

    Matches the percentile method documented in the test suite and the
    report's ``percentile_method`` field. 1-indexed rank:
    ``ceil(percentile/100 * n)``.
    """

    if not values:
        return None
    ordered = sorted(values)
    rank = math.ceil((percentile / 100) * len(ordered))
    index = min(max(rank - 1, 0), len(ordered) - 1)
    return ordered[index]


def collect_runner_metadata(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Collect runner metadata from an explicit env allowlist.

    ``env`` defaults to ``os.environ``. Only the keys in
    :data:`_RUNNER_METADATA_ENV_ALLOWLIST` are read. Values are coerced to
    ``str`` and stripped of any path-like content via
    :func:`_sanitize_message` as a defense-in-depth, although allowlisted
    values should never carry paths. Missing keys are emitted as ``None`` so
    the schema is explicit about absence rather than silently omitting it.
    """

    source = os.environ if env is None else env
    metadata: dict[str, Any] = {}
    for env_name, field_name in _RUNNER_METADATA_ENV_ALLOWLIST.items():
        raw = source.get(env_name)
        if raw is None:
            metadata[field_name] = None
        else:
            metadata[field_name] = _sanitize_message(str(raw))
    # Python implementation/version comes from the runtime, not the env.
    metadata["python_implementation"] = platform.python_implementation()
    metadata["python_version"] = platform.python_version()
    return metadata


def classify_native_exit(exit_code: int | None) -> tuple[str | None, str | None]:
    """Return ``(stage, errno_classification)`` for a native client exit code.

    ``errno_classification`` is the stable symbolic name (``EAGAIN``,
    ``ECONNRESET``, ...) when the diagnostic line is unavailable; otherwise
    it is the symbolic stage name. Returns ``(None, None)`` for unknown /
    non-native exit codes so callers never round a future code to a wrong
    bucket.
    """

    if exit_code is None:
        return None, None
    stage = _NATIVE_EXIT_STAGE.get(int(exit_code))
    if stage is None:
        return None, "unclassified"
    return stage, stage


def parse_native_diag(stderr_text: str | None) -> dict[str, Any] | None:
    """Extract a stable classification from a native diagnostic stderr line.

    Returns ``{"stage": ..., "errno": ..., "name": ...}`` or ``None``. Used
    by :func:`functional_failure_from_subprocess` to prefer the sanitized
    native diagnostic over raw stderr (which may contain request data on
    malformed envelopes).
    """

    if not stderr_text:
        return None
    match = _NATIVE_DIAG_RE.search(stderr_text)
    if match is None:
        return None
    return {
        "stage": match.group("stage"),
        "errno": int(match.group("errno")),
        "name": match.group("name"),
    }


def functional_failure_from_subprocess(
    *,
    stage: str,
    returncode: int | None,
    stderr_text: str | None,
) -> FunctionalFailure:
    """Build a :class:`FunctionalFailure` from a failed subprocess call.

    Prefers the sanitized native diagnostic line for errno classification.
    Falls back to the symbolic stage name from
    :func:`classify_native_exit`. The human-readable message is sanitized
    via :func:`_sanitize_message` and capped in length.
    """

    diag = parse_native_diag(stderr_text)
    native_stage: str | None = None
    native_errno_classification: str | None = None
    if diag is not None:
        native_stage = diag["stage"]
        native_errno_classification = diag["name"]
    else:
        stage_name, errno_class = classify_native_exit(returncode)
        native_stage = stage_name
        native_errno_classification = errno_class

    message_raw = _extract_native_diag_message(stderr_text) or f"subprocess exited returncode={returncode}"
    return FunctionalFailure(
        stage=stage,
        message=_sanitize_message(message_raw),
        native_exit_code=returncode,
        native_errno_classification=native_errno_classification,
        native_stage=native_stage,
    )


def build_report(
    *,
    benchmark_name: str,
    samples_ms: Any,
    threshold_ms: float | None,
    threshold_result: str,
    functional_failures: list[FunctionalFailure] | None = None,
    runner_metadata: dict[str, Any] | None = None,
    created_at_epoch_s: float | None = None,
) -> LatencyReport:
    """Build a validated :class:`LatencyReport`.

    ``threshold_result`` must be one of ``"pass"``, ``"fail"``,
    ``"telemetry_only"``. Functional failures are recorded as-is (already
    sanitized at construction time). The report's median/p95/p99 are derived
    from the *accepted* samples via :func:`nearest_rank`, so they are
    exactly recomputable from ``samples_ms`` by any reviewer.
    """

    if threshold_result not in {"pass", "fail", "telemetry_only"}:
        raise LatencyReportError(
            f"threshold_result must be pass/fail/telemetry_only, got {threshold_result!r}"
        )
    if not benchmark_name or not benchmark_name.strip():
        raise LatencyReportError("benchmark_name must not be empty")
    if runner_metadata is None:
        runner_metadata = collect_runner_metadata()

    validated = validate_samples(samples_ms)
    accepted = validated.accepted
    median_ms = statistics.median(accepted) if accepted else None
    p95_ms = nearest_rank(accepted, 95)
    p99_ms = nearest_rank(accepted, 99)

    failures_payload = [asdict(f) for f in (functional_failures or [])]
    validation_payload: dict[str, Any] = {
        "rejected_count": validated.rejected_count,
        "rejected": list(validated.rejected),
    }

    epoch = time.time() if created_at_epoch_s is None else float(created_at_epoch_s)
    # ISO 8601 UTC with ``Z`` suffix; ``time.gmtime`` + manual formatting keeps
    # this dependency-free and stable across platforms.
    iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))

    return LatencyReport(
        schema_version=REPORT_SCHEMA_VERSION,
        benchmark_name=benchmark_name,
        percentile_method=PERCENTILE_METHOD,
        created_at_epoch_s=epoch,
        created_at_iso=iso,
        samples_ms=list(accepted),
        sample_count=len(accepted),
        median_ms=median_ms,
        p95_ms=p95_ms,
        p99_ms=p99_ms,
        threshold_ms=float(threshold_ms) if threshold_ms is not None else None,
        threshold_result=threshold_result,
        functional_failures=failures_payload,
        runner_metadata=dict(runner_metadata),
        validation=validation_payload,
    )


def report_to_dict(report: LatencyReport) -> dict[str, Any]:
    """Serialize a :class:`LatencyReport` to a canonical dict.

    Field order is fixed for deterministic bytes (RFC 8785 canonicalization
    sorts keys, but explicit ordering here keeps the in-memory shape
    reviewer-friendly when pretty-printed).
    """

    return asdict(report)


def default_report_dir() -> Path:
    """Resolve the report output directory.

    Prefers ``$RUNNER_TEMP/ardur-latency-reports`` (GitHub Actions). Falls
    back to ``tempfile.gettempdir()/ardur-latency-reports`` for local runs.
    The directory is created with ``0o700`` if missing.
    """

    base = os.environ.get("RUNNER_TEMP")
    if base and base.strip():
        root = Path(base)
    else:
        import tempfile

        root = Path(tempfile.gettempdir())
    out = root / DEFAULT_REPORT_DIR_NAME
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(out, 0o700)
    except OSError:
        # Best-effort mode fix-up; the mkdir above already tried.
        pass
    return out


def write_report_atomic(
    report: LatencyReport,
    output_dir: Path | str | None = None,
) -> Path:
    """Atomically write ``report`` as canonical JSON and return its path.

    Filename is ``<benchmark_name>-<created_at_epoch_ns>.json`` to be
    deterministic within a run while avoiding collisions when the same
    benchmark name is written twice. Writes via ``os.O_EXCL`` + ``os.replace``
    with ``0o600`` perms, mirroring
    :func:`vibap.policy_conformance.write_policy_conformance_report`.

    ``output_dir`` defaults to :func:`default_report_dir`.
    """

    if output_dir is None:
        target_dir = default_report_dir()
    else:
        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(target_dir, 0o700)
        except OSError:  # noqa: BLE001 - best-effort chmod; dir may be on FS that doesn't support mode bits
            pass

    safe_name = _safe_filename_component(report.benchmark_name)
    epoch_ns = int(report.created_at_epoch_s * 1_000_000_000)
    filename = f"{safe_name}-{epoch_ns}.json"
    output = target_dir / filename
    temporary = output.with_name(f".{output.name}.{os.getpid()}.{time.time_ns()}.tmp")

    payload = canonical_json_bytes(report_to_dict(report)) + b"\n"
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            # Successful os.replace consumes the temp path.
            pass
    return output


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_filename_component(name: str) -> str:
    """Reduce ``benchmark_name`` to a filesystem-safe filename component."""

    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", name.strip())
    cleaned = cleaned.strip("-._")
    if not cleaned:
        cleaned = "benchmark"
    return cleaned[:64]


def _sanitize_message(text: str | None) -> str:
    """Redact path/token/bearer content from a free-form message.

    Replaces matches with stable placeholders. Truncates to 256 chars to keep
    reports bounded. Never used on structured fields, only on human-readable
    message text that may originate from stderr.
    """

    if not text:
        return ""
    redacted = _BEARER_RE.sub("<bearer>", text)
    redacted = _JWT_RE.sub("<jwt>", redacted)
    redacted = _FILE_URI_RE.sub("<file-uri>", redacted)
    redacted = _WIN_PATH_RE.sub("<path>", redacted)
    redacted = _PATH_RE.sub("<path>", redacted)
    if len(redacted) > 256:
        redacted = redacted[:253] + "..."
    return redacted


def _extract_native_diag_message(stderr_text: str | None) -> str | None:
    """Pull the first ``ardur-native: ...`` diagnostic line from stderr.

    The native client emits sanitized diagnostics on stderr; we keep only
    that line and discard any surrounding noise (e.g. shell wrapper output).
    """

    if not stderr_text:
        return None
    for line in stderr_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("ardur-native:"):
            return stripped
    return None


__all__ = [
    "REPORT_SCHEMA_VERSION",
    "PERCENTILE_METHOD",
    "DEFAULT_REPORT_DIR_NAME",
    "LatencyReportError",
    "ValidatedSamples",
    "FunctionalFailure",
    "LatencyReport",
    "validate_samples",
    "nearest_rank",
    "collect_runner_metadata",
    "classify_native_exit",
    "parse_native_diag",
    "functional_failure_from_subprocess",
    "build_report",
    "report_to_dict",
    "default_report_dir",
    "write_report_atomic",
]
