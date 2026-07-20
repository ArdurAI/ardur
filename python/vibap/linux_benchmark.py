"""Repeatable Linux governance-overhead benchmarks with bounded reports."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import math
import os
import platform
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time
import tracemalloc
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric import ec
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from ._specs import linux_governance_benchmark_report_v01_schema
from .backends.native import NativeBackend
from .canonical_json import canonical_json_bytes
from .offline_verification import verify_offline_path
from .passport import MissionPassport, generate_keypair, issue_passport
from .proxy import Decision, GovernanceProxy, PolicyEvent
from .receipt import build_receipt, sign_receipt, verify_receipt
from .runtime_evidence import (
    EVENT_SCHEMA_VERSION,
    RuntimeEvidenceError,
    SOURCE_ASSURANCE,
    correlate_verified_report,
    load_runtime_events,
    write_report,
)

REPORT_SCHEMA_VERSION = "ardur.linux_governance_benchmark_report.v0.1"
SENSOR_SCHEMA_VERSION = "ardur.sensor_pair.v0.1"
MAX_SENSOR_CONFIG_BYTES = 64 * 1024
MAX_ARGV_ITEMS = 64
MAX_ARG_BYTES = 4096
MAX_ARGV_BYTES = 32 * 1024
MAX_SCHEMA_ERROR_DETAILS = 5
MAX_SCHEMA_ERROR_PATH_CHARS = 192
MAX_SCHEMA_ERROR_TEXT_CHARS = 512

LIMITATIONS = (
    "Smoke mode verifies report shape and execution only; it is not performance evidence.",
    "Host-specific measurements do not establish a universal governance-overhead percentage.",
    "Imported evidence processing measures normalization and correlation, not live sensor capture overhead.",
    "Live sensor overhead is measured only when an operator supplies an explicit paired-command configuration.",
    "Process CPU comes from getrusage and Linux RSS from procfs; neither is portable heap accounting.",
    "This harness does not close observability-gap issue 39 or prove complete kernel-event capture.",
    "No model, API, network, or cloud-provider latency is included in governance-only measurements.",
)


class BenchmarkError(ValueError):
    """A benchmark request violates the bounded execution contract."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class BenchmarkConfig:
    """Bounded workload settings for one benchmark run."""

    mode: str
    warmup_count: int
    sample_count: int
    sustained_operations: int
    evidence_event_count: int
    policy_rule_counts: tuple[int, ...]

    @classmethod
    def profile(cls, mode: str) -> "BenchmarkConfig":
        if mode == "smoke":
            return cls("smoke", 2, 9, 25, 3, (1, 16, 64))
        if mode == "stress":
            return cls("stress", 10, 100, 1000, 100, (1, 16, 64, 256))
        raise BenchmarkError("mode_invalid", "mode must be smoke or stress")

    def validated(self, *, enforce_profile_floor: bool = True) -> "BenchmarkConfig":
        bounds = (
            ("warmup_count", self.warmup_count, 0, 1000),
            ("sample_count", self.sample_count, 1, 10000),
            ("sustained_operations", self.sustained_operations, 1, 100000),
            ("evidence_event_count", self.evidence_event_count, 1, 10000),
        )
        for name, value, minimum, maximum in bounds:
            if isinstance(value, bool) or not isinstance(value, int):
                raise BenchmarkError("config_invalid", f"{name} must be an integer")
            if not minimum <= value <= maximum:
                raise BenchmarkError(
                    "config_out_of_bounds",
                    f"{name} must be between {minimum} and {maximum}",
                )
        if self.mode not in {"smoke", "stress"}:
            raise BenchmarkError("mode_invalid", "mode must be smoke or stress")
        if enforce_profile_floor and self.mode == "stress" and self.sample_count < 100:
            raise BenchmarkError(
                "stress_samples_too_small", "stress mode requires at least 100 samples"
            )
        if not self.policy_rule_counts or len(self.policy_rule_counts) > 8:
            raise BenchmarkError(
                "policy_rules_invalid",
                "policy rule counts must contain one to eight values",
            )
        if len(set(self.policy_rule_counts)) != len(self.policy_rule_counts):
            raise BenchmarkError(
                "policy_rules_invalid", "policy rule counts must be unique"
            )
        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= 4096
            for value in self.policy_rule_counts
        ):
            raise BenchmarkError(
                "policy_rules_invalid",
                "policy rule counts must be integers from 1 to 4096",
            )
        return self

    def to_report(self) -> dict[str, Any]:
        return {
            "warmup_count": self.warmup_count,
            "sample_count": self.sample_count,
            "sustained_operations": self.sustained_operations,
            "evidence_event_count": self.evidence_event_count,
            "policy_rule_counts": list(self.policy_rule_counts),
        }


@dataclass(frozen=True)
class SensorPairConfig:
    baseline_argv: tuple[str, ...]
    instrumented_argv: tuple[str, ...]
    repetitions: int
    timeout_seconds: int


def _finite_rounded(value: float, *, digits: int = 6) -> float:
    if not math.isfinite(value):
        raise BenchmarkError("measurement_nonfinite", "measurement was not finite")
    return round(float(value), digits)


def nearest_rank(values: Sequence[float], percentile: int) -> float:
    """Return the nearest-rank percentile for a non-empty finite sample."""

    if not values:
        raise BenchmarkError("sample_empty", "measurement sample must not be empty")
    if percentile < 1 or percentile > 100:
        raise BenchmarkError("percentile_invalid", "percentile must be from 1 to 100")
    ordered = sorted(float(value) for value in values)
    if not all(math.isfinite(value) for value in ordered):
        raise BenchmarkError("sample_nonfinite", "measurement sample must be finite")
    rank = math.ceil((percentile / 100.0) * len(ordered))
    return ordered[rank - 1]


def _distribution(values: Sequence[float], unit: str) -> dict[str, Any]:
    ordered = [float(value) for value in values]
    return {
        "unit": unit,
        "sample_count": len(ordered),
        "p50": _finite_rounded(nearest_rank(ordered, 50)),
        "p95": _finite_rounded(nearest_rank(ordered, 95)),
        "p99": _finite_rounded(nearest_rank(ordered, 99)),
        "min": _finite_rounded(min(ordered)),
        "max": _finite_rounded(max(ordered)),
        "mean": _finite_rounded(sum(ordered) / len(ordered)),
    }


def _measure(operation: Callable[[], Any], config: BenchmarkConfig) -> list[float]:
    for _ in range(config.warmup_count):
        operation()
    samples: list[float] = []
    for _ in range(config.sample_count):
        started = time.perf_counter_ns()
        operation()
        samples.append((time.perf_counter_ns() - started) / 1000.0)
    return samples


def _metric(
    name: str,
    measurement_class: str,
    methodology: str,
    values: Sequence[float],
    warmup_count: int,
    notes: Sequence[str],
) -> dict[str, Any]:
    mean_us = sum(values) / len(values)
    if mean_us <= 0:
        raise BenchmarkError(
            "measurement_nonpositive", "measurement duration was not positive"
        )
    return {
        "name": name,
        "measurement_class": measurement_class,
        "methodology": methodology,
        "warmup_count": warmup_count,
        "latency": _distribution(values, "microseconds"),
        "throughput_ops_per_second": _finite_rounded(1_000_000.0 / mean_us),
        "notes": list(notes),
    }


def _native_operation(*, allow: bool, rule_count: int = 1) -> Callable[[], None]:
    backend = NativeBackend()
    target = "benchmark_target"
    filler = [f"rule_{index:04d}" for index in range(max(0, rule_count - 1))]
    passport = {
        "allowed_tools": [*filler, target] if allow else [*filler, "allowed_target"],
        "forbidden_tools": [target] if not allow else [],
        "resource_scope": [],
        "max_tool_calls": 1_000_000,
        "max_duration_s": 86400,
    }
    context = {
        "passport": passport,
        "session": {"tool_call_count": 0, "elapsed_s": 0.0},
    }
    expected = "Allow" if allow else "Deny"

    def operation() -> None:
        decision = backend.evaluate(
            tool_name=target,
            arguments={"value": 1},
            principal="benchmark-agent",
            target=target,
            context=context,
            policy_spec={},
        )
        if decision.decision != expected:
            raise BenchmarkError(
                "native_decision_unexpected", "native policy result changed"
            )

    return operation


def _new_proxy(root: Path, max_calls: int) -> tuple[GovernanceProxy, Any]:
    keys_dir = root / "keys"
    private_key, public_key = generate_keypair(keys_dir=keys_dir)
    proxy = GovernanceProxy(
        log_path=root / "governance.jsonl",
        receipts_log_path=root / "receipts.jsonl",
        state_dir=root / "state",
        keys_dir=keys_dir,
        public_key=public_key,
        private_key=private_key,
    )
    mission = MissionPassport(
        agent_id="linux-governance-benchmark",
        mission="measure local governance overhead",
        allowed_tools=["benchmark_permit"],
        forbidden_tools=["benchmark_deny"],
        resource_scope=[],
        max_tool_calls=max_calls,
        max_duration_s=86400,
        delegation_allowed=False,
    )
    token = issue_passport(mission, private_key, ttl_s=86400)
    return proxy, proxy.start_session(token)


def _proxy_operation(
    proxy: GovernanceProxy, session: Any, *, allow: bool
) -> Callable[[], None]:
    expected = Decision.PERMIT if allow else Decision.DENY
    tool = "benchmark_permit" if allow else "benchmark_deny"

    def operation() -> None:
        decision, _reason = proxy.evaluate_tool_call(session, tool, {"value": 1})
        if decision != expected:
            raise BenchmarkError(
                "proxy_decision_unexpected", "governance proxy result changed"
            )

    return operation


def _receipt_fixture() -> tuple[Any, ec.EllipticCurvePrivateKey, str, dict[str, Any]]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    event = PolicyEvent(
        timestamp=timestamp,
        step_id="step:linux-benchmark:1",
        actor="spiffe://ardur.local/benchmark-agent",
        verifier_id="spiffe://ardur.local/governance-proxy",
        tool_name="benchmark_permit",
        arguments={"value": 1},
        action_class="execute",
        target="benchmark_target",
        resource_family="benchmark",
        side_effect_class="process_launch",
        decision=Decision.PERMIT,
        reason="allowed by benchmark policy",
        passport_jti="grant:linux-benchmark",
        trace_id="trace:linux-benchmark",
        run_nonce="linux_benchmark_nonce_0123456789",
    )
    receipt = build_receipt(
        Decision.PERMIT,
        event,
        policy_decisions=[
            {"backend": "native", "decision": "Allow", "reason": event.reason}
        ],
        budget_remaining={"tool_calls": 9999},
    )
    token = sign_receipt(receipt, private_key)
    claims = verify_receipt(token, private_key.public_key())
    return receipt, private_key, token, claims


def _journal_operation(path: Path, line: bytes, *, durable: bool) -> Callable[[], None]:
    def operation() -> None:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            remaining = memoryview(line)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise BenchmarkError(
                        "journal_write_failed", "journal append made no progress"
                    )
                remaining = remaining[written:]
            if durable:
                os.fsync(fd)
        finally:
            os.close(fd)

    return operation


def _governance_metrics(config: BenchmarkConfig, root: Path) -> list[dict[str, Any]]:
    metrics: list[dict[str, Any]] = []
    common_native_notes = [
        "In-process native policy path; excludes proxy persistence and receipt generation."
    ]
    for name, operation in (
        ("native_policy_permit", _native_operation(allow=True)),
        ("native_policy_deny", _native_operation(allow=False)),
    ):
        metrics.append(
            _metric(
                name,
                "governance_only",
                "NativeBackend.evaluate measured with time.perf_counter_ns after warmup.",
                _measure(operation, config),
                config.warmup_count,
                common_native_notes,
            )
        )

    for rule_count in config.policy_rule_counts:
        values = _measure(_native_operation(allow=True, rule_count=rule_count), config)
        metrics.append(
            _metric(
                f"native_policy_rules_{rule_count}",
                "governance_only",
                "Native allow-list evaluation with the permitted tool in the final list position.",
                values,
                config.warmup_count,
                [f"Synthetic policy list contains {rule_count} entries."],
            )
        )

    for name, allow in (
        ("proxy_permit_end_to_end", True),
        ("proxy_deny_end_to_end", False),
    ):
        proxy, session = _new_proxy(
            root / name,
            config.warmup_count + config.sample_count + 100,
        )
        metrics.append(
            _metric(
                name,
                "governance_only",
                "GovernanceProxy.evaluate_tool_call including state persistence, signed receipt, and local logs.",
                _measure(_proxy_operation(proxy, session, allow=allow), config),
                config.warmup_count,
                [
                    "Each decision arm uses an independent session with identical sample history.",
                    "Local anchor queueing is best effort and remains inside the measured production call.",
                ],
            )
        )

    receipt, private_key, token, _claims = _receipt_fixture()
    metrics.append(
        _metric(
            "receipt_sign_es256",
            "governance_only",
            "RFC 8785 receipt payload signing with ES256 using the production signer.",
            _measure(lambda: sign_receipt(receipt, private_key), config),
            config.warmup_count,
            ["Key generation and receipt construction are outside the timed region."],
        )
    )
    metrics.append(
        _metric(
            "receipt_verify_es256",
            "governance_only",
            "Production receipt signature and claim verification with replay cache disabled.",
            _measure(lambda: verify_receipt(token, private_key.public_key()), config),
            config.warmup_count,
            ["Token parsing and canonical-payload validation are included."],
        )
    )

    line = canonical_json_bytes({"jwt": token}) + b"\n"
    for name, durable in (
        ("journal_append_buffered", False),
        ("journal_append_fsync", True),
    ):
        metrics.append(
            _metric(
                name,
                "governance_only",
                "Open, append one bounded JSONL record, and close; fsync is included only in the named fsync arm.",
                _measure(
                    _journal_operation(root / f"{name}.jsonl", line, durable=durable),
                    config,
                ),
                config.warmup_count,
                [
                    "The production proxy currently uses buffered append without explicit fsync."
                    if not durable
                    else "This comparative arm adds fsync and is not the current proxy default."
                ],
            )
        )
    return metrics


def _normalized_event(receipt_id: str, timestamp: str, index: int) -> dict[str, Any]:
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": f"benchmark-event-{index}",
        "source": {
            "kind": "normalized",
            "format": "ardur-linux-benchmark.v0.1",
            "instance_id": "benchmark-instance",
            "assurance": SOURCE_ASSURANCE,
            "coverage": "degraded",
        },
        "event_type": "process_start",
        "observed_at": timestamp,
        "process": {"pid": 1000 + index, "ppid": 1},
        "correlation": {
            "receipt_id": receipt_id,
            "trace_id": "trace:linux-benchmark",
            "actor": "spiffe://ardur.local/benchmark-agent",
        },
        "details": {"operation": "benchmark"},
    }


def _imported_evidence_metric(config: BenchmarkConfig, root: Path) -> dict[str, Any]:
    _receipt, private_key, token, claims = _receipt_fixture()
    journal = root / "verified-receipt.jsonl"
    journal.write_text(
        json.dumps({"jwt": token}, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    verified_report = verify_offline_path(
        journal,
        receipt_public_key=private_key.public_key(),
        chain_only=True,
        redact=False,
        include_correlation_fields=True,
    )
    if (
        verified_report.get("valid") is not True
        or claims["receipt_id"] != verified_report["timeline"][0]["receipt_id"]
    ):
        raise BenchmarkError(
            "receipt_verification_failed", "evidence fixture did not verify"
        )

    event_path = root / "events.jsonl"
    with event_path.open("w", encoding="utf-8") as handle:
        for index in range(config.evidence_event_count):
            handle.write(
                json.dumps(
                    _normalized_event(claims["receipt_id"], claims["timestamp"], index),
                    separators=(",", ":"),
                )
                + "\n"
            )

    def operation() -> None:
        batch = load_runtime_events(event_path, source_format="normalized")
        correlate_verified_report(verified_report, batch)

    return _metric(
        "imported_evidence_normalize_and_correlate",
        "imported_evidence_processing",
        "Load bounded normalized JSONL and correlate it with one pre-verified signed receipt report.",
        _measure(operation, config),
        config.warmup_count,
        [
            f"Each sample imports {config.evidence_event_count} events.",
            "Receipt verification and fixture creation are outside the timed region.",
            "This does not measure live kernel sensor capture.",
        ],
    )


def _proc_status_kib(field: str) -> int | None:
    if platform.system() != "Linux":
        return None
    try:
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            if line.startswith(field + ":"):
                parts = line.split()
                if len(parts) == 3 and parts[2] == "kB":
                    return int(parts[1])
    except (OSError, ValueError):
        return None
    return None


def _sustained_measurement(config: BenchmarkConfig, root: Path) -> dict[str, Any]:
    proxy, session = _new_proxy(root / "sustained", config.sustained_operations + 100)
    operation = _proxy_operation(proxy, session, allow=True)
    rss_start = _proc_status_kib("VmRSS")
    before = resource.getrusage(resource.RUSAGE_SELF)
    started = time.perf_counter()
    for _ in range(config.sustained_operations):
        operation()
    wall_seconds = time.perf_counter() - started
    after = resource.getrusage(resource.RUSAGE_SELF)
    rss_end = _proc_status_kib("VmRSS")
    rss_hwm = _proc_status_kib("VmHWM")

    heap_proxy, heap_session = _new_proxy(
        root / "sustained-heap", config.sustained_operations + 100
    )
    heap_operation = _proxy_operation(heap_proxy, heap_session, allow=True)
    tracemalloc.start()
    try:
        for _ in range(config.sustained_operations):
            heap_operation()
        _heap_current, heap_peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    user_cpu = after.ru_utime - before.ru_utime
    system_cpu = after.ru_stime - before.ru_stime
    cpu_percent = ((user_cpu + system_cpu) / wall_seconds) * 100.0
    return {
        "name": "sustained_proxy_permit_end_to_end",
        "methodology": "One uninstrumented production-proxy pass measures wall, CPU, throughput, and Linux procfs RSS; a second equal-operation pass measures Python heap under tracemalloc.",
        "operation_count": config.sustained_operations,
        "wall_seconds": _finite_rounded(wall_seconds),
        "user_cpu_seconds": _finite_rounded(user_cpu),
        "system_cpu_seconds": _finite_rounded(system_cpu),
        "cpu_utilization_percent": _finite_rounded(cpu_percent),
        "throughput_ops_per_second": _finite_rounded(
            config.sustained_operations / wall_seconds
        ),
        "python_heap_peak_bytes": heap_peak,
        "linux_rss_start_kib": rss_start,
        "linux_rss_end_kib": rss_end,
        "linux_rss_hwm_kib": rss_hwm,
        "notes": [
            "Python allocator peak excludes native allocations and child processes.",
            "Heap peak uses a separate equal-size pass so tracemalloc overhead does not contaminate reported throughput or CPU.",
            "VmRSS and VmHWM are Linux procfs observations and remain null off Linux.",
            "The process may retain allocations from earlier benchmark phases.",
        ],
    }


def _strict_json_object(raw: str) -> dict[str, Any]:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BenchmarkError(
                    "sensor_config_duplicate_key",
                    "sensor config contains a duplicate key",
                )
            result[key] = value
        return result

    def reject_nonfinite(_value: str) -> None:
        raise BenchmarkError(
            "sensor_config_nonfinite",
            "sensor config contains a non-finite number",
        )

    try:
        value = json.loads(
            raw,
            object_pairs_hook=object_pairs,
            parse_constant=reject_nonfinite,
        )
    except BenchmarkError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise BenchmarkError(
            "sensor_config_invalid_json", "sensor config must be strict UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise BenchmarkError(
            "sensor_config_not_object", "sensor config must be a JSON object"
        )
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > 8:
            raise BenchmarkError(
                "sensor_config_too_deep",
                "sensor config exceeds the structure depth limit",
            )
        if nodes > 2048:
            raise BenchmarkError(
                "sensor_config_too_complex",
                "sensor config exceeds the structure node limit",
            )
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return value


def _validated_argv(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ARGV_ITEMS:
        raise BenchmarkError(
            "sensor_argv_invalid", f"{label} must be a non-empty argv array"
        )
    argv: list[str] = []
    total = 0
    for item in value:
        if not isinstance(item, str) or not item or "\x00" in item:
            raise BenchmarkError(
                "sensor_argv_invalid", f"{label} entries must be non-empty strings"
            )
        encoded = item.encode("utf-8")
        if len(encoded) > MAX_ARG_BYTES:
            raise BenchmarkError(
                "sensor_argv_invalid", f"{label} contains an oversized argument"
            )
        total += len(encoded)
        argv.append(item)
    if total > MAX_ARGV_BYTES:
        raise BenchmarkError(
            "sensor_argv_invalid", f"{label} exceeds the total byte limit"
        )
    return tuple(argv)


def load_sensor_pair_config(path: str | Path) -> SensorPairConfig:
    config_path = Path(path).expanduser()
    descriptor = -1
    try:
        descriptor = os.open(
            config_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        info = os.fstat(descriptor)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise BenchmarkError(
                "sensor_config_not_regular",
                "sensor config must be a non-symlink regular file",
            ) from exc
        raise BenchmarkError(
            "sensor_config_unreadable", "sensor config is not a readable regular file"
        ) from exc
    try:
        if not stat.S_ISREG(info.st_mode):
            raise BenchmarkError(
                "sensor_config_not_regular",
                "sensor config must be a non-symlink regular file",
            )
        if info.st_size > MAX_SENSOR_CONFIG_BYTES:
            raise BenchmarkError(
                "sensor_config_too_large", "sensor config exceeds the byte limit"
            )
        collected = bytearray()
        while len(collected) <= MAX_SENSOR_CONFIG_BYTES:
            chunk = os.read(
                descriptor,
                min(65536, MAX_SENSOR_CONFIG_BYTES + 1 - len(collected)),
            )
            if not chunk:
                break
            collected.extend(chunk)
        raw_bytes = bytes(collected)
        if len(raw_bytes) > MAX_SENSOR_CONFIG_BYTES:
            raise BenchmarkError(
                "sensor_config_too_large", "sensor config exceeds the byte limit"
            )
        try:
            raw = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BenchmarkError(
                "sensor_config_unreadable", "sensor config must be readable UTF-8"
            ) from exc
    except OSError as exc:
        raise BenchmarkError(
            "sensor_config_unreadable", "sensor config must be readable UTF-8"
        ) from exc
    finally:
        os.close(descriptor)
    value = _strict_json_object(raw)
    expected = {
        "schema_version",
        "baseline_argv",
        "instrumented_argv",
        "repetitions",
        "timeout_seconds",
    }
    if set(value) != expected:
        raise BenchmarkError(
            "sensor_config_fields",
            "sensor config fields do not match the closed contract",
        )
    if value["schema_version"] != SENSOR_SCHEMA_VERSION:
        raise BenchmarkError(
            "sensor_config_version", "sensor config schema version is unsupported"
        )
    repetitions = value["repetitions"]
    timeout_seconds = value["timeout_seconds"]
    if (
        isinstance(repetitions, bool)
        or not isinstance(repetitions, int)
        or not 3 <= repetitions <= 100
    ):
        raise BenchmarkError(
            "sensor_repetitions_invalid",
            "sensor repetitions must be an integer from 3 to 100",
        )
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 1 <= timeout_seconds <= 3600
    ):
        raise BenchmarkError(
            "sensor_timeout_invalid",
            "sensor timeout must be an integer from 1 to 3600 seconds",
        )
    return SensorPairConfig(
        _validated_argv(value["baseline_argv"], "baseline_argv"),
        _validated_argv(value["instrumented_argv"], "instrumented_argv"),
        repetitions,
        timeout_seconds,
    )


def _argv_digest(argv: Sequence[str]) -> str:
    return hashlib.sha256(canonical_json_bytes(list(argv))).hexdigest()


def _run_sensor_command(
    argv: Sequence[str], timeout_seconds: int, working_directory: Path
) -> float:
    child_environment = {
        "HOME": str(working_directory),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", os.defpath),
        "TMPDIR": str(working_directory),
    }
    started = time.perf_counter_ns()
    try:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            cwd=working_directory,
            env=child_environment,
            start_new_session=True,
        )
    except OSError as exc:
        raise BenchmarkError(
            "sensor_command_failed", "a paired sensor command could not start"
        ) from exc
    try:
        try:
            return_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            raise BenchmarkError(
                "sensor_command_timeout", "a paired sensor command timed out"
            ) from exc
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    if return_code != 0:
        raise BenchmarkError(
            "sensor_command_nonzero", "a paired sensor command returned non-zero"
        )
    return (time.perf_counter_ns() - started) / 1000.0


def _sensor_measurement(config: SensorPairConfig | None) -> dict[str, Any]:
    notes = [
        "Commands are operator-supplied argv arrays executed without a shell.",
        "Commands use a private working directory and minimal environment; child output is discarded.",
    ]
    if config is None:
        return {
            "status": "not_measured",
            "methodology": "operator_supplied_shell_free_paired_commands",
            "reason": "no_sensor_pair_config_supplied",
            "repetitions": 0,
            "baseline_command_sha256": None,
            "instrumented_command_sha256": None,
            "baseline_latency": None,
            "instrumented_latency": None,
            "overhead_percent": None,
            "notes": notes,
        }
    baseline: list[float] = []
    instrumented: list[float] = []
    overhead: list[float] = []
    with tempfile.TemporaryDirectory(prefix="ardur-sensor-pair-") as temporary:
        working_directory = Path(temporary)
        for index in range(config.repetitions):
            if index % 2 == 0:
                baseline_value = _run_sensor_command(
                    config.baseline_argv, config.timeout_seconds, working_directory
                )
                instrumented_value = _run_sensor_command(
                    config.instrumented_argv,
                    config.timeout_seconds,
                    working_directory,
                )
            else:
                instrumented_value = _run_sensor_command(
                    config.instrumented_argv,
                    config.timeout_seconds,
                    working_directory,
                )
                baseline_value = _run_sensor_command(
                    config.baseline_argv, config.timeout_seconds, working_directory
                )
            baseline.append(baseline_value)
            instrumented.append(instrumented_value)
            overhead.append(
                ((instrumented_value - baseline_value) / baseline_value) * 100.0
            )
    return {
        "status": "measured",
        "methodology": "operator_supplied_shell_free_paired_commands",
        "reason": "operator_supplied_pair_completed",
        "repetitions": config.repetitions,
        "baseline_command_sha256": _argv_digest(config.baseline_argv),
        "instrumented_command_sha256": _argv_digest(config.instrumented_argv),
        "baseline_latency": _distribution(baseline, "microseconds"),
        "instrumented_latency": _distribution(instrumented, "microseconds"),
        "overhead_percent": _distribution(overhead, "percent"),
        "notes": [*notes, "Pair order alternates AB then BA to reduce ordering bias."],
    }


def _cpu_model() -> str:
    if platform.system() == "Linux":
        try:
            for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
                if line.lower().startswith("model name"):
                    value = line.partition(":")[2].strip()
                    if value:
                        return _host_text(value)
        except OSError:
            pass
    return _host_text(platform.processor())


def _host_text(value: object) -> str:
    collapsed = " ".join(str(value or "unknown").split())
    printable = "".join(
        "'"
        if character == "`"
        else character
        if 0x20 <= ord(character) <= 0x7E
        else "?"
        for character in collapsed
    )
    return printable[:256] or "unknown"


def _environment(*, allow_non_linux: bool) -> dict[str, Any]:
    system = platform.system()
    is_linux = system == "Linux"
    if not is_linux and not allow_non_linux:
        raise BenchmarkError(
            "linux_required", "benchmark requires Linux unless --allow-non-linux is set"
        )
    return {
        "os": _host_text(system),
        "architecture": _host_text(platform.machine()),
        "kernel_release": _host_text(platform.release()),
        "python_version": _host_text(platform.python_version()),
        "cpu_count": os.cpu_count() or 1,
        "cpu_model": _cpu_model(),
        "clock": "time.perf_counter_ns",
        "claim_eligible": is_linux,
        "claim_status": "eligible_linux_host" if is_linux else "non_linux_smoke_only",
    }


def _validate_source_ref(source_ref: str) -> str:
    if source_ref == "unknown":
        return source_ref
    if 7 <= len(source_ref) <= 64 and all(
        character in "0123456789abcdef" for character in source_ref.lower()
    ):
        return source_ref.lower()
    raise BenchmarkError(
        "source_ref_invalid",
        "source ref must be unknown or a 7-to-64 character hexadecimal revision",
    )


def _schema_error_token(value: object, *, fallback: str) -> str:
    if not isinstance(value, str):
        return fallback
    token = "".join(
        character
        if character.isascii() and (character.isalnum() or character in "_-")
        else "?"
        for character in value[:64]
    )
    return token or fallback


def _schema_error_path(error: ValidationError) -> str:
    parts = ["$"]
    for component in error.absolute_path:
        if isinstance(component, bool):
            parts.append("[?]")
        elif isinstance(component, int):
            parts.append(f"[{component}]")
        elif isinstance(component, str):
            parts.append(f".{_schema_error_token(component, fallback='?')}")
        else:
            parts.append(".?")
    path = "".join(parts)
    if len(path) > MAX_SCHEMA_ERROR_PATH_CHARS:
        return path[: MAX_SCHEMA_ERROR_PATH_CHARS - 3] + "..."
    return path


def _schema_error_sort_key(error: ValidationError) -> tuple[str, str, tuple[str, ...]]:
    return (
        _schema_error_path(error),
        _schema_error_token(error.validator, fallback="unknown"),
        tuple(str(component) for component in error.absolute_schema_path),
    )


def _schema_failure_detail(errors: Sequence[ValidationError]) -> str:
    seen_details: set[str] = set()
    details: list[str] = []
    for error in errors:
        rule = _schema_error_token(error.validator, fallback="unknown")
        detail = f"{_schema_error_path(error)} [{rule}]"
        if detail in seen_details:
            continue
        seen_details.add(detail)
        if len(details) < MAX_SCHEMA_ERROR_DETAILS:
            details.append(detail)

    omitted = len(seen_details) - len(details)
    summary = "generated report violated its JSON Schema: " + "; ".join(details)
    suffix = ""
    if omitted > 0:
        suffix = f"; +{omitted} more"
    if len(summary) + len(suffix) <= MAX_SCHEMA_ERROR_TEXT_CHARS:
        return summary + suffix
    body_limit = MAX_SCHEMA_ERROR_TEXT_CHARS - len(suffix)
    return summary[: body_limit - 3] + "..." + suffix


def validate_report(report: Mapping[str, Any]) -> None:
    validator = Draft202012Validator(
        linux_governance_benchmark_report_v01_schema(),
        format_checker=FormatChecker(),
    )
    errors = sorted(validator.iter_errors(report), key=_schema_error_sort_key)
    if errors:
        raise BenchmarkError("report_schema_invalid", _schema_failure_detail(errors))


def run_benchmark(
    config: BenchmarkConfig,
    *,
    source_ref: str = "unknown",
    allow_non_linux: bool = False,
    sensor_config: SensorPairConfig | None = None,
) -> dict[str, Any]:
    config.validated()
    environment = _environment(allow_non_linux=allow_non_linux)
    validated_source_ref = _validate_source_ref(source_ref)
    if config.mode == "stress" and validated_source_ref == "unknown":
        raise BenchmarkError(
            "stress_source_ref_required",
            "stress mode requires a hexadecimal source revision",
        )
    if sensor_config is not None and (
        config.mode != "stress" or environment["claim_eligible"] is not True
    ):
        raise BenchmarkError(
            "sensor_mode_invalid",
            "paired sensor measurement requires stress mode on Linux",
        )
    with tempfile.TemporaryDirectory(prefix="ardur-linux-benchmark-") as temporary:
        root = Path(temporary)
        report = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "mode": config.mode,
            "generated_at": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "source_ref": validated_source_ref,
            "environment": environment,
            "config": config.to_report(),
            "governance_only": _governance_metrics(config, root),
            "imported_evidence_processing": [_imported_evidence_metric(config, root)],
            "sustained_governance": _sustained_measurement(config, root),
            "optional_runtime_sensor": _sensor_measurement(sensor_config),
            "limitations": list(LIMITATIONS),
        }
    validate_report(report)
    return report


def render_markdown(report: Mapping[str, Any]) -> str:
    validate_report(report)
    environment = report["environment"]
    lines = [
        "# Ardur Linux Governance Benchmark",
        "",
        f"- Schema: `{report['schema_version']}`",
        f"- Mode: `{report['mode']}`",
        f"- Source ref: `{report['source_ref']}`",
        f"- Claim status: `{environment['claim_status']}`",
        f"- Host class: `{environment['os']} {environment['architecture']}`",
        f"- Kernel: `{environment['kernel_release']}`",
        f"- Python: `{environment['python_version']}`",
        "",
        "## Governance-only latency",
        "",
        "| Metric | n | p50 us | p95 us | p99 us | ops/s |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for metric in report["governance_only"]:
        latency = metric["latency"]
        lines.append(
            f"| `{metric['name']}` | {latency['sample_count']} | {latency['p50']} | {latency['p95']} | {latency['p99']} | {metric['throughput_ops_per_second']} |"
        )
    lines.extend(["", "## Imported evidence processing", ""])
    for metric in report["imported_evidence_processing"]:
        latency = metric["latency"]
        lines.append(
            f"- `{metric['name']}`: n={latency['sample_count']}, p50={latency['p50']} us, p95={latency['p95']} us, p99={latency['p99']} us."
        )
    sustained = report["sustained_governance"]
    sensor = report["optional_runtime_sensor"]
    lines.extend(
        [
            "",
            "## Sustained governance resources",
            "",
            f"- Operations: {sustained['operation_count']}",
            f"- Wall time: {sustained['wall_seconds']} s",
            f"- CPU: {sustained['cpu_utilization_percent']}%",
            f"- Throughput: {sustained['throughput_ops_per_second']} ops/s",
            f"- Python heap peak: {sustained['python_heap_peak_bytes']} bytes",
            f"- Linux RSS start/end/HWM: {sustained['linux_rss_start_kib']}/{sustained['linux_rss_end_kib']}/{sustained['linux_rss_hwm_kib']} KiB",
            "",
            "## Optional runtime sensor",
            "",
            f"- Status: `{sensor['status']}`",
            f"- Reason: `{sensor['reason']}`",
            *(
                [
                    f"- Baseline command SHA-256: `{sensor['baseline_command_sha256']}`",
                    f"- Instrumented command SHA-256: `{sensor['instrumented_command_sha256']}`",
                    f"- Overhead p50/p95/p99: {sensor['overhead_percent']['p50']}/{sensor['overhead_percent']['p95']}/{sensor['overhead_percent']['p99']}%",
                ]
                if sensor["status"] == "measured"
                else []
            ),
            "",
            "## Limitations",
            "",
            *(f"- {item}" for item in report["limitations"]),
            "",
        ]
    )
    return "\n".join(lines)


def write_outputs(
    output_dir: str | Path, report: Mapping[str, Any]
) -> tuple[Path, Path, str]:
    directory = Path(output_dir).expanduser()
    try:
        if directory.is_symlink():
            raise BenchmarkError(
                "output_dir_symlink", "output directory must not be a symlink"
            )
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        directory.chmod(0o700)
        if not directory.is_dir():
            raise BenchmarkError(
                "output_dir_invalid", "output directory must be a real directory"
            )
    except OSError as exc:
        raise BenchmarkError(
            "output_dir_invalid", "output directory could not be prepared"
        ) from exc
    markdown_payload = render_markdown(report).encode("utf-8")
    payload = canonical_json_bytes(dict(report)) + b"\n"
    digest = hashlib.sha256(payload).hexdigest()
    json_path = directory / "linux-governance-benchmark.json"
    markdown_path = directory / "linux-governance-benchmark.md"
    try:
        write_report(json_path, payload)
        write_report(markdown_path, markdown_payload)
    except RuntimeEvidenceError as exc:
        raise BenchmarkError(
            "output_write_failed", "benchmark reports could not be written"
        ) from exc
    return json_path, markdown_path, digest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("smoke", "stress"), default="smoke")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--source-ref", default="unknown")
    parser.add_argument("--allow-non-linux", action="store_true")
    parser.add_argument("--sensor-pair-config")
    parser.add_argument("--warmups", type=int)
    parser.add_argument("--samples", type=int)
    parser.add_argument("--sustained-operations", type=int)
    parser.add_argument("--evidence-event-count", type=int)
    parser.add_argument("--policy-rule-counts", type=int, nargs="+")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        profile = BenchmarkConfig.profile(args.mode)
        config = BenchmarkConfig(
            mode=args.mode,
            warmup_count=profile.warmup_count if args.warmups is None else args.warmups,
            sample_count=profile.sample_count if args.samples is None else args.samples,
            sustained_operations=profile.sustained_operations
            if args.sustained_operations is None
            else args.sustained_operations,
            evidence_event_count=profile.evidence_event_count
            if args.evidence_event_count is None
            else args.evidence_event_count,
            policy_rule_counts=profile.policy_rule_counts
            if args.policy_rule_counts is None
            else tuple(args.policy_rule_counts),
        ).validated()
        sensor = (
            load_sensor_pair_config(args.sensor_pair_config)
            if args.sensor_pair_config
            else None
        )
        report = run_benchmark(
            config,
            source_ref=args.source_ref,
            allow_non_linux=args.allow_non_linux,
            sensor_config=sensor,
        )
        _json_path, _markdown_path, digest = write_outputs(args.output_dir, report)
        summary = {
            "condition": "linux_governance_benchmark_written",
            "claim_eligible": report["environment"]["claim_eligible"],
            "governance_metric_count": len(report["governance_only"]),
            "mode": report["mode"],
            "report_sha256": digest,
            "sensor_status": report["optional_runtime_sensor"]["status"],
        }
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
        return 0
    except BenchmarkError as exc:
        print(f"error: {exc.code}: {exc.detail}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
