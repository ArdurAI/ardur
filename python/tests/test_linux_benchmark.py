from __future__ import annotations

import copy
import json
import os
import stat
import sys
import time
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import vibap.linux_benchmark as benchmark
from vibap._specs import linux_governance_benchmark_report_v01_schema


def _tiny_config(mode: str = "smoke") -> benchmark.BenchmarkConfig:
    return benchmark.BenchmarkConfig(mode, 0, 1, 1, 1, (1,))


def _sensor_value(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": benchmark.SENSOR_SCHEMA_VERSION,
        "baseline_argv": [sys.executable, "-c", "pass"],
        "instrumented_argv": [sys.executable, "-c", "pass"],
        "repetitions": 3,
        "timeout_seconds": 5,
    }
    value.update(overrides)
    return value


def _write_sensor(path: Path, **overrides: object) -> Path:
    path.write_text(json.dumps(_sensor_value(**overrides)), encoding="utf-8")
    return path


def test_schema_is_valid_and_embedded_copy_matches_canonical() -> None:
    root = Path(__file__).resolve().parents[2]
    canonical = root / "docs/specs/linux-governance-benchmark-report-v0.1.schema.json"
    embedded = (
        root / "python/vibap/_specs/linux_governance_benchmark_report_v01.schema.json"
    )

    assert canonical.read_bytes() == embedded.read_bytes()
    assert json.loads(canonical.read_text(encoding="utf-8")) == (
        linux_governance_benchmark_report_v01_schema()
    )
    Draft202012Validator.check_schema(linux_governance_benchmark_report_v01_schema())


def test_nearest_rank_uses_exact_nearest_rank_semantics() -> None:
    values = list(range(1, 101))
    assert benchmark.nearest_rank(values, 50) == 50
    assert benchmark.nearest_rank(values, 95) == 95
    assert benchmark.nearest_rank(values, 99) == 99
    with pytest.raises(benchmark.BenchmarkError, match="must not be empty"):
        benchmark.nearest_rank([], 95)


def test_journal_append_completes_short_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "journal.jsonl"
    line = b'{"receipt":"bounded-record"}\n'
    real_write = os.write

    def short_write(descriptor: int, payload: bytes | memoryview) -> int:
        view = memoryview(payload)
        return real_write(descriptor, view[:7])

    monkeypatch.setattr(benchmark.os, "write", short_write)
    benchmark._journal_operation(path, line, durable=False)()

    assert path.read_bytes() == line


def test_distribution_schema_separates_latency_and_percent_domains() -> None:
    schema = linux_governance_benchmark_report_v01_schema()
    validator = Draft202012Validator(schema).evolve(
        schema=schema["$defs"]["distribution"]
    )
    latency = {
        "unit": "microseconds",
        "sample_count": 1,
        "p50": 2_000_000,
        "p95": 2_000_000,
        "p99": 2_000_000,
        "min": 2_000_000,
        "max": 2_000_000,
        "mean": 2_000_000,
    }
    validator.validate(latency)
    latency["p50"] = -1
    assert any(
        list(error.absolute_path) == ["p50"] for error in validator.iter_errors(latency)
    )

    percent = {
        "unit": "percent",
        "sample_count": 1,
        "p50": -1,
        "p95": 0,
        "p99": 1,
        "min": -1,
        "max": 1,
        "mean": 0,
    }
    validator.validate(percent)
    percent["p50"] = 1_000_001
    assert any(
        list(error.absolute_path) == ["p50"] for error in validator.iter_errors(percent)
    )


def test_report_schema_rejects_cross_field_claim_mismatches() -> None:
    report = benchmark.run_benchmark(_tiny_config(), allow_non_linux=True)
    validator = Draft202012Validator(linux_governance_benchmark_report_v01_schema())

    wrong_class = copy.deepcopy(report)
    wrong_class["governance_only"][0]["measurement_class"] = (
        "imported_evidence_processing"
    )
    assert list(validator.iter_errors(wrong_class))

    wrong_sensor = copy.deepcopy(report)
    wrong_sensor["optional_runtime_sensor"]["status"] = "measured"
    assert list(validator.iter_errors(wrong_sensor))

    wrong_stress = copy.deepcopy(report)
    wrong_stress["mode"] = "stress"
    assert list(validator.iter_errors(wrong_stress))


def test_tiny_report_is_schema_valid_and_does_not_leak_private_paths(
    tmp_path: Path,
) -> None:
    report = benchmark.run_benchmark(
        _tiny_config(), source_ref="abcdef0", allow_non_linux=True
    )
    benchmark.validate_report(report)

    rendered = json.dumps(report, sort_keys=True) + benchmark.render_markdown(report)
    assert str(tmp_path) not in rendered
    assert "/ardur-linux-benchmark-" not in rendered
    assert report["optional_runtime_sensor"]["status"] == "not_measured"
    assert len(report["governance_only"]) >= 7
    assert report["imported_evidence_processing"][0]["notes"][-1] == (
        "This does not measure live kernel sensor capture."
    )


def test_report_schema_failure_names_path_and_rule_without_echoing_value(
    tmp_path: Path,
) -> None:
    report = benchmark.run_benchmark(_tiny_config(), allow_non_linux=True)
    private_marker = str(tmp_path / "private-report-value")
    report["environment"]["cpu_count"] = private_marker
    report[private_marker] = "unknown private field"

    with pytest.raises(benchmark.BenchmarkError) as error:
        benchmark.validate_report(report)

    assert error.value.code == "report_schema_invalid"
    assert "$ [additionalProperties]" in error.value.detail
    assert "$.environment.cpu_count [type]" in error.value.detail
    assert private_marker not in error.value.detail
    assert "unknown private field" not in error.value.detail
    assert "\n" not in error.value.detail


def test_report_schema_failure_details_are_deterministic_and_bounded() -> None:
    report = benchmark.run_benchmark(_tiny_config(), allow_non_linux=True)
    report["config"]["evidence_event_count"] = 0
    report["config"]["sample_count"] = 0
    report["environment"]["architecture"] = ""
    report["environment"]["cpu_count"] = 0
    report["environment"]["kernel_release"] = ""
    report["mode"] = "invalid"

    details = []
    for _ in range(2):
        with pytest.raises(benchmark.BenchmarkError) as error:
            benchmark.validate_report(report)
        details.append(error.value.detail)

    assert (
        details
        == [
            "generated report violated its JSON Schema: "
            "$.config.evidence_event_count [minimum]; "
            "$.config.sample_count [minimum]; "
            "$.environment.architecture [minLength]; "
            "$.environment.cpu_count [minimum]; "
            "$.environment.kernel_release [minLength]; +1 more"
        ]
        * 2
    )
    assert len(details[0]) < 512


def test_write_outputs_are_owner_only_and_stdout_is_path_free(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "private-output"
    exit_code = benchmark.main(
        [
            "--mode",
            "smoke",
            "--output-dir",
            str(output),
            "--allow-non-linux",
            "--warmups",
            "0",
            "--samples",
            "1",
            "--sustained-operations",
            "1",
            "--evidence-event-count",
            "1",
            "--policy-rule-counts",
            "1",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    summary = json.loads(captured.out)
    assert summary["condition"] == "linux_governance_benchmark_written"
    assert str(tmp_path) not in captured.out
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    for name in ("linux-governance-benchmark.json", "linux-governance-benchmark.md"):
        path = output / name
        assert path.is_file()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_non_linux_fails_closed_unless_explicitly_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(benchmark.platform, "system", lambda: "Darwin")
    with pytest.raises(benchmark.BenchmarkError) as error:
        benchmark.run_benchmark(_tiny_config())
    assert error.value.code == "linux_required"

    report = benchmark.run_benchmark(_tiny_config(), allow_non_linux=True)
    assert report["environment"]["claim_eligible"] is False
    assert report["environment"]["claim_status"] == "non_linux_smoke_only"


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (
            '{"schema_version":"ardur.sensor_pair.v0.1",'
            '"baseline_argv":["true"],"baseline_argv":["false"],'
            '"instrumented_argv":["true"],"repetitions":3,"timeout_seconds":5}',
            "sensor_config_duplicate_key",
        ),
        (json.dumps({**_sensor_value(), "unknown": True}), "sensor_config_fields"),
        (json.dumps(_sensor_value(baseline_argv="true")), "sensor_argv_invalid"),
        (json.dumps(_sensor_value(repetitions=2)), "sensor_repetitions_invalid"),
        (
            json.dumps(_sensor_value(timeout_seconds=float("inf"))),
            "sensor_config_nonfinite",
        ),
    ],
)
def test_sensor_config_rejects_hostile_shapes(
    tmp_path: Path, raw: str, code: str
) -> None:
    path = tmp_path / "sensor.json"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(benchmark.BenchmarkError) as error:
        benchmark.load_sensor_pair_config(path)
    assert error.value.code == code


def test_sensor_config_rejects_symlink(tmp_path: Path) -> None:
    target = _write_sensor(tmp_path / "sensor.json")
    link = tmp_path / "sensor-link.json"
    link.symlink_to(target)
    with pytest.raises(benchmark.BenchmarkError) as error:
        benchmark.load_sensor_pair_config(link)
    assert error.value.code == "sensor_config_not_regular"


def test_sensor_config_rejects_excessive_json_depth(tmp_path: Path) -> None:
    path = tmp_path / "sensor.json"
    path.write_text('{"nested":' + "[" * 20 + "0" + "]" * 20 + "}", encoding="utf-8")
    with pytest.raises(benchmark.BenchmarkError) as error:
        benchmark.load_sensor_pair_config(path)
    assert error.value.code == "sensor_config_too_deep"


def test_paired_sensor_report_contains_digests_not_argv(tmp_path: Path) -> None:
    private_marker = "private-sensor-command-marker"
    path = _write_sensor(
        tmp_path / "sensor.json",
        baseline_argv=[sys.executable, "-c", "pass", private_marker],
        instrumented_argv=[
            sys.executable,
            "-c",
            "pass",
            private_marker + "-instrumented",
        ],
    )
    config = benchmark.load_sensor_pair_config(path)

    result = benchmark._sensor_measurement(config)

    rendered = json.dumps(result, sort_keys=True)
    report = benchmark.run_benchmark(_tiny_config(), allow_non_linux=True)
    report["mode"] = "stress"
    report["source_ref"] = "abcdef0"
    report["config"]["sample_count"] = 100
    report["environment"]["os"] = "Linux"
    report["environment"]["claim_eligible"] = True
    report["environment"]["claim_status"] = "eligible_linux_host"
    report["optional_runtime_sensor"] = result
    markdown = benchmark.render_markdown(report)
    assert result["status"] == "measured"
    assert result["repetitions"] == 3
    assert private_marker not in rendered
    assert len(result["baseline_command_sha256"]) == 64
    assert len(result["instrumented_command_sha256"]) == 64
    assert private_marker not in markdown
    assert "Overhead p50/p95/p99" in markdown


def test_sensor_failures_are_stable_and_path_free(tmp_path: Path) -> None:
    marker = str(tmp_path / "private-command")
    config = benchmark.SensorPairConfig(
        (sys.executable, "-c", "raise SystemExit(7)", marker),
        (sys.executable, "-c", "pass"),
        3,
        5,
    )

    with pytest.raises(benchmark.BenchmarkError) as error:
        benchmark._sensor_measurement(config)

    assert error.value.code == "sensor_command_nonzero"
    assert marker not in str(error.value)


def test_sensor_timeout_terminates_spawned_process_group(tmp_path: Path) -> None:
    child_program = "import time; time.sleep(30)"
    parent_program = (
        "import pathlib,subprocess,sys,time;"
        f"p=subprocess.Popen([sys.executable,'-c',{child_program!r}]);"
        "pathlib.Path('child.pid').write_text(str(p.pid));"
        "time.sleep(30)"
    )
    with pytest.raises(benchmark.BenchmarkError) as error:
        benchmark._run_sensor_command(
            (sys.executable, "-c", parent_program), 1, tmp_path
        )
    assert error.value.code == "sensor_command_timeout"

    child_pid = int((tmp_path / "child.pid").read_text(encoding="utf-8"))
    for _ in range(50):
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.02)
    else:
        pytest.fail("sensor child process survived timeout cleanup")


def test_stress_cli_requires_meaningful_sample_floor(tmp_path: Path) -> None:
    exit_code = benchmark.main(
        [
            "--mode",
            "stress",
            "--output-dir",
            str(tmp_path / "output"),
            "--allow-non-linux",
            "--samples",
            "99",
        ]
    )
    assert exit_code == 2


def test_programmatic_stress_cannot_bypass_sample_or_source_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(benchmark.platform, "system", lambda: "Linux")
    with pytest.raises(benchmark.BenchmarkError) as sample_error:
        benchmark.run_benchmark(
            benchmark.BenchmarkConfig("stress", 0, 99, 1, 1, (1,)),
            source_ref="abcdef0",
        )
    assert sample_error.value.code == "stress_samples_too_small"

    with pytest.raises(benchmark.BenchmarkError) as source_error:
        benchmark.run_benchmark(benchmark.BenchmarkConfig("stress", 0, 100, 1, 1, (1,)))
    assert source_error.value.code == "stress_source_ref_required"


def test_sensor_pair_requires_linux_stress_mode() -> None:
    sensor = benchmark.SensorPairConfig(
        (sys.executable, "-c", "pass"),
        (sys.executable, "-c", "pass"),
        3,
        5,
    )
    with pytest.raises(benchmark.BenchmarkError) as error:
        benchmark.run_benchmark(
            _tiny_config(), allow_non_linux=True, sensor_config=sensor
        )
    assert error.value.code == "sensor_mode_invalid"


def test_host_metadata_is_bounded_printable_and_markdown_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(benchmark.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(benchmark.platform, "machine", lambda: "arm64\n| injected")
    monkeypatch.setattr(benchmark.platform, "release", lambda: "1.0`broken`")
    environment = benchmark._environment(allow_non_linux=True)

    assert environment["architecture"] == "arm64 | injected"
    assert "\n" not in environment["architecture"]
    assert all(
        0x20 <= ord(character) <= 0x7E for character in environment["kernel_release"]
    )
    assert "`" not in environment["kernel_release"]


def test_output_symlink_failure_is_stable_and_does_not_change_target(
    tmp_path: Path,
) -> None:
    report = benchmark.run_benchmark(_tiny_config(), allow_non_linux=True)
    output = tmp_path / "output"
    output.mkdir()
    target = tmp_path / "target.json"
    target.write_text("unchanged\n", encoding="utf-8")
    (output / "linux-governance-benchmark.json").symlink_to(target)

    with pytest.raises(benchmark.BenchmarkError) as error:
        benchmark.write_outputs(output, report)

    assert error.value.code == "output_write_failed"
    assert target.read_text(encoding="utf-8") == "unchanged\n"
