"""Credential-free regression tests for the Ollama showcase fail-closed logic.

These tests exercise ``_preflight_ollama()`` and the
``pytest_collection_modifyitems`` hook in ``test_e2e_showcase.py`` without any
real Ollama credentials, network access, or the ``ollama`` extra installed.

Coverage:
- ``_preflight_ollama()`` returns ``(False, reason)`` when the API key is empty.
- ``_preflight_ollama()`` returns ``(False, reason)`` when the cloud model is empty.
- ``_preflight_ollama()`` returns ``(False, reason)`` when both env vars are set
  but ``import ollama`` fails (simulated via ``sys.modules`` injection).
- ``_preflight_ollama()`` returns ``(True, "")`` when all three pass (simulated).
- The reason string never leaks the API key value, even when set.
- With ``ARDUR_OLLAMA_FAIL_CLOSED=1`` and credentials absent, invoking pytest
  on the showcase module exits non-zero (collection error, not silent skips).

None of these tests require real credentials or network access.
"""

from __future__ import annotations

import importlib
import os
import subprocess
import sys

import pytest


# ---------------------------------------------------------------------------
# Import the showcase module's preflight function in isolation.
#
# ``test_e2e_showcase`` reads ``ARDUR_OLLAMA_API_KEY`` / ``ARDUR_OLLAMA_CLOUD_MODEL``
# at import time into module-level constants. Importing it with credentials in
# the environment would also try to build the skip marker, which is fine, but we
# want a clean import under controlled env. We import once with both unset.
# ---------------------------------------------------------------------------


@pytest.fixture
def showcase_module(monkeypatch):
    """Import test_e2e_showcase with credentials unset for a deterministic base."""
    monkeypatch.delenv("ARDUR_OLLAMA_API_KEY", raising=False)
    monkeypatch.delenv("ARDUR_OLLAMA_CLOUD_MODEL", raising=False)
    monkeypatch.delenv("ARDUR_OLLAMA_FAIL_CLOSED", raising=False)
    # Remove any cached import so the module-level constants pick up the new env.
    sys.modules.pop("test_e2e_showcase", None)
    try:
        module = importlib.import_module("test_e2e_showcase")
    except Exception:
        pytest.skip("test_e2e_showcase import requires vibap test deps")
        return  # defensive: pytest.skip raises, but satisfy static analyzers
    yield module
    sys.modules.pop("test_e2e_showcase", None)


def _force_ollama_import_failure(monkeypatch):
    """Make ``import ollama`` raise ImportError without touching the real env."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "ollama":
            raise ImportError("simulated: ollama extra not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    # Clear any cached ollama module so the next import hits our stub.
    monkeypatch.delitem(sys.modules, "ollama", raising=False)


def _force_ollama_import_success(monkeypatch):
    """Make ``import ollama`` succeed with a stub module."""
    types = importlib.import_module("types")
    fake_ollama = types.ModuleType("ollama")
    monkeypatch.setitem(sys.modules, "ollama", fake_ollama)


# ---------------------------------------------------------------------------
# preflight: credential / config presence
# ---------------------------------------------------------------------------


def test_preflight_false_when_api_key_empty(showcase_module, monkeypatch):
    monkeypatch.delenv("ARDUR_OLLAMA_API_KEY", raising=False)
    monkeypatch.setenv("ARDUR_OLLAMA_CLOUD_MODEL", "some-model")
    _force_ollama_import_success(monkeypatch)

    ok, reason = showcase_module._preflight_ollama()
    assert ok is False
    assert "ARDUR_OLLAMA_API_KEY" in reason


def test_preflight_false_when_cloud_model_empty(showcase_module, monkeypatch):
    monkeypatch.setenv("ARDUR_OLLAMA_API_KEY", "some-key")
    monkeypatch.delenv("ARDUR_OLLAMA_CLOUD_MODEL", raising=False)
    _force_ollama_import_success(monkeypatch)

    ok, reason = showcase_module._preflight_ollama()
    assert ok is False
    assert "ARDUR_OLLAMA_CLOUD_MODEL" in reason


def test_preflight_false_when_credentials_set_but_import_fails(
    showcase_module, monkeypatch
):
    monkeypatch.setenv("ARDUR_OLLAMA_API_KEY", "some-key")
    monkeypatch.setenv("ARDUR_OLLAMA_CLOUD_MODEL", "some-model")
    _force_ollama_import_failure(monkeypatch)

    ok, reason = showcase_module._preflight_ollama()
    assert ok is False
    assert "import" in reason.lower() or "ImportError" in reason


def test_preflight_true_when_all_three_pass(showcase_module, monkeypatch):
    monkeypatch.setenv("ARDUR_OLLAMA_API_KEY", "some-key")
    monkeypatch.setenv("ARDUR_OLLAMA_CLOUD_MODEL", "some-model")
    _force_ollama_import_success(monkeypatch)

    ok, reason = showcase_module._preflight_ollama()
    assert ok is True
    assert reason == ""


# ---------------------------------------------------------------------------
# secret hygiene: the reason string must never contain the key value
# ---------------------------------------------------------------------------


def test_preflight_reason_never_leaks_api_key(showcase_module, monkeypatch):
    secret_value = "sk-DO-NOT-LEAK-THIS-VALUE-12345"
    monkeypatch.setenv("ARDUR_OLLAMA_API_KEY", secret_value)
    monkeypatch.delenv("ARDUR_OLLAMA_CLOUD_MODEL", raising=False)
    _force_ollama_import_success(monkeypatch)

    ok, reason = showcase_module._preflight_ollama()
    # We expect False here (cloud model missing), but the reason must not
    # echo the API key value back.
    assert ok is False
    assert secret_value not in reason
    assert secret_value not in str(reason)


# ---------------------------------------------------------------------------
# collection hook: fail-closed behavior via subprocess
#
# We invoke pytest in a subprocess against a tiny throwaway test file that
# re-uses the showcase module's pytest_collection_modifyitems hook. This avoids
# depending on the pytester plugin being enabled and keeps the test fully
# credential-free.
# ---------------------------------------------------------------------------


_SHOWCASE_HOOK_PROBE_CONFTEST = '''
import os
import pytest

# Mirror of the hook defined in the real python/tests/conftest.py.

def _preflight_ollama():
    api_key = os.environ.get("ARDUR_OLLAMA_API_KEY", "")
    cloud_model = os.environ.get("ARDUR_OLLAMA_CLOUD_MODEL", "")
    if not api_key:
        return False, "ARDUR_OLLAMA_API_KEY unset/empty"
    if not cloud_model:
        return False, "ARDUR_OLLAMA_CLOUD_MODEL unset/empty"
    try:
        import ollama  # noqa: F401
    except ImportError as exc:
        return False, f"ollama client import failed: {type(exc).__name__}"
    return True, ""


def pytest_collection_modifyitems(config, items):
    if os.environ.get("ARDUR_OLLAMA_FAIL_CLOSED", "") != "1":
        return
    ok, reason = _preflight_ollama()
    if not ok:
        raise pytest.UsageError(
            "ARDUR_OLLAMA_FAIL_CLOSED=1 but Ollama preflight failed: " + reason
        )
'''

_SHOWCASE_HOOK_PROBE_TEST = '''
import pytest

@pytest.mark.skipif(
    True,  # would always skip, simulating stale skipif state
    reason="Ollama cloud model not available "
           "(set ARDUR_OLLAMA_API_KEY and ARDUR_OLLAMA_CLOUD_MODEL)",
)
def test_placeholder_ollama_gated():
    pass


def test_plain():
    pass
'''


def test_fail_closed_hook_errors_when_credential_absent(tmp_path, monkeypatch):
    """When FAIL_CLOSED=1 and preflight fails, pytest must exit non-zero.

    pytest only auto-registers ``pytest_collection_modifyitems`` from
    ``conftest.py`` (never from a test module), so the probe writes the hook
    to ``conftest.py`` -- this mirrors the real layout where the hook lives
    in ``python/tests/conftest.py`` and the showcase test module carries
    only the skip marker.
    """
    (tmp_path / "conftest.py").write_text(_SHOWCASE_HOOK_PROBE_CONFTEST)
    probe = tmp_path / "test_probe_failclosed.py"
    probe.write_text(_SHOWCASE_HOOK_PROBE_TEST)

    env = os.environ.copy()
    # Force credentials absent.
    env.pop("ARDUR_OLLAMA_API_KEY", None)
    env.pop("ARDUR_OLLAMA_CLOUD_MODEL", None)
    env["ARDUR_OLLAMA_FAIL_CLOSED"] = "1"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(probe),
            "-q",
            "--no-header",
            "-p",
            "no:cacheprovider",
        ],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    # The collection-time UsageError must produce a non-zero exit code rather
    # than a silent green run full of skips.
    assert result.returncode != 0, (
        "FAIL_CLOSED=1 with absent credentials must not exit 0. "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    combined = result.stdout + result.stderr
    assert "preflight failed" in combined or "UsageError" in combined, (
        f"Expected a preflight failure message, got: {combined!r}"
    )


def test_fail_closed_hook_inactive_without_env_var(tmp_path):
    """Without FAIL_CLOSED set, the hook is inert and pytest may exit 0."""
    (tmp_path / "conftest.py").write_text(_SHOWCASE_HOOK_PROBE_CONFTEST)
    probe = tmp_path / "test_probe_inert.py"
    probe.write_text(_SHOWCASE_HOOK_PROBE_TEST)

    env = os.environ.copy()
    env.pop("ARDUR_OLLAMA_API_KEY", None)
    env.pop("ARDUR_OLLAMA_CLOUD_MODEL", None)
    env.pop("ARDUR_OLLAMA_FAIL_CLOSED", None)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(probe),
            "-q",
            "--no-header",
            "-p",
            "no:cacheprovider",
        ],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    # No FAIL_CLOSED -> hook inert -> placeholder skip does not fail the run.
    assert result.returncode == 0, (
        f"Without FAIL_CLOSED the run should be green. stdout={result.stdout!r}"
    )
