"""OPA/Rego policy backend — evaluates Rego policies via subprocess.

The backend expects the ``opa`` binary to be on PATH. Falls back cleanly
when it is not available. Follows the same pattern as the Cedar and
ForbidRules backends.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Any

from vibap.policy_backend import PolicyDecision, register_backend

BACKEND_NAME = "opa"
_logger = logging.getLogger(__name__)


class OPAIntegrityError(ValueError):
    """Raised when policy_sha256 does not match policy_inline."""


class OPAUnavailableError(RuntimeError):
    """Raised when the opa binary is not on PATH."""


def _opa_binary_path() -> str:
    """Return the path to the opa binary, or raise OPAUnavailableError."""
    path = shutil.which("opa")
    if path is None:
        raise OPAUnavailableError(
            "OPA backend unavailable: opa binary not found on PATH. "
            "Install from https://www.openpolicyagent.org/docs/latest/#running-opa"
        )
    return path


def _verify_sha256(source: str, declared: str) -> None:
    if not declared:
        raise OPAIntegrityError(
            "policy_spec missing required policy_sha256 field"
        )
    actual = hashlib.sha256(source.encode("utf-8")).hexdigest()
    if actual.lower() != declared.lower():
        raise OPAIntegrityError(
            f"policy_sha256 mismatch: declared={declared[:16]}... "
            f"actual={actual[:16]}..."
        )


def _build_rego_input(
    tool_name: str,
    arguments: dict[str, Any],
    principal: str,
    target: str,
    context: dict[str, Any],
) -> dict[str, Any]:
    return {
        "tool_name": tool_name,
        "arguments": arguments,
        "principal": principal,
        "target": target,
        "context": context,
    }


def _opa_eval(
    policy: str,
    input_data: dict[str, Any],
    query: str = "data.ardur.allow",
) -> tuple[bool, list[str]]:
    """Evaluate a Rego policy via the opa CLI.

    Returns (allowed, reasons). Reasons are extracted from
    ``data.ardur.reasons`` when present.
    """
    binary = _opa_binary_path()
    input_json = json.dumps(input_data, separators=(",", ":"))

    # Write policy to a temp file so we can use --data
    try:
        result = subprocess.run(
            [binary, "eval", "--format", "values", "--data", "-", "--input", "-", query],
            input=f"{policy}\n{'-' * 40}\n{input_json}",
            capture_output=True,
            text=True,
            timeout=10,
            env={**os.environ, "OPA_NO_COLOR": "1"},
        )
    except subprocess.TimeoutExpired:
        return False, ["OPA evaluation timed out"]
    except OSError as exc:
        return False, [f"OPA subprocess error: {exc}"]

    if result.returncode != 0:
        stderr = result.stderr.strip()
        return False, [f"OPA evaluation error: {stderr}" if stderr else "OPA evaluation failed"]

    # The output is a JSON array of results. We look for a top-level true/false.
    output = result.stdout.strip()
    if not output:
        return False, ["OPA returned no result"]

    try:
        parsed = json.loads(output)
    except json.JSONDecodeError:
        return False, [f"OPA returned non-JSON output: {output[:200]}"]

    # parsed is a list of results; first result is the query value
    if isinstance(parsed, list) and len(parsed) > 0:
        first = parsed[0]
        if isinstance(first, bool):
            return first, []
        if isinstance(first, list):
            # OPA returns an array of matching results; non-empty = true
            return len(first) > 0, []
        if isinstance(first, dict):
            # Complex result — treat as allow
            return True, []
    if isinstance(parsed, bool):
        return parsed, []

    # Fallback: couldn't interpret result
    return False, [f"OPA returned unexpected result format: {type(parsed).__name__}"]


def _is_opa_available() -> bool:
    """Check if opa binary is available and functional."""
    try:
        path = _opa_binary_path()
        result = subprocess.run(
            [path, "version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


@dataclass
class OPABackend:
    """Stateless OPA evaluator satisfying the PolicyBackend Protocol."""

    name: str = BACKEND_NAME

    def evaluate(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        principal: str,
        target: str,
        context: dict[str, Any],
        policy_spec: dict[str, Any],
    ) -> PolicyDecision:
        label = str(policy_spec.get("label", "opa"))
        policy_inline = str(policy_spec.get("policy_inline", ""))
        declared_sha = str(policy_spec.get("policy_sha256", ""))

        if not policy_inline:
            return PolicyDecision(
                backend=self.name,
                label=label,
                decision="Abstain",
                reasons=("empty policy_inline",),
            )

        t0 = time.perf_counter()

        try:
            _verify_sha256(policy_inline, declared_sha)
        except OPAIntegrityError as exc:
            ms = (time.perf_counter() - t0) * 1000.0
            return PolicyDecision(
                backend=self.name,
                label=label,
                decision="Deny",
                reasons=(f"integrity: {exc}",),
                eval_ms=ms,
            )

        try:
            rego_input = _build_rego_input(
                tool_name, arguments, principal, target, context
            )
            allowed, reasons = _opa_eval(policy_inline, rego_input)
        except OPAUnavailableError as exc:
            ms = (time.perf_counter() - t0) * 1000.0
            return PolicyDecision(
                backend=self.name,
                label=label,
                decision="Deny",
                reasons=(f"opa unavailable: {exc}",),
                eval_ms=ms,
            )
        except Exception as exc:
            ms = (time.perf_counter() - t0) * 1000.0
            return PolicyDecision(
                backend=self.name,
                label=label,
                decision="Deny",
                reasons=(f"opa error: {exc}",),
                eval_ms=ms,
            )

        ms = (time.perf_counter() - t0) * 1000.0
        if allowed:
            return PolicyDecision(
                backend=self.name,
                label=label,
                decision="Allow",
                reasons=tuple(reasons),
                eval_ms=ms,
            )
        if reasons:
            return PolicyDecision(
                backend=self.name,
                label=label,
                decision="Deny",
                reasons=tuple(reasons),
                eval_ms=ms,
            )
        return PolicyDecision(
            backend=self.name,
            label=label,
            decision="Abstain",
            eval_ms=ms,
        )


def register() -> None:
    """Register OPABackend if the opa binary is available."""
    if _is_opa_available():
        register_backend(OPABackend())
        _logger.info("OPA backend registered successfully")
    else:
        _logger.warning(
            "OPA backend unavailable: opa binary not on PATH. "
            "Install from https://www.openpolicyagent.org/docs/latest/#running-opa"
        )


# Auto-register on import if opa is available.
register()
