"""Native policy backend — wraps Ardur's built-in checks behind PolicyBackend."""

from __future__ import annotations

import time
from typing import Any

from ..native_checks import evaluate_native_denials
from ..policy_backend import PolicyDecision


class NativeBackend:
    """Implements PolicyBackend for Ardur's built-in native checks."""

    name = "native"

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
        del principal, policy_spec
        t0 = time.perf_counter()
        passport_dict = context.get("passport") or {}
        session_state = context.get("session") or {}
        policy_metadata = context.get("policy_metadata")
        reasons = evaluate_native_denials(
            dict(passport_dict),
            tool_name,
            arguments,
            target,
            dict(session_state),
            dict(policy_metadata) if isinstance(policy_metadata, dict) else None,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        if reasons:
            return PolicyDecision(
                backend=self.name,
                label="ardur_builtin",
                decision="Deny",
                reasons=tuple(reasons),
                eval_ms=elapsed_ms,
            )
        return PolicyDecision(
            backend=self.name,
            label="ardur_builtin",
            decision="Allow",
            reasons=("within scope",),
            eval_ms=elapsed_ms,
        )
