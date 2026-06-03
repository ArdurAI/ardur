"""Pluggable policy backend interface + composition.

Mission declarations can reference multiple policy engines. Each engine
implements :class:`PolicyBackend` and returns a :class:`PolicyDecision`.
Decisions are composed via :func:`compose_decisions`, which implements
the exact semantics formally verified in ``verification/composition_smt.py``:

    compose(B) = Deny   if  any pd.decision = "Deny"
               = Allow  elif any pd.decision = "Allow"
               = Deny   else (all Abstain or empty — fail-closed)

The four SMT-proven properties P1-P4 hold:
    P1 any Deny -> Deny
    P2 all Abstain -> Deny
    P3 Deny is resilient under extension (defense-in-depth)
    P4 appending Deny always yields Deny

A backend is free to Abstain when an action is outside its domain
(e.g. a compliance backend may only evaluate external_send actions and
Abstain on reads). Abstain does not contribute to fail-closed unless
every backend abstains — in which case the action is denied.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Protocol, runtime_checkable

DecisionType = Literal["Allow", "Deny", "Abstain"]


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Result of a single backend's evaluation for one tool call."""

    backend: str                     # machine name of the backend
    label: str                       # human label ("security_team", ...)
    decision: DecisionType           # Allow | Deny | Abstain
    reasons: tuple[str, ...] = ()    # engine-specific explanation
    eval_ms: float = 0.0             # measured evaluation time

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "label": self.label,
            "decision": self.decision,
            "reasons": list(self.reasons),
            "eval_ms": self.eval_ms,
        }


@runtime_checkable
class PolicyBackend(Protocol):
    """A policy evaluator. Any engine that exposes this interface can
    participate in composition.

    Backends are stateless with respect to any specific policy: the
    policy source, integrity hash, and any engine-specific data live
    on each mission's policy_spec dict and are passed per-call. This
    lets a single CedarBackend instance serve arbitrarily many missions,
    each with its own Cedar policy.
    """

    name: str                        # must be stable; used in registry

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
        """Evaluate one pending tool call against the given policy_spec.

        policy_spec fields:
          - backend: str          machine name (redundant, for symmetry)
          - label: str            human label
          - policy_inline: str    engine-specific source
          - policy_sha256: str    integrity hash (backend MUST verify)
          - data_inline: any      engine-specific data (entities, facts)

        Should return PolicyDecision with decision in {Allow, Deny, Abstain}.
        MUST NOT raise for ordinary policy decisions — raise only for
        catastrophic errors (malformed policy, solver crash,
        integrity-hash mismatch).
        """
        ...


def compose_decisions(
    decisions: list[PolicyDecision],
) -> tuple[DecisionType, PolicyDecision | None]:
    """Compose a list of backend decisions per the SMT-verified rule.

    Returns ``(final_decision, first_denier)``. ``first_denier`` is the
    first PolicyDecision in evaluation order that returned Deny (for
    audit trails); None when composition is Allow or fail-closed-Deny.
    """
    for pd in decisions:
        if pd.decision == "Deny":
            return "Deny", pd
    for pd in decisions:
        if pd.decision == "Allow":
            return "Allow", None
    # All Abstain or empty → fail-closed
    return "Deny", None


# ─── Registry ─────────────────────────────────────────────────────

_REGISTRY: dict[str, PolicyBackend] = {}


def _bootstrap_builtin_backend(name: str) -> bool:
    """Restore a built-in backend after registry clears.

    Tests intentionally call ``clear_registry()`` to isolate composition
    behavior. Built-in backends such as ``native`` and ``forbid_rules`` are
    registered at import/startup time, so a later lookup should be able to
    restore them without forcing unrelated callers to eagerly import optional
    dependencies again.
    """
    if name == "native":
        from vibap.backends.native import NativeBackend

        register_backend(NativeBackend())
        return True
    if name == "forbid_rules":
        from vibap.backends.forbid_rules import register as register_forbid_rules

        register_forbid_rules()
        return True
    if name == "cedar":
        try:
            from vibap.backends import register_cedar
        except Exception:
            return False
        try:
            register_cedar()
        except RuntimeError:
            return False
        return True
    return False


def register_backend(backend: PolicyBackend) -> None:
    """Register a backend by its ``name`` attribute. Idempotent — a
    second register with the same name replaces the first."""
    _REGISTRY[backend.name] = backend


def get_backend(name: str) -> PolicyBackend:
    """Fetch a registered backend. Raises KeyError if not registered."""
    if name not in _REGISTRY:
        _bootstrap_builtin_backend(name)
    if name not in _REGISTRY:
        raise KeyError(
            f"No policy backend registered under name {name!r}. "
            f"Registered backends: {sorted(_REGISTRY)}"
        )
    return _REGISTRY[name]


def list_backends() -> list[str]:
    return sorted(_REGISTRY)


def clear_registry() -> None:
    """Test helper: empty the registry. Do NOT call in production."""
    _REGISTRY.clear()


# ─── Timing helper ────────────────────────────────────────────────


def timed_evaluate(
    backend: PolicyBackend,
    *,
    tool_name: str,
    arguments: dict[str, Any],
    principal: str,
    target: str,
    context: dict[str, Any],
    policy_spec: dict[str, Any],
) -> PolicyDecision:
    """Call backend.evaluate and patch eval_ms with measured time.

    Backends are free to compute eval_ms themselves, but this wrapper
    ensures the timing field is always populated even if the backend
    forgets.
    """
    t0 = time.perf_counter()
    decision = backend.evaluate(
        tool_name=tool_name,
        arguments=arguments,
        principal=principal,
        target=target,
        context=context,
        policy_spec=policy_spec,
    )
    ms = (time.perf_counter() - t0) * 1000.0
    if decision.eval_ms == 0.0:
        return PolicyDecision(
            backend=decision.backend,
            label=decision.label,
            decision=decision.decision,
            reasons=decision.reasons,
            eval_ms=ms,
        )
    return decision
