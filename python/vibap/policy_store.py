"""Mission-id-keyed policy store for Cedar + forbid_rules + other
backend specs.

Why this exists
---------------
Biscuit credentials intentionally do NOT carry policy specs as Datalog
facts. Policy is server-side state — it changes at a different cadence
than identity (policies are revised by the security team; identity is
bound to the workload). Mixing them creates two problems:

1. Policy churn requires re-issuing credentials to every running
   agent — practically unshippable.
2. If the credential carried the policy, anyone who steals the
   credential also has the policy — the attacker can plan around
   the exact rules they need to evade.

The production flow is therefore: credential names the mission
(stable ID), proxy looks up current policies for that mission at
session-start time from an authoritative store.

This module defines the minimal `PolicyStore` Protocol the proxy
expects, plus `InMemoryPolicyStore` for tests and demos.

Previously the live-governance demo mutated `session.passport_claims
["additional_policies"]` AFTER session start, which was called out in
the 2026-04-17 external-review-X review:

> additional_policies are being injected by mutating live session state
> after session start ... the Cedar/forbid_rules layer is neither
> signed into the Biscuit nor loaded from an authoritative store.
> Anyone with a session handle can swap policy after the SPIFFE/
> Biscuit checks have already passed.

With `PolicyStore` the proxy loads policies into the session's
`passport_claims` BEFORE the session is cached, so downstream code
(`check_and_record`, receipt generation) sees the same server-
authoritative policy set every call.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


PolicySpec = dict[str, Any]
"""The shape consumed by the native / Cedar / forbid_rules backends.

Required keys:
    backend       : str   — "cedar" | "forbid_rules" | ...
    label         : str   — human-readable identity for the policy
                            (e.g. "security_team", "compliance")
    policy_sha256 : str   — SHA-256 fingerprint of the policy content
                            (enforced by the backend against either
                            policy_inline for Cedar or canonical JSON
                            of data_inline for forbid_rules)

Backend-specific keys:
    policy_inline : str            — Cedar DSL source (for backend="cedar")
    data_inline   : list[dict]     — forbid-rules definitions (for
                                     backend="forbid_rules")
"""


@runtime_checkable
class PolicyStore(Protocol):
    """The policy-lookup surface the proxy calls at session start.

    Implementations should be read-heavy: `get_policies` runs on the
    critical path of every session start. `put_policies` is mainly a
    test / admin affordance; production deployments usually reload the
    whole store via a config-change event.

    Implementations MUST be thread-safe. The proxy calls `get_policies`
    under its own locks, but the store is also exposed to admin-side
    mutation (a future admin API) so internal state changes under
    concurrent reads.
    """

    def get_policies(
        self,
        *,
        mission_id: str,
        agent_id: str | None = None,
    ) -> list[PolicySpec] | None:
        """Return the list of policy specs in force for this mission.

        The canonical key is ``mission_id`` — a stable identifier
        carried by the Biscuit/JWT credential. ``agent_id`` is passed
        in for stores that scope policies per (mission, agent) pair,
        but implementations are free to ignore it.

        Return values:
            ``None``   — this ``mission_id`` is unknown to the store.
                         The proxy MUST fall back to the credential's
                         ``additional_policies`` (or none) in this
                         case. Unknown missions should NOT silently
                         erase credential-supplied policies.
            ``[]``     — the mission is registered with ZERO
                         additional policies. This is an authoritative
                         "no extra policies" signal and MUST override
                         any credential-supplied ``additional_policies``
                         (the empty-list case that earlier versions of
                         the store logic ignored, leading to silent
                         policy escalation via credential forgery).
            non-empty  — the authoritative policy set for this mission.
                         Always overrides credential-supplied policies.
        """
        raise NotImplementedError

    def put_policies(
        self,
        *,
        mission_id: str,
        policies: list[PolicySpec],
        agent_id: str | None = None,
    ) -> None:
        """Replace the policy set for this mission.

        Implementations that don't support mutation (e.g. a read-only
        file-backed store) may raise ``NotImplementedError``. The
        proxy NEVER calls this method; only administrative tooling
        and tests do.
        """
        raise NotImplementedError


@dataclass
class InMemoryPolicyStore:
    """Thread-safe in-memory implementation suitable for tests + demos.

    Keyed by ``mission_id`` only; ``agent_id`` is accepted for
    interface compatibility but not used. A future multi-tenant store
    (e.g. backed by Postgres or a mission-registry service) would key
    on ``(tenant, mission_id, agent_id_glob)`` — this class is the
    minimum viable implementation.

    Storage is stored by value: input lists are copied defensively on
    ``put_policies`` and outputs are fresh list copies from
    ``get_policies``. That prevents a caller from mutating the
    authoritative store by mutating a returned list.
    """

    _policies: dict[str, list[PolicySpec]] = field(default_factory=dict)
    _lock_name: str = "_lock"  # Lock is created at __post_init__ so dataclass serialization stays clean.

    def __post_init__(self) -> None:
        import threading
        self._lock = threading.Lock()

    def get_policies(
        self,
        *,
        mission_id: str,
        agent_id: str | None = None,
    ) -> list[PolicySpec] | None:
        if not mission_id:
            return None
        with self._lock:
            if mission_id not in self._policies:
                return None
            stored = self._policies[mission_id]
            # Deep copy every spec. A shallow ``dict(spec)`` leaves
            # nested ``data_inline`` lists and Cedar policy dicts
            # aliased with the store's authoritative copy — a caller
            # that mutates the returned structure would silently
            # corrupt future reads and bypass the policy_sha256 check
            # (the hash was computed against the original content).
            return [copy.deepcopy(spec) for spec in stored]

    def put_policies(
        self,
        *,
        mission_id: str,
        policies: list[PolicySpec],
        agent_id: str | None = None,
    ) -> None:
        if not mission_id:
            raise ValueError("mission_id must be non-empty")
        # Validate every spec has the required shape so we fail fast
        # at registration time rather than at session-start time.
        for spec in policies:
            if not isinstance(spec, dict):
                raise TypeError(
                    f"policy spec must be a dict, got {type(spec).__name__}"
                )
            for required in ("backend", "label", "policy_sha256"):
                if required not in spec:
                    raise ValueError(
                        f"policy spec missing required key {required!r}"
                    )
        with self._lock:
            # Deep copy on ingress as well. Otherwise a caller that
            # mutates the original ``policies`` list (or a nested
            # ``data_inline`` inside any spec) after registration
            # would silently change what the store returns on later
            # reads. Combined with deep-copy-on-read this gives full
            # by-value isolation between the store and its callers.
            self._policies[mission_id] = [copy.deepcopy(spec) for spec in policies]

    def clear(self) -> None:
        """Drop all registered policies. Used by test teardown."""
        with self._lock:
            self._policies.clear()
