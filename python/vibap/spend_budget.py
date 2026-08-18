"""Pre-action token and monetary spend reservation.

The existing :mod:`vibap.lineage_budget` ledger conserves delegated tool-call
counts.  Spend authority is deliberately separate: it has two units, a
reserve/settle lifecycle, and an operator-owned quote trust boundary.

All authorization arithmetic is integer-only.  Quote and request fingerprints
use the package's RFC 8785 canonical JSON implementation.  The local reference
ledger serializes writers with ``flock`` and durably replaces state files; it
does not fetch mutable provider pricing on the authorization hot path.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import threading
import time
import uuid
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .canonical_json import canonical_json_bytes


SPEND_BUDGET_VERSION = 1
SPEND_QUOTE_VERSION = 1
SPEND_LEDGER_VERSION = 1
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_METERED_TOOLS = 256
MAX_LEDGER_RECORDS = 100_000
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SCOPES = ("session", "agent", "lineage")
_DIMENSIONS = ("tokens", "currency_micros")


class SpendBudgetError(ValueError):
    """Fail-closed spend policy, quote, or settlement error."""

    def __init__(self, reason_code: str, detail: str | None = None) -> None:
        self.reason_code = reason_code
        super().__init__(detail or reason_code)


class SpendBudgetConflictError(SpendBudgetError):
    """A stable request identifier was reused with different semantics."""


def _non_negative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SpendBudgetError(
            "spend_policy_invalid",
            f"{field_name} must be a non-negative integer",
        )
    if value < 0 or value > MAX_SAFE_INTEGER:
        raise SpendBudgetError(
            "spend_policy_invalid",
            f"{field_name} must be between 0 and {MAX_SAFE_INTEGER}",
        )
    return value


def _bounded_string(value: Any, field_name: str, *, max_bytes: int = 256) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SpendBudgetError(
            "spend_policy_invalid",
            f"{field_name} must be a non-empty string",
        )
    normalized = value.strip()
    if len(normalized.encode("utf-8")) > max_bytes:
        raise SpendBudgetError(
            "spend_policy_invalid",
            f"{field_name} exceeds {max_bytes} bytes",
        )
    return normalized


def _currency(value: Any, field_name: str = "currency") -> str:
    normalized = _bounded_string(value, field_name, max_bytes=3)
    if not _CURRENCY_RE.fullmatch(normalized):
        raise SpendBudgetError(
            "spend_policy_invalid",
            f"{field_name} must be a three-letter uppercase currency code",
        )
    return normalized


def _reject_unknown_fields(
    value: Mapping[str, Any],
    allowed: set[str],
    field_name: str,
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise SpendBudgetError(
            "spend_policy_invalid",
            f"{field_name} contains unknown fields: {unknown}",
        )


def normalize_spend_budget(
    raw: Mapping[str, Any],
    *,
    lineage_id: str | None = None,
    require_lineage_id: bool = False,
) -> dict[str, Any]:
    """Validate and canonicalize a signed ``spend_budget`` claim.

    Mission input omits ``lineage_id``.  Root issuance supplies the fresh
    passport JTI; child derivation preserves the already-signed identifier.
    """

    if not isinstance(raw, Mapping):
        raise SpendBudgetError("spend_policy_invalid", "spend_budget must be an object")
    _reject_unknown_fields(
        raw,
        {"version", "currency", "metered_tools", "ceilings", "lineage_id"},
        "spend_budget",
    )
    version = _non_negative_int(raw.get("version"), "spend_budget.version")
    if version != SPEND_BUDGET_VERSION:
        raise SpendBudgetError(
            "spend_policy_invalid",
            f"unsupported spend_budget.version {version}",
        )
    currency = _currency(raw.get("currency"), "spend_budget.currency")

    tools_raw = raw.get("metered_tools")
    if not isinstance(tools_raw, (list, tuple)) or not tools_raw:
        raise SpendBudgetError(
            "spend_policy_invalid",
            "spend_budget.metered_tools must be a non-empty array",
        )
    if len(tools_raw) > MAX_METERED_TOOLS:
        raise SpendBudgetError(
            "spend_policy_invalid",
            f"spend_budget.metered_tools exceeds {MAX_METERED_TOOLS} entries",
        )
    tools = sorted(
        {_bounded_string(item, "spend_budget.metered_tools[]") for item in tools_raw}
    )
    if len(tools) != len(tools_raw):
        raise SpendBudgetError(
            "spend_policy_invalid",
            "spend_budget.metered_tools must not contain duplicates",
        )

    ceilings_raw = raw.get("ceilings")
    if not isinstance(ceilings_raw, Mapping):
        raise SpendBudgetError(
            "spend_policy_invalid",
            "spend_budget.ceilings must be an object",
        )
    _reject_unknown_fields(ceilings_raw, set(_DIMENSIONS), "spend_budget.ceilings")
    if set(ceilings_raw) != set(_DIMENSIONS):
        raise SpendBudgetError(
            "spend_policy_invalid",
            "spend_budget.ceilings must declare tokens and currency_micros",
        )
    ceilings: dict[str, dict[str, int]] = {}
    for dimension in _DIMENSIONS:
        scope_raw = ceilings_raw.get(dimension)
        if not isinstance(scope_raw, Mapping) or set(scope_raw) != set(_SCOPES):
            raise SpendBudgetError(
                "spend_policy_invalid",
                f"spend_budget.ceilings.{dimension} must declare session, agent, and lineage",
            )
        ceilings[dimension] = {
            scope: _non_negative_int(
                scope_raw.get(scope),
                f"spend_budget.ceilings.{dimension}.{scope}",
            )
            for scope in _SCOPES
        }

    claimed_lineage = raw.get("lineage_id")
    if lineage_id is not None and claimed_lineage is not None:
        normalized_claimed = _bounded_string(
            claimed_lineage,
            "spend_budget.lineage_id",
        )
        if normalized_claimed != lineage_id:
            raise SpendBudgetError(
                "spend_policy_invalid",
                "spend_budget.lineage_id conflicts with issuance lineage",
            )
    effective_lineage = lineage_id if lineage_id is not None else claimed_lineage
    if effective_lineage is not None:
        effective_lineage = _bounded_string(
            effective_lineage,
            "spend_budget.lineage_id",
        )
    elif require_lineage_id:
        raise SpendBudgetError(
            "spend_policy_invalid",
            "spend_budget.lineage_id is required at runtime",
        )

    normalized: dict[str, Any] = {
        "version": SPEND_BUDGET_VERSION,
        "currency": currency,
        "metered_tools": tools,
        "ceilings": ceilings,
    }
    if effective_lineage is not None:
        normalized["lineage_id"] = effective_lineage
    return normalized


@dataclass(frozen=True, slots=True)
class SpendQuote:
    """Immutable operator-controlled token price snapshot."""

    quote_id: str
    tool_name: str
    model: str
    currency: str
    input_micros_per_million_tokens: int
    output_micros_per_million_tokens: int
    valid_from: int
    valid_until: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "quote_id", _bounded_string(self.quote_id, "quote_id"))
        object.__setattr__(
            self, "tool_name", _bounded_string(self.tool_name, "tool_name")
        )
        object.__setattr__(self, "model", _bounded_string(self.model, "model"))
        object.__setattr__(self, "currency", _currency(self.currency))
        for field_name in (
            "input_micros_per_million_tokens",
            "output_micros_per_million_tokens",
            "valid_from",
            "valid_until",
        ):
            object.__setattr__(
                self,
                field_name,
                _non_negative_int(getattr(self, field_name), field_name),
            )
        if self.valid_until <= self.valid_from:
            raise SpendBudgetError(
                "spend_quote_invalid",
                "valid_until must be greater than valid_from",
            )

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "version": SPEND_QUOTE_VERSION,
            "quote_id": self.quote_id,
            "tool_name": self.tool_name,
            "model": self.model,
            "currency": self.currency,
            "input_micros_per_million_tokens": self.input_micros_per_million_tokens,
            "output_micros_per_million_tokens": self.output_micros_per_million_tokens,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(self.canonical_payload())
        ).hexdigest()

    def reserve_amounts(self, input_tokens: int, output_tokens: int) -> dict[str, int]:
        input_count = _non_negative_int(input_tokens, "input_tokens")
        output_count = _non_negative_int(output_tokens, "output_tokens")
        total_tokens = input_count + output_count
        if total_tokens > MAX_SAFE_INTEGER:
            raise SpendBudgetError("spend_amount_overflow")
        input_micros = _ceil_div(
            input_count * self.input_micros_per_million_tokens,
            1_000_000,
        )
        output_micros = _ceil_div(
            output_count * self.output_micros_per_million_tokens,
            1_000_000,
        )
        money = input_micros + output_micros
        if money > MAX_SAFE_INTEGER:
            raise SpendBudgetError("spend_amount_overflow")
        return {"tokens": total_tokens, "currency_micros": money}


def _ceil_div(numerator: int, denominator: int) -> int:
    return (numerator + denominator - 1) // denominator


class StaticSpendQuoteStore:
    """In-memory immutable quote set loaded by the operator at startup."""

    def __init__(self, quotes: Iterable[SpendQuote]) -> None:
        by_id: dict[str, SpendQuote] = {}
        for quote in quotes:
            if not isinstance(quote, SpendQuote):
                raise TypeError("quotes must contain SpendQuote values")
            if quote.quote_id in by_id:
                raise SpendBudgetError(
                    "spend_quote_invalid",
                    f"duplicate quote_id {quote.quote_id!r}",
                )
            by_id[quote.quote_id] = quote
        self._quotes = by_id

    def resolve(
        self,
        quote_id: str,
        *,
        tool_name: str,
        model: str,
        currency: str,
        now: int | None = None,
    ) -> SpendQuote:
        quote = self._quotes.get(quote_id)
        if quote is None:
            raise SpendBudgetError("spend_quote_unknown")
        if quote.tool_name != tool_name or quote.model != model:
            raise SpendBudgetError("spend_quote_scope_mismatch")
        if quote.currency != currency:
            raise SpendBudgetError("spend_quote_currency_mismatch")
        observed = int(time.time() if now is None else now)
        if observed < quote.valid_from:
            raise SpendBudgetError("spend_quote_not_yet_valid")
        if observed >= quote.valid_until:
            raise SpendBudgetError("spend_quote_expired")
        return quote


@dataclass(frozen=True, slots=True)
class SpendReservationRequest:
    request_id: str
    quote_id: str
    model: str
    max_input_tokens: int
    max_output_tokens: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "request_id",
            _bounded_string(self.request_id, "request_id", max_bytes=512),
        )
        object.__setattr__(self, "quote_id", _bounded_string(self.quote_id, "quote_id"))
        object.__setattr__(self, "model", _bounded_string(self.model, "model"))
        object.__setattr__(
            self,
            "max_input_tokens",
            _non_negative_int(self.max_input_tokens, "max_input_tokens"),
        )
        object.__setattr__(
            self,
            "max_output_tokens",
            _non_negative_int(self.max_output_tokens, "max_output_tokens"),
        )
        if self.max_input_tokens + self.max_output_tokens <= 0:
            raise SpendBudgetError(
                "spend_request_invalid",
                "at least one reserved token is required",
            )


@dataclass(frozen=True, slots=True)
class SpendReservationResult:
    accepted: bool
    reason_code: str
    reservation_hash: str
    quote_digest: str
    currency: str
    reserved: dict[str, int]
    remaining: dict[str, dict[str, int]]
    idempotent: bool = False


@dataclass(frozen=True, slots=True)
class SpendCloseResult:
    operation: str
    reason_code: str
    reservation_hash: str
    quote_digest: str
    currency: str
    reserved: dict[str, int]
    actual: dict[str, int]
    refunded: dict[str, int]
    remaining: dict[str, dict[str, int]]
    idempotent: bool = False
    reconciled: bool = False


class SpendBudgetLedger:
    def reserve(
        self,
        *,
        policy: Mapping[str, Any],
        session_id: str,
        agent_id: str,
        request: SpendReservationRequest,
        quote: SpendQuote,
        now: int | None = None,
        retention_until: int | None = None,
    ) -> SpendReservationResult:
        raise NotImplementedError

    def cancel(
        self,
        *,
        lineage_id: str,
        session_id: str,
        request_id: str,
        reason_code: str,
    ) -> SpendCloseResult:
        raise NotImplementedError

    def settle(
        self,
        *,
        lineage_id: str,
        session_id: str,
        request_id: str,
        actual_input_tokens: int,
        actual_output_tokens: int,
        usage_proof_digest: str | None,
    ) -> SpendCloseResult:
        raise NotImplementedError

    def quarantine(
        self,
        *,
        lineage_id: str,
        session_id: str,
        request_id: str,
        reason_code: str,
    ) -> SpendCloseResult:
        raise NotImplementedError

    def quarantine_stale(
        self,
        *,
        lineage_id: str,
        session_id: str,
        older_than_s: int,
        now: int | None = None,
    ) -> list[SpendCloseResult]:
        raise NotImplementedError

    def snapshot(self, lineage_id: str) -> dict[str, Any]:
        raise NotImplementedError

    def has_active_reservations(
        self,
        *,
        lineage_id: str,
        session_id: str,
    ) -> bool:
        raise NotImplementedError


class _ProcessLock:
    __slots__ = ("lock", "__weakref__")

    def __init__(self) -> None:
        self.lock = threading.RLock()


_LOCKS: weakref.WeakValueDictionary[str, _ProcessLock] = weakref.WeakValueDictionary()
_LOCKS_GUARD = threading.Lock()


class FileSpendBudgetLedger(SpendBudgetLedger):
    """File-backed, cross-process spend ledger rooted under ``state_dir``."""

    def __init__(self, state_dir: str | Path) -> None:
        self.state_dir = Path(state_dir).expanduser()
        self.ledger_dir = self.state_dir / "spend_budgets"
        self.ledger_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.ledger_dir.chmod(0o700)

    def reserve(
        self,
        *,
        policy: Mapping[str, Any],
        session_id: str,
        agent_id: str,
        request: SpendReservationRequest,
        quote: SpendQuote,
        now: int | None = None,
        retention_until: int | None = None,
    ) -> SpendReservationResult:
        normalized = normalize_spend_budget(policy, require_lineage_id=True)
        lineage_id = str(normalized["lineage_id"])
        if quote.currency != normalized["currency"]:
            raise SpendBudgetError("spend_quote_currency_mismatch")
        if quote.quote_id != request.quote_id or quote.model != request.model:
            raise SpendBudgetError("spend_quote_scope_mismatch")
        observed = int(time.time() if now is None else now)
        if observed < quote.valid_from:
            raise SpendBudgetError("spend_quote_not_yet_valid")
        if observed >= quote.valid_until:
            raise SpendBudgetError("spend_quote_expired")
        terminal_retention = _non_negative_int(
            quote.valid_until if retention_until is None else retention_until,
            "retention_until",
        )
        if terminal_retention <= observed:
            raise SpendBudgetError("spend_retention_expired")

        reserved = quote.reserve_amounts(
            request.max_input_tokens,
            request.max_output_tokens,
        )
        scope_refs = {
            "session": _scope_hash("session", session_id),
            "agent": _scope_hash("agent", agent_id),
            "lineage": _scope_hash("lineage", lineage_id),
        }
        reservation_hash = _reservation_hash(request.request_id)
        fingerprint_payload = {
            "version": SPEND_LEDGER_VERSION,
            "lineage_id_hash": _scope_hash("lineage", lineage_id),
            "scope_refs": scope_refs,
            "policy": normalized,
            "quote_digest": quote.digest,
            "request": {
                "request_id_hash": reservation_hash,
                "quote_id_hash": _opaque_hash("quote", request.quote_id),
                "model_hash": _opaque_hash("model", request.model),
                "max_input_tokens": request.max_input_tokens,
                "max_output_tokens": request.max_output_tokens,
            },
        }
        fingerprint = hashlib.sha256(
            canonical_json_bytes(fingerprint_payload)
        ).hexdigest()

        with self._locked(lineage_id):
            payload = self._load(lineage_id)
            self._prune_terminal_records(payload, now=observed)
            active = payload["reservations"]
            closed = payload["closed_reservations"]
            quarantined = payload["quarantined_reservations"]

            prior_active = active.get(reservation_hash)
            if isinstance(prior_active, dict):
                self._require_fingerprint(prior_active, fingerprint)
                return self._result_from_record(
                    prior_active,
                    accepted=False,
                    reason_code="spend_request_already_reserved",
                    payload=payload,
                    idempotent=True,
                )
            prior_quarantined = quarantined.get(reservation_hash)
            if isinstance(prior_quarantined, dict):
                self._require_fingerprint(prior_quarantined, fingerprint)
                return self._result_from_record(
                    prior_quarantined,
                    accepted=False,
                    reason_code="spend_reservation_quarantined",
                    payload=payload,
                    idempotent=True,
                )
            prior_closed = closed.get(reservation_hash)
            if isinstance(prior_closed, dict):
                self._require_fingerprint(prior_closed, fingerprint)
                reason = str(
                    prior_closed.get("reason_code") or "spend_request_already_closed"
                )
                return self._result_from_record(
                    prior_closed,
                    accepted=False,
                    reason_code=reason,
                    payload=payload,
                    idempotent=True,
                )
            if (
                sum(len(container) for container in (active, closed, quarantined))
                >= MAX_LEDGER_RECORDS
            ):
                raise SpendBudgetError("spend_ledger_capacity_exhausted")

            remaining = self._remaining(payload, normalized, scope_refs)
            breach = _first_breach(reserved, remaining)
            record = {
                "fingerprint": fingerprint,
                "reservation_hash": reservation_hash,
                "quote_digest": quote.digest,
                "quote_id_hash": _opaque_hash("quote", request.quote_id),
                "currency": quote.currency,
                "reserved": dict(reserved),
                "scope_refs": scope_refs,
                "ceilings": normalized["ceilings"],
                "max_input_tokens": request.max_input_tokens,
                "max_output_tokens": request.max_output_tokens,
                "pricing": {
                    "input_micros_per_million_tokens": quote.input_micros_per_million_tokens,
                    "output_micros_per_million_tokens": quote.output_micros_per_million_tokens,
                },
                "created_at": observed,
                "retention_until": terminal_retention,
            }
            if breach is not None:
                scope, dimension = breach
                record.update(
                    {
                        "operation": "reject",
                        "reason_code": f"spend_{scope}_{dimension}_exhausted",
                        "remaining_at_decision": remaining,
                        "closed_at": observed,
                    }
                )
                closed[reservation_hash] = record
                self._persist(lineage_id, payload)
                return self._result_from_record(
                    record,
                    accepted=False,
                    reason_code=str(record["reason_code"]),
                    payload=payload,
                )

            for scope in _SCOPES:
                totals = self._scope_totals(payload, scope_refs[scope])
                for dimension in _DIMENSIONS:
                    totals["reserved"][dimension] += reserved[dimension]
            active[reservation_hash] = record
            self._persist(lineage_id, payload)
            return self._result_from_record(
                record,
                accepted=True,
                reason_code="spend_reserved",
                payload=payload,
            )

    def cancel(
        self,
        *,
        lineage_id: str,
        session_id: str,
        request_id: str,
        reason_code: str,
    ) -> SpendCloseResult:
        return self._close_without_spend(
            lineage_id=lineage_id,
            session_id=session_id,
            request_id=request_id,
            operation="release",
            reason_code=_bounded_string(reason_code, "reason_code"),
        )

    def settle(
        self,
        *,
        lineage_id: str,
        session_id: str,
        request_id: str,
        actual_input_tokens: int,
        actual_output_tokens: int,
        usage_proof_digest: str | None,
    ) -> SpendCloseResult:
        input_tokens = _non_negative_int(actual_input_tokens, "actual_input_tokens")
        output_tokens = _non_negative_int(actual_output_tokens, "actual_output_tokens")
        reservation_hash = _reservation_hash(request_id)
        settlement_payload = {
            "reservation_hash": reservation_hash,
            "actual_input_tokens": input_tokens,
            "actual_output_tokens": output_tokens,
            "usage_proof_digest": usage_proof_digest,
        }
        settlement_fingerprint = hashlib.sha256(
            canonical_json_bytes(settlement_payload)
        ).hexdigest()

        with self._locked(lineage_id):
            payload = self._load(lineage_id)
            closed = payload["closed_reservations"]
            prior = closed.get(reservation_hash)
            if isinstance(prior, dict):
                self._require_session_scope(prior, session_id)
                if prior.get("operation") != "settle":
                    raise SpendBudgetConflictError(
                        "spend_settlement_conflict",
                        "reservation is already closed without settlement",
                    )
                if prior.get("settlement_fingerprint") != settlement_fingerprint:
                    raise SpendBudgetConflictError(
                        "spend_settlement_conflict",
                        "settlement replay carries different usage evidence",
                    )
                return self._close_result(prior, payload, idempotent=True)

            active = payload["reservations"]
            quarantined = payload["quarantined_reservations"]
            record = active.get(reservation_hash)
            reconciled = False
            if not isinstance(record, dict):
                record = quarantined.get(reservation_hash)
                reconciled = isinstance(record, dict)
            if not isinstance(record, dict):
                raise SpendBudgetError("spend_reservation_unknown")
            self._require_session_scope(record, session_id)

            proof_valid = (
                isinstance(usage_proof_digest, str)
                and _DIGEST_RE.fullmatch(usage_proof_digest) is not None
            )
            within_reservation = input_tokens <= int(
                record["max_input_tokens"]
            ) and output_tokens <= int(record["max_output_tokens"])
            if not proof_valid or not within_reservation:
                reason = (
                    "spend_settlement_evidence_missing"
                    if not proof_valid
                    else "spend_usage_exceeds_reservation"
                )
                if not reconciled:
                    del active[reservation_hash]
                    record = dict(record)
                    record.update(
                        {
                            "operation": "quarantine",
                            "reason_code": reason,
                            "quarantined_at": int(time.time()),
                        }
                    )
                    quarantined[reservation_hash] = record
                    self._persist(lineage_id, payload)
                return self._close_result(record, payload, reconciled=False)

            pricing = record["pricing"]
            actual = {
                "tokens": input_tokens + output_tokens,
                "currency_micros": _ceil_div(
                    input_tokens * int(pricing["input_micros_per_million_tokens"]),
                    1_000_000,
                )
                + _ceil_div(
                    output_tokens * int(pricing["output_micros_per_million_tokens"]),
                    1_000_000,
                ),
            }
            reserved = {key: int(record["reserved"][key]) for key in _DIMENSIONS}
            if any(actual[key] > reserved[key] for key in _DIMENSIONS):
                if not reconciled:
                    del active[reservation_hash]
                    record = dict(record)
                    record.update(
                        {
                            "operation": "quarantine",
                            "reason_code": "spend_usage_exceeds_reservation",
                            "quarantined_at": int(time.time()),
                        }
                    )
                    quarantined[reservation_hash] = record
                    self._persist(lineage_id, payload)
                return self._close_result(record, payload, reconciled=False)

            for scope in _SCOPES:
                totals = self._scope_totals(payload, record["scope_refs"][scope])
                for dimension in _DIMENSIONS:
                    totals["reserved"][dimension] -= reserved[dimension]
                    totals["spent"][dimension] += actual[dimension]
            if reconciled:
                del quarantined[reservation_hash]
            else:
                del active[reservation_hash]
            record = dict(record)
            record.update(
                {
                    "operation": "settle",
                    "reason_code": "spend_settled",
                    "settlement_fingerprint": settlement_fingerprint,
                    "usage_proof_digest": usage_proof_digest,
                    "actual": actual,
                    "refunded": {
                        key: reserved[key] - actual[key] for key in _DIMENSIONS
                    },
                    "settled_at": int(time.time()),
                    "reconciled": reconciled,
                }
            )
            closed[reservation_hash] = record
            self._persist(lineage_id, payload)
            return self._close_result(record, payload, reconciled=reconciled)

    def quarantine(
        self,
        *,
        lineage_id: str,
        session_id: str,
        request_id: str,
        reason_code: str,
    ) -> SpendCloseResult:
        reservation_hash = _reservation_hash(request_id)
        reason = _bounded_string(reason_code, "reason_code")
        with self._locked(lineage_id):
            payload = self._load(lineage_id)
            active = payload["reservations"]
            quarantined = payload["quarantined_reservations"]
            prior = quarantined.get(reservation_hash)
            if isinstance(prior, dict):
                self._require_session_scope(prior, session_id)
                if prior.get("reason_code") != reason:
                    raise SpendBudgetConflictError("spend_quarantine_conflict")
                return self._close_result(prior, payload, idempotent=True)
            prior_closed = payload["closed_reservations"].get(reservation_hash)
            if isinstance(prior_closed, dict):
                self._require_session_scope(prior_closed, session_id)
                raise SpendBudgetConflictError("spend_reservation_already_closed")
            record = active.get(reservation_hash)
            if not isinstance(record, dict):
                raise SpendBudgetError("spend_reservation_unknown")
            self._require_session_scope(record, session_id)
            del active[reservation_hash]
            record = dict(record)
            record.update(
                {
                    "operation": "quarantine",
                    "reason_code": reason,
                    "quarantined_at": int(time.time()),
                }
            )
            quarantined[reservation_hash] = record
            self._persist(lineage_id, payload)
            return self._close_result(record, payload)

    def quarantine_stale(
        self,
        *,
        lineage_id: str,
        session_id: str,
        older_than_s: int,
        now: int | None = None,
    ) -> list[SpendCloseResult]:
        age = _non_negative_int(older_than_s, "older_than_s")
        observed = int(time.time() if now is None else now)
        cutoff = observed - age
        session_ref = _scope_hash("session", session_id)
        results: list[SpendCloseResult] = []
        with self._locked(lineage_id):
            payload = self._load(lineage_id)
            active = payload["reservations"]
            quarantined = payload["quarantined_reservations"]
            for reservation_hash, original in list(active.items()):
                if original.get("scope_refs", {}).get("session") != session_ref:
                    continue
                if int(original.get("created_at", observed)) > cutoff:
                    continue
                record = dict(original)
                record.update(
                    {
                        "operation": "quarantine",
                        "reason_code": "spend_reservation_stale",
                        "quarantined_at": observed,
                    }
                )
                del active[reservation_hash]
                quarantined[reservation_hash] = record
                results.append(self._close_result(record, payload))
            if results:
                self._persist(lineage_id, payload)
        return results

    def snapshot(self, lineage_id: str) -> dict[str, Any]:
        with self._locked(lineage_id):
            return self._load(lineage_id)

    def has_active_reservations(
        self,
        *,
        lineage_id: str,
        session_id: str,
    ) -> bool:
        session_ref = _scope_hash("session", session_id)
        with self._locked(lineage_id):
            payload = self._load(lineage_id)
            return any(
                record.get("scope_refs", {}).get("session") == session_ref
                for record in payload["reservations"].values()
            )

    def _close_without_spend(
        self,
        *,
        lineage_id: str,
        session_id: str,
        request_id: str,
        operation: str,
        reason_code: str,
    ) -> SpendCloseResult:
        reservation_hash = _reservation_hash(request_id)
        with self._locked(lineage_id):
            payload = self._load(lineage_id)
            closed = payload["closed_reservations"]
            prior = closed.get(reservation_hash)
            if isinstance(prior, dict):
                self._require_session_scope(prior, session_id)
                if (
                    prior.get("operation") != operation
                    or prior.get("reason_code") != reason_code
                ):
                    raise SpendBudgetConflictError("spend_close_conflict")
                return self._close_result(prior, payload, idempotent=True)
            record = payload["reservations"].get(reservation_hash)
            if not isinstance(record, dict):
                raise SpendBudgetError("spend_reservation_unknown")
            self._require_session_scope(record, session_id)
            del payload["reservations"][reservation_hash]
            reserved = {key: int(record["reserved"][key]) for key in _DIMENSIONS}
            for scope in _SCOPES:
                totals = self._scope_totals(payload, record["scope_refs"][scope])
                for dimension in _DIMENSIONS:
                    totals["reserved"][dimension] -= reserved[dimension]
            record = dict(record)
            record.update(
                {
                    "operation": operation,
                    "reason_code": reason_code,
                    "actual": {key: 0 for key in _DIMENSIONS},
                    "refunded": reserved,
                    "closed_at": int(time.time()),
                }
            )
            closed[reservation_hash] = record
            self._persist(lineage_id, payload)
            return self._close_result(record, payload)

    @staticmethod
    def _require_fingerprint(record: Mapping[str, Any], fingerprint: str) -> None:
        if record.get("fingerprint") != fingerprint:
            raise SpendBudgetConflictError(
                "spend_request_conflict",
                "request_id was reused with different reservation semantics",
            )

    @staticmethod
    def _require_session_scope(record: Mapping[str, Any], session_id: str) -> None:
        expected = _scope_hash("session", session_id)
        if record.get("scope_refs", {}).get("session") != expected:
            raise SpendBudgetConflictError("spend_reservation_session_mismatch")

    def _result_from_record(
        self,
        record: Mapping[str, Any],
        *,
        accepted: bool,
        reason_code: str,
        payload: dict[str, Any],
        idempotent: bool = False,
    ) -> SpendReservationResult:
        return SpendReservationResult(
            accepted=accepted,
            reason_code=reason_code,
            reservation_hash=str(record["reservation_hash"]),
            quote_digest=str(record["quote_digest"]),
            currency=str(record["currency"]),
            reserved={key: int(record["reserved"][key]) for key in _DIMENSIONS},
            remaining=self._remaining_from_record(payload, record),
            idempotent=idempotent,
        )

    def _close_result(
        self,
        record: Mapping[str, Any],
        payload: dict[str, Any],
        *,
        idempotent: bool = False,
        reconciled: bool | None = None,
    ) -> SpendCloseResult:
        reserved = {key: int(record["reserved"][key]) for key in _DIMENSIONS}
        operation = str(record.get("operation", "quarantine"))
        actual_raw = record.get("actual") if operation == "settle" else None
        actual = (
            {key: int(actual_raw[key]) for key in _DIMENSIONS}
            if isinstance(actual_raw, Mapping)
            else {key: 0 for key in _DIMENSIONS}
        )
        refunded_raw = record.get("refunded")
        refunded = (
            {key: int(refunded_raw[key]) for key in _DIMENSIONS}
            if isinstance(refunded_raw, Mapping)
            else {key: 0 for key in _DIMENSIONS}
        )
        return SpendCloseResult(
            operation=operation,
            reason_code=str(record.get("reason_code", "spend_reservation_quarantined")),
            reservation_hash=str(record["reservation_hash"]),
            quote_digest=str(record["quote_digest"]),
            currency=str(record["currency"]),
            reserved=reserved,
            actual=actual,
            refunded=refunded,
            remaining=self._remaining_from_record(payload, record),
            idempotent=idempotent,
            reconciled=bool(
                record.get("reconciled", False) if reconciled is None else reconciled
            ),
        )

    def _remaining_from_record(
        self,
        payload: dict[str, Any],
        record: Mapping[str, Any],
    ) -> dict[str, dict[str, int]]:
        policy = {
            "version": SPEND_BUDGET_VERSION,
            "currency": record["currency"],
            "metered_tools": ["ledger_projection"],
            "ceilings": record["ceilings"],
            "lineage_id": "ledger_projection",
        }
        return self._remaining(payload, policy, record["scope_refs"])

    def _remaining(
        self,
        payload: dict[str, Any],
        policy: Mapping[str, Any],
        scope_refs: Mapping[str, str],
    ) -> dict[str, dict[str, int]]:
        ceilings = policy["ceilings"]
        remaining: dict[str, dict[str, int]] = {}
        for scope in _SCOPES:
            totals = self._scope_totals(payload, scope_refs[scope])
            remaining[scope] = {
                dimension: max(
                    0,
                    int(ceilings[dimension][scope])
                    - int(totals["spent"][dimension])
                    - int(totals["reserved"][dimension]),
                )
                for dimension in _DIMENSIONS
            }
        return remaining

    @staticmethod
    def _scope_totals(
        payload: dict[str, Any], scope_ref: str
    ) -> dict[str, dict[str, int]]:
        scopes = payload["scopes"]
        totals = scopes.get(scope_ref)
        if totals is None:
            totals = {
                "spent": {key: 0 for key in _DIMENSIONS},
                "reserved": {key: 0 for key in _DIMENSIONS},
            }
            scopes[scope_ref] = totals
        else:
            FileSpendBudgetLedger._validate_scope_totals(totals)
        return totals

    @staticmethod
    def _validate_ledger_int(value: Any) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or value > MAX_SAFE_INTEGER
        ):
            raise SpendBudgetError("spend_ledger_invalid")
        return value

    @classmethod
    def _validate_amounts(cls, value: Any) -> dict[str, int]:
        if not isinstance(value, dict) or set(value) != set(_DIMENSIONS):
            raise SpendBudgetError("spend_ledger_invalid")
        return {
            dimension: cls._validate_ledger_int(value[dimension])
            for dimension in _DIMENSIONS
        }

    @classmethod
    def _validate_scope_totals(cls, value: Any) -> None:
        if not isinstance(value, dict) or set(value) != {"spent", "reserved"}:
            raise SpendBudgetError("spend_ledger_invalid")
        cls._validate_amounts(value["spent"])
        cls._validate_amounts(value["reserved"])

    @classmethod
    def _validate_record(
        cls,
        reservation_hash: str,
        record: Any,
        *,
        container: str,
    ) -> None:
        if not isinstance(record, dict):
            raise SpendBudgetError("spend_ledger_invalid")
        if not _DIGEST_RE.fullmatch(reservation_hash):
            raise SpendBudgetError("spend_ledger_invalid")
        for digest_field in (
            "fingerprint",
            "reservation_hash",
            "quote_digest",
            "quote_id_hash",
        ):
            digest = record.get(digest_field)
            if not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
                raise SpendBudgetError("spend_ledger_invalid")
        if record["reservation_hash"] != reservation_hash:
            raise SpendBudgetError("spend_ledger_invalid")
        if (
            not isinstance(record.get("currency"), str)
            or _CURRENCY_RE.fullmatch(record["currency"]) is None
        ):
            raise SpendBudgetError("spend_ledger_invalid")
        cls._validate_amounts(record.get("reserved"))
        for int_field in (
            "max_input_tokens",
            "max_output_tokens",
            "created_at",
            "retention_until",
        ):
            cls._validate_ledger_int(record.get(int_field))
        if record["retention_until"] <= record["created_at"]:
            raise SpendBudgetError("spend_ledger_invalid")

        scope_refs = record.get("scope_refs")
        if not isinstance(scope_refs, dict) or set(scope_refs) != set(_SCOPES):
            raise SpendBudgetError("spend_ledger_invalid")
        if any(
            not isinstance(scope_refs[scope], str)
            or _DIGEST_RE.fullmatch(scope_refs[scope]) is None
            for scope in _SCOPES
        ):
            raise SpendBudgetError("spend_ledger_invalid")

        ceilings = record.get("ceilings")
        if not isinstance(ceilings, dict) or set(ceilings) != set(_DIMENSIONS):
            raise SpendBudgetError("spend_ledger_invalid")
        for dimension in _DIMENSIONS:
            values = ceilings.get(dimension)
            if not isinstance(values, dict) or set(values) != set(_SCOPES):
                raise SpendBudgetError("spend_ledger_invalid")
            for scope in _SCOPES:
                cls._validate_ledger_int(values[scope])

        pricing = record.get("pricing")
        if not isinstance(pricing, dict) or set(pricing) != {
            "input_micros_per_million_tokens",
            "output_micros_per_million_tokens",
        }:
            raise SpendBudgetError("spend_ledger_invalid")
        for rate in pricing.values():
            cls._validate_ledger_int(rate)

        operation = record.get("operation")
        if container == "reservations":
            if operation is not None:
                raise SpendBudgetError("spend_ledger_invalid")
            return
        if container == "quarantined_reservations":
            if operation != "quarantine":
                raise SpendBudgetError("spend_ledger_invalid")
            return
        if operation not in {"reject", "release", "settle"}:
            raise SpendBudgetError("spend_ledger_invalid")
        if operation == "settle":
            actual = cls._validate_amounts(record.get("actual"))
            refunded = cls._validate_amounts(record.get("refunded"))
            reserved = cls._validate_amounts(record.get("reserved"))
            if any(
                actual[dimension] + refunded[dimension] != reserved[dimension]
                for dimension in _DIMENSIONS
            ):
                raise SpendBudgetError("spend_ledger_accounting_mismatch")
            for digest_field in ("settlement_fingerprint", "usage_proof_digest"):
                digest = record.get(digest_field)
                if not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
                    raise SpendBudgetError("spend_ledger_invalid")
        elif operation == "release":
            actual = cls._validate_amounts(record.get("actual"))
            refunded = cls._validate_amounts(record.get("refunded"))
            reserved = cls._validate_amounts(record.get("reserved"))
            if actual != {dimension: 0 for dimension in _DIMENSIONS}:
                raise SpendBudgetError("spend_ledger_accounting_mismatch")
            if refunded != reserved:
                raise SpendBudgetError("spend_ledger_accounting_mismatch")

    @classmethod
    def _validate_payload(cls, payload: dict[str, Any], lineage_id: str) -> None:
        if payload.get("version") != SPEND_LEDGER_VERSION:
            raise SpendBudgetError("spend_ledger_invalid")
        if payload.get("lineage_id_hash") != _scope_hash("lineage", lineage_id):
            raise SpendBudgetError("spend_ledger_lineage_mismatch")
        for field_name in (
            "scopes",
            "archived_spent",
            "reservations",
            "closed_reservations",
            "quarantined_reservations",
        ):
            if not isinstance(payload.get(field_name), dict):
                raise SpendBudgetError("spend_ledger_invalid")

        scopes = payload["scopes"]
        for scope_ref, totals in scopes.items():
            if (
                not isinstance(scope_ref, str)
                or _DIGEST_RE.fullmatch(scope_ref) is None
            ):
                raise SpendBudgetError("spend_ledger_invalid")
            cls._validate_scope_totals(totals)
        archived_spent = payload["archived_spent"]
        for scope_ref, amounts in archived_spent.items():
            if scope_ref not in scopes:
                raise SpendBudgetError("spend_ledger_invalid")
            cls._validate_amounts(amounts)

        for container_name in (
            "reservations",
            "closed_reservations",
            "quarantined_reservations",
        ):
            for reservation_hash, record in payload[container_name].items():
                cls._validate_record(
                    reservation_hash,
                    record,
                    container=container_name,
                )
                if any(ref not in scopes for ref in record["scope_refs"].values()):
                    raise SpendBudgetError("spend_ledger_invalid")

        expected_reserved = {
            scope_ref: {dimension: 0 for dimension in _DIMENSIONS}
            for scope_ref in scopes
        }
        expected_spent = {
            scope_ref: {
                dimension: int(archived_spent.get(scope_ref, {}).get(dimension, 0))
                for dimension in _DIMENSIONS
            }
            for scope_ref in scopes
        }
        for container_name in ("reservations", "quarantined_reservations"):
            for record in payload[container_name].values():
                for scope_ref in record["scope_refs"].values():
                    for dimension in _DIMENSIONS:
                        expected_reserved[scope_ref][dimension] += int(
                            record["reserved"][dimension]
                        )
        for record in payload["closed_reservations"].values():
            if record.get("operation") != "settle":
                continue
            for scope_ref in record["scope_refs"].values():
                for dimension in _DIMENSIONS:
                    expected_spent[scope_ref][dimension] += int(
                        record["actual"][dimension]
                    )
        for scope_ref, totals in scopes.items():
            if totals["reserved"] != expected_reserved[scope_ref]:
                raise SpendBudgetError("spend_ledger_accounting_mismatch")
            if totals["spent"] != expected_spent[scope_ref]:
                raise SpendBudgetError("spend_ledger_accounting_mismatch")

    @classmethod
    def _prune_terminal_records(cls, payload: dict[str, Any], *, now: int) -> None:
        closed = payload["closed_reservations"]
        archived_spent = payload["archived_spent"]
        for reservation_hash, record in list(closed.items()):
            if int(record["retention_until"]) > now:
                continue
            if record.get("operation") == "settle":
                for scope_ref in record["scope_refs"].values():
                    amounts = archived_spent.setdefault(
                        scope_ref,
                        {dimension: 0 for dimension in _DIMENSIONS},
                    )
                    for dimension in _DIMENSIONS:
                        amounts[dimension] += int(record["actual"][dimension])
            del closed[reservation_hash]

    def _path(self, lineage_id: str) -> Path:
        return self.ledger_dir / f"{_scope_hash('lineage', lineage_id)}.json"

    def _lock_path(self, lineage_id: str) -> Path:
        return self._path(lineage_id).with_suffix(".lock")

    @contextlib.contextmanager
    def _locked(self, lineage_id: str):
        lock_path = self._lock_path(lineage_id)
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        os.close(fd)
        with contextlib.suppress(OSError):
            os.chmod(lock_path, 0o600)
        key = str(lock_path.resolve())
        with _LOCKS_GUARD:
            process_lock = _LOCKS.get(key)
            if process_lock is None:
                process_lock = _ProcessLock()
                _LOCKS[key] = process_lock
        with process_lock.lock:
            with lock_path.open("a+b") as lock_handle:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    def _load(self, lineage_id: str) -> dict[str, Any]:
        path = self._path(lineage_id)
        if not path.exists():
            return {
                "version": SPEND_LEDGER_VERSION,
                "lineage_id_hash": _scope_hash("lineage", lineage_id),
                "scopes": {},
                "archived_spent": {},
                "reservations": {},
                "closed_reservations": {},
                "quarantined_reservations": {},
            }
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise SpendBudgetError("spend_ledger_invalid")
        self._validate_payload(payload, lineage_id)
        return payload

    def _persist(self, lineage_id: str, payload: dict[str, Any]) -> None:
        self._validate_payload(payload, lineage_id)
        path = self._path(lineage_id)
        tmp = path.with_name(f"{path.stem}.{uuid.uuid4().hex}.tmp")
        fd = -1
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
            directory_fd = os.open(self.ledger_dir, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            if fd >= 0:
                os.close(fd)
            with contextlib.suppress(OSError):
                tmp.unlink()
            raise


def _scope_hash(scope: str, value: str) -> str:
    return _opaque_hash(f"scope:{scope}", value)


def _reservation_hash(request_id: str) -> str:
    return _opaque_hash(
        "spend-reservation", _bounded_string(request_id, "request_id", max_bytes=512)
    )


def _opaque_hash(domain: str, value: str) -> str:
    return hashlib.sha256(f"ardur:{domain}:v1\0{value}".encode("utf-8")).hexdigest()


def _first_breach(
    requested: Mapping[str, int],
    remaining: Mapping[str, Mapping[str, int]],
) -> tuple[str, str] | None:
    for scope in _SCOPES:
        for dimension in _DIMENSIONS:
            if int(requested[dimension]) > int(remaining[scope][dimension]):
                return scope, dimension
    return None
