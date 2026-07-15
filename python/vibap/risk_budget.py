"""Typed dangerous-action impact contracts and durable blast-radius budgets.

Risk facts are derived locally from authenticated tool schemas and a closed,
declarative extractor vocabulary.  A signed ``risk_budget`` passport claim
binds each governed tool to its contract digest, per-action caps, and additive
session/agent/lineage ceilings.  The file ledger reserves every numeric fact
across every scope in one transaction before the tool may execute.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import stat
import threading
import time
import uuid
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from .canonical_json import canonical_json_bytes

RISK_BUDGET_VERSION = 1
MAX_RISK_VALUE = 2**63 - 1
MAX_CONTRACT_BYTES = 64 * 1024
MAX_ARGUMENT_BYTES = 64 * 1024
MAX_SCHEMA_NODES = 4096
MAX_SCHEMA_DEPTH = 64
MAX_RESERVATIONS = 4096
QUARANTINE_RETENTION_S = 24 * 60 * 60
REPLAY_TOMBSTONE_RETENTION_S = 60 * 60

NUMERIC_RISK_FACTS = (
    "destructive_targets",
    "objects_affected",
    "bytes_affected",
)
RISK_SCOPES = ("session", "agent", "lineage")
CATEGORICAL_RISK_LEVELS: dict[str, tuple[str, ...]] = {
    "secret_sensitivity": (
        "none",
        "public",
        "internal",
        "confidential",
        "restricted",
        "regulated",
        "unknown",
    ),
    "destination_risk": (
        "local",
        "private_network",
        "trusted_service",
        "public_internet",
        "untrusted",
        "unknown",
    ),
    "filesystem_scope": (
        "none",
        "declared",
        "workspace",
        "external",
        "system",
        "unknown",
    ),
    "irreversibility": (
        "reversible",
        "compensatable",
        "irreversible",
        "unknown",
    ),
}
ALL_RISK_FACTS = frozenset(NUMERIC_RISK_FACTS) | frozenset(CATEGORICAL_RISK_LEVELS)
EXTRACTOR_KINDS = frozenset({"integer", "array_length", "constant", "enum"})


class RiskBudgetError(ValueError):
    """Fail-closed risk policy, contract, extraction, or ledger error."""


class RiskFactError(RiskBudgetError):
    """A trusted contract could not derive a valid typed risk fact."""


class RiskBudgetConflictError(RiskBudgetError):
    """A request id was replayed with different authorization semantics."""


class RiskBudgetReplayError(RiskBudgetError):
    """A request id already has an active or terminal ledger record."""


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RiskBudgetError(f"{label} must be a JSON object")
    return dict(value)


def _require_string(value: Any, label: str, *, max_bytes: int = 256) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RiskBudgetError(f"{label} must be a non-empty string")
    normalized = value.strip()
    if len(normalized.encode("utf-8")) > max_bytes:
        raise RiskBudgetError(f"{label} exceeds {max_bytes} bytes")
    return normalized


def _require_risk_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RiskBudgetError(f"{label} must be an integer")
    if value < 0 or value > MAX_RISK_VALUE:
        raise RiskBudgetError(f"{label} must be between 0 and {MAX_RISK_VALUE}")
    return value


def _bounded_json_bytes(value: Any, label: str, limit: int) -> bytes:
    try:
        encoded = canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        raise RiskBudgetError(f"{label} must be RFC 8785 canonicalizable JSON") from exc
    if len(encoded) > limit:
        raise RiskBudgetError(f"{label} exceeds {limit} canonical bytes")
    return encoded


def _validate_schema_shape(value: Any) -> None:
    nodes = 0

    def visit(node: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_SCHEMA_NODES:
            raise RiskBudgetError("tool input schema exceeds the node limit")
        if depth > MAX_SCHEMA_DEPTH:
            raise RiskBudgetError("tool input schema exceeds the nesting limit")
        if isinstance(node, dict):
            for key, child in node.items():
                if key in {"$ref", "$dynamicRef", "$recursiveRef"}:
                    if not isinstance(child, str) or not child.startswith("#"):
                        raise RiskBudgetError(
                            "external JSON Schema references are forbidden"
                        )
                visit(child, depth + 1)
        elif isinstance(node, list):
            for child in node:
                visit(child, depth + 1)

    visit(value, 0)


def _json_pointer(document: Mapping[str, Any], pointer: str) -> Any:
    if pointer == "":
        return document
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise RiskFactError("extractor pointer must be an RFC 6901 JSON Pointer")
    current: Any = document
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if part not in current:
                raise RiskFactError("required risk fact source is missing")
            current = current[part]
        elif isinstance(current, list):
            if (
                not part.isascii()
                or not part.isdigit()
                or (part.startswith("0") and part != "0")
            ):
                raise RiskFactError("risk fact array pointer is invalid")
            index = int(part)
            if index >= len(current):
                raise RiskFactError("risk fact array pointer is out of range")
            current = current[index]
        else:
            raise RiskFactError("risk fact pointer traverses a scalar")
    return current


def _pointer_syntax_is_valid(pointer: str) -> bool:
    if pointer and not pointer.startswith("/"):
        return False
    index = 0
    while index < len(pointer):
        if pointer[index] == "~":
            if index + 1 >= len(pointer) or pointer[index + 1] not in {"0", "1"}:
                return False
            index += 2
            continue
        index += 1
    return True


@dataclass(frozen=True, slots=True)
class ToolRiskContract:
    """Trusted typed risk facts for one authenticated tool definition."""

    tool_name: str
    _input_schema_json: bytes
    _risk_contract_json: bytes
    digest: str

    @property
    def input_schema(self) -> dict[str, Any]:
        """Return a detached view; canonical bytes remain authoritative."""

        return json.loads(self._input_schema_json)

    @property
    def risk_contract(self) -> dict[str, Any]:
        """Return a detached view; canonical bytes remain authoritative."""

        return json.loads(self._risk_contract_json)

    @classmethod
    def from_schema(
        cls,
        tool_name: str,
        input_schema: Mapping[str, Any],
        risk_contract: Mapping[str, Any],
    ) -> "ToolRiskContract":
        name = _require_string(tool_name, "tool_name")
        schema = _require_object(input_schema, "input_schema")
        contract = _require_object(risk_contract, "risk_contract")
        _bounded_json_bytes(schema, "input_schema", MAX_CONTRACT_BYTES)
        _validate_schema_shape(schema)
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as exc:
            raise RiskBudgetError(
                "input_schema is not valid JSON Schema 2020-12"
            ) from exc

        if set(contract) != {"version", "mandatory_facts", "extractors"}:
            raise RiskBudgetError(
                "risk_contract fields must be version, mandatory_facts, and extractors"
            )
        if contract.get("version") != RISK_BUDGET_VERSION:
            raise RiskBudgetError("unsupported risk_contract version")
        mandatory = contract.get("mandatory_facts")
        extractors = contract.get("extractors")
        if not isinstance(mandatory, list) or not mandatory:
            raise RiskBudgetError("mandatory_facts must be a non-empty list")
        if not isinstance(extractors, dict) or not extractors:
            raise RiskBudgetError("extractors must be a non-empty object")
        if len(set(mandatory)) != len(mandatory):
            raise RiskBudgetError("mandatory_facts must not contain duplicates")
        if any(
            not isinstance(fact, str) or fact not in ALL_RISK_FACTS
            for fact in mandatory
        ):
            raise RiskBudgetError("mandatory_facts contains an unknown risk fact")
        if set(extractors) != set(mandatory):
            raise RiskBudgetError("extractors must exactly cover mandatory_facts")

        normalized_extractors: dict[str, dict[str, Any]] = {}
        for fact in mandatory:
            spec = _require_object(extractors[fact], f"extractors.{fact}")
            kind = spec.get("kind")
            if kind not in EXTRACTOR_KINDS:
                raise RiskBudgetError(f"extractors.{fact}.kind is unsupported")
            expected_fields = (
                {"kind", "value"} if kind == "constant" else {"kind", "pointer"}
            )
            if set(spec) != expected_fields:
                raise RiskBudgetError(
                    f"extractors.{fact} must contain exactly {sorted(expected_fields)}"
                )
            if kind != "constant":
                pointer = spec.get("pointer")
                if not isinstance(pointer, str) or not _pointer_syntax_is_valid(
                    pointer
                ):
                    raise RiskBudgetError(f"extractors.{fact}.pointer is invalid")
            if kind in {"integer", "array_length"} and fact not in NUMERIC_RISK_FACTS:
                raise RiskBudgetError(f"extractors.{fact} requires a numeric fact")
            if kind == "enum" and fact not in CATEGORICAL_RISK_LEVELS:
                raise RiskBudgetError(f"extractors.{fact} requires a categorical fact")
            if kind == "constant":
                cls._validate_fact(fact, spec.get("value"))
            normalized_extractors[fact] = spec

        normalized_contract = {
            "version": RISK_BUDGET_VERSION,
            "mandatory_facts": list(mandatory),
            "extractors": normalized_extractors,
        }
        material = {
            "tool_name": name,
            "input_schema": schema,
            "risk_contract": normalized_contract,
        }
        digest = f"sha256:{hashlib.sha256(canonical_json_bytes(material)).hexdigest()}"
        return cls(
            name,
            canonical_json_bytes(schema),
            canonical_json_bytes(normalized_contract),
            digest,
        )

    @staticmethod
    def _validate_fact(fact: str, value: Any) -> int | str:
        if fact in NUMERIC_RISK_FACTS:
            try:
                return _require_risk_int(value, fact)
            except RiskBudgetError as exc:
                raise RiskFactError(str(exc)) from exc
        levels = CATEGORICAL_RISK_LEVELS.get(fact)
        if levels is None or not isinstance(value, str) or value not in levels:
            raise RiskFactError(f"{fact} has an invalid categorical value")
        return value

    def extract(self, arguments: Mapping[str, Any]) -> dict[str, int | str]:
        if not isinstance(arguments, Mapping):
            raise RiskFactError("tool arguments must be a JSON object")
        args = dict(arguments)
        try:
            _bounded_json_bytes(args, "tool arguments", MAX_ARGUMENT_BYTES)
        except RiskBudgetError as exc:
            raise RiskFactError(str(exc)) from exc
        schema = self.input_schema
        risk_contract = self.risk_contract
        try:
            Draft202012Validator(schema).validate(args)
        except ValidationError as exc:
            raise RiskFactError(
                "tool arguments do not satisfy the authenticated schema"
            ) from exc

        facts: dict[str, int | str] = {}
        for fact in risk_contract["mandatory_facts"]:
            spec = risk_contract["extractors"][fact]
            kind = spec["kind"]
            if kind == "constant":
                raw = spec["value"]
            else:
                raw = _json_pointer(args, spec["pointer"])
            if kind == "array_length":
                if not isinstance(raw, list):
                    raise RiskFactError(f"{fact} source must be an array")
                raw = len(raw)
            elif kind == "integer":
                if isinstance(raw, bool) or not isinstance(raw, int):
                    raise RiskFactError(f"{fact} source must be an integer")
            elif kind == "enum" and not isinstance(raw, str):
                raise RiskFactError(f"{fact} source must be a string")
            facts[fact] = self._validate_fact(fact, raw)
        return facts


class ToolRiskRegistry:
    """Immutable-after-start registry of authenticated risk contracts."""

    def __init__(self) -> None:
        self._contracts: dict[str, ToolRiskContract] = {}
        self._frozen = False
        self._lock = threading.RLock()

    def register(self, contract: ToolRiskContract) -> None:
        if not isinstance(contract, ToolRiskContract):
            raise TypeError("contract must be a ToolRiskContract")
        with self._lock:
            if self._frozen:
                raise RuntimeError("tool risk registry is frozen")
            if contract.tool_name in self._contracts:
                raise RiskBudgetConflictError(
                    f"risk contract already registered for {contract.tool_name!r}"
                )
            self._contracts[contract.tool_name] = contract

    def freeze(self) -> None:
        with self._lock:
            self._frozen = True

    def resolve(self, tool_name: str) -> ToolRiskContract | None:
        with self._lock:
            return self._contracts.get(tool_name)


def normalize_risk_budget(
    value: Mapping[str, Any],
    *,
    lineage_id: str | None = None,
) -> dict[str, Any]:
    """Validate and canonicalize the signed ``risk_budget`` claim."""

    policy = _require_object(value, "risk_budget")
    allowed = {"version", "lineage_id", "tools", "ceilings"}
    unknown = set(policy) - allowed
    if unknown:
        raise RiskBudgetError(f"risk_budget contains unknown fields: {sorted(unknown)}")
    if policy.get("version") != RISK_BUDGET_VERSION:
        raise RiskBudgetError("unsupported risk_budget version")
    effective_lineage = (
        lineage_id if lineage_id is not None else policy.get("lineage_id")
    )
    effective_lineage = _require_string(effective_lineage, "risk_budget.lineage_id")

    raw_tools = _require_object(policy.get("tools"), "risk_budget.tools")
    raw_ceilings = _require_object(policy.get("ceilings"), "risk_budget.ceilings")
    if not raw_tools:
        raise RiskBudgetError("risk_budget.tools must not be empty")
    tools: dict[str, Any] = {}
    for raw_name, raw_tool_policy in raw_tools.items():
        name = _require_string(raw_name, "risk_budget tool name")
        if name in tools:
            raise RiskBudgetError(
                f"risk_budget contains duplicate normalized tool name {name!r}"
            )
        tool_policy = _require_object(raw_tool_policy, f"risk_budget.tools.{name}")
        if set(tool_policy) != {"contract_digest", "max_facts"}:
            raise RiskBudgetError(
                f"risk_budget.tools.{name} must contain contract_digest and max_facts"
            )
        digest = _require_string(
            tool_policy.get("contract_digest"),
            f"risk_budget.tools.{name}.contract_digest",
        )
        if not digest.startswith("sha256:") or len(digest) != 71:
            raise RiskBudgetError(
                f"risk_budget.tools.{name}.contract_digest is invalid"
            )
        try:
            int(digest[7:], 16)
        except ValueError as exc:
            raise RiskBudgetError(
                f"risk_budget.tools.{name}.contract_digest is invalid"
            ) from exc
        if digest[7:] != digest[7:].lower():
            raise RiskBudgetError(
                f"risk_budget.tools.{name}.contract_digest must use lowercase hex"
            )
        raw_caps = _require_object(
            tool_policy.get("max_facts"), f"risk_budget.tools.{name}.max_facts"
        )
        if not raw_caps or any(fact not in ALL_RISK_FACTS for fact in raw_caps):
            raise RiskBudgetError(f"risk_budget.tools.{name}.max_facts is invalid")
        caps: dict[str, int | str] = {}
        for fact, cap in raw_caps.items():
            caps[fact] = ToolRiskContract._validate_fact(fact, cap)
        tools[name] = {"contract_digest": digest, "max_facts": caps}

    ceilings: dict[str, dict[str, int]] = {}
    for fact, raw_scopes in raw_ceilings.items():
        if fact not in NUMERIC_RISK_FACTS:
            raise RiskBudgetError("risk_budget.ceilings only accepts numeric facts")
        scopes = _require_object(raw_scopes, f"risk_budget.ceilings.{fact}")
        if set(scopes) != set(RISK_SCOPES):
            raise RiskBudgetError(
                f"risk_budget.ceilings.{fact} must contain session, agent, and lineage"
            )
        ceilings[fact] = {
            scope: _require_risk_int(
                scopes[scope], f"risk_budget.ceilings.{fact}.{scope}"
            )
            for scope in RISK_SCOPES
        }
    required_numeric = {
        fact
        for tool_policy in tools.values()
        for fact in tool_policy["max_facts"]
        if fact in NUMERIC_RISK_FACTS
    }
    if set(ceilings) != required_numeric:
        raise RiskBudgetError(
            "risk_budget.ceilings must exactly cover numeric facts in tool policies"
        )
    return {
        "version": RISK_BUDGET_VERSION,
        "lineage_id": effective_lineage,
        "tools": tools,
        "ceilings": ceilings,
    }


def attenuate_risk_budget(
    parent: Mapping[str, Any],
    child: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Return a child policy that is provably no broader than ``parent``."""

    normalized_parent = normalize_risk_budget(parent)
    if child is None:
        return normalized_parent
    if child.get("lineage_id") != normalized_parent["lineage_id"]:
        raise PermissionError("risk_budget lineage_id escalation")
    normalized_child = normalize_risk_budget(
        child,
        lineage_id=normalized_parent["lineage_id"],
    )
    if normalized_child["lineage_id"] != normalized_parent["lineage_id"]:
        raise PermissionError("risk_budget lineage_id escalation")
    if not set(normalized_child["tools"]).issubset(normalized_parent["tools"]):
        raise PermissionError("risk_budget tool escalation")
    for tool, child_policy in normalized_child["tools"].items():
        parent_policy = normalized_parent["tools"][tool]
        if child_policy["contract_digest"] != parent_policy["contract_digest"]:
            raise PermissionError("risk_budget contract digest escalation")
        if set(child_policy["max_facts"]) != set(parent_policy["max_facts"]):
            raise PermissionError("risk_budget fact set must be preserved")
        for fact, child_cap in child_policy["max_facts"].items():
            parent_cap = parent_policy["max_facts"][fact]
            if fact in NUMERIC_RISK_FACTS:
                broader = int(child_cap) > int(parent_cap)
            else:
                levels = CATEGORICAL_RISK_LEVELS[fact]
                broader = levels.index(str(child_cap)) > levels.index(str(parent_cap))
            if broader:
                raise PermissionError(f"risk_budget {fact} cap escalation")
    if set(normalized_child["ceilings"]) != set(normalized_parent["ceilings"]):
        raise PermissionError("risk_budget ceiling facts must be preserved")
    for fact, child_scopes in normalized_child["ceilings"].items():
        for scope in RISK_SCOPES:
            if child_scopes[scope] > normalized_parent["ceilings"][fact][scope]:
                raise PermissionError(f"risk_budget {fact}.{scope} ceiling escalation")
    return normalized_child


def validate_action_risk(
    policy: Mapping[str, Any],
    contract: ToolRiskContract,
    facts: Mapping[str, int | str],
) -> dict[str, int]:
    """Validate contract binding and per-action caps; return numeric facts."""

    normalized = normalize_risk_budget(policy)
    tool_policy = normalized["tools"].get(contract.tool_name)
    if tool_policy is None:
        raise RiskBudgetError("risk_policy_tool_missing")
    if tool_policy["contract_digest"] != contract.digest:
        raise RiskBudgetError("risk_contract_digest_mismatch")
    if set(facts) != set(contract.risk_contract["mandatory_facts"]):
        raise RiskBudgetError("risk_fact_set_mismatch")
    caps = tool_policy["max_facts"]
    if set(caps) != set(facts):
        raise RiskBudgetError("risk_policy_fact_cap_missing")
    numeric: dict[str, int] = {}
    for fact, value in facts.items():
        validated = ToolRiskContract._validate_fact(fact, value)
        cap = caps[fact]
        if fact in NUMERIC_RISK_FACTS:
            if int(validated) > int(cap):
                raise RiskBudgetError("risk_action_cap_exceeded")
            numeric[fact] = int(validated)
        else:
            levels = CATEGORICAL_RISK_LEVELS[fact]
            if str(validated) == "unknown" or levels.index(
                str(validated)
            ) > levels.index(str(cap)):
                raise RiskBudgetError("risk_action_cap_exceeded")
    return numeric


@dataclass(frozen=True, slots=True)
class RiskReservationResult:
    accepted: bool
    request_hash: str
    status: str
    remaining: dict[str, int]
    blocking_fact: str | None = None
    blocking_scope: str | None = None


@dataclass(frozen=True, slots=True)
class RiskOutcomeResult:
    request_hash: str
    status: str
    remaining: dict[str, int]
    fact_digest: str
    lifecycle_id: str
    lifecycle_state: str
    receipt_id: str | None = None
    idempotent: bool = False


class _ProcessLock:
    __slots__ = ("lock", "__weakref__")

    def __init__(self) -> None:
        self.lock = threading.RLock()


_LOCKS: weakref.WeakValueDictionary[str, _ProcessLock] = weakref.WeakValueDictionary()
_LOCKS_GUARD = threading.Lock()


class FileRiskBudgetLedger:
    """Atomic multi-fact, multi-scope reservation ledger per lineage."""

    def __init__(self, state_dir: str | Path) -> None:
        self.state_dir = Path(state_dir).expanduser()
        self.ledger_dir = self.state_dir / "risk_budgets"
        if self.ledger_dir.is_symlink():
            raise RiskBudgetError("risk ledger directory must not be a symlink")
        self.ledger_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.ledger_dir, stat.S_IRWXU)

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _remaining(
        payload: Mapping[str, Any],
        ceilings: Mapping[str, Mapping[str, int]],
        scope_keys: Mapping[str, str],
    ) -> dict[str, int]:
        result: dict[str, int] = {}
        accounts = payload.get("accounts", {})
        for fact, fact_ceilings in ceilings.items():
            for scope in RISK_SCOPES:
                account_key = f"{fact}:{scope}:{scope_keys[scope]}"
                account = accounts.get(account_key, {})
                used = int(account.get("spent", 0)) + int(account.get("reserved", 0))
                result[f"{fact}.{scope}"] = max(0, int(fact_ceilings[scope]) - used)
        return result

    def reserve(
        self,
        *,
        lineage_id: str,
        session_id: str,
        agent_id: str,
        request_id: str,
        fingerprint: str,
        numeric_facts: Mapping[str, int],
        ceilings: Mapping[str, Mapping[str, int]],
        policy_digest: str,
        contract_digest: str,
        fact_digest: str,
        expires_at: int,
        now: float | None = None,
    ) -> RiskReservationResult:
        for label, value in {
            "lineage_id": lineage_id,
            "session_id": session_id,
            "agent_id": agent_id,
            "request_id": request_id,
            "fingerprint": fingerprint,
        }.items():
            _require_string(value, label, max_bytes=1024)
        if set(numeric_facts) != set(ceilings):
            raise RiskBudgetError("numeric facts and ceilings must have identical keys")
        amounts = {
            fact: _require_risk_int(value, fact)
            for fact, value in numeric_facts.items()
        }
        request_hash = self._hash(request_id)
        fingerprint_hash = self._hash(fingerprint)
        scope_keys = {
            "session": self._hash(session_id),
            "agent": self._hash(agent_id),
            "lineage": self._hash(lineage_id),
        }
        with self._locked(lineage_id):
            payload = self._load(lineage_id)
            self._validate(payload)
            timestamp = float(time.time() if now is None else now)
            self._prune_payload(payload, timestamp)
            reservations = payload["reservations"]
            tombstone = payload["tombstones"].get(request_hash)
            if isinstance(tombstone, dict):
                if tombstone.get("fingerprint_hash") != fingerprint_hash:
                    raise RiskBudgetConflictError(
                        "risk request id tombstone has different semantics"
                    )
                raise RiskBudgetReplayError(
                    f"risk request id already archived as {tombstone.get('status', 'unknown')}"
                )
            existing = reservations.get(request_hash)
            if isinstance(existing, dict):
                expected = {
                    "fingerprint_hash": fingerprint_hash,
                    "policy_digest": policy_digest,
                    "contract_digest": contract_digest,
                    "fact_digest": fact_digest,
                    "amounts": amounts,
                    "scope_keys": scope_keys,
                }
                actual = {key: existing.get(key) for key in expected}
                if actual != expected:
                    raise RiskBudgetConflictError(
                        "risk request id already used for different semantics"
                    )
                raise RiskBudgetReplayError(
                    f"risk request id already recorded as {existing.get('status', 'unknown')}"
                )
            if len(reservations) >= MAX_RESERVATIONS:
                raise RiskBudgetError("risk reservation retention limit reached")

            remaining = self._remaining(payload, ceilings, scope_keys)
            for fact, amount in amounts.items():
                for scope in RISK_SCOPES:
                    if amount > remaining[f"{fact}.{scope}"]:
                        return RiskReservationResult(
                            accepted=False,
                            request_hash=request_hash,
                            status="rejected",
                            remaining=remaining,
                            blocking_fact=fact,
                            blocking_scope=scope,
                        )

            accounts = payload["accounts"]
            for fact, amount in amounts.items():
                for scope in RISK_SCOPES:
                    account_key = f"{fact}:{scope}:{scope_keys[scope]}"
                    account = accounts.setdefault(
                        account_key,
                        {"spent": 0, "reserved": 0, "archived_spent": 0},
                    )
                    account["reserved"] = int(account["reserved"]) + amount
            reservations[request_hash] = {
                "fingerprint_hash": fingerprint_hash,
                "policy_digest": policy_digest,
                "contract_digest": contract_digest,
                "fact_digest": fact_digest,
                "amounts": amounts,
                "scope_keys": scope_keys,
                "ceilings": json.loads(json.dumps(ceilings)),
                "status": "active",
                "created_at": timestamp,
                "updated_at": timestamp,
                "expires_at": _require_risk_int(expires_at, "expires_at"),
                "lifecycle": None,
            }
            self._validate(payload)
            self._persist(lineage_id, payload)
            return RiskReservationResult(
                accepted=True,
                request_hash=request_hash,
                status="active",
                remaining=self._remaining(payload, ceilings, scope_keys),
            )

    def record_outcome(
        self,
        *,
        lineage_id: str,
        session_id: str,
        request_id: str,
        outcome: str,
        now: float | None = None,
    ) -> RiskOutcomeResult:
        if outcome not in {"committed", "released"}:
            raise RiskBudgetError("risk outcome must be committed or released")
        request_hash = self._hash(
            _require_string(request_id, "request_id", max_bytes=1024)
        )
        session_hash = self._hash(
            _require_string(session_id, "session_id", max_bytes=1024)
        )
        with self._locked(lineage_id):
            payload = self._load(lineage_id)
            self._validate(payload)
            reservation = payload["reservations"].get(request_hash)
            if not isinstance(reservation, dict):
                raise RiskBudgetError("risk reservation does not exist")
            if reservation.get("scope_keys", {}).get("session") != session_hash:
                raise RiskBudgetConflictError(
                    "risk reservation belongs to a different session"
                )
            status = reservation.get("status")
            scope_keys = reservation["scope_keys"]
            ceilings = reservation["ceilings"]
            if status == outcome:
                lifecycle = reservation["lifecycle"]
                return RiskOutcomeResult(
                    request_hash=request_hash,
                    status=outcome,
                    remaining=self._remaining(payload, ceilings, scope_keys),
                    fact_digest=reservation["fact_digest"],
                    lifecycle_id=lifecycle["id"],
                    lifecycle_state=lifecycle["state"],
                    receipt_id=lifecycle.get("receipt_id"),
                    idempotent=True,
                )
            if status == "quarantined" and outcome == "released":
                raise RiskBudgetConflictError(
                    "quarantined risk reservation cannot be released"
                )
            if (
                status == "quarantined"
                and reservation["lifecycle"]["state"] != "delivered"
            ):
                raise RiskBudgetError(
                    "quarantine lifecycle receipt must be delivered before reconciliation"
                )
            if status not in {"active", "quarantined"}:
                raise RiskBudgetConflictError(
                    f"risk reservation is {status!r}, not reconcilable"
                )
            for fact, amount in reservation["amounts"].items():
                for scope in RISK_SCOPES:
                    account_key = f"{fact}:{scope}:{scope_keys[scope]}"
                    account = payload["accounts"][account_key]
                    account["reserved"] = int(account["reserved"]) - int(amount)
                    if outcome == "committed":
                        account["spent"] = int(account["spent"]) + int(amount)
            reservation["status"] = outcome
            reservation["updated_at"] = float(time.time() if now is None else now)
            lifecycle_id = self._hash(f"outcome:{request_hash}:{outcome}")
            reservation["lifecycle"] = {
                "id": lifecycle_id,
                "state": "pending",
                "receipt_id": None,
            }
            self._validate(payload)
            self._persist(lineage_id, payload)
            return RiskOutcomeResult(
                request_hash=request_hash,
                status=outcome,
                remaining=self._remaining(payload, ceilings, scope_keys),
                fact_digest=reservation["fact_digest"],
                lifecycle_id=lifecycle_id,
                lifecycle_state="pending",
            )

    def mark_lifecycle_delivered(
        self,
        *,
        lineage_id: str,
        session_id: str,
        request_hash: str,
        lifecycle_id: str,
        receipt_id: str,
    ) -> None:
        """Atomically acknowledge that a lifecycle receipt is durable."""

        session_hash = self._hash(
            _require_string(session_id, "session_id", max_bytes=1024)
        )
        _require_string(lifecycle_id, "lifecycle_id", max_bytes=128)
        _require_string(receipt_id, "receipt_id", max_bytes=1024)
        with self._locked(lineage_id):
            payload = self._load(lineage_id)
            self._validate(payload)
            record = payload["reservations"].get(request_hash)
            if not isinstance(record, dict):
                record = payload["tombstones"].get(request_hash)
            if not isinstance(record, dict):
                raise RiskBudgetError("risk lifecycle reservation does not exist")
            record_session_hash = record.get("session_hash")
            if record_session_hash is None:
                record_session_hash = record.get("scope_keys", {}).get("session")
            if record_session_hash != session_hash:
                raise RiskBudgetConflictError(
                    "risk lifecycle belongs to a different session"
                )
            lifecycle = record.get("lifecycle")
            if not isinstance(lifecycle, dict) or lifecycle.get("id") != lifecycle_id:
                raise RiskBudgetConflictError("risk lifecycle binding mismatch")
            if lifecycle.get("state") == "delivered":
                if lifecycle.get("receipt_id") != receipt_id:
                    raise RiskBudgetConflictError(
                        "risk lifecycle receipt binding mismatch"
                    )
                return
            lifecycle["state"] = "delivered"
            lifecycle["receipt_id"] = receipt_id
            self._validate(payload)
            self._persist(lineage_id, payload)

    def quarantine_stale(
        self,
        *,
        lineage_id: str,
        session_id: str,
        stale_before: float,
        now: float | None = None,
    ) -> list[RiskOutcomeResult]:
        quarantined: list[RiskOutcomeResult] = []
        newly_quarantined: set[str] = set()
        session_hash = self._hash(
            _require_string(session_id, "session_id", max_bytes=1024)
        )
        with self._locked(lineage_id):
            payload = self._load(lineage_id)
            self._validate(payload)
            timestamp = float(time.time() if now is None else now)
            for request_hash, reservation in payload["reservations"].items():
                if (
                    reservation.get("status") == "active"
                    and reservation.get("scope_keys", {}).get("session") == session_hash
                    and float(reservation.get("created_at", timestamp)) <= stale_before
                ):
                    reservation["status"] = "quarantined"
                    reservation["updated_at"] = timestamp
                    reservation["lifecycle"] = {
                        "id": self._hash(f"outcome:{request_hash}:quarantined"),
                        "state": "pending",
                        "receipt_id": None,
                    }
                    newly_quarantined.add(request_hash)
            for request_hash, reservation in payload["reservations"].items():
                lifecycle = reservation.get("lifecycle")
                if (
                    reservation.get("status") == "quarantined"
                    and reservation.get("scope_keys", {}).get("session") == session_hash
                    and isinstance(lifecycle, dict)
                    and lifecycle.get("state") == "pending"
                ):
                    quarantined.append(
                        RiskOutcomeResult(
                            request_hash=request_hash,
                            status="quarantined",
                            remaining=self._remaining(
                                payload,
                                reservation["ceilings"],
                                reservation["scope_keys"],
                            ),
                            fact_digest=reservation["fact_digest"],
                            lifecycle_id=lifecycle["id"],
                            lifecycle_state="pending",
                            idempotent=request_hash not in newly_quarantined,
                        )
                    )
            for request_hash, tombstone in payload["tombstones"].items():
                lifecycle = tombstone.get("lifecycle")
                if (
                    tombstone.get("status") == "quarantined_committed"
                    and tombstone.get("session_hash") == session_hash
                    and isinstance(lifecycle, dict)
                    and lifecycle.get("state") == "pending"
                ):
                    quarantined.append(
                        RiskOutcomeResult(
                            request_hash=request_hash,
                            status="quarantined",
                            remaining={},
                            fact_digest=tombstone["fact_digest"],
                            lifecycle_id=lifecycle["id"],
                            lifecycle_state="pending",
                            idempotent=True,
                        )
                    )
            if quarantined:
                self._validate(payload)
                self._persist(lineage_id, payload)
        return quarantined

    def unresolved_for_session(self, *, lineage_id: str, session_id: str) -> list[str]:
        session_hash = self._hash(session_id)
        with self._locked(lineage_id):
            payload = self._load(lineage_id)
            self._validate(payload)
            return [
                request_hash
                for request_hash, reservation in payload["reservations"].items()
                if reservation.get("status") in {"active", "quarantined"}
                and reservation.get("scope_keys", {}).get("session") == session_hash
            ] + [
                request_hash
                for request_hash, tombstone in payload["tombstones"].items()
                if tombstone.get("status") == "quarantined_committed"
                and tombstone.get("session_hash") == session_hash
                and tombstone.get("lifecycle", {}).get("state") == "pending"
            ]

    def pending_lifecycles_for_session(
        self,
        *,
        lineage_id: str,
        session_id: str,
    ) -> list[RiskOutcomeResult]:
        """Return retryable lifecycle outbox records owned by one session."""

        session_hash = self._hash(
            _require_string(session_id, "session_id", max_bytes=1024)
        )
        with self._locked(lineage_id):
            payload = self._load(lineage_id)
            self._validate(payload)
            pending: list[RiskOutcomeResult] = []
            for request_hash, reservation in payload["reservations"].items():
                lifecycle = reservation.get("lifecycle")
                if (
                    reservation.get("scope_keys", {}).get("session") == session_hash
                    and isinstance(lifecycle, dict)
                    and lifecycle.get("state") == "pending"
                ):
                    pending.append(
                        RiskOutcomeResult(
                            request_hash=request_hash,
                            status=str(reservation["status"]),
                            remaining=self._remaining(
                                payload,
                                reservation["ceilings"],
                                reservation["scope_keys"],
                            ),
                            fact_digest=reservation["fact_digest"],
                            lifecycle_id=lifecycle["id"],
                            lifecycle_state="pending",
                            idempotent=True,
                        )
                    )
            for request_hash, tombstone in payload["tombstones"].items():
                lifecycle = tombstone["lifecycle"]
                if (
                    tombstone["session_hash"] == session_hash
                    and lifecycle["state"] == "pending"
                ):
                    status = str(tombstone["status"])
                    if status == "quarantined_committed":
                        status = "quarantined"
                    pending.append(
                        RiskOutcomeResult(
                            request_hash=request_hash,
                            status=status,
                            remaining={},
                            fact_digest=tombstone["fact_digest"],
                            lifecycle_id=lifecycle["id"],
                            lifecycle_state="pending",
                            idempotent=True,
                        )
                    )
            return pending

    def remaining(
        self,
        *,
        lineage_id: str,
        session_id: str,
        agent_id: str,
        ceilings: Mapping[str, Mapping[str, int]],
    ) -> dict[str, int]:
        scope_keys = {
            "session": self._hash(session_id),
            "agent": self._hash(agent_id),
            "lineage": self._hash(lineage_id),
        }
        with self._locked(lineage_id):
            payload = self._load(lineage_id)
            self._validate(payload)
            return self._remaining(payload, ceilings, scope_keys)

    def snapshot(self, lineage_id: str) -> dict[str, Any]:
        with self._locked(lineage_id):
            payload = self._load(lineage_id)
            self._validate(payload)
            return json.loads(json.dumps(payload))

    def prune_expired(
        self,
        *,
        lineage_id: str,
        now: float | None = None,
    ) -> dict[str, int]:
        with self._locked(lineage_id):
            payload = self._load(lineage_id)
            self._validate(payload)
            result = self._prune_payload(
                payload,
                float(time.time() if now is None else now),
            )
            if result["pruned"] or result["quarantined"]:
                self._validate(payload)
                self._persist(lineage_id, payload)
            return result

    @staticmethod
    def _prune_payload(payload: dict[str, Any], now: float) -> dict[str, int]:
        pruned = 0
        quarantined = 0
        reservations = payload["reservations"]
        tombstones = payload["tombstones"]
        for request_hash, tombstone in list(tombstones.items()):
            if (
                float(tombstone["replay_until"]) <= now
                and tombstone["lifecycle"]["state"] == "delivered"
            ):
                del tombstones[request_hash]
                pruned += 1
        for request_hash, reservation in list(reservations.items()):
            expires_at = _require_risk_int(
                reservation.get("expires_at"),
                "risk ledger expires_at",
            )
            if expires_at > now:
                continue
            status_value = reservation["status"]
            if status_value == "active":
                reservation["status"] = "quarantined"
                reservation["updated_at"] = now
                reservation["lifecycle"] = {
                    "id": hashlib.sha256(
                        f"outcome:{request_hash}:quarantined".encode("utf-8")
                    ).hexdigest(),
                    "state": "pending",
                    "receipt_id": None,
                }
                quarantined += 1
                continue
            if status_value == "quarantined":
                if now < float(reservation["updated_at"]) + QUARANTINE_RETENTION_S:
                    continue
                for fact, amount in reservation["amounts"].items():
                    for scope in RISK_SCOPES:
                        account_key = (
                            f"{fact}:{scope}:{reservation['scope_keys'][scope]}"
                        )
                        account = payload["accounts"][account_key]
                        account["reserved"] = int(account["reserved"]) - int(amount)
                        account["spent"] = int(account["spent"]) + int(amount)
                        account["archived_spent"] = int(
                            account["archived_spent"]
                        ) + int(amount)
                status_value = "quarantined_committed"
            lifecycle = reservation.get("lifecycle")
            if (
                status_value in {"committed", "released"}
                and isinstance(lifecycle, dict)
                and lifecycle.get("state") != "delivered"
            ):
                continue
            if status_value == "committed":
                for fact, amount in reservation["amounts"].items():
                    for scope in RISK_SCOPES:
                        account_key = (
                            f"{fact}:{scope}:{reservation['scope_keys'][scope]}"
                        )
                        account = payload["accounts"][account_key]
                        account["archived_spent"] = int(
                            account["archived_spent"]
                        ) + int(amount)
            if len(tombstones) >= MAX_RESERVATIONS:
                raise RiskBudgetError("risk replay tombstone retention limit reached")
            tombstones[request_hash] = {
                "fingerprint_hash": reservation["fingerprint_hash"],
                "fact_digest": reservation["fact_digest"],
                "session_hash": reservation["scope_keys"]["session"],
                "status": status_value,
                "replay_until": max(expires_at, int(now))
                + REPLAY_TOMBSTONE_RETENTION_S,
                "lifecycle": json.loads(json.dumps(reservation["lifecycle"])),
            }
            del reservations[request_hash]
            pruned += 1
        return {"pruned": pruned, "quarantined": quarantined}

    def _path(self, lineage_id: str) -> Path:
        return self.ledger_dir / f"{self._hash(lineage_id)}.json"

    def _lock_path(self, lineage_id: str) -> Path:
        return self._path(lineage_id).with_suffix(".lock")

    @contextlib.contextmanager
    def _locked(self, lineage_id: str):
        lock_path = self._lock_path(lineage_id)
        if lock_path.is_symlink():
            raise RiskBudgetError("risk ledger lock must not be a symlink")
        fd = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        key = str(lock_path.resolve())
        with _LOCKS_GUARD:
            process_lock = _LOCKS.get(key)
            if process_lock is None:
                process_lock = _ProcessLock()
                _LOCKS[key] = process_lock
        try:
            with process_lock.lock:
                with os.fdopen(fd, "a+b", closefd=False) as lock_handle:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                    try:
                        yield
                    finally:
                        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _load(self, lineage_id: str) -> dict[str, Any]:
        path = self._path(lineage_id)
        if not path.exists():
            return {
                "version": RISK_BUDGET_VERSION,
                "lineage_hash": self._hash(lineage_id),
                "accounts": {},
                "reservations": {},
                "tombstones": {},
            }
        if path.is_symlink():
            raise RiskBudgetError("risk ledger file must not be a symlink")
        fd = -1
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "r", encoding="utf-8") as handle:
                fd = -1
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise RiskBudgetError("risk ledger is unavailable or corrupt") from exc
        finally:
            if fd != -1:
                os.close(fd)
        if not isinstance(payload, dict):
            raise RiskBudgetError("risk ledger must contain a JSON object")
        if payload.get("lineage_hash") != self._hash(lineage_id):
            raise RiskBudgetError("risk ledger lineage binding mismatch")
        return payload

    @staticmethod
    def _validate(payload: Mapping[str, Any]) -> None:
        if set(payload) != {
            "version",
            "lineage_hash",
            "accounts",
            "reservations",
            "tombstones",
        }:
            raise RiskBudgetError("risk ledger has an invalid top-level shape")
        if payload.get("version") != RISK_BUDGET_VERSION:
            raise RiskBudgetError("risk ledger version is unsupported")
        accounts = _require_object(payload.get("accounts"), "risk ledger accounts")
        reservations = _require_object(
            payload.get("reservations"), "risk ledger reservations"
        )
        tombstones = _require_object(
            payload.get("tombstones"), "risk ledger tombstones"
        )
        if len(reservations) > MAX_RESERVATIONS:
            raise RiskBudgetError("risk ledger exceeds reservation retention limit")
        if len(tombstones) > MAX_RESERVATIONS:
            raise RiskBudgetError("risk ledger exceeds tombstone retention limit")
        for request_hash, tombstone_value in tombstones.items():
            if not isinstance(request_hash, str) or len(request_hash) != 64:
                raise RiskBudgetError("risk ledger tombstone request hash is invalid")
            tombstone = _require_object(tombstone_value, "risk ledger tombstone")
            if set(tombstone) != {
                "fingerprint_hash",
                "fact_digest",
                "session_hash",
                "status",
                "replay_until",
                "lifecycle",
            }:
                raise RiskBudgetError("risk ledger tombstone shape is invalid")
            if (
                not isinstance(tombstone["fingerprint_hash"], str)
                or len(tombstone["fingerprint_hash"]) != 64
            ):
                raise RiskBudgetError("risk ledger tombstone fingerprint is invalid")
            fact_digest = tombstone["fact_digest"]
            if (
                not isinstance(fact_digest, str)
                or not fact_digest.startswith("sha256:")
                or len(fact_digest) != 71
                or fact_digest[7:] != fact_digest[7:].lower()
            ):
                raise RiskBudgetError("risk ledger tombstone fact digest is invalid")
            try:
                bytes.fromhex(fact_digest[7:])
            except ValueError as exc:
                raise RiskBudgetError(
                    "risk ledger tombstone fact digest is invalid"
                ) from exc
            if (
                not isinstance(tombstone["session_hash"], str)
                or len(tombstone["session_hash"]) != 64
            ):
                raise RiskBudgetError("risk ledger tombstone session hash is invalid")
            if tombstone["status"] not in {
                "committed",
                "released",
                "quarantined_committed",
            }:
                raise RiskBudgetError("risk ledger tombstone status is invalid")
            _require_risk_int(tombstone["replay_until"], "risk ledger replay_until")
            lifecycle = _require_object(
                tombstone["lifecycle"], "risk ledger tombstone lifecycle"
            )
            if set(lifecycle) != {"id", "state", "receipt_id"}:
                raise RiskBudgetError(
                    "risk ledger tombstone lifecycle shape is invalid"
                )
            if not isinstance(lifecycle["id"], str) or len(lifecycle["id"]) != 64:
                raise RiskBudgetError("risk ledger tombstone lifecycle id is invalid")
            if lifecycle["state"] not in {"pending", "delivered"}:
                raise RiskBudgetError(
                    "risk ledger tombstone lifecycle state is invalid"
                )
            if lifecycle["state"] == "pending" and lifecycle["receipt_id"] is not None:
                raise RiskBudgetError(
                    "pending risk tombstone lifecycle has a receipt id"
                )
            if lifecycle["state"] == "delivered":
                _require_string(
                    lifecycle["receipt_id"], "risk ledger tombstone receipt id"
                )
        expected_reserved: dict[str, int] = {}
        retained_spent: dict[str, int] = {}
        for request_hash, reservation_value in reservations.items():
            if len(request_hash) != 64:
                raise RiskBudgetError("risk ledger request hash is invalid")
            reservation = _require_object(reservation_value, "risk ledger reservation")
            _require_risk_int(
                reservation.get("expires_at"),
                "risk ledger expires_at",
            )
            status_value = reservation.get("status")
            if status_value not in {"active", "quarantined", "committed", "released"}:
                raise RiskBudgetError("risk ledger reservation status is invalid")
            amounts = _require_object(reservation.get("amounts"), "risk ledger amounts")
            scope_keys = _require_object(
                reservation.get("scope_keys"), "risk ledger scope keys"
            )
            ceilings = _require_object(
                reservation.get("ceilings"), "risk ledger ceilings"
            )
            if set(ceilings) != set(amounts):
                raise RiskBudgetError("risk ledger ceiling facts are incomplete")
            for fact, fact_ceilings_value in ceilings.items():
                fact_ceilings = _require_object(
                    fact_ceilings_value, f"risk ledger ceilings {fact}"
                )
                if set(fact_ceilings) != set(RISK_SCOPES):
                    raise RiskBudgetError("risk ledger ceiling scopes are incomplete")
                for scope in RISK_SCOPES:
                    _require_risk_int(
                        fact_ceilings[scope], f"risk ledger ceiling {fact}.{scope}"
                    )
            lifecycle = reservation.get("lifecycle")
            if status_value == "active":
                if lifecycle is not None:
                    raise RiskBudgetError("active risk reservation has lifecycle state")
            else:
                lifecycle = _require_object(lifecycle, "risk ledger lifecycle")
                if set(lifecycle) != {"id", "state", "receipt_id"}:
                    raise RiskBudgetError("risk ledger lifecycle shape is invalid")
                if not isinstance(lifecycle["id"], str) or len(lifecycle["id"]) != 64:
                    raise RiskBudgetError("risk ledger lifecycle id is invalid")
                if lifecycle["state"] not in {"pending", "delivered"}:
                    raise RiskBudgetError("risk ledger lifecycle state is invalid")
                if (
                    lifecycle["state"] == "pending"
                    and lifecycle["receipt_id"] is not None
                ):
                    raise RiskBudgetError("pending risk lifecycle has a receipt id")
                if lifecycle["state"] == "delivered":
                    _require_string(lifecycle["receipt_id"], "risk ledger receipt id")
            if set(scope_keys) != set(RISK_SCOPES):
                raise RiskBudgetError("risk ledger scope keys are incomplete")
            for fact, raw_amount in amounts.items():
                if fact not in NUMERIC_RISK_FACTS:
                    raise RiskBudgetError(
                        "risk ledger contains an unknown numeric fact"
                    )
                amount = _require_risk_int(raw_amount, "risk ledger amount")
                for scope in RISK_SCOPES:
                    scope_hash = scope_keys[scope]
                    if not isinstance(scope_hash, str) or len(scope_hash) != 64:
                        raise RiskBudgetError("risk ledger scope hash is invalid")
                    account_key = f"{fact}:{scope}:{scope_hash}"
                    if status_value in {"active", "quarantined"}:
                        expected_reserved[account_key] = (
                            expected_reserved.get(account_key, 0) + amount
                        )
                    elif status_value == "committed":
                        retained_spent[account_key] = (
                            retained_spent.get(account_key, 0) + amount
                        )
        for account_key, account_value in accounts.items():
            account = _require_object(
                account_value, f"risk ledger account {account_key}"
            )
            if set(account) != {"spent", "reserved", "archived_spent"}:
                raise RiskBudgetError("risk ledger account shape is invalid")
            spent = _require_risk_int(account["spent"], "risk ledger spent")
            reserved = _require_risk_int(account["reserved"], "risk ledger reserved")
            archived = _require_risk_int(
                account["archived_spent"], "risk ledger archived_spent"
            )
            if reserved != expected_reserved.get(account_key, 0):
                raise RiskBudgetError("risk ledger reserved invariant failed")
            if spent != archived + retained_spent.get(account_key, 0):
                raise RiskBudgetError("risk ledger spent invariant failed")
        referenced_accounts = set(expected_reserved) | set(retained_spent)
        if not referenced_accounts.issubset(accounts):
            raise RiskBudgetError("risk ledger references a missing account")

    def _persist(self, lineage_id: str, payload: Mapping[str, Any]) -> None:
        path = self._path(lineage_id)
        tmp = path.with_name(f"{path.stem}.{uuid.uuid4().hex}.tmp")
        data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        fd = -1
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(fd, "wb", closefd=False) as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.close(fd)
            fd = -1
            os.replace(tmp, path)
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            dir_fd = os.open(self.ledger_dir, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except Exception:
            if fd != -1:
                os.close(fd)
            with contextlib.suppress(OSError):
                tmp.unlink()
            raise
