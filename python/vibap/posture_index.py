"""Read-only posture index over local Ardur evidence artifacts.

The posture index is intentionally derived evidence: it summarizes local receipt
chains, optional ``ARDUR.md`` profile metadata, and optional redacted evidence
bundle fields without mutating any of them. It does not claim enterprise-wide
asset discovery, provider-hidden visibility, or kernel/process capture.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence, cast

import jwt
from cryptography.hazmat.primitives import serialization

from .receipt import ReceiptChainError, verify_chain
from .shareable_redaction import redact_local_path_text

SCHEMA_VERSION = "ardur.posture_index.v0"
POSITIONING = "derived_local_evidence"

_SECRET_KEY_RE = re.compile(
    r"(token|secret|password|passwd|credential|api[_-]?key|private[_-]?key|jwt|bearer)",
    re.IGNORECASE,
)
_JWT_LIKE_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b", re.IGNORECASE)
_API_KEY_VALUE_RE = re.compile(r"\b(?:sk|pk|ghp|github_pat|xox[baprs])-?[A-Za-z0-9_\-]{12,}\b")
# Conservative local absolute-path redaction is centralized in
# vibap.shareable_redaction so posture scans and shareable bundles apply the same
# root/path/file-URI rules.
_SHA256_RE = re.compile(r"^(?:sha256:|sha-256:)?[a-fA-F0-9]{64}$")

_UNKNOWN_BOUNDARY_BY_TOOL = {
    "Bash": "tool_boundary_only:bash_subprocess_effects",
}


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class _Redactor:
    def __init__(self, roots: list[Path] | None = None) -> None:
        self._roots: list[str] = []
        for root in roots or []:
            try:
                text = str(root.expanduser().resolve())
            except OSError:
                text = str(root.expanduser())
            if text and text != ".":
                self._roots.append(text)
        self._roots = sorted(set(self._roots), key=len, reverse=True)

    def path_token(self, value: str | Path) -> str:
        text = str(value)
        return f"<PATH:{_sha256_text(text)[:12]}>"

    def text(self, value: Any) -> str:
        text = str(value)
        text = _JWT_LIKE_RE.sub("[REDACTED]", text)
        text = _BEARER_RE.sub("Bearer [REDACTED]", text)
        text = _API_KEY_VALUE_RE.sub("[REDACTED]", text)
        root_pairs = [(root, self.path_token(root)) for root in self._roots]
        return redact_local_path_text(
            text,
            root_pairs=root_pairs,
            absolute_replacement=self.path_token,
            file_uri_replacement=self.path_token,
        )

    def value(self, value: Any, *, key: str | None = None) -> Any:
        if key and _SECRET_KEY_RE.search(key):
            return "[REDACTED]"
        if isinstance(value, Mapping):
            return {str(k): self.value(v, key=str(k)) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
        if isinstance(value, list):
            return [self.value(item) for item in value]
        if isinstance(value, tuple):
            return [self.value(item) for item in value]
        if isinstance(value, str):
            return self.text(value)
        return value


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    return value if isinstance(value, dict) else None


def _read_receipt_tokens(path: Path) -> list[str]:
    try:
        return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError:
        return []


def _decode_unverified(tokens: list[str]) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for token in tokens:
        try:
            decoded = jwt.decode(
                token,
                options={
                    "verify_signature": False,
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_aud": False,
                },
            )
        except Exception:
            continue
        if isinstance(decoded, dict):
            claims.append(decoded)
    return claims


def _receipt_files(receipts: Path) -> list[Path]:
    path = receipts.expanduser()
    if path.is_file():
        return [path]
    if not path.exists():
        return []
    return sorted(path.rglob("receipts.jsonl"))


def _load_public_key_read_only(keys_dir: Path | None) -> tuple[Any | None, dict[str, Any] | None]:
    if keys_dir is None:
        return None, {"status": "not_verified", "reason": "keys_dir_not_provided"}
    pub_path = keys_dir.expanduser() / "passport_public.pem"
    if not pub_path.is_file():
        return None, {"status": "not_verified", "reason": "passport_public_key_missing"}
    try:
        return serialization.load_pem_public_key(pub_path.read_bytes()), None
    except (OSError, ValueError) as exc:
        return None, {"status": "not_verified", "reason": f"passport_public_key_unreadable:{type(exc).__name__}"}


def _policy_digest_values(value: Any) -> list[str]:
    found: set[str] = set()

    def walk(node: Any, key: str = "") -> None:
        if isinstance(node, Mapping):
            for raw_key, raw_value in node.items():
                walk(raw_value, str(raw_key))
            return
        if isinstance(node, list):
            for item in node:
                walk(item, key)
            return
        if not isinstance(node, str):
            return
        key_l = key.lower()
        if "policy" in key_l and ("digest" in key_l or "sha256" in key_l) and _SHA256_RE.fullmatch(node):
            prefix = "sha256:"
            digest = node.split(":", 1)[-1].lower()
            found.add(prefix + digest)

    walk(value)
    return sorted(found)


def _profile_summary(profile: Path | None, redactor: _Redactor) -> dict[str, Any]:
    if profile is None:
        return {"present": False}
    path = profile.expanduser()
    if not path.is_file():
        return {"present": False, "path": redactor.text(str(path)), "status": "missing"}
    return {
        "present": True,
        "path": redactor.text(str(path)),
        "sha256": _sha256_file(path),
    }


def _evidence_bundle_summary(evidence_bundle: Path | None, redactor: _Redactor) -> tuple[dict[str, Any], list[str]]:
    if evidence_bundle is None:
        return {"present": False}, []
    path = evidence_bundle.expanduser()
    data = _read_json(path)
    if data is None:
        return {"present": False, "path": redactor.text(str(path)), "status": "missing_or_invalid_json"}, []
    policy_digests = _policy_digest_values(data)
    summary_keys = ["schema_version", "rwt_id", "classification", "status", "receipts", "redaction", "claim_mapping"]
    summary = {key: data[key] for key in summary_keys if key in data}
    return (
        {
            "present": True,
            "path": redactor.text(str(path)),
            "sha256": _sha256_file(path),
            "summary": redactor.value(summary),
        },
        policy_digests,
    )


def _verdict_counts(claims: Sequence[Mapping[str, Any]], *, missing_unknown: bool = False) -> dict[str, int]:
    allow = sum(1 for claim in claims if claim.get("verdict") == "compliant")
    deny = sum(1 for claim in claims if claim.get("verdict") == "violation")
    unknown = sum(1 for claim in claims if claim.get("verdict") not in {"compliant", "violation"})
    if missing_unknown and not claims:
        unknown = 1
    return {"allow": allow, "deny": deny, "unknown": unknown}


def _policy_decisions(claims: Sequence[Mapping[str, Any]], redactor: _Redactor) -> list[dict[str, Any]]:
    decisions: list[dict[str, Any]] = []
    for claim in claims:
        for item in claim.get("policy_decisions", []) or []:
            if not isinstance(item, Mapping):
                continue
            decisions.append(
                {
                    "backend": redactor.text(str(item.get("backend", "unknown"))),
                    "decision": redactor.text(str(item.get("decision", "unknown"))),
                    "reason": redactor.value(item.get("reason")),
                }
            )
    return decisions


def _boundary_gap_for_tool(tool: str) -> str | None:
    if tool in _UNKNOWN_BOUNDARY_BY_TOOL:
        return _UNKNOWN_BOUNDARY_BY_TOOL[tool]
    if tool.startswith("mcp__"):
        return "tool_boundary_only:mcp_downstream_effects"
    return None


def _chain_report(
    *,
    receipt_file: Path,
    tokens: list[str],
    claims: list[dict[str, Any]],
    verification: dict[str, Any],
    redactor: _Redactor,
) -> dict[str, Any]:
    trace_ids = sorted({str(claim.get("trace_id", "")) for claim in claims if claim.get("trace_id")})
    return {
        "receipt_file": redactor.text(str(receipt_file)),
        "trace_ids": trace_ids,
        "receipt_count": len(claims),
        "raw_entry_count": len(tokens),
        "verification": verification,
    }


def _aggregate_verification(chains: list[dict[str, Any]]) -> dict[str, Any]:
    if not chains:
        return {"status": "missing", "ok": False, "chain_count": 0}
    statuses = [str(chain.get("verification", {}).get("status", "not_verified")) for chain in chains]
    if "fail" in statuses:
        status = "fail"
        ok: bool | None = False
    elif all(item == "pass" for item in statuses):
        status = "pass"
        ok = True
    elif "not_verified" in statuses:
        status = "not_verified"
        ok = None
    else:
        status = "unknown"
        ok = None
    return {"status": status, "ok": ok, "chain_count": len(chains)}


def build_posture_index(
    *,
    receipts: Path,
    keys_dir: Path | None = None,
    profile: Path | None = None,
    evidence_bundle: Path | None = None,
    verify_expiry: bool = False,
) -> dict[str, Any]:
    """Build a shareable, read-only posture index from local evidence.

    ``keys_dir`` is intentionally read-only: unlike passport helpers, this
    function never creates missing key material just to verify archived receipts.
    """
    roots = [receipts]
    if keys_dir is not None:
        roots.append(keys_dir)
    if profile is not None:
        roots.append(profile)
        roots.append(profile.parent)
    if evidence_bundle is not None:
        roots.append(evidence_bundle)
        roots.append(evidence_bundle.parent)
    redactor = _Redactor(roots)

    public_key, key_warning = _load_public_key_read_only(keys_dir)
    chains: list[dict[str, Any]] = []
    all_claims: list[dict[str, Any]] = []
    coverage_gaps: set[str] = set()
    unknown_boundary_count = 0
    receipt_paths = _receipt_files(receipts)

    if not receipt_paths:
        coverage_gaps.add("missing_receipt_telemetry")

    for receipt_file in receipt_paths:
        tokens = _read_receipt_tokens(receipt_file)
        verification: dict[str, Any]
        claims: list[dict[str, Any]]
        if not tokens:
            verification = {"status": "missing", "ok": False, "reason": "receipt_file_empty"}
            claims = []
            coverage_gaps.add("missing_receipt_telemetry")
        elif public_key is None:
            verification = {"status": "not_verified", "ok": None, **(key_warning or {})}
            claims = _decode_unverified(tokens)
            coverage_gaps.add("receipt_chain_not_verified")
        else:
            try:
                claims = verify_chain(cast(list[str | dict[str, Any]], tokens), public_key, verify_expiry=verify_expiry)
                verification = {"status": "pass", "ok": True, "verify_expiry": verify_expiry}
            except ReceiptChainError as exc:
                verification = {
                    "status": "fail",
                    "ok": False,
                    "error": redactor.text(str(exc)),
                    "verify_expiry": verify_expiry,
                }
                claims = _decode_unverified(tokens)
                coverage_gaps.add("broken_receipt_chain")
        all_claims.extend(claims)
        chains.append(
            _chain_report(
                receipt_file=receipt_file,
                tokens=tokens,
                claims=claims,
                verification=verification,
                redactor=redactor,
            )
        )

    observed_tools = Counter(str(claim.get("tool", "unknown")) for claim in all_claims)
    observed_actions = Counter(str(claim.get("action_class", "unknown")) for claim in all_claims)
    observed_verdicts = Counter(str(claim.get("verdict", "unknown")) for claim in all_claims)
    evidence_levels = Counter(str(claim.get("evidence_level", "unknown")) for claim in all_claims)

    observations: list[dict[str, Any]] = []
    for claim in all_claims:
        tool = str(claim.get("tool", "unknown"))
        gap = _boundary_gap_for_tool(tool)
        boundary = "unknown" if gap else "tool_call"
        if gap:
            unknown_boundary_count += 1
            coverage_gaps.add(gap)
        observations.append(
            {
                "receipt_id": redactor.text(str(claim.get("receipt_id", ""))),
                "trace_id": redactor.text(str(claim.get("trace_id", ""))),
                "tool": redactor.text(tool),
                "action_class": redactor.text(str(claim.get("action_class", "unknown"))),
                "target": redactor.text(str(claim.get("target", ""))),
                "verdict": redactor.text(str(claim.get("verdict", "unknown"))),
                "evidence_level": redactor.text(str(claim.get("evidence_level", "unknown"))),
                "boundary": boundary,
            }
        )

    profile_info = _profile_summary(profile, redactor)
    evidence_info, bundle_policy_digests = _evidence_bundle_summary(evidence_bundle, redactor)
    policy_decisions = _policy_decisions(all_claims, redactor)
    policy_backends = Counter(str(item.get("backend", "unknown")) for item in policy_decisions)
    policy_digests = sorted(set(bundle_policy_digests))

    chain_verification = _aggregate_verification(chains)
    missing_unknown = not all_claims and chain_verification["status"] == "missing"
    boundary_counts = {
        "tool_call": len(all_claims) - unknown_boundary_count,
        "unknown": unknown_boundary_count,
        "missing": 1 if missing_unknown else 0,
    }

    posture = {
        "schema_version": SCHEMA_VERSION,
        "positioning": POSITIONING,
        "claim_scope": (
            "Derived local evidence from Ardur receipt/profile/bundle artifacts; "
            "not live enterprise-wide discovery, provider-hidden visibility, or kernel/process capture."
        ),
        "inputs": {
            "receipts": redactor.text(str(receipts)),
            "keys_dir": redactor.text(str(keys_dir)) if keys_dir is not None else None,
            "profile": redactor.text(str(profile)) if profile is not None else None,
            "evidence_bundle": redactor.text(str(evidence_bundle)) if evidence_bundle is not None else None,
        },
        "chain_verification": chain_verification,
        "summary": {
            "chain_count": len(chains),
            "receipt_count": len(all_claims),
            "policy_verdict_counts": _verdict_counts(all_claims, missing_unknown=missing_unknown),
            "boundary_counts": boundary_counts,
            "unknown_boundary_count": unknown_boundary_count,
        },
        "observed_tools": dict(sorted(observed_tools.items())),
        "observed_actions": dict(sorted(observed_actions.items())),
        "observed_verdicts": dict(sorted(observed_verdicts.items())),
        "evidence_levels": dict(sorted(evidence_levels.items())),
        "policy": {
            "digests": policy_digests,
            "backends": dict(sorted(policy_backends.items())),
            "decision_count": len(policy_decisions),
            "decisions": policy_decisions,
        },
        "profile": profile_info,
        "evidence_bundle": evidence_info,
        "coverage_gaps": sorted(coverage_gaps),
        "observations": observations,
        "chains": chains,
        "redaction": {
            "local_absolute_paths": "hashed_placeholders",
            "credential_like_values": "[REDACTED]",
            "raw_secret_values_copied": False,
        },
    }
    return redactor.value(posture)


def format_posture_report(posture: Mapping[str, Any]) -> str:
    """Render a concise Markdown report from a posture-index JSON object."""
    summary = posture.get("summary", {}) if isinstance(posture.get("summary"), Mapping) else {}
    verdicts = summary.get("policy_verdict_counts", {}) if isinstance(summary.get("policy_verdict_counts"), Mapping) else {}
    boundaries = summary.get("boundary_counts", {}) if isinstance(summary.get("boundary_counts"), Mapping) else {}
    chain = posture.get("chain_verification", {}) if isinstance(posture.get("chain_verification"), Mapping) else {}
    tools = posture.get("observed_tools", {}) if isinstance(posture.get("observed_tools"), Mapping) else {}
    actions = posture.get("observed_actions", {}) if isinstance(posture.get("observed_actions"), Mapping) else {}
    policy = posture.get("policy", {}) if isinstance(posture.get("policy"), Mapping) else {}
    profile = posture.get("profile", {}) if isinstance(posture.get("profile"), Mapping) else {}
    gaps = posture.get("coverage_gaps", []) if isinstance(posture.get("coverage_gaps"), list) else []

    lines = [
        "# Ardur Posture Report",
        "",
        "This report is derived local evidence from Ardur artifacts. It is not live enterprise-wide discovery, provider-hidden visibility, or kernel/process capture.",
        "",
        f"- Positioning: {posture.get('positioning', POSITIONING)}",
        f"- Chain verification: {chain.get('status', 'unknown')}",
        f"- Chains: {summary.get('chain_count', 0)}",
        f"- Receipts: {summary.get('receipt_count', 0)}",
        f"- Policy verdicts: allow {verdicts.get('allow', 0)}, deny {verdicts.get('deny', 0)}, unknown {verdicts.get('unknown', 0)}",
        f"- Boundary coverage: tool-call {boundaries.get('tool_call', 0)}, unknown {boundaries.get('unknown', 0)}, missing {boundaries.get('missing', 0)}",
        "",
        "## Observed tools",
    ]
    if tools:
        for name, count in sorted(tools.items()):
            lines.append(f"- {name}: {count}")
    else:
        lines.append("- none")

    lines.extend(["", "## Observed actions"])
    if actions:
        for name, count in sorted(actions.items()):
            lines.append(f"- {name}: {count}")
    else:
        lines.append("- none")

    lines.extend(["", "## Policy/profile digests"])
    digests = policy.get("digests", []) if isinstance(policy.get("digests"), list) else []
    if digests:
        for digest in digests:
            lines.append(f"- policy: {digest}")
    else:
        lines.append("- policy: not present")
    if profile.get("present"):
        lines.append(f"- profile: sha256:{profile.get('sha256', 'unknown')}")
    else:
        lines.append("- profile: not present")

    lines.extend(["", "## Coverage gaps"])
    if gaps:
        for gap in sorted(str(item) for item in gaps):
            lines.append(f"- {gap}")
    else:
        lines.append("- none")

    lines.append("")
    return "\n".join(lines)
