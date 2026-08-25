#!/usr/bin/env python3
"""Validate Hugo claim metadata before the public site builds."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SITE_ROOT = REPO_ROOT / "site"
CLAIMS_PATH = SITE_ROOT / "data" / "claims.json"
CONTENT_ROOT = SITE_ROOT / "content"

REQUIRED_BOUNDARY_CLAIM_ID = "configured-tool-boundary"
PUBLIC_FRAMING_PATHS = (
    Path("README.md"),
    Path("STATUS.md"),
    Path("go/README.md"),
    Path("site/content/_index.md"),
    Path("site/content/build/python-go.md"),
    Path("site/content/get-started.md"),
    Path("site/content/how-it-works.md"),
    Path("site/content/proof.md"),
)
AUDITBENCH_PROTOCOL_PATH = Path("docs/specs/auditbench-evaluation-protocol-v0.1.md")
LEGACY_AUDITBENCH_PROFILE_PATH = Path(
    "docs/specs/auditbench-independent-evaluation-v0.1.md"
)
AUDITBENCH_FRAMING_PATHS = (
    Path("README.md"),
    Path("ROADMAP.md"),
    Path("STATUS.md"),
    Path("REPRODUCE.md"),
    Path("docs/TESTING.md"),
    Path("docs/known-limitations.md"),
    Path("docs/specs/README.md"),
    Path("Makefile"),
    Path("go/cmd/auditbench-score/main.go"),
)
FORBIDDEN_PUBLIC_PHRASES = (
    "blocks anything outside that boundary",
    "proof of every decision",
    "no bypass, no direct access",
    "the agent never touches resources it shouldn't",
    "captures every claude code tool-call invocation",
    "complete implementation of the attenuating authorization token",
    "every single tool call went through ardur first",
    "every `permit` was correct",
)
FORBIDDEN_AUDITBENCH_PATTERNS = (
    re.compile(r"\bauditbench independent(?:[ -])evaluation\b"),
    re.compile(r"\bindependent auditbench pipeline\b"),
    re.compile(r"\bsealed independent(?:[ -])evaluation pipeline\b"),
    re.compile(r"\bscores independently labeled studies\b"),
)
REQUIRED_AUDITBENCH_BOUNDARIES = (
    "content-integrity seal",
    "self-asserted identity strings",
    "does not authenticate annotators",
    "does not demonstrate evaluator independence",
    "no real annotation study has been run",
)

REQUIRED_FIELDS = {
    "id",
    "title",
    "body",
    "evidence_level",
    "maturity",
    "claim_type",
    "surface",
    "framework",
    "source_paths",
}

ALLOWED_MATURITY = {"public-now", "in-progress", "not-public-yet"}
ALLOWED_EVIDENCE_LEVEL = {
    "archival-media",
    "code-and-doc",
    "doc-and-manifest",
    "limitation-backed",
    "spec",
}


def fail(message: str) -> None:
    print(f"claim validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_claims() -> list[dict[str, object]]:
    try:
        payload = json.loads(CLAIMS_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing {CLAIMS_PATH.relative_to(REPO_ROOT)}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {CLAIMS_PATH.relative_to(REPO_ROOT)}: {exc}")
    claims = payload.get("claims")
    if not isinstance(claims, list) or not claims:
        fail("claims.json must contain a non-empty 'claims' list")
    return claims


def validate_claim(claim: dict[str, object], seen: set[str]) -> str:
    missing = sorted(REQUIRED_FIELDS - claim.keys())
    if missing:
        fail(f"claim is missing required fields: {', '.join(missing)}")

    claim_id = claim["id"]
    if not isinstance(claim_id, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9-]+", claim_id
    ):
        fail(f"invalid claim id: {claim_id!r}")
    if claim_id in seen:
        fail(f"duplicate claim id: {claim_id}")
    seen.add(claim_id)

    for field in ("title", "body", "evidence_level", "maturity", "claim_type"):
        if not isinstance(claim[field], str) or not claim[field].strip():
            fail(f"{claim_id}: field '{field}' must be a non-empty string")

    if claim["maturity"] not in ALLOWED_MATURITY:
        fail(f"{claim_id}: unknown maturity {claim['maturity']!r}")
    if claim["evidence_level"] not in ALLOWED_EVIDENCE_LEVEL:
        fail(f"{claim_id}: unknown evidence_level {claim['evidence_level']!r}")

    for field in ("surface", "framework", "source_paths"):
        value = claim[field]
        if not isinstance(value, list) or not value:
            fail(f"{claim_id}: field '{field}' must be a non-empty list")
        if not all(isinstance(item, str) and item.strip() for item in value):
            fail(f"{claim_id}: field '{field}' must contain only non-empty strings")

    for source in claim["source_paths"]:
        relative_source = Path(source)
        source_path = REPO_ROOT / relative_source
        if relative_source.is_absolute() or ".." in relative_source.parts:
            fail(f"{claim_id}: source path escapes repo: {source}")
        if not source_path.exists():
            fail(f"{claim_id}: source path does not exist: {source}")

    claim_page = CONTENT_ROOT / "claims" / f"{claim_id}.md"
    if not claim_page.exists():
        fail(f"{claim_id}: missing claim page {claim_page.relative_to(REPO_ROOT)}")
    page_text = claim_page.read_text(encoding="utf-8")
    if f'{{{{< claim "{claim_id}" >}}}}' not in page_text:
        fail(f"{claim_id}: claim page does not render its claim shortcode")

    return claim_id


def validate_public_framing(seen: set[str]) -> None:
    if REQUIRED_BOUNDARY_CLAIM_ID not in seen:
        fail(f"missing required boundary claim: {REQUIRED_BOUNDARY_CLAIM_ID}")

    for relative_path in PUBLIC_FRAMING_PATHS:
        text = (REPO_ROOT / relative_path).read_text(encoding="utf-8").lower()
        for phrase in FORBIDDEN_PUBLIC_PHRASES:
            if phrase in text:
                fail(f"{relative_path}: forbidden public overclaim phrase: {phrase!r}")


def validate_auditbench_framing() -> None:
    if (REPO_ROOT / LEGACY_AUDITBENCH_PROFILE_PATH).exists():
        fail(
            "legacy AuditBench independent-evaluation profile still exists: "
            f"{LEGACY_AUDITBENCH_PROFILE_PATH}"
        )
    protocol_path = REPO_ROOT / AUDITBENCH_PROTOCOL_PATH
    if not protocol_path.exists():
        fail(f"missing AuditBench evaluation protocol: {AUDITBENCH_PROTOCOL_PATH}")

    protocol_text = protocol_path.read_text(encoding="utf-8").lower()
    for phrase in REQUIRED_AUDITBENCH_BOUNDARIES:
        if phrase not in protocol_text:
            fail(f"{AUDITBENCH_PROTOCOL_PATH}: missing proof boundary: {phrase!r}")

    for relative_path in AUDITBENCH_FRAMING_PATHS:
        text = (REPO_ROOT / relative_path).read_text(encoding="utf-8").lower()
        for pattern in FORBIDDEN_AUDITBENCH_PATTERNS:
            if pattern.search(text):
                fail(
                    f"{relative_path}: forbidden AuditBench framing: "
                    f"{pattern.pattern!r}"
                )

    reproduce = (REPO_ROOT / "REPRODUCE.md").read_text(encoding="utf-8")
    if not reproduce.startswith("# Reproducing AuditBench Harness Fixtures\n"):
        fail("REPRODUCE.md must identify the current outputs as harness fixtures")

    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    if "bench-independent-test" in makefile or "bench-protocol-test" not in makefile:
        fail("Makefile must expose bench-protocol-test without the legacy target")

    score_cli = (REPO_ROOT / "go/cmd/auditbench-score/main.go").read_text(
        encoding="utf-8"
    )
    for phrase in ("unsigned content-integrity seal", "local content-integrity seal"):
        if phrase not in score_cli:
            fail(f"auditbench-score output must disclose {phrase!r}")


def main() -> int:
    seen: set[str] = set()
    claims = load_claims()
    for claim in claims:
        if not isinstance(claim, dict):
            fail("every claim entry must be an object")
        validate_claim(claim, seen)
    validate_public_framing(seen)
    validate_auditbench_framing()

    print(f"validated {len(claims)} public-site claims")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
