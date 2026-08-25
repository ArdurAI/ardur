#!/usr/bin/env python3
"""Validate the daemon-emitted #39 metric in an ardur run demo home."""

import base64
import glob
import json
import os
import stat
import sys


def attestation_claims(home: str) -> dict:
    for path in glob.glob(f"{home}/**/*", recursive=True):
        try:
            metadata = os.lstat(path)
        except OSError:
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 2 * 1024 * 1024:
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as source:
                text = source.read()
        except OSError:
            continue
        for token in text.replace('"', " ").split():
            if not (token.startswith("ey") and token.count(".") == 2 and len(token) > 80):
                continue
            try:
                payload = token.split(".")[1]
                payload += "=" * (-len(payload) % 4)
                claims = json.loads(base64.urlsafe_b64decode(payload))
            except (ValueError, UnicodeDecodeError):
                continue
            if "scope_compliance" in claims:
                return claims
    raise SystemExit("FAIL: session attestation not found")


claims = attestation_claims(sys.argv[1])
gap = (claims.get("kernel_enforcement") or {}).get("observability_gap") or {}
required = {
    "effect_scope": "process_lifecycle",
    "receipt_source_assurance": "authenticated_session_owner",
}
for field, expected in required.items():
    if gap.get(field) != expected:
        raise SystemExit(f"FAIL: observability_gap.{field}={gap.get(field)!r}, want {expected!r}")
if gap.get("status") not in {"measured", "degraded"}:
    raise SystemExit(f"FAIL: observability_gap.status={gap.get('status')!r}")
for field in ("registered_receipts", "corroborated_receipts", "captured_effects", "correlated_effects"):
    if not isinstance(gap.get(field), int) or gap[field] < 1:
        raise SystemExit(f"FAIL: observability_gap.{field}={gap.get(field)!r}, want >= 1")
if not isinstance(gap.get("observed_effect_gap_ratio"), (int, float)):
    raise SystemExit("FAIL: observability_gap.observed_effect_gap_ratio is not measured")

print(f"observability gap status = {gap['status']}")
print(f"observability gap captured effects = {gap['captured_effects']}")
print(f"observability gap correlated effects = {gap['correlated_effects']}")
print(f"observability gap ratio = {gap['observed_effect_gap_ratio']}")
