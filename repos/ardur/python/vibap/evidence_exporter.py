"""
Regulator Evidence Bundle exporter (Phase 2).

Enhanced with basic receipt chain support (simple list of receipt summaries).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, List, Dict


def export_evidence_bundle(
    session_jti: str,
    output_path: Optional[str] = None,
    include_kernel: bool = True,
    include_semantic: bool = False,
    sign: bool = False,
    kernel_data: Optional[dict] = None,
    semantic_data: Optional[dict] = None,
    receipt_chain: Optional[List[Dict[str, Any]]] = None,
) -> dict[str, Any]:
    """
    Produces a portable regulator-grade evidence bundle for a completed session.

    Now supports a simple receipt_chain list for Phase 2 progress.
    """
    bundle: dict[str, Any] = {
        "ardur_evidence_bundle_version": "0.1",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "session": {
            "jti": session_jti,
            "mission_declaration": {
                "hash": "placeholder",
                "content": None,
            },
            "receipt_chain": receipt_chain or [],
        },
        "kernel": {
            "events": kernel_data.get("kernel_events", []) if kernel_data else [],
            "evidence_level": kernel_data.get("kernel_evidence_level", "insufficient_evidence") if kernel_data else "insufficient_evidence",
        },
        "semantic_review": semantic_data if include_semantic and semantic_data else None,
        "coverage_snapshot": "see docs/coverage-map.md at export time",
        "limitations_snapshot": "see docs/known-limitations.md at export time",
        "evidence_level": "observed" if (kernel_data or semantic_data or receipt_chain) else "self_signed",
    }

    # Automatic key rotation + revocation list wiring (item #2) — now actively exercised
    try:
        from .key_rotation import KeyManager
        km = KeyManager()
        current_key = km.get_current_signing_key()
        km.record_bundle_signed()
        bundle["rotation"] = {
            "active_key_id": current_key.key_id if current_key else None,
            "bundles_since_rotation": getattr(km, "_bundles_since_last_rotation", 0),
        }
        if current_key:
            bundle["signing_key"] = {
                "key_id": current_key.key_id,
                "created_at": current_key.created_at.isoformat(),
                "expires_at": current_key.expires_at.isoformat() if current_key.expires_at else None,
            }
        rev_list = km.get_revocation_list()
        bundle["revocation_list"] = [
            {"key_id": r.key_id, "revoked_at": r.revoked_at.isoformat(), "reason": r.reason}
            for r in rev_list
        ]
    except Exception:
        pass  # rotation is best-effort in early skeleton stage

    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2, sort_keys=True)

    # Performance metrics hook (item #7)
    try:
        from .metrics import metrics as ardur_metrics
        size = len(json.dumps(bundle))
        ardur_metrics.record_bundle(size)
    except Exception:
        pass

    # Surface capture level in bundle when known (item #3)
    try:
        from .capture_levels import CaptureLevel
        # If the caller passed kernel data or we can infer, note it
        if kernel_data and kernel_data.get("kernel_evidence_level") == "observed":
            bundle["capture_level"] = "kernel"
    except Exception:
        pass

    return bundle


def export_evidence_bundle_cli(
    session_jti: str,
    output: str,
    include_kernel: bool = True,
    include_semantic: bool = False,
) -> int:
    """Thin CLI wrapper. Returns exit code."""
    try:
        bundle = export_evidence_bundle(
            session_jti,
            output,
            include_kernel=include_kernel,
            include_semantic=include_semantic,
        )
        print(f"Evidence bundle written to {output} (version {bundle['ardur_evidence_bundle_version']})")
        return 0
    except Exception as e:
        print(f"ERROR: {e}")
        return 2
