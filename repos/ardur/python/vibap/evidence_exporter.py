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

    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2, sort_keys=True)

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
