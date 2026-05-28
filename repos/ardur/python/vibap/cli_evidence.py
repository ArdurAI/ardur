"""
Phase 2 CLI surface for evidence export (small reviewable module).

Provides the command implementation for:
  ardur evidence export --session <jti> --output <path> [--include-kernel] [--include-semantic]

This will be wired into the main cli.py in a later small PR.
Uses the kernel_receipt_integration + evidence_exporter for real work.
"""

from __future__ import annotations
import argparse
from typing import Optional

from .evidence_exporter import export_evidence_bundle_cli
from .kernel_receipt_integration import export_session_evidence


def add_evidence_subparser(subparsers: argparse._SubParsersAction) -> None:
    """Register the 'evidence' subcommand group."""
    p = subparsers.add_parser("evidence", help="Regulator evidence bundle operations")
    evidence_sub = p.add_subparsers(dest="evidence_cmd", required=True)

    export_p = evidence_sub.add_parser("export", help="Export a signed/unsigned evidence bundle for a session")
    export_p.add_argument("--session", required=True, help="Session/trace JTI")
    export_p.add_argument("--output", required=True, help="Output file path for the bundle JSON")
    export_p.add_argument("--include-kernel", action="store_true", default=True)
    export_p.add_argument("--include-semantic", action="store_true", default=False)
    export_p.set_defaults(func=_export_cmd)


def _export_cmd(args: argparse.Namespace) -> int:
    # For now uses the integration path (which can pull real/simulated kernel data)
    # In a real wiring this would load an actual session + client from the proxy.
    rc = export_evidence_bundle_cli(
        args.session,
        args.output,
        include_kernel=args.include_kernel,
        include_semantic=args.include_semantic,
    )
    return rc


def main(argv: Optional[list[str]] = None) -> int:
    """Standalone entry for testing the evidence subcommand surface."""
    parser = argparse.ArgumentParser(prog="ardur evidence")
    subparsers = parser.add_subparsers(dest="cmd", required=True)
    add_evidence_subparser(subparsers)
    args = parser.parse_args(argv)
    if hasattr(args, "func"):
        return args.func(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
