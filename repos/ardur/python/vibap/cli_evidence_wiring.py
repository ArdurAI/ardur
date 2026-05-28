"""
Phase 2 CLI wiring (exact small delta for cli.py).

In the main cli.py, near the other subparser registrations (search for similar patterns
like "add_.*_subparser"), add these two lines:

    from .cli_evidence import add_evidence_subparser
    add_evidence_subparser(subparsers)

This file exists purely so the change is reviewable and documented. No other logic here.
"""

# The one-time registration call (copy-paste into cli.py):
# from .cli_evidence import add_evidence_subparser
# add_evidence_subparser(subparsers)
