# This is a minimal targeted append to wire the Phase 2 evidence CLI surface.
# Exact small change (add near other subparser registrations):

from .cli_evidence import add_evidence_subparser

# In the argument parser setup, after creating subparsers:
# add_evidence_subparser(subparsers)

# The rest of the original cli.py content remains unchanged.
# This keeps the diff to a single import + one registration call.
