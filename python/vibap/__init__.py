"""Public package API for the Ardur governance proxy."""

from .attestation import compute_log_digest, issue_attestation, verify_attestation
from .drp import (
    DRPEmissionError,
    DRPProfileError,
    DRPVerificationContext,
    DRPVerificationError,
    DRPVerificationResult,
    DRPVerifiedLogEvidence,
    DRPVerifiedReceiptChainEvidence,
    DRPVerifiedRevocationEvidence,
    emit_drp_receipt,
    tool_universe_digest,
    validate_drp_receipt,
    verify_drp_chain,
)
from .mission import MissionCache, MissionDeclaration, load_mission_declaration
from .passport import (
    ALGORITHM,
    DEFAULT_AUDIENCE,
    DEFAULT_ISSUER,
    MissionPassport,
    derive_child_passport,
    generate_keypair,
    issue_passport,
    load_mission_file,
    verify_passport,
)
from .proxy import Decision, GovernanceProxy, GovernanceSession, PolicyEvent
from .receipt import ExecutionReceipt, build_receipt, sign_receipt, verify_receipt

__all__ = [
    "ALGORITHM",
    "DEFAULT_AUDIENCE",
    "DEFAULT_ISSUER",
    "Decision",
    "DRPEmissionError",
    "DRPProfileError",
    "DRPVerificationContext",
    "DRPVerificationError",
    "DRPVerificationResult",
    "DRPVerifiedLogEvidence",
    "DRPVerifiedReceiptChainEvidence",
    "DRPVerifiedRevocationEvidence",
    "ExecutionReceipt",
    "GovernanceProxy",
    "GovernanceSession",
    "MissionPassport",
    "MissionCache",
    "MissionDeclaration",
    "PolicyEvent",
    "build_receipt",
    "compute_log_digest",
    "derive_child_passport",
    "emit_drp_receipt",
    "generate_keypair",
    "issue_attestation",
    "issue_passport",
    "load_mission_declaration",
    "load_mission_file",
    "sign_receipt",
    "tool_universe_digest",
    "validate_drp_receipt",
    "verify_attestation",
    "verify_receipt",
    "verify_drp_chain",
    "verify_passport",
]

__version__ = "0.2.0"
