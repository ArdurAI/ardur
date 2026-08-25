package aat

import (
	"errors"
	"fmt"
)

var (
	// Generic scaffold errors.
	ErrNotImplemented                      = errors.New("aat: not implemented")
	ErrVerifyChainNotImplemented           = fmt.Errorf("%w: chain verification", ErrNotImplemented)
	ErrDeriveChildNotImplemented           = fmt.Errorf("%w: child derivation", ErrNotImplemented)
	ErrIssueRootNotImplemented             = fmt.Errorf("%w: root issuance", ErrNotImplemented)
	ErrBuildPoPJWTNotImplemented           = fmt.Errorf("%w: pop jwt build", ErrNotImplemented)
	ErrVerifyPoPJWTNotImplemented          = fmt.Errorf("%w: pop jwt verify", ErrNotImplemented)
	ErrCanonicalizationNotImplemented      = fmt.Errorf("%w: jcs canonicalization", ErrNotImplemented)
	ErrConstraintCheckNotImplemented       = fmt.Errorf("%w: constraint check predicate", ErrNotImplemented)
	ErrConstraintSubsumptionNotImplemented = fmt.Errorf("%w: constraint subsumption", ErrNotImplemented)

	// Invariant tracking placeholders (AAT §4, I1-I6).
	ErrInvariantI1NotImplemented = fmt.Errorf("%w: I1 signer linkage", ErrNotImplemented)
	ErrInvariantI2NotImplemented = fmt.Errorf("%w: I2 delegation depth monotonicity", ErrNotImplemented)
	ErrInvariantI3NotImplemented = fmt.Errorf("%w: I3 ttl monotonicity", ErrNotImplemented)
	ErrInvariantI4NotImplemented = fmt.Errorf("%w: I4 capability monotonicity", ErrNotImplemented)
	ErrInvariantI5NotImplemented = fmt.Errorf("%w: I5 cryptographic linkage", ErrNotImplemented)
	ErrInvariantI6NotImplemented = fmt.Errorf("%w: I6 proof of possession", ErrNotImplemented)

	// Constraint registry errors.
	ErrUnknownConstraintType    = errors.New("aat: unknown constraint type")
	ErrDuplicateConstraintType  = errors.New("aat: duplicate constraint type registration")
	ErrNilConstraintHandler     = errors.New("aat: nil constraint handler")
	ErrNilConstraint            = errors.New("aat: nil constraint")
	ErrUnsupportedDraftRevision = fmt.Errorf(
		"aat: unprofiled %s wire is unsupported; use the explicit %s profile or the %s wire contract",
		Draft01Revision,
		DGProfileV02,
		SupportedDraftRevision,
	)
	ErrUnknownDGProfile      = errors.New("aat: unknown or missing Ardur DG profile")
	ErrMixedDraftWire        = errors.New("aat: mixed draft-00 and draft-01 wire claims")
	ErrProfileMismatch       = errors.New("aat: delegation chain changes DG profile")
	ErrDraft01Constraint     = errors.New("aat: constraint is not in the draft-01 core vocabulary")
	ErrDraft01HolderKeyReuse = errors.New("aat: DG v0.2 requires a fresh holder key at every derivation")
	ErrReceiptSignerKeyReuse = errors.New("aat: AAT holder key must differ from the DRP receipt signer key")
	ErrApprovalRefInvalid    = errors.New("aat: invalid DG approval requirement reference")
	ErrApprovalRefDropped    = errors.New("aat: derived token drops a DG approval requirement")
	ErrApprovalUnsatisfied   = errors.New("aat: required DG approval was not independently satisfied")
	ErrMissionRefInvalid     = errors.New("aat: DG v0.2 mission_ref is missing or invalid")
	ErrMissionRefChanged     = errors.New("aat: derived token changes DG mission_ref")
	ErrPoPAudienceRequired   = errors.New("aat: DG v0.2 PoP audience is required")
	ErrPoPAudienceMismatch   = errors.New("aat: PoP audience does not match the enforcement point")

	// Chain verification DENY points (AAT §7).
	ErrDenyStep1EmptyChain = errors.New("aat: deny step 1 empty chain")

	ErrDenyStep2ATokenTooLarge  = errors.New("aat: deny step 2a token exceeds MAX_TOKEN_SIZE")
	ErrDenyStep2BChainTooLarge  = errors.New("aat: deny step 2b chain exceeds MAX_STACK_SIZE")
	ErrDenyStep2CInvalidPayload = errors.New("aat: deny step 2c invalid payload json")
	ErrDenyStep2CMissingJTI     = errors.New("aat: deny step 2c missing or non-string jti")
	ErrDenyStep2CDuplicateJTI   = errors.New("aat: deny step 2c duplicate jti cycle detected")

	ErrDenyStep3AInvalidRootAlg    = errors.New("aat: deny step 3a invalid root alg")
	ErrDenyStep3BRootSignature     = errors.New("aat: deny step 3b root signature verification failed")
	ErrDenyStep3CInvalidRootType   = errors.New("aat: deny step 3c invalid root aat_type")
	ErrDenyStep3DInvalidRootDepth  = errors.New("aat: deny step 3d root del_depth must be 0")
	ErrDenyStep3ERootParentHash    = errors.New("aat: deny step 3e root par_hash must be absent")
	ErrDenyStep3FRootExpired       = errors.New("aat: deny step 3f root exp is not in the future")
	ErrDenyStep3GRootIATSkew       = errors.New("aat: deny step 3g root iat exceeds MAX_IAT_SKEW")
	ErrDenyStep3HRootLifetimeOrder = errors.New("aat: deny step 3h root exp must be greater than iat")
	ErrDenyStep3IRootLifetimeBound = errors.New("aat: deny step 3i root lifetime exceeds MAX_TOKEN_LIFETIME")
	ErrDenyStep3JRootMaxDepth      = errors.New("aat: deny step 3j invalid root del_max_depth")
	ErrDenyStep3KRootJTI           = errors.New("aat: deny step 3k missing root jti")
	ErrDenyStep3LRootIssuer        = errors.New("aat: deny step 3l invalid root iss uri")
	ErrDenyStep3MRootCNF           = errors.New("aat: deny step 3m invalid root cnf.jwk")
	ErrDenyStep3NRootAuthorization = errors.New("aat: deny step 3n invalid root authorization_details")

	ErrDenyStep4AInvalidChildAlg               = errors.New("aat: deny step 4a invalid child alg")
	ErrDenyStep4BChildSignature                = errors.New("aat: deny step 4b child signature verification failed")
	ErrDenyStep4B1ChildJTI                     = errors.New("aat: deny step 4b1 missing child jti")
	ErrDenyStep4B2ChildCNF                     = errors.New("aat: deny step 4b2 invalid child cnf.jwk")
	ErrDenyStep4B3ChildAuthorization           = errors.New("aat: deny step 4b3 invalid child authorization_details")
	ErrDenyStep4B4ChildDepthClaims             = errors.New("aat: deny step 4b4 invalid child depth claims")
	ErrDenyStep4B5ChildRequiredClaims          = errors.New("aat: deny step 4b5 missing child required claims")
	ErrDenyStep4CIssuerMismatch                = errors.New("aat: deny step 4c child iss does not match parent cnf.jwk thumbprint uri")
	ErrDenyStep4DInvalidChildType              = errors.New("aat: deny step 4d invalid child aat_type")
	ErrDenyStep4EInvalidDepthIncrement         = errors.New("aat: deny step 4e child del_depth must equal parent del_depth + 1")
	ErrDenyStep4FDepthExceedsParentMax         = errors.New("aat: deny step 4f child del_depth exceeds parent del_max_depth")
	ErrDenyStep4GDepthExceedsImplementationMax = errors.New("aat: deny step 4g child del_depth exceeds MAX_DELEGATION_DEPTH")
	ErrDenyStep4HChildMaxDepth                 = errors.New("aat: deny step 4h child del_max_depth exceeds parent del_max_depth")
	ErrDenyStep4IChildExpAfterParent           = errors.New("aat: deny step 4i child exp exceeds parent exp")
	ErrDenyStep4JChildExpired                  = errors.New("aat: deny step 4j child exp is not in the future")
	ErrDenyStep4KChildIATBeforeParent          = errors.New("aat: deny step 4k child iat precedes parent iat")
	ErrDenyStep4LChildIATSkew                  = errors.New("aat: deny step 4l child iat exceeds MAX_IAT_SKEW")
	ErrDenyStep4MChildLifetimeOrder            = errors.New("aat: deny step 4m child exp must be greater than iat")
	ErrDenyStep4NChildDepthWindow              = errors.New("aat: deny step 4n child del_depth exceeds child del_max_depth")
	ErrDenyStep4OMultipleAATEntries            = errors.New("aat: deny step 4o multiple attenuating_agent_token entries")
	ErrDenyStep4PConstraintDepth               = errors.New("aat: deny step 4p constraint tree exceeds MAX_CONSTRAINT_DEPTH")
	ErrDenyStep4Q1ToolExpansion                = errors.New("aat: deny step 4q1 child tool not present in parent authorization")
	ErrDenyStep4Q2ArgumentShape                = errors.New("aat: deny step 4q2 child argument keys differ from parent closed-world shape")
	ErrDenyStep4Q4ConstraintSubsume            = errors.New("aat: deny step 4q4 child constraint does not subsume parent")
	ErrDenyStep4RParentHash                    = errors.New("aat: deny step 4r child par_hash mismatch")
	ErrDenyStep4STypeTransitionKeyReuse        = errors.New("aat: deny step 4s type-transition key separation violated")

	ErrDenyStep5ChainLengthMismatch = errors.New("aat: deny step 5 chain length does not equal leaf del_depth + 1")

	ErrDenyStep6ALeafAuthorization       = errors.New("aat: deny step 6a leaf must contain exactly one attenuating_agent_token authorization entry")
	ErrDenyStep6BLeafToolUnauthorized    = errors.New("aat: deny step 6b leaf tool is not authorized")
	ErrDenyStep6BLeafUnknownArgument     = errors.New("aat: deny step 6b unknown argument in closed-world constraint map")
	ErrDenyStep6BLeafMissingArgument     = errors.New("aat: deny step 6b constrained argument missing from invocation")
	ErrDenyStep6BLeafConstraintViolation = errors.New("aat: deny step 6b leaf argument failed constraint check")
	ErrDenyStep6CDelegationLeaf          = errors.New("aat: deny step 6c delegation token cannot authorize direct invocation")

	ErrDenyStep7APoPSignature = errors.New("aat: deny step 7a pop signature verification failed")
	ErrDenyStep7AMissingJTI   = errors.New("aat: deny step 7a pop jti is required")
	ErrDenyStep7ANonCanonical = errors.New("aat: deny step 7a pop payload is not RFC 8785 canonical JSON")
	ErrDenyStep7BAATID        = errors.New("aat: deny step 7b pop aat_id does not match leaf jti")
	ErrDenyStep7CPoPTool      = errors.New("aat: deny step 7c pop aat_tool does not match requested tool")
	ErrDenyStep7DHTAMismatch  = errors.New("aat: deny step 7d pop hta does not match canonicalized args")
	ErrDenyStep7EPopIAT       = errors.New("aat: deny step 7e pop iat outside accepted clock tolerance")
)
