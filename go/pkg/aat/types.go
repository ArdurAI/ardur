// Package aat implements the JWT path of the Attenuating Authorization Tokens
// (AAT) profile adopted by Ardur. It includes issuance, attenuation,
// proof-of-possession, constraint, and chain-verification logic.
//
// Spec reference:
//   - draft-niyikiza-oauth-attenuating-agent-tokens-00
//   - draft-niyikiza-oauth-attenuating-agent-tokens-01
//
// The companion CWT integer claim-key mapping remains pending; see ClaimKeys.
package aat

import (
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	AuthorizationDetailType  = "attenuating_agent_token"
	SigningAlgorithmEdDSA    = "EdDSA"
	SupportedDraftRevision   = "draft-niyikiza-oauth-attenuating-agent-tokens-00"
	Draft01Revision          = "draft-niyikiza-oauth-attenuating-agent-tokens-01"
	UnsupportedDraftRevision = Draft01Revision
	DGProfileV02             = "ardur.dg.aat-draft-01.v0.2"

	// TODO(B.5/Appendix-D.3): assign integer claim keys in the companion CWT
	// profile document once Appendix D.3 is translated into repo-local
	// guidance.
)

// AATType is the wire value for the aat_type claim (AAT §3.1).
type AATType string

const (
	AATTypeDelegation AATType = "delegation"
	AATTypeExecution  AATType = "execution"
)

// ConstraintType identifies the constraint_type member for tool arguments
// (AAT §3.4).
type ConstraintType string

const (
	ConstraintTypeExact    ConstraintType = "exact"
	ConstraintTypePattern  ConstraintType = "pattern"
	ConstraintTypeRange    ConstraintType = "range"
	ConstraintTypeOneOf    ConstraintType = "one_of"
	ConstraintTypeNotOneOf ConstraintType = "not_one_of"
	ConstraintTypeContains ConstraintType = "contains"
	ConstraintTypeSubset   ConstraintType = "subset"
	ConstraintTypeRegex    ConstraintType = "regex"
	ConstraintTypeCEL      ConstraintType = "cel"
	ConstraintTypeWildcard ConstraintType = "wildcard"
	ConstraintTypeAll      ConstraintType = "all"
	ConstraintTypeAny      ConstraintType = "any"
	ConstraintTypeNot      ConstraintType = "not"
)

// Verdict captures the verifier outcome for the current scaffold.
type Verdict string

const (
	VerdictPermit        Verdict = "permit"
	VerdictDeny          Verdict = "deny"
	VerdictIndeterminate Verdict = "indeterminate"
)

// Token is the generic AAT artifact shared by delegation and execution tokens.
// The JSON fields map directly to the common claims defined in AAT §3.2.
type Token struct {
	// JOSE/JWS metadata retained for chain verification and later signing work.
	Header           jose.Header `json:"-"`
	Compact          string      `json:"-"`
	ProtectedSegment string      `json:"-"`
	PayloadSegment   string      `json:"-"`
	SignatureSegment string      `json:"-"`
	SigningInput     string      `json:"-"`

	// Common AAT claims (AAT §3.2).
	JWTID              string                `json:"jti"`
	Issuer             string                `json:"iss"`
	IssuedAt           int64                 `json:"iat"`
	ExpiresAt          int64                 `json:"exp"`
	Confirmation       *ConfirmationKey      `json:"cnf,omitempty"`
	TokenType          AATType               `json:"aat_type"`
	DelegationDepth    int                   `json:"del_depth"`
	DelegationMaxDepth int                   `json:"del_max_depth"`
	ParentHash         string                `json:"par_hash,omitempty"`
	Authorization      []AuthorizationDetail `json:"authorization_details,omitempty"`

	// DG v0.2 profile claims. They are absent from the draft-00 profile.
	Profile      string   `json:"ardur_dg_profile,omitempty"`
	MissionRef   any      `json:"mission_ref,omitempty"`
	ApprovalRefs []string `json:"ardur_approval_refs,omitempty"`

	// Unknown top-level claims are intentionally preserved for future extension
	// handling. Per AAT §3.4, unrecognized top-level claims do not by themselves
	// invalidate a token.
	Extensions map[string]any `json:"-"`
}

// IsRoot reports whether the token shape is consistent with a root token.
func (t *Token) IsRoot() bool {
	return t != nil && t.DelegationDepth == 0 && t.ParentHash == ""
}

// DelegationGrant is the VIBAP-facing name for an AAT delegation token.
type DelegationGrant struct {
	Token
}

// ExecutionToken is the AAT artifact presented at tool-invocation time.
type ExecutionToken struct {
	Token
}

// ConfirmationKey models the cnf claim required by AAT §3.2.
type ConfirmationKey struct {
	JWK jose.JSONWebKey `json:"jwk"`
}

// AuthorizationDetail profiles RFC 9396 authorization_details for AAT tool
// capabilities (AAT §3.3).
type AuthorizationDetail struct {
	Type  string  `json:"type"`
	Tools ToolMap `json:"tools,omitempty"`
}

// ToolMap maps tool identifiers to their argument constraint maps.
type ToolMap map[string]ArgumentConstraintMap

// ArgumentConstraintMap maps an argument name to its governing constraint.
//
// An empty map authorizes the tool without argument restrictions. Closed-world
// semantics apply when the map is non-empty (AAT §3.3).
type ArgumentConstraintMap map[string]*Constraint

// Constraint is the wire-format union for all core AAT argument constraints
// defined in AAT §3.4. Type-specific members are carried directly on the
// struct so every normative claim/member has a concrete field in Go.
type Constraint struct {
	ConstraintType ConstraintType `json:"constraint_type"`

	// exact, pattern
	Value any `json:"value,omitempty"`

	// range
	Min          *float64 `json:"min,omitempty"`
	Max          *float64 `json:"max,omitempty"`
	MinInclusive *bool    `json:"min_inclusive,omitempty"`
	MaxInclusive *bool    `json:"max_inclusive,omitempty"`

	// one_of, not_one_of, contains, subset
	Values   []any `json:"values,omitempty"`
	Excluded []any `json:"excluded,omitempty"`
	Required []any `json:"required,omitempty"`
	Allowed  []any `json:"allowed,omitempty"`

	// regex, cel
	Pattern    string `json:"pattern,omitempty"`
	Expression string `json:"expression,omitempty"`

	// all, any, not
	Children []*Constraint `json:"constraints,omitempty"`
	Inner    *Constraint   `json:"constraint,omitempty"`

	// Unknown members for extension constraints are deferred to later waves.
	Extensions map[string]any `json:"-"`
}

// PoPJWT is the proof-of-possession artifact defined in AAT §5.2.
type PoPJWT struct {
	Header       jose.Header    `json:"-"`
	Compact      string         `json:"-"`
	SigningInput string         `json:"-"`
	JWTID        string         `json:"jti"`
	IssuedAt     int64          `json:"iat"`
	AATID        string         `json:"aat_id"`
	AATTool      string         `json:"aat_tool"`
	AATAudience  string         `json:"aat_aud,omitempty"`
	HTA          map[string]any `json:"hta"`
}

// VerifyChainOpts carries Ardur DG profile inputs that are intentionally not
// inferred from attacker-controlled token claims.
type VerifyChainOpts struct {
	Now                   time.Time
	Audience              string
	ReceiptSignerJWK      jose.JSONWebKey
	SatisfiedApprovalRefs map[string]struct{}
}

// ChainLink captures one adjacent parent/child relationship in a chain.
type ChainLink struct {
	Index  int
	Parent *Token
	Child  *Token
}

// VerifyResult is the high-level result envelope returned by VerifyChain.
// The struct is intentionally small for now; the follow-up implementation can
// extend it without breaking call sites that already depend on the skeleton.
type VerifyResult struct {
	Verdict         Verdict
	Chain           []*Token
	Leaf            *Token
	Links           []ChainLink
	PoP             *PoPJWT
	FailedStep      string
	FailedInvariant string
	Cause           error
	Notes           []string
}
