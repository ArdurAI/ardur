package credential

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"
)

const (
	defaultPassportIssuer   = "vibap-governance-proxy" // #nosec G101 -- issuer identifier, not a credential.
	defaultPassportAudience = "vibap-proxy"
	defaultChildTTL         = 5 * time.Minute
	maxDelegationChainDepth = 16
)

// MissionPassport is the Go analogue of the Python mission-passport primitive.
// It intentionally models the delegation-specific claims used by the escrow
// tests instead of the full SD-JWT VC shape.
type MissionPassport struct {
	AgentID            string
	Mission            string
	AllowedTools       []string
	ForbiddenTools     []string
	ResourceScope      []string
	MaxToolCalls       int
	MaxDurationSeconds int
	DelegationAllowed  bool
	MaxDelegationDepth int
	ParentJTI          string
	CWD                string
}

// PassportClaims is the compact JWT claim set used for delegated mission
// passports and escrow-rights accounting.
type PassportClaims struct {
	Issuer              string                `json:"iss"`
	Subject             string                `json:"sub"`
	Audience            string                `json:"aud,omitempty"`
	IssuedAt            int64                 `json:"iat"`
	NotBefore           int64                 `json:"nbf,omitempty"`
	ExpiresAt           int64                 `json:"exp"`
	JWTID               string                `json:"jti"`
	MissionID           string                `json:"mission_id,omitempty"`
	Mission             string                `json:"mission"`
	AllowedTools        []string              `json:"allowed_tools"`
	ForbiddenTools      []string              `json:"forbidden_tools,omitempty"`
	ResourceScope       []string              `json:"resource_scope,omitempty"`
	MaxToolCalls        int                   `json:"max_tool_calls"`
	MaxDurationSeconds  int                   `json:"max_duration_s"`
	DelegationAllowed   bool                  `json:"delegation_allowed"`
	MaxDelegationDepth  int                   `json:"max_delegation_depth"`
	ParentJTI           string                `json:"parent_jti,omitempty"`
	ParentTokenHash     string                `json:"parent_token_hash,omitempty"`
	DelegationChain     []DelegationChainLink `json:"delegation_chain,omitempty"`
	ReservedBudgetShare int                   `json:"reserved_budget_share,omitempty"`
	CWD                 string                `json:"cwd,omitempty"`
}

// DelegationChainLink captures a signed ancestor snapshot copied into a child
// token so downstream auditors can reason about the chain without session
// state or access to intermediate tokens.
type DelegationChainLink struct {
	JTI                 string `json:"jti"`
	ParentJTI           string `json:"parent_jti,omitempty"`
	ParentTokenHash     string `json:"parent_token_hash,omitempty"`
	MaxToolCalls        int    `json:"max_tool_calls,omitempty"`
	ReservedBudgetShare int    `json:"reserved_budget_share,omitempty"`
}

// IssuePassportOptions configures compact mission-passport issuance.
type IssuePassportOptions struct {
	Issuer   string
	Audience string
	TTL      time.Duration
	Now      time.Time
}

// DeriveChildOptions configures child-passport derivation.
type DeriveChildOptions struct {
	ParentToken                  string
	PublicKey                    crypto.PublicKey
	SigningKey                   *SigningKey
	ChildAgentID                 string
	ChildAllowedTools            []string
	ChildMission                 string
	ChildTTL                     time.Duration
	ChildMaxToolCalls            *int
	ParentCallsRemaining         *int
	ParentReservedForDescendants int
	ChildResourceScope           []string
	ChildCWD                     *string
	Now                          time.Time
	Issuer                       string
	Audience                     string
}

// IssuePassport signs a compact JWT mission passport.
func IssuePassport(passport MissionPassport, key *SigningKey, opts *IssuePassportOptions) (string, error) {
	if key == nil {
		return "", fmt.Errorf("signing key is required")
	}
	now := time.Now()
	if opts != nil && !opts.Now.IsZero() {
		now = opts.Now
	}

	issuer := defaultPassportIssuer
	audience := defaultPassportAudience
	ttl := time.Duration(passport.MaxDurationSeconds) * time.Second
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if opts != nil {
		if opts.Issuer != "" {
			issuer = opts.Issuer
		}
		if opts.Audience != "" {
			audience = opts.Audience
		}
		if opts.TTL > 0 {
			ttl = opts.TTL
		}
	}

	jti, err := randomJTI()
	if err != nil {
		return "", fmt.Errorf("generating jti: %w", err)
	}

	cwd, err := normalizeCWD(passport.CWD)
	if err != nil {
		return "", err
	}

	maxToolCalls := passport.MaxToolCalls
	if maxToolCalls <= 0 {
		maxToolCalls = 50
	}

	maxDurationSeconds := passport.MaxDurationSeconds
	if maxDurationSeconds <= 0 {
		maxDurationSeconds = int(ttl.Seconds())
	}

	claims := PassportClaims{
		Issuer:             issuer,
		Subject:            passport.AgentID,
		Audience:           audience,
		IssuedAt:           now.Unix(),
		NotBefore:          now.Unix(),
		ExpiresAt:          now.Add(ttl).Unix(),
		JWTID:              jti,
		MissionID:          jti,
		Mission:            passport.Mission,
		AllowedTools:       append([]string(nil), passport.AllowedTools...),
		ForbiddenTools:     append([]string(nil), passport.ForbiddenTools...),
		ResourceScope:      append([]string(nil), passport.ResourceScope...),
		MaxToolCalls:       maxToolCalls,
		MaxDurationSeconds: maxDurationSeconds,
		DelegationAllowed:  passport.DelegationAllowed,
		MaxDelegationDepth: passport.MaxDelegationDepth,
		ParentJTI:          passport.ParentJTI,
		CWD:                cwd,
	}

	return SignPassportClaims(claims, key)
}

// SignPassportClaims signs an already-prepared compact mission-passport claim set.
func SignPassportClaims(claims PassportClaims, key *SigningKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("signing key is required")
	}

	header := Header{
		Algorithm: "EdDSA",
		Type:      "JWT",
		KeyID:     key.KeyID,
	}
	return signJWT(header, claims, key.PrivateKey)
}

// VerifyPassport verifies a compact mission-passport JWT and returns the decoded claims.
func VerifyPassport(token string, publicKey crypto.PublicKey) (*PassportClaims, error) {
	pub, err := coerceEd25519PublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	if err := verifyJWTSignature(token, pub); err != nil {
		return nil, err
	}

	claims, err := parsePassportClaims(token)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	if claims.ExpiresAt <= 0 {
		return nil, fmt.Errorf("passport missing exp")
	}
	if claims.ExpiresAt < now {
		return nil, fmt.Errorf("passport expired")
	}
	// Round 5 hardening (FIX-R5-H3, 2026-04-28): bound iat into the
	// future as well. Round-4 audit flagged that the SD-JWT-VC verifier
	// in verify.go was the only Go verifier closing the future-iat
	// bypass; VerifyPassport (this function) was missed. A briefly-
	// compromised signer mints {iat=year_3000, exp=year_3001}; without
	// this check the verifier accepts both as future-dated and the
	// passport is valid indefinitely from the verifier's perspective.
	// passportIatSkewSec mirrors the skewSec used by Verify (30s) so
	// legitimate clock drift across nodes still verifies cleanly.
	const passportIatSkewSec int64 = 30
	if claims.IssuedAt > now+passportIatSkewSec {
		return nil, fmt.Errorf(
			"passport iat lies more than %ds in the future "+
				"(iat=%d, now=%d) — refusing to accept",
			passportIatSkewSec, claims.IssuedAt, now)
	}
	if strings.TrimSpace(claims.JWTID) == "" {
		return nil, fmt.Errorf("passport missing jti")
	}
	if len(claims.AllowedTools) == 0 {
		return nil, fmt.Errorf("passport missing allowed_tools")
	}
	if claims.ParentJTI != "" && strings.TrimSpace(claims.ParentTokenHash) == "" {
		return nil, fmt.Errorf("delegated passport missing parent_token_hash")
	}
	if _, err := DelegationChainEntries(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// DelegationChainEntries validates and normalizes a delegated passport's chain snapshot.
func DelegationChainEntries(claims *PassportClaims) ([]DelegationChainLink, error) {
	if claims == nil {
		return nil, fmt.Errorf("claims are required")
	}
	if claims.ParentJTI == "" {
		if len(claims.DelegationChain) > 0 {
			return nil, fmt.Errorf("root passport must not include delegation_chain")
		}
		return nil, nil
	}
	if len(claims.DelegationChain) == 0 {
		return nil, fmt.Errorf("delegated passport missing delegation_chain")
	}
	if len(claims.DelegationChain) > maxDelegationChainDepth {
		return nil, fmt.Errorf("delegation depth exceeded")
	}

	seen := make(map[string]struct{}, len(claims.DelegationChain))
	foundParent := false
	out := make([]DelegationChainLink, 0, len(claims.DelegationChain))
	for _, raw := range claims.DelegationChain {
		jti := strings.TrimSpace(raw.JTI)
		if jti == "" {
			return nil, fmt.Errorf("delegated passport has malformed delegation_chain")
		}
		if _, ok := seen[jti]; ok {
			return nil, fmt.Errorf("delegated passport has inconsistent delegation_chain")
		}
		seen[jti] = struct{}{}
		if jti == claims.ParentJTI {
			foundParent = true
		}
		out = append(out, raw)
	}
	if !foundParent {
		return nil, fmt.Errorf("delegated passport missing delegation_chain ancestry")
	}
	return out, nil
}

// DeriveChildPassport derives a child mission passport with Python-matching escrow semantics.
func DeriveChildPassport(opts DeriveChildOptions) (string, error) {
	if strings.TrimSpace(opts.ParentToken) == "" {
		return "", fmt.Errorf("parent token is required")
	}
	if opts.SigningKey == nil {
		return "", fmt.Errorf("signing key is required")
	}
	pub, err := coerceEd25519PublicKey(opts.PublicKey)
	if err != nil {
		return "", err
	}
	parent, err := VerifyPassport(opts.ParentToken, pub)
	if err != nil {
		return "", err
	}
	if !parent.DelegationAllowed {
		return "", fmt.Errorf("parent passport does not allow delegation")
	}
	if parent.MaxDelegationDepth <= 0 {
		return "", fmt.Errorf("delegation depth exhausted")
	}

	childTools := append([]string(nil), opts.ChildAllowedTools...)
	if len(childTools) == 0 {
		return "", fmt.Errorf("child_allowed_tools must be non-empty")
	}
	parentTools := make(map[string]struct{}, len(parent.AllowedTools))
	for _, tool := range parent.AllowedTools {
		parentTools[tool] = struct{}{}
	}
	var escalated []string
	for _, tool := range childTools {
		if _, ok := parentTools[tool]; !ok {
			escalated = append(escalated, tool)
		}
	}
	if len(escalated) > 0 {
		return "", fmt.Errorf("scope escalation (tools): %v", escalated)
	}

	now := time.Now()
	if !opts.Now.IsZero() {
		now = opts.Now
	}
	maxTTL := time.Unix(parent.ExpiresAt, 0).Sub(now)
	if maxTTL <= 0 {
		return "", fmt.Errorf("parent passport expired")
	}
	requestedTTL := maxTTL
	if requestedTTL > defaultChildTTL {
		requestedTTL = defaultChildTTL
	}
	if opts.ChildTTL > 0 && opts.ChildTTL < requestedTTL {
		requestedTTL = opts.ChildTTL
	}
	if requestedTTL <= 0 {
		return "", fmt.Errorf("insufficient TTL for child passport")
	}

	parentBudgetCeiling := parent.MaxToolCalls
	if opts.ParentReservedForDescendants < 0 {
		return "", fmt.Errorf("parent_reserved_for_descendants must be non-negative")
	}
	if opts.ParentReservedForDescendants > parentBudgetCeiling {
		return "", fmt.Errorf("parent_reserved_for_descendants exceeds parent ceiling — lineage budget already over-allocated")
	}
	escrowRemaining := parentBudgetCeiling - opts.ParentReservedForDescendants
	if escrowRemaining <= 0 {
		return "", fmt.Errorf("parent passport descendant-reservation pool exhausted; cannot delegate")
	}

	candidates := []int{parentBudgetCeiling, escrowRemaining}
	if opts.ParentCallsRemaining != nil {
		if *opts.ParentCallsRemaining <= 0 {
			return "", fmt.Errorf("parent passport budget exhausted; cannot delegate")
		}
		candidates = append(candidates, *opts.ParentCallsRemaining)
	}
	if opts.ChildMaxToolCalls != nil {
		if *opts.ChildMaxToolCalls <= 0 {
			return "", fmt.Errorf("child_max_tool_calls must be positive")
		}
		candidates = append(candidates, *opts.ChildMaxToolCalls)
	}
	childBudget := minInt(candidates...)

	finalScope, err := narrowedResourceScope(parent.ResourceScope, opts.ChildResourceScope)
	if err != nil {
		return "", err
	}
	finalCWD, err := narrowedCWD(parent.CWD, opts.ChildCWD)
	if err != nil {
		return "", err
	}

	childDepth := parent.MaxDelegationDepth - 1
	child := MissionPassport{
		AgentID:            opts.ChildAgentID,
		Mission:            opts.ChildMission,
		AllowedTools:       uniqueSorted(childTools),
		ForbiddenTools:     mergeForbidden(parent.ForbiddenTools, parent.AllowedTools, childTools),
		ResourceScope:      finalScope,
		MaxToolCalls:       childBudget,
		MaxDurationSeconds: int(requestedTTL.Seconds()),
		DelegationAllowed:  childDepth > 0,
		MaxDelegationDepth: childDepth,
		ParentJTI:          parent.JWTID,
		CWD:                finalCWD,
	}

	issueOpts := &IssuePassportOptions{
		Issuer:   parent.Issuer,
		Audience: parent.Audience,
		TTL:      requestedTTL,
		Now:      now,
	}
	childToken, err := IssuePassport(child, opts.SigningKey, issueOpts)
	if err != nil {
		return "", err
	}

	childClaims, err := parsePassportClaims(childToken)
	if err != nil {
		return "", err
	}
	childClaims.ParentTokenHash = tokenSHA256(opts.ParentToken)
	childClaims.ReservedBudgetShare = childBudget
	childClaims.DelegationChain = append([]DelegationChainLink{{
		JTI:                 parent.JWTID,
		ParentJTI:           parent.ParentJTI,
		ParentTokenHash:     parent.ParentTokenHash,
		MaxToolCalls:        parent.MaxToolCalls,
		ReservedBudgetShare: parent.ReservedBudgetShare,
	}}, parent.DelegationChain...)
	if len(childClaims.DelegationChain) > maxDelegationChainDepth {
		return "", fmt.Errorf("delegation depth exceeded")
	}
	return SignPassportClaims(*childClaims, opts.SigningKey)
}

func parsePassportClaims(token string) (*PassportClaims, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 dot-separated parts")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}
	var claims PassportClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("unmarshaling claims: %w", err)
	}
	return &claims, nil
}

func coerceEd25519PublicKey(publicKey crypto.PublicKey) (ed25519.PublicKey, error) {
	switch key := publicKey.(type) {
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 public key size: got %d, want %d", len(key), ed25519.PublicKeySize)
		}
		return key, nil
	case []byte:
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 public key size: got %d, want %d", len(key), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(key), nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", publicKey)
	}
}

func randomJTI() (string, error) {
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(jtiBytes), nil
}

func tokenSHA256(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func uniqueSorted(values []string) []string {
	set := make(map[string]struct{}, len(values))
	var out []string
	for _, value := range values {
		if _, ok := set[value]; ok {
			continue
		}
		set[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) <= 1 {
		return out
	}
	// Keep the implementation local and dependency-free.
	for i := 0; i < len(out)-1; i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func mergeForbidden(parentForbidden, parentAllowed, childAllowed []string) []string {
	childSet := make(map[string]struct{}, len(childAllowed))
	for _, tool := range childAllowed {
		childSet[tool] = struct{}{}
	}
	out := append([]string(nil), parentForbidden...)
	for _, tool := range parentAllowed {
		if _, ok := childSet[tool]; !ok {
			out = append(out, tool)
		}
	}
	return uniqueSorted(out)
}

func narrowedResourceScope(parentScope, childScope []string) ([]string, error) {
	if childScope == nil {
		return append([]string(nil), parentScope...), nil
	}
	childSet := make(map[string]struct{}, len(childScope))
	for _, scope := range childScope {
		childSet[scope] = struct{}{}
	}
	if len(parentScope) == 0 {
		return uniqueSorted(childScope), nil
	}
	if len(childSet) == 0 {
		return nil, fmt.Errorf("child_resource_scope cannot widen a restricted parent scope to unrestricted")
	}
	parentSet := make(map[string]struct{}, len(parentScope))
	for _, scope := range parentScope {
		parentSet[scope] = struct{}{}
	}
	var extra []string
	for scope := range childSet {
		if _, ok := parentSet[scope]; !ok {
			extra = append(extra, scope)
		}
	}
	if len(extra) > 0 {
		return nil, fmt.Errorf("scope escalation (resources): %v", uniqueSorted(extra))
	}
	return uniqueSorted(childScope), nil
}

func narrowedCWD(parentRaw string, child *string) (string, error) {
	parentCWD, err := normalizeCWD(parentRaw)
	if err != nil {
		return "", err
	}
	if child == nil {
		return parentCWD, nil
	}
	finalCWD, err := normalizeCWD(*child)
	if err != nil {
		return "", err
	}
	if finalCWD == "" {
		if parentCWD != "" {
			return "", fmt.Errorf("cwd escalation: clearing parent's cwd %q is not allowed", parentCWD)
		}
		return "", nil
	}
	if parentCWD == "" {
		return "", fmt.Errorf("cannot introduce cwd: parent has none (child requested %q)", finalCWD)
	}
	if !cwdIsSubpath(finalCWD, parentCWD) {
		return "", fmt.Errorf("cwd escalation: %q is not a subpath of parent's %q", finalCWD, parentCWD)
	}
	return finalCWD, nil
}

func normalizeCWD(raw string) (string, error) {
	stripped := strings.TrimSpace(raw)
	if stripped == "" {
		return "", nil
	}
	if !strings.HasPrefix(stripped, "/") {
		return "", fmt.Errorf("cwd must be an absolute path (start with '/'), got %q", raw)
	}
	for _, segment := range strings.Split(stripped, "/") {
		if segment == ".." {
			return "", fmt.Errorf("cwd must not contain '..' segments: %q", raw)
		}
	}
	return path.Clean(stripped), nil
}

func cwdIsSubpath(child, parent string) bool {
	if child == parent {
		return true
	}
	if parent == "/" {
		return strings.HasPrefix(child, "/")
	}
	return strings.HasPrefix(child, parent+"/")
}

func minInt(values ...int) int {
	if len(values) == 0 {
		return 0
	}
	min := values[0]
	for _, value := range values[1:] {
		if value < min {
			min = value
		}
	}
	return min
}
