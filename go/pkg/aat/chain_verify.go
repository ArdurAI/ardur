package aat

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// VerifyChain is the offline enforcement algorithm defined in AAT §7.
//
// Input contract:
//   - chain is ordered root -> leaf
//   - trustAnchors holds root public keys (raw Ed25519 32-byte keys)
//   - tool/args/popJWT are the invocation-time presentation inputs
func VerifyChain(chain []*Token, trustAnchors [][]byte, tool string, args map[string]interface{}, popJWT string) (*VerifyResult, error) {
	now := time.Now()

	result := &VerifyResult{
		Verdict: VerdictDeny,
		Chain:   chain,
		Notes:   []string{},
	}

	// Step 1: reject empty chains
	if len(chain) == 0 {
		result.FailedStep = "step-1"
		result.Cause = ErrDenyStep1EmptyChain
		return result, ErrDenyStep1EmptyChain
	}

	// Step 2: structural validation
	if err := validateStructure(chain); err != nil {
		result.FailedStep = "step-2"
		result.Cause = err
		return result, err
	}

	// Parse all tokens from compact form
	parsed := make([]*Token, len(chain))
	for i, tok := range chain {
		if tok.Compact != "" && tok.JWTID == "" {
			pt, err := parseCompactToken(tok.Compact)
			if err != nil {
				result.FailedStep = "step-2c"
				result.Cause = err
				return result, err
			}
			parsed[i] = pt
		} else {
			parsed[i] = tok
		}
	}

	// Step 3: root verification
	root := parsed[0]
	if err := verifyRoot(root, trustAnchors, now); err != nil {
		result.FailedStep = "step-3"
		result.Cause = err
		return result, err
	}

	// Step 4: parent/child link verification
	var links []ChainLink
	for i := 1; i < len(parsed); i++ {
		parent := parsed[i-1]
		child := parsed[i]
		if err := verifyLink(parent, child, i-1, now); err != nil {
			result.FailedStep = "step-4"
			result.Cause = err
			return result, err
		}
		links = append(links, ChainLink{Index: i - 1, Parent: parent, Child: child})
	}
	result.Links = links

	leaf := parsed[len(parsed)-1]
	result.Leaf = leaf

	// Step 5: chain length == leaf.del_depth + 1
	if len(parsed) != leaf.DelegationDepth+1 {
		result.FailedStep = "step-5"
		result.Cause = ErrDenyStep5ChainLengthMismatch
		return result, ErrDenyStep5ChainLengthMismatch
	}

	// Step 6: leaf constraint check
	if err := verifyLeafInvocation(leaf, tool, args); err != nil {
		result.FailedStep = "step-6"
		result.Cause = err
		return result, err
	}

	// Step 7: PoP verification
	if popJWT == "" {
		result.FailedStep = "step-7"
		result.Cause = fmt.Errorf("PoP JWT is required")
		return result, fmt.Errorf("PoP JWT is required")
	}
	popResult, err := VerifyPoPJWT(leaf, tool, args, popJWT, VerifyPoPOpts{Now: now})
	if err != nil {
		result.FailedStep = "step-7"
		result.Cause = err
		return result, err
	}
	result.PoP = popResult

	// Step 8: permit
	result.Verdict = VerdictPermit
	return result, nil
}

func validateStructure(chain []*Token) error {
	if len(chain) > MAX_STACK_SIZE {
		return ErrDenyStep2BChainTooLarge
	}
	for i, tok := range chain {
		if len(tok.Compact) > MAX_TOKEN_SIZE {
			return fmt.Errorf("%w at index %d", ErrDenyStep2ATokenTooLarge, i)
		}
	}
	// JTI cycle detection
	seen := make(map[string]bool)
	for _, tok := range chain {
		jti := tok.JWTID
		if jti == "" {
			// Try to extract from compact form
			jti = extractJTI(tok.Compact)
		}
		if jti == "" {
			return ErrDenyStep2CMissingJTI
		}
		if seen[jti] {
			return ErrDenyStep2CDuplicateJTI
		}
		seen[jti] = true
	}
	return nil
}

func parseCompactToken(compact string) (*Token, error) {
	parts := strings.SplitN(compact, ".", 3)
	if len(parts) < 2 {
		return nil, ErrDenyStep2CInvalidPayload
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrDenyStep2CInvalidPayload
	}

	var token Token
	if err := json.Unmarshal(payloadBytes, &token); err != nil {
		return nil, ErrDenyStep2CInvalidPayload
	}

	sigPart := ""
	if len(parts) >= 3 {
		sigPart = parts[2]
	}

	token.Compact = compact
	token.ProtectedSegment = parts[0]
	token.PayloadSegment = parts[1]
	token.SignatureSegment = sigPart
	token.SigningInput = parts[0] + "." + parts[1]
	return &token, nil
}

func extractJTI(compact string) string {
	tok, err := parseCompactToken(compact)
	if err != nil || tok == nil {
		return ""
	}
	return tok.JWTID
}

func verifyRoot(root *Token, trustAnchors [][]byte, now time.Time) error {
	// 3a: alg must be EdDSA
	parsed, err := jose.ParseSignedCompact(root.Compact, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDenyStep3AInvalidRootAlg, err)
	}

	// 3b: signature verification against trust anchors
	verified := false
	var verifyErr error
	for _, anchor := range trustAnchors {
		if len(anchor) != ed25519.PublicKeySize {
			continue
		}
		pubKey := ed25519.PublicKey(anchor)
		if _, err := parsed.Verify(pubKey); err == nil {
			verified = true
			break
		} else {
			verifyErr = err
		}
	}
	if !verified {
		return fmt.Errorf("%w: %v", ErrDenyStep3BRootSignature, verifyErr)
	}

	// Reload claims after successful verification
	claims, err := parseClaims(root.Compact)
	if err != nil {
		return err
	}

	// 3c: aat_type
	aatType, _ := claims["aat_type"].(string)
	if aatType != string(AATTypeDelegation) && aatType != string(AATTypeExecution) {
		return ErrDenyStep3CInvalidRootType
	}
	root.TokenType = AATType(aatType)

	// 3d: del_depth == 0
	delDepth, ok := claims["del_depth"].(float64)
	if !ok || int(delDepth) != 0 {
		return ErrDenyStep3DInvalidRootDepth
	}
	root.DelegationDepth = 0

	// 3e: par_hash must be absent
	if _, exists := claims["par_hash"]; exists {
		return ErrDenyStep3ERootParentHash
	}

	// 3f: exp > now
	exp, ok := claims["exp"].(float64)
	if !ok {
		return ErrDenyStep3FRootExpired
	}
	root.ExpiresAt = int64(exp)
	if int64(exp) <= now.Unix() {
		return ErrDenyStep3FRootExpired
	}

	// 3g: iat within MAX_IAT_SKEW
	iat, ok := claims["iat"].(float64)
	if !ok {
		return ErrDenyStep3GRootIATSkew
	}
	root.IssuedAt = int64(iat)
	if absDiff(int64(iat), now.Unix()) > MAX_IAT_SKEW_S {
		return ErrDenyStep3GRootIATSkew
	}

	// 3h: exp > iat
	if int64(exp) <= int64(iat) {
		return ErrDenyStep3HRootLifetimeOrder
	}

	// 3i: lifetime ≤ MAX_TOKEN_LIFETIME_S
	if int64(exp)-int64(iat) > MAX_TOKEN_LIFETIME_S {
		return ErrDenyStep3IRootLifetimeBound
	}

	// 3j: del_max_depth validity
	delMaxDepth, ok := claims["del_max_depth"].(float64)
	if !ok || int(delMaxDepth) < 0 || int(delMaxDepth) > MAX_DELEGATION_DEPTH {
		return ErrDenyStep3JRootMaxDepth
	}
	root.DelegationMaxDepth = int(delMaxDepth)

	// 3k: jti present
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return ErrDenyStep3KRootJTI
	}
	root.JWTID = jti

	// 3l: iss URI (basic check)
	iss, _ := claims["iss"].(string)
	if iss == "" {
		return ErrDenyStep3LRootIssuer
	}
	root.Issuer = iss

	// 3m: cnf.jwk public key valid
	cnf, ok := claims["cnf"].(map[string]interface{})
	if !ok {
		return ErrDenyStep3MRootCNF
	}
	jwkMap, ok := cnf["jwk"].(map[string]interface{})
	if !ok {
		return ErrDenyStep3MRootCNF
	}
	jwkBytes, err := json.Marshal(jwkMap)
	if err != nil {
		return ErrDenyStep3MRootCNF
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(jwkBytes, &jwk); err != nil || !jwk.Valid() {
		return ErrDenyStep3MRootCNF
	}
	root.Confirmation = &ConfirmationKey{JWK: jwk}

	// 3n: authorization_details
	if err := validateAuthorization(claims); err != nil {
		return fmt.Errorf("%w: %v", ErrDenyStep3NRootAuthorization, err)
	}
	root.Authorization = extractAuthorization(claims)

	return nil
}

func verifyLink(parent, child *Token, linkIdx int, now time.Time) error {
	// 4a: child alg EdDSA
	parsed, err := jose.ParseSignedCompact(child.Compact, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return fmt.Errorf("link %d %w: %v", linkIdx, ErrDenyStep4AInvalidChildAlg, err)
	}

	// 4b: child signature under parent.cnf.jwk
	if parent.Confirmation == nil {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4B2ChildCNF)
	}
	if _, err := parsed.Verify(parent.Confirmation.JWK.Public()); err != nil {
		return fmt.Errorf("link %d %w: %v", linkIdx, ErrDenyStep4BChildSignature, err)
	}

	claims, err := parseClaims(child.Compact)
	if err != nil {
		return fmt.Errorf("link %d %w", linkIdx, err)
	}

	// 4b1: child jti
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4B1ChildJTI)
	}
	child.JWTID = jti

	// 4b2: child cnf.jwk
	cnf, ok := claims["cnf"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4B2ChildCNF)
	}
	jwkMap, ok := cnf["jwk"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4B2ChildCNF)
	}
	jwkBytes, _ := json.Marshal(jwkMap)
	var childJWK jose.JSONWebKey
	if err := json.Unmarshal(jwkBytes, &childJWK); err != nil || !childJWK.Valid() {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4B2ChildCNF)
	}
	child.Confirmation = &ConfirmationKey{JWK: childJWK}

	// 4b3: child authorization_details
	if err := validateAuthorization(claims); err != nil {
		return fmt.Errorf("link %d %w: %v", linkIdx, ErrDenyStep4B3ChildAuthorization, err)
	}
	child.Authorization = extractAuthorization(claims)

	// 4b4: child depth claims
	delDepth, ok := claims["del_depth"].(float64)
	if !ok {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4B4ChildDepthClaims)
	}
	child.DelegationDepth = int(delDepth)

	delMaxDepth, ok := claims["del_max_depth"].(float64)
	if !ok {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4B4ChildDepthClaims)
	}
	child.DelegationMaxDepth = int(delMaxDepth)

	// 4b5: required claims (iat, exp, iss)
	iat, ok := claims["iat"].(float64)
	if !ok {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4B5ChildRequiredClaims)
	}
	child.IssuedAt = int64(iat)

	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4B5ChildRequiredClaims)
	}
	child.ExpiresAt = int64(exp)

	iss, _ := claims["iss"].(string)
	child.Issuer = iss

	child.ParentHash, _ = claims["par_hash"].(string)

	// 4c: I1 signer linkage — child.iss must match parent.cnf.jwk thumbprint URI
	parentThumbprint, err := parent.Confirmation.JWK.Thumbprint(crypto.SHA256)
	if err != nil {
		return fmt.Errorf("link %d %w: computing thumbprint: %v", linkIdx, ErrDenyStep4CIssuerMismatch, err)
	}
	expectedIssuer := "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + base64.RawURLEncoding.EncodeToString(parentThumbprint)
	if child.Issuer != expectedIssuer {
		return fmt.Errorf("link %d %w: child.iss=%q expected=%q", linkIdx, ErrDenyStep4CIssuerMismatch, child.Issuer, expectedIssuer)
	}

	// 4d: child aat_type
	childType := AATType(claims["aat_type"].(string))
	if childType != AATTypeDelegation && childType != AATTypeExecution {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4DInvalidChildType)
	}
	child.TokenType = childType

	// 4e: I2 del_depth = parent.del_depth + 1
	if child.DelegationDepth != parent.DelegationDepth+1 {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4EInvalidDepthIncrement)
	}

	// 4f: child.del_depth ≤ parent.del_max_depth
	if child.DelegationDepth > parent.DelegationMaxDepth {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4FDepthExceedsParentMax)
	}

	// 4g: child.del_depth ≤ MAX_DELEGATION_DEPTH
	if child.DelegationDepth > MAX_DELEGATION_DEPTH {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4GDepthExceedsImplementationMax)
	}

	// 4h: child.del_max_depth ≤ parent.del_max_depth
	if child.DelegationMaxDepth > parent.DelegationMaxDepth {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4HChildMaxDepth)
	}

	// 4i: I3 child.exp ≤ parent.exp
	if child.ExpiresAt > parent.ExpiresAt {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4IChildExpAfterParent)
	}

	// 4j: child.exp > now
	if child.ExpiresAt <= now.Unix() {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4JChildExpired)
	}

	// 4k: child.iat ≥ parent.iat
	if child.IssuedAt < parent.IssuedAt {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4KChildIATBeforeParent)
	}

	// 4l: child.iat within MAX_IAT_SKEW
	if absDiff(child.IssuedAt, now.Unix()) > MAX_IAT_SKEW_S {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4LChildIATSkew)
	}

	// 4m: child.exp > child.iat
	if child.ExpiresAt <= child.IssuedAt {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4MChildLifetimeOrder)
	}

	// 4n: child.del_depth ≤ child.del_max_depth
	if child.DelegationDepth > child.DelegationMaxDepth {
		return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4NChildDepthWindow)
	}

	// 4o: single "attenuating_agent_token" entry
	if err := validateAuthorization(claims); err != nil {
		return fmt.Errorf("link %d %w: %v", linkIdx, ErrDenyStep4OMultipleAATEntries, err)
	}

	// 4p: constraint tree depth ≤ MAX_CONSTRAINT_DEPTH
	for _, auth := range child.Authorization {
		for _, argMap := range auth.Tools {
			for _, constraint := range argMap {
				if d := constraintDepth(constraint); d > MAX_CONSTRAINT_DEPTH {
					return fmt.Errorf("link %d %w: depth %d", linkIdx, ErrDenyStep4PConstraintDepth, d)
				}
			}
		}
	}

	// 4q1: I4 each child tool must be in parent's authorization set
	// 4q2: child argument shape must match parent closed-world shape
	// 4q4: child constraint must subsume parent's constraint
	if err := verifyCapabilityMonotonicity(parent, child); err != nil {
		return fmt.Errorf("link %d %w", linkIdx, err)
	}

	// 4r: I5 par_hash must match
	expectedHash := computeParentHash(parent)
	if child.ParentHash != expectedHash {
		return fmt.Errorf("link %d %w: got=%q expected=%q", linkIdx, ErrDenyStep4RParentHash, child.ParentHash, expectedHash)
	}

	// 4s: type-transition key separation
	if parent.TokenType != child.TokenType {
		parentPub := parent.Confirmation.JWK.Key
		childPub := child.Confirmation.JWK.Key
		if keysEqual(parentPub, childPub) {
			return fmt.Errorf("link %d %w", linkIdx, ErrDenyStep4STypeTransitionKeyReuse)
		}
	}

	return nil
}

func verifyLeafInvocation(leaf *Token, tool string, args map[string]interface{}) error {
	// 6a: leaf must have exactly one attenuating_agent_token entry
	if len(leaf.Authorization) != 1 || leaf.Authorization[0].Type != AuthorizationDetailType {
		return ErrDenyStep6ALeafAuthorization
	}

	// 6c: leaf must be execution type
	if leaf.TokenType != AATTypeExecution {
		return ErrDenyStep6CDelegationLeaf
	}

	auth := leaf.Authorization[0]

	// 6b: tool must be authorized
	toolConstraints, ok := auth.Tools[tool]
	if !ok {
		return fmt.Errorf("%w: %q", ErrDenyStep6BLeafToolUnauthorized, tool)
	}

	// Check each constrained argument
	for argName, constraint := range toolConstraints {
		argValue, exists := args[argName]
		if !exists {
			return fmt.Errorf("%w: %q", ErrDenyStep6BLeafMissingArgument, argName)
		}
		if err := CheckConstraint(argValue, constraint); err != nil {
			return fmt.Errorf("%w: %v", ErrDenyStep6BLeafConstraintViolation, err)
		}
	}

	// Check for unknown args in closed-world mode (if toolConstraints is non-empty)
	if len(toolConstraints) > 0 {
		for argName := range args {
			if _, ok := toolConstraints[argName]; !ok {
				return fmt.Errorf("%w: %q", ErrDenyStep6BLeafUnknownArgument, argName)
			}
		}
	}

	return nil
}

func verifyCapabilityMonotonicity(parent, child *Token) error {
	parentAuth := parent.Authorization[0]
	childAuth := child.Authorization[0]

	// I4: each child tool must be in parent's tools
	for childTool, childArgMap := range childAuth.Tools {
		parentArgMap, ok := parentAuth.Tools[childTool]
		if !ok {
			return fmt.Errorf("%w: child tool %q not in parent", ErrDenyStep4Q1ToolExpansion, childTool)
		}

		// 4q2: closed-world shape — if parent has constraints, child must constrain same args
		if len(parentArgMap) > 0 && len(childArgMap) == 0 {
			return fmt.Errorf("%w: parent constrains tool %q but child has no constraints", ErrDenyStep4Q2ArgumentShape, childTool)
		}
		for argName := range parentArgMap {
			if _, ok := childArgMap[argName]; !ok {
				return fmt.Errorf("%w: parent arg %q on tool %q not constrained by child", ErrDenyStep4Q2ArgumentShape, argName, childTool)
			}
		}

		// 4q4: child constraint must subsume parent's for each arg
		for argName, parentConstraint := range parentArgMap {
			childConstraint := childArgMap[argName]
			subsumes, err := SubsumesConstraint(childConstraint, parentConstraint)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrDenyStep4Q4ConstraintSubsume, err)
			}
			if !subsumes {
				return fmt.Errorf("%w: child constraint for %q on tool %q does not subsume parent", ErrDenyStep4Q4ConstraintSubsume, argName, childTool)
			}
		}
	}

	return nil
}

func parseClaims(compact string) (map[string]interface{}, error) {
	parts := strings.SplitN(compact, ".", 3)
	if len(parts) < 2 {
		return nil, ErrDenyStep2CInvalidPayload
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrDenyStep2CInvalidPayload
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrDenyStep2CInvalidPayload
	}
	return claims, nil
}

func validateAuthorization(claims map[string]interface{}) error {
	authDetails, ok := claims["authorization_details"]
	if !ok {
		return fmt.Errorf("missing authorization_details")
	}
	authList, ok := authDetails.([]interface{})
	if !ok {
		return fmt.Errorf("authorization_details must be an array")
	}
	aatCount := 0
	for _, item := range authList {
		auth, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if typ, _ := auth["type"].(string); typ == AuthorizationDetailType {
			aatCount++
		}
	}
	if aatCount != 1 {
		return fmt.Errorf("expected exactly one %s entry, got %d", AuthorizationDetailType, aatCount)
	}
	return nil
}

func extractAuthorization(claims map[string]interface{}) []AuthorizationDetail {
	var result []AuthorizationDetail
	authList, ok := claims["authorization_details"].([]interface{})
	if !ok {
		return result
	}
	for _, item := range authList {
		authMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		detail := AuthorizationDetail{}
		if typ, ok := authMap["type"].(string); ok {
			detail.Type = typ
		}
		if tools, ok := authMap["tools"].(map[string]interface{}); ok {
			detail.Tools = parseToolMap(tools)
		}
		result = append(result, detail)
	}
	return result
}

func parseToolMap(tools map[string]interface{}) ToolMap {
	result := make(ToolMap)
	for toolName, argMapRaw := range tools {
		argMap, ok := argMapRaw.(map[string]interface{})
		if !ok {
			continue
		}
		constraints := make(ArgumentConstraintMap)
		for argName, constraintRaw := range argMap {
			constraint := parseConstraint(constraintRaw)
			if constraint != nil {
				constraints[argName] = constraint
			}
		}
		result[toolName] = constraints
	}
	return result
}

func parseConstraint(raw interface{}) *Constraint {
	constraintMap, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	jsonBytes, err := json.Marshal(constraintMap)
	if err != nil {
		return nil
	}
	var constraint Constraint
	if err := json.Unmarshal(jsonBytes, &constraint); err != nil {
		return nil
	}
	return &constraint
}

func constraintDepth(c *Constraint) int {
	if c == nil {
		return 0
	}
	maxChild := 0
	for _, child := range c.Children {
		if d := constraintDepth(child); d > maxChild {
			maxChild = d
		}
	}
	if c.Inner != nil {
		if d := constraintDepth(c.Inner); d > maxChild {
			maxChild = d
		}
	}
	return 1 + maxChild
}

func absDiff(a, b int64) int64 {
	if a > b {
		return a - b
	}
	return b - a
}

func keysEqual(a, b interface{}) bool {
	// Compare public keys by their raw bytes
	aBytes, _ := json.Marshal(a)
	bBytes, _ := json.Marshal(b)
	return string(aBytes) == string(bBytes)
}
