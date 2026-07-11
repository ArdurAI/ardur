package aat

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// IssueRootOpts captures the AS-side inputs for AAT §3.7.3 root issuance.
type IssueRootOpts struct {
	JWTID              string
	Issuer             string
	Now                time.Time
	ExpiresAt          time.Time
	TokenType          AATType
	MaxDelegationDepth int
	HolderJWK          jose.JSONWebKey
	Authorization      []AuthorizationDetail
	Signer             ed25519.PrivateKey
	KeyID              string
}

// DeriveOpts captures the local holder inputs for AAT §6 derivation.
type DeriveOpts struct {
	JWTID              string
	Issuer             string
	Now                time.Time
	ExpiresAt          time.Time
	TokenType          AATType
	MaxDelegationDepth int
	HolderJWK          jose.JSONWebKey
	Authorization      []AuthorizationDetail
	Signer             ed25519.PrivateKey
	KeyID              string
}

// IssueRoot constructs the root AAT issued by the authorization server.
func IssueRoot(opts IssueRootOpts) (*Token, error) {
	if opts.JWTID == "" {
		return nil, fmt.Errorf("IssueRoot: missing JWTID")
	}
	issuerURI, err := url.Parse(opts.Issuer)
	if err != nil || opts.Issuer == "" || issuerURI.Scheme == "" {
		return nil, fmt.Errorf("IssueRoot: missing Issuer")
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	if opts.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("IssueRoot: missing ExpiresAt")
	}
	if opts.TokenType != AATTypeDelegation && opts.TokenType != AATTypeExecution {
		return nil, fmt.Errorf("IssueRoot: invalid aat_type %q", opts.TokenType)
	}
	if !isEd25519PublicJWK(opts.HolderJWK) {
		return nil, fmt.Errorf("IssueRoot: holder public key must be a valid public Ed25519 JWK")
	}
	if opts.MaxDelegationDepth < 0 || opts.MaxDelegationDepth > MAX_DELEGATION_DEPTH {
		return nil, ErrDenyStep3JRootMaxDepth
	}
	if len(opts.Authorization) == 0 {
		return nil, fmt.Errorf("IssueRoot: authorization_details required")
	}
	profiledAuthorization, err := profiledAuthorization(opts.Authorization)
	if err != nil {
		return nil, fmt.Errorf("IssueRoot: %w", err)
	}
	if len(opts.Signer) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("IssueRoot: valid Ed25519 signer required")
	}

	issuedAt := opts.Now.Unix()
	expiresAt := opts.ExpiresAt.Unix()

	if expiresAt <= issuedAt {
		return nil, ErrDenyStep3HRootLifetimeOrder
	}
	if expiresAt-issuedAt > MAX_TOKEN_LIFETIME_S {
		return nil, ErrDenyStep3IRootLifetimeBound
	}

	payload := map[string]any{
		"jti":                   opts.JWTID,
		"iss":                   opts.Issuer,
		"iat":                   issuedAt,
		"exp":                   expiresAt,
		"aat_type":              string(opts.TokenType),
		"del_depth":             0,
		"del_max_depth":         opts.MaxDelegationDepth,
		"cnf":                   map[string]any{"jwk": opts.HolderJWK},
		"authorization_details": opts.Authorization,
	}

	signerOpts := &jose.SignerOptions{}
	signerOpts.WithHeader("alg", "EdDSA")
	if opts.KeyID != "" {
		signerOpts.WithHeader("kid", opts.KeyID)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: ed25519.PrivateKey(opts.Signer)},
		signerOpts,
	)
	if err != nil {
		return nil, fmt.Errorf("IssueRoot: creating signer: %w", err)
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("IssueRoot: marshaling payload: %w", err)
	}

	jws, err := signer.Sign(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("IssueRoot: signing: %w", err)
	}

	compact, err := jws.CompactSerialize()
	if err != nil {
		return nil, fmt.Errorf("IssueRoot: compact serialize: %w", err)
	}
	parts := strings.SplitN(compact, ".", 3)

	token := &Token{
		Compact:            compact,
		ProtectedSegment:   parts[0],
		PayloadSegment:     parts[1],
		SignatureSegment:   parts[2],
		SigningInput:       parts[0] + "." + parts[1],
		JWTID:              opts.JWTID,
		Issuer:             opts.Issuer,
		IssuedAt:           issuedAt,
		ExpiresAt:          expiresAt,
		TokenType:          opts.TokenType,
		DelegationDepth:    0,
		DelegationMaxDepth: opts.MaxDelegationDepth,
		Authorization:      profiledAuthorization,
		Confirmation:       &ConfirmationKey{JWK: opts.HolderJWK},
	}

	return token, nil
}

// DeriveChild constructs a locally derived child token from a parent AAT.
func DeriveChild(parent *Token, opts DeriveOpts) (*Token, error) {
	if parent == nil {
		return nil, fmt.Errorf("DeriveChild: parent is nil")
	}
	if opts.JWTID == "" {
		return nil, fmt.Errorf("DeriveChild: missing JWTID")
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	if opts.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("DeriveChild: missing ExpiresAt")
	}
	if len(opts.Signer) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("DeriveChild: valid Ed25519 signer required")
	}
	if opts.TokenType != AATTypeDelegation && opts.TokenType != AATTypeExecution {
		return nil, fmt.Errorf("DeriveChild: invalid aat_type %q", opts.TokenType)
	}
	if !isEd25519PublicJWK(opts.HolderJWK) {
		return nil, fmt.Errorf("DeriveChild: holder public key must be a valid public Ed25519 JWK")
	}
	profiledAuthorization, err := profiledAuthorization(opts.Authorization)
	if err != nil {
		return nil, fmt.Errorf("DeriveChild: %w", err)
	}
	if parent.Confirmation == nil || !isEd25519PublicJWK(parent.Confirmation.JWK) {
		return nil, fmt.Errorf("DeriveChild: parent confirmation key is invalid")
	}
	parentThumbprint, err := parent.Confirmation.JWK.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("DeriveChild: parent confirmation thumbprint: %w", err)
	}
	expectedIssuer := "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + base64.RawURLEncoding.EncodeToString(parentThumbprint)
	if opts.Issuer != expectedIssuer {
		return nil, fmt.Errorf("DeriveChild: %w", ErrDenyStep4CIssuerMismatch)
	}
	if !signerMatchesJWK(opts.Signer, parent.Confirmation.JWK) {
		return nil, fmt.Errorf("DeriveChild: signer does not match parent confirmation key")
	}
	if parent.TokenType != opts.TokenType {
		childThumbprint, err := opts.HolderJWK.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("DeriveChild: child confirmation thumbprint: %w", err)
		}
		if bytes.Equal(parentThumbprint, childThumbprint) {
			return nil, fmt.Errorf("DeriveChild: %w", ErrDenyStep4STypeTransitionKeyReuse)
		}
	}

	issuedAt := opts.Now.Unix()
	expiresAt := opts.ExpiresAt.Unix()

	// I3: child exp <= parent exp
	if expiresAt > parent.ExpiresAt {
		return nil, ErrDenyStep4IChildExpAfterParent
	}
	// Child iat >= parent iat (AAT §4.4 lifetime ordering)
	if issuedAt < parent.IssuedAt {
		return nil, ErrDenyStep4KChildIATBeforeParent
	}
	// exp must be strictly greater than iat
	if expiresAt <= issuedAt {
		return nil, ErrDenyStep4MChildLifetimeOrder
	}
	// Token lifetime bound
	if expiresAt-issuedAt > MAX_TOKEN_LIFETIME_S {
		return nil, ErrDenyStep3IRootLifetimeBound
	}

	// I2: depth increment
	childDepth := parent.DelegationDepth + 1
	if childDepth > parent.DelegationMaxDepth {
		return nil, ErrDenyStep4FDepthExceedsParentMax
	}
	if childDepth > MAX_DELEGATION_DEPTH {
		return nil, ErrDenyStep4GDepthExceedsImplementationMax
	}
	if opts.MaxDelegationDepth > parent.DelegationMaxDepth {
		return nil, ErrDenyStep4HChildMaxDepth
	}
	if opts.MaxDelegationDepth < childDepth {
		return nil, ErrDenyStep4NChildDepthWindow
	}
	childCandidate := &Token{Authorization: profiledAuthorization}
	if err := verifyCapabilityMonotonicity(parent, childCandidate); err != nil {
		return nil, fmt.Errorf("DeriveChild: %w", err)
	}

	// I5: compute par_hash over parent's JWS Signing Input
	parHash := computeParentHash(parent)
	wireAuthorization := opts.Authorization
	if wireAuthorization == nil {
		wireAuthorization = []AuthorizationDetail{}
	}

	payload := map[string]any{
		"jti":                   opts.JWTID,
		"iss":                   opts.Issuer, // will be overwritten by caller with JWK thumbprint URI
		"iat":                   issuedAt,
		"exp":                   expiresAt,
		"aat_type":              string(opts.TokenType),
		"del_depth":             childDepth,
		"del_max_depth":         opts.MaxDelegationDepth,
		"par_hash":              parHash,
		"cnf":                   map[string]any{"jwk": opts.HolderJWK},
		"authorization_details": wireAuthorization,
	}

	signerOpts := &jose.SignerOptions{}
	signerOpts.WithHeader("alg", "EdDSA")
	if opts.KeyID != "" {
		signerOpts.WithHeader("kid", opts.KeyID)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: ed25519.PrivateKey(opts.Signer)},
		signerOpts,
	)
	if err != nil {
		return nil, fmt.Errorf("DeriveChild: creating signer: %w", err)
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("DeriveChild: marshaling payload: %w", err)
	}

	jws, err := signer.Sign(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("DeriveChild: signing: %w", err)
	}

	compact, err := jws.CompactSerialize()
	if err != nil {
		return nil, fmt.Errorf("DeriveChild: compact serialize: %w", err)
	}
	parts := strings.SplitN(compact, ".", 3)

	token := &Token{
		Compact:            compact,
		ProtectedSegment:   parts[0],
		PayloadSegment:     parts[1],
		SignatureSegment:   parts[2],
		SigningInput:       parts[0] + "." + parts[1],
		JWTID:              opts.JWTID,
		Issuer:             opts.Issuer,
		IssuedAt:           issuedAt,
		ExpiresAt:          expiresAt,
		TokenType:          opts.TokenType,
		DelegationDepth:    childDepth,
		DelegationMaxDepth: opts.MaxDelegationDepth,
		ParentHash:         parHash,
		Authorization:      profiledAuthorization,
		Confirmation:       &ConfirmationKey{JWK: opts.HolderJWK},
	}

	return token, nil
}

func computeParentHash(parent *Token) string {
	return base64.RawURLEncoding.EncodeToString(sha256Hash([]byte(parent.SigningInput)))
}

func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func profiledAuthorization(details []AuthorizationDetail) ([]AuthorizationDetail, error) {
	profiled := make([]AuthorizationDetail, 0, 1)
	for _, detail := range details {
		if detail.Type == "" {
			return nil, fmt.Errorf("authorization detail type is required")
		}
		if detail.Type != AuthorizationDetailType {
			continue
		}
		profiled = append(profiled, detail)
		if len(profiled) > 1 {
			return nil, fmt.Errorf("at most one %s authorization detail is allowed", AuthorizationDetailType)
		}
	}
	return profiled, nil
}

func isEd25519PublicJWK(jwk jose.JSONWebKey) bool {
	if jwk.Key == nil || !jwk.Valid() || !jwk.IsPublic() {
		return false
	}
	_, ok := jwk.Public().Key.(ed25519.PublicKey)
	return ok
}

func signerMatchesJWK(signer ed25519.PrivateKey, jwk jose.JSONWebKey) bool {
	if len(signer) != ed25519.PrivateKeySize || !isEd25519PublicJWK(jwk) {
		return false
	}
	signerJWK := jose.JSONWebKey{Key: signer.Public().(ed25519.PublicKey)}
	signerThumbprint, err := signerJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		return false
	}
	holderThumbprint, err := jwk.Thumbprint(crypto.SHA256)
	return err == nil && bytes.Equal(signerThumbprint, holderThumbprint)
}
