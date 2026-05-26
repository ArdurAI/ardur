package aat

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	if opts.Issuer == "" {
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
	if opts.HolderJWK.Key == nil || !opts.HolderJWK.Valid() {
		return nil, fmt.Errorf("IssueRoot: holder public key required and must be valid")
	}
	if len(opts.Authorization) == 0 {
		return nil, fmt.Errorf("IssueRoot: authorization_details required")
	}
	if len(opts.Signer) == 0 {
		return nil, fmt.Errorf("IssueRoot: signer required")
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
		Compact:           compact,
		ProtectedSegment:  parts[0],
		PayloadSegment:    parts[1],
		SignatureSegment:  parts[2],
		SigningInput:      parts[0] + "." + parts[1],
		JWTID:             opts.JWTID,
		Issuer:            opts.Issuer,
		IssuedAt:          issuedAt,
		ExpiresAt:         expiresAt,
		TokenType:         opts.TokenType,
		DelegationDepth:   0,
		DelegationMaxDepth: opts.MaxDelegationDepth,
		Authorization:     opts.Authorization,
		Confirmation:      &ConfirmationKey{JWK: opts.HolderJWK},
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
	if len(opts.Signer) == 0 {
		return nil, fmt.Errorf("DeriveChild: signer required")
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

	// I5: compute par_hash over parent's JWS Signing Input
	parHash := computeParentHash(parent)

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
		Compact:           compact,
		ProtectedSegment:  parts[0],
		PayloadSegment:    parts[1],
		SignatureSegment:  parts[2],
		SigningInput:      parts[0] + "." + parts[1],
		JWTID:             opts.JWTID,
		Issuer:            opts.Issuer,
		IssuedAt:          issuedAt,
		ExpiresAt:         expiresAt,
		TokenType:         opts.TokenType,
		DelegationDepth:   childDepth,
		DelegationMaxDepth: opts.MaxDelegationDepth,
		ParentHash:        parHash,
		Authorization:     opts.Authorization,
		Confirmation:      &ConfirmationKey{JWK: opts.HolderJWK},
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
