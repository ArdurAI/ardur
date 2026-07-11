package aat

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	jose "github.com/go-jose/go-jose/v4"
)

// BuildPoPOpts captures the inputs needed to construct a PoP JWT per AAT §5.2.
type BuildPoPOpts struct {
	JWTID  string
	Now    time.Time
	Leaf   *Token
	Tool   string
	Args   map[string]interface{}
	Signer ed25519.PrivateKey
	KeyID  string
}

// VerifyPoPOpts captures verifier-local knobs for AAT §5.3 / §7 step 7.
type VerifyPoPOpts struct {
	Now       time.Time
	ClockSkew time.Duration
}

// BuildPoPJWT constructs the compact PoP JWT bound to the leaf token holder.
func BuildPoPJWT(opts BuildPoPOpts) (string, error) {
	if opts.Leaf == nil {
		return "", fmt.Errorf("BuildPoPJWT: leaf token is nil")
	}
	if opts.Tool == "" {
		return "", fmt.Errorf("BuildPoPJWT: missing tool")
	}
	if opts.JWTID == "" {
		return "", fmt.Errorf("BuildPoPJWT: missing JWTID")
	}
	if opts.Leaf.JWTID == "" {
		return "", fmt.Errorf("BuildPoPJWT: leaf JWTID is required")
	}
	if opts.Leaf.Confirmation == nil || !signerMatchesJWK(opts.Signer, opts.Leaf.Confirmation.JWK) {
		return "", fmt.Errorf("BuildPoPJWT: signer does not match leaf confirmation key")
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}

	hta := opts.Args
	if hta == nil {
		hta = map[string]interface{}{}
	}

	issuedAt := opts.Now.Unix()

	payload := map[string]interface{}{
		"jti":      opts.JWTID,
		"iat":      issuedAt,
		"aat_id":   opts.Leaf.JWTID,
		"aat_tool": opts.Tool,
		"hta":      hta,
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
		return "", fmt.Errorf("BuildPoPJWT: creating signer: %w", err)
	}

	payloadBytes, err := canonicalizeJSON(payload)
	if err != nil {
		return "", fmt.Errorf("BuildPoPJWT: canonicalizing payload: %w", err)
	}

	jws, err := signer.Sign(payloadBytes)
	if err != nil {
		return "", fmt.Errorf("BuildPoPJWT: signing: %w", err)
	}

	compact, err := jws.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("BuildPoPJWT: compact serialize: %w", err)
	}

	return compact, nil
}

// VerifyPoPJWT verifies the PoP JWT against a fully validated execution token.
func VerifyPoPJWT(leaf *Token, tool string, args map[string]interface{}, popJWT string, opts VerifyPoPOpts) (*PoPJWT, error) {
	if leaf == nil {
		return nil, fmt.Errorf("VerifyPoPJWT: leaf token is nil")
	}
	if leaf.Confirmation == nil {
		return nil, ErrDenyStep4B2ChildCNF
	}

	// I6: verify PoP signature under leaf.cnf.jwk
	parsed, err := jose.ParseSignedCompact(popJWT, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDenyStep7APoPSignature, err)
	}

	verifiedPayload, err := parsed.Verify(leaf.Confirmation.JWK.Public())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDenyStep7APoPSignature, err)
	}

	canonicalPayload, err := jsoncanonicalizer.Transform(verifiedPayload)
	if err != nil || !bytes.Equal(canonicalPayload, verifiedPayload) {
		return nil, ErrDenyStep7ANonCanonical
	}

	// Parse the verified payload into PoPJWT struct
	var verified map[string]interface{}
	if err := json.Unmarshal(verifiedPayload, &verified); err != nil {
		return nil, fmt.Errorf("%w: invalid pop payload: %v", ErrDenyStep7APoPSignature, err)
	}

	pop := &PoPJWT{Compact: popJWT}

	if jti, ok := verified["jti"].(string); ok {
		pop.JWTID = jti
	}
	if pop.JWTID == "" {
		return nil, ErrDenyStep7AMissingJTI
	}
	if iat, ok := verified["iat"].(float64); ok {
		pop.IssuedAt = int64(iat)
	}
	if aatID, ok := verified["aat_id"].(string); ok {
		pop.AATID = aatID
	}
	if aatTool, ok := verified["aat_tool"].(string); ok {
		pop.AATTool = aatTool
	}

	// Step 7b: pop.aat_id must match leaf.jti
	if pop.AATID != leaf.JWTID {
		return nil, ErrDenyStep7BAATID
	}

	// Step 7c: pop.aat_tool must match the requested tool
	if pop.AATTool != tool {
		return nil, ErrDenyStep7CPoPTool
	}

	// Step 7d: compare JCS-canonicalized HTA
	expectedHTA := args
	if expectedHTA == nil {
		expectedHTA = map[string]interface{}{}
	}
	expectedCanon, err := CanonicalizeHTA(expectedHTA)
	if err != nil {
		return nil, fmt.Errorf("VerifyPoPJWT: canonicalizing expected HTA: %w", err)
	}

	if htaRaw, ok := verified["hta"]; ok {
		// Re-canonicalize the parsed HTA to get a stable byte comparison
		parsedHTAMap, ok := htaRaw.(map[string]interface{})
		if !ok {
			return nil, ErrDenyStep7DHTAMismatch
		}
		parsedCanon, err := CanonicalizeHTA(parsedHTAMap)
		if err != nil {
			return nil, fmt.Errorf("VerifyPoPJWT: canonicalizing parsed HTA: %w", err)
		}
		pop.HTA = parsedHTAMap

		if string(expectedCanon) != string(parsedCanon) {
			return nil, ErrDenyStep7DHTAMismatch
		}
	} else {
		return nil, ErrDenyStep7DHTAMismatch
	}

	// Step 7e: enforce iat clock-tolerance window
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	skew := opts.ClockSkew
	if skew == 0 {
		skew = time.Duration(MAX_IAT_SKEW_S) * time.Second
	}
	iatTime := time.Unix(pop.IssuedAt, 0)
	if now.Sub(iatTime) > skew || iatTime.Sub(now) > skew {
		return nil, ErrDenyStep7EPopIAT
	}

	return pop, nil
}

// VerifyPoP is a convenience alias retained for the B.5 brief wording.
func VerifyPoP(leaf *Token, tool string, args map[string]interface{}, popJWT string, opts VerifyPoPOpts) (*PoPJWT, error) {
	return VerifyPoPJWT(leaf, tool, args, popJWT, opts)
}

// CanonicalizeHTA returns the RFC 8785 representation used for PoP argument
// equality. The complete PoP payload is canonicalized separately before JWS
// signing, as required by AAT draft-00 Section 5.2.
func CanonicalizeHTA(hta map[string]interface{}) ([]byte, error) {
	return canonicalizeJSON(hta)
}

func canonicalizeJSON(value interface{}) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(raw)
}
