package aat

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

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
	if len(opts.Signer) == 0 {
		return "", fmt.Errorf("BuildPoPJWT: signer required")
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}

	hta := map[string]interface{}{
		"tool": opts.Tool,
		"args": opts.Args,
	}

	canonicalHTA, err := CanonicalizeHTA(hta)
	if err != nil {
		return "", fmt.Errorf("BuildPoPJWT: canonicalizing HTA: %w", err)
	}

	issuedAt := opts.Now.Unix()

	payload := map[string]interface{}{
		"jti":      opts.JWTID,
		"iat":      issuedAt,
		"aat_id":   opts.Leaf.JWTID,
		"aat_tool": opts.Tool,
		"hta":      json.RawMessage(canonicalHTA),
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

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("BuildPoPJWT: marshaling payload: %w", err)
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

	// Parse the verified payload into PoPJWT struct
	var verified map[string]interface{}
	if err := json.Unmarshal(verifiedPayload, &verified); err != nil {
		return nil, fmt.Errorf("%w: invalid pop payload: %v", ErrDenyStep7APoPSignature, err)
	}

	pop := &PoPJWT{Compact: popJWT}

	if jti, ok := verified["jti"].(string); ok {
		pop.JWTID = jti
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
	expectedHTA := map[string]interface{}{
		"tool": tool,
		"args": args,
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

// CanonicalizeHTA returns the deterministic JSON byte representation needed by
// AAT §5.2 and §7 step 7d. Go's encoding/json produces sorted-key output with
// compact formatting; both builder and verifier use the same serializer, so
// byte comparison is sound for HTA equality checks.
func CanonicalizeHTA(hta map[string]interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(hta); err != nil {
		return nil, fmt.Errorf("CanonicalizeHTA: encode: %w", err)
	}
	// json.Encoder.Encode appends a newline; trim it.
	result := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	return result, nil
}
