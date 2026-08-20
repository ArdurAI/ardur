package credential

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// VerifyOptions configures credential verification behavior.
type VerifyOptions struct {
	// CurrentTime overrides time.Now() for testing. Zero value uses real time.
	CurrentTime time.Time

	// SkipStatusCheck disables Token Status List verification.
	SkipStatusCheck bool

	// StatusClient is used for Token Status List verification.
	// Required if SkipStatusCheck is false and credential has status claim.
	StatusClient *StatusClient

	// ExpectedAudience for Key Binding JWT verification.
	// Required if the credential includes a KB-JWT.
	ExpectedAudience string

	// ExpectedNonce for Key Binding JWT verification.
	// Required if the credential includes a KB-JWT.
	ExpectedNonce string

	// MaxKBAge is the maximum allowed age for a Key Binding JWT.
	// Default (zero value) is 5 minutes.
	MaxKBAge time.Duration

	// ClockSkew tolerance for temporal checks (exp, nbf, iat).
	// Default (zero value) is 30 seconds.
	ClockSkew time.Duration
}

// VerificationResult contains the outcome of credential verification.
type VerificationResult struct {
	Valid      bool     // Overall validity
	Errors     []string // List of verification failures
	Warnings   []string // Non-fatal issues
	Credential *VIBAPCredential
}

// Verify performs full verification of an SD-JWT-VC credential string.
// It checks: JWT signature, expiration, VCT, disclosure hashes,
// and optionally Key Binding JWT and Token Status List.
func Verify(raw string, issuerPubKey ed25519.PublicKey, opts *VerifyOptions) (*VerificationResult, error) {
	if raw == "" {
		return nil, fmt.Errorf("empty credential string")
	}
	if len(issuerPubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid issuer public key size: got %d, want %d", len(issuerPubKey), ed25519.PublicKeySize)
	}

	if opts == nil {
		opts = &VerifyOptions{}
	}

	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}

	result := &VerificationResult{Valid: true}

	// Step 1: Split the SD-JWT into components
	parts := strings.Split(raw, "~")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid SD-JWT format: need at least 2 tilde-separated parts")
	}

	issuerJWT := parts[0]

	// Step 2: Verify issuer JWT signature
	if err := verifyJWTSignature(issuerJWT, issuerPubKey); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("issuer JWT signature: %v", err))
		return result, nil
	}

	// Step 3: Decode the credential
	cred, err := Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding credential: %w", err)
	}
	result.Credential = cred

	// Step 4: Verify header
	if cred.Header.Algorithm != "EdDSA" {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("unexpected algorithm %q, expected EdDSA", cred.Header.Algorithm))
	}
	if cred.Header.Type != MediaTypeDCSDJWT && cred.Header.Type != "vc+sd-jwt" {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("unexpected type %q, expected %q", cred.Header.Type, MediaTypeDCSDJWT))
	}
	// Warn if using legacy media type
	if cred.Header.Type == "vc+sd-jwt" {
		result.Warnings = append(result.Warnings, "credential uses legacy media type 'vc+sd-jwt'; 'dc+sd-jwt' is current per draft-15")
	}

	// Step 5: Verify VCT (Verifiable Credential Type)
	if cred.Claims.VerifiableCredentialType != VIBAPTypeURI {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("unexpected vct %q, expected %q", cred.Claims.VerifiableCredentialType, VIBAPTypeURI))
	}

	// Step 6: Verify temporal validity (with clock skew tolerance)
	skew := opts.ClockSkew
	if skew == 0 {
		skew = 30 * time.Second
	}
	skewSec := int64(skew.Seconds())

	if now.Unix()-skewSec > cred.Claims.ExpiresAt {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("credential expired at %s", time.Unix(cred.Claims.ExpiresAt, 0).UTC()))
	}
	if cred.Claims.NotBefore > 0 && now.Unix()+skewSec < cred.Claims.NotBefore {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("credential not valid before %s", time.Unix(cred.Claims.NotBefore, 0).UTC()))
	}
	// Round 4 hardening (FIX-R4-2, 2026-04-28): a future iat is a
	// hard error, not a warning. Round-3 hostile audit flagged that
	// emitting a warning while leaving result.Valid=true mirrors the
	// same iat-skew bypass pattern the Python side closed in FIX-R3-A
	// — a briefly-compromised signer could mint credentials with iat
	// far in the future that the verifier accepts forever. The skew
	// tolerance defined as `skewSec` (clock-drift slack) still
	// applies; anything beyond that is rejected.
	if cred.Claims.IssuedAt > now.Unix()+skewSec {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf(
			"credential iat lies more than %ds in the future "+
				"(iat=%d, now=%d, skew=%ds) — refusing to accept",
			skewSec, cred.Claims.IssuedAt, now.Unix(), skewSec))
	}

	// Step 7: Verify required VIBAP layers and identity/core subject boundaries.
	subject := strings.TrimSpace(cred.Claims.Subject)
	if subject == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "credential subject is empty")
	}
	if cred.Claims.Identity == nil {
		if strings.HasPrefix(strings.ToLower(subject), "spiffe://") {
			result.Valid = false
			result.Errors = append(result.Errors, "core credential subject must not be SPIFFE-formatted when identity is omitted")
		}
	} else if cred.Claims.Identity.SPIFFEID == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "identity layer: spiffe_id is empty")
	} else {
		if cred.Claims.Identity.SPIFFEID != cred.Claims.Subject {
			// The credential subject (sub) MUST match the identity layer's spiffe_id.
			// Divergence would allow a credential issued for agent A to claim identity of agent B.
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf(
				"subject/identity mismatch: sub=%q but identity.spiffe_id=%q",
				cred.Claims.Subject, cred.Claims.Identity.SPIFFEID))
		}
	}
	if cred.Claims.Intent == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "missing required Layer 3 (Intent)")
	}
	if cred.Claims.Trust == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "missing required Layer 5 (Trust)")
	}

	// Step 8: Verify disclosure hashes match _sd array
	if len(cred.Disclosures) > 0 {
		if cred.Claims.SDAlgorithm != SDAlgorithm {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("unexpected _sd_alg %q, expected %q", cred.Claims.SDAlgorithm, SDAlgorithm))
		}

		sdSet := make(map[string]bool)
		for _, h := range cred.Claims.SD {
			sdSet[h] = true
		}

		for i, d := range cred.Disclosures {
			if !sdSet[d.Hash] {
				result.Valid = false
				result.Errors = append(result.Errors, fmt.Sprintf("disclosure %d (%s) hash not found in _sd array", i, d.ClaimName))
			}
		}
	}

	// Step 9: Verify Token Status List (revocation check).
	//
	// FAIL CLOSED. If the credential carries a status claim, the caller
	// MUST either (a) provide a StatusClient that can resolve it, or
	// (b) explicitly opt out via opts.SkipStatusCheck. Treating "missing
	// StatusClient" as a warning leaves a revoked credential accepted as
	// Valid=true, which is a real cap-bypass — the comprehensive audit
	// of 2026-04-28 flagged this as the only CRITICAL finding.
	//
	// If the deployment genuinely has no revocation infrastructure, the
	// caller can set SkipStatusCheck = true to acknowledge the risk
	// explicitly. Silent skip is no longer an option.
	if cred.Claims.Status != nil && !opts.SkipStatusCheck {
		if opts.StatusClient == nil {
			result.Valid = false
			result.Errors = append(result.Errors,
				"credential has status claim but no StatusClient was provided; "+
					"set opts.StatusClient to enable revocation checking, or "+
					"set opts.SkipStatusCheck=true to explicitly opt out")
		} else {
			status, err := opts.StatusClient.CheckStatus(cred, issuerPubKey)
			if err != nil {
				result.Valid = false
				result.Errors = append(result.Errors, fmt.Sprintf("status check: %v", err))
			} else if status != StatusValid {
				result.Valid = false
				result.Errors = append(result.Errors, fmt.Sprintf("credential status: %s", status))
			}
		}
	}

	// Step 10: Verify Key Binding JWT
	// If the credential has a cnf claim, the holder MUST prove possession
	// via a KB-JWT. Accepting a bound credential without proof defeats
	// the purpose of holder key binding.
	if cred.Claims.Confirmation != nil && cred.KeyBinding == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "credential has cnf claim but no Key Binding JWT — holder possession not proven")
	}
	if cred.KeyBinding != nil {
		if err := verifyKeyBinding(cred, raw, opts, now); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("key binding: %v", err))
		}
	}

	// Step 10: Verify identity layer specifics
	if cred.Claims.Identity != nil {
		if cred.Claims.Identity.OwnerID == "" {
			result.Valid = false
			result.Errors = append(result.Errors, "identity layer: owner_id is empty")
		}
		if cred.Claims.Identity.OwnerIDAssurance != OwnerIDAssuranceSelfAsserted {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf(
				"identity layer: unsupported owner_id_assurance %q; only %q is implemented",
				cred.Claims.Identity.OwnerIDAssurance,
				OwnerIDAssuranceSelfAsserted,
			))
		}
		// The assurance label states how spiffe_id entered the credential.
		// Missing and invented values both fail closed, on the same reasoning
		// ADR-024 gives for owner_id_assurance: accepting either would let a
		// credential assert a workload identity with no corresponding proof
		// path, and would leave a verifier reading spiffe_id as though it
		// meant something it has no basis for.
		switch cred.Claims.Identity.SPIFFEIDAssurance {
		case SPIFFEIDAssuranceCallerProvided, SPIFFEIDAssuranceProviderVerified:
		default:
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf(
				"identity layer: unsupported spiffe_id_assurance %q; a missing or unrecognised value fails closed",
				cred.Claims.Identity.SPIFFEIDAssurance,
			))
		}
	}

	// Step 11: Verify intent layer specifics
	if cred.Claims.Intent != nil {
		if cred.Claims.Intent.PolicyEngine != "cedar" && cred.Claims.Intent.PolicyEngine != "rego" {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("intent layer: invalid policy_engine %q", cred.Claims.Intent.PolicyEngine))
		}
	}

	// Step 12: Verify trust score ranges
	if cred.Claims.Trust != nil {
		t := cred.Claims.Trust
		if t.StaticCapabilityScore < 0 || t.StaticCapabilityScore > 1.0 {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("trust layer: static_capability_score %f out of [0,1] range", t.StaticCapabilityScore))
		}
		if t.HistoricalReputation < 0 || t.HistoricalReputation > 1.0 {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("trust layer: historical_reputation %f out of [0,1] range", t.HistoricalReputation))
		}
		if t.CompositeScore < 0 || t.CompositeScore > 100 {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("trust layer: composite_score %f out of [0,100] range", t.CompositeScore))
		}
	}

	return result, nil
}

// verifyJWTSignature checks the Ed25519 signature on a JWS Compact Serialization.
func verifyJWTSignature(token string, pubKey ed25519.PublicKey) error {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format: expected 3 dot-separated parts")
	}

	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	if !ed25519.Verify(pubKey, []byte(signingInput), signature) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}

	return nil
}

// verifyKeyBinding validates the Key Binding JWT against the credential.
func verifyKeyBinding(cred *VIBAPCredential, raw string, opts *VerifyOptions, now time.Time) error {
	kb := cred.KeyBinding

	// Verify KB-JWT header
	if kb.Header.Algorithm != "EdDSA" {
		return fmt.Errorf("unexpected KB algorithm %q", kb.Header.Algorithm)
	}
	if kb.Header.Type != MediaTypeKBJWT {
		return fmt.Errorf("unexpected KB type %q", kb.Header.Type)
	}

	// Extract holder public key from credential's cnf claim
	if cred.Claims.Confirmation == nil || cred.Claims.Confirmation.JWK == nil {
		return fmt.Errorf("credential missing cnf claim for key binding verification")
	}

	holderPubBytes, err := base64.RawURLEncoding.DecodeString(cred.Claims.Confirmation.JWK.X)
	if err != nil {
		return fmt.Errorf("decoding holder public key: %w", err)
	}
	holderPubKey := ed25519.PublicKey(holderPubBytes)

	// Verify KB-JWT signature
	if err := verifyJWTSignature(kb.Raw, holderPubKey); err != nil {
		return fmt.Errorf("KB-JWT signature: %w", err)
	}

	// Verify sd_hash: SHA-256 of the SD-JWT (everything before the KB-JWT)
	lastTilde := strings.LastIndex(raw, "~")
	if lastTilde < 0 {
		return fmt.Errorf("cannot extract SD-JWT part for sd_hash verification")
	}
	sdJWTPart := raw[:lastTilde]
	expectedHash := sha256.Sum256([]byte(sdJWTPart))
	expectedHashB64 := base64.RawURLEncoding.EncodeToString(expectedHash[:])
	if kb.Claims.SDHash != expectedHashB64 {
		return fmt.Errorf("sd_hash mismatch")
	}

	// Verify audience and nonce if expected values are provided
	if opts.ExpectedAudience != "" && kb.Claims.Audience != opts.ExpectedAudience {
		return fmt.Errorf("audience mismatch: got %q, want %q", kb.Claims.Audience, opts.ExpectedAudience)
	}
	if opts.ExpectedNonce != "" && kb.Claims.Nonce != opts.ExpectedNonce {
		return fmt.Errorf("nonce mismatch")
	}

	// Verify KB-JWT freshness
	maxAge := opts.MaxKBAge
	if maxAge == 0 {
		maxAge = 5 * time.Minute
	}
	kbTime := time.Unix(kb.Claims.IssuedAt, 0)
	if kbTime.After(now.Add(30 * time.Second)) {
		return fmt.Errorf("KB-JWT issued in the future (clock skew?)")
	}
	if now.Sub(kbTime) > maxAge {
		return fmt.Errorf("KB-JWT is too old (issued %s ago, max %s)", now.Sub(kbTime), maxAge)
	}

	return nil
}
