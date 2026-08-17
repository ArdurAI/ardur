package credential

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// testKeyPair generates a deterministic Ed25519 key pair for testing.
func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key pair: %v", err)
	}
	return pub, priv
}

// testSigningKey creates a SigningKey for testing.
func testSigningKey(t *testing.T) *SigningKey {
	t.Helper()
	pub, priv := testKeyPair(t)
	return &SigningKey{
		PrivateKey: priv,
		PublicKey:  pub,
		KeyID:      "test-key-001",
	}
}

// testBuilder creates a minimal valid builder for testing.
func testBuilder(t *testing.T) *Builder {
	t.Helper()
	return NewBuilder(
		"https://vibap.example.com",
		"spiffe://ardur.dev/ns/default/sa/agent/instance/test-001",
	).
		WithIdentity(
			"spiffe://ardur.dev/ns/default/sa/agent/instance/test-001",
			"spiffe://ardur.dev/ns/default/sa/deployer",
			"",
		).
		WithIntent(
			"sha256:abc123def456",
			"cedar",
			"sha256:policy789",
			[]string{"read:database", "call:api/v1/*"},
		).
		WithTrust(0.3, 0.9, 85.0, "", "")
}

// --- Builder Tests ---

func TestBuilderMinimal(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	if cred.Header.Algorithm != "EdDSA" {
		t.Errorf("Header.Algorithm = %q, want EdDSA", cred.Header.Algorithm)
	}
	if cred.Header.Type != MediaTypeDCSDJWT {
		t.Errorf("Header.Type = %q, want %q", cred.Header.Type, MediaTypeDCSDJWT)
	}
	if cred.Claims.VerifiableCredentialType != VIBAPTypeURI {
		t.Errorf("VCT = %q, want %q", cred.Claims.VerifiableCredentialType, VIBAPTypeURI)
	}
	if cred.Claims.Identity == nil {
		t.Fatal("Identity layer is nil")
	}
	identityJSON, err := json.Marshal(cred.Claims.Identity)
	if err != nil {
		t.Fatalf("marshal identity claims: %v", err)
	}
	var identityFields map[string]any
	if err := json.Unmarshal(identityJSON, &identityFields); err != nil {
		t.Fatalf("decode identity claims: %v", err)
	}
	if got := identityFields["owner_id_assurance"]; got != "self_asserted" {
		t.Fatalf("owner_id_assurance = %v, want self_asserted", got)
	}
	if _, ok := identityFields["spiffe_id_assurance"]; ok {
		t.Fatal("identity must not add an unversioned spiffe_id_assurance claim")
	}
	if cred.Claims.Intent == nil {
		t.Fatal("Intent layer is nil")
	}
	if cred.Claims.Trust == nil {
		t.Fatal("Trust layer is nil")
	}
	if cred.Claims.Trust.AuthorizationTier != TierFull {
		t.Errorf("Trust tier = %q, want %q (score 85)", cred.Claims.Trust.AuthorizationTier, TierFull)
	}
}

func TestVerifyRejectsUnsupportedOwnerIDAssurance(t *testing.T) {
	for _, tt := range []struct {
		name      string
		assurance OwnerIDAssurance
	}{
		{name: "missing", assurance: ""},
		{name: "fabricated verified", assurance: "verified"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key := testSigningKey(t)
			cred, err := testBuilder(t).Build(key)
			if err != nil {
				t.Fatalf("Build() error: %v", err)
			}
			cred.Claims.Identity.OwnerIDAssurance = tt.assurance

			encoded, err := Encode(cred, key)
			if err != nil {
				t.Fatalf("Encode() error: %v", err)
			}
			result, err := Verify(encoded, key.PublicKey, nil)
			if err != nil {
				t.Fatalf("Verify() error: %v", err)
			}
			if result.Valid {
				t.Fatalf("unsupported owner assurance %q was accepted", tt.assurance)
			}
			if got := strings.Join(result.Errors, "; "); !strings.Contains(got, "owner_id_assurance") {
				t.Fatalf("verification errors = %q, want owner_id_assurance failure", got)
			}
		})
	}
}

func TestBuilderAllLayers(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).
		WithProvenance("sha256:image-digest", "https://rekor.example.com/entry/123", "sha256:model-hash", "github-actions://...", "https://sbom.example.com/agent").
		WithBaseline("sha256:profile-hash", []string{"10.0.0.0/8:443"}, []string{"read", "write", "openat"}, map[string]FrequencyBound{
			"search": {Min: 1, Max: 100, Window: "1h"},
		}, []string{"/tmp/*"}, 2).
		Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	if cred.Claims.Provenance == nil {
		t.Error("Provenance layer is nil")
	}
	if cred.Claims.Baseline == nil {
		t.Error("Baseline layer is nil")
	}
	if cred.Claims.Baseline.MaxDelegationDepth != 2 {
		t.Errorf("MaxDelegationDepth = %d, want 2", cred.Claims.Baseline.MaxDelegationDepth)
	}
}

func TestBuilderSelectiveDisclosure(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).
		WithProvenance("sha256:digest", "", "", "", "").
		WithBaseline("sha256:profile", nil, nil, nil, nil, 0).
		WithSelectiveDisclosure("provenance", "baseline").
		Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// SD layers should NOT appear in Claims (they're in disclosures)
	if cred.Claims.Provenance != nil {
		t.Error("Provenance should be nil in claims when selectively disclosed")
	}
	if cred.Claims.Baseline != nil {
		t.Error("Baseline should be nil in claims when selectively disclosed")
	}

	// Should have 2 disclosures
	if len(cred.Disclosures) != 2 {
		t.Fatalf("expected 2 disclosures, got %d", len(cred.Disclosures))
	}

	// Verify _sd array has matching hashes
	if len(cred.Claims.SD) != 2 {
		t.Fatalf("expected 2 _sd hashes, got %d", len(cred.Claims.SD))
	}
	if cred.Claims.SDAlgorithm != SDAlgorithm {
		t.Errorf("_sd_alg = %q, want %q", cred.Claims.SDAlgorithm, SDAlgorithm)
	}

	// Verify disclosure names
	names := map[string]bool{}
	for _, d := range cred.Disclosures {
		names[d.ClaimName] = true
	}
	if !names["provenance"] {
		t.Error("missing provenance disclosure")
	}
	if !names["baseline"] {
		t.Error("missing baseline disclosure")
	}
}

func TestBuilderValidationErrors(t *testing.T) {
	key := testSigningKey(t)

	tests := []struct {
		name    string
		builder *Builder
		wantErr string
	}{
		{
			name:    "empty issuer",
			builder: NewBuilder("", "spiffe://test"),
			wantErr: "issuer is required",
		},
		{
			name:    "empty subject",
			builder: NewBuilder("https://test", ""),
			wantErr: "subject is required",
		},
		{
			name: "SPIFFE subject without identity",
			builder: NewBuilder("https://test", "spiffe://test/agent").
				WithIntent("checksum", "cedar", "hash", nil).
				WithTrust(0.5, 0.5, 50, "", ""),
			wantErr: "SPIFFE-formatted subject requires identity",
		},
		{
			name: "missing intent",
			builder: NewBuilder("https://test", "spiffe://test").
				WithIdentity("spiffe://test", "spiffe://owner", "").
				WithTrust(0.5, 0.5, 50, "", ""),
			wantErr: "intent layer",
		},
		{
			name: "missing trust",
			builder: NewBuilder("https://test", "spiffe://test").
				WithIdentity("spiffe://test", "spiffe://owner", "").
				WithIntent("checksum", "cedar", "hash", nil),
			wantErr: "trust layer",
		},
		{
			name: "invalid policy engine",
			builder: NewBuilder("https://test", "spiffe://test").
				WithIdentity("spiffe://test", "spiffe://owner", "").
				WithIntent("checksum", "invalid-engine", "hash", nil).
				WithTrust(0.5, 0.5, 50, "", ""),
			wantErr: "policy_engine",
		},
		{
			name: "trust score out of range",
			builder: NewBuilder("https://test", "spiffe://test").
				WithIdentity("spiffe://test", "spiffe://owner", "").
				WithIntent("checksum", "cedar", "hash", nil).
				WithTrust(1.5, 0.5, 50, "", ""),
			wantErr: "static_capability_score",
		},
		{
			name: "SD on required layer",
			builder: NewBuilder("https://test", "spiffe://test").
				WithIdentity("spiffe://test", "spiffe://owner", "").
				WithIntent("checksum", "cedar", "hash", nil).
				WithTrust(0.5, 0.5, 50, "", "").
				WithSelectiveDisclosure("identity"),
			wantErr: "cannot be selectively disclosable",
		},
		{
			name: "negative TTL",
			builder: NewBuilder("https://test", "spiffe://test").
				WithTTL(-1 * time.Hour),
			wantErr: "TTL must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.builder.Build(key)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestBuilderWithHolderKey(t *testing.T) {
	issuerKey := testSigningKey(t)
	holderPub, _ := testKeyPair(t)

	cred, err := testBuilder(t).
		WithHolderKey(holderPub).
		Build(issuerKey)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	if cred.Claims.Confirmation == nil {
		t.Fatal("Confirmation (cnf) claim is nil")
	}
	if cred.Claims.Confirmation.JWK == nil {
		t.Fatal("Confirmation JWK is nil")
	}
	if cred.Claims.Confirmation.JWK.KeyType != "OKP" {
		t.Errorf("JWK key type = %q, want OKP", cred.Claims.Confirmation.JWK.KeyType)
	}
	if cred.Claims.Confirmation.JWK.Curve != "Ed25519" {
		t.Errorf("JWK curve = %q, want Ed25519", cred.Claims.Confirmation.JWK.Curve)
	}
}

func TestBuilderWithStatus(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).
		WithStatus("https://status.example.com/list/1", 42).
		Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	if cred.Claims.Status == nil {
		t.Fatal("Status claim is nil")
	}
	if cred.Claims.Status.StatusList.URI != "https://status.example.com/list/1" {
		t.Errorf("Status URI = %q", cred.Claims.Status.StatusList.URI)
	}
	if cred.Claims.Status.StatusList.Index != 42 {
		t.Errorf("Status index = %d, want 42", cred.Claims.Status.StatusList.Index)
	}
}

// --- Encoding/Decoding Tests ---

func TestEncodeDecodeRoundtrip(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	// Verify format: should end with trailing tilde (no KB-JWT)
	if !strings.HasSuffix(encoded, "~") {
		t.Error("encoded credential should end with trailing tilde")
	}

	// Count tildes: at minimum issuerJWT~
	parts := strings.Split(encoded, "~")
	if len(parts) < 2 {
		t.Fatalf("expected at least 2 tilde-separated parts, got %d", len(parts))
	}

	// Decode back
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	// Verify round-trip
	if decoded.Header.Algorithm != cred.Header.Algorithm {
		t.Errorf("Header.Algorithm mismatch: %q vs %q", decoded.Header.Algorithm, cred.Header.Algorithm)
	}
	if decoded.Claims.Issuer != cred.Claims.Issuer {
		t.Errorf("Issuer mismatch: %q vs %q", decoded.Claims.Issuer, cred.Claims.Issuer)
	}
	if decoded.Claims.Subject != cred.Claims.Subject {
		t.Errorf("Subject mismatch: %q vs %q", decoded.Claims.Subject, cred.Claims.Subject)
	}
	if decoded.Claims.VerifiableCredentialType != VIBAPTypeURI {
		t.Errorf("VCT mismatch: %q", decoded.Claims.VerifiableCredentialType)
	}
	if decoded.Claims.Identity == nil {
		t.Error("decoded Identity is nil")
	} else if decoded.Claims.Identity.OwnerIDAssurance != OwnerIDAssuranceSelfAsserted {
		t.Errorf("decoded owner assurance = %q, want %q", decoded.Claims.Identity.OwnerIDAssurance, OwnerIDAssuranceSelfAsserted)
	}
	if decoded.Claims.Intent == nil {
		t.Error("decoded Intent is nil")
	}
	if decoded.Claims.Trust == nil {
		t.Error("decoded Trust is nil")
	}
}

func TestEncodeDecodeWithDisclosures(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).
		WithProvenance("sha256:digest", "", "", "", "").
		WithBaseline("sha256:profile", nil, nil, nil, nil, 0).
		WithSelectiveDisclosure("provenance", "baseline").
		Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	if len(decoded.Disclosures) != 2 {
		t.Fatalf("expected 2 disclosures, got %d", len(decoded.Disclosures))
	}

	// Verify disclosure claim names survived round-trip
	names := map[string]bool{}
	for _, d := range decoded.Disclosures {
		names[d.ClaimName] = true
	}
	if !names["provenance"] || !names["baseline"] {
		t.Errorf("disclosure names = %v, want provenance and baseline", names)
	}
}

func TestEncodeDecodeWithKeyBinding(t *testing.T) {
	issuerKey := testSigningKey(t)
	holderPub, holderPriv := testKeyPair(t)

	cred, err := testBuilder(t).
		WithHolderKey(holderPub).
		Build(issuerKey)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	encoded, err := EncodeWithKeyBinding(cred, issuerKey, holderPriv, "test-nonce-123", "https://verifier.example.com")
	if err != nil {
		t.Fatalf("EncodeWithKeyBinding() error: %v", err)
	}

	// Should NOT end with trailing tilde (KB-JWT is appended)
	if strings.HasSuffix(encoded, "~") {
		t.Error("credential with KB-JWT should not end with trailing tilde")
	}

	// Decode and verify KB-JWT is present
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	if decoded.KeyBinding == nil {
		t.Fatal("decoded KeyBinding is nil")
	}
	if decoded.KeyBinding.Header.Type != MediaTypeKBJWT {
		t.Errorf("KB-JWT type = %q, want %q", decoded.KeyBinding.Header.Type, MediaTypeKBJWT)
	}
	if decoded.KeyBinding.Claims.Nonce != "test-nonce-123" {
		t.Errorf("KB-JWT nonce = %q, want test-nonce-123", decoded.KeyBinding.Claims.Nonce)
	}
	if decoded.KeyBinding.Claims.Audience != "https://verifier.example.com" {
		t.Errorf("KB-JWT audience = %q", decoded.KeyBinding.Claims.Audience)
	}
}

func TestEncodeErrors(t *testing.T) {
	key := testSigningKey(t)

	_, err := Encode(nil, key)
	if err == nil {
		t.Error("expected error for nil credential")
	}

	cred, _ := testBuilder(t).Build(key)
	_, err = Encode(cred, nil)
	if err == nil {
		t.Error("expected error for nil key")
	}
}

func TestDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"empty", "", "empty credential string"},
		{"no tilde", "just.a.jwt", "at least 2 tilde-separated parts"},
		{"invalid jwt", "not-a-jwt~disclosure~", "parsing issuer JWT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// --- Verification Tests ---

func TestVerifyValid(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	result, err := Verify(encoded, key.PublicKey, &VerifyOptions{
		SkipStatusCheck: true,
	})
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid, got errors: %v", result.Errors)
	}
	if len(result.Errors) > 0 {
		t.Errorf("unexpected errors: %v", result.Errors)
	}
}

func TestVerifyExpired(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).
		WithTTL(1 * time.Millisecond).
		Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	// Verify at a time after expiration
	result, err := Verify(encoded, key.PublicKey, &VerifyOptions{
		CurrentTime: time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}

	if result.Valid {
		t.Error("expected invalid (expired), but got valid")
	}

	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "expired") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected expiry error, got: %v", result.Errors)
	}
}

func TestVerifyTampered(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	// Tamper with the encoded credential (change a character in the payload)
	parts := strings.Split(encoded, "~")
	jwtParts := strings.SplitN(parts[0], ".", 3)
	// Flip a character in the payload
	payload := []byte(jwtParts[1])
	if len(payload) > 5 {
		payload[5] ^= 0xFF
	}
	jwtParts[1] = string(payload)
	parts[0] = strings.Join(jwtParts, ".")
	tampered := strings.Join(parts, "~")

	result, err := Verify(tampered, key.PublicKey, nil)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}

	if result.Valid {
		t.Error("expected invalid (tampered), but got valid")
	}

	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "signature") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected signature error, got: %v", result.Errors)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	// Verify with a different key
	wrongKey := testSigningKey(t)
	result, err := Verify(encoded, wrongKey.PublicKey, nil)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}

	if result.Valid {
		t.Error("expected invalid (wrong key), but got valid")
	}
}

func TestVerifyWithKeyBinding(t *testing.T) {
	issuerKey := testSigningKey(t)
	holderPub, holderPriv := testKeyPair(t)

	cred, err := testBuilder(t).
		WithHolderKey(holderPub).
		Build(issuerKey)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	encoded, err := EncodeWithKeyBinding(cred, issuerKey, holderPriv, "nonce-abc", "https://verifier.example.com")
	if err != nil {
		t.Fatalf("EncodeWithKeyBinding() error: %v", err)
	}

	result, err := Verify(encoded, issuerKey.PublicKey, &VerifyOptions{
		ExpectedNonce:    "nonce-abc",
		ExpectedAudience: "https://verifier.example.com",
	})
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid, got errors: %v", result.Errors)
	}
}

func TestVerifyKeyBindingWrongNonce(t *testing.T) {
	issuerKey := testSigningKey(t)
	holderPub, holderPriv := testKeyPair(t)

	cred, err := testBuilder(t).
		WithHolderKey(holderPub).
		Build(issuerKey)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	encoded, err := EncodeWithKeyBinding(cred, issuerKey, holderPriv, "nonce-abc", "https://verifier.example.com")
	if err != nil {
		t.Fatalf("EncodeWithKeyBinding() error: %v", err)
	}

	result, err := Verify(encoded, issuerKey.PublicKey, &VerifyOptions{
		ExpectedNonce:    "wrong-nonce",
		ExpectedAudience: "https://verifier.example.com",
	})
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}

	if result.Valid {
		t.Error("expected invalid (wrong nonce), but got valid")
	}
}

func TestVerifyWithDisclosures(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).
		WithProvenance("sha256:digest", "", "", "", "").
		WithSelectiveDisclosure("provenance").
		Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	result, err := Verify(encoded, key.PublicKey, nil)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid, got errors: %v", result.Errors)
	}

	if len(result.Credential.Disclosures) != 1 {
		t.Errorf("expected 1 disclosure, got %d", len(result.Credential.Disclosures))
	}
}

func TestVerifyNotYetValid(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Set nbf to future
	cred.Claims.NotBefore = time.Now().Add(1 * time.Hour).Unix()

	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	result, err := Verify(encoded, key.PublicKey, nil)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if result.Valid {
		t.Error("expected invalid (not yet valid)")
	}
	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "not valid before") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'not valid before' error, got: %v", result.Errors)
	}
}

// TestVerifyFutureIssuedAt locks in FIX-R4-2 from the round-3 hostile
// audit (2026-04-28): a credential whose iat lies more than skewSec in
// the future is REJECTED, not warned about. The previous behaviour
// emitted a "clock skew?" warning while leaving result.Valid=true,
// which silently accepted credentials minted by a briefly-compromised
// signer with iat far in the future. The current contract is symmetric
// with the bounded-iat-skew gate Python uses (vibap.passport.assert_iat_in_window).
func TestVerifyFutureIssuedAt(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Set iat to 1 hour in the future — well beyond the skewSec
	// clock-drift tolerance the verifier uses.
	cred.Claims.IssuedAt = time.Now().Add(1 * time.Hour).Unix()

	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	result, err := Verify(encoded, key.PublicKey, nil)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}

	if result.Valid {
		t.Errorf("expected result.Valid=false for future-iat credential, got Valid=true")
	}
	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "iat lies more than") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'iat lies more than' error, got errors: %v", result.Errors)
	}
}

// TestVerifyIssuedAtWithinSkewWindowAccepted complements the regression
// above: an iat within skewSec of now should still be accepted, so the
// fix doesn't accidentally reject legitimate clock drift across nodes.
func TestVerifyIssuedAtWithinSkewWindowAccepted(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	// 15 seconds in the future — within the default skewSec tolerance
	// (the Go verifier uses skewSec=30 by default; see verify.go).
	cred.Claims.IssuedAt = time.Now().Add(15 * time.Second).Unix()
	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}
	result, err := Verify(encoded, key.PublicKey, nil)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if !result.Valid {
		t.Errorf("expected result.Valid=true for in-window iat, got false; errors=%v", result.Errors)
	}
}

// TestVerifyRevocationFailsClosed locks in the 2026-04-28 audit's CRITICAL
// fix: a credential carrying a status claim must NOT be accepted as Valid
// when no StatusClient is provided. The previous behaviour appended a
// warning and returned Valid=true, which silently accepted revoked
// credentials in deployments that forgot to wire status checking.
//
// Two acceptable outcomes for a status-bearing credential:
//   - StatusClient is set, the check runs, Valid reflects the result
//   - SkipStatusCheck = true, the caller has explicitly opted out
//
// Anything else (no StatusClient AND no SkipStatusCheck) must mark the
// result invalid. This test guards against silent regression to the
// fail-open default.
func TestVerifyRevocationFailsClosedWithoutStatusClient(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).
		WithStatus("https://status.example.com/list/1", 7).
		Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	// Caller does NOT provide a StatusClient and does NOT opt out via
	// SkipStatusCheck. Must fail closed.
	result, err := Verify(encoded, key.PublicKey, nil)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if result.Valid {
		t.Error("expected Valid=false when status claim present but no StatusClient and no SkipStatusCheck (audit CRITICAL: fail-open revocation)")
	}
	hasStatusErr := false
	for _, e := range result.Errors {
		if strings.Contains(e, "StatusClient") || strings.Contains(e, "status") {
			hasStatusErr = true
			break
		}
	}
	if !hasStatusErr {
		t.Errorf("expected an error mentioning StatusClient/status; got %v", result.Errors)
	}

	// Now opt out explicitly via SkipStatusCheck — must be accepted.
	result2, err := Verify(encoded, key.PublicKey, &VerifyOptions{SkipStatusCheck: true})
	if err != nil {
		t.Fatalf("Verify() with SkipStatusCheck error: %v", err)
	}
	if !result2.Valid {
		t.Errorf("expected Valid=true with SkipStatusCheck=true (explicit opt-out), got errors: %v", result2.Errors)
	}
}

func TestVerifyMissingLayers(t *testing.T) {
	key := testSigningKey(t)

	// Build a credential, omit optional identity, and nil out required layers.
	cred, err := testBuilder(t).Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	cred.Claims.Identity = nil
	cred.Claims.Intent = nil
	cred.Claims.Trust = nil

	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	result, err := Verify(encoded, key.PublicKey, nil)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}

	if result.Valid {
		t.Error("expected invalid (missing layers)")
	}

	errorSet := strings.Join(result.Errors, "; ")
	for _, want := range []string{"Layer 3", "Layer 5"} {
		if !strings.Contains(errorSet, want) {
			t.Errorf("expected error mentioning %q, got: %s", want, errorSet)
		}
	}
	if strings.Contains(errorSet, "Layer 1") {
		t.Errorf("optional identity must not be reported as missing: %s", errorSet)
	}
}

func TestVerifyEmptyIdentityFields(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Empty out identity fields
	cred.Claims.Identity = &IdentityClaims{SPIFFEID: "", OwnerID: ""}

	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	result, err := Verify(encoded, key.PublicKey, nil)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}

	if result.Valid {
		t.Error("expected invalid (empty identity fields)")
	}

	errorSet := strings.Join(result.Errors, "; ")
	if !strings.Contains(errorSet, "spiffe_id is empty") {
		t.Errorf("expected spiffe_id error, got: %s", errorSet)
	}
	if !strings.Contains(errorSet, "owner_id is empty") {
		t.Errorf("expected owner_id error, got: %s", errorSet)
	}
}

func TestVerifyRejectsSPIFFESubjectWithoutIdentity(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	cred.Claims.Identity = nil
	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	result, err := Verify(encoded, key.PublicKey, nil)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if result.Valid {
		t.Fatal("expected invalid SPIFFE-formatted core subject")
	}
	if got := strings.Join(result.Errors, "; "); !strings.Contains(got, "core credential subject must not be SPIFFE-formatted") {
		t.Fatalf("expected core subject error, got: %s", got)
	}
}

func TestVerifyInvalidPolicyEngine(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	cred.Claims.Intent.PolicyEngine = "invalid"

	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	result, err := Verify(encoded, key.PublicKey, nil)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}

	if result.Valid {
		t.Error("expected invalid (bad policy engine)")
	}

	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "invalid policy_engine") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected policy_engine error, got: %v", result.Errors)
	}
}

func TestVerifyLegacyMediaType(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Set legacy media type
	cred.Header.Type = "vc+sd-jwt"

	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	result, err := Verify(encoded, key.PublicKey, nil)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}

	// Should still be valid but with a warning
	found := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "legacy media type") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected legacy media type warning, got warnings: %v", result.Warnings)
	}
}

func TestVerifyErrors(t *testing.T) {
	key := testSigningKey(t)

	_, err := Verify("", key.PublicKey, nil)
	if err == nil {
		t.Error("expected error for empty string")
	}

	_, err = Verify("test~test~", []byte("short"), nil)
	if err == nil {
		t.Error("expected error for invalid key size")
	}
}

// --- Builder Error Path Tests (coverage) ---

func TestBuilderWithIdentityEmptyOwnerID(t *testing.T) {
	key := testSigningKey(t)
	_, err := NewBuilder("https://test", "spiffe://test").
		WithIdentity("spiffe://test", "", "").
		WithIntent("checksum", "cedar", "hash", nil).
		WithTrust(0.5, 0.5, 50, "", "").
		Build(key)
	if err == nil {
		t.Fatal("expected error for empty ownerID")
	}
	if !strings.Contains(err.Error(), "owner_id") {
		t.Errorf("error %q does not contain owner_id", err.Error())
	}
}

func TestBuilderWithIdentityEmptySPIFFEID(t *testing.T) {
	key := testSigningKey(t)
	_, err := NewBuilder("https://test", "spiffe://test").
		WithIdentity("", "spiffe://owner", "").
		WithIntent("checksum", "cedar", "hash", nil).
		WithTrust(0.5, 0.5, 50, "", "").
		Build(key)
	if err == nil {
		t.Fatal("expected error for empty spiffeID")
	}
	if !strings.Contains(err.Error(), "spiffe_id") {
		t.Errorf("error %q does not contain spiffe_id", err.Error())
	}
}

func TestBuilderWithProvenanceEmptyImageDigest(t *testing.T) {
	key := testSigningKey(t)
	_, err := testBuilder(t).
		WithProvenance("", "https://rekor.example.com", "", "", "").
		Build(key)
	if err == nil {
		t.Fatal("expected error for empty imageDigest")
	}
	if !strings.Contains(err.Error(), "image_digest") {
		t.Errorf("error %q does not contain image_digest", err.Error())
	}
}

func TestBuilderWithIntentEmptyAgentChecksum(t *testing.T) {
	key := testSigningKey(t)
	_, err := NewBuilder("https://test", "spiffe://test").
		WithIdentity("spiffe://test", "spiffe://owner", "").
		WithIntent("", "cedar", "hash", nil).
		WithTrust(0.5, 0.5, 50, "", "").
		Build(key)
	if err == nil {
		t.Fatal("expected error for empty agentChecksum")
	}
	if !strings.Contains(err.Error(), "agent_checksum") {
		t.Errorf("error %q does not contain agent_checksum", err.Error())
	}
}

func TestBuilderWithIntentEmptyPolicyEngine(t *testing.T) {
	key := testSigningKey(t)
	_, err := NewBuilder("https://test", "spiffe://test").
		WithIdentity("spiffe://test", "spiffe://owner", "").
		WithIntent("checksum", "", "hash", nil).
		WithTrust(0.5, 0.5, 50, "", "").
		Build(key)
	if err == nil {
		t.Fatal("expected error for empty policyEngine")
	}
	if !strings.Contains(err.Error(), "policy_engine") {
		t.Errorf("error %q does not contain policy_engine", err.Error())
	}
}

func TestBuilderWithIntentEmptyPolicyHash(t *testing.T) {
	key := testSigningKey(t)
	_, err := NewBuilder("https://test", "spiffe://test").
		WithIdentity("spiffe://test", "spiffe://owner", "").
		WithIntent("checksum", "cedar", "", nil).
		WithTrust(0.5, 0.5, 50, "", "").
		Build(key)
	if err == nil {
		t.Fatal("expected error for empty policyHash")
	}
	if !strings.Contains(err.Error(), "policy_hash") {
		t.Errorf("error %q does not contain policy_hash", err.Error())
	}
}

func TestBuilderWithBaselineEmptyProfileHash(t *testing.T) {
	key := testSigningKey(t)
	_, err := testBuilder(t).
		WithBaseline("", nil, nil, nil, nil, 0).
		Build(key)
	if err == nil {
		t.Fatal("expected error for empty profileHash")
	}
	if !strings.Contains(err.Error(), "application_profile_hash") {
		t.Errorf("error %q does not contain application_profile_hash", err.Error())
	}
}

func TestBuilderWithBaselineNegativeMaxDepth(t *testing.T) {
	key := testSigningKey(t)
	_, err := testBuilder(t).
		WithBaseline("sha256:profile", nil, nil, nil, nil, -1).
		Build(key)
	if err == nil {
		t.Fatal("expected error for negative maxDepth")
	}
	if !strings.Contains(err.Error(), "max_delegation_depth") {
		t.Errorf("error %q does not contain max_delegation_depth", err.Error())
	}
}

func TestBuilderWithStatusEmptyURI(t *testing.T) {
	key := testSigningKey(t)
	_, err := testBuilder(t).
		WithStatus("", 0).
		Build(key)
	if err == nil {
		t.Fatal("expected error for empty status URI")
	}
	if !strings.Contains(err.Error(), "uri") {
		t.Errorf("error %q does not contain uri", err.Error())
	}
}

func TestBuilderWithStatusNegativeIndex(t *testing.T) {
	key := testSigningKey(t)
	_, err := testBuilder(t).
		WithStatus("https://status.example.com/list/1", -1).
		Build(key)
	if err == nil {
		t.Fatal("expected error for negative status index")
	}
	if !strings.Contains(err.Error(), "index") {
		t.Errorf("error %q does not contain index", err.Error())
	}
}

func TestBuilderWithHolderKeyWrongSize(t *testing.T) {
	key := testSigningKey(t)
	shortKey := make([]byte, 16) // Ed25519 public key must be 32 bytes
	_, err := testBuilder(t).
		WithHolderKey(shortKey).
		Build(key)
	if err == nil {
		t.Fatal("expected error for wrong holder key size")
	}
	if !strings.Contains(err.Error(), "holder key") {
		t.Errorf("error %q does not contain holder key", err.Error())
	}
}

func TestBuilderWithTrustHistoricalRepOutOfRange(t *testing.T) {
	key := testSigningKey(t)
	_, err := NewBuilder("https://test", "spiffe://test").
		WithIdentity("spiffe://test", "spiffe://owner", "").
		WithIntent("checksum", "cedar", "hash", nil).
		WithTrust(0.5, 1.5, 50, "", "").
		Build(key)
	if err == nil {
		t.Fatal("expected error for historicalRep > 1.0")
	}
	if !strings.Contains(err.Error(), "historical_reputation") {
		t.Errorf("error %q does not contain historical_reputation", err.Error())
	}
}

func TestBuilderWithTrustCompositeScoreOutOfRange(t *testing.T) {
	key := testSigningKey(t)
	_, err := NewBuilder("https://test", "spiffe://test").
		WithIdentity("spiffe://test", "spiffe://owner", "").
		WithIntent("checksum", "cedar", "hash", nil).
		WithTrust(0.5, 0.5, 150, "", "").
		Build(key)
	if err == nil {
		t.Fatal("expected error for compositeScore > 100")
	}
	if !strings.Contains(err.Error(), "composite_score") {
		t.Errorf("error %q does not contain composite_score", err.Error())
	}
}

func TestBuilderWithTrustNegativeStaticScore(t *testing.T) {
	key := testSigningKey(t)
	_, err := NewBuilder("https://test", "spiffe://test").
		WithIdentity("spiffe://test", "spiffe://owner", "").
		WithIntent("checksum", "cedar", "hash", nil).
		WithTrust(-0.1, 0.5, 50, "", "").
		Build(key)
	if err == nil {
		t.Fatal("expected error for negative staticScore")
	}
	if !strings.Contains(err.Error(), "static_capability_score") {
		t.Errorf("error %q does not contain static_capability_score", err.Error())
	}
}

func TestBuilderWithSelectiveDisclosureTrust(t *testing.T) {
	key := testSigningKey(t)
	_, err := NewBuilder("https://test", "spiffe://test").
		WithIdentity("spiffe://test", "spiffe://owner", "").
		WithIntent("checksum", "cedar", "hash", nil).
		WithTrust(0.5, 0.5, 50, "", "").
		WithSelectiveDisclosure("trust").
		Build(key)
	if err == nil {
		t.Fatal("expected error for SD on trust layer")
	}
	if !strings.Contains(err.Error(), "cannot be selectively disclosable") {
		t.Errorf("error %q does not contain cannot be selectively disclosable", err.Error())
	}
}

func TestBuilderWithSelectiveDisclosureIntent(t *testing.T) {
	key := testSigningKey(t)
	_, err := NewBuilder("https://test", "spiffe://test").
		WithIdentity("spiffe://test", "spiffe://owner", "").
		WithIntent("checksum", "cedar", "hash", nil).
		WithTrust(0.5, 0.5, 50, "", "").
		WithSelectiveDisclosure("intent").
		Build(key)
	if err == nil {
		t.Fatal("expected error for SD on intent layer")
	}
	if !strings.Contains(err.Error(), "cannot be selectively disclosable") {
		t.Errorf("error %q does not contain cannot be selectively disclosable", err.Error())
	}
}

func TestBuilderWithSelectiveDisclosureUnknownLayer(t *testing.T) {
	key := testSigningKey(t)
	_, err := testBuilder(t).
		WithSelectiveDisclosure("unknown_layer").
		Build(key)
	if err == nil {
		t.Fatal("expected error for unknown layer")
	}
	if !strings.Contains(err.Error(), "unknown layer") {
		t.Errorf("error %q does not contain unknown layer", err.Error())
	}
}

func TestBuilderBuildNilKey(t *testing.T) {
	_, err := testBuilder(t).Build(nil)
	if err == nil {
		t.Fatal("expected error for nil signing key")
	}
	if !strings.Contains(err.Error(), "signing key") {
		t.Errorf("error %q does not contain signing key", err.Error())
	}
}

func TestBuilderBuildWithPriorError(t *testing.T) {
	// Builder that already has an error from NewBuilder
	b := NewBuilder("", "spiffe://test")
	_, err := b.Build(testSigningKey(t))
	if err == nil {
		t.Fatal("expected error from builder with prior error")
	}
	if !strings.Contains(err.Error(), "builder error") {
		t.Errorf("error %q does not contain builder error", err.Error())
	}
}

// --- Decode/Encoding Error Path Tests (coverage) ---

func TestDecodeInvalidDisclosureBase64(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).
		WithProvenance("sha256:digest", "", "", "", "").
		WithSelectiveDisclosure("provenance").
		Build(key)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Replace first disclosure with invalid base64
	parts := strings.Split(encoded, "~")
	parts[1] = "!!!invalid-base64!!!"
	invalidEncoded := strings.Join(parts, "~")

	_, err = Decode(invalidEncoded)
	if err == nil {
		t.Fatal("expected error for invalid disclosure base64")
	}
	if !strings.Contains(err.Error(), "disclosure") && !strings.Contains(err.Error(), "base64") {
		t.Errorf("error %q should mention disclosure or base64", err.Error())
	}
}

func TestDecodeInvalidDisclosureJSON(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).Build(key)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Add a disclosure part with valid base64 but invalid JSON structure (not 3-element array)
	invalidDisclosure := "eyJub3QiOiJhcnJheSJ9" // base64 of {"not":"array"}
	parts := strings.Split(strings.TrimSuffix(encoded, "~"), "~")
	parts = append(parts, invalidDisclosure, "")
	invalidEncoded := strings.Join(parts, "~")

	_, err = Decode(invalidEncoded)
	if err == nil {
		t.Fatal("expected error for invalid disclosure JSON")
	}
}

func TestDecodeInvalidDisclosureArrayLength(t *testing.T) {
	// base64 of [1,2] - only 2 elements, need 3
	invalidDisclosure := "WzEsMl0"
	key := testSigningKey(t)
	cred, err := testBuilder(t).Build(key)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parts := strings.Split(strings.TrimSuffix(encoded, "~"), "~")
	parts = append(parts, invalidDisclosure, "")
	invalidEncoded := strings.Join(parts, "~")

	_, err = Decode(invalidEncoded)
	if err == nil {
		t.Fatal("expected error for disclosure with wrong array length")
	}
	if !strings.Contains(err.Error(), "3 elements") {
		t.Errorf("error %q should mention 3 elements", err.Error())
	}
}

func TestDecodeInvalidJWTType(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).Build(key)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Tamper with the credential to have wrong typ in header - we need to decode, modify, re-encode
	// Simpler: create a JWT with wrong typ. We need a valid signed JWT structure.
	parts := strings.Split(encoded, "~")
	jwtParts := strings.SplitN(parts[0], ".", 3)
	// Decode header, change typ, re-encode
	headerJSON, _ := base64.RawURLEncoding.DecodeString(jwtParts[0])
	var header map[string]interface{}
	json.Unmarshal(headerJSON, &header)
	header["typ"] = "wrong+type"
	newHeaderJSON, _ := json.Marshal(header)
	jwtParts[0] = base64.RawURLEncoding.EncodeToString(newHeaderJSON)
	// Re-sign with same key
	signingInput := jwtParts[0] + "." + jwtParts[1]
	sig := ed25519.Sign(key.PrivateKey, []byte(signingInput))
	jwtParts[2] = base64.RawURLEncoding.EncodeToString(sig)
	parts[0] = strings.Join(jwtParts, ".")
	invalidEncoded := strings.Join(parts, "~")

	_, err = Decode(invalidEncoded)
	if err == nil {
		t.Fatal("expected error for wrong JWT type")
	}
	if !strings.Contains(err.Error(), "unexpected JWT type") && !strings.Contains(err.Error(), "expected") {
		t.Errorf("error %q should mention unexpected type", err.Error())
	}
}
