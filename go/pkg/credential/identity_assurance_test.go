package credential

import (
	"encoding/json"
	"strings"
	"testing"
)

// The credential is the artifact a relying party actually receives. Without a
// signed assurance label, a correctly signed credential carrying a
// caller-configured spiffe_id is indistinguishable from one whose workload
// identity an identity provider authenticated — and the signature makes the
// weaker one read as the stronger. These tests pin that distinction.

func TestWithIdentityEmitsCallerProvidedAssurance(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	if got := cred.Claims.Identity.SPIFFEIDAssurance; got != SPIFFEIDAssuranceCallerProvided {
		t.Fatalf("spiffe_id_assurance = %q, want %q", got, SPIFFEIDAssuranceCallerProvided)
	}

	identityJSON, err := json.Marshal(cred.Claims.Identity)
	if err != nil {
		t.Fatalf("marshal identity claims: %v", err)
	}
	var identityFields map[string]any
	if err := json.Unmarshal(identityJSON, &identityFields); err != nil {
		t.Fatalf("decode identity claims: %v", err)
	}
	if got := identityFields["spiffe_id_assurance"]; got != string(SPIFFEIDAssuranceCallerProvided) {
		t.Fatalf("serialized spiffe_id_assurance = %v, want %q", got, SPIFFEIDAssuranceCallerProvided)
	}
}

// TestBuilderNeverEmitsProviderVerifiedAssurance guards the "unreachable until
// S3" property. No builder path authenticates a workload identity, so no
// builder path may claim one was authenticated. Binding issuance to SPIRE (S3,
// EPIC J #396 / EPIC K #397) is what earns the stronger label, and whoever does
// that work has to delete this test deliberately rather than flip the label by
// accident.
func TestBuilderNeverEmitsProviderVerifiedAssurance(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).
		WithIdentity(
			"spiffe://ardur.dev/ns/default/sa/agent/instance/test-001",
			"spiffe://ardur.dev/ns/default/sa/deployer",
			"https://agent.example.com/.well-known/agent.json",
		).
		Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if cred.Claims.Identity.SPIFFEIDProviderVerified() {
		t.Fatal("a builder path claimed provider-verified workload identity; no issuance path authenticates one yet")
	}
}

func TestSPIFFEIDProviderVerified(t *testing.T) {
	for _, tt := range []struct {
		name     string
		identity *IdentityClaims
		want     bool
	}{
		{name: "nil identity layer", identity: nil, want: false},
		{name: "absent label", identity: &IdentityClaims{}, want: false},
		{
			name:     "caller provided",
			identity: &IdentityClaims{SPIFFEIDAssurance: SPIFFEIDAssuranceCallerProvided},
			want:     false,
		},
		{
			name:     "unrecognised label",
			identity: &IdentityClaims{SPIFFEIDAssurance: "verified"},
			want:     false,
		},
		{
			name:     "near miss label",
			identity: &IdentityClaims{SPIFFEIDAssurance: "identity_provider_verified "},
			want:     false,
		},
		{
			name:     "provider verified",
			identity: &IdentityClaims{SPIFFEIDAssurance: SPIFFEIDAssuranceProviderVerified},
			want:     true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.identity.SPIFFEIDProviderVerified(); got != tt.want {
				t.Fatalf("SPIFFEIDProviderVerified() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestVerifyNeverAuthenticatesCallerProvidedIdentity is the verifier-side
// invariant from issue #405: a valid signature over an identity layer proves
// the issuer signed that spiffe_id, not that anyone authenticated the workload
// it names. A credential naming a privileged workload verifies successfully and
// still must not report provider-verified identity.
func TestVerifyNeverAuthenticatesCallerProvidedIdentity(t *testing.T) {
	const impersonated = "spiffe://ardur.dev/ns/kube-system/sa/cluster-admin/instance/attacker-001"

	key := testSigningKey(t)
	cred, err := NewBuilder("https://vibap.example.com", impersonated).
		WithIdentity(impersonated, "spiffe://ardur.dev/ns/default/sa/deployer", "").
		WithIntent("sha256:abc123def456", "cedar", "sha256:policy789", []string{"read:database"}).
		WithTrust(0.3, 0.9, 85.0, "", "").
		Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	result, err := Verify(encoded, key.PublicKey, &VerifyOptions{SkipStatusCheck: true})
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected a validly signed credential, got errors: %v", result.Errors)
	}
	if result.Credential.Claims.Identity.SPIFFEID != impersonated {
		t.Fatalf("spiffe_id = %q, want %q", result.Credential.Claims.Identity.SPIFFEID, impersonated)
	}
	if result.Credential.Claims.Identity.SPIFFEIDProviderVerified() {
		t.Fatal("a valid signature over a caller-provided spiffe_id was reported as an authenticated workload identity")
	}
	if got := result.Credential.Claims.Identity.SPIFFEIDAssurance; got != SPIFFEIDAssuranceCallerProvided {
		t.Fatalf("spiffe_id_assurance = %q, want %q", got, SPIFFEIDAssuranceCallerProvided)
	}
}

// TestVerifyRejectsUnsupportedSPIFFEIDAssurance covers the missing value as
// well as invented ones. ADR-024 fails closed on a missing owner_id_assurance
// for the reason that applies identically here: a credential must not assert a
// workload identity with no corresponding proof path, and a verifier that
// tolerated absence would read spiffe_id as though it meant something it has no
// basis for. Nothing in the repository issues an unlabelled credential, no
// committed fixture contains one, and the default credential lifetime is an
// hour, so failing closed costs no compatibility.
func TestVerifyRejectsUnsupportedSPIFFEIDAssurance(t *testing.T) {
	for _, assurance := range []SPIFFEIDAssurance{
		"",
		"verified",
		"spire",
		"identity_provider_verified ",
		"IDENTITY_PROVIDER_VERIFIED",
	} {
		t.Run("assurance="+string(assurance), func(t *testing.T) {
			key := testSigningKey(t)
			cred, err := testBuilder(t).Build(key)
			if err != nil {
				t.Fatalf("Build() error: %v", err)
			}
			cred.Claims.Identity.SPIFFEIDAssurance = assurance

			encoded, err := Encode(cred, key)
			if err != nil {
				t.Fatalf("Encode() error: %v", err)
			}
			result, err := Verify(encoded, key.PublicKey, &VerifyOptions{SkipStatusCheck: true})
			if err != nil {
				t.Fatalf("Verify() error: %v", err)
			}
			if result.Valid {
				t.Fatalf("unsupported spiffe_id_assurance %q was accepted", assurance)
			}
			if got := strings.Join(result.Errors, "; "); !strings.Contains(got, "spiffe_id_assurance") {
				t.Fatalf("verification errors = %q, want a spiffe_id_assurance failure", got)
			}
		})
	}
}

// TestBothIdentityAssurancesFailClosedAlike pins the symmetry. Two assurance
// fields sit side by side in the same layer; a verifier author who reads one as
// strict will assume the other is too, so they must not diverge.
func TestBothIdentityAssurancesFailClosedAlike(t *testing.T) {
	for _, tt := range []struct {
		name  string
		strip func(*IdentityClaims)
		want  string
	}{
		{
			name:  "missing owner_id_assurance",
			strip: func(i *IdentityClaims) { i.OwnerIDAssurance = "" },
			want:  "owner_id_assurance",
		},
		{
			name:  "missing spiffe_id_assurance",
			strip: func(i *IdentityClaims) { i.SPIFFEIDAssurance = "" },
			want:  "spiffe_id_assurance",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key := testSigningKey(t)
			cred, err := testBuilder(t).Build(key)
			if err != nil {
				t.Fatalf("Build() error: %v", err)
			}
			tt.strip(cred.Claims.Identity)

			encoded, err := Encode(cred, key)
			if err != nil {
				t.Fatalf("Encode() error: %v", err)
			}
			result, err := Verify(encoded, key.PublicKey, &VerifyOptions{SkipStatusCheck: true})
			if err != nil {
				t.Fatalf("Verify() error: %v", err)
			}
			if result.Valid {
				t.Fatal("a missing assurance value was accepted")
			}
			if got := strings.Join(result.Errors, "; "); !strings.Contains(got, tt.want) {
				t.Fatalf("verification errors = %q, want a %s failure", got, tt.want)
			}
		})
	}
}
