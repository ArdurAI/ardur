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

func TestVerifyRejectsUnsupportedSPIFFEIDAssurance(t *testing.T) {
	for _, assurance := range []SPIFFEIDAssurance{
		"verified",
		"spire",
		"identity_provider_verified ",
		"IDENTITY_PROVIDER_VERIFIED",
	} {
		t.Run(string(assurance), func(t *testing.T) {
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

// TestVerifyAcceptsCredentialIssuedBeforeAssuranceLabel keeps the restore
// additive. Credentials issued while the label was absent from dev carry no
// value at all; rejecting them would turn a labelling improvement into a
// breaking format change. Absence is reported and read as unauthenticated.
func TestVerifyAcceptsCredentialIssuedBeforeAssuranceLabel(t *testing.T) {
	key := testSigningKey(t)
	cred, err := testBuilder(t).Build(key)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	cred.Claims.Identity.SPIFFEIDAssurance = ""

	encoded, err := Encode(cred, key)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}
	identityJSON, err := json.Marshal(cred.Claims.Identity)
	if err != nil {
		t.Fatalf("marshal identity claims: %v", err)
	}
	if strings.Contains(string(identityJSON), "spiffe_id_assurance") {
		t.Fatalf("an unlabelled identity layer must not serialize the field at all: %s", identityJSON)
	}

	result, err := Verify(encoded, key.PublicKey, &VerifyOptions{SkipStatusCheck: true})
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if !result.Valid {
		t.Fatalf("a credential predating the label must still verify, got errors: %v", result.Errors)
	}
	if got := strings.Join(result.Warnings, "; "); !strings.Contains(got, "spiffe_id_assurance") {
		t.Fatalf("verification warnings = %q, want the absent-label warning", got)
	}
	if result.Credential.Claims.Identity.SPIFFEIDProviderVerified() {
		t.Fatal("an absent assurance label was read as an authenticated workload identity")
	}
}
