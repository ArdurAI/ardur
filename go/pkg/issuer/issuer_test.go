package issuer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/credential"
	"github.com/ArdurAI/ardur/go/pkg/policy"
	"github.com/ArdurAI/ardur/go/pkg/profiling"
	"github.com/ArdurAI/ardur/go/pkg/provenance"
	"github.com/ArdurAI/ardur/go/pkg/spiffe"
	"github.com/ArdurAI/ardur/go/pkg/transparency"
	"github.com/ArdurAI/ardur/go/pkg/trust"
)

func testSigningKey(t *testing.T) *credential.SigningKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating signing key: %v", err)
	}
	return &credential.SigningKey{
		PrivateKey: priv,
		PublicKey:  pub,
		KeyID:      "test-key-001",
	}
}

func testHolderKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating holder key: %v", err)
	}
	return pub, priv
}

func defaultMockIdentity() *spiffe.MockIdentityProvider {
	return spiffe.NewMockIdentityProvider(spiffe.MockIdentityProviderOptions{
		SPIFFEID:    "spiffe://ardur.dev/agent/test/instance-001",
		OwnerID:     "spiffe://ardur.dev/user/deployer",
		TrustDomain: "ardur.dev",
		A2ACardRef:  "https://agent.example.com/.well-known/agent.json",
	})
}

func defaultMockProvenance() *provenance.MockProvenanceVerifier {
	return provenance.NewMockProvenanceVerifier()
}

func defaultMockPolicy() *policy.MockPolicyEngine {
	return policy.NewMockPolicyEngine(policy.WithMockEngineName("cedar"))
}

func defaultMockProfiling() *profiling.MockProfileProvider {
	m := profiling.NewMockProfileProvider()
	m.AddProfile(&profiling.ApplicationProfile{
		Name:      "test-pod",
		Namespace: "default",
		Container: "agent",
		Endpoints: []string{"10.0.0.1:443", "10.0.0.2:8080"},
		Syscalls:  []string{"read", "write", "openat", "connect"},
	})
	return m
}

func defaultMockTrust() *trust.MockAggregator {
	m := trust.NewMockAggregator()
	m.SetScore(&trust.TrustScore{
		AgentID:              "spiffe://ardur.dev/agent/test/instance-001",
		StaticCapability:     0.8,
		HistoricalReputation: 0.9,
		RuntimeCompliance:    1.0,
		CompositeScore:       88.0,
		AuthorizationTier:    trust.TierFull,
	})
	return m
}

func defaultTransparencyLog(t *testing.T) *transparency.InMemoryLog {
	t.Helper()
	return transparency.NewInMemoryLog()
}

func minimalRequest() IssueRequest {
	return IssueRequest{
		SPIFFEID:         "spiffe://ardur.dev/agent/test/instance-001",
		OwnerID:          "spiffe://ardur.dev/user/deployer",
		PolicyText:       `permit(principal, action == Action::"read", resource);`,
		PermittedActions: []string{"read:database"},
		AgentID:          "spiffe://ardur.dev/agent/test/instance-001",
		SystemPrompt:     "You are a test agent",
		ToolManifest:     `{"tools": ["read"]}`,
	}
}

func fullRequest() IssueRequest {
	holderPub, _ := testHolderKeyRaw()
	return IssueRequest{
		ImageRef:          "ghcr.io/ardur/agent:latest@sha256:abc123",
		ModelHash:         "e3b0c44298fc1c149afbf4c8996fb924",
		PolicyText:        `permit(principal, action == Action::"read", resource);`,
		PermittedActions:  []string{"read:database", "call:api/v1/*"},
		SystemPrompt:      "You are a production agent",
		ToolManifest:      `{"tools": ["read", "api_call"]}`,
		Namespace:         "default",
		PodName:           "test-pod",
		Container:         "agent",
		TTL:               30 * time.Minute,
		StatusURI:         "https://vibap.ardur.dev/status/v1",
		StatusIndex:       42,
		HolderKey:         holderPub,
		SelectiveDisclose: []string{"provenance", "baseline"},
	}
}

func testHolderKeyRaw() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return pub, priv
}

// --- Constructor Tests ---

func TestNewIssuer_RequiresSigningKey(t *testing.T) {
	_, err := NewIssuer(nil, "https://vibap.example.com")
	if err == nil {
		t.Fatal("expected error for nil signing key")
	}
	if !strings.Contains(err.Error(), "signing key") {
		t.Errorf("error should mention signing key: %v", err)
	}
}

func TestNewIssuer_RequiresIssuerURI(t *testing.T) {
	key := testSigningKey(t)
	_, err := NewIssuer(key, "")
	if err == nil {
		t.Fatal("expected error for empty issuer URI")
	}
	if !strings.Contains(err.Error(), "issuer URI") {
		t.Errorf("error should mention issuer URI: %v", err)
	}
}

func TestNewIssuer_MinimalConfig(t *testing.T) {
	key := testSigningKey(t)
	iss, err := NewIssuer(key, "https://vibap.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if iss.signingKey != key {
		t.Error("signing key not set")
	}
	if iss.issuerURI != "https://vibap.example.com" {
		t.Errorf("issuer URI = %q, want %q", iss.issuerURI, "https://vibap.example.com")
	}
}

func TestNewIssuer_WithAllOptions(t *testing.T) {
	key := testSigningKey(t)
	idp := defaultMockIdentity()
	prov := defaultMockProvenance()
	pol := defaultMockPolicy()
	prof := defaultMockProfiling()
	ta := defaultMockTrust()
	tl := defaultTransparencyLog(t)
	defer tl.Close()

	iss, err := NewIssuer(key, "https://vibap.example.com",
		WithIdentityProvider(idp),
		WithProvenanceVerifier(prov),
		WithPolicyEngine(pol),
		WithProfileProvider(prof),
		WithTrustAggregator(ta),
		WithTransparencyLog(tl),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if iss.identity == nil || iss.provenance == nil || iss.policy == nil ||
		iss.profiling == nil || iss.trust == nil || iss.transparency == nil {
		t.Error("not all providers were set")
	}
}

// --- MaxComplianceLevel Tests ---

func TestMaxComplianceLevel_Core(t *testing.T) {
	key := testSigningKey(t)
	iss, _ := NewIssuer(key, "https://vibap.example.com")
	if got := iss.MaxComplianceLevel(); got != LevelCore {
		t.Errorf("MaxComplianceLevel = %q, want %q", got, LevelCore)
	}
}

func TestMaxComplianceLevel_Verified(t *testing.T) {
	key := testSigningKey(t)
	iss, _ := NewIssuer(key, "https://vibap.example.com",
		WithIdentityProvider(defaultMockIdentity()),
		WithProvenanceVerifier(defaultMockProvenance()),
		WithPolicyEngine(defaultMockPolicy()),
	)
	if got := iss.MaxComplianceLevel(); got != LevelVerified {
		t.Errorf("MaxComplianceLevel = %q, want %q", got, LevelVerified)
	}
}

func TestMaxComplianceLevel_Enforced(t *testing.T) {
	key := testSigningKey(t)
	iss, _ := NewIssuer(key, "https://vibap.example.com",
		WithIdentityProvider(defaultMockIdentity()),
		WithProvenanceVerifier(defaultMockProvenance()),
		WithPolicyEngine(defaultMockPolicy()),
		WithProfileProvider(defaultMockProfiling()),
		WithTrustAggregator(defaultMockTrust()),
	)
	if got := iss.MaxComplianceLevel(); got != LevelEnforced {
		t.Errorf("MaxComplianceLevel = %q, want %q", got, LevelEnforced)
	}
}

// --- Issue Tests: Core Level ---

func TestIssue_CoreLevel_MinimalRequest(t *testing.T) {
	key := testSigningKey(t)
	iss, err := NewIssuer(key, "https://vibap.example.com")
	if err != nil {
		t.Fatalf("creating issuer: %v", err)
	}

	ctx := context.Background()
	result, err := iss.Issue(ctx, minimalRequest())
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if result.ComplianceLevel != LevelCore {
		t.Errorf("ComplianceLevel = %q, want %q", result.ComplianceLevel, LevelCore)
	}
	if result.Credential == nil {
		t.Fatal("credential is nil")
	}
	if result.Encoded == "" {
		t.Fatal("encoded credential is empty")
	}
	if result.LogIndex != nil {
		t.Error("log index should be nil without transparency log")
	}

	cred := result.Credential
	if cred.Claims.Identity == nil {
		t.Fatal("missing Layer 1 (Identity)")
	}
	if cred.Claims.Intent == nil {
		t.Fatal("missing Layer 3 (Intent)")
	}
	if cred.Claims.Trust == nil {
		t.Fatal("missing Layer 5 (Trust)")
	}
	if cred.Claims.Trust.AuthorizationTier != trust.TierLimited {
		t.Errorf("default tier = %q, want %q (core defaults to score 60)", cred.Claims.Trust.AuthorizationTier, trust.TierLimited)
	}
}

func TestIssue_CoreLevel_RequiresIdentity(t *testing.T) {
	key := testSigningKey(t)
	iss, _ := NewIssuer(key, "https://vibap.example.com")

	req := minimalRequest()
	req.SPIFFEID = ""
	req.OwnerID = ""

	_, err := iss.Issue(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing identity")
	}
	if !strings.Contains(err.Error(), "identity") {
		t.Errorf("error should mention identity: %v", err)
	}
}

func TestIssue_CoreLevel_RequiresPolicy(t *testing.T) {
	key := testSigningKey(t)
	iss, _ := NewIssuer(key, "https://vibap.example.com")

	req := minimalRequest()
	req.PolicyText = ""

	_, err := iss.Issue(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing policy")
	}
	if !strings.Contains(err.Error(), "policy text") {
		t.Errorf("error should mention policy: %v", err)
	}
}

// --- Issue Tests: Verified Level ---

func TestIssue_VerifiedLevel_WithProviders(t *testing.T) {
	key := testSigningKey(t)
	iss, _ := NewIssuer(key, "https://vibap.example.com",
		WithIdentityProvider(defaultMockIdentity()),
		WithProvenanceVerifier(defaultMockProvenance()),
		WithPolicyEngine(defaultMockPolicy()),
		WithTrustAggregator(defaultMockTrust()),
	)

	req := IssueRequest{
		ImageRef:         "ghcr.io/ardur/agent:latest",
		PolicyText:       `permit(principal, action == Action::"read", resource);`,
		PermittedActions: []string{"read:database"},
		SystemPrompt:     "You are a test agent",
		ToolManifest:     `{"tools": ["read"]}`,
	}

	result, err := iss.Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if result.ComplianceLevel != LevelVerified {
		t.Errorf("ComplianceLevel = %q, want %q", result.ComplianceLevel, LevelVerified)
	}

	cred := result.Credential
	if cred.Claims.Identity.SPIFFEID == "" {
		t.Error("identity should come from SPIRE mock")
	}
	if cred.Claims.Provenance == nil {
		t.Error("provenance should be set when image is verified")
	}
}

// --- Issue Tests: Enforced Level ---

func TestIssue_EnforcedLevel_FullStack(t *testing.T) {
	key := testSigningKey(t)
	tl := defaultTransparencyLog(t)
	defer tl.Close()

	iss, _ := NewIssuer(key, "https://vibap.example.com",
		WithIdentityProvider(defaultMockIdentity()),
		WithProvenanceVerifier(defaultMockProvenance()),
		WithPolicyEngine(defaultMockPolicy()),
		WithProfileProvider(defaultMockProfiling()),
		WithTrustAggregator(defaultMockTrust()),
		WithTransparencyLog(tl),
	)

	req := fullRequest()
	result, err := iss.Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if result.ComplianceLevel != LevelEnforced {
		t.Errorf("ComplianceLevel = %q, want %q", result.ComplianceLevel, LevelEnforced)
	}

	cred := result.Credential
	if cred.Claims.Identity == nil {
		t.Fatal("missing Layer 1")
	}
	if cred.Claims.Intent == nil {
		t.Fatal("missing Layer 3")
	}
	if cred.Claims.Trust == nil {
		t.Fatal("missing Layer 5")
	}
	if cred.Claims.Trust.AuthorizationTier != trust.TierFull {
		t.Errorf("tier = %q, want %q", cred.Claims.Trust.AuthorizationTier, trust.TierFull)
	}

	if len(cred.Disclosures) != 2 {
		t.Errorf("expected 2 selective disclosures (provenance + baseline), got %d", len(cred.Disclosures))
	}

	if result.LogIndex == nil {
		t.Error("log index should be set with transparency log")
	}

	entry, err := tl.Get(context.Background(), *result.LogIndex)
	if err != nil {
		t.Fatalf("fetching log entry: %v", err)
	}
	if entry.Type != transparency.EntryCredentialIssued {
		t.Errorf("log entry type = %q, want %q", entry.Type, transparency.EntryCredentialIssued)
	}
}

// --- Issue Tests: Credential Validation ---

func TestIssue_CredentialIsVerifiable(t *testing.T) {
	key := testSigningKey(t)
	iss, _ := NewIssuer(key, "https://vibap.example.com")

	result, err := iss.Issue(context.Background(), minimalRequest())
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	vr, err := credential.Verify(result.Encoded, key.PublicKey, &credential.VerifyOptions{
		SkipStatusCheck: true,
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !vr.Valid {
		t.Errorf("credential should be valid, errors: %v", vr.Errors)
	}
}

func TestIssue_WithHolderKey(t *testing.T) {
	key := testSigningKey(t)
	holderPub, _ := testHolderKey(t)
	iss, _ := NewIssuer(key, "https://vibap.example.com")

	req := minimalRequest()
	req.HolderKey = holderPub

	result, err := iss.Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if result.Credential.Claims.Confirmation == nil {
		t.Error("credential should have cnf claim when holder key is provided")
	}
}

func TestIssue_WithStatusReference(t *testing.T) {
	key := testSigningKey(t)
	iss, _ := NewIssuer(key, "https://vibap.example.com")

	req := minimalRequest()
	req.StatusURI = "https://vibap.ardur.dev/status/v1"
	req.StatusIndex = 42

	result, err := iss.Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if result.Credential.Claims.Status == nil {
		t.Fatal("status should be set")
	}
	if result.Credential.Claims.Status.StatusList.URI != "https://vibap.ardur.dev/status/v1" {
		t.Error("status URI mismatch")
	}
	if result.Credential.Claims.Status.StatusList.Index != 42 {
		t.Error("status index mismatch")
	}
}

func TestIssue_WithCustomTTL(t *testing.T) {
	key := testSigningKey(t)
	iss, _ := NewIssuer(key, "https://vibap.example.com")

	req := minimalRequest()
	req.TTL = 15 * time.Minute

	result, err := iss.Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	ttl := time.Duration(result.Credential.Claims.ExpiresAt-result.Credential.Claims.IssuedAt) * time.Second
	if ttl < 14*time.Minute || ttl > 16*time.Minute {
		t.Errorf("TTL = %v, expected ~15m", ttl)
	}
}

// --- Issue Tests: Provider Failures ---

func TestIssue_IdentityProviderFailure(t *testing.T) {
	key := testSigningKey(t)
	mock := defaultMockIdentity()
	mock.Close()

	iss, _ := NewIssuer(key, "https://vibap.example.com",
		WithIdentityProvider(mock),
	)

	_, err := iss.Issue(context.Background(), minimalRequest())
	if err == nil {
		t.Fatal("expected error from closed identity provider")
	}
	if !strings.Contains(err.Error(), "layer 1") {
		t.Errorf("error should reference layer 1: %v", err)
	}
}

func TestIssue_ProvenanceVerifierFailure(t *testing.T) {
	key := testSigningKey(t)
	mock := defaultMockProvenance()
	mock.VerifyError = fmt.Errorf("signature verification failed")

	iss, _ := NewIssuer(key, "https://vibap.example.com",
		WithProvenanceVerifier(mock),
	)

	req := minimalRequest()
	req.ImageRef = "ghcr.io/ardur/agent:latest"

	_, err := iss.Issue(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from provenance verifier")
	}
	if !strings.Contains(err.Error(), "layer 2") {
		t.Errorf("error should reference layer 2: %v", err)
	}
}

func TestIssue_PolicyEngineFailure(t *testing.T) {
	key := testSigningKey(t)
	mock := policy.NewMockPolicyEngine(
		policy.WithMockCompileError(fmt.Errorf("invalid Cedar syntax")),
	)

	iss, _ := NewIssuer(key, "https://vibap.example.com",
		WithPolicyEngine(mock),
	)

	_, err := iss.Issue(context.Background(), minimalRequest())
	if err == nil {
		t.Fatal("expected error from policy engine")
	}
	if !strings.Contains(err.Error(), "layer 3") {
		t.Errorf("error should reference layer 3: %v", err)
	}
}

func TestIssue_ProfilingProviderFailure(t *testing.T) {
	key := testSigningKey(t)
	mock := profiling.NewMockProfileProvider()
	mock.SetGetError(fmt.Errorf("profile not available"))

	iss, _ := NewIssuer(key, "https://vibap.example.com",
		WithProfileProvider(mock),
	)

	req := minimalRequest()
	req.PodName = "nonexistent-pod"
	req.Namespace = "default"
	req.Container = "agent"

	_, err := iss.Issue(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from profiling provider")
	}
	if !strings.Contains(err.Error(), "layer 4") {
		t.Errorf("error should reference layer 4: %v", err)
	}
}

func TestIssue_TrustAggregatorFailure(t *testing.T) {
	key := testSigningKey(t)
	mock := trust.NewMockAggregator()

	iss, _ := NewIssuer(key, "https://vibap.example.com",
		WithTrustAggregator(mock),
	)

	_, err := iss.Issue(context.Background(), minimalRequest())
	if err == nil {
		t.Fatal("expected error from trust aggregator (agent not registered)")
	}
	if !strings.Contains(err.Error(), "layer 5") {
		t.Errorf("error should reference layer 5: %v", err)
	}
}

// --- Issue Tests: Bundle Path ---

func TestIssue_ProvenanceViaBundle(t *testing.T) {
	key := testSigningKey(t)
	mock := defaultMockProvenance()

	iss, _ := NewIssuer(key, "https://vibap.example.com",
		WithProvenanceVerifier(mock),
	)

	req := minimalRequest()
	req.BundlePath = "/path/to/bundle.sigstore.json"
	req.ArtifactDigest = "sha256:abc123"

	result, err := iss.Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if result.Credential.Claims.Provenance == nil {
		t.Error("provenance should be set when bundle is verified")
	}
	if mock.CallCount != 1 {
		t.Errorf("verifier called %d times, want 1", mock.CallCount)
	}
}

// --- Issue Tests: Selective Disclosure ---

func TestIssue_SelectiveDisclosure_ProvenanceOnly(t *testing.T) {
	key := testSigningKey(t)
	iss, _ := NewIssuer(key, "https://vibap.example.com",
		WithProvenanceVerifier(defaultMockProvenance()),
	)

	req := minimalRequest()
	req.ImageRef = "ghcr.io/ardur/agent:latest"
	req.SelectiveDisclose = []string{"provenance"}

	result, err := iss.Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if len(result.Credential.Disclosures) != 1 {
		t.Errorf("expected 1 disclosure, got %d", len(result.Credential.Disclosures))
	}
	if result.Credential.Claims.Provenance != nil {
		t.Error("provenance should NOT be in claims when selectively disclosed")
	}
}

// --- Issue Tests: Agent ID Fallback ---

func TestIssue_AgentIDFallbackToSPIFFEID(t *testing.T) {
	key := testSigningKey(t)
	ta := defaultMockTrust()

	iss, _ := NewIssuer(key, "https://vibap.example.com",
		WithTrustAggregator(ta),
	)

	req := minimalRequest()
	req.AgentID = ""

	result, err := iss.Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if result.Credential.Claims.Trust.CompositeScore != 88.0 {
		t.Errorf("score = %f, want 88.0 (should use SPIFFE ID as agent ID fallback)", result.Credential.Claims.Trust.CompositeScore)
	}
}

// --- Issue Tests: Compliance Level Computation ---

func TestComputeActualCompliance(t *testing.T) {
	tests := []struct {
		name                                         string
		identity, provenance, policy, profile, trust bool
		want                                         ComplianceLevel
	}{
		{"all true", true, true, true, true, true, LevelEnforced},
		{"missing profile", true, true, true, false, true, LevelVerified},
		{"missing trust", true, true, true, true, false, LevelVerified},
		{"identity+provenance+policy", true, true, true, false, false, LevelVerified},
		{"identity+policy only", true, false, true, false, false, LevelCore},
		{"nothing verified", false, false, false, false, false, LevelCore},
		{"identity only", true, false, false, false, false, LevelCore},
		{"provenance+policy only", false, true, true, false, false, LevelCore},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeActualCompliance(tt.identity, tt.provenance, tt.policy, tt.profile, tt.trust)
			if got != tt.want {
				t.Errorf("computeActualCompliance(%v,%v,%v,%v,%v) = %q, want %q",
					tt.identity, tt.provenance, tt.policy, tt.profile, tt.trust, got, tt.want)
			}
		})
	}
}

// --- Issue Tests: Provenance Skipped Without ImageRef ---

func TestIssue_ProvenanceSkippedWithoutImageRef(t *testing.T) {
	key := testSigningKey(t)
	mock := defaultMockProvenance()

	iss, _ := NewIssuer(key, "https://vibap.example.com",
		WithProvenanceVerifier(mock),
	)

	result, err := iss.Issue(context.Background(), minimalRequest())
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if mock.CallCount != 0 {
		t.Error("provenance verifier should not be called without ImageRef or BundlePath")
	}
	if result.Credential.Claims.Provenance != nil {
		t.Error("provenance claims should be nil when not verified")
	}
}

// --- Issue Tests: Profiling Skipped Without PodName ---

func TestIssue_ProfilingSkippedWithoutPodName(t *testing.T) {
	key := testSigningKey(t)
	mock := defaultMockProfiling()

	iss, _ := NewIssuer(key, "https://vibap.example.com",
		WithProfileProvider(mock),
	)

	result, err := iss.Issue(context.Background(), minimalRequest())
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if mock.GetCount() != 0 {
		t.Error("profile provider should not be called without PodName")
	}
	if result.Credential.Claims.Baseline != nil {
		t.Error("baseline claims should be nil when profiling is skipped")
	}
}

// --- Issue Tests: Transparency Log Failure ---

func TestIssue_TransparencyLogFailure(t *testing.T) {
	key := testSigningKey(t)
	tl := defaultTransparencyLog(t)
	tl.Close()

	iss, _ := NewIssuer(key, "https://vibap.example.com",
		WithTransparencyLog(tl),
	)

	_, err := iss.Issue(context.Background(), minimalRequest())
	if err == nil {
		t.Fatal("expected error when transparency log is closed")
	}
	if !strings.Contains(err.Error(), "transparency log") {
		t.Errorf("error should mention transparency log: %v", err)
	}
}

// --- Roundtrip Test: Issue → Encode → Decode → Verify ---

func TestIssue_FullRoundtrip(t *testing.T) {
	key := testSigningKey(t)
	tl := defaultTransparencyLog(t)
	defer tl.Close()

	iss, _ := NewIssuer(key, "https://vibap.example.com",
		WithIdentityProvider(defaultMockIdentity()),
		WithProvenanceVerifier(defaultMockProvenance()),
		WithPolicyEngine(defaultMockPolicy()),
		WithProfileProvider(defaultMockProfiling()),
		WithTrustAggregator(defaultMockTrust()),
		WithTransparencyLog(tl),
	)

	req := fullRequest()
	req.HolderKey = nil // KB-JWT is created at presentation time, not issuance
	result, err := iss.Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	decoded, err := credential.Decode(result.Encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.Claims.VerifiableCredentialType != credential.VIBAPTypeURI {
		t.Errorf("vct = %q, want %q", decoded.Claims.VerifiableCredentialType, credential.VIBAPTypeURI)
	}
	if decoded.Claims.Issuer != "https://vibap.example.com" {
		t.Errorf("iss = %q", decoded.Claims.Issuer)
	}
	if decoded.Claims.Identity.SPIFFEID != "spiffe://ardur.dev/agent/test/instance-001" {
		t.Errorf("spiffe_id = %q", decoded.Claims.Identity.SPIFFEID)
	}

	vr, err := credential.Verify(result.Encoded, key.PublicKey, &credential.VerifyOptions{
		SkipStatusCheck: true,
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !vr.Valid {
		t.Errorf("credential invalid after roundtrip: %v", vr.Errors)
	}

	cp, err := tl.GetCheckpoint(context.Background())
	if err != nil {
		t.Fatalf("GetCheckpoint: %v", err)
	}
	if cp.TreeSize < 1 {
		t.Error("transparency log should have at least 1 entry")
	}
}
