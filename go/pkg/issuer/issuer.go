// Package issuer provides the credential issuance pipeline for VIBAP.
//
// The Issuer is the core orchestration component that wires all 5 security
// layer packages together into a single credential issuance flow:
//
//  1. Fetch workload identity (pkg/spiffe)
//  2. Verify supply chain provenance (pkg/provenance)
//  3. Compile and hash policy (pkg/policy)
//  4. Retrieve behavioral baseline (pkg/profiling)
//  5. Compute trust score (pkg/trust)
//  6. Build SD-JWT-VC credential (pkg/credential)
//  7. Log issuance to transparency log (pkg/transparency)
//
// Each provider is optional. The Issuer supports three compliance levels:
//   - Level 1 (Core): Layers 1 + 3 + 5 only (identity + intent + trust)
//   - Level 2 (Verified): All layers with external verification
//   - Level 3 (Enforced): All layers with kernel-level enforcement
package issuer

import (
	"context"
	"fmt"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/credential"
	"github.com/ArdurAI/ardur/go/pkg/policy"
	"github.com/ArdurAI/ardur/go/pkg/profiling"
	"github.com/ArdurAI/ardur/go/pkg/provenance"
	"github.com/ArdurAI/ardur/go/pkg/spiffe"
	"github.com/ArdurAI/ardur/go/pkg/transparency"
	"github.com/ArdurAI/ardur/go/pkg/trust"
)

// ComplianceLevel indicates the assurance tier of the issuance.
type ComplianceLevel string

const (
	LevelCore     ComplianceLevel = "core"     // L1: self-attested identity + intent + trust
	LevelVerified ComplianceLevel = "verified" // L2: SPIFFE + Sigstore + Cedar verified
	LevelEnforced ComplianceLevel = "enforced" // L3: Full stack with eBPF + network enforcement
)

// Issuer orchestrates credential issuance across all VIBAP components.
// Providers are optional; the Issuer adapts to what's available.
type Issuer struct {
	identity     spiffe.IdentityProvider
	provenance   provenance.ProvenanceVerifier
	policy       policy.PolicyEngine
	profiling    profiling.ProfileProvider
	trust        trust.ScoreAggregator
	transparency transparency.TransparencyLog
	signingKey   *credential.SigningKey

	issuerURI string
}

// Option configures an Issuer.
type Option func(*Issuer)

func WithIdentityProvider(p spiffe.IdentityProvider) Option {
	return func(i *Issuer) { i.identity = p }
}

func WithProvenanceVerifier(v provenance.ProvenanceVerifier) Option {
	return func(i *Issuer) { i.provenance = v }
}

func WithPolicyEngine(e policy.PolicyEngine) Option {
	return func(i *Issuer) { i.policy = e }
}

func WithProfileProvider(p profiling.ProfileProvider) Option {
	return func(i *Issuer) { i.profiling = p }
}

func WithTrustAggregator(a trust.ScoreAggregator) Option {
	return func(i *Issuer) { i.trust = a }
}

func WithTransparencyLog(l transparency.TransparencyLog) Option {
	return func(i *Issuer) { i.transparency = l }
}

// NewIssuer creates a new VIBAP credential issuer.
// signingKey and issuerURI are always required.
func NewIssuer(signingKey *credential.SigningKey, issuerURI string, opts ...Option) (*Issuer, error) {
	if signingKey == nil {
		return nil, fmt.Errorf("signing key is required")
	}
	if issuerURI == "" {
		return nil, fmt.Errorf("issuer URI is required")
	}

	iss := &Issuer{
		signingKey: signingKey,
		issuerURI:  issuerURI,
	}
	for _, opt := range opts {
		opt(iss)
	}
	return iss, nil
}

// MaxComplianceLevel returns the highest compliance level achievable
// with the currently configured providers. Note: the actual compliance
// level of an issued credential depends on what was verified at runtime
// — use IssueResult.ComplianceLevel for the ground-truth level.
func (iss *Issuer) MaxComplianceLevel() ComplianceLevel {
	if iss.identity != nil && iss.provenance != nil && iss.policy != nil &&
		iss.profiling != nil && iss.trust != nil {
		return LevelEnforced
	}
	if iss.identity != nil && iss.provenance != nil && iss.policy != nil {
		return LevelVerified
	}
	return LevelCore
}

// computeActualCompliance determines the compliance level based on
// what was actually verified during issuance, not just what providers
// are configured.
func computeActualCompliance(identityFromSPIRE bool, provenanceVerified bool, policyCompiled bool, profileRetrieved bool, trustScored bool) ComplianceLevel {
	if identityFromSPIRE && provenanceVerified && policyCompiled && profileRetrieved && trustScored {
		return LevelEnforced
	}
	if identityFromSPIRE && provenanceVerified && policyCompiled {
		return LevelVerified
	}
	return LevelCore
}

// IssueRequest contains all inputs for credential issuance.
// Not all fields are required — it depends on the compliance level.
type IssueRequest struct {
	// Layer 1: Identity (required for L2+; for L1, provide SPIFFEID/OwnerID directly)
	SPIFFEID   string // Direct SPIFFE ID (used if no IdentityProvider)
	OwnerID    string // Direct owner ID (used if no IdentityProvider)
	A2ACardRef string

	// Layer 2: Provenance (optional)
	ImageRef       string // OCI image reference for verification
	BundlePath     string // Sigstore bundle path (alternative to ImageRef)
	ArtifactDigest string // Image digest if known
	ModelHash      string
	VerifyOpts     provenance.VerifyOptions

	// Layer 3: Intent (required)
	SystemPrompt     string
	ToolManifest     string
	PolicyText       string // Cedar policy text
	PermittedActions []string

	// Layer 4: Baseline (optional, required for L3)
	Namespace string
	PodName   string
	Container string

	// Layer 5: Trust (required)
	AgentID string // Used for trust score lookup

	// Credential options
	TTL               time.Duration
	SelectiveDisclose []string // Layer names to selectively disclose
	StatusURI         string
	StatusIndex       int
	HolderKey         []byte // Ed25519 public key for key binding
}

// IssueResult contains the credential and metadata from issuance.
type IssueResult struct {
	Credential      *credential.VIBAPCredential
	Encoded         string
	ComplianceLevel ComplianceLevel
	LogIndex        *uint64 // Transparency log index, if logging enabled
}

// Issue executes the full credential issuance pipeline.
func (iss *Issuer) Issue(ctx context.Context, req IssueRequest) (*IssueResult, error) {
	var (
		agentID  string
		ownerID  string
		a2aRef   string
		prov     *provenance.ImageProvenance
		compiled *policy.CompiledPolicy
		profile  *profiling.ApplicationProfile
		score    *trust.TrustScore

		// Track what was actually verified for compliance level
		identityFromSPIRE  bool
		provenanceVerified bool
		policyCompiled     bool
		profileRetrieved   bool
		trustScored        bool
	)

	// --- Layer 1: Identity ---
	if iss.identity != nil {
		identity, err := iss.identity.FetchIdentity(ctx)
		if err != nil {
			return nil, fmt.Errorf("layer 1 (identity): %w", err)
		}
		agentID = identity.SPIFFEID
		ownerID = identity.OwnerID
		a2aRef = identity.A2ACardRef
		identityFromSPIRE = true
	} else {
		if req.SPIFFEID == "" || req.OwnerID == "" {
			return nil, fmt.Errorf("layer 1 (identity): SPIFFEID and OwnerID required when no IdentityProvider")
		}
		agentID = req.SPIFFEID
		ownerID = req.OwnerID
		a2aRef = req.A2ACardRef
	}

	// --- Layer 2: Provenance (optional) ---
	if iss.provenance != nil && (req.ImageRef != "" || req.BundlePath != "") {
		var err error
		if req.BundlePath != "" {
			prov, err = iss.provenance.VerifyBundle(ctx, req.BundlePath, req.ArtifactDigest, req.VerifyOpts)
		} else {
			prov, err = iss.provenance.VerifyImage(ctx, req.ImageRef, req.VerifyOpts)
		}
		if err != nil {
			return nil, fmt.Errorf("layer 2 (provenance): %w", err)
		}
		provenanceVerified = true
	}

	// --- Layer 3: Intent ---
	policyHash := ""
	agentChecksum := ""
	engineName := "cedar"

	if iss.policy != nil && req.PolicyText != "" {
		var err error
		compiled, err = iss.policy.Compile(ctx, req.PolicyText)
		if err != nil {
			return nil, fmt.Errorf("layer 3 (intent): %w", err)
		}
		policyHash = compiled.Hash
		agentChecksum = policy.ComputeAgentChecksum(req.SystemPrompt, req.ToolManifest, compiled.PolicyText)
		engineName = iss.policy.EngineName()
		policyCompiled = true
	} else {
		if req.PolicyText == "" {
			return nil, fmt.Errorf("layer 3 (intent): policy text is required")
		}
		policyHash = policy.ComputePolicyHash(req.PolicyText)
		agentChecksum = policy.ComputeAgentChecksum(req.SystemPrompt, req.ToolManifest, req.PolicyText)
	}

	// --- Layer 4: Baseline (optional) ---
	var profileHash string
	var endpoints, syscalls []string
	if iss.profiling != nil && req.PodName != "" {
		var err error
		profile, err = iss.profiling.GetProfile(ctx, req.Namespace, req.PodName, req.Container)
		if err != nil {
			return nil, fmt.Errorf("layer 4 (baseline): %w", err)
		}
		profileHash, err = profiling.ComputeProfileHash(profile)
		if err != nil {
			return nil, fmt.Errorf("layer 4 (baseline hash): %w", err)
		}
		endpoints = profile.Endpoints
		syscalls = profile.Syscalls
		profileRetrieved = true
	}

	// --- Layer 5: Trust ---
	trustAgentID := req.AgentID
	if trustAgentID == "" {
		trustAgentID = agentID
	}

	if iss.trust != nil {
		var err error
		score, err = iss.trust.GetScore(ctx, trustAgentID)
		if err != nil {
			return nil, fmt.Errorf("layer 5 (trust): %w", err)
		}
		trustScored = true
	} else {
		score = &trust.TrustScore{
			AgentID:              trustAgentID,
			StaticCapability:     0.5,
			HistoricalReputation: 0.5,
			RuntimeCompliance:    1.0,
			CompositeScore:       60.0,
			AuthorizationTier:    trust.TierLimited,
		}
	}

	// --- Build Credential ---
	b := credential.NewBuilder(iss.issuerURI, agentID).
		WithIdentity(agentID, ownerID, a2aRef).
		WithIntent(agentChecksum, engineName, policyHash, req.PermittedActions).
		WithTrust(
			score.StaticCapability,
			score.HistoricalReputation,
			score.CompositeScore,
			"",
			score.AuthorizationTier,
		)

	if req.TTL > 0 {
		b = b.WithTTL(req.TTL)
	}

	if prov != nil {
		b = b.WithProvenance(prov.ImageDigest, prov.SLSAProvenanceRef, req.ModelHash, prov.BuildPipeline, prov.SBOMRef)
	}

	if profileHash != "" {
		b = b.WithBaseline(profileHash, endpoints, syscalls, nil, nil, 3)
	}

	if req.StatusURI != "" {
		b = b.WithStatus(req.StatusURI, req.StatusIndex)
	}

	if len(req.HolderKey) > 0 {
		b = b.WithHolderKey(req.HolderKey)
	}

	for _, layer := range req.SelectiveDisclose {
		b = b.WithSelectiveDisclosure(layer)
	}

	cred, err := b.Build(iss.signingKey)
	if err != nil {
		return nil, fmt.Errorf("building credential: %w", err)
	}

	encoded, err := credential.Encode(cred, iss.signingKey)
	if err != nil {
		return nil, fmt.Errorf("encoding credential: %w", err)
	}

	result := &IssueResult{
		Credential:      cred,
		Encoded:         encoded,
		ComplianceLevel: computeActualCompliance(identityFromSPIRE, provenanceVerified, policyCompiled, profileRetrieved, trustScored),
	}

	// --- Transparency Log ---
	// Transparency logging is a security control, not optional telemetry.
	// Failures must be surfaced — silently issuing credentials without
	// an audit trail defeats the purpose of the transparency log.
	if iss.transparency != nil {
		entry, err := transparency.NewLogEntry(
			transparency.EntryCredentialIssued, trustAgentID,
			map[string]any{
				"compliance_level": string(result.ComplianceLevel),
				"tier":             score.AuthorizationTier,
				"composite_score":  score.CompositeScore,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("creating transparency log entry: %w", err)
		}
		idx, err := iss.transparency.Append(ctx, entry)
		if err != nil {
			return nil, fmt.Errorf("appending to transparency log: %w", err)
		}
		result.LogIndex = &idx
	}

	return result, nil
}
