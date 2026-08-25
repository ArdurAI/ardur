package credential

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Builder constructs a VIBAPCredential using the builder pattern.
// Each .With*() method sets the claims for one credential layer.
// Call .Build() to sign and produce the final credential.
//
// Usage:
//
//	cred, err := credential.NewBuilder("https://vibap.example.com", "spiffe://ardur.dev/ns/default/sa/agent/instance/abc123").
//	    WithIdentity("spiffe://ardur.dev/ns/default/sa/agent/instance/abc123", "spiffe://ardur.dev/ns/default/sa/deployer", "").
//	    WithProvenance("sha256:deadbeef...", "", "", "", "").
//	    WithIntent("abc123hash", "cedar", "policysha256", []string{"read:db"}).
//	    WithTrust(0.3, 0.9, 85.0, "", TierFull).
//	    WithSelectiveDisclosure("provenance", "baseline").
//	    Build(signingKey)
type Builder struct {
	issuer  string
	subject string
	ttl     time.Duration

	identity   *IdentityClaims
	provenance *ProvenanceClaims
	intent     *IntentClaims
	baseline   *BaselineClaims
	trust      *TrustClaims

	// Layers to make selectively disclosable (by layer name)
	sdLayers map[string]bool

	// Status list reference for revocation
	status *StatusReference

	// Holder public key for key binding
	holderKey ed25519.PublicKey

	err error // Captures first error during building
}

// NewBuilder creates a new credential builder.
// issuer is the VIBAP Authority identifier.
// subject is always required. It is a SPIFFE ID when Layer 1 is present, or a
// non-SPIFFE agent identifier when a Core credential omits optional Layer 1.
func NewBuilder(issuer, subject string) *Builder {
	b := &Builder{
		issuer:   issuer,
		subject:  subject,
		ttl:      DefaultTTL,
		sdLayers: make(map[string]bool),
	}
	if issuer == "" {
		b.err = fmt.Errorf("issuer is required")
	}
	if b.err == nil && subject == "" {
		b.err = fmt.Errorf("subject is required")
	}
	return b
}

// WithTTL sets the credential time-to-live. Default is 1 hour.
func (b *Builder) WithTTL(ttl time.Duration) *Builder {
	if ttl <= 0 {
		b.err = fmt.Errorf("TTL must be positive, got %v", ttl)
		return b
	}
	b.ttl = ttl
	return b
}

// WithIdentity sets Layer 1 (Identity) claims.
// spiffeID and ownerID are required; a2aCardRef is optional. ownerID is
// configured attribution and is always emitted with self-asserted assurance.
//
// The SPIFFE ID is emitted as caller-provided. This builder has no path that
// emits SPIFFEIDAssuranceProviderVerified, because no issuance path in this
// repository authenticates a workload identity yet; binding issuance to SPIRE
// (S3) is what will earn that label.
func (b *Builder) WithIdentity(spiffeID, ownerID, a2aCardRef string) *Builder {
	if spiffeID == "" {
		b.err = fmt.Errorf("identity: spiffe_id is required")
		return b
	}
	if ownerID == "" {
		b.err = fmt.Errorf("identity: owner_id is required")
		return b
	}
	b.identity = &IdentityClaims{
		SPIFFEID:          spiffeID,
		SPIFFEIDAssurance: SPIFFEIDAssuranceCallerProvided,
		OwnerID:           ownerID,
		OwnerIDAssurance:  OwnerIDAssuranceSelfAsserted,
		A2ACardRef:        a2aCardRef,
	}
	return b
}

// WithProvenance sets Layer 2 (Provenance) claims.
// imageDigest is required; other fields are optional.
func (b *Builder) WithProvenance(imageDigest, slsaRef, modelHash, buildPipeline, sbomRef string) *Builder {
	if imageDigest == "" {
		b.err = fmt.Errorf("provenance: image_digest is required")
		return b
	}
	b.provenance = &ProvenanceClaims{
		ImageDigest:       imageDigest,
		SLSAProvenanceRef: slsaRef,
		ModelHash:         modelHash,
		BuildPipeline:     buildPipeline,
		SBOMRef:           sbomRef,
	}
	return b
}

// WithIntent sets Layer 3 (Intent Binding) claims.
// All fields except permittedActions are required.
func (b *Builder) WithIntent(agentChecksum, policyEngine, policyHash string, permittedActions []string) *Builder {
	if agentChecksum == "" {
		b.err = fmt.Errorf("intent: agent_checksum is required")
		return b
	}
	if policyEngine == "" {
		b.err = fmt.Errorf("intent: policy_engine is required")
		return b
	}
	if policyEngine != "cedar" && policyEngine != "rego" {
		b.err = fmt.Errorf("intent: policy_engine must be 'cedar' or 'rego', got %q", policyEngine)
		return b
	}
	if policyHash == "" {
		b.err = fmt.Errorf("intent: policy_hash is required")
		return b
	}
	b.intent = &IntentClaims{
		AgentChecksum:    agentChecksum,
		PolicyEngine:     policyEngine,
		PolicyHash:       policyHash,
		PermittedActions: permittedActions,
	}
	return b
}

// WithBaseline sets Layer 4 (Behavioral Baseline) claims.
// profileHash is required; other fields are optional.
func (b *Builder) WithBaseline(profileHash string, endpoints, syscalls []string, toolBounds map[string]FrequencyBound, filePaths []string, maxDepth int) *Builder {
	if profileHash == "" {
		b.err = fmt.Errorf("baseline: application_profile_hash is required")
		return b
	}
	if maxDepth < 0 {
		b.err = fmt.Errorf("baseline: max_delegation_depth must be non-negative, got %d", maxDepth)
		return b
	}
	b.baseline = &BaselineClaims{
		ApplicationProfileHash: profileHash,
		ExpectedEndpoints:      endpoints,
		ExpectedSyscalls:       syscalls,
		ToolFrequencyBounds:    toolBounds,
		FileAccessPaths:        filePaths,
		MaxDelegationDepth:     maxDepth,
	}
	return b
}

// WithTrust sets Layer 5 (Trust Score) claims.
// staticScore and historicalRep must be in [0.0, 1.0].
// compositeScore must be in [0, 100].
func (b *Builder) WithTrust(staticScore, historicalRep, compositeScore float64, endpoint string, tier string) *Builder {
	if staticScore < 0 || staticScore > 1.0 {
		b.err = fmt.Errorf("trust: static_capability_score must be in [0.0, 1.0], got %f", staticScore)
		return b
	}
	if historicalRep < 0 || historicalRep > 1.0 {
		b.err = fmt.Errorf("trust: historical_reputation must be in [0.0, 1.0], got %f", historicalRep)
		return b
	}
	if compositeScore < 0 || compositeScore > 100 {
		b.err = fmt.Errorf("trust: composite_score must be in [0, 100], got %f", compositeScore)
		return b
	}
	// Auto-derive tier from score if not provided
	if tier == "" {
		tier = TierFromScore(compositeScore)
	}
	b.trust = &TrustClaims{
		StaticCapabilityScore: staticScore,
		HistoricalReputation:  historicalRep,
		CompositeScore:        compositeScore,
		TrustScoreEndpoint:    endpoint,
		AuthorizationTier:     tier,
	}
	return b
}

// WithSelectiveDisclosure marks the specified layers for selective disclosure.
// Valid layer names: "provenance", "baseline".
// Identity, Intent, and Trust are always disclosed per VIBAP spec.
func (b *Builder) WithSelectiveDisclosure(layers ...string) *Builder {
	for _, layer := range layers {
		switch layer {
		case "provenance", "baseline":
			b.sdLayers[layer] = true
		case "identity", "intent", "trust":
			b.err = fmt.Errorf("layer %q cannot be selectively disclosable — it must always be disclosed", layer)
			return b
		default:
			b.err = fmt.Errorf("unknown layer %q for selective disclosure", layer)
			return b
		}
	}
	return b
}

// WithStatus sets the Token Status List reference for revocation checking.
func (b *Builder) WithStatus(uri string, index int) *Builder {
	if uri == "" {
		b.err = fmt.Errorf("status: uri is required")
		return b
	}
	if index < 0 {
		b.err = fmt.Errorf("status: index must be non-negative, got %d", index)
		return b
	}
	b.status = &StatusReference{
		StatusList: StatusListRef{
			URI:   uri,
			Index: index,
		},
	}
	return b
}

// WithHolderKey sets the holder's Ed25519 public key for key binding.
// When set, the credential includes a cnf claim enabling KB-JWT verification.
func (b *Builder) WithHolderKey(pub ed25519.PublicKey) *Builder {
	if len(pub) != ed25519.PublicKeySize {
		b.err = fmt.Errorf("holder key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
		return b
	}
	b.holderKey = pub
	return b
}

// Build signs and produces the final VIBAPCredential.
// The signingKey is the VIBAP Authority's Ed25519 key.
func (b *Builder) Build(key *SigningKey) (*VIBAPCredential, error) {
	if b.err != nil {
		return nil, fmt.Errorf("builder error: %w", b.err)
	}
	if key == nil {
		return nil, fmt.Errorf("signing key is required")
	}
	if b.identity == nil && strings.HasPrefix(strings.ToLower(strings.TrimSpace(b.subject)), "spiffe://") {
		return nil, fmt.Errorf("SPIFFE-formatted subject requires identity layer")
	}
	if b.intent == nil {
		return nil, fmt.Errorf("intent layer (Layer 3) is required")
	}
	if b.trust == nil {
		return nil, fmt.Errorf("trust layer (Layer 5) is required")
	}

	now := time.Now()

	// Generate unique credential ID (jti) for replay prevention
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return nil, fmt.Errorf("generating jti: %w", err)
	}
	jti := hex.EncodeToString(jtiBytes)

	claims := Claims{
		JWTID:                    jti,
		Issuer:                   b.issuer,
		Subject:                  b.subject,
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(b.ttl).Unix(),
		VerifiableCredentialType: VIBAPTypeURI,
		Identity:                 b.identity,
		Intent:                   b.intent,
		Trust:                    b.trust,
	}

	// Set optional layers
	if b.provenance != nil && !b.sdLayers["provenance"] {
		claims.Provenance = b.provenance
	}
	if b.baseline != nil && !b.sdLayers["baseline"] {
		claims.Baseline = b.baseline
	}
	if b.status != nil {
		claims.Status = b.status
	}

	// Set holder key binding (cnf claim uses holder's key, not issuer's)
	if len(b.holderKey) > 0 {
		claims.Confirmation = &ConfirmationKey{
			JWK: &JWK{
				KeyType: "OKP",
				Curve:   "Ed25519",
				X:       base64.RawURLEncoding.EncodeToString(b.holderKey),
			},
		}
	}

	// Generate disclosures for selectively disclosable layers
	var disclosures []Disclosure
	var sdHashes []string

	if b.sdLayers["provenance"] && b.provenance != nil {
		d, err := createDisclosure("provenance", b.provenance)
		if err != nil {
			return nil, fmt.Errorf("creating provenance disclosure: %w", err)
		}
		disclosures = append(disclosures, d)
		sdHashes = append(sdHashes, d.Hash)
	}

	if b.sdLayers["baseline"] && b.baseline != nil {
		d, err := createDisclosure("baseline", b.baseline)
		if err != nil {
			return nil, fmt.Errorf("creating baseline disclosure: %w", err)
		}
		disclosures = append(disclosures, d)
		sdHashes = append(sdHashes, d.Hash)
	}

	// Set SD claims if we have disclosures
	if len(sdHashes) > 0 {
		claims.SDAlgorithm = SDAlgorithm
		claims.SD = sdHashes
	}

	// Build the header
	header := Header{
		Algorithm: "EdDSA",
		Type:      MediaTypeDCSDJWT,
		KeyID:     key.KeyID,
	}

	cred := &VIBAPCredential{
		Header:      header,
		Claims:      claims,
		Disclosures: disclosures,
	}

	return cred, nil
}

// createDisclosure generates an SD-JWT disclosure for a layer claim.
// Returns a Disclosure with random salt, encoded string, and SHA-256 hash.
func createDisclosure(claimName string, value any) (Disclosure, error) {
	// Generate 128-bit random salt
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return Disclosure{}, fmt.Errorf("generating salt: %w", err)
	}
	salt := base64.RawURLEncoding.EncodeToString(saltBytes)

	// Create disclosure array: [salt, claim_name, value]
	disclosureArray := []any{salt, claimName, value}
	disclosureJSON, err := json.Marshal(disclosureArray)
	if err != nil {
		return Disclosure{}, fmt.Errorf("marshaling disclosure: %w", err)
	}

	// Base64url encode the disclosure
	encoded := base64.RawURLEncoding.EncodeToString(disclosureJSON)

	// Compute SHA-256 hash of the encoded disclosure
	hash := sha256.Sum256([]byte(encoded))
	hashStr := base64.RawURLEncoding.EncodeToString(hash[:])

	return Disclosure{
		Salt:      salt,
		ClaimName: claimName,
		Value:     value,
		Encoded:   encoded,
		Hash:      hashStr,
	}, nil
}
