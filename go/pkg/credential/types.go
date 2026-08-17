// Package credential implements VIBAP SD-JWT-VC credential types, construction,
// encoding, and verification per draft-ietf-oauth-sd-jwt-vc-15.
//
// A VIBAP credential binds five security layers into a single SD-JWT-VC:
//   - Layer 1: Identity (SPIFFE-based, always disclosed)
//   - Layer 2: Provenance (Sigstore/SLSA, selectively disclosable)
//   - Layer 3: Intent Binding (Cedar policy, always disclosed)
//   - Layer 4: Behavioral Baseline (Kubescape profile, selectively disclosable)
//   - Layer 5: Trust Score (dynamic posture, always disclosed)
package credential

import (
	"crypto/ed25519"
	"time"
)

// VIBAPCredential represents a complete VIBAP SD-JWT-VC credential.
// The token format follows draft-ietf-oauth-sd-jwt-vc-15:
//
//	<Issuer-Signed JWT>~<Disclosure 1>~...~<Disclosure N>~<Key Binding JWT>
type VIBAPCredential struct {
	Header      Header         `json:"-"` // JWT header (serialized separately)
	Claims      Claims         `json:"claims"`
	Disclosures []Disclosure   `json:"-"` // SD-JWT disclosures (serialized in tilde format)
	KeyBinding  *KeyBindingJWT `json:"-"` // Optional KB-JWT proving holder possession
	Raw         string         `json:"-"` // Original serialized form
}

// Header represents the JWT header for a VIBAP credential.
// Per SD-JWT-VC draft-15, typ MUST be "dc+sd-jwt".
type Header struct {
	Algorithm string `json:"alg"`           // Signing algorithm, "EdDSA" for Ed25519
	Type      string `json:"typ"`           // MUST be "dc+sd-jwt"
	KeyID     string `json:"kid,omitempty"` // Key identifier for the signing key
}

// Claims contains all JWT claims for a VIBAP credential.
// Standard claims follow RFC 7519; VIBAP layers are nested objects.
type Claims struct {
	// Standard JWT claims
	JWTID     string `json:"jti,omitempty"` // Unique credential identifier (prevents replay)
	Issuer    string `json:"iss"`           // VIBAP Authority identifier
	Subject   string `json:"sub"`           // Agent identifier; SPIFFE ID when one is present
	IssuedAt  int64  `json:"iat"`           // Unix timestamp of issuance
	ExpiresAt int64  `json:"exp"`           // Unix timestamp of expiration
	NotBefore int64  `json:"nbf,omitempty"` // Unix timestamp, not valid before

	// SD-JWT-VC specific claims
	VerifiableCredentialType string           `json:"vct"`              // MUST be the VIBAP type URI
	Confirmation             *ConfirmationKey `json:"cnf,omitempty"`    // Holder key binding (Ed25519 JWK)
	Status                   *StatusReference `json:"status,omitempty"` // Token Status List reference

	// SD-JWT hash algorithm and selective disclosure array
	SDAlgorithm string   `json:"_sd_alg,omitempty"` // "sha-256"
	SD          []string `json:"_sd,omitempty"`     // Array of disclosure hashes

	// VIBAP credential layers
	Identity   *IdentityClaims   `json:"identity,omitempty"`   // Layer 1 — optional; always disclosed when present
	Provenance *ProvenanceClaims `json:"provenance,omitempty"` // Layer 2 — selectively disclosable
	Intent     *IntentClaims     `json:"intent,omitempty"`     // Layer 3 — always disclosed
	Baseline   *BaselineClaims   `json:"baseline,omitempty"`   // Layer 4 — selectively disclosable
	Trust      *TrustClaims      `json:"trust,omitempty"`      // Layer 5 — always disclosed
}

// ConfirmationKey holds the holder's public key for Key Binding JWT verification.
// Per RFC 7800, this proves the presenter possesses the corresponding private key.
type ConfirmationKey struct {
	JWK *JWK `json:"jwk"` // Ed25519 public key as JWK
}

// JWK represents a JSON Web Key for Ed25519 (OKP key type).
type JWK struct {
	KeyType string `json:"kty"`           // "OKP" for Ed25519
	Curve   string `json:"crv"`           // "Ed25519"
	X       string `json:"x"`             // Base64url-encoded public key
	KeyID   string `json:"kid,omitempty"` // Optional key identifier
}

// StatusReference points to a Token Status List for revocation checking.
// Per draft-ietf-oauth-status-list-18, each credential has a unique index
// in the issuer's status list.
type StatusReference struct {
	StatusList StatusListRef `json:"status_list"` // Reference to the status list
}

// StatusListRef contains the URI and index for a Token Status List entry.
type StatusListRef struct {
	URI   string `json:"uri"` // URL of the Status List Token (JWT)
	Index int    `json:"idx"` // Credential's index in the bitstring (2-bit)
}

// StatusValue represents the 2-bit status of a credential in a Token Status List.
type StatusValue uint8

const (
	StatusValid     StatusValue = 0x00 // Credential is valid
	StatusInvalid   StatusValue = 0x01 // Credential is revoked
	StatusSuspended StatusValue = 0x02 // Credential is temporarily suspended
)

// String returns a human-readable status description.
func (s StatusValue) String() string {
	switch s {
	case StatusValid:
		return "VALID"
	case StatusInvalid:
		return "INVALID"
	case StatusSuspended:
		return "SUSPENDED"
	default:
		return "UNKNOWN"
	}
}

// --- VIBAP Credential Layers ---

// OwnerIDAssurance describes how the owner/deployer attribution was proven.
// Only self-asserted attribution is implemented. A verified state must not be
// added until issuance verifies owner-controlled proof against configured
// trust anchors.
type OwnerIDAssurance string

const (
	// OwnerIDAssuranceSelfAsserted means the issuer signed the configured owner
	// string as attribution but did not authenticate the ownership relation.
	OwnerIDAssuranceSelfAsserted OwnerIDAssurance = "self_asserted"
)

// IdentityClaims represents Layer 1: Agent Identity.
// Always disclosed — verifiers need to know who the agent is.
//
// Uses SPIFFE IDs for per-instance identity (not per-service-account)
// because agents are non-deterministic — two replicas may behave differently.
type IdentityClaims struct {
	// Per-instance SPIFFE ID: spiffe://ardur.dev/ns/{ns}/sa/{sa}/instance/{pod-uid}
	SPIFFEID string `json:"spiffe_id"`

	// SPIFFE-formatted deploying human or service-account attribution.
	// This value is not an authenticated dual-identity binding.
	OwnerID string `json:"owner_id"`

	// Assurance for OwnerID. It is signed as part of the credential so a
	// consumer cannot mistake configured attribution for SPIRE verification.
	OwnerIDAssurance OwnerIDAssurance `json:"owner_id_assurance"`

	// URL to the agent's A2A Agent Card (Google A2A protocol).
	// Optional — only set if the agent participates in A2A discovery.
	A2ACardRef string `json:"a2a_card_ref,omitempty"`
}

// ProvenanceClaims represents Layer 2: Supply Chain Provenance.
// Selectively disclosable — not all verifiers need full supply chain details.
//
// Binds the agent to its build pipeline using Sigstore cosign + SLSA attestations.
type ProvenanceClaims struct {
	// SHA-256 digest of the container image (e.g., "sha256:abc123...")
	ImageDigest string `json:"image_digest"`

	// URI to SLSA v1.2 build provenance attestation (in-toto format)
	SLSAProvenanceRef string `json:"slsa_provenance_ref,omitempty"`

	// SHA-256 hash of model weights (for AI agents with embedded models)
	// Uses Sigstore model-transparency approach
	ModelHash string `json:"model_hash,omitempty"`

	// CI/CD pipeline identifier (e.g., GitHub Actions workflow URL)
	BuildPipeline string `json:"build_pipeline,omitempty"`

	// URI to SBOM (Software Bill of Materials) document
	SBOMRef string `json:"sbom_ref,omitempty"`
}

// IntentClaims represents Layer 3: Intent Binding.
// Always disclosed — verifiers must know what the agent is authorized to do.
//
// Implements the agent_checksum concept from draft-goswami-agentic-jwt-00:
// authorization is derived from and cryptographically bound to the agent's
// actual configuration (system prompt + tool manifest + derived policy).
type IntentClaims struct {
	// SHA-256 of (system prompt + tool manifest + compiled policy).
	// Any change to the agent's configuration invalidates this checksum.
	AgentChecksum string `json:"agent_checksum"`

	// Policy engine used: "cedar" (default, formally verifiable) or "rego"
	PolicyEngine string `json:"policy_engine"`

	// SHA-256 of the compiled Cedar/Rego policy text
	PolicyHash string `json:"policy_hash"`

	// Human-readable list of permitted actions (e.g., ["read:database", "call:api/v1/*"])
	PermittedActions []string `json:"permitted_actions,omitempty"`
}

// BaselineClaims represents Layer 4: Behavioral Baseline.
// Selectively disclosable — baseline details are sensitive operational data.
//
// Generated by Kubescape ApplicationProfile (eBPF-based runtime profiling).
// The monitor sidecar compares actual behavior against this baseline.
type BaselineClaims struct {
	// SHA-256 hash of the Kubescape ApplicationProfile
	ApplicationProfileHash string `json:"application_profile_hash"`

	// Expected network endpoints (CIDRs or hostnames with ports)
	ExpectedEndpoints []string `json:"expected_endpoints,omitempty"`

	// Expected syscall set (from eBPF profiling)
	ExpectedSyscalls []string `json:"expected_syscalls,omitempty"`

	// Expected tool-call frequency bounds: {"tool_name": {"min": N, "max": M}}
	ToolFrequencyBounds map[string]FrequencyBound `json:"tool_frequency_bounds,omitempty"`

	// Permitted file access paths (read/write)
	FileAccessPaths []string `json:"file_access_paths,omitempty"`

	// Maximum delegation depth (how many sub-agents deep this agent can spawn)
	MaxDelegationDepth int `json:"max_delegation_depth"`
}

// FrequencyBound defines min/max expected invocations per time window.
type FrequencyBound struct {
	Min    int    `json:"min"`
	Max    int    `json:"max"`
	Window string `json:"window"` // Duration string, e.g., "1h", "5m"
}

// TrustClaims represents Layer 5: Trust Score.
// Always disclosed — verifiers use trust score to determine authorization tier.
//
// The composite score determines the agent's authorization tier:
//   - Full (≥70): all egress allowed to authorized services
//   - Limited (≥40, <70): observation-only, no external access
//   - Quarantine (<40): all egress denied, only Prometheus scraping allowed
type TrustClaims struct {
	// Static capability risk score (0.0–1.0), based on declared permissions scope.
	// Inspired by MI9 Agency-Risk Index (ARI). Set at issuance, does not change.
	StaticCapabilityScore float64 `json:"static_capability_score"`

	// Historical behavior compliance score (0.0–1.0).
	// Based on past credential periods. Higher = more trustworthy history.
	HistoricalReputation float64 `json:"historical_reputation"`

	// Dynamic composite trust score (0–100). Computed by posture aggregator.
	// Weighted combination of static + historical + runtime signals.
	CompositeScore float64 `json:"composite_score"`

	// URL to query current trust score (served by monitor sidecar or aggregator)
	TrustScoreEndpoint string `json:"trust_score_endpoint,omitempty"`

	// Current authorization tier: "full", "limited", or "quarantine"
	AuthorizationTier string `json:"authorization_tier"`
}

// AuthorizationTier constants for trust-based access control.
const (
	TierFull       = "full"       // ≥70 composite score
	TierLimited    = "limited"    // ≥40, <70 composite score
	TierQuarantine = "quarantine" // <40 composite score
)

// TierFromScore determines the authorization tier from a composite trust score.
func TierFromScore(score float64) string {
	switch {
	case score >= 70:
		return TierFull
	case score >= 40:
		return TierLimited
	default:
		return TierQuarantine
	}
}

// Disclosure represents a single SD-JWT selective disclosure.
// Each disclosure is a base64url-encoded JSON array: [salt, claim_name, claim_value].
// The hash of the disclosure is included in the _sd array of the JWT payload.
type Disclosure struct {
	Salt      string `json:"salt"`       // Random salt (min 128 bits of entropy)
	ClaimName string `json:"claim_name"` // Name of the disclosed claim
	Value     any    `json:"value"`      // Value of the disclosed claim
	Encoded   string `json:"-"`          // Base64url-encoded disclosure string
	Hash      string `json:"-"`          // SHA-256 hash for the _sd array
}

// KeyBindingJWT proves the presenter holds the private key corresponding
// to the cnf public key in the credential. Per SD-JWT-VC spec, the KB-JWT
// contains nonce, aud, and iat claims.
type KeyBindingJWT struct {
	Header KeyBindingHeader `json:"header"`
	Claims KeyBindingClaims `json:"claims"`
	Raw    string           `json:"-"` // Serialized KB-JWT
}

// KeyBindingHeader is the JWT header for a Key Binding JWT.
type KeyBindingHeader struct {
	Algorithm string `json:"alg"` // "EdDSA"
	Type      string `json:"typ"` // "kb+jwt"
}

// KeyBindingClaims contains the claims for a Key Binding JWT.
type KeyBindingClaims struct {
	Nonce    string `json:"nonce"`   // Challenge nonce from the verifier
	Audience string `json:"aud"`     // Intended verifier
	IssuedAt int64  `json:"iat"`     // Timestamp of KB-JWT creation
	SDHash   string `json:"sd_hash"` // Hash of the presented SD-JWT (without KB-JWT)
}

// SigningKey wraps an Ed25519 private key with metadata for credential signing.
type SigningKey struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	KeyID      string
}

// VIBAPTypeURI is the Verifiable Credential Type URI for VIBAP credentials.
const VIBAPTypeURI = "https://vibap.ardur.dev/credentials/AgentPassport/v1"

// MediaType constants for SD-JWT-VC.
const (
	MediaTypeDCSDJWT = "dc+sd-jwt" // Current media type per draft-15
	MediaTypeKBJWT   = "kb+jwt"    // Key Binding JWT media type
)

// DefaultTTL is the default credential time-to-live (1 hour).
const DefaultTTL = 1 * time.Hour

// SDAlgorithm is the hash algorithm for selective disclosure.
const SDAlgorithm = "sha-256"
