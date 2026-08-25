// Package provenance provides Sigstore/SLSA integration for VIBAP Layer 2 (Provenance).
//
// It defines a ProvenanceVerifier interface for OCI image signature verification
// and SLSA provenance attestation extraction. The primary implementation uses
// sigstore-go (the library underlying cosign v3) for bundle verification against
// the Rekor transparency log with TSA timestamp validation.
package provenance

import (
	"context"
	"time"
)

// ImageProvenance holds the verified provenance information for a container image.
// This feeds directly into the ProvenanceClaims of a VIBAP credential (Layer 2).
type ImageProvenance struct {
	// SHA-256 digest of the verified container image (e.g., "sha256:abc123...")
	ImageDigest string

	// URI to the SLSA build provenance attestation (in-toto format)
	SLSAProvenanceRef string

	// CI/CD pipeline that built the image (e.g., GitHub Actions workflow URL)
	BuildPipeline string

	// SBOM reference URI (populated statically in Phase 2; GUAC in Phase 4)
	SBOMRef string

	// Whether the image signature was verified against Rekor transparency log
	RekorVerified bool

	// Whether a TSA timestamp was validated (required for cosign v3/Rekor v2)
	TSAVerified bool

	// Timestamp of the signature
	SignedAt time.Time

	// Signer identity (e.g., OIDC email or service account from Fulcio cert)
	SignerIdentity string

	// OIDC issuer that authenticated the signer
	SignerIssuer string
}

// VerifyOptions configures how provenance verification is performed.
type VerifyOptions struct {
	// RequiredIdentity is the expected signer identity (e.g., OIDC email).
	// It must be set together with RequiredIssuer.
	RequiredIdentity string

	// RequiredIssuer is the expected OIDC issuer (e.g., "https://accounts.google.com").
	// It must be set together with RequiredIdentity.
	RequiredIssuer string

	// TrustedRootPath overrides the default Sigstore public good TUF root.
	// Used for private Sigstore deployments.
	TrustedRootPath string

	// SkipTLog disables Rekor transparency log verification.
	// WARNING: only for testing with locally-signed images.
	SkipTLog bool

	// SkipTSA disables TSA timestamp verification.
	// WARNING: only for testing; TSA is required for Rekor v2/cosign v3.
	SkipTSA bool
}

// ProvenanceVerifier abstracts container image provenance verification.
// The primary implementation uses sigstore-go for Sigstore bundle verification.
type ProvenanceVerifier interface {
	// VerifyImage verifies the signature and provenance of an OCI container image.
	// The imageRef should be a fully-qualified image reference with digest
	// (e.g., "ghcr.io/org/image@sha256:abc123...").
	VerifyImage(ctx context.Context, imageRef string, opts VerifyOptions) (*ImageProvenance, error)

	// VerifyBundle verifies a Sigstore protobuf bundle directly (for offline verification).
	// bundlePath is the path to the .sigstore.json bundle file.
	// artifactDigest is the expected SHA-256 digest of the artifact.
	VerifyBundle(ctx context.Context, bundlePath string, artifactDigest string, opts VerifyOptions) (*ImageProvenance, error)

	// Close releases resources held by the verifier.
	Close() error
}

// ModelVerifier abstracts model weights verification for AI agents.
// In Phase 2 this is a stub that accepts deployer-provided digests.
// In future phases it will integrate with sigstore/model-transparency.
type ModelVerifier interface {
	// VerifyModelHash validates a model weights hash.
	// In Phase 2, this accepts the hash as-is (no external verification).
	// Returns the verified hash and any error.
	VerifyModelHash(ctx context.Context, modelHash string) (string, error)
}

// StaticModelVerifier is a Phase 2 stub that trusts deployer-provided model hashes.
// It validates format only (must be a hex-encoded SHA-256 digest).
type StaticModelVerifier struct{}

// VerifyModelHash validates the format of a model hash without external verification.
func (v *StaticModelVerifier) VerifyModelHash(_ context.Context, modelHash string) (string, error) {
	if modelHash == "" {
		return "", nil
	}
	if err := validateSHA256Hex(modelHash); err != nil {
		return "", err
	}
	return modelHash, nil
}
