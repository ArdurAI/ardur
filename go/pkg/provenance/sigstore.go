package provenance

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// SigstoreVerifier implements ProvenanceVerifier using sigstore-go.
// It verifies Sigstore protobuf bundles against the Rekor transparency log
// with TSA timestamp validation (required by cosign v3/Rekor v2).
type SigstoreVerifier struct {
	trustedRoot root.TrustedMaterial
	mu          sync.RWMutex
	closed      bool
}

// NewSigstoreVerifier creates a verifier using the Sigstore public good TUF root.
// This fetches the latest trusted root from the Sigstore TUF repository.
func NewSigstoreVerifier() (*SigstoreVerifier, error) {
	tr, err := root.FetchTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Sigstore trusted root: %w", err)
	}

	return &SigstoreVerifier{trustedRoot: tr}, nil
}

// NewSigstoreVerifierFromPath creates a verifier using a custom trusted root file.
// Used for private Sigstore deployments.
func NewSigstoreVerifierFromPath(trustedRootPath string) (*SigstoreVerifier, error) {
	tr, err := root.NewTrustedRootFromPath(trustedRootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load trusted root from %s: %w", trustedRootPath, err)
	}

	return &SigstoreVerifier{trustedRoot: tr}, nil
}

// NewSigstoreVerifierFromJSON creates a verifier from trusted root JSON bytes.
// Useful for embedding trusted root in configuration.
func NewSigstoreVerifierFromJSON(trustedRootJSON []byte) (*SigstoreVerifier, error) {
	tr, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trusted root JSON: %w", err)
	}

	return &SigstoreVerifier{trustedRoot: tr}, nil
}

// VerifyImage is not yet implemented for direct OCI image verification.
// sigstore-go does not natively pull OCI images; this requires
// go-containerregistry to fetch bundles from OCI annotations.
// For Phase 2, use VerifyBundle with pre-fetched bundles instead.
func (v *SigstoreVerifier) VerifyImage(_ context.Context, imageRef string, _ VerifyOptions) (*ImageProvenance, error) {
	return nil, fmt.Errorf("direct OCI image verification not yet implemented; use VerifyBundle for image %s", imageRef)
}

// VerifyBundle verifies a Sigstore protobuf bundle file against the trusted root.
// This validates the signature, transparency log inclusion, and TSA timestamps.
func (v *SigstoreVerifier) VerifyBundle(_ context.Context, bundlePath string, artifactDigest string, opts VerifyOptions) (*ImageProvenance, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.closed {
		return nil, fmt.Errorf("verifier is closed")
	}
	if err := validateSignerConstraints(opts); err != nil {
		return nil, err
	}

	b, err := bundle.LoadJSONFromPath(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load bundle from %s: %w", bundlePath, err)
	}

	verifierOpts := v.buildVerifierOptions(opts)
	verifier, err := verify.NewVerifier(v.trustedRoot, verifierOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	cleanDigest := strings.TrimPrefix(artifactDigest, "sha256:")
	if err := validateSHA256Hex(cleanDigest); err != nil {
		return nil, fmt.Errorf("invalid artifact digest: %w", err)
	}
	digestBytes, err := hex.DecodeString(cleanDigest)
	if err != nil {
		return nil, fmt.Errorf("invalid artifact digest hex: %w", err)
	}

	identity, err := verify.NewShortCertificateIdentity(
		opts.RequiredIssuer, "",
		opts.RequiredIdentity, "",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate identity matcher: %w", err)
	}
	policyOpts := []verify.PolicyOption{verify.WithCertificateIdentity(identity)}

	policy := verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digestBytes),
		policyOpts...,
	)

	result, err := verifier.Verify(b, policy)
	if err != nil {
		return nil, fmt.Errorf("bundle verification failed: %w", err)
	}

	provenance := &ImageProvenance{
		ImageDigest:   "sha256:" + cleanDigest,
		RekorVerified: false,
		TSAVerified:   false,
	}

	// Set RekorVerified and TSAVerified from actual verification results,
	// not from option flags. This ensures the credential only claims
	// what was actually verified.
	for _, ts := range result.VerifiedTimestamps {
		switch ts.Type {
		case "Tlog":
			provenance.RekorVerified = true
		case "TimestampAuthority":
			provenance.TSAVerified = true
		}
		if provenance.SignedAt.IsZero() {
			provenance.SignedAt = ts.Timestamp
		}
	}

	if result.VerifiedIdentity != nil {
		if result.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName != "" {
			provenance.SignerIdentity = result.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName
		}
		if result.VerifiedIdentity.Issuer.Issuer != "" {
			provenance.SignerIssuer = result.VerifiedIdentity.Issuer.Issuer
		}
	}

	if result.Statement != nil {
		provenance.SLSAProvenanceRef = result.Statement.PredicateType
		if len(result.Statement.Subject) > 0 {
			for _, s := range result.Statement.Subject {
				if d, ok := s.Digest["sha256"]; ok {
					provenance.ImageDigest = "sha256:" + d
					break
				}
			}
		}
	}

	return provenance, nil
}

func validateSignerConstraints(opts VerifyOptions) error {
	if opts.RequiredIdentity == "" || opts.RequiredIssuer == "" {
		return fmt.Errorf("provenance verification requires both RequiredIdentity and RequiredIssuer; refusing to verify with incomplete signer constraints")
	}
	return nil
}

func (v *SigstoreVerifier) buildVerifierOptions(opts VerifyOptions) []verify.VerifierOption {
	var vopts []verify.VerifierOption

	if !opts.SkipTLog {
		vopts = append(vopts, verify.WithTransparencyLog(1))
	}

	if !opts.SkipTSA {
		vopts = append(vopts, verify.WithSignedTimestamps(1))
	}

	if opts.SkipTLog && opts.SkipTSA {
		vopts = append(vopts, verify.WithObserverTimestamps(1))
	}

	return vopts
}

// Close releases resources held by the verifier.
func (v *SigstoreVerifier) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.closed = true
	return nil
}
