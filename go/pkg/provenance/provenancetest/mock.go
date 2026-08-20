// Package provenancetest provides test doubles for the artifact provenance
// (Layer 2) verification layer.
//
// It lives in its own package, separate from pkg/provenance, so that a fake
// verifier cannot be linked into a production binary. That matters because
// pkg/issuer treats "a ProvenanceVerifier is configured and VerifyImage or
// VerifyBundle returned no error" as the provenanceVerified input to
// computeActualCompliance, one of the three conditions that raise a credential
// to LevelVerified. A mock reachable from cmd/ would let an unsigned image —
// carrying a canned digest with RekorVerified and TSAVerified already set true
// — earn that treatment without any signature ever being checked.
//
// go/internal/linkgraph enforces the separation: its architecture test fails
// if this package, or any exported Mock/Fake/Stub/Dummy symbol in a non-test
// file, becomes reachable from a binary under cmd/.
package provenancetest

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/provenance"
)

// MockProvenanceVerifier implements provenance.ProvenanceVerifier for testing.
// Returns preconfigured results for image verification.
type MockProvenanceVerifier struct {
	mu     sync.RWMutex
	closed bool

	// VerifyResult is the result returned by VerifyImage and VerifyBundle.
	VerifyResult *provenance.ImageProvenance

	// VerifyError is the error returned by VerifyImage and VerifyBundle.
	// If set, VerifyResult is ignored.
	VerifyError error

	// CallCount tracks how many times Verify was called.
	CallCount int
}

// NewMockProvenanceVerifier creates a mock verifier with a default success result.
func NewMockProvenanceVerifier() *MockProvenanceVerifier {
	return &MockProvenanceVerifier{
		VerifyResult: &provenance.ImageProvenance{
			ImageDigest:       "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			SLSAProvenanceRef: "https://slsa.dev/provenance/v1",
			BuildPipeline:     "https://github.com/org/repo/actions/runs/12345",
			SBOMRef:           "",
			RekorVerified:     true,
			TSAVerified:       true,
			SignedAt:          time.Now().Add(-1 * time.Hour),
			SignerIdentity:    "deployer@example.com",
			SignerIssuer:      "https://accounts.google.com",
		},
	}
}

// VerifyImage returns the preconfigured result or error.
func (m *MockProvenanceVerifier) VerifyImage(_ context.Context, _ string, _ provenance.VerifyOptions) (*provenance.ImageProvenance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, fmt.Errorf("mock verifier is closed")
	}
	m.CallCount++

	if m.VerifyError != nil {
		return nil, m.VerifyError
	}

	result := *m.VerifyResult
	return &result, nil
}

// VerifyBundle returns the preconfigured result or error.
func (m *MockProvenanceVerifier) VerifyBundle(_ context.Context, _ string, _ string, _ provenance.VerifyOptions) (*provenance.ImageProvenance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, fmt.Errorf("mock verifier is closed")
	}
	m.CallCount++

	if m.VerifyError != nil {
		return nil, m.VerifyError
	}

	result := *m.VerifyResult
	return &result, nil
}

// Close marks the mock verifier as closed.
func (m *MockProvenanceVerifier) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

var _ provenance.ProvenanceVerifier = (*MockProvenanceVerifier)(nil)
