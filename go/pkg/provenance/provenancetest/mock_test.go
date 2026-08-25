package provenancetest

import (
	"context"
	"fmt"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/provenance"
)

func TestMockProvenanceVerifier_VerifyImage(t *testing.T) {
	mock := NewMockProvenanceVerifier()
	defer mock.Close()

	result, err := mock.VerifyImage(context.Background(), "ghcr.io/org/agent@sha256:abc", provenance.VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyImage() error = %v", err)
	}

	if !result.RekorVerified {
		t.Error("RekorVerified should be true")
	}
	if !result.TSAVerified {
		t.Error("TSAVerified should be true")
	}
	if result.SignerIdentity != "deployer@example.com" {
		t.Errorf("SignerIdentity = %q, want deployer@example.com", result.SignerIdentity)
	}
	if mock.CallCount != 1 {
		t.Errorf("CallCount = %d, want 1", mock.CallCount)
	}
}

func TestMockProvenanceVerifier_VerifyBundle(t *testing.T) {
	mock := NewMockProvenanceVerifier()
	defer mock.Close()

	result, err := mock.VerifyBundle(context.Background(), "/path/to/bundle.json", "abc123", provenance.VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyBundle() error = %v", err)
	}

	if result.SLSAProvenanceRef != "https://slsa.dev/provenance/v1" {
		t.Errorf("SLSAProvenanceRef = %q", result.SLSAProvenanceRef)
	}
}

func TestMockProvenanceVerifier_Error(t *testing.T) {
	mock := NewMockProvenanceVerifier()
	mock.VerifyError = fmt.Errorf("signature verification failed")
	defer mock.Close()

	_, err := mock.VerifyImage(context.Background(), "ghcr.io/org/agent@sha256:abc", provenance.VerifyOptions{})
	if err == nil {
		t.Fatal("VerifyImage() should return error when VerifyError is set")
	}
	if err.Error() != "signature verification failed" {
		t.Errorf("error = %q, want %q", err.Error(), "signature verification failed")
	}
}

func TestMockProvenanceVerifier_ClosedError(t *testing.T) {
	mock := NewMockProvenanceVerifier()
	mock.Close()

	_, err := mock.VerifyImage(context.Background(), "ghcr.io/org/agent@sha256:abc", provenance.VerifyOptions{})
	if err == nil {
		t.Fatal("VerifyImage() after Close() should return error")
	}

	_, err = mock.VerifyBundle(context.Background(), "/path", "abc", provenance.VerifyOptions{})
	if err == nil {
		t.Fatal("VerifyBundle() after Close() should return error")
	}
}

func TestMockProvenanceVerifier_CallCount(t *testing.T) {
	mock := NewMockProvenanceVerifier()
	defer mock.Close()

	for i := 0; i < 5; i++ {
		_, _ = mock.VerifyImage(context.Background(), "img", provenance.VerifyOptions{})
	}
	_, _ = mock.VerifyBundle(context.Background(), "path", "digest", provenance.VerifyOptions{})

	if mock.CallCount != 6 {
		t.Errorf("CallCount = %d, want 6", mock.CallCount)
	}
}

func TestMockProvenanceVerifier_VerifyBundleWithError(t *testing.T) {
	mock := NewMockProvenanceVerifier()
	mock.VerifyError = fmt.Errorf("bundle verification failed")
	defer mock.Close()

	_, err := mock.VerifyBundle(context.Background(), "/path/to/bundle.json", "abc123", provenance.VerifyOptions{})
	if err == nil {
		t.Fatal("VerifyBundle() should return error when VerifyError is set")
	}
	if err.Error() != "bundle verification failed" {
		t.Errorf("error = %q, want %q", err.Error(), "bundle verification failed")
	}
	if mock.CallCount != 1 {
		t.Errorf("CallCount = %d, want 1", mock.CallCount)
	}
}
