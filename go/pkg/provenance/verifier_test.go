package provenance

import (
	"context"
	"strings"
	"testing"
)

func TestStaticModelVerifier_ValidHash(t *testing.T) {
	v := &StaticModelVerifier{}
	hash := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"

	result, err := v.VerifyModelHash(context.Background(), hash)
	if err != nil {
		t.Fatalf("VerifyModelHash() error = %v", err)
	}
	if result != hash {
		t.Errorf("VerifyModelHash() = %q, want %q", result, hash)
	}
}

func TestStaticModelVerifier_EmptyHash(t *testing.T) {
	v := &StaticModelVerifier{}

	result, err := v.VerifyModelHash(context.Background(), "")
	if err != nil {
		t.Fatalf("VerifyModelHash() error = %v", err)
	}
	if result != "" {
		t.Errorf("VerifyModelHash() = %q, want empty", result)
	}
}

func TestStaticModelVerifier_InvalidLength(t *testing.T) {
	v := &StaticModelVerifier{}

	_, err := v.VerifyModelHash(context.Background(), "tooshort")
	if err == nil {
		t.Fatal("VerifyModelHash() should reject short hash")
	}
}

func TestStaticModelVerifier_InvalidHex(t *testing.T) {
	v := &StaticModelVerifier{}
	hash := "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"

	_, err := v.VerifyModelHash(context.Background(), hash)
	if err == nil {
		t.Fatal("VerifyModelHash() should reject non-hex characters")
	}
}

func TestStaticModelVerifier_SHA256Prefix(t *testing.T) {
	v := &StaticModelVerifier{}
	hash := "sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"

	result, err := v.VerifyModelHash(context.Background(), hash)
	if err != nil {
		t.Fatalf("VerifyModelHash() error = %v", err)
	}
	if result != hash {
		t.Errorf("VerifyModelHash() = %q, want %q", result, hash)
	}
}

func TestValidateSHA256Hex(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:  "valid lowercase hex",
			input: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
		},
		{
			name:  "valid with sha256 prefix",
			input: "sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
		},
		{
			name:    "too short",
			input:   "abc123",
			wantErr: true,
		},
		{
			name:    "too long",
			input:   "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2ff",
			wantErr: true,
		},
		{
			name:    "non-hex characters",
			input:   "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSHA256Hex(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSHA256Hex(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestVerifyOptions_Defaults(t *testing.T) {
	opts := VerifyOptions{}
	if opts.SkipTLog {
		t.Error("SkipTLog should default to false")
	}
	if opts.SkipTSA {
		t.Error("SkipTSA should default to false")
	}
	if opts.RequiredIdentity != "" {
		t.Error("RequiredIdentity should default to empty")
	}
	if opts.RequiredIssuer != "" {
		t.Error("RequiredIssuer should default to empty")
	}
}

func TestImageProvenance_Fields(t *testing.T) {
	p := &ImageProvenance{
		ImageDigest:       "sha256:abc123",
		SLSAProvenanceRef: "https://slsa.dev/provenance/v1",
		BuildPipeline:     "https://github.com/org/repo/actions/runs/123",
		SBOMRef:           "https://sbom.example.com/agent-v1.spdx.json",
		RekorVerified:     true,
		TSAVerified:       true,
		SignerIdentity:    "deployer@example.com",
		SignerIssuer:      "https://accounts.google.com",
	}

	if p.ImageDigest != "sha256:abc123" {
		t.Errorf("ImageDigest = %q", p.ImageDigest)
	}
	if !p.RekorVerified {
		t.Error("RekorVerified should be true")
	}
	if !p.TSAVerified {
		t.Error("TSAVerified should be true")
	}
}

func TestSigstoreVerifier_VerifyImageReportsUnsupported(t *testing.T) {
	v := &SigstoreVerifier{}

	_, err := v.VerifyImage(context.Background(), "ghcr.io/org/agent@sha256:abc", VerifyOptions{})
	if err == nil {
		t.Fatal("VerifyImage() should report unsupported direct OCI verification")
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Fatalf("VerifyImage() error = %q, want unsupported message", err.Error())
	}
}

func TestSigstoreVerifier_CloseIsIdempotentForClosedState(t *testing.T) {
	v := &SigstoreVerifier{}

	if err := v.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !v.closed {
		t.Fatal("Close() should mark verifier closed")
	}
	if err := v.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestSigstoreVerifier_VerifyBundleRejectsClosedVerifierBeforeIO(t *testing.T) {
	v := &SigstoreVerifier{closed: true}

	_, err := v.VerifyBundle(
		context.Background(),
		"/path/that/does/not/exist.sigstore.json",
		strings.Repeat("a", 64),
		VerifyOptions{RequiredIdentity: "deployer@example.com"},
	)
	if err == nil {
		t.Fatal("VerifyBundle() should reject a closed verifier")
	}
	if !strings.Contains(err.Error(), "verifier is closed") {
		t.Fatalf("VerifyBundle() error = %q, want closed-verifier error", err.Error())
	}
}

func TestSigstoreVerifier_VerifyBundleRequiresCompleteSignerConstraintsBeforeIO(t *testing.T) {
	tests := []struct {
		name string
		opts VerifyOptions
	}{
		{name: "both missing"},
		{name: "identity only", opts: VerifyOptions{RequiredIdentity: "deployer@example.com"}},
		{name: "issuer only", opts: VerifyOptions{RequiredIssuer: "https://token.actions.githubusercontent.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &SigstoreVerifier{}
			_, err := v.VerifyBundle(
				context.Background(),
				"/path/that/does/not/exist.sigstore.json",
				strings.Repeat("a", 64),
				tt.opts,
			)
			if err == nil {
				t.Fatal("VerifyBundle() should reject incomplete signer constraints")
			}
			if !strings.Contains(err.Error(), "requires both RequiredIdentity and RequiredIssuer") {
				t.Fatalf("VerifyBundle() error = %q, want complete-constraints error", err.Error())
			}
		})
	}
}

func TestSigstoreVerifierFromJSONRejectsInvalidTrustedRoot(t *testing.T) {
	_, err := NewSigstoreVerifierFromJSON([]byte(`{"not":"a trusted root"}`))
	if err == nil {
		t.Fatal("NewSigstoreVerifierFromJSON() should reject invalid trusted root JSON")
	}
	if !strings.Contains(err.Error(), "failed to parse trusted root JSON") {
		t.Fatalf("NewSigstoreVerifierFromJSON() error = %q", err.Error())
	}
}

func TestSigstoreVerifierFromPathRejectsMissingTrustedRoot(t *testing.T) {
	_, err := NewSigstoreVerifierFromPath("/path/that/does/not/exist.trustedroot.json")
	if err == nil {
		t.Fatal("NewSigstoreVerifierFromPath() should reject a missing trusted root")
	}
	if !strings.Contains(err.Error(), "failed to load trusted root") {
		t.Fatalf("NewSigstoreVerifierFromPath() error = %q", err.Error())
	}
}

func TestSigstoreVerifierBuildVerifierOptions(t *testing.T) {
	v := &SigstoreVerifier{}

	tests := []struct {
		name string
		opts VerifyOptions
		want int
	}{
		{name: "default requires tlog and tsa", want: 2},
		{name: "skip tlog keeps tsa", opts: VerifyOptions{SkipTLog: true}, want: 1},
		{name: "skip tsa keeps tlog", opts: VerifyOptions{SkipTSA: true}, want: 1},
		{name: "skip both uses observer timestamp", opts: VerifyOptions{SkipTLog: true, SkipTSA: true}, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.buildVerifierOptions(tt.opts)
			if len(got) != tt.want {
				t.Fatalf("buildVerifierOptions() len = %d, want %d", len(got), tt.want)
			}
		})
	}
}

// compile-time interface checks
var _ ProvenanceVerifier = (*SigstoreVerifier)(nil)
var _ ModelVerifier = (*StaticModelVerifier)(nil)
