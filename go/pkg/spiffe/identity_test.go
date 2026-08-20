package spiffe

import (
	"strings"
	"testing"
)

func TestValidateSPIFFEID(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		wantTD   string
		wantPath string
		wantErr  bool
	}{
		{
			name:     "valid agent SPIFFE ID",
			id:       "spiffe://ardur.dev/agent/weather-bot/instance-abc123",
			wantTD:   "ardur.dev",
			wantPath: "/agent/weather-bot/instance-abc123",
		},
		{
			name:     "valid owner SPIFFE ID",
			id:       "spiffe://ardur.dev/user/deployer-42",
			wantTD:   "ardur.dev",
			wantPath: "/user/deployer-42",
		},
		{
			name:     "trust domain only",
			id:       "spiffe://example.org",
			wantTD:   "example.org",
			wantPath: "/",
		},
		{
			name:     "root path",
			id:       "spiffe://example.org/",
			wantTD:   "example.org",
			wantPath: "/",
		},
		{
			name:    "empty string",
			id:      "",
			wantErr: true,
		},
		{
			name:    "wrong scheme",
			id:      "https://vibap.ardur.dev/agent/test",
			wantErr: true,
		},
		{
			name:    "no trust domain",
			id:      "spiffe:///agent/test",
			wantErr: true,
		},
		{
			name:    "with query string",
			id:      "spiffe://example.org/agent?foo=bar",
			wantErr: true,
		},
		{
			name:    "with fragment",
			id:      "spiffe://example.org/agent#section",
			wantErr: true,
		},
		{
			name:    "with port",
			id:      "spiffe://example.org:8080/agent",
			wantErr: true,
		},
		{
			name:    "with userinfo",
			id:      "spiffe://user@example.org/agent",
			wantErr: true,
		},
		{
			name:    "double slashes in path",
			id:      "spiffe://example.org//agent//test",
			wantErr: true,
		},
		{
			name:    "exceeds 2048 byte limit",
			id:      "spiffe://example.org/" + strings.Repeat("a", 2048),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			td, path, err := ValidateSPIFFEID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSPIFFEID(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if td != tt.wantTD {
				t.Errorf("ValidateSPIFFEID(%q) trustDomain = %q, want %q", tt.id, td, tt.wantTD)
			}
			if path != tt.wantPath {
				t.Errorf("ValidateSPIFFEID(%q) path = %q, want %q", tt.id, path, tt.wantPath)
			}
		})
	}
}

func TestValidateSPIFFEID_PortInTrustDomain(t *testing.T) {
	// Port in trust domain is invalid per SPIFFE spec
	_, _, err := ValidateSPIFFEID("spiffe://domain:8080/path")
	if err == nil {
		t.Fatal("ValidateSPIFFEID should fail for trust domain with port")
	}
	if !strings.Contains(err.Error(), "must not contain port") {
		t.Errorf("error = %v, want message about port", err)
	}
}

func TestValidateSPIFFEID_Userinfo(t *testing.T) {
	// Userinfo is invalid per SPIFFE spec
	_, _, err := ValidateSPIFFEID("spiffe://user@domain/path")
	if err == nil {
		t.Fatal("ValidateSPIFFEID should fail for SPIFFE ID with userinfo")
	}
	if !strings.Contains(err.Error(), "userinfo") {
		t.Errorf("error = %v, want message about userinfo", err)
	}
}

// compile-time check that SPIREClient implements IdentityProvider
var _ IdentityProvider = (*SPIREClient)(nil)
