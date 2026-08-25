package policy

import (
	"strings"
	"testing"
)

func TestComputePolicyHash(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		same bool
	}{
		{"identical", "permit(principal, action, resource);", "permit(principal, action, resource);", true},
		{"trimmed whitespace", "  permit(principal, action, resource);  \n", "permit(principal, action, resource);", true},
		{"different policies", "permit(principal, action, resource);", "forbid(principal, action, resource);", false},
		{"crlf normalized", "permit(principal,\r\naction, resource);", "permit(principal,\naction, resource);", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ha := ComputePolicyHash(tt.a)
			hb := ComputePolicyHash(tt.b)
			if (ha == hb) != tt.same {
				t.Errorf("hashes same=%v, want %v (a=%q, b=%q)", ha == hb, tt.same, ha, hb)
			}
			if len(ha) != 64 {
				t.Errorf("hash length = %d, want 64 hex chars", len(ha))
			}
		})
	}
}

func TestComputeAgentChecksum(t *testing.T) {
	cs1 := ComputeAgentChecksum("You are a weather bot", "tools: [get_weather]", "permit(...);")
	cs2 := ComputeAgentChecksum("You are a weather bot", "tools: [get_weather]", "permit(...);")
	cs3 := ComputeAgentChecksum("You are a finance bot", "tools: [get_weather]", "permit(...);")

	if cs1 != cs2 {
		t.Error("identical inputs should produce identical checksums")
	}
	if cs1 == cs3 {
		t.Error("different prompts should produce different checksums")
	}
	if len(cs1) != 64 {
		t.Errorf("checksum length = %d, want 64", len(cs1))
	}
}

func TestValidatePolicyEngine(t *testing.T) {
	tests := []struct {
		name    string
		engine  string
		wantErr bool
	}{
		{"cedar", "cedar", false},
		{"rego", "rego", false},
		{"unknown", "unknown", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePolicyEngine(tt.engine)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePolicyEngine(%q) error = %v, wantErr %v", tt.engine, err, tt.wantErr)
			}
		})
	}
}

func TestEntityRefString(t *testing.T) {
	ref := EntityRef{Type: "VIBAP::Agent", ID: "weather-bot"}
	got := ref.String()
	if !strings.Contains(got, "VIBAP::Agent") || !strings.Contains(got, "weather-bot") {
		t.Errorf("EntityRef.String() = %q, want to contain type and ID", got)
	}
}
