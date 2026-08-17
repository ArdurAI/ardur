package main

import "testing"

// TestValidateWebhookPort mirrors the validator pattern already landed for
// ardur-seccomp-smoke (validateRequiredPaths) and the Python proxy.py --port
// range guard (66ae3c9): out-of-range --webhook-port values must be rejected
// at parse time rather than flowing into webhook.NewServer as an invalid
// webhook.Options.Port that produces a confusing bind-time failure.
func TestValidateWebhookPort(t *testing.T) {
	cases := []struct {
		name string
		port int
		want bool
	}{
		{"negative", -1, false},
		{"zero", 0, false},
		{"one lower bound", 1, true},
		{"default", 9443, true},
		{"upper bound", 65535, true},
		{"just over upper bound", 65536, false},
		{"far over upper bound", 70000, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validateWebhookPort(tc.port); got != tc.want {
				t.Fatalf("validateWebhookPort(%d) = %v, want %v", tc.port, got, tc.want)
			}
		})
	}
}
