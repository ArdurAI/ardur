//go:build linux

package main

import "testing"

// TestValidateArgumentsRejectsWhitespaceOnlySessionID mirrors the
// auditbench-oracle whitespace guard: a whitespace-only required flag must
// be rejected at validation instead of flowing into seccomp setup as an
// empty-looking session id.
func TestValidateArgumentsRejectsWhitespaceOnlySessionID(t *testing.T) {
	cases := []struct {
		name    string
		session string
		args    []string
		want    bool
	}{
		{"empty session", "", []string{"echo"}, false},
		{"whitespace session", "   ", []string{"echo"}, false},
		{"tab session", "\t", []string{"echo"}, false},
		{"empty args", "ardur-session", nil, false},
		{"valid", "ardur-session", []string{"echo", "hi"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validateArguments(tc.session, tc.args); got != tc.want {
				t.Fatalf("validateArguments(%q, %v) = %v, want %v", tc.session, tc.args, got, tc.want)
			}
		})
	}
}
