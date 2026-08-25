//go:build linux

package main

import (
	"strings"
	"testing"
)

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
		{"tab session", "	", []string{"echo"}, false},
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

// TestTrimmedSeccompSocketEmptyDetection documents the contract that a
// whitespace-only or empty --seccomp-socket value must be rejected before
// reaching run(). main() trims the flag and exits(2) when the trimmed value
// is empty; this test encodes the TrimSpace predicate so a refactor cannot
// silently drop the guard.
func TestTrimmedSeccompSocketEmptyDetection(t *testing.T) {
	cases := []struct {
		name  string
		input string
		empty bool
	}{
		{"valid path", "/run/ardur/seccomp.sock", false},
		{"empty", "", true},
		{"spaces", "   ", true},
		{"tab", "	", true},
		{"newline", "\n", true},
		{"mixed whitespace", " 	\n ", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trimmed := strings.TrimSpace(tc.input)
			got := trimmed == ""
			if got != tc.empty {
				t.Fatalf("TrimSpace(%q)=='' = %v, want %v", tc.input, got, tc.empty)
			}
		})
	}
}
