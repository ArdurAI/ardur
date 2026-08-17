//go:build linux

package main

import "testing"

// TestValidateRequiredPathsRejectsWhitespace mirrors the whitespace guard
// pattern already landed for ardur-exec-shim and auditbench-oracle: a
// whitespace-only required flag must be rejected at validation instead of
// flowing into run() as an empty-looking binary path that exec.Command
// turns into a confusing "file not found" far from the actual misuse.
func TestValidateRequiredPathsRejectsWhitespace(t *testing.T) {
	cases := []struct {
		name      string
		daemonBin string
		shimBin   string
		want      bool
	}{
		{"both empty", "", "", false},
		{"daemon empty", "", "/bin/ardur-exec-shim", false},
		{"shim empty", "/bin/ardur-kernelcaptured", "", false},
		{"daemon spaces", "   ", "/bin/ardur-exec-shim", false},
		{"shim spaces", "/bin/ardur-kernelcaptured", "   ", false},
		{"daemon tab", "\t", "/bin/ardur-exec-shim", false},
		{"shim newline", "/bin/ardur-kernelcaptured", "\n", false},
		{"both valid", "/bin/ardur-kernelcaptured", "/bin/ardur-exec-shim", true},
		{"valid with surrounding spaces", "  /bin/daemon  ", "  /bin/shim  ", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validateRequiredPaths(tc.daemonBin, tc.shimBin); got != tc.want {
				t.Fatalf("validateRequiredPaths(%q, %q) = %v, want %v", tc.daemonBin, tc.shimBin, got, tc.want)
			}
		})
	}
}
