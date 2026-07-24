package main

import "testing"

// TestValidateDaemonPathFlags covers the whitespace guard for the four
// required daemon path flags. A whitespace-only value (e.g. from a shell
// quoting slip) must be treated as missing so the daemon fails with a clear
// error rather than a confusing OS-level failure.
func TestValidateDaemonPathFlags(t *testing.T) {
	const validSocket = "/run/ardur/kernelcapture/control.sock"
	const validSeccomp = "/run/ardur/kernelcapture/seccomp.sock"
	const validEvidence = "/var/lib/ardur/kernelcapture/evidence"
	const validState = "/var/lib/ardur/kernelcapture/state"

	cases := []struct {
		name          string
		socket        string
		seccompSocket string
		evidenceDir   string
		stateDir      string
		wantError     bool
	}{
		{"all valid", validSocket, validSeccomp, validEvidence, validState, false},
		{"empty socket", "", validSeccomp, validEvidence, validState, true},
		{"whitespace socket", "   ", validSeccomp, validEvidence, validState, true},
		{"empty seccomp", validSocket, "", validEvidence, validState, true},
		{"whitespace seccomp", validSocket, "\t", validEvidence, validState, true},
		{"empty evidence", validSocket, validSeccomp, "", validState, true},
		{"whitespace evidence", validSocket, validSeccomp, " \n ", validState, true},
		{"empty state", validSocket, validSeccomp, validEvidence, "", true},
		{"whitespace state", validSocket, validSeccomp, validEvidence, "  ", true},
		{"all whitespace", "  ", "\t", "\n", " ", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := validateDaemonPathFlags(tc.socket, tc.seccompSocket, tc.evidenceDir, tc.stateDir)
			if tc.wantError && msg == "" {
				t.Fatalf("expected error message, got empty string")
			}
			if !tc.wantError && msg != "" {
				t.Fatalf("expected no error, got: %s", msg)
			}
		})
	}
}
