package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsInvalidArgumentsWithoutEchoingPrivatePaths(t *testing.T) {
	privatePath := filepath.Join(t.TempDir(), "private-output")
	var stdout bytes.Buffer
	if code := run([]string{"--output-dir", privatePath}, &stdout); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if strings.Contains(stdout.String(), privatePath) {
		t.Fatalf("stdout exposed private path: %s", stdout.String())
	}
	var summary commandSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil || summary.ErrorCode != "arguments_invalid" {
		t.Fatalf("summary=%+v error=%v", summary, err)
	}
}

func TestRunRejectsUnknownProfileBeforeMeasurement(t *testing.T) {
	privatePath := filepath.Join(t.TempDir(), "private-output")
	var stdout bytes.Buffer
	if code := run([]string{
		"--daemon-bin", "/not/a/daemon",
		"--reference-daemon-bin", "/not/a/private-reference-daemon",
		"--workload-bin", "/not/a/workload",
		"--source-sha", strings.Repeat("a", 40),
		"--reference-source-sha", strings.Repeat("b", 40),
		"--output-dir", privatePath,
		"--profile", "unbounded",
	}, &stdout); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	var summary commandSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil || summary.ErrorCode != "arguments_invalid" {
		t.Fatalf("summary=%+v error=%v", summary, err)
	}
	if strings.Contains(stdout.String(), privatePath) {
		t.Fatalf("stdout exposed private path: %s", stdout.String())
	}
}

// TestRunRejectsWhitespaceOnlyRequiredFlags mirrors the auditbench-oracle
// whitespace guard: each of the six required flags must reject whitespace-only
// input instead of falling through to a confusing downstream error.
func TestRunRejectsWhitespaceOnlyRequiredFlags(t *testing.T) {
	validSHA := strings.Repeat("a", 40)
	otherSHA := strings.Repeat("b", 40)
	cases := []struct {
		name string
		args []string
	}{
		{"daemon-bin", []string{"--daemon-bin", "   ", "--reference-daemon-bin", "/ref", "--workload-bin", "/wl", "--source-sha", validSHA, "--reference-source-sha", otherSHA, "--output-dir", "/out", "--profile", "ci"}},
		{"reference-daemon-bin", []string{"--daemon-bin", "/d", "--reference-daemon-bin", "	", "--workload-bin", "/wl", "--source-sha", validSHA, "--reference-source-sha", otherSHA, "--output-dir", "/out", "--profile", "ci"}},
		{"workload-bin", []string{"--daemon-bin", "/d", "--reference-daemon-bin", "/ref", "--workload-bin", "  ", "--source-sha", validSHA, "--reference-source-sha", otherSHA, "--output-dir", "/out", "--profile", "ci"}},
		{"source-sha", []string{"--daemon-bin", "/d", "--reference-daemon-bin", "/ref", "--workload-bin", "/wl", "--source-sha", "   ", "--reference-source-sha", otherSHA, "--output-dir", "/out", "--profile", "ci"}},
		{"reference-source-sha", []string{"--daemon-bin", "/d", "--reference-daemon-bin", "/ref", "--workload-bin", "/wl", "--source-sha", validSHA, "--reference-source-sha", "	", "--output-dir", "/out", "--profile", "ci"}},
		{"output-dir", []string{"--daemon-bin", "/d", "--reference-daemon-bin", "/ref", "--workload-bin", "/wl", "--source-sha", validSHA, "--reference-source-sha", otherSHA, "--output-dir", "  ", "--profile", "ci"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout bytes.Buffer
			if code := run(tc.args, &stdout); code != 2 {
				t.Fatalf("run exit = %d for whitespace-only %s, want 2; stdout=%q", code, tc.name, stdout.String())
			}
			var summary commandSummary
			if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil || summary.ErrorCode != "arguments_invalid" {
				t.Fatalf("whitespace-only %s did not produce arguments_invalid: summary=%+v err=%v", tc.name, summary, err)
			}
		})
	}
}
