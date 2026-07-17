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
