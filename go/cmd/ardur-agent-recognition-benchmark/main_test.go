package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
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
	if code := run([]string{"--daemon-bin", "/not/a/daemon", "--workload-bin", "/not/a/workload", "--source-sha", strings.Repeat("a", 40), "--output-dir", privatePath, "--profile", "unbounded"}, &stdout); code != 2 {
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

func TestWriteReportUsesOwnerOnlyAtomicOutputAndRejectsSymlinkDirectory(t *testing.T) {
	report := &kernelcapture.AgentRecognitionBenchmarkReport{SchemaVersion: kernelcapture.AgentRecognitionBenchmarkReportSchema, ArtifactSHA256: strings.Repeat("a", 64)}
	output := filepath.Join(t.TempDir(), "output")
	if err := writeReport(output, report); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(output); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("output mode=%v error=%v", info.Mode().Perm(), err)
	}
	path := filepath.Join(output, reportFilename)
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("report mode=%v error=%v", info.Mode().Perm(), err)
	}

	link := filepath.Join(t.TempDir(), "output-link")
	if err := os.Symlink(output, link); err != nil {
		t.Fatal(err)
	}
	if err := writeReport(link, report); err == nil {
		t.Fatal("symlink output directory was accepted")
	}
}
