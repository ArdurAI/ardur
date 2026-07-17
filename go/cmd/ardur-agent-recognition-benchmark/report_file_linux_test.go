//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

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

func TestWriteReportRejectsSymlinkedParentAndExistingDestination(t *testing.T) {
	report := &kernelcapture.AgentRecognitionBenchmarkReport{SchemaVersion: kernelcapture.AgentRecognitionBenchmarkReportSchema, ArtifactSHA256: strings.Repeat("a", 64)}
	realParent := t.TempDir()
	linkRoot := t.TempDir()
	linkParent := filepath.Join(linkRoot, "parent")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatal(err)
	}
	if err := writeReport(filepath.Join(linkParent, "output"), report); err == nil {
		t.Fatal("symlinked output parent was accepted")
	}
	if _, err := os.Stat(filepath.Join(realParent, "output")); !os.IsNotExist(err) {
		t.Fatalf("symlink target was modified: %v", err)
	}

	staleOutput := filepath.Join(t.TempDir(), "output")
	if err := os.Mkdir(staleOutput, 0o700); err != nil {
		t.Fatal(err)
	}
	staleTarget := filepath.Join(t.TempDir(), "sentinel")
	if err := os.WriteFile(staleTarget, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(staleTarget, filepath.Join(staleOutput, benchmarkReportTemporaryFilename)); err != nil {
		t.Fatal(err)
	}
	if err := writeReport(staleOutput, report); err != nil {
		t.Fatalf("stale temporary symlink recovery failed: %v", err)
	}
	if content, err := os.ReadFile(staleTarget); err != nil || string(content) != "sentinel" {
		t.Fatalf("stale symlink target content=%q error=%v", content, err)
	}

	output := filepath.Join(t.TempDir(), "output")
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(output, reportFilename)
	if err := os.WriteFile(path, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeReport(output, report); err == nil {
		t.Fatal("existing report destination was replaced")
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "sentinel" {
		t.Fatalf("existing destination content=%q error=%v", content, err)
	}
}
