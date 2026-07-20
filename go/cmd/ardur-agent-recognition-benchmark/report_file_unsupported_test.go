//go:build !linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

func TestWriteReportFailsClosedOnUnsupportedPlatform(t *testing.T) {
	report := &kernelcapture.AgentRecognitionBenchmarkReport{
		SchemaVersion:  kernelcapture.AgentRecognitionBenchmarkReportSchema,
		ArtifactSHA256: strings.Repeat("a", 64),
	}
	output := filepath.Join(t.TempDir(), "output")

	err := writeReport(output, report)
	if err == nil || !strings.Contains(err.Error(), "secure benchmark report publication is unsupported outside Linux") {
		t.Fatalf("writeReport() error = %v, want unsupported-platform error", err)
	}
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
		t.Fatalf("unsupported platform created output: %v", statErr)
	}
}
