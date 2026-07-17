package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

func TestRunEmbeddedCorpusProducesDeterministicPassingReport(t *testing.T) {
	var firstOut, firstErr bytes.Buffer
	if code := run(nil, &firstOut, &firstErr); code != exitPassed {
		t.Fatalf("run exit = %d, stderr = %q", code, firstErr.String())
	}
	var report kernelcapture.AgentRecognitionEvaluationReport
	if err := json.Unmarshal(firstOut.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if !report.Gate.Passed || report.CorpusSampleCount != 36 || report.NameOnly.SampleCount != 28 || report.ContentFingerprint.SampleCount != 8 || report.ClaimBoundary != "maintained_corpus_contract_only_not_population_accuracy_provenance_or_identity_assurance" {
		t.Fatalf("unsafe or incomplete report: %+v", report)
	}
	var secondOut, secondErr bytes.Buffer
	if code := run(nil, &secondOut, &secondErr); code != exitPassed {
		t.Fatalf("second run exit = %d, stderr = %q", code, secondErr.String())
	}
	if !bytes.Equal(firstOut.Bytes(), secondOut.Bytes()) {
		t.Fatal("default evaluation output is not deterministic")
	}
}

func TestRunReturnsGateFailureWithCompleteReport(t *testing.T) {
	corpus, _, err := kernelcapture.EmbeddedAgentRecognitionCorpus()
	if err != nil {
		t.Fatal(err)
	}
	for index := range corpus.Samples {
		if corpus.Samples[index].SampleID == "claude.native" {
			corpus.Samples[index].Input = kernelcapture.AgentRecognitionInput{Comm: "renamed-claude", ExecutableBasename: "renamed-claude"}
		}
	}
	path := filepath.Join(t.TempDir(), "failing-corpus.json")
	raw, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-corpus", path}, &stdout, &stderr); code != exitGateFailed {
		t.Fatalf("run exit = %d, want %d; stderr = %q", code, exitGateFailed, stderr.String())
	}
	var report kernelcapture.AgentRecognitionEvaluationReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("gate failure did not emit a complete report: %v", err)
	}
	if report.Gate.Passed || report.NameOnly.SupportedRecall.Numerator != 8 || report.NameOnly.SupportedRecall.Denominator != 9 {
		t.Fatalf("unexpected failing report: %+v", report.Gate)
	}
}

func TestRunRejectsInvalidInputWithoutEchoingHostPath(t *testing.T) {
	path := "/private/operator/secret/corpus.json"
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-corpus", path}, &stdout, &stderr); code != exitInvalid {
		t.Fatalf("run exit = %d, want %d", code, exitInvalid)
	}
	if strings.Contains(stderr.String(), path) || stdout.Len() != 0 {
		t.Fatalf("invalid-input output leaked a path or report: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunRejectsUnknownThresholdFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "thresholds.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"ardur.agent_recognition_thresholds.v0.1","unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-thresholds", path}, &stdout, &stderr); code != exitInvalid {
		t.Fatalf("run exit = %d, want %d", code, exitInvalid)
	}
	if !strings.Contains(stderr.String(), "unknown field") || stdout.Len() != 0 {
		t.Fatalf("unexpected invalid-threshold output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunTreatsOutputFailureAsInvalidExecution(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(nil, failingWriter{}, &stderr); code != exitInvalid {
		t.Fatalf("run exit = %d, want %d", code, exitInvalid)
	}
	if !strings.Contains(stderr.String(), "write evaluation report") {
		t.Fatalf("missing output failure: %q", stderr.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("output unavailable")
}
