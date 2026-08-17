package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunRejectsWhitespaceOnlyInput(t *testing.T) {
	args := []string{"-in", "   ", "-out", "/tmp/ignore"}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != exitInvalid {
		t.Fatalf("run exit = %d, want %d; stdout=%q stderr=%q", code, exitInvalid, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "usage:") || stdout.Len() != 0 {
		t.Fatalf("expected usage on stderr and empty stdout: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunRejectsWhitespaceOnlyOutput(t *testing.T) {
	args := []string{"-in", "/tmp/some.json", "-out", "\t"}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != exitInvalid {
		t.Fatalf("run exit = %d, want %d; stdout=%q stderr=%q", code, exitInvalid, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "usage:") || stdout.Len() != 0 {
		t.Fatalf("expected usage on stderr and empty stdout: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunRejectsExtraPositionalArgs(t *testing.T) {
	args := []string{"-in", "capture.json", "-out", "corpus/", "leftover"}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != exitInvalid {
		t.Fatalf("run exit = %d, want %d; stdout=%q stderr=%q", code, exitInvalid, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "usage:") || stdout.Len() != 0 {
		t.Fatalf("expected usage on stderr and empty stdout: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunRejectsMissingFlags(t *testing.T) {
	args := []string{}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != exitInvalid {
		t.Fatalf("run exit = %d, want %d; stdout=%q stderr=%q", code, exitInvalid, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "usage:") || stdout.Len() != 0 {
		t.Fatalf("expected usage on stderr and empty stdout: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
