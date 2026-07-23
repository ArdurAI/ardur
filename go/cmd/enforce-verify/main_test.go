package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestMain builds the enforce-verify binary into a temp dir so table-driven
// tests can invoke it as a subprocess with various positional inputs.
var enforceVerifyBinary string

func TestMain(m *testing.M) {
	bin, err := os.MkdirTemp("", "enforce-verify-test-*")
	if err != nil {
		panic(err)
	}
	enforceVerifyBinary = filepath.Join(bin, "enforce-verify")
	cmd := exec.Command("go", "build", "-o", enforceVerifyBinary, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(bin)
	os.Exit(code)
}

func TestEnforceVerify_EmptyPathArg(t *testing.T) {
	cmd := exec.Command(enforceVerifyBinary, "")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected exit error for empty path arg, got success")
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 2 {
			t.Errorf("expected exit code 2, got %d", exitErr.ExitCode())
		}
	}
	got := string(out)
	want := "non-empty path after trimming whitespace"
	if !containsStr(got, want) {
		t.Errorf("expected stderr to contain %q, got:\n%s", want, got)
	}
}

func TestEnforceVerify_WhitespacePathArg(t *testing.T) {
	cmd := exec.Command(enforceVerifyBinary, "   ")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected exit error for whitespace path arg, got success")
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 2 {
			t.Errorf("expected exit code 2, got %d", exitErr.ExitCode())
		}
	}
	got := string(out)
	want := "non-empty path after trimming whitespace"
	if !containsStr(got, want) {
		t.Errorf("expected stderr to contain %q, got:\n%s", want, got)
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
