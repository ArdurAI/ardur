package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestShouldUseDefaultPackDir covers the positional pack-dir fallback: an
// absent or whitespace-only argument must fall back to the detected default
// so a stray "   " (e.g. from a shell quoting slip) does not get passed to
// live.EvaluatePack as a literal directory name.
func TestShouldUseDefaultPackDir(t *testing.T) {
	cases := []struct {
		name string
		arg  string
		want bool
	}{
		{"empty", "", true},
		{"spaces", "   ", true},
		{"tab", "\t", true},
		{"newline", "\n", true},
		{"mixed whitespace", " \t\n ", true},
		{"relative path", "./benchmark/testdata", false},
		{"absolute path", "/srv/ardur/benchmark/testdata", false},
		{"path with surrounding spaces", "  ./benchmark/testdata  ", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldUseDefaultPackDir(tc.arg); got != tc.want {
				t.Fatalf("shouldUseDefaultPackDir(%q) = %v, want %v", tc.arg, got, tc.want)
			}
		})
	}
}

// --- -out empty/whitespace validation tests ---
//
// These tests build the benchcheck binary into a temp dir and invoke it as a
// subprocess so the -out flag validation is exercised at the real CLI boundary.

var benchcheckBinary string

func TestMain(m *testing.M) {
	bin, err := os.MkdirTemp("", "benchcheck-test-*")
	if err != nil {
		panic(err)
	}
	benchcheckBinary = filepath.Join(bin, "benchcheck")
	cmd := exec.Command("go", "build", "-o", benchcheckBinary, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(bin)
	os.Exit(code)
}

func TestBenchcheck_EmptyOutDir(t *testing.T) {
	cmd := exec.Command(benchcheckBinary, "-out", "")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected exit error for empty -out, got success")
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 2 {
			t.Errorf("expected exit code 2, got %d", exitErr.ExitCode())
		}
	}
	got := string(out)
	want := "must be a non-empty path after trimming whitespace"
	if !containsStr(got, want) {
		t.Errorf("expected stderr to contain %q, got:\n%s", want, got)
	}
}

func TestBenchcheck_WhitespaceOutDir(t *testing.T) {
	tmpDir := t.TempDir()
	cmd := exec.Command(benchcheckBinary, "-out", "   ")
	cmd.Dir = tmpDir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected exit error for whitespace -out, got success")
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 2 {
			t.Errorf("expected exit code 2, got %d", exitErr.ExitCode())
		}
	}
	got := string(out)
	want := "must be a non-empty path after trimming whitespace"
	if !containsStr(got, want) {
		t.Errorf("expected stderr to contain %q, got:\n%s", want, got)
	}
	// Verify no whitespace-named directory was created in CWD.
	entries, _ := os.ReadDir(tmpDir)
	for _, e := range entries {
		if e.Name() == "   " {
			t.Errorf("whitespace-named directory was created in CWD (CWD pollution)")
		}
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
