//go:build linux

package kernelcapture

import "testing"

func TestProcessExecRecognitionCommKeyUsesExactNULTerminatedShape(t *testing.T) {
	key, err := processExecRecognitionCommKey("codex")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(key[:5]); got != "codex" {
		t.Fatalf("key prefix = %q, want codex", got)
	}
	for index, value := range key[5:] {
		if value != 0 {
			t.Fatalf("key byte %d = %d, want NUL padding", index+5, value)
		}
	}
}

func TestProcessExecRecognitionCommKeyRejectsPathAndOverflow(t *testing.T) {
	for _, value := range []string{"/usr/bin/codex", "sixteen-byte-name"} {
		if _, err := processExecRecognitionCommKey(value); err == nil {
			t.Fatalf("invalid comm %q unexpectedly accepted", value)
		}
	}
}
