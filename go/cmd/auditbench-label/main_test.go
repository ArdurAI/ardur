package main

import (
	"strings"
	"testing"
)

func TestRunBundleRejectsWhitespaceOnlyFlags(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"study-id", []string{"-study-id", "   ", "-view", "oracle", "-source", "src.json", "-out", "out.json"}},
		{"view", []string{"-study-id", "AB-01", "-view", "   ", "-source", "src.json", "-out", "out.json"}},
		{"source", []string{"-study-id", "AB-01", "-view", "oracle", "-source", "\t", "-out", "out.json"}},
		{"output", []string{"-study-id", "AB-01", "-view", "oracle", "-source", "src.json", "-out", "  "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runBundle(tc.args)
			if err == nil {
				t.Fatalf("runBundle accepted whitespace-only %s flag; expected usage error", tc.name)
			}
			if !strings.Contains(err.Error(), "usage:") {
				t.Fatalf("runBundle error for %s did not contain usage: %v", tc.name, err)
			}
		})
	}
}

func TestRunAdjudicateRejectsWhitespaceOnlyFlags(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"study-id", []string{"-study-id", "   ", "-annotations", "ann.json", "-out", "out.json"}},
		{"annotations", []string{"-study-id", "AB-01", "-annotations", "  ", "-out", "out.json"}},
		{"output", []string{"-study-id", "AB-01", "-annotations", "ann.json", "-out", "\t"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runAdjudicate(tc.args)
			if err == nil {
				t.Fatalf("runAdjudicate accepted whitespace-only %s flag; expected usage error", tc.name)
			}
			if !strings.Contains(err.Error(), "usage:") {
				t.Fatalf("runAdjudicate error for %s did not contain usage: %v", tc.name, err)
			}
		})
	}
}

func TestRunBundleRejectsExtraPositionalArgs(t *testing.T) {
	args := []string{"-study-id", "AB-01", "-view", "oracle", "-source", "src.json", "-out", "out.json", "extra"}
	if err := runBundle(args); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("runBundle should reject extra positional arg: err=%v", err)
	}
}

func TestRunAdjudicateRejectsExtraPositionalArgs(t *testing.T) {
	args := []string{"-study-id", "AB-01", "-annotations", "ann.json", "-out", "out.json", "extra"}
	if err := runAdjudicate(args); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("runAdjudicate should reject extra positional arg: err=%v", err)
	}
}
