package main

import "testing"

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
