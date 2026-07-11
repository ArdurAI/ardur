package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGeneratedFixtureMatchesCommittedArtifact(t *testing.T) {
	document, err := generateFixture()
	if err != nil {
		t.Fatalf("generate fixture: %v", err)
	}
	generated, err := encodeFixture(document)
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	path := filepath.Join("..", "..", "..", "docs", "specs", "conformance", "aat-draft01-v0.2", "fixture.json")
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read committed fixture: %v", err)
	}
	if !bytes.Equal(generated, committed) {
		t.Fatal("generated fixture differs from committed artifact; run go run ./cmd/aat-draft01-fixture")
	}
}
