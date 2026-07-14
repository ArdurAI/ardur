//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

func TestLoadAgentFingerprintRegistryValidatesOwnershipModeTypeAndSize(t *testing.T) {
	directory := t.TempDir()
	valid := filepath.Join(directory, "registry.json")
	if err := os.WriteFile(valid, []byte(validAgentFingerprintRegistryJSON()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAgentFingerprintRegistry(valid, uint32(os.Getuid())); err != nil {
		t.Fatalf("valid registry rejected: %v", err)
	}

	symlink := filepath.Join(directory, "registry-link.json")
	if err := os.Symlink(valid, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAgentFingerprintRegistry(symlink, uint32(os.Getuid())); err == nil {
		t.Fatal("symlink registry was accepted")
	}

	if err := os.Chmod(valid, 0o620); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAgentFingerprintRegistry(valid, uint32(os.Getuid())); err == nil {
		t.Fatal("group-writable registry was accepted")
	}
	if err := os.Chmod(valid, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAgentFingerprintRegistry(valid, uint32(os.Getuid())+1); err == nil {
		t.Fatal("wrong-owner registry was accepted")
	}

	if _, err := loadAgentFingerprintRegistry(directory, uint32(os.Getuid())); err == nil {
		t.Fatal("directory registry was accepted")
	}
	oversized := filepath.Join(directory, "oversized.json")
	if err := os.WriteFile(oversized, []byte(strings.Repeat("x", kernelcapture.MaxAgentFingerprintRegistryBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAgentFingerprintRegistry(oversized, uint32(os.Getuid())); err == nil {
		t.Fatal("oversized registry was accepted")
	}
}

func validAgentFingerprintRegistryJSON() string {
	digest := sha256.Sum256([]byte("trusted executable"))
	return fmt.Sprintf(`{"schema_version":%q,"registry_version":"operator.v1","rules":[{"rule_id":"native.codex","agent_type":"codex_cli","expected_sha256":[%q]}]}`,
		kernelcapture.AgentFingerprintRegistrySchema, hex.EncodeToString(digest[:]))
}
