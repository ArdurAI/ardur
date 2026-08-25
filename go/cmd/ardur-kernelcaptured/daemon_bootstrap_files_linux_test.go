//go:build linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

func TestCollectBootstrapFileIdentitiesUsesExactRegularFiles(t *testing.T) {
	dir := t.TempDir()
	executable := filepath.Join(dir, "python3")
	script := filepath.Join(dir, "agent.py")
	for _, path := range []string{executable, script} {
		if err := os.WriteFile(path, []byte("test"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(script, filepath.Join(dir, "agent-link.py")); err != nil {
		t.Fatal(err)
	}

	got := collectBootstrapFileIdentities(
		executable,
		dir,
		[]string{"python3", "agent.py", "agent-link.py", "--flag", "missing.txt"},
	)
	if len(got) != 2 {
		t.Fatalf("identities = %+v, want executable and one deduplicated script identity", got)
	}
	wantExecutable := fileIdentity(t, executable)
	wantScript := fileIdentity(t, script)
	if got[0] != wantExecutable || got[1] != wantScript {
		t.Fatalf("identities = %+v, want [%+v %+v]", got, wantExecutable, wantScript)
	}
}

func TestCollectBootstrapFileIdentitiesCapsObservedArguments(t *testing.T) {
	dir := t.TempDir()
	paths := make([]string, 0, kernelcapture.MaxBootstrapFileIdentities+2)
	for i := 0; i < kernelcapture.MaxBootstrapFileIdentities+2; i++ {
		path := filepath.Join(dir, string(rune('a'+i)))
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	argv := append([]string{paths[0]}, paths[1:]...)
	got := collectBootstrapFileIdentities(paths[0], dir, argv)
	if len(got) != kernelcapture.MaxBootstrapFileIdentities {
		t.Fatalf("identity count = %d, want cap %d", len(got), kernelcapture.MaxBootstrapFileIdentities)
	}
}

func fileIdentity(t *testing.T, path string) kernelcapture.BootstrapFile {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat payload for %s is %T", path, info.Sys())
	}
	return kernelcapture.BootstrapFile{Path: path, Inode: stat.Ino}
}
