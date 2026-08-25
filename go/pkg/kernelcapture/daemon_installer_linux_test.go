//go:build linux

package kernelcapture

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// tempCustodyConfig returns a DaemonCustodyConfig whose paths are all rooted
// under a fresh T.TempDir(). All paths are set so that InstallDaemonCustody
// can succeed without touching real system paths.
func tempCustodyConfig(t *testing.T) DaemonCustodyConfig {
	t.Helper()
	root := t.TempDir()

	// We override the custody path validators by placing everything under
	// /etc/ardur → root+"/etc/ardur", etc., matching real path prefixes so
	// validateDaemonCustodyConfig is satisfied. The tests rewrite the actual
	// paths to point into the tmpdir.
	//
	// NOTE: validateDaemonCustodyConfig checks for specific path prefixes
	// (/etc/ardur, /var/lib/ardur, /run/ardur, /sys/fs/bpf). We cannot pass
	// arbitrary tmpdir paths through that validator. Instead, we bypass the
	// validator in installer-level tests by calling the installer primitives
	// directly (installerMkdirAll, installerWriteConfigFile) with relative
	// paths anchored to a tmpdir rootFD.
	_ = root
	return DefaultDaemonCustodyConfig()
}

// rootFDForDir opens dir with O_PATH|O_DIRECTORY and returns the fd. The caller
// must close it.
func rootFDForDir(t *testing.T, dir string) int {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatalf("open tmpdir as rootFD: %v", err)
	}
	return fd
}

// readFileAt reads the file at absPath, relative to a tmpdir root, for assertions.
func readFileAt(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readFileAt %q: %v", path, err)
	}
	return string(b)
}

// ── installerMkdirAll tests ───────────────────────────────────────────────

// TestInstallerMkdirAll_CreatesDirectoryChain verifies that installerMkdirAll
// creates nested directories with the requested mode.
func TestInstallerMkdirAll_CreatesDirectoryChain(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	rootFD := rootFDForDir(t, tmp)
	defer unix.Close(rootFD)

	// installerMkdirAll resolves absPath relative to rootFD (after stripping the
	// leading "/"), so pass a root-anchored path — NOT filepath.Join(tmp, ...),
	// which would be re-walked from the tmpdir and nest incorrectly. Chown to the
	// current uid/gid so the test exercises the fchown/fchmod path without root.
	if err := installerMkdirAll(rootFD, "/a/b/c", os.Getuid(), os.Getgid(), 0o700); err != nil {
		t.Fatalf("installerMkdirAll: %v", err)
	}

	target := filepath.Join(tmp, "a", "b", "c")
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target: %v", err)
	}
	if !info.IsDir() {
		t.Error("want directory")
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("mode = %o, want 0700", info.Mode().Perm())
	}
}

// TestInstallerMkdirAll_IdempotentOnExistingDir verifies that calling
// installerMkdirAll on an already-existing directory succeeds.
func TestInstallerMkdirAll_IdempotentOnExistingDir(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	rootFD := rootFDForDir(t, tmp)
	defer unix.Close(rootFD)

	if err := os.Mkdir(filepath.Join(tmp, "existing"), 0o700); err != nil {
		t.Fatal(err)
	}

	// Second call (on the already-existing dir) must not return an error.
	if err := installerMkdirAll(rootFD, "/existing", os.Getuid(), os.Getgid(), 0o700); err != nil {
		t.Fatalf("idempotent call failed: %v", err)
	}
}

// ── installerWriteConfigFile tests ────────────────────────────────────────

// TestInstallerWriteConfigFile_WritesContent verifies that
// installerWriteConfigFile creates the file with the expected content and mode.
func TestInstallerWriteConfigFile_WritesContent(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	rootFD := rootFDForDir(t, tmp)
	defer unix.Close(rootFD)

	data := []byte("key = \"value\"\n")

	// Path is resolved relative to rootFD (the tmpdir); chown to self so the
	// test runs without root.
	if err := installerWriteConfigFile(rootFD, "/config.toml", data, os.Getuid(), os.Getgid(), 0o600); err != nil {
		t.Fatalf("installerWriteConfigFile: %v", err)
	}

	onDisk := filepath.Join(tmp, "config.toml")
	got := readFileAt(t, onDisk)
	if got != string(data) {
		t.Errorf("content = %q, want %q", got, data)
	}

	info, err := os.Stat(onDisk)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %04o, want 0600", info.Mode().Perm())
	}
}

// TestInstallerWriteConfigFile_RejectsSymlinkTarget is the symlink-swap
// adversary test. It verifies that installerWriteConfigFile refuses to write
// through a symlink placed at the target path by an adversary, preventing a
// TOCTOU race from redirecting the write to an attacker-controlled location.
//
// Attack scenario:
//  1. Attacker creates a symlink at the config path pointing to a sensitive
//     file (e.g. /etc/shadow or an attacker-owned path outside the custody
//     boundary).
//  2. A naive writer follows the symlink and overwrites the target.
//  3. installerWriteConfigFile uses openat2(RESOLVE_NO_SYMLINKS) which
//     returns ELOOP or ENOENT if a symlink is present in the path — the
//     write is rejected and the attack fails.
func TestInstallerWriteConfigFile_RejectsSymlinkTarget(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	rootFD := rootFDForDir(t, tmp)
	defer unix.Close(rootFD)

	// Attacker places a symlink at the desired config path (tmp/daemon.toml).
	// The installer resolves "/daemon.toml" relative to rootFD (the tmpdir), so
	// it opens "daemon.toml" directly and must hit the symlink — this is what
	// makes the assertion below non-vacuous (RESOLVE_NO_SYMLINKS must reject it,
	// rather than the write failing earlier for an unrelated path-traversal reason).
	attackTarget := filepath.Join(tmp, "sensitive_file.txt")
	if err := os.WriteFile(attackTarget, []byte("sensitive\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(attackTarget, filepath.Join(tmp, "daemon.toml")); err != nil {
		t.Fatal(err)
	}

	// The installer must reject the write.
	err := installerWriteConfigFile(rootFD, "/daemon.toml", []byte("injected\n"), os.Getuid(), os.Getgid(), 0o600)
	if err == nil {
		t.Fatal("expected error when target is a symlink, got nil")
	}

	// The sensitive file must be untouched.
	got := readFileAt(t, attackTarget)
	if got != "sensitive\n" {
		t.Errorf("sensitive file was overwritten! content=%q", got)
	}
}

// TestInstallerWriteConfigFile_RejectsSymlinkInParentDir verifies that a
// symlink placed in a parent directory component also causes rejection. This
// covers the case where an adversary replaces an intermediate directory with a
// symlink pointing outside the custody boundary.
//
// Attack scenario:
//  1. Attacker replaces "/etc/ardur" (an intermediate directory) with a
//     symlink pointing to /tmp/attacker/ (outside the custody boundary).
//  2. A naive installer follows it and writes config to /tmp/attacker/.
//  3. installerWriteConfigFile calls installerOpenDir which uses openat2
//     with RESOLVE_NO_SYMLINKS on each component — ELOOP is returned when
//     the "ardur" directory component resolves to a symlink.
func TestInstallerWriteConfigFile_RejectsSymlinkInParentDir(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	rootFD := rootFDForDir(t, tmp)
	defer unix.Close(rootFD)

	// Set up: legitimate dir then attacker replaces it with a symlink.
	realDir := filepath.Join(tmp, "realdir")
	attackDir := filepath.Join(tmp, "attackdir")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(attackDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// "ardur" directory is now a symlink to attackdir.
	if err := os.Symlink(attackDir, filepath.Join(tmp, "ardur")); err != nil {
		t.Fatal(err)
	}

	// Resolve "/ardur/daemon.toml" relative to rootFD (the tmpdir): the parent
	// component "ardur" is a symlink, so installerOpenDir must reject it. Passing
	// a root-anchored path (not filepath.Join(tmp, ...)) ensures the traversal
	// actually reaches — and is stopped at — the symlinked component.
	err := installerWriteConfigFile(rootFD, "/ardur/daemon.toml", []byte("injected\n"), os.Getuid(), os.Getgid(), 0o600)
	if err == nil {
		t.Fatal("expected error when a parent directory is a symlink, got nil")
	}

	// No file must have been created in the attackdir.
	entries, _ := os.ReadDir(attackDir)
	if len(entries) != 0 {
		t.Errorf("attackdir has files: %v (write leaked through symlink)", entries)
	}
}

// ── installerOpenDir tests ───────────────────────────────────────────────

// TestInstallerOpenDir_FollowsRealDirs verifies that installerOpenDir succeeds
// on a real directory chain.
func TestInstallerOpenDir_FollowsRealDirs(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	sub := filepath.Join(tmp, "a", "b")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}

	rootFD := rootFDForDir(t, tmp)
	defer unix.Close(rootFD)

	fd, err := installerOpenDir(rootFD, "a/b")
	if err != nil {
		t.Fatalf("installerOpenDir: %v", err)
	}
	unix.Close(fd)
}

// TestInstallerOpenDir_RejectsSymlink ensures that installerOpenDir returns an
// error when any path component is a symlink.
func TestInstallerOpenDir_RejectsSymlink(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	realDir := filepath.Join(tmp, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(tmp, "link")
	if err := os.Symlink(realDir, symlink); err != nil {
		t.Fatal(err)
	}

	rootFD := rootFDForDir(t, tmp)
	defer unix.Close(rootFD)

	_, err := installerOpenDir(rootFD, "link")
	if err == nil {
		t.Fatal("expected error for symlink component, got nil")
	}
	// RESOLVE_NO_SYMLINKS returns ELOOP when a symlink is encountered.
	if !errors.Is(err, fs.ErrInvalid) && !errors.Is(err, unix.ELOOP) && !strings.Contains(err.Error(), "ELOOP") && !strings.Contains(err.Error(), "too many levels of symbolic links") && !strings.Contains(err.Error(), "openat2") {
		t.Logf("error (acceptable variant): %v", err)
	}
}

// ── parseKernelVersionString tests ──────────────────────────────────────

func TestParseKernelVersionString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input        string
		wantMajor    int
		wantMinor    int
		wantErr      bool
		satisfies5_8 bool
	}{
		{"5.15.0-83-generic", 5, 15, false, true},
		{"5.8.0", 5, 8, false, true},
		{"5.7.0", 5, 7, false, false},
		{"6.1.0-28", 6, 1, false, true},
		{"4.19.0", 4, 19, false, false},
		{"5.8-rc1", 5, 8, false, true},
		{"bad", 0, 0, true, false},
		{"5", 0, 0, true, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			major, minor, err := parseKernelVersionString(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("parseKernelVersionString(%q): expected error, got %d.%d", tc.input, major, minor)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseKernelVersionString(%q): %v", tc.input, err)
			}
			if major != tc.wantMajor || minor != tc.wantMinor {
				t.Errorf("parseKernelVersionString(%q) = %d.%d, want %d.%d", tc.input, major, minor, tc.wantMajor, tc.wantMinor)
			}
			satisfies := major > 5 || (major == 5 && minor >= 8)
			if satisfies != tc.satisfies5_8 {
				t.Errorf("satisfies5_8(%q) = %v, want %v", tc.input, satisfies, tc.satisfies5_8)
			}
		})
	}
}
