//go:build linux

package kernelcapture

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// InstallResult describes the outcome of a daemon installation.
type InstallResult struct {
	// PathsCreated lists paths successfully created or verified.
	PathsCreated []string
	// PreflightReport is the post-install custody assertion result.
	PreflightReport DaemonPreflightReport
}

// InstallDaemonCustody creates the root-owned custody paths required by the
// kernelcapture daemon and writes the default daemon configuration file.
//
// The installer is TOCTOU-safe: every directory create and file write is
// anchored to an fd opened with openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH),
// and ownership/mode is applied via fchown/fchmod on the resulting fd so that
// no name-based TOCTOU window exists between create and permission-set.
//
// After all paths are created the installer runs InspectDaemonCustodyPreflight
// to assert the on-disk state matches the declared custody spec. If the
// assertion fails the error is returned and the caller must remediate.
//
// Requires: root (UID 0) and CAP_SYS_ADMIN. Returns ErrDaemonInstallerNotRoot
// if called without root privileges.
//
// NOT in scope for this function:
//   - systemd unit installation or service enable/start (handled by CLI)
//   - bpffs map pinning (handled by the daemon at startup)
//   - socket bind (handled by the daemon at startup)
//   - /run/ardur/kernelcapture (RuntimeDirectory= in the unit creates this on boot)
//
// The config file written always stamps SensorVersion. If a config already
// exists at cfg.ConfigPath with a newer version, InstallDaemonCustody refuses
// with ErrSensorVersionDowngradeRefused unless WithAllowDowngrade(true) is
// passed — an upgrade-in-place must not silently regress a host to an older
// sensor without the operator asking for it.
func InstallDaemonCustody(cfg DaemonCustodyConfig, optFns ...InstallOption) (*InstallResult, error) {
	cfg = normalizeDaemonCustodyConfig(cfg)
	opts := resolveInstallOptions(optFns)

	if os.Getuid() != 0 {
		return nil, ErrDaemonInstallerNotRoot
	}

	if existing, readErr := os.ReadFile(cfg.ConfigPath); readErr == nil {
		if err := checkSensorVersionDowngrade(SensorVersion, existing, opts.allowDowngrade); err != nil {
			return nil, err
		}
	}

	result := &InstallResult{}

	// Open "/" as the anchor dirfd for all RESOLVE_BENEATH traversals.
	rootFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("open /: %w", err)
	}
	defer unix.Close(rootFD)

	// Directories to create in order (parents before children). Enumerate the
	// distinct paths we need: /etc/ardur for config, and the state dir and its
	// parent under /var/lib/ardur.
	type dirSpec struct {
		path string
		mode fs.FileMode
	}
	stateDirParent := filepath.Dir(cfg.StateDir) // /var/lib/ardur

	distinctDirs := []dirSpec{
		{path: "/etc/ardur", mode: 0o700},
		{path: stateDirParent, mode: 0o700},
		{path: cfg.StateDir, mode: cfg.StateDirMode},
	}

	for _, d := range distinctDirs {
		if err := installerMkdirAll(rootFD, d.path, 0, 0, d.mode); err != nil {
			return nil, fmt.Errorf("create %s: %w", d.path, err)
		}
		result.PathsCreated = append(result.PathsCreated, d.path)
	}

	// Write the config file using an fd-anchored open.
	if err := installerWriteConfigFile(rootFD, cfg.ConfigPath, defaultDaemonConfig(SensorVersion), 0, 0, cfg.ConfigMode); err != nil {
		return nil, fmt.Errorf("write config %s: %w", cfg.ConfigPath, err)
	}
	result.PathsCreated = append(result.PathsCreated, cfg.ConfigPath)

	// Post-install preflight assertion: verifies the on-disk state matches
	// the declared custody spec. Failure here means an adversary or a race
	// altered the filesystem between our writes and the check.
	report, err := InspectDaemonCustodyPreflight(cfg)
	if err != nil {
		return nil, fmt.Errorf("post-install preflight: %w", err)
	}
	result.PreflightReport = report

	// The socket, bpffs, and run-dir paths are intentionally omitted from
	// the preflight assertion here: the socket is created by the daemon at
	// startup, bpffs is created on first map-pin, and the run-dir is managed
	// by systemd RuntimeDirectory=. We only assert the paths we created.
	for _, f := range report.Findings {
		switch f.PathCategory {
		case DaemonPreflightPathConfig, DaemonPreflightPathStateDir:
			if f.Verdict == DaemonPreflightVerdictFail {
				return result, fmt.Errorf("post-install assertion failed for %s (%s): %s", f.CheckName, f.Path, f.Details)
			}
		}
	}

	return result, nil
}

// UninstallDaemonCustody removes the daemon custody paths created by
// InstallDaemonCustody. It does NOT remove the systemd unit file or
// bpffs-pinned maps (the daemon must be stopped first).
//
// The state directory (which holds both daemon state and, at runtime, the
// per-session evidence log tree the daemon creates under it — see
// defaultEvidenceDir in ardur-kernelcaptured) is only removed when purge is
// true. Evidence is the durable governance record of what a governed agent
// did; uninstalling the sensor must not silently destroy it. Default
// (purge=false) behavior removes only the config file, matching the pre-purge
// behavior of this function.
func UninstallDaemonCustody(cfg DaemonCustodyConfig, purge bool) error {
	cfg = normalizeDaemonCustodyConfig(cfg)
	if os.Getuid() != 0 {
		return ErrDaemonInstallerNotRoot
	}

	// Remove config file; leave the directory tree for operator review unless purge.
	if err := os.Remove(cfg.ConfigPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove config %s: %w", cfg.ConfigPath, err)
	}
	if purge {
		if err := os.RemoveAll(cfg.StateDir); err != nil {
			return fmt.Errorf("purge state dir %s: %w", cfg.StateDir, err)
		}
	}
	return nil
}

// ErrDaemonInstallerNotRoot is returned when Install/Uninstall is called
// without root privileges.
var ErrDaemonInstallerNotRoot = errors.New("kernelcapture: installer requires root (UID 0)")

// installerMkdirAll creates all directories in path using openat2 with
// RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH so that no symlink can redirect a
// directory create to an attacker-controlled path. Each new directory fd is
// fchown'd and fchmod'd before being closed.
func installerMkdirAll(rootFD int, absPath string, uid, gid int, mode fs.FileMode) error {
	if !filepath.IsAbs(absPath) {
		return fmt.Errorf("installerMkdirAll: path must be absolute, got %q", absPath)
	}
	// Convert to path relative to "/".
	rel := strings.TrimPrefix(filepath.Clean(absPath), "/")
	if rel == "" {
		return nil // it's just "/"
	}

	components := strings.Split(rel, "/")
	parentFD := rootFD
	owned := false

	for i, comp := range components {
		if comp == "" || comp == "." {
			continue
		}
		// Try to open the component first (it may already exist).
		//
		// NOTE: the fd is opened O_DIRECTORY (a real, readable directory fd) —
		// NOT O_PATH. fchown(2)/fchmod(2) fail with EBADF on an O_PATH fd, so
		// applying ownership below requires a non-O_PATH handle. The
		// RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH guarantees are properties of
		// openat2 resolution and are independent of O_PATH, so dropping O_PATH
		// does not weaken the TOCTOU/symlink protection.
		fd, err := unix.Openat2(parentFD, comp, &unix.OpenHow{
			Flags:   unix.O_DIRECTORY,
			Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
		})
		if err != nil {
			// Not found or not a directory: create it.
			if err2 := unix.Mkdirat(parentFD, comp, uint32(mode.Perm())); err2 != nil {
				if !errors.Is(err2, fs.ErrExist) {
					return fmt.Errorf("mkdirat %q: %w", strings.Join(components[:i+1], "/"), err2)
				}
			}
			// Now open the freshly-created (or already-existing) directory.
			fd, err = unix.Openat2(parentFD, comp, &unix.OpenHow{
				Flags:   unix.O_DIRECTORY,
				Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
			})
			if err != nil {
				return fmt.Errorf("openat2 %q: %w", strings.Join(components[:i+1], "/"), err)
			}
			owned = true
		}

		// fchown/fchmod only the directories we need to own (the last
		// component and any intermediate dirs under the ardur subtree that
		// we just created).
		if owned || i == len(components)-1 {
			if ferr := unix.Fchown(fd, uid, gid); ferr != nil {
				unix.Close(fd)
				return fmt.Errorf("fchown %q: %w", strings.Join(components[:i+1], "/"), ferr)
			}
			if ferr := unix.Fchmod(fd, uint32(mode.Perm())); ferr != nil {
				unix.Close(fd)
				return fmt.Errorf("fchmod %q: %w", strings.Join(components[:i+1], "/"), ferr)
			}
		}

		if parentFD != rootFD {
			unix.Close(parentFD)
		}
		parentFD = fd
	}

	if parentFD != rootFD {
		unix.Close(parentFD)
	}
	return nil
}

// installerWriteConfigFile writes data to absPath using openat2 with
// RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH so that no symlink can redirect the
// write. Ownership and mode are applied via fchown/fchmod on the open fd.
// Fails if the target already exists (O_EXCL); callers who want to overwrite
// must remove the file first.
func installerWriteConfigFile(rootFD int, absPath string, data []byte, uid, gid int, mode fs.FileMode) error {
	if !filepath.IsAbs(absPath) {
		return fmt.Errorf("installerWriteConfigFile: path must be absolute, got %q", absPath)
	}
	rel := strings.TrimPrefix(filepath.Clean(absPath), "/")
	dir, base := filepath.Split(rel)
	dir = strings.TrimSuffix(dir, "/")

	// Open the parent directory with RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH.
	parentFD, err := installerOpenDir(rootFD, dir)
	if err != nil {
		return fmt.Errorf("open parent dir for %q: %w", absPath, err)
	}
	defer unix.Close(parentFD)

	// Open (or create) the file. If it already exists we truncate it rather
	// than using O_EXCL so reinstall is idempotent.
	fd, err := unix.Openat2(parentFD, base, &unix.OpenHow{
		Flags:   unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC,
		Mode:    uint64(mode.Perm()),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
	})
	if err != nil {
		return fmt.Errorf("openat2 %q: %w", absPath, err)
	}
	defer unix.Close(fd)

	if err := unix.Fchown(fd, uid, gid); err != nil {
		return fmt.Errorf("fchown %q: %w", absPath, err)
	}
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return fmt.Errorf("fchmod %q: %w", absPath, err)
	}

	if len(data) > 0 {
		if _, err := unix.Write(fd, data); err != nil {
			return fmt.Errorf("write %q: %w", absPath, err)
		}
	}
	return nil
}

// installerOpenDir opens a directory path relative to rootFD using a chain of
// openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH) calls, one per path component.
// This ensures no symlink in any component can redirect the traversal.
func installerOpenDir(rootFD int, relPath string) (int, error) {
	if relPath == "" || relPath == "." {
		fd, err := unix.Openat2(rootFD, ".", &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_DIRECTORY,
			Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
		})
		if err != nil {
			return -1, fmt.Errorf("openat2 .: %w", err)
		}
		return fd, nil
	}

	components := strings.Split(filepath.Clean(relPath), "/")
	parentFD := rootFD

	for i, comp := range components {
		if comp == "" || comp == "." {
			continue
		}
		fd, err := unix.Openat2(parentFD, comp, &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_DIRECTORY,
			Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
		})
		if err != nil {
			if parentFD != rootFD {
				unix.Close(parentFD)
			}
			return -1, fmt.Errorf("openat2 component[%d]=%q: %w", i, comp, err)
		}
		if parentFD != rootFD {
			unix.Close(parentFD)
		}
		parentFD = fd
	}
	return parentFD, nil
}

// defaultDaemonConfig returns the minimal TOML content written to the daemon
// config file during install. Values can be overridden after install. The
// version line is read back by checkSensorVersionDowngrade on a later
// install/upgrade run — see ExtractSensorVersion for its exact expected shape.
func defaultDaemonConfig(version string) []byte {
	return []byte(fmt.Sprintf(`# ardur-kernelcaptured configuration
# Generated by 'ardur sensor install'. Edit to customize.

[daemon]
version      = %q
socket_path  = "/run/ardur/kernelcapture/control.sock"
state_dir    = "/var/lib/ardur/kernelcapture"
evidence_dir = "/var/lib/ardur/kernelcapture/evidence"
bpffs_dir    = "/sys/fs/bpf/ardur"
log_level    = "info"
`, version))
}
