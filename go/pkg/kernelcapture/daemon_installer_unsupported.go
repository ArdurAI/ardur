//go:build !linux

package kernelcapture

import "errors"

// InstallResult describes the outcome of a daemon installation.
type InstallResult struct {
	PathsCreated    []string
	PreflightReport DaemonPreflightReport
}

// ErrDaemonInstallerNotRoot is returned when Install/Uninstall is called
// without root privileges.
var ErrDaemonInstallerNotRoot = errors.New("kernelcapture: installer requires root (UID 0)")

// InstallDaemonCustody is unavailable on non-Linux platforms.
func InstallDaemonCustody(cfg DaemonCustodyConfig) (*InstallResult, error) {
	return nil, errors.New("kernelcapture: daemon installer is Linux-only")
}

// UninstallDaemonCustody is unavailable on non-Linux platforms.
func UninstallDaemonCustody(cfg DaemonCustodyConfig) error {
	return errors.New("kernelcapture: daemon installer is Linux-only")
}
