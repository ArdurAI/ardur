package kernelcapture

// sensor_version.go — version tracking for the ardur-sensor installer
// (Epic A #63, Slice 2 remainder).
//
// InstallDaemonCustody stamps SensorVersion into the daemon config file it
// writes. A later install run (an upgrade, or a reinstall) reads back
// whatever version is already on disk and refuses to proceed if it is newer
// than the binary currently running — an operator accidentally running an
// older ardur-sensor binary against a host already upgraded to a newer one
// must not silently downgrade the installed config. WithAllowDowngrade is the
// explicit, rare override for an operator who really means it.
//
// This file has no build tag: parsing and comparison are pure Go, testable
// on every platform. The install-time file I/O that uses these helpers is
// Linux-only (daemon_installer_linux.go), matching the rest of the installer.

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SensorVersion is the ardur-sensor / ardur-kernelcaptured release version.
// Bump manually per release. Independent of the Go module version — this is
// the version stamped into the installed config file and reported over the
// daemon health protocol's DaemonProtocolResponse (a future slice may wire
// health to also report it; today it gates install-time downgrades only).
const SensorVersion = "0.2.0"

// ErrSensorVersionDowngradeRefused is returned by InstallDaemonCustody when
// the config already on disk reports a version newer than SensorVersion and
// the caller did not pass WithAllowDowngrade(true).
var ErrSensorVersionDowngradeRefused = errors.New("kernelcapture: refusing to downgrade installed sensor version")

// InstallOption configures InstallDaemonCustody. Unset (the zero value)
// behaves exactly as before this option existed: downgrades are refused.
type InstallOption func(*installOptions)

type installOptions struct {
	allowDowngrade bool
}

// WithAllowDowngrade explicitly permits InstallDaemonCustody to overwrite a
// newer on-disk config with an older binary's version. Use only when an
// operator has deliberately decided to roll back.
func WithAllowDowngrade(allow bool) InstallOption {
	return func(o *installOptions) { o.allowDowngrade = allow }
}

func resolveInstallOptions(optFns []InstallOption) installOptions {
	var opts installOptions
	for _, fn := range optFns {
		if fn != nil {
			fn(&opts)
		}
	}
	return opts
}

// sensorVersionPattern matches a `version = "X.Y.Z"` line in the config file
// this package writes. This is intentionally narrow — a single-field reader
// for a format Ardur controls both ends of, not a general TOML parser.
var sensorVersionPattern = regexp.MustCompile(`(?m)^\s*version\s*=\s*"([^"]*)"\s*$`)

// ExtractSensorVersion finds the `version = "..."` line in config content and
// returns its value. ok is false if no such line is present (e.g. a config
// file written before version stamping existed).
func ExtractSensorVersion(config []byte) (version string, ok bool) {
	m := sensorVersionPattern.FindSubmatch(config)
	if m == nil {
		return "", false
	}
	return string(m[1]), true
}

// ParseSensorVersion parses a "MAJOR.MINOR.PATCH" string into comparable
// integer components. Errors on anything else (pre-release/build metadata,
// missing components, non-numeric parts) — deliberately narrow, matching
// ExtractSensorVersion's claim boundary.
func ParseSensorVersion(v string) (major, minor, patch int, err error) {
	parts := strings.Split(strings.TrimSpace(v), ".")
	if len(parts) != 3 {
		return 0, 0, 0, fmt.Errorf("kernelcapture: sensor version %q must have exactly 3 dot-separated components", v)
	}
	nums := make([]int, 3)
	for i, part := range parts {
		n, convErr := strconv.Atoi(part)
		if convErr != nil || n < 0 {
			return 0, 0, 0, fmt.Errorf("kernelcapture: sensor version %q component %q is not a non-negative integer", v, part)
		}
		nums[i] = n
	}
	return nums[0], nums[1], nums[2], nil
}

// CompareSensorVersions returns -1 if a < b, 0 if a == b, 1 if a > b.
func CompareSensorVersions(a, b string) (int, error) {
	aMaj, aMin, aPatch, err := ParseSensorVersion(a)
	if err != nil {
		return 0, err
	}
	bMaj, bMin, bPatch, err := ParseSensorVersion(b)
	if err != nil {
		return 0, err
	}
	for _, pair := range [][2]int{{aMaj, bMaj}, {aMin, bMin}, {aPatch, bPatch}} {
		if pair[0] != pair[1] {
			if pair[0] < pair[1] {
				return -1, nil
			}
			return 1, nil
		}
	}
	return 0, nil
}

// checkSensorVersionDowngrade compares candidateVersion (the version about to
// be installed) against whatever version is stamped in existingConfig (the
// config file already on disk, if any). It returns ErrSensorVersionDowngradeRefused
// wrapped with both versions when candidateVersion is strictly older and
// allowDowngrade is false.
//
// A missing existingConfig, a config with no version line, or an unparsable
// version are all treated as "nothing to compare against" — proceed. Refusing
// to install over a config this function cannot understand would make every
// pre-version-stamping install permanently stuck; that is worse than the
// narrow risk this check exists to catch.
func checkSensorVersionDowngrade(candidateVersion string, existingConfig []byte, allowDowngrade bool) error {
	installedVersion, ok := ExtractSensorVersion(existingConfig)
	if !ok {
		return nil
	}
	cmp, err := CompareSensorVersions(candidateVersion, installedVersion)
	if err != nil {
		return nil
	}
	if cmp >= 0 || allowDowngrade {
		return nil
	}
	return fmt.Errorf("%w: installed version is %s, this binary is %s (pass --allow-downgrade to override)",
		ErrSensorVersionDowngradeRefused, installedVersion, candidateVersion)
}
