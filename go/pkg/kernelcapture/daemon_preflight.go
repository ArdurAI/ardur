package kernelcapture

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

const (
	DaemonPreflightVerdictPass    = "pass"
	DaemonPreflightVerdictWarn    = "warn"
	DaemonPreflightVerdictFail    = "fail"
	DaemonPreflightVerdictMissing = "missing"

	DaemonPreflightPathConfig     = "config"
	DaemonPreflightPathStateDir   = "state_dir"
	DaemonPreflightPathRunDir     = "run_dir"
	DaemonPreflightPathSocket     = "socket"
	DaemonPreflightPathBPFFSDir   = "bpffs_dir"
	DaemonPreflightPathRingbufMap = "bpffs_map"
)

// DaemonPreflightReport is a read-only inspection result for the future
// kernelcapture daemon custody boundary. It never represents filesystem
// mutation, daemon startup, socket binding, or map pinning.
type DaemonPreflightReport struct {
	Mode        string
	Findings    []DaemonPreflightFinding
	WorksNow    []string
	NotClaimed  []string
	CanContinue bool
}

// DaemonPreflightFinding is intentionally structured so callers can render
// local diagnostics or consume the result in tests without scraping text.
type DaemonPreflightFinding struct {
	CheckName    string
	PathCategory string
	Path         string
	ResolvedPath string
	ExpectedMode fs.FileMode
	ExpectedUID  int
	ExpectedGID  int
	ObservedMode fs.FileMode
	ObservedUID  int
	ObservedGID  int
	ObservedType string
	Symlink      bool
	Verdict      string
	Remediation  string
	Details      string
}

type DaemonPreflightOption func(*daemonPreflightOptions)

type daemonPreflightOptions struct {
	fs daemonPreflightFS
}

// WithDaemonPreflightFilesystem injects a read-only filesystem/stat provider.
// It is primarily for tests; production callers use the OS adapter.
func WithDaemonPreflightFilesystem(fsys daemonPreflightFS) DaemonPreflightOption {
	return func(opts *daemonPreflightOptions) {
		opts.fs = fsys
	}
}

type daemonPreflightFS interface {
	Lstat(path string) (daemonPreflightPathInfo, error)
	Stat(path string) (daemonPreflightPathInfo, error)
	EvalSymlinks(path string) (string, error)
}

type daemonPreflightPathInfo struct {
	Mode fs.FileMode
	UID  int
	GID  int
}

// InspectDaemonCustodyPreflight inspects the daemon-owned config/state/runtime
// socket/bpffs boundary without creating paths, changing ownership or modes,
// binding sockets, pinning BPF maps, installing services, or starting daemons.
func InspectDaemonCustodyPreflight(cfg DaemonCustodyConfig, optFns ...DaemonPreflightOption) (DaemonPreflightReport, error) {
	cfg = normalizeDaemonCustodyConfig(cfg)
	report := DaemonPreflightReport{
		Mode: DaemonCustodyModeLocalOnlyScaffold,
		WorksNow: []string{
			"read-only daemon custody preflight inspection",
			"symlink-aware path, owner, mode, and type diagnostics",
			"local protocol contract validation can run without a daemon",
		},
		NotClaimed: []string{
			"daemon installation or startup",
			"socket bind/listen or service exposure",
			"bpffs map pinning or mutation",
			"production daemon readiness",
		},
	}
	if repoFindings := daemonPreflightRepositoryFindings(cfg); len(repoFindings) > 0 {
		report.Findings = repoFindings
		report.CanContinue = false
		return report, nil
	}
	if err := validateDaemonCustodyConfig(cfg); err != nil {
		return DaemonPreflightReport{}, err
	}

	opts := daemonPreflightOptions{fs: osDaemonPreflightFS{}}
	for _, optFn := range optFns {
		if optFn != nil {
			optFn(&opts)
		}
	}
	if opts.fs == nil {
		return DaemonPreflightReport{}, fmt.Errorf("kernelcapture: daemon preflight filesystem is nil")
	}

	checks := daemonPreflightChecks(cfg)
	for _, check := range checks {
		report.Findings = append(report.Findings, inspectDaemonPreflightPath(opts.fs, check))
	}
	report.CanContinue = true
	for _, finding := range report.Findings {
		if finding.Verdict == DaemonPreflightVerdictFail || finding.Verdict == DaemonPreflightVerdictMissing {
			report.CanContinue = false
			break
		}
	}
	return report, nil
}

func daemonPreflightRepositoryFindings(cfg DaemonCustodyConfig) []DaemonPreflightFinding {
	if cfg.RepositoryRoot == "" {
		return nil
	}
	var findings []DaemonPreflightFinding
	for _, check := range daemonPreflightChecks(cfg) {
		if !lexicalPathWithin(check.path, cfg.RepositoryRoot) {
			continue
		}
		findings = append(findings, DaemonPreflightFinding{
			CheckName:    check.name,
			PathCategory: check.category,
			Path:         check.path,
			ExpectedMode: check.expectedMode,
			ExpectedUID:  check.expectedUID,
			ExpectedGID:  check.expectedGID,
			ObservedUID:  -1,
			ObservedGID:  -1,
			Verdict:      DaemonPreflightVerdictFail,
			Remediation:  "move daemon-owned privileged custody paths outside the repository-controlled tree; this preflight does not execute changes",
			Details:      "privileged custody path is repository-controlled",
		})
	}
	return findings
}

type daemonPreflightCheck struct {
	name          string
	category      string
	path          string
	expectedMode  fs.FileMode
	expectedUID   int
	expectedGID   int
	expectType    fs.FileMode
	boundary      string
	boundaryLabel string
}

func daemonPreflightChecks(cfg DaemonCustodyConfig) []daemonPreflightCheck {
	return []daemonPreflightCheck{
		{
			name:     "config_file_present_root_owned",
			category: DaemonPreflightPathConfig, path: cfg.ConfigPath,
			expectedMode: cfg.ConfigMode, expectedUID: cfg.OwnerUID, expectedGID: cfg.OwnerGID,
			boundary: "/etc/ardur", boundaryLabel: "/etc/ardur",
		},
		{
			name:     "state_dir_present_root_owned",
			category: DaemonPreflightPathStateDir, path: cfg.StateDir,
			expectedMode: cfg.StateDirMode, expectedUID: cfg.OwnerUID, expectedGID: cfg.OwnerGID,
			expectType: fs.ModeDir, boundary: "/var/lib/ardur", boundaryLabel: "/var/lib/ardur",
		},
		{
			name:     "run_dir_present_root_owned",
			category: DaemonPreflightPathRunDir, path: cfg.RunDir,
			expectedMode: cfg.RunDirMode, expectedUID: cfg.OwnerUID, expectedGID: cfg.OwnerGID,
			expectType: fs.ModeDir, boundary: cfg.RunDir, boundaryLabel: "configured runtime directory",
		},
		{
			name:     "control_socket_present_root_owned",
			category: DaemonPreflightPathSocket, path: cfg.SocketPath,
			expectedMode: cfg.SocketMode, expectedUID: cfg.OwnerUID, expectedGID: cfg.OwnerGID,
			expectType: fs.ModeSocket, boundary: cfg.RunDir, boundaryLabel: "configured runtime directory",
		},
		{
			name:     "bpffs_dir_present_root_owned",
			category: DaemonPreflightPathBPFFSDir, path: cfg.BPFFSDir,
			expectedMode: cfg.BPFFSDirMode, expectedUID: cfg.OwnerUID, expectedGID: cfg.OwnerGID,
			expectType: fs.ModeDir, boundary: "/sys/fs/bpf", boundaryLabel: "/sys/fs/bpf",
		},
		{
			name:     "ringbuf_map_present_root_owned",
			category: DaemonPreflightPathRingbufMap, path: cfg.RingbufMapPath,
			expectedMode: cfg.BPFFSDirMode, expectedUID: cfg.OwnerUID, expectedGID: cfg.OwnerGID,
			boundary: cfg.BPFFSDir, boundaryLabel: "configured bpffs directory",
		},
	}
}

func inspectDaemonPreflightPath(fsys daemonPreflightFS, check daemonPreflightCheck) DaemonPreflightFinding {
	finding := DaemonPreflightFinding{
		CheckName:    check.name,
		PathCategory: check.category,
		Path:         check.path,
		ExpectedMode: check.expectedMode,
		ExpectedUID:  check.expectedUID,
		ExpectedGID:  check.expectedGID,
		ObservedUID:  -1,
		ObservedGID:  -1,
		Remediation:  "review and repair daemon-owned custody path manually; this preflight does not execute changes",
	}

	linkInfo, err := fsys.Lstat(check.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || os.IsNotExist(err) {
			finding.Verdict = DaemonPreflightVerdictMissing
			finding.Details = "path is missing"
			return finding
		}
		finding.Verdict = DaemonPreflightVerdictFail
		finding.Details = fmt.Sprintf("lstat failed: %v", err)
		return finding
	}
	finding.Symlink = linkInfo.Mode&fs.ModeSymlink != 0

	resolved, err := fsys.EvalSymlinks(check.path)
	if err != nil {
		finding.Verdict = DaemonPreflightVerdictFail
		finding.Details = fmt.Sprintf("realpath evaluation failed: %v", err)
		return finding
	}
	finding.ResolvedPath = cleanPath(resolved)
	if !lexicalPathWithin(finding.ResolvedPath, check.boundary) {
		finding.Verdict = DaemonPreflightVerdictFail
		finding.Details = fmt.Sprintf("resolved path escapes %s", check.boundaryLabel)
		return finding
	}

	info, err := fsys.Stat(check.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || os.IsNotExist(err) {
			finding.Verdict = DaemonPreflightVerdictMissing
			finding.Details = "path target is missing"
			return finding
		}
		finding.Verdict = DaemonPreflightVerdictFail
		finding.Details = fmt.Sprintf("stat failed: %v", err)
		return finding
	}
	finding.ObservedMode = info.Mode.Perm()
	finding.ObservedUID = info.UID
	finding.ObservedGID = info.GID
	finding.ObservedType = daemonPreflightModeType(info.Mode)

	if info.Mode&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
		finding.Verdict = DaemonPreflightVerdictFail
		finding.Details = "mode contains non-permission bits outside the expected file type"
		return finding
	}
	if check.expectType != 0 && info.Mode&check.expectType == 0 {
		finding.Verdict = DaemonPreflightVerdictFail
		finding.Details = fmt.Sprintf("path type is %s, want %s", finding.ObservedType, daemonPreflightModeType(check.expectType))
		return finding
	}
	if check.expectType == 0 && info.Mode.Type() != 0 {
		finding.Verdict = DaemonPreflightVerdictFail
		finding.Details = fmt.Sprintf("path type is %s, want file", finding.ObservedType)
		return finding
	}
	if info.UID != check.expectedUID || info.GID != check.expectedGID {
		finding.Verdict = DaemonPreflightVerdictFail
		finding.Details = fmt.Sprintf("owner is %d:%d, want %d:%d", info.UID, info.GID, check.expectedUID, check.expectedGID)
		return finding
	}
	if info.Mode.Perm() != check.expectedMode {
		finding.Verdict = DaemonPreflightVerdictFail
		finding.Details = fmt.Sprintf("mode is %04o, want %04o", info.Mode.Perm(), check.expectedMode)
		return finding
	}
	if finding.Symlink {
		finding.Verdict = DaemonPreflightVerdictWarn
		finding.Details = "path is a symlink but resolves inside the configured custody boundary"
		return finding
	}
	finding.Verdict = DaemonPreflightVerdictPass
	finding.Details = "path exists with expected type, owner, mode, and realpath boundary"
	return finding
}

func daemonPreflightModeType(mode fs.FileMode) string {
	switch {
	case mode&fs.ModeSocket != 0:
		return "socket"
	case mode&fs.ModeDir != 0:
		return "directory"
	case mode&fs.ModeSymlink != 0:
		return "symlink"
	default:
		return "file"
	}
}

type osDaemonPreflightFS struct{}

func (osDaemonPreflightFS) Lstat(path string) (daemonPreflightPathInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return daemonPreflightPathInfo{}, err
	}
	return daemonPreflightPathInfoFromFileInfo(info), nil
}

func (osDaemonPreflightFS) Stat(path string) (daemonPreflightPathInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return daemonPreflightPathInfo{}, err
	}
	return daemonPreflightPathInfoFromFileInfo(info), nil
}

func (osDaemonPreflightFS) EvalSymlinks(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}

func daemonPreflightPathInfoFromFileInfo(info fs.FileInfo) daemonPreflightPathInfo {
	out := daemonPreflightPathInfo{Mode: info.Mode(), UID: -1, GID: -1}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		out.UID = int(st.Uid)
		out.GID = int(st.Gid)
	}
	return out
}
