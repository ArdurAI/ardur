package kernelcapture

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

var ErrDaemonSessionStatusEvidenceLogFilesystemAppend = errors.New("kernelcapture: invalid daemon session status evidence-log filesystem append")

// DaemonSessionStatusEvidenceLogFilesystem is the narrow injected filesystem
// surface for the evidence-log append adapter. Implementations may map the
// daemon-owned logical paths into a test temp directory, but the adapter still
// validates and returns the reviewed daemon-owned logical paths. This interface
// deliberately omits daemon install/start, ownership changes, fsync guarantees,
// service lifecycle, cgroup assignment, BPF map mutation, and client-visible
// protocol expansion.
type DaemonSessionStatusEvidenceLogFilesystem interface {
	Lstat(path string) (fs.FileInfo, error)
	MkdirAll(path string, perm fs.FileMode) error
	AppendFile(path string, data []byte, perm fs.FileMode) error
	Rename(oldPath string, newPath string) error
}

// DaemonSessionStatusEvidenceLogFilesystemAppendConfig configures one bounded
// filesystem append attempt against an existing evidence-log append state.
type DaemonSessionStatusEvidenceLogFilesystemAppendConfig struct {
	State      *DaemonSessionStatusEvidenceLogAppendState
	Filesystem DaemonSessionStatusEvidenceLogFilesystem

	DirectoryMode fs.FileMode
	FileMode      fs.FileMode
}

// ApplyDaemonSessionStatusEvidenceLogFilesystemAppend applies a validated JSONL
// evidence-log entry to an injected filesystem. It reuses the in-memory append
// planner for validation and append/rotation decisions, then performs a minimal
// mkdir/append or mkdir/rename/append sequence through the injected filesystem.
// State is committed only after filesystem operations succeed. This function is
// still not daemon wiring: it does not install/start a daemon, change ownership,
// fsync, recover after crashes, expand client-visible protocol, mutate cgroups,
// or mutate BPF maps.
func ApplyDaemonSessionStatusEvidenceLogFilesystemAppend(cfg DaemonSessionStatusEvidenceLogFilesystemAppendConfig, entryBytes []byte) (DaemonSessionStatusEvidenceLogAppendPlan, error) {
	if cfg.State == nil {
		return DaemonSessionStatusEvidenceLogAppendPlan{}, evidenceLogFilesystemAppendError("state is required")
	}
	cfg.State.mu.Lock()
	proposedPlan := copyDaemonSessionStatusEvidenceLogPlan(cfg.State.plan)
	cfg.State.mu.Unlock()
	return ApplyDaemonSessionStatusEvidenceLogFilesystemAppendForPlan(cfg, proposedPlan, entryBytes)
}

// ApplyDaemonSessionStatusEvidenceLogFilesystemAppendForPlan applies a JSONL
// entry that was built from proposedPlan while preserving the byte/rotation
// state in cfg.State. proposedPlan may carry a newer snapshot digest than the
// state was opened with, but it must match the same session, evidence-log path,
// schema, kind, and retention bounds. State is committed only after filesystem
// operations succeed.
func ApplyDaemonSessionStatusEvidenceLogFilesystemAppendForPlan(cfg DaemonSessionStatusEvidenceLogFilesystemAppendConfig, proposedPlan DaemonSessionStatusEvidenceLogPlan, entryBytes []byte) (DaemonSessionStatusEvidenceLogAppendPlan, error) {
	if cfg.State == nil {
		return DaemonSessionStatusEvidenceLogAppendPlan{}, evidenceLogFilesystemAppendError("state is required")
	}
	if cfg.Filesystem == nil {
		return DaemonSessionStatusEvidenceLogAppendPlan{}, evidenceLogFilesystemAppendError("filesystem is required")
	}
	directoryMode := cfg.DirectoryMode
	if directoryMode == 0 {
		directoryMode = 0o700
	}
	fileMode := cfg.FileMode
	if fileMode == 0 {
		fileMode = 0o600
	}
	if err := validateEvidenceLogFilesystemModes(directoryMode, fileMode); err != nil {
		return DaemonSessionStatusEvidenceLogAppendPlan{}, err
	}

	cfg.State.mu.Lock()
	defer cfg.State.mu.Unlock()

	computed, err := computeDaemonSessionStatusEvidenceLogAppendForPlanLocked(cfg.State, proposedPlan, entryBytes)
	if err != nil {
		return DaemonSessionStatusEvidenceLogAppendPlan{}, evidenceLogFilesystemAppendError("append planning failed: %w", err)
	}
	plan := computed.Plan
	if plan.Decision == DaemonSessionStatusEvidenceLogAppendReject {
		return plan, nil
	}
	if err := validateEvidenceLogFilesystemAppendPlanPaths(plan); err != nil {
		return DaemonSessionStatusEvidenceLogAppendPlan{}, err
	}
	if err := validateEvidenceLogFilesystemAppendNoSymlinks(cfg.Filesystem, plan); err != nil {
		return DaemonSessionStatusEvidenceLogAppendPlan{}, err
	}

	parentDir := filepath.Dir(plan.EvidenceLogPath)
	if err := cfg.Filesystem.MkdirAll(parentDir, directoryMode); err != nil {
		return DaemonSessionStatusEvidenceLogAppendPlan{}, evidenceLogFilesystemAppendError("create evidence-log parent directory %q failed: %w", parentDir, err)
	}
	rotated := false
	if plan.Decision == DaemonSessionStatusEvidenceLogAppendRotateThenAppend {
		if err := cfg.Filesystem.Rename(plan.EvidenceLogPath, plan.RotationPath); err != nil {
			return DaemonSessionStatusEvidenceLogAppendPlan{}, evidenceLogFilesystemAppendError("rotate evidence log %q to %q failed: %w", plan.EvidenceLogPath, plan.RotationPath, err)
		}
		rotated = true
	}
	if err := cfg.Filesystem.AppendFile(plan.EvidenceLogPath, computed.CanonicalBytes, fileMode); err != nil {
		if rotated {
			if rollbackErr := cfg.Filesystem.Rename(plan.RotationPath, plan.EvidenceLogPath); rollbackErr != nil {
				return DaemonSessionStatusEvidenceLogAppendPlan{}, evidenceLogFilesystemAppendError("append evidence log entry to %q failed after rotation and rollback failed: append=%w rollback=%w", plan.EvidenceLogPath, err, rollbackErr)
			}
		}
		return DaemonSessionStatusEvidenceLogAppendPlan{}, evidenceLogFilesystemAppendError("append evidence log entry to %q failed: %w", plan.EvidenceLogPath, err)
	}

	if plan.Decision == DaemonSessionStatusEvidenceLogAppendAccept {
		cfg.State.entries = append(cfg.State.entries, append([]byte(nil), computed.CanonicalBytes...))
		cfg.State.totalBytes = plan.PostBytes
		cfg.State.plan = copyDaemonSessionStatusEvidenceLogPlan(proposedPlan)
	} else if plan.Decision == DaemonSessionStatusEvidenceLogAppendRotateThenAppend {
		cfg.State.entries = [][]byte{append([]byte(nil), computed.CanonicalBytes...)}
		cfg.State.totalBytes = plan.PostBytes
		cfg.State.rotationCount = plan.RotationCount
		cfg.State.plan = copyDaemonSessionStatusEvidenceLogPlan(proposedPlan)
	} else {
		return DaemonSessionStatusEvidenceLogAppendPlan{}, evidenceLogFilesystemAppendError("unsupported append decision %q", plan.Decision)
	}
	return markDaemonSessionStatusEvidenceLogFilesystemStepsExecuted(plan), nil
}

func validateEvidenceLogFilesystemModes(directoryMode fs.FileMode, fileMode fs.FileMode) error {
	if directoryMode&^fs.ModePerm != 0 || directoryMode != 0o700 {
		return evidenceLogFilesystemAppendError("directory mode must be 0700")
	}
	if fileMode&^fs.ModePerm != 0 || fileMode != 0o600 {
		return evidenceLogFilesystemAppendError("file mode must be 0600")
	}
	return nil
}

func validateEvidenceLogFilesystemAppendPlanPaths(plan DaemonSessionStatusEvidenceLogAppendPlan) error {
	stateDir := cleanPath(plan.StateDir)
	if stateDir == "" || stateDir != plan.StateDir {
		return evidenceLogFilesystemAppendError("daemon state dir must be clean and non-empty")
	}
	path := cleanPath(plan.EvidenceLogPath)
	if path == "" || path != plan.EvidenceLogPath {
		return evidenceLogFilesystemAppendError("evidence-log path must be clean and non-empty")
	}
	if !lexicalPathWithin(path, stateDir) {
		return evidenceLogFilesystemAppendError("evidence-log path %q is outside daemon state custody root", path)
	}
	parentDir := filepath.Dir(path)
	if plan.Decision == DaemonSessionStatusEvidenceLogAppendRotateThenAppend {
		rotationPath := cleanPath(plan.RotationPath)
		if rotationPath == "" || rotationPath != plan.RotationPath {
			return evidenceLogFilesystemAppendError("rotation path must be clean and non-empty")
		}
		if !lexicalPathWithin(rotationPath, parentDir) {
			return evidenceLogFilesystemAppendError("rotation path %q escaped evidence-log directory %q", rotationPath, parentDir)
		}
		if !strings.HasPrefix(rotationPath, path+".") {
			return evidenceLogFilesystemAppendError("rotation path %q is not derived from evidence-log path %q", rotationPath, path)
		}
	}
	return nil
}

func validateEvidenceLogFilesystemAppendNoSymlinks(filesystem DaemonSessionStatusEvidenceLogFilesystem, plan DaemonSessionStatusEvidenceLogAppendPlan) error {
	parentDir := filepath.Dir(plan.EvidenceLogPath)
	if err := validateEvidenceLogFilesystemParentChain(filesystem, plan.StateDir, parentDir); err != nil {
		return err
	}
	if err := validateEvidenceLogFilesystemPathNotSymlink(filesystem, plan.EvidenceLogPath, "evidence-log path"); err != nil {
		return err
	}
	if plan.Decision == DaemonSessionStatusEvidenceLogAppendRotateThenAppend {
		if err := validateEvidenceLogFilesystemParentChain(filesystem, plan.StateDir, filepath.Dir(plan.RotationPath)); err != nil {
			return err
		}
		if err := validateEvidenceLogFilesystemPathNotSymlink(filesystem, plan.RotationPath, "rotation path"); err != nil {
			return err
		}
	}
	return nil
}

func validateEvidenceLogFilesystemParentChain(filesystem DaemonSessionStatusEvidenceLogFilesystem, stateDir string, parentDir string) error {
	parents, err := evidenceLogFilesystemParentChain(stateDir, parentDir)
	if err != nil {
		return err
	}
	for _, parent := range parents {
		info, err := filesystem.Lstat(parent)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return evidenceLogFilesystemAppendError("prevalidate evidence-log parent %q failed: %w", parent, err)
		}
		mode := info.Mode()
		if mode&fs.ModeSymlink != 0 {
			return evidenceLogFilesystemAppendError("prevalidate evidence-log parent %q failed: symlink parent is not allowed", parent)
		}
		if !mode.IsDir() {
			return evidenceLogFilesystemAppendError("prevalidate evidence-log parent %q failed: parent is not a directory", parent)
		}
	}
	return nil
}

func evidenceLogFilesystemParentChain(stateDir string, parentDir string) ([]string, error) {
	stateDir = cleanPath(stateDir)
	parentDir = cleanPath(parentDir)
	if stateDir == "" || parentDir == "" {
		return nil, evidenceLogFilesystemAppendError("parent prevalidation requires daemon state dir and evidence-log parent")
	}
	if !lexicalPathWithin(parentDir, stateDir) {
		return nil, evidenceLogFilesystemAppendError("evidence-log parent %q is outside daemon state custody root", parentDir)
	}
	parents := []string{stateDir}
	if parentDir == stateDir {
		return parents, nil
	}
	rel, err := filepath.Rel(stateDir, parentDir)
	if err != nil {
		return nil, evidenceLogFilesystemAppendError("derive evidence-log parent chain failed: %w", err)
	}
	current := stateDir
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return nil, evidenceLogFilesystemAppendError("evidence-log parent %q escaped daemon state custody root", parentDir)
		}
		current = filepath.Join(current, part)
		parents = append(parents, current)
	}
	return parents, nil
}

func validateEvidenceLogFilesystemPathNotSymlink(filesystem DaemonSessionStatusEvidenceLogFilesystem, path string, label string) error {
	info, err := filesystem.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return evidenceLogFilesystemAppendError("prevalidate %s %q failed: %w", label, path, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return evidenceLogFilesystemAppendError("prevalidate %s %q failed: symlink path is not allowed", label, path)
	}
	return nil
}

func markDaemonSessionStatusEvidenceLogFilesystemStepsExecuted(plan DaemonSessionStatusEvidenceLogAppendPlan) DaemonSessionStatusEvidenceLogAppendPlan {
	plan.Steps = append([]DaemonSessionStatusEvidenceLogStep(nil), plan.Steps...)
	for i := range plan.Steps {
		plan.Steps[i].Executed = true
	}
	plan.ClaimBoundary = []string{
		"evidence-log entry validation and append/rotation decision are reused from the reviewed in-memory planner",
		"filesystem writes are executed only through an injected filesystem surface using daemon-owned logical paths",
		"successful append/rotation commits detached in-memory state only after injected filesystem operations succeed",
	}
	plan.NotClaimed = []string{
		"daemon install/start/service lifecycle",
		"ownership changes, fsync guarantees, crash recovery, or restart-safe persistence",
		"client-visible protocol expansion",
		"production daemon readiness",
		"live enforcement, cgroup assignment, or kernel-map mutation",
	}
	return plan
}

func evidenceLogFilesystemAppendError(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrDaemonSessionStatusEvidenceLogFilesystemAppend}, args...)...)
}
