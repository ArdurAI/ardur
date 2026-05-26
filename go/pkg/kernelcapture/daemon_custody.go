package kernelcapture

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

const (
	// DaemonCustodyModeLocalOnlyScaffold means BuildDaemonCustodyPlan only builds
	// and validates a plan. It does not create paths, pin maps, bind sockets,
	// install service units, or start a privileged process.
	DaemonCustodyModeLocalOnlyScaffold = "local_only_scaffold"
)

var ErrDaemonCustodyConfig = errors.New("kernelcapture: invalid daemon custody config")

// DaemonCustodyConfig defines the privileged custody boundary for a future local
// kernelcapture daemon. This configuration is intentionally daemon-owned:
// repository, mission, and agent-session configuration must not select these
// privileged paths.
type DaemonCustodyConfig struct {
	ConfigPath     string
	StateDir       string
	RunDir         string
	SocketPath     string
	BPFFSDir       string
	RingbufMapPath string

	OwnerUID int
	OwnerGID int

	ConfigMode   fs.FileMode
	StateDirMode fs.FileMode
	RunDirMode   fs.FileMode
	BPFFSDirMode fs.FileMode
	SocketMode   fs.FileMode

	ProducerName    string
	ProducerVersion string

	// RepositoryRoot is optional validation context. When set, daemon-owned
	// privileged paths must not live under this repo-controlled tree.
	RepositoryRoot string

	// These flags are rejected in this scaffold slice. Installation/startup belong
	// to a separate reviewed privilege model.
	InstallService bool
	StartDaemon    bool
}

// DaemonCustodyPlan is a validated dry-run plan for the future daemon custody
// boundary. The steps are descriptive; none are executed by this package.
type DaemonCustodyPlan struct {
	Mode           string
	ConfigPath     string
	StateDir       string
	RunDir         string
	SocketPath     string
	BPFFSDir       string
	RingbufMapPath string
	OwnerUID       int
	OwnerGID       int

	ProducerName    string
	ProducerVersion string

	Steps         []DaemonCustodyStep
	ClaimBoundary []string
	NotClaimed    []string
}

// DaemonCustodyStep describes one future privileged setup action without
// performing it.
type DaemonCustodyStep struct {
	Name       string
	Path       string
	Mode       fs.FileMode
	Privileged bool
	Executed   bool
	Rationale  string
}

type DaemonCustodyConfigError struct {
	Field  string
	Reason string
}

func (e *DaemonCustodyConfigError) Error() string {
	if e == nil {
		return ErrDaemonCustodyConfig.Error()
	}
	if e.Field == "" {
		return fmt.Sprintf("%s: %s", ErrDaemonCustodyConfig, e.Reason)
	}
	return fmt.Sprintf("%s: %s: %s", ErrDaemonCustodyConfig, e.Field, e.Reason)
}

func (e *DaemonCustodyConfigError) Unwrap() error {
	return ErrDaemonCustodyConfig
}

// DefaultDaemonCustodyConfig returns the narrow local scaffold defaults for a
// future root-owned Linux daemon. The defaults are data only; callers must opt
// into any privileged setup in a future reviewed slice.
func DefaultDaemonCustodyConfig() DaemonCustodyConfig {
	return DaemonCustodyConfig{
		ConfigPath:      "/etc/ardur/kernelcapture-daemon.toml",
		StateDir:        "/var/lib/ardur/kernelcapture",
		RunDir:          "/run/ardur/kernelcapture",
		SocketPath:      "/run/ardur/kernelcapture/control.sock",
		BPFFSDir:        "/sys/fs/bpf/ardur",
		RingbufMapPath:  "/sys/fs/bpf/ardur/process_lifecycle_events",
		OwnerUID:        0,
		OwnerGID:        0,
		ConfigMode:      0o600,
		StateDirMode:    0o700,
		RunDirMode:      0o700,
		BPFFSDirMode:    0o700,
		SocketMode:      0o660,
		ProducerName:    "ardur-process-lifecycle-ebpf",
		ProducerVersion: "phase2-process-lifecycle-v0",
	}
}

// BuildDaemonCustodyPlan validates daemon custody config and returns a dry-run
// local-only plan. It does not touch the filesystem or start privileged code.
func BuildDaemonCustodyPlan(cfg DaemonCustodyConfig) (DaemonCustodyPlan, error) {
	cfg = normalizeDaemonCustodyConfig(cfg)
	if err := validateDaemonCustodyConfig(cfg); err != nil {
		return DaemonCustodyPlan{}, err
	}
	return DaemonCustodyPlan{
		Mode:            DaemonCustodyModeLocalOnlyScaffold,
		ConfigPath:      cfg.ConfigPath,
		StateDir:        cfg.StateDir,
		RunDir:          cfg.RunDir,
		SocketPath:      cfg.SocketPath,
		BPFFSDir:        cfg.BPFFSDir,
		RingbufMapPath:  cfg.RingbufMapPath,
		OwnerUID:        cfg.OwnerUID,
		OwnerGID:        cfg.OwnerGID,
		ProducerName:    cfg.ProducerName,
		ProducerVersion: cfg.ProducerVersion,
		Steps: []DaemonCustodyStep{
			{
				Name:       "validate_root_owned_config",
				Path:       cfg.ConfigPath,
				Mode:       cfg.ConfigMode,
				Privileged: true,
				Rationale:  "daemon-owned config is the only source allowed to select privileged eBPF map/socket paths",
			},
			{
				Name:       "prepare_state_dir",
				Path:       cfg.StateDir,
				Mode:       cfg.StateDirMode,
				Privileged: true,
				Rationale:  "state/checkpoint custody must not be writable by repository or mission config",
			},
			{
				Name:       "prepare_runtime_dir",
				Path:       cfg.RunDir,
				Mode:       cfg.RunDirMode,
				Privileged: true,
				Rationale:  "control socket parent must be daemon-owned and restrictive",
			},
			{
				Name:       "prepare_bpffs_dir",
				Path:       cfg.BPFFSDir,
				Mode:       cfg.BPFFSDirMode,
				Privileged: true,
				Rationale:  "pinned maps belong under a root-owned bpffs namespace",
			},
			{
				Name:       "pin_process_lifecycle_ringbuf",
				Path:       cfg.RingbufMapPath,
				Mode:       cfg.BPFFSDirMode,
				Privileged: true,
				Rationale:  "consumer ringbuf path must be chosen by daemon custody, not repo-controlled config",
			},
			{
				Name:       "bind_local_control_socket",
				Path:       cfg.SocketPath,
				Mode:       cfg.SocketMode,
				Privileged: true,
				Rationale:  "future local clients should cross a narrow local socket boundary instead of loading eBPF directly",
			},
		},
		ClaimBoundary: []string{
			"local-only dry-run scaffold: does not install or start a daemon",
			"privileged eBPF map and socket paths must come from daemon-owned root config",
			"repository, mission, and agent-session config cannot select pinned map paths",
			"scaffold records custody invariants before kernel-map filtering or service startup work",
		},
		NotClaimed: []string{
			"production daemon readiness",
			"system service installation",
			"daemon startup or persistent privileged process custody",
			"kernel-enforced session/cgroup filtering",
			"file/network/privilege side-effect capture",
			"unprivileged/no-install eBPF support",
		},
	}, nil
}

func normalizeDaemonCustodyConfig(cfg DaemonCustodyConfig) DaemonCustodyConfig {
	if cfg.ProducerName == "" {
		cfg.ProducerName = "ardur-process-lifecycle-ebpf"
	}
	if cfg.ProducerVersion == "" {
		cfg.ProducerVersion = "phase2-process-lifecycle-v0"
	}
	cfg.ConfigPath = cleanPath(cfg.ConfigPath)
	cfg.StateDir = cleanPath(cfg.StateDir)
	cfg.RunDir = cleanPath(cfg.RunDir)
	cfg.SocketPath = cleanPath(cfg.SocketPath)
	cfg.BPFFSDir = cleanPath(cfg.BPFFSDir)
	cfg.RingbufMapPath = cleanPath(cfg.RingbufMapPath)
	cfg.RepositoryRoot = cleanPath(cfg.RepositoryRoot)
	return cfg
}

func validateDaemonCustodyConfig(cfg DaemonCustodyConfig) error {
	if cfg.InstallService {
		return custodyConfigError("install_service", "service installation is outside the local-only scaffold")
	}
	if cfg.StartDaemon {
		return custodyConfigError("start_daemon", "daemon startup is outside the local-only scaffold")
	}
	if cfg.OwnerUID != 0 || cfg.OwnerGID != 0 {
		return custodyConfigError("owner", "daemon custody paths must be planned as root-owned 0:0")
	}

	for _, item := range []struct {
		field string
		path  string
	}{
		{field: "config_path", path: cfg.ConfigPath},
		{field: "state_dir", path: cfg.StateDir},
		{field: "run_dir", path: cfg.RunDir},
		{field: "socket_path", path: cfg.SocketPath},
		{field: "bpffs_dir", path: cfg.BPFFSDir},
		{field: "ringbuf_map_path", path: cfg.RingbufMapPath},
	} {
		if item.path == "" {
			return custodyConfigError(item.field, "path is required")
		}
		if !filepath.IsAbs(item.path) {
			return custodyConfigError(item.field, "path must be absolute")
		}
		if lexicalPathWithin(item.path, cfg.RepositoryRoot) {
			return custodyConfigError(item.field, "privileged custody path is repository-controlled")
		}
	}

	if !lexicalPathWithin(cfg.ConfigPath, "/etc/ardur") {
		return custodyConfigError("config_path", "daemon-owned config must live under /etc/ardur")
	}
	if !lexicalPathWithin(cfg.StateDir, "/var/lib/ardur") {
		return custodyConfigError("state_dir", "daemon state must live under /var/lib/ardur")
	}
	if !lexicalPathWithin(cfg.RunDir, "/run/ardur") && !lexicalPathWithin(cfg.RunDir, "/var/run/ardur") {
		return custodyConfigError("run_dir", "runtime directory must live under /run/ardur or /var/run/ardur")
	}
	if !lexicalPathWithin(cfg.SocketPath, cfg.RunDir) {
		return custodyConfigError("socket_path", "socket must live under the daemon runtime directory")
	}
	if !lexicalPathWithin(cfg.BPFFSDir, "/sys/fs/bpf") {
		return custodyConfigError("bpffs_dir", "bpffs directory must live under /sys/fs/bpf")
	}
	if !lexicalPathWithin(cfg.RingbufMapPath, cfg.BPFFSDir) {
		return custodyConfigError("ringbuf_map_path", "ringbuf map path must live under the daemon bpffs directory")
	}

	if err := validateExactMode("config_mode", cfg.ConfigMode, 0o600); err != nil {
		return err
	}
	if err := validateExactMode("state_dir_mode", cfg.StateDirMode, 0o700); err != nil {
		return err
	}
	if err := validateExactMode("run_dir_mode", cfg.RunDirMode, 0o700); err != nil {
		return err
	}
	if err := validateExactMode("bpffs_dir_mode", cfg.BPFFSDirMode, 0o700); err != nil {
		return err
	}
	if cfg.SocketMode&^fs.ModePerm != 0 {
		return custodyConfigError("socket_mode", "mode must contain permission bits only")
	}
	if cfg.SocketMode != 0o600 && cfg.SocketMode != 0o660 {
		return custodyConfigError("socket_mode", "socket mode must be 0600 or 0660")
	}
	return nil
}

func validateExactMode(field string, got fs.FileMode, want fs.FileMode) error {
	if got&^fs.ModePerm != 0 {
		return custodyConfigError(field, "mode must contain permission bits only")
	}
	if got != want {
		return custodyConfigError(field, fmt.Sprintf("mode must be %04o", want))
	}
	return nil
}

func custodyConfigError(field string, reason string) error {
	return &DaemonCustodyConfigError{Field: field, Reason: reason}
}

func cleanPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	return filepath.Clean(path)
}

// lexicalPathWithin performs lexical-only path containment without checking
// symlinks or filesystem state. DO NOT USE for production path enforcement —
// perform symlink-aware realpath resolution first.
func lexicalPathWithin(child string, parent string) bool {
	// This is lexical-only containment for a dry-run/no-IO scaffold. Any future
	// privileged filesystem write must add symlink-aware realpath, ownership, and
	// mode checks before trusting these paths on disk.
	if child == "" || parent == "" {
		return false
	}
	child = filepath.Clean(child)
	parent = filepath.Clean(parent)
	if child == parent {
		return true
	}
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, "../") && !strings.HasPrefix(rel, `..\`)
}
