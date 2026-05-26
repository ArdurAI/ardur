package kernelcapture

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultDaemonCustodyConfigBuildsLocalOnlyPlan(t *testing.T) {
	t.Parallel()

	cfg := DefaultDaemonCustodyConfig()
	cfg.RepositoryRoot = t.TempDir()

	plan, err := BuildDaemonCustodyPlan(cfg)
	if err != nil {
		t.Fatalf("BuildDaemonCustodyPlan returned error: %v", err)
	}
	if plan.Mode != DaemonCustodyModeLocalOnlyScaffold {
		t.Fatalf("mode = %q, want %q", plan.Mode, DaemonCustodyModeLocalOnlyScaffold)
	}
	if plan.RingbufMapPath != "/sys/fs/bpf/ardur/process_lifecycle_events" {
		t.Fatalf("ringbuf map path = %q", plan.RingbufMapPath)
	}
	if plan.OwnerUID != 0 || plan.OwnerGID != 0 {
		t.Fatalf("owner = %d:%d, want 0:0", plan.OwnerUID, plan.OwnerGID)
	}
	if len(plan.Steps) < 5 {
		t.Fatalf("expected custody steps, got %d", len(plan.Steps))
	}
	for _, step := range plan.Steps {
		if step.Executed {
			t.Fatalf("step %q executed; scaffold must be dry-run/local-only", step.Name)
		}
	}
	if !containsText(plan.ClaimBoundary, "does not install or start a daemon") {
		t.Fatalf("claim boundary missing local-only daemon statement: %#v", plan.ClaimBoundary)
	}
	if !containsText(plan.NotClaimed, "production daemon readiness") {
		t.Fatalf("not-claimed list missing production daemon boundary: %#v", plan.NotClaimed)
	}
}

func TestDaemonCustodyConfigRejectsRepositoryControlledPrivilegedPaths(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	cfg := DefaultDaemonCustodyConfig()
	cfg.RepositoryRoot = repoRoot
	cfg.RingbufMapPath = filepath.Join(repoRoot, ".ardur", "process_lifecycle_events")

	_, err := BuildDaemonCustodyPlan(cfg)
	if err == nil {
		t.Fatalf("expected repository-controlled path rejection")
	}
	if !errors.Is(err, ErrDaemonCustodyConfig) {
		t.Fatalf("expected ErrDaemonCustodyConfig, got %v", err)
	}
	if !strings.Contains(err.Error(), "repository-controlled") {
		t.Fatalf("expected repository-controlled error, got %v", err)
	}
}

func TestDaemonCustodyConfigRejectsInstallOrStart(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		mut  func(*DaemonCustodyConfig)
	}{
		{name: "install", mut: func(cfg *DaemonCustodyConfig) { cfg.InstallService = true }},
		{name: "start", mut: func(cfg *DaemonCustodyConfig) { cfg.StartDaemon = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultDaemonCustodyConfig()
			cfg.RepositoryRoot = t.TempDir()
			tc.mut(&cfg)
			_, err := BuildDaemonCustodyPlan(cfg)
			if err == nil {
				t.Fatalf("expected local-only scaffold rejection")
			}
			if !errors.Is(err, ErrDaemonCustodyConfig) {
				t.Fatalf("expected ErrDaemonCustodyConfig, got %v", err)
			}
		})
	}
}

func TestDaemonCustodyConfigRejectsPermissiveModes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		mut  func(*DaemonCustodyConfig)
	}{
		{name: "config world readable", mut: func(cfg *DaemonCustodyConfig) { cfg.ConfigMode = 0o644 }},
		{name: "state world writable", mut: func(cfg *DaemonCustodyConfig) { cfg.StateDirMode = 0o777 }},
		{name: "run world writable", mut: func(cfg *DaemonCustodyConfig) { cfg.RunDirMode = 0o777 }},
		{name: "bpffs group readable", mut: func(cfg *DaemonCustodyConfig) { cfg.BPFFSDirMode = 0o750 }},
		{name: "socket world writable", mut: func(cfg *DaemonCustodyConfig) { cfg.SocketMode = fs.FileMode(0o666) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultDaemonCustodyConfig()
			cfg.RepositoryRoot = t.TempDir()
			tc.mut(&cfg)
			_, err := BuildDaemonCustodyPlan(cfg)
			if err == nil {
				t.Fatalf("expected mode rejection")
			}
			if !errors.Is(err, ErrDaemonCustodyConfig) {
				t.Fatalf("expected ErrDaemonCustodyConfig, got %v", err)
			}
		})
	}
}

func TestDaemonCustodyConfigRejectsNonPermissionModeBits(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		mut  func(*DaemonCustodyConfig)
	}{
		{name: "config setuid bit", mut: func(cfg *DaemonCustodyConfig) { cfg.ConfigMode = fs.ModeSetuid | 0o600 }},
		{name: "state directory type bit", mut: func(cfg *DaemonCustodyConfig) { cfg.StateDirMode = fs.ModeDir | 0o700 }},
		{name: "run sticky bit", mut: func(cfg *DaemonCustodyConfig) { cfg.RunDirMode = fs.ModeSticky | 0o700 }},
		{name: "bpffs setgid bit", mut: func(cfg *DaemonCustodyConfig) { cfg.BPFFSDirMode = fs.ModeSetgid | 0o700 }},
		{name: "socket type bit", mut: func(cfg *DaemonCustodyConfig) { cfg.SocketMode = fs.ModeSocket | 0o660 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultDaemonCustodyConfig()
			cfg.RepositoryRoot = t.TempDir()
			tc.mut(&cfg)
			_, err := BuildDaemonCustodyPlan(cfg)
			if err == nil {
				t.Fatalf("expected non-permission mode bit rejection")
			}
			if !errors.Is(err, ErrDaemonCustodyConfig) {
				t.Fatalf("expected ErrDaemonCustodyConfig, got %v", err)
			}
			if !strings.Contains(err.Error(), "permission bits only") {
				t.Fatalf("expected permission-bits-only error, got %v", err)
			}
		})
	}
}

func TestDaemonCustodyConfigRejectsInvalidPathRelationships(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		mut  func(*DaemonCustodyConfig)
	}{
		{name: "relative config", mut: func(cfg *DaemonCustodyConfig) { cfg.ConfigPath = "ardur/kernelcapture.toml" }},
		{name: "map outside bpffs", mut: func(cfg *DaemonCustodyConfig) { cfg.RingbufMapPath = "/tmp/ardur/process_lifecycle_events" }},
		{name: "map outside configured bpffs dir", mut: func(cfg *DaemonCustodyConfig) { cfg.RingbufMapPath = "/sys/fs/bpf/other/process_lifecycle_events" }},
		{name: "socket outside run dir", mut: func(cfg *DaemonCustodyConfig) { cfg.SocketPath = "/tmp/kernelcapture.sock" }},
		{name: "config outside etc", mut: func(cfg *DaemonCustodyConfig) { cfg.ConfigPath = "/tmp/kernelcapture.toml" }},
		{name: "state outside var lib", mut: func(cfg *DaemonCustodyConfig) { cfg.StateDir = "/tmp/ardur/kernelcapture" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultDaemonCustodyConfig()
			cfg.RepositoryRoot = t.TempDir()
			tc.mut(&cfg)
			_, err := BuildDaemonCustodyPlan(cfg)
			if err == nil {
				t.Fatalf("expected invalid path relationship rejection")
			}
			if !errors.Is(err, ErrDaemonCustodyConfig) {
				t.Fatalf("expected ErrDaemonCustodyConfig, got %v", err)
			}
		})
	}
}

func containsText(values []string, needle string) bool {
	for _, value := range values {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
