package kernelcapture

import (
	"io/fs"
	"testing"
)

func TestInspectDaemonCustodyPreflightSafeDefaults(t *testing.T) {
	t.Parallel()

	cfg := DefaultDaemonCustodyConfig()
	fsys := newFakeDaemonPreflightFS(cfg)
	report, err := InspectDaemonCustodyPreflight(cfg, WithDaemonPreflightFilesystem(fsys))
	if err != nil {
		t.Fatalf("InspectDaemonCustodyPreflight returned error: %v", err)
	}
	if !report.CanContinue {
		t.Fatalf("CanContinue = false, findings=%+v", report.Findings)
	}
	if len(report.Findings) != 6 {
		t.Fatalf("findings = %d, want 6", len(report.Findings))
	}
	for _, finding := range report.Findings {
		if finding.Verdict != DaemonPreflightVerdictPass {
			t.Fatalf("%s verdict = %q, want pass: %+v", finding.CheckName, finding.Verdict, finding)
		}
		if finding.ObservedUID != 0 || finding.ObservedGID != 0 {
			t.Fatalf("%s owner = %d:%d, want 0:0", finding.CheckName, finding.ObservedUID, finding.ObservedGID)
		}
	}
}

func TestInspectDaemonCustodyPreflightMissingPath(t *testing.T) {
	t.Parallel()

	cfg := DefaultDaemonCustodyConfig()
	fsys := newFakeDaemonPreflightFS(cfg)
	delete(fsys.nodes, cfg.SocketPath)

	report, err := InspectDaemonCustodyPreflight(cfg, WithDaemonPreflightFilesystem(fsys))
	if err != nil {
		t.Fatalf("InspectDaemonCustodyPreflight returned error: %v", err)
	}
	finding := findPreflightFinding(t, report, DaemonPreflightPathSocket)
	if finding.Verdict != DaemonPreflightVerdictMissing {
		t.Fatalf("socket verdict = %q, want missing: %+v", finding.Verdict, finding)
	}
	if report.CanContinue {
		t.Fatalf("CanContinue = true, want false")
	}
}

func TestInspectDaemonCustodyPreflightSymlinkWarningAndEscapeFailure(t *testing.T) {
	t.Parallel()

	cfg := DefaultDaemonCustodyConfig()
	fsys := newFakeDaemonPreflightFS(cfg)
	fsys.nodes[cfg.SocketPath] = daemonPreflightPathInfo{Mode: fs.ModeSymlink | 0o777, UID: 0, GID: 0}
	socketTarget := cfg.SocketPath + ".target"
	fsys.nodes[socketTarget] = daemonPreflightPathInfo{Mode: fs.ModeSocket | 0o660, UID: 0, GID: 0}
	fsys.resolved[cfg.SocketPath] = socketTarget

	report, err := InspectDaemonCustodyPreflight(cfg, WithDaemonPreflightFilesystem(fsys))
	if err != nil {
		t.Fatalf("InspectDaemonCustodyPreflight returned error: %v", err)
	}
	finding := findPreflightFinding(t, report, DaemonPreflightPathSocket)
	if finding.Verdict != DaemonPreflightVerdictWarn || !finding.Symlink {
		t.Fatalf("socket finding = %+v, want symlink warn", finding)
	}

	fsys.resolved[cfg.SocketPath] = "/tmp/ardur/control.sock"
	report, err = InspectDaemonCustodyPreflight(cfg, WithDaemonPreflightFilesystem(fsys))
	if err != nil {
		t.Fatalf("InspectDaemonCustodyPreflight returned error: %v", err)
	}
	finding = findPreflightFinding(t, report, DaemonPreflightPathSocket)
	if finding.Verdict != DaemonPreflightVerdictFail {
		t.Fatalf("socket verdict = %q, want fail: %+v", finding.Verdict, finding)
	}
}

func TestInspectDaemonCustodyPreflightWrongModeOwnerAndType(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		mut      func(DaemonCustodyConfig, *fakeDaemonPreflightFS)
		category string
	}{
		{
			name:     "wrong mode",
			category: DaemonPreflightPathStateDir,
			mut: func(cfg DaemonCustodyConfig, fsys *fakeDaemonPreflightFS) {
				node := fsys.nodes[cfg.StateDir]
				node.Mode = fs.ModeDir | 0o755
				fsys.nodes[cfg.StateDir] = node
			},
		},
		{
			name:     "wrong owner",
			category: DaemonPreflightPathBPFFSDir,
			mut: func(cfg DaemonCustodyConfig, fsys *fakeDaemonPreflightFS) {
				node := fsys.nodes[cfg.BPFFSDir]
				node.UID = 1000
				fsys.nodes[cfg.BPFFSDir] = node
			},
		},
		{
			name:     "directory expected",
			category: DaemonPreflightPathRunDir,
			mut: func(cfg DaemonCustodyConfig, fsys *fakeDaemonPreflightFS) {
				node := fsys.nodes[cfg.RunDir]
				node.Mode = 0o700
				fsys.nodes[cfg.RunDir] = node
			},
		},
		{
			name:     "socket expected",
			category: DaemonPreflightPathSocket,
			mut: func(cfg DaemonCustodyConfig, fsys *fakeDaemonPreflightFS) {
				node := fsys.nodes[cfg.SocketPath]
				node.Mode = 0o660
				fsys.nodes[cfg.SocketPath] = node
			},
		},
		{
			name:     "special mode bit rejected",
			category: DaemonPreflightPathStateDir,
			mut: func(cfg DaemonCustodyConfig, fsys *fakeDaemonPreflightFS) {
				node := fsys.nodes[cfg.StateDir]
				node.Mode = fs.ModeDir | fs.ModeSticky | 0o700
				fsys.nodes[cfg.StateDir] = node
			},
		},
		{
			name:     "regular file expected",
			category: DaemonPreflightPathConfig,
			mut: func(cfg DaemonCustodyConfig, fsys *fakeDaemonPreflightFS) {
				node := fsys.nodes[cfg.ConfigPath]
				node.Mode = fs.ModeDir | 0o600
				fsys.nodes[cfg.ConfigPath] = node
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultDaemonCustodyConfig()
			fsys := newFakeDaemonPreflightFS(cfg)
			tc.mut(cfg, fsys)
			report, err := InspectDaemonCustodyPreflight(cfg, WithDaemonPreflightFilesystem(fsys))
			if err != nil {
				t.Fatalf("InspectDaemonCustodyPreflight returned error: %v", err)
			}
			finding := findPreflightFinding(t, report, tc.category)
			if finding.Verdict != DaemonPreflightVerdictFail {
				t.Fatalf("%s verdict = %q, want fail: %+v", tc.category, finding.Verdict, finding)
			}
		})
	}
}

func TestInspectDaemonCustodyPreflightRejectsRepositoryControlledPath(t *testing.T) {
	t.Parallel()

	cfg := DefaultDaemonCustodyConfig()
	cfg.RepositoryRoot = "/sys/fs/bpf"
	fsys := newFakeDaemonPreflightFS(cfg)

	report, err := InspectDaemonCustodyPreflight(cfg, WithDaemonPreflightFilesystem(fsys))
	if err != nil {
		t.Fatalf("InspectDaemonCustodyPreflight returned error: %v", err)
	}
	if report.CanContinue {
		t.Fatalf("CanContinue = true, want false")
	}
	finding := findPreflightFinding(t, report, DaemonPreflightPathBPFFSDir)
	if finding.Verdict != DaemonPreflightVerdictFail {
		t.Fatalf("bpffs verdict = %q, want fail: %+v", finding.Verdict, finding)
	}
	if finding.Details != "privileged custody path is repository-controlled" {
		t.Fatalf("details = %q", finding.Details)
	}
}

func findPreflightFinding(t *testing.T, report DaemonPreflightReport, category string) DaemonPreflightFinding {
	t.Helper()
	for _, finding := range report.Findings {
		if finding.PathCategory == category {
			return finding
		}
	}
	t.Fatalf("missing finding category %q in %+v", category, report.Findings)
	return DaemonPreflightFinding{}
}

type fakeDaemonPreflightFS struct {
	nodes    map[string]daemonPreflightPathInfo
	resolved map[string]string
}

func newFakeDaemonPreflightFS(cfg DaemonCustodyConfig) *fakeDaemonPreflightFS {
	fsys := &fakeDaemonPreflightFS{
		nodes:    map[string]daemonPreflightPathInfo{},
		resolved: map[string]string{},
	}
	add := func(path string, mode fs.FileMode) {
		fsys.nodes[path] = daemonPreflightPathInfo{Mode: mode, UID: 0, GID: 0}
		fsys.resolved[path] = path
	}
	add(cfg.ConfigPath, 0o600)
	add(cfg.StateDir, fs.ModeDir|0o700)
	add(cfg.RunDir, fs.ModeDir|0o700)
	add(cfg.SocketPath, fs.ModeSocket|0o660)
	add(cfg.BPFFSDir, fs.ModeDir|0o700)
	add(cfg.RingbufMapPath, 0o700)
	return fsys
}

func (fsys *fakeDaemonPreflightFS) Lstat(path string) (daemonPreflightPathInfo, error) {
	info, ok := fsys.nodes[path]
	if !ok {
		return daemonPreflightPathInfo{}, fs.ErrNotExist
	}
	return info, nil
}

func (fsys *fakeDaemonPreflightFS) Stat(path string) (daemonPreflightPathInfo, error) {
	info, ok := fsys.nodes[path]
	if !ok {
		return daemonPreflightPathInfo{}, fs.ErrNotExist
	}
	if info.Mode&fs.ModeSymlink != 0 {
		resolved := fsys.resolved[path]
		target, ok := fsys.nodes[resolved]
		if !ok {
			return daemonPreflightPathInfo{}, fs.ErrNotExist
		}
		return target, nil
	}
	return info, nil
}

func (fsys *fakeDaemonPreflightFS) EvalSymlinks(path string) (string, error) {
	resolved, ok := fsys.resolved[path]
	if !ok {
		return "", fs.ErrNotExist
	}
	return resolved, nil
}
