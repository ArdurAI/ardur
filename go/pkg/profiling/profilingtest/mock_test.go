package profilingtest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/profiling"
)

func baselineProfile() *profiling.ApplicationProfile {
	return &profiling.ApplicationProfile{
		Name:      "weather-bot-0",
		Namespace: "vibap-agents",
		Container: "agent",
		Syscalls:  []string{"read", "write", "openat", "close", "mmap", "fstat"},
		Endpoints: []string{"tcp://weather-api:8080", "tcp://dns:53"},
		Execs: []profiling.ExecCall{
			{Path: "/usr/bin/python3", Args: []string{"main.py"}},
		},
		FileAccesses: []profiling.FileAccess{
			{Path: "/app/config.yaml", Flags: []string{"O_RDONLY"}},
			{Path: "/tmp/cache", Flags: []string{"O_RDWR", "O_CREAT"}},
		},
		Capabilities: []string{"NET_BIND_SERVICE"},
		ProfiledAt:   time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC),
		Status:       "ready",
	}
}

func TestMockProfileProvider(t *testing.T) {
	t.Run("get existing profile", func(t *testing.T) {
		mock := NewMockProfileProvider()
		defer mock.Close()

		profile := baselineProfile()
		mock.AddProfile(profile)

		got, err := mock.GetProfile(context.Background(), "vibap-agents", "weather-bot-0", "agent")
		if err != nil {
			t.Fatalf("GetProfile: %v", err)
		}
		if got.Name != "weather-bot-0" {
			t.Errorf("name = %s, want weather-bot-0", got.Name)
		}
	})

	t.Run("profile not found", func(t *testing.T) {
		mock := NewMockProfileProvider()
		defer mock.Close()

		_, err := mock.GetProfile(context.Background(), "ns", "pod", "container")
		if !errors.Is(err, profiling.ErrProfileNotFound) {
			t.Errorf("err = %v, want ErrProfileNotFound", err)
		}
	})

	t.Run("configured error", func(t *testing.T) {
		mock := NewMockProfileProvider()
		defer mock.Close()
		mock.SetGetError(profiling.ErrProfileNotReady)

		_, err := mock.GetProfile(context.Background(), "ns", "pod", "container")
		if !errors.Is(err, profiling.ErrProfileNotReady) {
			t.Errorf("err = %v, want ErrProfileNotReady", err)
		}
	})

	t.Run("closed provider", func(t *testing.T) {
		mock := NewMockProfileProvider()
		mock.Close()

		_, err := mock.GetProfile(context.Background(), "ns", "pod", "container")
		if !errors.Is(err, profiling.ErrProviderClosed) {
			t.Errorf("err = %v, want ErrProviderClosed", err)
		}
	})

	t.Run("compare profiles", func(t *testing.T) {
		mock := NewMockProfileProvider()
		defer mock.Close()

		baseline := baselineProfile()
		current := baselineProfile()
		current.Syscalls = append(current.Syscalls, "execve")

		diff, err := mock.CompareProfiles(baseline, current)
		if err != nil {
			t.Fatalf("CompareProfiles: %v", err)
		}
		if !diff.HasDrift {
			t.Error("expected drift")
		}
	})

	t.Run("get count", func(t *testing.T) {
		mock := NewMockProfileProvider()
		defer mock.Close()

		profile := baselineProfile()
		mock.AddProfile(profile)

		mock.GetProfile(context.Background(), "vibap-agents", "weather-bot-0", "agent")
		mock.GetProfile(context.Background(), "vibap-agents", "weather-bot-0", "agent")

		if mock.GetCount() != 2 {
			t.Errorf("get count = %d, want 2", mock.GetCount())
		}
	})
}
