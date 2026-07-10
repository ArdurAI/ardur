//go:build linux

package kernelcapture

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizePinnedEBPFPathsDerivesDropCounterSibling(t *testing.T) {
	paths := normalizePinnedEBPFPaths(PinnedEBPFPaths{
		EventsMapPath: "/sys/fs/bpf/ardur/custom_events",
	})
	want := "/sys/fs/bpf/ardur/process_lifecycle_events_dropped"
	if paths.DroppedEventsMapPath != want {
		t.Fatalf("DroppedEventsMapPath = %q, want %q", paths.DroppedEventsMapPath, want)
	}
}

func TestRemovePinnedProcessExecStateRemovesCompleteAndPartialSets(t *testing.T) {
	dir := t.TempDir()
	paths := PinnedEBPFPaths{
		ExecLinkPath:         filepath.Join(dir, "exec"),
		ExitLinkPath:         filepath.Join(dir, "exit"),
		EventsMapPath:        filepath.Join(dir, "events"),
		DroppedEventsMapPath: filepath.Join(dir, "dropped"),
	}
	for _, path := range pinnedProcessExecPaths(paths) {
		if err := os.WriteFile(path, []byte("pin"), 0o600); err != nil {
			t.Fatalf("create fake pin %q: %v", path, err)
		}
	}
	if err := removePinnedProcessExecState(paths); err != nil {
		t.Fatalf("remove complete pin set: %v", err)
	}
	for _, path := range pinnedProcessExecPaths(paths) {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("pin %q still exists or returned unexpected error: %v", path, err)
		}
	}

	if err := os.WriteFile(paths.ExecLinkPath, []byte("partial"), 0o600); err != nil {
		t.Fatalf("create partial fake pin: %v", err)
	}
	if err := removePinnedProcessExecState(paths); err != nil {
		t.Fatalf("remove partial pin set: %v", err)
	}
}
