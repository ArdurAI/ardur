//go:build linux

package kernelcapture

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProcessExecAllowedCgroupsCapacityMatchesSessionRegistry(t *testing.T) {
	spec, err := loadProcessExec()
	if err != nil {
		t.Fatalf("load process-exec collection spec: %v", err)
	}
	allowed := spec.Maps[processExecMapAllowedCgroups]
	if allowed == nil {
		t.Fatal("process-exec collection spec is missing allowed_cgroups")
	}
	if got, want := int(allowed.MaxEntries), DefaultDaemonSessionRegistryMaxSessions; got != want {
		t.Fatalf("allowed_cgroups max entries = %d, registry capacity = %d", got, want)
	}
}

func TestProcessExecRecognitionMapIsBoundedToLinuxCommKeys(t *testing.T) {
	spec, err := loadProcessExec()
	if err != nil {
		t.Fatalf("load process-exec collection spec: %v", err)
	}
	recognition := spec.Maps[processExecMapRecognitionComms]
	if recognition == nil {
		t.Fatal("process-exec collection spec is missing recognition_comms")
	}
	if got, want := int(recognition.MaxEntries), processExecRecognitionMax; got != want {
		t.Fatalf("recognition_comms max entries = %d, want %d", got, want)
	}
	if got, want := recognition.KeySize, uint32(16); got != want {
		t.Fatalf("recognition_comms key size = %d, want %d", got, want)
	}
	if spec.Maps[processExecMapRecognitionControl] == nil {
		t.Fatal("process-exec collection spec is missing recognition_control")
	}
}

func TestNormalizePinnedEBPFPathsDerivesLifecycleMapSiblings(t *testing.T) {
	paths := normalizePinnedEBPFPaths(PinnedEBPFPaths{
		EventsMapPath: "/sys/fs/bpf/ardur/custom_events",
	})
	wants := map[string]string{
		"DroppedEventsMapPath":      "/sys/fs/bpf/ardur/process_lifecycle_events_dropped",
		"FilterControlMapPath":      "/sys/fs/bpf/ardur/process_lifecycle_filter_control",
		"AllowedCgroupsMapPath":     "/sys/fs/bpf/ardur/process_lifecycle_allowed_cgroups",
		"RecognitionControlMapPath": "/sys/fs/bpf/ardur/process_recognition_filter_control",
		"RecognitionCommsMapPath":   "/sys/fs/bpf/ardur/process_recognition_comms",
	}
	gots := map[string]string{
		"DroppedEventsMapPath":      paths.DroppedEventsMapPath,
		"FilterControlMapPath":      paths.FilterControlMapPath,
		"AllowedCgroupsMapPath":     paths.AllowedCgroupsMapPath,
		"RecognitionControlMapPath": paths.RecognitionControlMapPath,
		"RecognitionCommsMapPath":   paths.RecognitionCommsMapPath,
	}
	for field, want := range wants {
		if got := gots[field]; got != want {
			t.Errorf("%s = %q, want %q", field, got, want)
		}
	}
}

func TestRemovePinnedProcessExecStateRemovesCompleteAndPartialSets(t *testing.T) {
	dir := t.TempDir()
	paths := PinnedEBPFPaths{
		ExecLinkPath:              filepath.Join(dir, "exec"),
		ExitLinkPath:              filepath.Join(dir, "exit"),
		EventsMapPath:             filepath.Join(dir, "events"),
		DroppedEventsMapPath:      filepath.Join(dir, "dropped"),
		FilterControlMapPath:      filepath.Join(dir, "filter_control"),
		AllowedCgroupsMapPath:     filepath.Join(dir, "allowed_cgroups"),
		RecognitionControlMapPath: filepath.Join(dir, "recognition_control"),
		RecognitionCommsMapPath:   filepath.Join(dir, "recognition_comms"),
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
