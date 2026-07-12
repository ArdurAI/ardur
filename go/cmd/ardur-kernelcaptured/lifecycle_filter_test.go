package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeLifecycleCgroupFilter struct {
	mu                             sync.Mutex
	ops                            []string
	allowed                        map[uint64]struct{}
	enabled                        bool
	fail                           map[string]error
	recognitionComms               []string
	recognitionExecutableBasenames []string
}

func newFakeLifecycleCgroupFilter() *fakeLifecycleCgroupFilter {
	return &fakeLifecycleCgroupFilter{
		allowed: make(map[uint64]struct{}),
		fail:    make(map[string]error),
	}
}

func (f *fakeLifecycleCgroupFilter) record(op string) error {
	f.ops = append(f.ops, op)
	return f.fail[op]
}

func (f *fakeLifecycleCgroupFilter) SetLifecycleCgroupFilterEnabled(enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	op := fmt.Sprintf("enabled:%t", enabled)
	if err := f.record(op); err != nil {
		return err
	}
	f.enabled = enabled
	return nil
}

func (f *fakeLifecycleCgroupFilter) AllowLifecycleCgroup(cgroupID uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	op := fmt.Sprintf("allow:%d", cgroupID)
	if err := f.record(op); err != nil {
		return err
	}
	f.allowed[cgroupID] = struct{}{}
	return nil
}

func (f *fakeLifecycleCgroupFilter) RemoveLifecycleCgroup(cgroupID uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	op := fmt.Sprintf("remove:%d", cgroupID)
	if err := f.record(op); err != nil {
		return err
	}
	delete(f.allowed, cgroupID)
	return nil
}

func (f *fakeLifecycleCgroupFilter) ClearLifecycleCgroups() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("clear"); err != nil {
		return err
	}
	clear(f.allowed)
	return nil
}

func (f *fakeLifecycleCgroupFilter) ConfigureAgentRecognitionNames(comms, executableBasenames []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	op := "recognition:" + strings.Join(comms, ",") + ";" + strings.Join(executableBasenames, ",")
	if err := f.record(op); err != nil {
		return err
	}
	f.recognitionComms = append([]string(nil), comms...)
	f.recognitionExecutableBasenames = append([]string(nil), executableBasenames...)
	return nil
}

func TestLifecycleFilterInstallKeepsIdleProducerQuiet(t *testing.T) {
	manager := newLifecycleFilterManager()
	filter := newFakeLifecycleCgroupFilter()
	if err := manager.install(filter); err != nil {
		t.Fatalf("install: %v", err)
	}
	if !filter.enabled || len(filter.allowed) != 0 {
		t.Fatalf("idle filter enabled=%t allowed=%v, want enabled empty", filter.enabled, filter.allowed)
	}
	wantOps := []string{"enabled:false", "clear", "enabled:true", "recognition:;"}
	if !reflect.DeepEqual(filter.ops, wantOps) {
		t.Fatalf("install operations = %v, want %v", filter.ops, wantOps)
	}
}

func TestLifecycleFilterInstallsRecognitionWithoutWeakeningCgroupScope(t *testing.T) {
	manager := newLifecycleFilterManager()
	if err := manager.setAgentRecognitionNames([]string{"claude", "codex"}, []string{"claude", "codex"}); err != nil {
		t.Fatal(err)
	}
	filter := newFakeLifecycleCgroupFilter()
	if err := manager.install(filter); err != nil {
		t.Fatalf("install: %v", err)
	}
	if !filter.enabled || !reflect.DeepEqual(filter.recognitionComms, []string{"claude", "codex"}) || !reflect.DeepEqual(filter.recognitionExecutableBasenames, []string{"claude", "codex"}) {
		t.Fatalf("installed state enabled=%t comms=%v basenames=%v", filter.enabled, filter.recognitionComms, filter.recognitionExecutableBasenames)
	}
	if err := manager.agentRecognitionError(); err != nil {
		t.Fatalf("recognition status: %v", err)
	}
}

func TestLifecycleFilterRecognitionFailureKeepsScopedProducerSafe(t *testing.T) {
	manager := newLifecycleFilterManager()
	if err := manager.setAgentRecognitionNames([]string{"claude"}, []string{"claude"}); err != nil {
		t.Fatal(err)
	}
	filter := newFakeLifecycleCgroupFilter()
	filter.fail["recognition:claude;claude"] = errors.New("recognition map unavailable")
	if err := manager.install(filter); err != nil {
		t.Fatalf("optional recognition failure broke lifecycle install: %v", err)
	}
	if !filter.enabled || len(filter.recognitionComms) != 0 {
		t.Fatalf("unsafe fallback enabled=%t recognition=%v", filter.enabled, filter.recognitionComms)
	}
	if err := manager.agentRecognitionError(); err == nil {
		t.Fatal("recognition failure was not reported")
	}
}

func TestLifecycleFilterWaitsForStartupThenTracksMultipleSessions(t *testing.T) {
	manager := newLifecycleFilterManager()
	result := make(chan error, 1)
	go func() {
		_, err := manager.prepare(context.Background(), "session-a", 11)
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("prepare returned before startup resolved: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	filter := newFakeLifecycleCgroupFilter()
	if err := manager.install(filter); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := <-result; err != nil {
		t.Fatalf("prepare session-a: %v", err)
	}
	if added, err := manager.prepare(context.Background(), "session-b", 22); err != nil || !added {
		t.Fatalf("prepare session-b added=%t err=%v", added, err)
	}
	if err := manager.remove("session-a"); err != nil {
		t.Fatalf("remove session-a: %v", err)
	}
	if _, ok := filter.allowed[22]; !ok {
		t.Fatal("removing one session removed the other allowed cgroup")
	}
	if err := manager.remove("session-b"); err != nil {
		t.Fatalf("remove session-b: %v", err)
	}
	if !filter.enabled || len(filter.allowed) != 0 {
		t.Fatalf("last removal enabled=%t allowed=%v, want enabled empty", filter.enabled, filter.allowed)
	}
}

func TestLifecycleFilterAddFailureRejectsReservation(t *testing.T) {
	manager := newLifecycleFilterManager()
	filter := newFakeLifecycleCgroupFilter()
	if err := manager.install(filter); err != nil {
		t.Fatalf("install: %v", err)
	}
	filter.fail["allow:33"] = errors.New("map full")
	if added, err := manager.prepare(context.Background(), "session-a", 33); err == nil || added {
		t.Fatalf("prepare with failed map update added=%t err=%v", added, err)
	}
	if len(manager.sessions) != 0 || len(filter.allowed) != 0 {
		t.Fatalf("failed reservation leaked manager=%v filter=%v", manager.sessions, filter.allowed)
	}
}

func TestLifecycleFilterDuplicateRegistrationRollbackKeepsExistingBinding(t *testing.T) {
	manager := newLifecycleFilterManager()
	filter := newFakeLifecycleCgroupFilter()
	if err := manager.install(filter); err != nil {
		t.Fatalf("install: %v", err)
	}
	if added, err := manager.prepare(context.Background(), "session-a", 44); err != nil || !added {
		t.Fatalf("first prepare added=%t err=%v", added, err)
	}
	if added, err := manager.prepare(context.Background(), "session-a", 44); err != nil || added {
		t.Fatalf("duplicate prepare added=%t err=%v", added, err)
	}
	if _, ok := filter.allowed[44]; !ok {
		t.Fatal("duplicate admission removed the existing cgroup binding")
	}
}

func TestLifecycleFilterInstallFailureLeavesPermissiveFallback(t *testing.T) {
	manager := newLifecycleFilterManager()
	filter := newFakeLifecycleCgroupFilter()
	filter.fail["clear"] = errors.New("clear failed")
	if err := manager.install(filter); err == nil {
		t.Fatal("install unexpectedly succeeded")
	}
	if filter.enabled {
		t.Fatal("failed reconciliation left filter enabled and potentially omitting governed events")
	}
	if added, err := manager.prepare(context.Background(), "session-a", 55); err != nil || !added {
		t.Fatalf("permissive fallback prepare added=%t err=%v", added, err)
	}
}

func TestLifecycleFilterRejectsRegistrationWhenPermissiveFallbackCannotBeEstablished(t *testing.T) {
	manager := newLifecycleFilterManager()
	filter := newFakeLifecycleCgroupFilter()
	filter.fail["enabled:false"] = errors.New("control map unavailable")
	if err := manager.install(filter); err == nil {
		t.Fatal("install unexpectedly succeeded")
	}
	if added, err := manager.prepare(context.Background(), "session-a", 56); err == nil || added {
		t.Fatalf("unsafe fallback prepare added=%t err=%v", added, err)
	}
	if len(manager.sessions) != 0 {
		t.Fatalf("unsafe fallback leaked session reservation: %v", manager.sessions)
	}
}

func TestLifecycleFilterDetachLeavesPinnedProducerQuiet(t *testing.T) {
	manager := newLifecycleFilterManager()
	filter := newFakeLifecycleCgroupFilter()
	if err := manager.install(filter); err != nil {
		t.Fatalf("install: %v", err)
	}
	if _, err := manager.prepare(context.Background(), "session-a", 66); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := manager.detach(filter); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if !filter.enabled || len(filter.allowed) != 0 {
		t.Fatalf("detached filter enabled=%t allowed=%v, want enabled empty", filter.enabled, filter.allowed)
	}
	if len(filter.recognitionComms) != 0 {
		t.Fatalf("detached recognition prefilter = %v, want empty", filter.recognitionComms)
	}
	if len(filter.recognitionExecutableBasenames) != 0 {
		t.Fatalf("detached recognition basename prefilter = %v, want empty", filter.recognitionExecutableBasenames)
	}
}
