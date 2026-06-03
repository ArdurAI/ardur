package kernelcapture

import (
	"sync"
)

// DaemonSessionStatusSnapshotSink is a daemon-side in-memory log that retains detached
// internal DaemonSessionStatusSnapshot copies. It is deliberately internal-only:
// snapshots are never serialized into the client-visible daemon protocol response.
// The sink performs no persistence, filesystem writes, cgroup assignment, BPF map
// mutation, or live enforcement.
type DaemonSessionStatusSnapshotSink struct {
	mu        sync.Mutex
	snapshots []DaemonSessionStatusSnapshot
}

// NewDaemonSessionStatusSnapshotSink returns an empty in-memory snapshot sink.
func NewDaemonSessionStatusSnapshotSink() *DaemonSessionStatusSnapshotSink {
	return &DaemonSessionStatusSnapshotSink{}
}

// Retain stores a detached copy of snapshot in the sink. The caller's snapshot is
// not mutated and the sink's copy is independent of caller memory.
func (s *DaemonSessionStatusSnapshotSink) Retain(snapshot DaemonSessionStatusSnapshot) {
	if s == nil {
		return
	}
	detached := copyDaemonSessionStatusSnapshot(snapshot)
	s.mu.Lock()
	s.snapshots = append(s.snapshots, detached)
	s.mu.Unlock()
}

// Snapshots returns detached copies of every retained snapshot. The returned slice
// is a new allocation and each element is independently detached from the sink's
// internal state.
func (s *DaemonSessionStatusSnapshotSink) Snapshots() []DaemonSessionStatusSnapshot {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]DaemonSessionStatusSnapshot, len(s.snapshots))
	for i, snapshot := range s.snapshots {
		result[i] = copyDaemonSessionStatusSnapshot(snapshot)
	}
	return result
}

// copyDaemonSessionStatusSnapshot returns a deep copy of a snapshot that is
// independently detached from the original.
func copyDaemonSessionStatusSnapshot(snapshot DaemonSessionStatusSnapshot) DaemonSessionStatusSnapshot {
	snapshot.Session = copyDaemonSessionRecord(snapshot.Session)
	snapshot.HandoffPlan = copyDaemonSessionHandoffPlan(snapshot.HandoffPlan)
	snapshot.ClaimBoundary = copyStringSlice(snapshot.ClaimBoundary)
	snapshot.NotClaimed = copyStringSlice(snapshot.NotClaimed)
	return snapshot
}

// copyDaemonSessionHandoffPlan returns a deep copy of a handoff plan.
func copyDaemonSessionHandoffPlan(plan DaemonSessionHandoffPlan) DaemonSessionHandoffPlan {
	plan.Steps = copyDaemonSessionHandoffSteps(plan.Steps)
	plan.CgroupFilterSequence.AllowlistCgroupIDs = copyUint64Slice(plan.CgroupFilterSequence.AllowlistCgroupIDs)
	plan.ClaimBoundary = copyStringSlice(plan.ClaimBoundary)
	plan.NotClaimed = copyStringSlice(plan.NotClaimed)
	return plan
}

func copyDaemonSessionHandoffSteps(steps []DaemonSessionHandoffStep) []DaemonSessionHandoffStep {
	if steps == nil {
		return nil
	}
	result := make([]DaemonSessionHandoffStep, len(steps))
	copy(result, steps)
	return result
}

func copyStringSlice(src []string) []string {
	if src == nil {
		return nil
	}
	result := make([]string, len(src))
	copy(result, src)
	return result
}

func copyUint64Slice(src []uint64) []uint64 {
	if src == nil {
		return nil
	}
	result := make([]uint64, len(src))
	copy(result, src)
	return result
}
