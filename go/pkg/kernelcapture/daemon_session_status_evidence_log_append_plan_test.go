package kernelcapture

import (
	"errors"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOpenDaemonSessionStatusEvidenceLogAppendStateCopiesPlan(t *testing.T) {
	t.Parallel()

	openedAt := time.Date(2026, 6, 5, 12, 30, 0, 123456789, time.UTC)
	cfg := daemonSessionStatusEvidenceLogConfigForTest(t, "append-open-session")
	plan, err := BuildDaemonSessionStatusEvidenceLogPlan(cfg)
	if err != nil {
		t.Fatalf("BuildDaemonSessionStatusEvidenceLogPlan returned error: %v", err)
	}

	state, err := NewDaemonSessionStatusEvidenceLogAppendState(plan, func() time.Time { return openedAt })
	if err != nil {
		t.Fatalf("NewDaemonSessionStatusEvidenceLogAppendState returned error: %v", err)
	}
	snapshot := state.Snapshot()
	if snapshot.OpenedAt != openedAt {
		t.Fatalf("opened_at = %s, want %s", snapshot.OpenedAt, openedAt)
	}
	if snapshot.TotalBytes != 0 || snapshot.EntryCount != 0 || len(snapshot.Entries) != 0 || snapshot.RotationCount != 0 {
		t.Fatalf("initial state is not empty: %#v", snapshot)
	}
	if snapshot.Plan.EntryDigest != plan.EntryDigest || snapshot.Plan.EvidenceLogPath != plan.EvidenceLogPath {
		t.Fatalf("state plan was not copied from source plan: %#v", snapshot.Plan)
	}

	snapshot.Plan.EntryDigest = strings.Repeat("0", 64)
	again := state.Snapshot()
	if again.Plan.EntryDigest != plan.EntryDigest {
		t.Fatalf("snapshot mutation leaked into state plan: %q", again.Plan.EntryDigest)
	}
}

func TestDaemonSessionStatusEvidenceLogAppendStateAcceptsAndCopiesEntries(t *testing.T) {
	t.Parallel()

	state, entry := appendStateAndEntryForTest(t, "append-accept-session", 8192, DefaultDaemonSessionStatusEvidenceLogMaxLogBytes)

	first, err := PlanDaemonSessionStatusEvidenceLogAppend(state, entry)
	if err != nil {
		t.Fatalf("first append plan returned error: %v", err)
	}
	if first.Decision != DaemonSessionStatusEvidenceLogAppendAccept {
		t.Fatalf("first decision = %q", first.Decision)
	}
	if first.PreBytes != 0 || first.EntryBytes != int64(len(entry)) || first.PostBytes != int64(len(entry)) {
		t.Fatalf("first byte accounting = %#v, entry len %d", first, len(entry))
	}
	if !containsText(first.ClaimBoundary, "in-memory append decision") || !containsText(first.NotClaimed, "filesystem writes") {
		t.Fatalf("append plan boundaries missing no-write language: %#v / %#v", first.ClaimBoundary, first.NotClaimed)
	}
	assertAppendPlanStepsUnexecuted(t, first)

	second, err := PlanDaemonSessionStatusEvidenceLogAppend(state, entry)
	if err != nil {
		t.Fatalf("second append plan returned error: %v", err)
	}
	if second.Decision != DaemonSessionStatusEvidenceLogAppendAccept {
		t.Fatalf("second decision = %q", second.Decision)
	}
	if second.PreBytes != int64(len(entry)) || second.PostBytes != int64(len(entry))*2 {
		t.Fatalf("second byte accounting = %#v", second)
	}

	snapshot := state.Snapshot()
	if snapshot.EntryCount != 2 || len(snapshot.Entries) != 2 || snapshot.TotalBytes != int64(len(entry))*2 {
		t.Fatalf("state did not retain two in-memory entries: %#v", snapshot)
	}
	entry[0]++
	fresh := state.Snapshot()
	if string(fresh.Entries[0]) != string(snapshot.Entries[0]) {
		t.Fatalf("caller entry mutation leaked into retained fake sink entry")
	}
}

func TestDaemonSessionStatusEvidenceLogAppendStateRotatesInMemoryWhenExceeded(t *testing.T) {
	t.Parallel()

	state, entry := appendStateAndEntryForTest(t, "append-rotate-session", 8192, 8192)
	state.mu.Lock()
	state.totalBytes = int64(len(entry))
	state.entries = [][]byte{append([]byte(nil), entry...)}
	state.mu.Unlock()

	plan, err := PlanDaemonSessionStatusEvidenceLogAppend(state, entry)
	if err != nil {
		t.Fatalf("append rotation plan returned error: %v", err)
	}
	if plan.Decision != DaemonSessionStatusEvidenceLogAppendRotateThenAppend {
		t.Fatalf("decision = %q", plan.Decision)
	}
	if plan.PreBytes != int64(len(entry)) || plan.PostBytes != int64(len(entry)) {
		t.Fatalf("rotation byte accounting = %#v", plan)
	}
	if plan.RotationPath == "" {
		t.Fatalf("rotation path is empty")
	}
	if !lexicalPathWithin(plan.RotationPath, filepath.Dir(plan.EvidenceLogPath)) {
		t.Fatalf("rotation path %q escaped evidence log directory %q", plan.RotationPath, filepath.Dir(plan.EvidenceLogPath))
	}
	if !strings.HasPrefix(plan.RotationPath, plan.EvidenceLogPath+".") {
		t.Fatalf("rotation path %q is not derived from evidence log path %q", plan.RotationPath, plan.EvidenceLogPath)
	}
	assertAppendPlanStepsUnexecuted(t, plan)

	snapshot := state.Snapshot()
	if snapshot.RotationCount != 1 || snapshot.EntryCount != 1 || snapshot.TotalBytes != int64(len(entry)) {
		t.Fatalf("state did not simulate rotate-then-append: %#v", snapshot)
	}
}

func TestDaemonSessionStatusEvidenceLogAppendStateCyclesRotationSlots(t *testing.T) {
	t.Parallel()

	state, entry := appendStateAndEntryForTest(t, "append-rotation-cycle-session", 8192, 8192)

	var paths []string
	for i := 0; i < 4; i++ {
		state.mu.Lock()
		state.totalBytes = int64(len(entry))
		state.entries = [][]byte{append([]byte(nil), entry...)}
		state.mu.Unlock()

		plan, err := PlanDaemonSessionStatusEvidenceLogAppend(state, entry)
		if err != nil {
			t.Fatalf("rotation %d returned error: %v", i, err)
		}
		if plan.Decision != DaemonSessionStatusEvidenceLogAppendRotateThenAppend {
			t.Fatalf("rotation %d decision = %q", i, plan.Decision)
		}
		paths = append(paths, plan.RotationPath)
	}

	if paths[0] != paths[3] {
		t.Fatalf("rotation slot did not wrap after MaxRotatedFiles: first=%q fourth=%q all=%#v", paths[0], paths[3], paths)
	}
	if paths[0] == paths[1] || paths[1] == paths[2] {
		t.Fatalf("rotation slots did not advance before wrap: %#v", paths)
	}
}

func TestDaemonSessionStatusEvidenceLogAppendStateAllowsConcurrentFakeSinkAppends(t *testing.T) {
	t.Parallel()

	state, entry := appendStateAndEntryForTest(t, "append-concurrent-session", 8192, DefaultDaemonSessionStatusEvidenceLogMaxLogBytes)
	const workers = 16

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			plan, err := PlanDaemonSessionStatusEvidenceLogAppend(state, entry)
			if err != nil {
				errs <- err
				return
			}
			if plan.Decision != DaemonSessionStatusEvidenceLogAppendAccept {
				errs <- errors.New("unexpected non-accept decision: " + string(plan.Decision))
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent append returned error: %v", err)
		}
	}

	snapshot := state.Snapshot()
	if snapshot.EntryCount != workers || len(snapshot.Entries) != workers {
		t.Fatalf("concurrent fake sink entry count = %d/%d, want %d", snapshot.EntryCount, len(snapshot.Entries), workers)
	}
	if snapshot.TotalBytes != int64(len(entry))*workers {
		t.Fatalf("concurrent fake sink total bytes = %d, want %d", snapshot.TotalBytes, int64(len(entry))*workers)
	}
}

func TestDaemonSessionStatusEvidenceLogAppendStateRejectsEntryTooLarge(t *testing.T) {
	t.Parallel()

	state, entry := appendStateAndEntryForTest(t, "append-too-large-session", 8192, DefaultDaemonSessionStatusEvidenceLogMaxLogBytes)
	state.mu.Lock()
	state.plan.MaxEntryBytes = int64(len(entry) - 1)
	state.mu.Unlock()

	plan, err := PlanDaemonSessionStatusEvidenceLogAppend(state, entry)
	if err != nil {
		t.Fatalf("oversized append should return reject plan, got error: %v", err)
	}
	if plan.Decision != DaemonSessionStatusEvidenceLogAppendReject {
		t.Fatalf("decision = %q", plan.Decision)
	}
	if plan.Reason == "" || !strings.Contains(plan.Reason, "exceeds max entry") {
		t.Fatalf("reject reason = %q", plan.Reason)
	}
	if state.Snapshot().EntryCount != 0 {
		t.Fatalf("reject mutated in-memory state: %#v", state.Snapshot())
	}
}

func TestDaemonSessionStatusEvidenceLogAppendStateFailsClosed(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		nilState bool
		entryMut func([]byte) []byte
		stateMut func(*DaemonSessionStatusEvidenceLogAppendState, []byte)
		want     string
	}{
		{name: "nil state", nilState: true, want: "state"},
		{name: "empty entry", entryMut: func(_ []byte) []byte { return nil }, want: "entry"},
		{name: "missing newline", entryMut: func(entry []byte) []byte {
			return []byte(strings.TrimSuffix(string(entry), "\n"))
		}, want: "newline"},
		{name: "malformed json", entryMut: func(_ []byte) []byte { return []byte("{not-json}\n") }, want: "JSON"},
		{name: "entry digest mismatch", entryMut: func(entry []byte) []byte {
			return corruptEntryDigestForTest(t, entry)
		}, want: "digest"},
		{name: "non canonical json", entryMut: func(entry []byte) []byte {
			return []byte(strings.Replace(string(entry), `,"entry_kind"`, `, "entry_kind"`, 1))
		}, want: "canonical"},
		{name: "invalid state plan", stateMut: func(s *DaemonSessionStatusEvidenceLogAppendState, _ []byte) {
			s.plan.Steps[0].Executed = true
		}, want: "executed"},
		{name: "overflow guard", stateMut: func(s *DaemonSessionStatusEvidenceLogAppendState, entry []byte) {
			s.totalBytes = math.MaxInt64 - int64(len(entry)) + 1
		}, want: "overflow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			localState, localEntry := appendStateAndEntryForTest(t, "append-fail-"+strings.ReplaceAll(tc.name, " ", "-"), 8192, DefaultDaemonSessionStatusEvidenceLogMaxLogBytes)
			if tc.nilState {
				localState = nil
			}
			if tc.entryMut != nil {
				localEntry = tc.entryMut(localEntry)
			}
			if tc.stateMut != nil && localState != nil {
				localState.mu.Lock()
				tc.stateMut(localState, localEntry)
				localState.mu.Unlock()
			}

			_, err := PlanDaemonSessionStatusEvidenceLogAppend(localState, localEntry)
			if err == nil {
				t.Fatalf("expected failure")
			}
			if !errors.Is(err, ErrDaemonSessionStatusEvidenceLogAppendPlan) {
				t.Fatalf("expected ErrDaemonSessionStatusEvidenceLogAppendPlan, got %v", err)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func appendStateAndEntryForTest(t *testing.T, sessionID string, maxEntryBytes int64, maxLogBytes int64) (*DaemonSessionStatusEvidenceLogAppendState, []byte) {
	t.Helper()

	cfg := daemonSessionStatusEvidenceLogConfigForTest(t, sessionID)
	cfg.MaxEntryBytes = maxEntryBytes
	cfg.MaxLogBytes = maxLogBytes
	plan, err := BuildDaemonSessionStatusEvidenceLogPlan(cfg)
	if err != nil {
		t.Fatalf("BuildDaemonSessionStatusEvidenceLogPlan returned error: %v", err)
	}
	entry, err := BuildDaemonSessionStatusEvidenceLogEntry(plan, cfg.Snapshot)
	if err != nil {
		t.Fatalf("BuildDaemonSessionStatusEvidenceLogEntry returned error: %v", err)
	}
	state, err := NewDaemonSessionStatusEvidenceLogAppendState(plan, func() time.Time {
		return time.Date(2026, 6, 5, 13, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatalf("NewDaemonSessionStatusEvidenceLogAppendState returned error: %v", err)
	}
	return state, entry
}

func corruptEntryDigestForTest(t *testing.T, entry []byte) []byte {
	t.Helper()

	mutated := append([]byte(nil), entry...)
	old := []byte(`"entry_digest":"`)
	idx := strings.Index(string(mutated), string(old))
	if idx < 0 {
		t.Fatalf("entry digest field not found in %q", string(mutated))
	}
	start := idx + len(old)
	if start >= len(mutated) {
		t.Fatalf("entry digest field malformed")
	}
	if mutated[start] == '0' {
		mutated[start] = '1'
	} else {
		mutated[start] = '0'
	}
	return mutated
}

func assertAppendPlanStepsUnexecuted(t *testing.T, plan DaemonSessionStatusEvidenceLogAppendPlan) {
	t.Helper()

	if len(plan.Steps) == 0 {
		t.Fatalf("append plan has no steps")
	}
	for i, step := range plan.Steps {
		if strings.TrimSpace(step.Name) == "" || strings.TrimSpace(step.Rationale) == "" {
			t.Fatalf("append step %d is missing name/rationale: %#v", i, step)
		}
		if step.Executed {
			t.Fatalf("append step %d is executed: %#v", i, step)
		}
	}
}
