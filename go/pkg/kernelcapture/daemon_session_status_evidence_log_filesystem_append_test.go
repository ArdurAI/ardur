package kernelcapture

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestDaemonSessionStatusEvidenceLogFilesystemAppendWritesAcceptedEntry(t *testing.T) {
	t.Parallel()

	state, entry := appendStateAndEntryForTest(t, "filesystem-append-accept-session", 8192, DefaultDaemonSessionStatusEvidenceLogMaxLogBytes)
	mapped := newMappedEvidenceLogFilesystemForTest(t, state.Snapshot().Plan.EvidenceLogPath)

	plan, err := ApplyDaemonSessionStatusEvidenceLogFilesystemAppend(DaemonSessionStatusEvidenceLogFilesystemAppendConfig{
		State:      state,
		Filesystem: mapped,
	}, entry)
	if err != nil {
		t.Fatalf("ApplyDaemonSessionStatusEvidenceLogFilesystemAppend returned error: %v", err)
	}
	if plan.Decision != DaemonSessionStatusEvidenceLogAppendAccept {
		t.Fatalf("decision = %q", plan.Decision)
	}
	if plan.PreBytes != 0 || plan.EntryBytes != int64(len(entry)) || plan.PostBytes != int64(len(entry)) {
		t.Fatalf("byte accounting = %#v", plan)
	}
	assertAppendPlanStepsExecuted(t, plan)
	if !containsText(plan.ClaimBoundary, "injected filesystem") {
		t.Fatalf("claim boundary missing injected filesystem scope: %#v", plan.ClaimBoundary)
	}
	if !containsText(plan.NotClaimed, "daemon install/start") || containsText(plan.NotClaimed, "filesystem writes") {
		t.Fatalf("not-claimed boundary is wrong for filesystem append: %#v", plan.NotClaimed)
	}

	content := mapped.readLogicalFile(t, plan.EvidenceLogPath)
	if string(content) != string(entry) {
		t.Fatalf("evidence log content mismatch\n got: %q\nwant: %q", string(content), string(entry))
	}
	if snapshot := state.Snapshot(); snapshot.EntryCount != 1 || snapshot.TotalBytes != int64(len(entry)) {
		t.Fatalf("state was not committed after successful filesystem append: %#v", snapshot)
	}
	if !mapped.sawOp("mkdirall", filepath.Dir(plan.EvidenceLogPath)) || !mapped.sawOp("append", plan.EvidenceLogPath) {
		t.Fatalf("expected mkdirall+append ops, got %#v", mapped.operations())
	}
}

func TestDaemonSessionStatusEvidenceLogFilesystemAppendRotatesAndWritesFreshLog(t *testing.T) {
	t.Parallel()

	state, entry := appendStateAndEntryForTest(t, "filesystem-append-rotate-session", 8192, 8192)
	mapped := newMappedEvidenceLogFilesystemForTest(t, state.Snapshot().Plan.EvidenceLogPath)

	first, err := ApplyDaemonSessionStatusEvidenceLogFilesystemAppend(DaemonSessionStatusEvidenceLogFilesystemAppendConfig{State: state, Filesystem: mapped}, entry)
	if err != nil {
		t.Fatalf("first filesystem append returned error: %v", err)
	}
	if first.Decision != DaemonSessionStatusEvidenceLogAppendAccept {
		t.Fatalf("first decision = %q", first.Decision)
	}

	second, err := ApplyDaemonSessionStatusEvidenceLogFilesystemAppend(DaemonSessionStatusEvidenceLogFilesystemAppendConfig{State: state, Filesystem: mapped}, entry)
	if err != nil {
		t.Fatalf("second filesystem append returned error: %v", err)
	}
	if second.Decision != DaemonSessionStatusEvidenceLogAppendRotateThenAppend {
		t.Fatalf("second decision = %q", second.Decision)
	}
	if second.RotationPath == "" {
		t.Fatalf("rotation path is empty")
	}
	assertAppendPlanStepsExecuted(t, second)

	if string(mapped.readLogicalFile(t, second.RotationPath)) != string(entry) {
		t.Fatalf("rotated evidence log did not contain prior entry")
	}
	if string(mapped.readLogicalFile(t, second.EvidenceLogPath)) != string(entry) {
		t.Fatalf("fresh evidence log did not contain new entry")
	}
	if snapshot := state.Snapshot(); snapshot.EntryCount != 1 || snapshot.RotationCount != 1 || snapshot.TotalBytes != int64(len(entry)) {
		t.Fatalf("state was not committed after successful rotation append: %#v", snapshot)
	}
	if !mapped.sawOp("rename", second.EvidenceLogPath+"->"+second.RotationPath) || !mapped.sawOp("append", second.EvidenceLogPath) {
		t.Fatalf("expected rename+append ops, got %#v", mapped.operations())
	}
}

func TestDaemonSessionStatusEvidenceLogFilesystemAppendRejectDoesNotTouchFilesystem(t *testing.T) {
	t.Parallel()

	state, entry := appendStateAndEntryForTest(t, "filesystem-append-reject-session", 8192, DefaultDaemonSessionStatusEvidenceLogMaxLogBytes)
	state.mu.Lock()
	state.plan.MaxEntryBytes = int64(len(entry) - 1)
	state.mu.Unlock()
	mapped := newMappedEvidenceLogFilesystemForTest(t, state.Snapshot().Plan.EvidenceLogPath)

	plan, err := ApplyDaemonSessionStatusEvidenceLogFilesystemAppend(DaemonSessionStatusEvidenceLogFilesystemAppendConfig{State: state, Filesystem: mapped}, entry)
	if err != nil {
		t.Fatalf("reject should return a plan, not error: %v", err)
	}
	if plan.Decision != DaemonSessionStatusEvidenceLogAppendReject {
		t.Fatalf("decision = %q", plan.Decision)
	}
	assertAppendPlanStepsUnexecuted(t, plan)
	if got := mapped.operations(); len(got) != 0 {
		t.Fatalf("reject touched filesystem: %#v", got)
	}
	if snapshot := state.Snapshot(); snapshot.EntryCount != 0 || snapshot.TotalBytes != 0 {
		t.Fatalf("reject mutated state: %#v", snapshot)
	}
}

func TestDaemonSessionStatusEvidenceLogFilesystemAppendFailsClosedBeforeFilesystem(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		nilState bool
		nilFS    bool
		entryMut func([]byte) []byte
		want     string
	}{
		{name: "nil state", nilState: true, want: "state"},
		{name: "nil filesystem", nilFS: true, want: "filesystem"},
		{name: "non canonical entry", entryMut: func(entry []byte) []byte {
			return []byte(strings.Replace(string(entry), `,"entry_kind"`, `, "entry_kind"`, 1))
		}, want: "canonical"},
		{name: "bad digest", entryMut: func(entry []byte) []byte { return corruptEntryDigestForTest(t, entry) }, want: "digest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			state, entry := appendStateAndEntryForTest(t, "filesystem-append-fail-"+strings.ReplaceAll(tc.name, " ", "-"), 8192, DefaultDaemonSessionStatusEvidenceLogMaxLogBytes)
			mapped := newMappedEvidenceLogFilesystemForTest(t, state.Snapshot().Plan.EvidenceLogPath)
			if tc.entryMut != nil {
				entry = tc.entryMut(entry)
			}
			var targetState *DaemonSessionStatusEvidenceLogAppendState = state
			if tc.nilState {
				targetState = nil
			}
			var targetFS DaemonSessionStatusEvidenceLogFilesystem = mapped
			if tc.nilFS {
				targetFS = nil
			}

			_, err := ApplyDaemonSessionStatusEvidenceLogFilesystemAppend(DaemonSessionStatusEvidenceLogFilesystemAppendConfig{State: targetState, Filesystem: targetFS}, entry)
			if err == nil {
				t.Fatalf("expected failure")
			}
			if !errors.Is(err, ErrDaemonSessionStatusEvidenceLogFilesystemAppend) {
				t.Fatalf("expected ErrDaemonSessionStatusEvidenceLogFilesystemAppend, got %v", err)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
			if got := mapped.operations(); len(got) != 0 {
				t.Fatalf("failure touched filesystem: %#v", got)
			}
			if snapshot := state.Snapshot(); snapshot.EntryCount != 0 || snapshot.TotalBytes != 0 {
				t.Fatalf("failure mutated state: %#v", snapshot)
			}
		})
	}
}

func TestDaemonSessionStatusEvidenceLogFilesystemAppendFSErrorDoesNotMutateState(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		trigger   func(t *testing.T, state *DaemonSessionStatusEvidenceLogAppendState, mapped *mappedEvidenceLogFilesystemForTest, entry []byte)
		want      string
		wantFile  bool
		wantEntry bool
	}{
		{name: "mkdir failure", trigger: func(_ *testing.T, _ *DaemonSessionStatusEvidenceLogAppendState, mapped *mappedEvidenceLogFilesystemForTest, _ []byte) {
			mapped.failMkdir = errors.New("simulated mkdir failure")
		}, want: "directory"},
		{name: "append failure", trigger: func(_ *testing.T, _ *DaemonSessionStatusEvidenceLogAppendState, mapped *mappedEvidenceLogFilesystemForTest, _ []byte) {
			mapped.failAppend = errors.New("simulated append failure")
		}, want: "append"},
		{name: "rename failure", trigger: func(t *testing.T, state *DaemonSessionStatusEvidenceLogAppendState, mapped *mappedEvidenceLogFilesystemForTest, entry []byte) {
			first, err := ApplyDaemonSessionStatusEvidenceLogFilesystemAppend(DaemonSessionStatusEvidenceLogFilesystemAppendConfig{State: state, Filesystem: mapped}, entry)
			if err != nil {
				t.Fatalf("setup append returned error: %v", err)
			}
			if first.Decision != DaemonSessionStatusEvidenceLogAppendAccept {
				t.Fatalf("setup decision = %q", first.Decision)
			}
			mapped.failRename = errors.New("simulated rename failure")
		}, want: "rotate", wantFile: true, wantEntry: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			maxLogBytes := DefaultDaemonSessionStatusEvidenceLogMaxLogBytes
			if tc.wantEntry {
				maxLogBytes = 8192
			}
			state, entry := appendStateAndEntryForTest(t, "filesystem-append-fs-error-"+strings.ReplaceAll(tc.name, " ", "-"), 8192, maxLogBytes)
			mapped := newMappedEvidenceLogFilesystemForTest(t, state.Snapshot().Plan.EvidenceLogPath)
			before := state.Snapshot()
			tc.trigger(t, state, mapped, entry)
			if tc.wantEntry {
				before = state.Snapshot()
			}

			_, err := ApplyDaemonSessionStatusEvidenceLogFilesystemAppend(DaemonSessionStatusEvidenceLogFilesystemAppendConfig{State: state, Filesystem: mapped}, entry)
			if err == nil {
				t.Fatalf("expected filesystem failure")
			}
			if !errors.Is(err, ErrDaemonSessionStatusEvidenceLogFilesystemAppend) {
				t.Fatalf("expected ErrDaemonSessionStatusEvidenceLogFilesystemAppend, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
			after := state.Snapshot()
			if after.EntryCount != before.EntryCount || after.TotalBytes != before.TotalBytes || after.RotationCount != before.RotationCount {
				t.Fatalf("filesystem error mutated state: before=%#v after=%#v", before, after)
			}
			if tc.wantFile {
				if string(mapped.readLogicalFile(t, after.Plan.EvidenceLogPath)) != string(entry) {
					t.Fatalf("pre-existing evidence log was not preserved")
				}
			} else if _, statErr := os.Stat(mapped.physicalPath(after.Plan.EvidenceLogPath)); !errors.Is(statErr, fs.ErrNotExist) {
				t.Fatalf("failed append left evidence log file behind: %v", statErr)
			}
		})
	}
}

func TestDaemonSessionStatusEvidenceLogFilesystemAppendRejectsBadModesAndPathsBeforeFilesystem(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		cfg  func(*DaemonSessionStatusEvidenceLogFilesystemAppendConfig)
		want string
	}{
		{name: "directory mode", cfg: func(cfg *DaemonSessionStatusEvidenceLogFilesystemAppendConfig) { cfg.DirectoryMode = 0o755 }, want: "directory mode"},
		{name: "file mode", cfg: func(cfg *DaemonSessionStatusEvidenceLogFilesystemAppendConfig) { cfg.FileMode = 0o644 }, want: "file mode"},
		{name: "directory special bit", cfg: func(cfg *DaemonSessionStatusEvidenceLogFilesystemAppendConfig) {
			cfg.DirectoryMode = fs.ModeSetuid | 0o700
		}, want: "directory mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			state, entry := appendStateAndEntryForTest(t, "filesystem-append-bad-mode-"+strings.ReplaceAll(tc.name, " ", "-"), 8192, DefaultDaemonSessionStatusEvidenceLogMaxLogBytes)
			mapped := newMappedEvidenceLogFilesystemForTest(t, state.Snapshot().Plan.EvidenceLogPath)
			applyCfg := DaemonSessionStatusEvidenceLogFilesystemAppendConfig{State: state, Filesystem: mapped}
			tc.cfg(&applyCfg)

			_, err := ApplyDaemonSessionStatusEvidenceLogFilesystemAppend(applyCfg, entry)
			if err == nil {
				t.Fatalf("expected bad mode failure")
			}
			if !errors.Is(err, ErrDaemonSessionStatusEvidenceLogFilesystemAppend) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want sentinel and %q", err, tc.want)
			}
			if got := mapped.operations(); len(got) != 0 {
				t.Fatalf("bad mode touched filesystem: %#v", got)
			}
			if snapshot := state.Snapshot(); snapshot.EntryCount != 0 || snapshot.TotalBytes != 0 {
				t.Fatalf("bad mode mutated state: %#v", snapshot)
			}
		})
	}

	cfg := daemonSessionStatusEvidenceLogConfigForTest(t, "filesystem-append-path-escape-session")
	plan, err := BuildDaemonSessionStatusEvidenceLogPlan(cfg)
	if err != nil {
		t.Fatalf("BuildDaemonSessionStatusEvidenceLogPlan returned error: %v", err)
	}
	plan.EvidenceLogPath = "/tmp/ardur-escape.evlog"
	entry, err := BuildDaemonSessionStatusEvidenceLogEntry(plan, cfg.Snapshot)
	if err != nil {
		t.Fatalf("BuildDaemonSessionStatusEvidenceLogEntry returned error for path escape fixture: %v", err)
	}
	state, err := NewDaemonSessionStatusEvidenceLogAppendState(plan, nil)
	if err != nil {
		t.Fatalf("NewDaemonSessionStatusEvidenceLogAppendState returned error for path escape fixture: %v", err)
	}
	mapped := newMappedEvidenceLogFilesystemForTest(t, plan.EvidenceLogPath)
	_, err = ApplyDaemonSessionStatusEvidenceLogFilesystemAppend(DaemonSessionStatusEvidenceLogFilesystemAppendConfig{State: state, Filesystem: mapped}, entry)
	if err == nil {
		t.Fatalf("expected path containment failure")
	}
	if !errors.Is(err, ErrDaemonSessionStatusEvidenceLogFilesystemAppend) || !strings.Contains(err.Error(), "outside daemon state") {
		t.Fatalf("path containment error = %v", err)
	}
	if got := mapped.operations(); len(got) != 0 {
		t.Fatalf("path containment failure touched filesystem: %#v", got)
	}

	cfg = daemonSessionStatusEvidenceLogConfigForTest(t, "filesystem-append-state-sibling-escape-session")
	plan, err = BuildDaemonSessionStatusEvidenceLogPlan(cfg)
	if err != nil {
		t.Fatalf("BuildDaemonSessionStatusEvidenceLogPlan returned error: %v", err)
	}
	plan.EvidenceLogPath = "/var/lib/ardur/sibling/escape.evlog"
	entry, err = BuildDaemonSessionStatusEvidenceLogEntry(plan, cfg.Snapshot)
	if err != nil {
		t.Fatalf("BuildDaemonSessionStatusEvidenceLogEntry returned error for sibling escape fixture: %v", err)
	}
	state, err = NewDaemonSessionStatusEvidenceLogAppendState(plan, nil)
	if err != nil {
		t.Fatalf("NewDaemonSessionStatusEvidenceLogAppendState returned error for sibling escape fixture: %v", err)
	}
	mapped = newMappedEvidenceLogFilesystemForTest(t, plan.EvidenceLogPath)
	_, err = ApplyDaemonSessionStatusEvidenceLogFilesystemAppend(DaemonSessionStatusEvidenceLogFilesystemAppendConfig{State: state, Filesystem: mapped}, entry)
	if err == nil {
		t.Fatalf("expected daemon state sibling containment failure")
	}
	if !errors.Is(err, ErrDaemonSessionStatusEvidenceLogFilesystemAppend) || !strings.Contains(err.Error(), "outside daemon state") {
		t.Fatalf("sibling path containment error = %v", err)
	}
	if got := mapped.operations(); len(got) != 0 {
		t.Fatalf("sibling path containment failure touched filesystem: %#v", got)
	}
}

func TestDaemonSessionStatusEvidenceLogFilesystemAppendRollbackAfterRotationAppendError(t *testing.T) {
	t.Parallel()

	state, entry := appendStateAndEntryForTest(t, "filesystem-append-rollback-session", 8192, 8192)
	mapped := newMappedEvidenceLogFilesystemForTest(t, state.Snapshot().Plan.EvidenceLogPath)

	first, err := ApplyDaemonSessionStatusEvidenceLogFilesystemAppend(DaemonSessionStatusEvidenceLogFilesystemAppendConfig{State: state, Filesystem: mapped}, entry)
	if err != nil {
		t.Fatalf("first append returned error: %v", err)
	}
	if first.Decision != DaemonSessionStatusEvidenceLogAppendAccept {
		t.Fatalf("first decision = %q", first.Decision)
	}
	before := state.Snapshot()
	mapped.failAppend = errors.New("simulated post-rotation append failure")

	_, err = ApplyDaemonSessionStatusEvidenceLogFilesystemAppend(DaemonSessionStatusEvidenceLogFilesystemAppendConfig{State: state, Filesystem: mapped}, entry)
	if err == nil {
		t.Fatalf("expected rotation append failure")
	}
	if !errors.Is(err, ErrDaemonSessionStatusEvidenceLogFilesystemAppend) {
		t.Fatalf("expected ErrDaemonSessionStatusEvidenceLogFilesystemAppend, got %v", err)
	}
	after := state.Snapshot()
	if after.EntryCount != before.EntryCount || after.TotalBytes != before.TotalBytes || after.RotationCount != before.RotationCount {
		t.Fatalf("rotation append failure mutated state: before=%#v after=%#v", before, after)
	}
	if string(mapped.readLogicalFile(t, before.Plan.EvidenceLogPath)) != string(entry) {
		t.Fatalf("rollback did not restore current evidence log")
	}
	if !mapped.sawOp("rename", first.EvidenceLogPath+".000001->"+first.EvidenceLogPath) {
		t.Fatalf("expected rollback rename op, got %#v", mapped.operations())
	}
}

func TestDaemonSessionStatusEvidenceLogFilesystemAppendAllowsConcurrentAppends(t *testing.T) {
	t.Parallel()

	state, entry := appendStateAndEntryForTest(t, "filesystem-append-concurrent-session", 8192, DefaultDaemonSessionStatusEvidenceLogMaxLogBytes)
	mapped := newMappedEvidenceLogFilesystemForTest(t, state.Snapshot().Plan.EvidenceLogPath)
	const workers = 8

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			plan, err := ApplyDaemonSessionStatusEvidenceLogFilesystemAppend(DaemonSessionStatusEvidenceLogFilesystemAppendConfig{State: state, Filesystem: mapped}, entry)
			if err != nil {
				errs <- err
				return
			}
			if plan.Decision != DaemonSessionStatusEvidenceLogAppendAccept {
				errs <- errors.New("unexpected decision: " + string(plan.Decision))
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent append error: %v", err)
		}
	}

	content := string(mapped.readLogicalFile(t, state.Snapshot().Plan.EvidenceLogPath))
	if strings.Count(content, "\n") != workers {
		t.Fatalf("evidence log line count = %d, want %d", strings.Count(content, "\n"), workers)
	}
	if snapshot := state.Snapshot(); snapshot.EntryCount != workers || snapshot.TotalBytes != int64(len(entry))*workers {
		t.Fatalf("concurrent state snapshot = %#v", snapshot)
	}
}

func assertAppendPlanStepsExecuted(t *testing.T, plan DaemonSessionStatusEvidenceLogAppendPlan) {
	t.Helper()

	if len(plan.Steps) == 0 {
		t.Fatalf("append plan has no steps")
	}
	for i, step := range plan.Steps {
		if strings.TrimSpace(step.Name) == "" || strings.TrimSpace(step.Rationale) == "" {
			t.Fatalf("append step %d is missing name/rationale: %#v", i, step)
		}
		if !step.Executed {
			t.Fatalf("append step %d is not executed: %#v", i, step)
		}
	}
}

type mappedEvidenceLogFilesystemForTest struct {
	t           *testing.T
	root        string
	logicalRoot string
	mu          sync.Mutex
	ops         []string
	failMkdir   error
	failAppend  error
	failRename  error
}

func newMappedEvidenceLogFilesystemForTest(t *testing.T, evidenceLogPath string) *mappedEvidenceLogFilesystemForTest {
	t.Helper()
	return &mappedEvidenceLogFilesystemForTest{
		t:           t,
		root:        t.TempDir(),
		logicalRoot: filepath.Dir(evidenceLogPath),
	}
}

func (m *mappedEvidenceLogFilesystemForTest) MkdirAll(path string, perm fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failMkdir != nil {
		return m.failMkdir
	}
	m.recordLocked("mkdirall", path)
	return os.MkdirAll(m.physicalPathLocked(path), perm)
}

func (m *mappedEvidenceLogFilesystemForTest) AppendFile(path string, data []byte, perm fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failAppend != nil {
		return m.failAppend
	}
	m.recordLocked("append", path)
	physical := m.physicalPathLocked(path)
	file, err := os.OpenFile(physical, os.O_CREATE|os.O_WRONLY|os.O_APPEND, perm)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(append([]byte(nil), data...))
	return err
}

func (m *mappedEvidenceLogFilesystemForTest) Rename(oldPath, newPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failRename != nil {
		return m.failRename
	}
	m.recordLocked("rename", oldPath+"->"+newPath)
	return os.Rename(m.physicalPathLocked(oldPath), m.physicalPathLocked(newPath))
}

func (m *mappedEvidenceLogFilesystemForTest) readLogicalFile(t *testing.T, logicalPath string) []byte {
	t.Helper()
	m.mu.Lock()
	physical := m.physicalPathLocked(logicalPath)
	m.mu.Unlock()
	data, err := os.ReadFile(physical)
	if err != nil {
		t.Fatalf("ReadFile(%q) returned error: %v", logicalPath, err)
	}
	return data
}

func (m *mappedEvidenceLogFilesystemForTest) physicalPath(logicalPath string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.physicalPathLocked(logicalPath)
}

func (m *mappedEvidenceLogFilesystemForTest) physicalPathLocked(logicalPath string) string {
	m.t.Helper()
	logicalPath = cleanPath(logicalPath)
	if !lexicalPathWithin(logicalPath, m.logicalRoot) {
		m.t.Fatalf("logical path %q escaped mapped logical root %q", logicalPath, m.logicalRoot)
	}
	rel, err := filepath.Rel(m.logicalRoot, logicalPath)
	if err != nil {
		m.t.Fatalf("Rel(%q, %q) returned error: %v", m.logicalRoot, logicalPath, err)
	}
	return filepath.Join(m.root, rel)
}

func (m *mappedEvidenceLogFilesystemForTest) sawOp(kind, detail string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := kind + ":" + detail
	for _, op := range m.ops {
		if op == want {
			return true
		}
	}
	return false
}

func (m *mappedEvidenceLogFilesystemForTest) operations() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.ops...)
}

func (m *mappedEvidenceLogFilesystemForTest) recordLocked(kind, detail string) {
	m.ops = append(m.ops, kind+":"+detail)
}
