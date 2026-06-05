package kernelcapture

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var ErrDaemonSessionStatusEvidenceLogAppendPlan = errors.New("kernelcapture: invalid daemon session status evidence-log append plan")

type DaemonSessionStatusEvidenceLogAppendDecision string

const (
	DaemonSessionStatusEvidenceLogAppendAccept           DaemonSessionStatusEvidenceLogAppendDecision = "append_accept"
	DaemonSessionStatusEvidenceLogAppendRotateThenAppend DaemonSessionStatusEvidenceLogAppendDecision = "rotate_then_append"
	DaemonSessionStatusEvidenceLogAppendReject           DaemonSessionStatusEvidenceLogAppendDecision = "append_reject"
)

// DaemonSessionStatusEvidenceLogAppendState is an injected in-memory fake sink
// for proving append/rotation decisions before any daemon-owned filesystem write
// path exists. It stores detached JSONL entries only in memory and deliberately
// does not implement io.Writer, open files, create directories, rotate logs on
// disk, persist state, mutate kernel maps, or expand the client-visible daemon
// protocol.
type DaemonSessionStatusEvidenceLogAppendState struct {
	mu            sync.Mutex
	plan          DaemonSessionStatusEvidenceLogPlan
	openedAt      time.Time
	entries       [][]byte
	totalBytes    int64
	rotationCount int
	now           DaemonSessionClock
}

// DaemonSessionStatusEvidenceLogAppendStateSnapshot is a detached view of the
// in-memory fake sink state for tests and future internal daemon planning code.
type DaemonSessionStatusEvidenceLogAppendStateSnapshot struct {
	Plan          DaemonSessionStatusEvidenceLogPlan
	OpenedAt      time.Time
	Entries       [][]byte
	TotalBytes    int64
	EntryCount    int
	RotationCount int
}

// DaemonSessionStatusEvidenceLogAppendPlan records the in-memory-only decision
// for a proposed evidence-log entry. It is not a writer: Decision records whether
// a future daemon write path would append, rotate-then-append, or reject. Steps
// remain Executed=false because no filesystem write, append, rotation, or
// persistence is performed by this planner.
type DaemonSessionStatusEvidenceLogAppendPlan struct {
	Mode string

	Decision DaemonSessionStatusEvidenceLogAppendDecision
	Reason   string

	SessionID       string
	EvidenceLogPath string
	RotationPath    string
	EntryDigest     string

	PreBytes   int64
	EntryBytes int64
	PostBytes  int64

	MaxEntryBytes   int64
	MaxLogBytes     int64
	MaxRotatedFiles int
	RotationCount   int
	PlannedAt       time.Time

	Steps         []DaemonSessionStatusEvidenceLogStep
	ClaimBoundary []string
	NotClaimed    []string
}

// NewDaemonSessionStatusEvidenceLogAppendState opens a fake in-memory evidence
// log state from a reviewed evidence-log plan. It performs no filesystem work.
func NewDaemonSessionStatusEvidenceLogAppendState(plan DaemonSessionStatusEvidenceLogPlan, clock DaemonSessionClock) (*DaemonSessionStatusEvidenceLogAppendState, error) {
	if err := validateDaemonSessionStatusEvidenceLogEntryPlan(plan); err != nil {
		return nil, evidenceLogAppendPlanError("plan is invalid: %v", err)
	}
	if clock == nil {
		clock = time.Now
	}
	openedAt := clock()
	if openedAt.IsZero() {
		return nil, evidenceLogAppendPlanError("clock returned zero opened_at")
	}
	return &DaemonSessionStatusEvidenceLogAppendState{
		plan:     copyDaemonSessionStatusEvidenceLogPlan(plan),
		openedAt: openedAt,
		now:      clock,
	}, nil
}

// Snapshot returns a detached view of the fake sink state. Callers cannot mutate
// retained entries or the state plan through the returned value.
func (s *DaemonSessionStatusEvidenceLogAppendState) Snapshot() DaemonSessionStatusEvidenceLogAppendStateSnapshot {
	if s == nil {
		return DaemonSessionStatusEvidenceLogAppendStateSnapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return DaemonSessionStatusEvidenceLogAppendStateSnapshot{
		Plan:          copyDaemonSessionStatusEvidenceLogPlan(s.plan),
		OpenedAt:      s.openedAt,
		Entries:       copyEvidenceLogEntryBytes(s.entries),
		TotalBytes:    s.totalBytes,
		EntryCount:    len(s.entries),
		RotationCount: s.rotationCount,
	}
}

// PlanDaemonSessionStatusEvidenceLogAppend evaluates and records a proposed
// JSONL entry against the injected in-memory fake sink. Accepted entries are
// retained only in memory; rotate-then-append clears the fake sink's retained
// entries and records the proposed entry as the first entry after a simulated
// rotation. Rejections and validation failures do not mutate state. No OS files
// are opened, written, appended, created, rotated, or persisted.
func PlanDaemonSessionStatusEvidenceLogAppend(state *DaemonSessionStatusEvidenceLogAppendState, entryBytes []byte) (DaemonSessionStatusEvidenceLogAppendPlan, error) {
	if state == nil {
		return DaemonSessionStatusEvidenceLogAppendPlan{}, evidenceLogAppendPlanError("state is required")
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	computed, err := computeDaemonSessionStatusEvidenceLogAppendLocked(state, entryBytes)
	if err != nil {
		return DaemonSessionStatusEvidenceLogAppendPlan{}, err
	}
	if computed.Plan.Decision == DaemonSessionStatusEvidenceLogAppendAccept {
		state.entries = append(state.entries, append([]byte(nil), computed.CanonicalBytes...))
		state.totalBytes = computed.Plan.PostBytes
		return computed.Plan, nil
	}
	if computed.Plan.Decision == DaemonSessionStatusEvidenceLogAppendRotateThenAppend {
		state.entries = [][]byte{append([]byte(nil), computed.CanonicalBytes...)}
		state.totalBytes = computed.Plan.PostBytes
		state.rotationCount = computed.Plan.RotationCount
		return computed.Plan, nil
	}
	return computed.Plan, nil
}

type daemonSessionStatusEvidenceLogAppendComputation struct {
	Plan           DaemonSessionStatusEvidenceLogAppendPlan
	CanonicalBytes []byte
}

func computeDaemonSessionStatusEvidenceLogAppendLocked(state *DaemonSessionStatusEvidenceLogAppendState, entryBytes []byte) (daemonSessionStatusEvidenceLogAppendComputation, error) {
	if state == nil {
		return daemonSessionStatusEvidenceLogAppendComputation{}, evidenceLogAppendPlanError("state is required")
	}
	if err := validateDaemonSessionStatusEvidenceLogEntryPlan(state.plan); err != nil {
		return daemonSessionStatusEvidenceLogAppendComputation{}, evidenceLogAppendPlanError("state plan is invalid: %v", err)
	}
	entry, canonicalBytes, err := validateEvidenceLogAppendEntryBytes(state.plan, entryBytes)
	if err != nil {
		return daemonSessionStatusEvidenceLogAppendComputation{}, err
	}

	entryLen := len(canonicalBytes)
	entryLen64 := int64(entryLen)
	plannedAt := state.now()
	if plannedAt.IsZero() {
		return daemonSessionStatusEvidenceLogAppendComputation{}, evidenceLogAppendPlanError("clock returned zero planned_at")
	}
	base := state.baseAppendPlan(entry.EntryDigest, entryLen64, plannedAt)

	maxEntryBytes := int(state.plan.MaxEntryBytes)
	if entryLen > maxEntryBytes {
		base.Decision = DaemonSessionStatusEvidenceLogAppendReject
		base.Reason = fmt.Sprintf("entry bytes %d exceeds max entry bytes %d", entryLen, state.plan.MaxEntryBytes)
		base.PostBytes = state.totalBytes
		return daemonSessionStatusEvidenceLogAppendComputation{Plan: base}, nil
	}
	if state.totalBytes < 0 {
		return daemonSessionStatusEvidenceLogAppendComputation{}, evidenceLogAppendPlanError("state total bytes is negative")
	}
	if math.MaxInt64-state.totalBytes < entryLen64 {
		return daemonSessionStatusEvidenceLogAppendComputation{}, evidenceLogAppendPlanError("append byte accounting would overflow")
	}

	candidateTotal := state.totalBytes + entryLen64
	if candidateTotal <= state.plan.MaxLogBytes {
		base.Decision = DaemonSessionStatusEvidenceLogAppendAccept
		base.Reason = "entry fits current in-memory evidence-log bounds"
		base.PostBytes = candidateTotal
		base.RotationCount = state.rotationCount
		return daemonSessionStatusEvidenceLogAppendComputation{Plan: base, CanonicalBytes: canonicalBytes}, nil
	}

	rotationPath, err := nextEvidenceLogRotationPath(state.plan, state.rotationCount)
	if err != nil {
		return daemonSessionStatusEvidenceLogAppendComputation{}, err
	}
	base.Decision = DaemonSessionStatusEvidenceLogAppendRotateThenAppend
	base.Reason = "entry would exceed current in-memory log bounds; simulated rotation is required before append"
	base.RotationPath = rotationPath
	base.PostBytes = entryLen64
	base.RotationCount = state.rotationCount + 1
	return daemonSessionStatusEvidenceLogAppendComputation{Plan: base, CanonicalBytes: canonicalBytes}, nil
}

func (s *DaemonSessionStatusEvidenceLogAppendState) baseAppendPlan(entryDigest string, entryBytes int64, plannedAt time.Time) DaemonSessionStatusEvidenceLogAppendPlan {
	return DaemonSessionStatusEvidenceLogAppendPlan{
		Mode:            DaemonCustodyModeLocalOnlyScaffold,
		SessionID:       strings.TrimSpace(s.plan.SessionID),
		EvidenceLogPath: cleanPath(s.plan.EvidenceLogPath),
		EntryDigest:     entryDigest,
		PreBytes:        s.totalBytes,
		EntryBytes:      entryBytes,
		PostBytes:       s.totalBytes,
		MaxEntryBytes:   s.plan.MaxEntryBytes,
		MaxLogBytes:     s.plan.MaxLogBytes,
		MaxRotatedFiles: s.plan.MaxRotatedFiles,
		RotationCount:   s.rotationCount,
		PlannedAt:       plannedAt,
		Steps: []DaemonSessionStatusEvidenceLogStep{
			{
				Name:      "validate_in_memory_append_state",
				Rationale: "fake sink append planning must start from a reviewed no-write evidence-log plan and detached in-memory byte counts",
			},
			{
				Name:      "validate_jsonl_entry_digest",
				Path:      cleanPath(s.plan.EvidenceLogPath),
				Rationale: "proposed JSONL entry must match the canonical entry builder and planned snapshot digest before any future append path",
			},
			{
				Name:      "compute_append_or_rotation_decision",
				Path:      cleanPath(s.plan.EvidenceLogPath),
				Rationale: "append versus rotate-then-append is computed from validated in-memory byte counts and retention bounds only",
			},
			{
				Name:      "retain_detached_fake_sink_entry",
				Rationale: "accepted entries are copied into the in-memory fake sink only; no filesystem append or persistence is performed",
			},
		},
		ClaimBoundary: []string{
			"in-memory append decision is computed from reviewed evidence-log plan bounds and proposed JSONL entry size",
			"rotation path is derived from the daemon-owned evidence-log path and validated within the evidence-log directory",
			"accepted entries are retained as detached bytes in the fake sink only",
			"every append/rotation step is recorded with Executed=false; this planner performs no filesystem writes, evidence-log creation, append/write path, rotation execution, or persistence",
		},
		NotClaimed: []string{
			"filesystem writes, evidence-log creation, append/write path, rotation execution, or persistence",
			"daemon filesystem ownership, directory creation, or log flushing",
			"daemon install/start/service lifecycle",
			"client-visible protocol expansion",
			"production daemon readiness",
			"live enforcement, cgroup assignment, or kernel-map mutation",
		},
	}
}

func validateEvidenceLogAppendEntryBytes(plan DaemonSessionStatusEvidenceLogPlan, entryBytes []byte) (DaemonSessionStatusEvidenceLogEntry, []byte, error) {
	if len(entryBytes) == 0 {
		return DaemonSessionStatusEvidenceLogEntry{}, nil, evidenceLogAppendPlanError("entry bytes are required")
	}
	maxCanonicalEntryBytes := int(MaxDaemonSessionStatusEvidenceLogMaxEntryBytes)
	if len(entryBytes) > maxCanonicalEntryBytes {
		return DaemonSessionStatusEvidenceLogEntry{}, nil, evidenceLogAppendPlanError("entry bytes %d exceed maximum supported entry bytes %d", len(entryBytes), MaxDaemonSessionStatusEvidenceLogMaxEntryBytes)
	}
	entryText := string(entryBytes)
	if !strings.HasSuffix(entryText, "\n") {
		return DaemonSessionStatusEvidenceLogEntry{}, nil, evidenceLogAppendPlanError("entry must be newline-terminated JSONL")
	}
	if strings.Count(entryText, "\n") != 1 {
		return DaemonSessionStatusEvidenceLogEntry{}, nil, evidenceLogAppendPlanError("entry must contain exactly one JSONL newline")
	}
	payload := strings.TrimSuffix(entryText, "\n")
	if strings.TrimSpace(payload) == "" {
		return DaemonSessionStatusEvidenceLogEntry{}, nil, evidenceLogAppendPlanError("entry JSON payload is empty")
	}
	var entry DaemonSessionStatusEvidenceLogEntry
	if err := json.Unmarshal([]byte(payload), &entry); err != nil {
		return DaemonSessionStatusEvidenceLogEntry{}, nil, evidenceLogAppendPlanError("entry JSON did not parse: %v", err)
	}
	if entry.SchemaVersion != DaemonSessionStatusEvidenceLogSchemaVersion {
		return DaemonSessionStatusEvidenceLogEntry{}, nil, evidenceLogAppendPlanError("entry schema version is %q, want %q", entry.SchemaVersion, DaemonSessionStatusEvidenceLogSchemaVersion)
	}
	if entry.EntryKind != DaemonSessionStatusEvidenceLogEntryKind {
		return DaemonSessionStatusEvidenceLogEntry{}, nil, evidenceLogAppendPlanError("entry kind is %q, want %q", entry.EntryKind, DaemonSessionStatusEvidenceLogEntryKind)
	}
	if strings.TrimSpace(entry.SessionID) != strings.TrimSpace(plan.SessionID) {
		return DaemonSessionStatusEvidenceLogEntry{}, nil, evidenceLogAppendPlanError("entry session id %q does not match plan session id %q", entry.SessionID, plan.SessionID)
	}
	if cleanPath(entry.EvidenceLogPath) != cleanPath(plan.EvidenceLogPath) {
		return DaemonSessionStatusEvidenceLogEntry{}, nil, evidenceLogAppendPlanError("entry evidence-log path %q does not match plan path %q", entry.EvidenceLogPath, plan.EvidenceLogPath)
	}
	if entry.EntryDigest != plan.EntryDigest {
		return DaemonSessionStatusEvidenceLogEntry{}, nil, evidenceLogAppendPlanError("entry digest %q does not match planned entry digest %q", entry.EntryDigest, plan.EntryDigest)
	}
	computedDigest, err := computeSnapshotEvidenceLogEntryDigest(entry.Snapshot)
	if err != nil {
		return DaemonSessionStatusEvidenceLogEntry{}, nil, evidenceLogAppendPlanError("entry snapshot digest computation failed: %v", err)
	}
	if computedDigest != plan.EntryDigest {
		return DaemonSessionStatusEvidenceLogEntry{}, nil, evidenceLogAppendPlanError("entry snapshot digest %q does not match planned entry digest %q", computedDigest, plan.EntryDigest)
	}
	canonicalPlan := plan
	if len(entryBytes) > int(canonicalPlan.MaxEntryBytes) {
		canonicalPlan.MaxEntryBytes = int64(len(entryBytes))
	}
	canonicalBytes, err := BuildDaemonSessionStatusEvidenceLogEntry(canonicalPlan, entry.Snapshot)
	if err != nil {
		return DaemonSessionStatusEvidenceLogEntry{}, nil, evidenceLogAppendPlanError("entry canonical rebuild failed: %v", err)
	}
	if string(canonicalBytes) != entryText {
		return DaemonSessionStatusEvidenceLogEntry{}, nil, evidenceLogAppendPlanError("entry bytes do not match canonical JSONL encoding")
	}
	return entry, canonicalBytes, nil
}

func nextEvidenceLogRotationPath(plan DaemonSessionStatusEvidenceLogPlan, rotationCount int) (string, error) {
	if rotationCount < 0 {
		return "", evidenceLogAppendPlanError("rotation count is negative")
	}
	if plan.MaxRotatedFiles <= 0 {
		return "", evidenceLogAppendPlanError("max rotated files must be positive")
	}
	basePath := cleanPath(plan.EvidenceLogPath)
	if basePath == "" {
		return "", evidenceLogAppendPlanError("evidence-log path is required for rotation")
	}
	slot := rotationCount%plan.MaxRotatedFiles + 1
	rotationPath := fmt.Sprintf("%s.%06d", basePath, slot)
	if cleanPath(rotationPath) != rotationPath {
		return "", evidenceLogAppendPlanError("rotation path must be clean")
	}
	if !lexicalPathWithin(rotationPath, filepath.Dir(basePath)) {
		return "", evidenceLogAppendPlanError("rotation path escaped evidence-log directory")
	}
	return rotationPath, nil
}

func copyDaemonSessionStatusEvidenceLogPlan(plan DaemonSessionStatusEvidenceLogPlan) DaemonSessionStatusEvidenceLogPlan {
	plan.Steps = append([]DaemonSessionStatusEvidenceLogStep(nil), plan.Steps...)
	plan.ClaimBoundary = append([]string(nil), plan.ClaimBoundary...)
	plan.NotClaimed = append([]string(nil), plan.NotClaimed...)
	return plan
}

func copyEvidenceLogEntryBytes(entries [][]byte) [][]byte {
	if len(entries) == 0 {
		return nil
	}
	copied := make([][]byte, 0, len(entries))
	for _, entry := range entries {
		copied = append(copied, append([]byte(nil), entry...))
	}
	return copied
}

func evidenceLogAppendPlanError(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrDaemonSessionStatusEvidenceLogAppendPlan}, args...)...)
}
