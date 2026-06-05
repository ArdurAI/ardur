package kernelcapture

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrDaemonSessionStatusEvidenceLogEntry = errors.New("kernelcapture: invalid daemon session status evidence-log entry")

// DaemonSessionStatusEvidenceLogEntry is the in-memory JSONL record shape for
// a planned daemon session-status evidence-log entry. It is deliberately not a
// writer: building this value does not create files, append to logs, rotate
// logs, persist state, mutate kernel maps, or expand the client-visible daemon
// protocol.
type DaemonSessionStatusEvidenceLogEntry struct {
	SchemaVersion   string                      `json:"schema_version"`
	EntryKind       string                      `json:"entry_kind"`
	SessionID       string                      `json:"session_id"`
	EvidenceLogPath string                      `json:"evidence_log_path"`
	EntryDigest     string                      `json:"entry_digest"`
	SnapshotAsOf    time.Time                   `json:"snapshot_as_of"`
	Snapshot        DaemonSessionStatusSnapshot `json:"snapshot"`
	ClaimBoundary   []string                    `json:"claim_boundary"`
	NotClaimed      []string                    `json:"not_claimed"`
}

// BuildDaemonSessionStatusEvidenceLogEntry converts a reviewed no-write plan and
// its retained status snapshot into one newline-terminated JSONL entry in memory.
// It validates the plan shape, revalidates snapshot integrity, recomputes the
// snapshot digest, and fails closed if the resulting entry would exceed the
// plan's MaxEntryBytes. It performs no filesystem writes, append operations,
// directory creation, log rotation, persistence, or protocol expansion.
func BuildDaemonSessionStatusEvidenceLogEntry(plan DaemonSessionStatusEvidenceLogPlan, snapshot DaemonSessionStatusSnapshot) ([]byte, error) {
	if err := validateDaemonSessionStatusEvidenceLogEntryPlan(plan); err != nil {
		return nil, evidenceLogEntryError("plan is invalid: %v", err)
	}
	if err := validateEvidenceLogSnapshot(snapshot); err != nil {
		return nil, evidenceLogEntryError("snapshot integrity check failed: %v", err)
	}

	snapshotSessionID := strings.TrimSpace(snapshot.Session.SessionID)
	planSessionID := strings.TrimSpace(plan.SessionID)
	if snapshotSessionID != planSessionID {
		return nil, evidenceLogEntryError("snapshot session id %q does not match plan session id %q", snapshotSessionID, planSessionID)
	}

	computedDigest, err := computeSnapshotEvidenceLogEntryDigest(snapshot)
	if err != nil {
		return nil, evidenceLogEntryError("snapshot digest computation failed: %v", err)
	}
	if computedDigest != plan.EntryDigest {
		return nil, evidenceLogEntryError("snapshot digest %q does not match planned entry digest %q", computedDigest, plan.EntryDigest)
	}

	entry := DaemonSessionStatusEvidenceLogEntry{
		SchemaVersion:   DaemonSessionStatusEvidenceLogSchemaVersion,
		EntryKind:       DaemonSessionStatusEvidenceLogEntryKind,
		SessionID:       planSessionID,
		EvidenceLogPath: cleanPath(plan.EvidenceLogPath),
		EntryDigest:     plan.EntryDigest,
		SnapshotAsOf:    snapshot.AsOf,
		Snapshot:        copyDaemonSessionStatusSnapshot(snapshot),
		ClaimBoundary: []string{
			"in-memory evidence-log entry is anchored to the reviewed daemon status snapshot digest",
			"entry builder revalidates snapshot integrity and size before any future write path",
			"entry builder performs no filesystem writes, evidence-log append, rotation, persistence, or protocol expansion",
		},
		NotClaimed: []string{
			"filesystem writes, evidence-log creation, evidence-log append, rotation, or persistence",
			"daemon install/start/service lifecycle",
			"client-visible protocol expansion",
			"production daemon readiness",
			"live enforcement or kernel-map mutation",
		},
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return nil, evidenceLogEntryError("entry JSON encoding failed: %v", err)
	}
	maxEntryBytes := int(plan.MaxEntryBytes)
	if len(data) >= maxEntryBytes {
		return nil, evidenceLogEntryError("entry JSON bytes %d plus newline exceeds max entry bytes %d", len(data), plan.MaxEntryBytes)
	}

	result := append([]byte(nil), data...)
	result = append(result, '\n')
	return result, nil
}

func validateDaemonSessionStatusEvidenceLogEntryPlan(plan DaemonSessionStatusEvidenceLogPlan) error {
	if plan.Mode != DaemonCustodyModeLocalOnlyScaffold {
		return fmt.Errorf("mode is %q, want %q", plan.Mode, DaemonCustodyModeLocalOnlyScaffold)
	}
	if strings.TrimSpace(plan.SessionID) == "" {
		return fmt.Errorf("session id is required")
	}
	if strings.TrimSpace(plan.EvidenceLogPath) == "" {
		return fmt.Errorf("evidence-log path is required")
	}
	if cleanPath(plan.EvidenceLogPath) != plan.EvidenceLogPath {
		return fmt.Errorf("evidence-log path must be clean")
	}
	if plan.SchemaVersion != DaemonSessionStatusEvidenceLogSchemaVersion {
		return fmt.Errorf("schema version is %q, want %q", plan.SchemaVersion, DaemonSessionStatusEvidenceLogSchemaVersion)
	}
	if plan.EntryKind != DaemonSessionStatusEvidenceLogEntryKind {
		return fmt.Errorf("entry kind is %q, want %q", plan.EntryKind, DaemonSessionStatusEvidenceLogEntryKind)
	}
	if err := validateEvidenceLogEntryDigest(plan.EntryDigest); err != nil {
		return err
	}
	if plan.MaxEntryBytes <= 0 || plan.MaxEntryBytes > MaxDaemonSessionStatusEvidenceLogMaxEntryBytes {
		return fmt.Errorf("max entry bytes must be between 1 and %d", MaxDaemonSessionStatusEvidenceLogMaxEntryBytes)
	}
	if plan.MaxLogBytes <= 0 || plan.MaxLogBytes > MaxDaemonSessionStatusEvidenceLogMaxLogBytes {
		return fmt.Errorf("max log bytes must be between 1 and %d", MaxDaemonSessionStatusEvidenceLogMaxLogBytes)
	}
	if plan.MaxLogBytes < plan.MaxEntryBytes {
		return fmt.Errorf("max log bytes (%d) cannot be less than max entry bytes (%d)", plan.MaxLogBytes, plan.MaxEntryBytes)
	}
	if plan.MaxRotatedFiles <= 0 || plan.MaxRotatedFiles > MaxDaemonSessionStatusEvidenceLogMaxRotatedFiles {
		return fmt.Errorf("max rotated files must be between 1 and %d", MaxDaemonSessionStatusEvidenceLogMaxRotatedFiles)
	}
	if len(plan.Steps) == 0 {
		return fmt.Errorf("evidence-log plan steps are required")
	}
	for i, step := range plan.Steps {
		if strings.TrimSpace(step.Name) == "" {
			return fmt.Errorf("evidence-log plan step %d has empty name", i)
		}
		if step.Executed {
			return fmt.Errorf("evidence-log plan step %d %q is executed; entry builder requires no-mutation plan steps", i, step.Name)
		}
	}
	if len(plan.ClaimBoundary) == 0 {
		return fmt.Errorf("claim boundary is required")
	}
	if len(plan.NotClaimed) == 0 {
		return fmt.Errorf("not-claimed boundary is required")
	}
	return nil
}

func validateEvidenceLogEntryDigest(digest string) error {
	if len(digest) != 64 {
		return fmt.Errorf("entry digest must be 64 lowercase hex characters")
	}
	if digest != strings.ToLower(digest) {
		return fmt.Errorf("entry digest must be lowercase hex")
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("entry digest must be valid sha256 hex")
	}
	return nil
}

func evidenceLogEntryError(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrDaemonSessionStatusEvidenceLogEntry}, args...)...)
}
