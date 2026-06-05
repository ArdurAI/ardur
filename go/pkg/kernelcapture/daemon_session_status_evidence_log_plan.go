package kernelcapture

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	DaemonSessionStatusEvidenceLogSchemaVersion = "ardur.daemon.evidence-log.v0"
	DaemonSessionStatusEvidenceLogEntryKind     = "session_status_snapshot"

	DefaultDaemonSessionStatusEvidenceLogMaxEntryBytes   int64 = 64 * 1024
	MaxDaemonSessionStatusEvidenceLogMaxEntryBytes       int64 = 1024 * 1024
	DefaultDaemonSessionStatusEvidenceLogMaxLogBytes     int64 = 64 * 1024 * 1024
	MaxDaemonSessionStatusEvidenceLogMaxLogBytes         int64 = 1024 * 1024 * 1024
	DefaultDaemonSessionStatusEvidenceLogMaxRotatedFiles int   = 3
	MaxDaemonSessionStatusEvidenceLogMaxRotatedFiles     int   = 1024
)

var ErrDaemonSessionStatusEvidenceLogPlan = errors.New("kernelcapture: invalid daemon session status evidence-log plan")

// DaemonSessionStatusEvidenceLogConfig is the no-mutation bridge from a retained
// daemon-internal status snapshot into a daemon-side evidence-log planning seam.
// It is intentionally data-only: it does not create evidence-log files, write to
// disk, rotate logs, or persist any state.
type DaemonSessionStatusEvidenceLogConfig struct {
	CustodyPlan     DaemonCustodyPlan
	Snapshot        DaemonSessionStatusSnapshot
	MaxEntryBytes   int64
	MaxLogBytes     int64
	MaxRotatedFiles int
}

// DaemonSessionStatusEvidenceLogPlan records daemon-owned evidence-log path
// derivation, entry schema/version/kind, retention/rotation parameters, and a
// digest of the planned snapshot entry. Every step must remain Executed=false
// until a separately reviewed privileged daemon slice owns actual evidence-log
// writes, rotation, and fail-closed integrity.
type DaemonSessionStatusEvidenceLogPlan struct {
	Mode string

	SessionID       string
	EvidenceLogPath string

	SchemaVersion string
	EntryKind     string
	EntryDigest   string

	MaxEntryBytes   int64
	MaxLogBytes     int64
	MaxRotatedFiles int

	Steps         []DaemonSessionStatusEvidenceLogStep
	ClaimBoundary []string
	NotClaimed    []string
}

// DaemonSessionStatusEvidenceLogStep is one future evidence-log operation
// recorded as reviewable plan data. This package must never execute these steps.
type DaemonSessionStatusEvidenceLogStep struct {
	Name      string
	Path      string
	Executed  bool
	Rationale string
}

// DefaultDaemonSessionStatusEvidenceLogConfig returns bounded defaults for the
// evidence-log planning seam.
func DefaultDaemonSessionStatusEvidenceLogConfig() DaemonSessionStatusEvidenceLogConfig {
	return DaemonSessionStatusEvidenceLogConfig{
		MaxEntryBytes:   DefaultDaemonSessionStatusEvidenceLogMaxEntryBytes,
		MaxLogBytes:     DefaultDaemonSessionStatusEvidenceLogMaxLogBytes,
		MaxRotatedFiles: DefaultDaemonSessionStatusEvidenceLogMaxRotatedFiles,
	}
}

// BuildDaemonSessionStatusEvidenceLogPlan validates the evidence-log config
// against a retained DaemonSessionStatusSnapshot and returns a dry-run plan
// only. It performs no filesystem writes, log creation, log rotation, or
// persistence of any kind.
func BuildDaemonSessionStatusEvidenceLogPlan(cfg DaemonSessionStatusEvidenceLogConfig) (DaemonSessionStatusEvidenceLogPlan, error) {
	if err := validateDaemonSessionStatusEvidenceLogConfig(cfg); err != nil {
		return DaemonSessionStatusEvidenceLogPlan{}, err
	}

	sessionID := strings.TrimSpace(cfg.Snapshot.Session.SessionID)
	sessionKey := daemonSessionHandoffSessionKey(sessionID)
	evidenceLogPath := filepath.Join(
		cleanPath(cfg.CustodyPlan.StateDir),
		"evidence",
		"sessions",
		sessionKey+".evlog",
	)
	if !lexicalPathWithin(evidenceLogPath, cfg.CustodyPlan.StateDir) {
		return DaemonSessionStatusEvidenceLogPlan{}, evidenceLogPlanError("evidence-log path escaped daemon state directory")
	}

	entryDigest, err := computeSnapshotEvidenceLogEntryDigest(cfg.Snapshot)
	if err != nil {
		return DaemonSessionStatusEvidenceLogPlan{}, evidenceLogPlanError("snapshot digest computation failed: %v", err)
	}

	return DaemonSessionStatusEvidenceLogPlan{
		Mode:            DaemonCustodyModeLocalOnlyScaffold,
		SessionID:       sessionID,
		EvidenceLogPath: evidenceLogPath,
		SchemaVersion:   DaemonSessionStatusEvidenceLogSchemaVersion,
		EntryKind:       DaemonSessionStatusEvidenceLogEntryKind,
		EntryDigest:     entryDigest,
		MaxEntryBytes:   cfg.MaxEntryBytes,
		MaxLogBytes:     cfg.MaxLogBytes,
		MaxRotatedFiles: cfg.MaxRotatedFiles,
		Steps: []DaemonSessionStatusEvidenceLogStep{
			{
				Name:      "validate_active_session_status_snapshot",
				Rationale: "evidence-log planning must start from a valid OK session_status snapshot with matching session ids, active status, non-zero AsOf, and clean handoff plan",
			},
			{
				Name:      "derive_daemon_owned_evidence_log_path",
				Path:      evidenceLogPath,
				Rationale: "evidence-log path is derived from a hash of the session id under the validated daemon state directory; client-supplied paths are never used",
			},
			{
				Name:      "compute_evidence_entry_digest",
				Rationale: "the snapshot entry digest anchors the planned evidence entry to the snapshot contents before any write occurs",
			},
			{
				Name:      "validate_retention_bounds",
				Rationale: "retention bounds (max entry bytes, max log bytes, max rotated files) must be validated before any future write path",
			},
			{
				Name:      "plan_fail_closed_rotation",
				Rationale: "future evidence-log rotation must fail closed on overflow, truncation, or integrity violation; this plan records the intent without executing it",
			},
		},
		ClaimBoundary: []string{
			"daemon-side evidence-log path is derived from session-id hash under validated daemon custody StateDir",
			"entry schema/version/kind are recorded as plan data before any write path exists",
			"snapshot entry digest is computed and recorded in the plan, anchoring the evidence entry to snapshot contents",
			"retention/rotation bounds are validated fail-closed in the plan before any write path",
			"every evidence-log step is recorded with Executed=false; this plan performs no filesystem writes, log creation, rotation, or persistence",
		},
		NotClaimed: []string{
			"filesystem writes, evidence-log creation, rotation, or persistence",
			"daemon install/start/service lifecycle",
			"client-visible protocol expansion",
			"production daemon readiness",
			"live enforcement or kernel-map mutation",
		},
	}, nil
}

func validateDaemonSessionStatusEvidenceLogConfig(cfg DaemonSessionStatusEvidenceLogConfig) error {
	if err := validateDaemonPeerHandshakeCustodyPlan(cfg.CustodyPlan); err != nil {
		return evidenceLogPlanError("custody plan is invalid: %v", err)
	}

	snapshot := cfg.Snapshot

	// Validate snapshot has the right shape before we trust it.
	if err := validateEvidenceLogSnapshot(snapshot); err != nil {
		return evidenceLogPlanError("snapshot integrity check failed: %v", err)
	}
	if err := validateEvidenceLogSnapshotCustody(snapshot, cfg.CustodyPlan); err != nil {
		return evidenceLogPlanError("snapshot custody check failed: %v", err)
	}

	// Validate retention/rotation bounds.
	if cfg.MaxEntryBytes <= 0 || cfg.MaxEntryBytes > MaxDaemonSessionStatusEvidenceLogMaxEntryBytes {
		return evidenceLogPlanError("max entry bytes must be between 1 and %d", MaxDaemonSessionStatusEvidenceLogMaxEntryBytes)
	}
	if cfg.MaxLogBytes <= 0 || cfg.MaxLogBytes > MaxDaemonSessionStatusEvidenceLogMaxLogBytes {
		return evidenceLogPlanError("max log bytes must be between 1 and %d", MaxDaemonSessionStatusEvidenceLogMaxLogBytes)
	}
	if cfg.MaxLogBytes < cfg.MaxEntryBytes {
		return evidenceLogPlanError("max log bytes (%d) cannot be less than max entry bytes (%d)", cfg.MaxLogBytes, cfg.MaxEntryBytes)
	}
	if cfg.MaxRotatedFiles <= 0 || cfg.MaxRotatedFiles > MaxDaemonSessionStatusEvidenceLogMaxRotatedFiles {
		return evidenceLogPlanError("max rotated files must be between 1 and %d", MaxDaemonSessionStatusEvidenceLogMaxRotatedFiles)
	}

	return nil
}

// validateEvidenceLogSnapshot performs all fail-closed checkpoint validations.
func validateEvidenceLogSnapshot(snapshot DaemonSessionStatusSnapshot) error {
	// Check that the snapshot has a valid ProtocolResponse.
	resp := snapshot.ProtocolResponse
	if resp.ProtocolVersion != DaemonProtocolVersion {
		return fmt.Errorf("protocol response version is %q, want %q", resp.ProtocolVersion, DaemonProtocolVersion)
	}
	if resp.Method != DaemonProtocolMethodSessionStatus {
		return fmt.Errorf("snapshot response method is %q, want session_status", resp.Method)
	}
	if !resp.OK {
		return fmt.Errorf("snapshot response is not OK: %s", resp.Error)
	}
	if strings.TrimSpace(resp.Error) != "" {
		return fmt.Errorf("snapshot response is OK but carries error text")
	}
	if resp.Status != DaemonSessionStatusActive {
		return fmt.Errorf("protocol response status is %q, want active", resp.Status)
	}
	if snapshot.Status != DaemonSessionStatusActive {
		return fmt.Errorf("snapshot status is %q, want active", snapshot.Status)
	}

	// Session ID consistency.
	sessionID := strings.TrimSpace(snapshot.Session.SessionID)
	respSessionID := strings.TrimSpace(resp.SessionID)
	planSessionID := strings.TrimSpace(snapshot.HandoffPlan.SessionID)

	if sessionID == "" {
		return fmt.Errorf("snapshot session id is empty")
	}
	if respSessionID == "" {
		return fmt.Errorf("protocol response session id is empty")
	}
	if respSessionID != sessionID {
		return fmt.Errorf("protocol response session id %q does not match snapshot session id %q", respSessionID, sessionID)
	}
	if planSessionID == "" {
		return fmt.Errorf("handoff plan session id is empty")
	}
	if planSessionID != sessionID {
		return fmt.Errorf("handoff plan session id %q does not match snapshot session id %q", planSessionID, sessionID)
	}

	// Must have non-zero AsOf.
	if snapshot.AsOf.IsZero() {
		return fmt.Errorf("snapshot AsOf is zero")
	}

	plan := snapshot.HandoffPlan
	if plan.Mode != DaemonCustodyModeLocalOnlyScaffold {
		return fmt.Errorf("handoff plan mode is %q, want %q", plan.Mode, DaemonCustodyModeLocalOnlyScaffold)
	}
	if plan.RootPID == 0 || plan.RootPID != snapshot.Session.RootPID {
		return fmt.Errorf("handoff plan root pid %d does not match snapshot root pid %d", plan.RootPID, snapshot.Session.RootPID)
	}
	if plan.CgroupID == 0 || plan.CgroupID != snapshot.Session.CgroupID {
		return fmt.Errorf("handoff plan cgroup id %d does not match snapshot cgroup id %d", plan.CgroupID, snapshot.Session.CgroupID)
	}
	if len(plan.Steps) == 0 {
		return fmt.Errorf("handoff plan steps are required")
	}

	// Handoff plan must have unexecuted steps only.
	for i, step := range plan.Steps {
		if step.Executed {
			return fmt.Errorf("evidence-log snapshot handoff step %d %q is executed; handoff plan must remain no-mutation", i, step.Name)
		}
	}

	// Check for forbidden metadata in the session handoff metadata.
	if containsForbiddenClientHandoffMetadataField(snapshot.Session.HandoffMetadata) {
		return fmt.Errorf("snapshot session contains forbidden raw/secret/path handoff metadata")
	}

	return nil
}

func validateEvidenceLogSnapshotCustody(snapshot DaemonSessionStatusSnapshot, custody DaemonCustodyPlan) error {
	plan := snapshot.HandoffPlan
	if strings.TrimSpace(plan.SessionStatePath) == "" {
		return fmt.Errorf("handoff plan session state path is required")
	}
	if strings.TrimSpace(plan.SessionRuntimeDir) == "" {
		return fmt.Errorf("handoff plan session runtime directory is required")
	}
	if strings.TrimSpace(plan.CgroupAllowlistMapPath) == "" {
		return fmt.Errorf("handoff plan cgroup allowlist map path is required")
	}
	if !lexicalPathWithin(plan.SessionStatePath, custody.StateDir) {
		return fmt.Errorf("handoff plan session state path escaped daemon state directory")
	}
	if !lexicalPathWithin(plan.SessionRuntimeDir, custody.RunDir) {
		return fmt.Errorf("handoff plan session runtime directory escaped daemon run directory")
	}
	if !lexicalPathWithin(plan.CgroupAllowlistMapPath, custody.BPFFSDir) {
		return fmt.Errorf("handoff plan cgroup allowlist map path escaped daemon bpffs directory")
	}
	return nil
}

func computeSnapshotEvidenceLogEntryDigest(snapshot DaemonSessionStatusSnapshot) (string, error) {
	entry := struct {
		SchemaVersion string                      `json:"schema_version"`
		EntryKind     string                      `json:"entry_kind"`
		Snapshot      DaemonSessionStatusSnapshot `json:"snapshot"`
	}{
		SchemaVersion: DaemonSessionStatusEvidenceLogSchemaVersion,
		EntryKind:     DaemonSessionStatusEvidenceLogEntryKind,
		Snapshot:      copyDaemonSessionStatusSnapshot(snapshot),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	return sha256Hex(data), nil
}

func evidenceLogPlanError(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrDaemonSessionStatusEvidenceLogPlan}, args...)...)
}
