package kernelcapture

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const DaemonSessionHandoffAllowlistMapName = "session_cgroup_allowlist"

var ErrDaemonSessionHandoffPlan = errors.New("kernelcapture: invalid daemon session handoff plan")

// DaemonSessionHandoffConfig is the no-mutation bridge from daemon-owned
// in-memory session state into the next reviewable daemon session/cgroup
// handoff plan. It is intentionally data-only: it does not create cgroups,
// write session files, pin BPF maps, or enable kernel filtering.
type DaemonSessionHandoffConfig struct {
	CustodyPlan DaemonCustodyPlan
	Session     DaemonSessionRecord
	AsOf        time.Time
}

// DaemonSessionHandoffPlan records daemon-owned paths and sequencing invariants
// for a registered process-lifecycle session. Every step is descriptive and must
// remain Executed=false until a separately reviewed privileged daemon slice owns
// actual filesystem, cgroup, BPF map, and enforcement mutations.
type DaemonSessionHandoffPlan struct {
	Mode string

	SessionID  string
	MissionID  string
	TraceID    string
	SessionKey string

	RootPID        uint32
	PIDNamespaceID uint32
	CgroupID       uint64

	SessionStatePath               string
	SessionRuntimeDir              string
	CgroupAllowlistMapPath         string
	ProcessLifecycleRingbufMapPath string
	CgroupFilterSequence           CgroupFilterSequence

	Steps         []DaemonSessionHandoffStep
	ClaimBoundary []string
	NotClaimed    []string
}

// DaemonSessionHandoffStep is one future daemon handoff operation recorded as
// reviewable plan data. This package must never execute these steps.
type DaemonSessionHandoffStep struct {
	Name      string
	Path      string
	Executed  bool
	Rationale string
}

func BuildDaemonSessionHandoffPlan(cfg DaemonSessionHandoffConfig) (DaemonSessionHandoffPlan, error) {
	if err := validateDaemonSessionHandoffConfig(cfg); err != nil {
		return DaemonSessionHandoffPlan{}, err
	}

	session := copyDaemonSessionRecord(cfg.Session)
	sessionID := strings.TrimSpace(session.SessionID)
	sessionKey := daemonSessionHandoffSessionKey(sessionID)
	statePath := filepath.Join(cleanPath(cfg.CustodyPlan.StateDir), "sessions", sessionKey+".json")
	runtimeDir := filepath.Join(cleanPath(cfg.CustodyPlan.RunDir), "sessions", sessionKey)
	allowlistMapPath := filepath.Join(cleanPath(cfg.CustodyPlan.BPFFSDir), DaemonSessionHandoffAllowlistMapName)
	filterSequence := CgroupFilterSequence{
		Enable:             true,
		AllowlistCgroupIDs: []uint64{session.CgroupID},
	}
	if err := ValidateCgroupFilterSequence(filterSequence); err != nil {
		return DaemonSessionHandoffPlan{}, daemonSessionHandoffError("cgroup filter sequence is invalid: %v", err)
	}
	if !lexicalPathWithin(statePath, cfg.CustodyPlan.StateDir) {
		return DaemonSessionHandoffPlan{}, daemonSessionHandoffError("session state path escaped daemon state directory")
	}
	if !lexicalPathWithin(runtimeDir, cfg.CustodyPlan.RunDir) {
		return DaemonSessionHandoffPlan{}, daemonSessionHandoffError("session runtime path escaped daemon runtime directory")
	}
	if !lexicalPathWithin(allowlistMapPath, cfg.CustodyPlan.BPFFSDir) {
		return DaemonSessionHandoffPlan{}, daemonSessionHandoffError("cgroup allowlist map path escaped daemon bpffs directory")
	}

	return DaemonSessionHandoffPlan{
		Mode:                           DaemonCustodyModeLocalOnlyScaffold,
		SessionID:                      sessionID,
		MissionID:                      strings.TrimSpace(session.MissionID),
		TraceID:                        strings.TrimSpace(session.TraceID),
		SessionKey:                     sessionKey,
		RootPID:                        session.RootPID,
		PIDNamespaceID:                 session.PIDNamespaceID,
		CgroupID:                       session.CgroupID,
		SessionStatePath:               statePath,
		SessionRuntimeDir:              runtimeDir,
		CgroupAllowlistMapPath:         allowlistMapPath,
		ProcessLifecycleRingbufMapPath: cleanPath(cfg.CustodyPlan.RingbufMapPath),
		CgroupFilterSequence:           filterSequence,
		Steps: []DaemonSessionHandoffStep{
			{
				Name:      "validate_active_registered_session",
				Rationale: "session handoff planning starts only from active daemon-owned registry state",
			},
			{
				Name:      "derive_daemon_owned_session_paths",
				Rationale: "session paths are derived from a hash of the session id under validated daemon custody roots, never from client-supplied paths",
			},
			{
				Name:      "plan_session_state_checkpoint",
				Path:      statePath,
				Rationale: "future daemon persistence must stay under the daemon-owned state directory; this plan does not write the file",
			},
			{
				Name:      "plan_session_runtime_directory",
				Path:      runtimeDir,
				Rationale: "future volatile session artifacts must stay under the daemon-owned runtime directory; this plan does not create it",
			},
			{
				Name:      "plan_nonzero_cgroup_allowlist_entry",
				Path:      allowlistMapPath,
				Rationale: "future filtering can only be described after a non-zero cgroup id is available; this plan does not mutate the BPF map",
			},
			{
				Name:      "verify_filter_enable_precondition",
				Path:      allowlistMapPath,
				Rationale: "filter enablement is valid only after the planned allowlist sequence contains a non-zero cgroup id",
			},
			{
				Name:      "seed_process_tree_correlation",
				Rationale: "root pid, optional pid namespace, and cgroup id can seed correlation before broader syscall/file/network capture exists",
			},
		},
		ClaimBoundary: []string{
			"registered session metadata is projected into daemon-owned handoff paths as no-mutation plan data",
			"session path names are derived from a session-id hash under validated daemon custody roots",
			"cgroup filtering sequence is only a precondition plan with a non-zero observed cgroup id",
			"every handoff step is recorded with Executed=false",
		},
		NotClaimed: []string{
			"production daemon readiness",
			"daemon install/start, service management, or persistent privileged process custody",
			"daemon-created/assigned cgroups",
			"filesystem writes, cgroup writes, BPF map mutation, or live enforcement",
			"file/network/privilege side-effect capture",
		},
	}, nil
}

func validateDaemonSessionHandoffConfig(cfg DaemonSessionHandoffConfig) error {
	if cfg.AsOf.IsZero() {
		return daemonSessionHandoffError("as_of time is required")
	}
	if err := validateDaemonPeerHandshakeCustodyPlan(cfg.CustodyPlan); err != nil {
		return daemonSessionHandoffError("custody plan is invalid: %v", err)
	}
	session := cfg.Session
	if strings.TrimSpace(session.SessionID) == "" {
		return daemonSessionHandoffError("session_id is required")
	}
	if session.RootPID == 0 {
		return daemonSessionHandoffError("root_pid is required")
	}
	if session.CgroupID == 0 {
		return daemonSessionHandoffError("non-zero cgroup_id is required before cgroup handoff planning")
	}
	if session.RegisteredAt.IsZero() {
		return daemonSessionHandoffError("registered_at is required")
	}
	if session.ExpiresAt.IsZero() {
		return daemonSessionHandoffError("expires_at is required")
	}
	if status := session.Status(cfg.AsOf); status != DaemonSessionStatusActive {
		return daemonSessionHandoffError("session must be active before handoff planning: %s", status)
	}
	if !daemonSessionHasEventClass(session, DaemonProtocolEventProcessLifecycle) {
		return daemonSessionHandoffError("process_lifecycle event class is required")
	}
	if strings.TrimSpace(session.CredentialSource) == "" {
		return daemonSessionHandoffError("daemon-observed credential source is required")
	}
	if session.CredentialSource != DaemonPeerCredentialSourceLinuxSOPeerCred {
		return daemonSessionHandoffError("unsupported credential source %q", session.CredentialSource)
	}
	if session.PeerPID == 0 {
		return daemonSessionHandoffError("daemon-observed peer pid is required")
	}
	if cleanPath(session.SocketPath) != cleanPath(cfg.CustodyPlan.SocketPath) {
		return daemonSessionHandoffError("session socket path must match daemon custody plan")
	}
	if containsForbiddenClientHandoffMetadataField(session.HandoffMetadata) {
		return daemonSessionHandoffError("handoff metadata contains forbidden raw command, path, environment, secret-like, daemon-owned path, or peer identity fields")
	}
	return nil
}

func daemonSessionHasEventClass(session DaemonSessionRecord, eventClass string) bool {
	for _, got := range session.EventClasses {
		if got == eventClass {
			return true
		}
	}
	return false
}

func daemonSessionHandoffSessionKey(sessionID string) string {
	return sha256Hex([]byte(strings.TrimSpace(sessionID)))
}

func daemonSessionHandoffError(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrDaemonSessionHandoffPlan}, args...)...)
}
