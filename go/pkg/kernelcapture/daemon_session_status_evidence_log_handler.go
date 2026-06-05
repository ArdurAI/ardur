package kernelcapture

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DaemonSessionStatusEvidenceLogHandlerConfig configures daemon-side wiring from
// successful authorized session_status snapshots into the evidence-log entry
// builder and injected filesystem append adapter. It deliberately carries no
// daemon install/start/service lifecycle, ownership-management, fsync, cgroup,
// BPF, or client-visible protocol expansion authority.
type DaemonSessionStatusEvidenceLogHandlerConfig struct {
	Registry     *DaemonSessionRegistry
	CustodyPlan  DaemonCustodyPlan
	SnapshotSink *DaemonSessionStatusSnapshotSink
	Filesystem   DaemonSessionStatusEvidenceLogFilesystem

	EvidenceLogConfig DaemonSessionStatusEvidenceLogConfig
	DirectoryMode     fs.FileMode
	FileMode          fs.FileMode
	Clock             DaemonSessionClock
}

// DaemonSessionStatusEvidenceLogHandler is a DaemonAuthorizedProtocolHandler
// that forwards non-status requests to the registry and, for successful
// authorized session_status requests, composes the daemon-internal snapshot,
// evidence-log no-write plan, JSONL entry builder, and injected filesystem
// append adapter. The client still receives only DaemonProtocolResponse.
type DaemonSessionStatusEvidenceLogHandler struct {
	registry    *DaemonSessionRegistry
	custody     DaemonCustodyPlan
	sink        *DaemonSessionStatusSnapshotSink
	filesystem  DaemonSessionStatusEvidenceLogFilesystem
	evidenceCfg DaemonSessionStatusEvidenceLogConfig
	dirMode     fs.FileMode
	fileMode    fs.FileMode
	clock       DaemonSessionClock

	mu     sync.Mutex
	states map[string]*DaemonSessionStatusEvidenceLogAppendState
}

func NewDaemonSessionStatusEvidenceLogHandler(cfg DaemonSessionStatusEvidenceLogHandlerConfig) *DaemonSessionStatusEvidenceLogHandler {
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &DaemonSessionStatusEvidenceLogHandler{
		registry:    cfg.Registry,
		custody:     cfg.CustodyPlan,
		sink:        cfg.SnapshotSink,
		filesystem:  cfg.Filesystem,
		evidenceCfg: cfg.EvidenceLogConfig,
		dirMode:     cfg.DirectoryMode,
		fileMode:    cfg.FileMode,
		clock:       clock,
		states:      make(map[string]*DaemonSessionStatusEvidenceLogAppendState),
	}
}

func (h *DaemonSessionStatusEvidenceLogHandler) HandleAuthorizedRequest(ctx context.Context, req DaemonProtocolRequest, handshake DaemonProtocolPeerHandshake) DaemonProtocolResponse {
	if h == nil {
		return daemonSessionRegistryErrorResponse(req, "", "session status evidence-log handler is required")
	}
	if req.Method != DaemonProtocolMethodSessionStatus {
		if h.registry == nil {
			return daemonSessionRegistryErrorResponse(req, "", "registry is required")
		}
		return h.registry.HandleAuthorizedRequest(ctx, req, handshake)
	}
	if h.sink == nil {
		return daemonSessionRegistryErrorResponse(req, "", "session status evidence-log snapshot sink is required")
	}
	if h.filesystem == nil {
		return daemonSessionRegistryErrorResponse(req, "", "session status evidence-log filesystem is required")
	}
	if h.registry == nil {
		return daemonSessionRegistryErrorResponse(req, "", "registry is required")
	}

	snapshot, response := h.registry.HandleAuthorizedSessionStatusSnapshot(ctx, req, handshake, h.custody)
	if !response.OK {
		return response
	}
	appendPlan, ok := h.appendSnapshot(snapshot)
	if !ok {
		return daemonSessionRegistryErrorResponse(req, response.Status, "session_status evidence-log append failed")
	}
	if appendPlan.Decision == DaemonSessionStatusEvidenceLogAppendReject {
		return daemonSessionRegistryErrorResponse(req, response.Status, "session_status evidence-log append rejected")
	}
	h.sink.Retain(snapshot)
	return response
}

// EvidenceLogStateSnapshot returns a detached view of the per-session append
// state retained by this handler. It is an internal observability seam for tests
// and future daemon code; it does not expose data on the client protocol.
func (h *DaemonSessionStatusEvidenceLogHandler) EvidenceLogStateSnapshot(sessionID string) (DaemonSessionStatusEvidenceLogAppendStateSnapshot, bool) {
	if h == nil {
		return DaemonSessionStatusEvidenceLogAppendStateSnapshot{}, false
	}
	path := h.evidenceLogPathForSession(sessionID)
	if path == "" {
		return DaemonSessionStatusEvidenceLogAppendStateSnapshot{}, false
	}
	h.mu.Lock()
	state := h.states[path]
	h.mu.Unlock()
	if state == nil {
		return DaemonSessionStatusEvidenceLogAppendStateSnapshot{}, false
	}
	return state.Snapshot(), true
}

func (h *DaemonSessionStatusEvidenceLogHandler) appendSnapshot(snapshot DaemonSessionStatusSnapshot) (DaemonSessionStatusEvidenceLogAppendPlan, bool) {
	planCfg := h.evidenceLogConfigForSnapshot(snapshot)
	plan, err := BuildDaemonSessionStatusEvidenceLogPlan(planCfg)
	if err != nil {
		return DaemonSessionStatusEvidenceLogAppendPlan{}, false
	}
	entry, err := BuildDaemonSessionStatusEvidenceLogEntry(plan, snapshot)
	if err != nil {
		return DaemonSessionStatusEvidenceLogAppendPlan{}, false
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	state := h.states[plan.EvidenceLogPath]
	created := false
	if state == nil {
		state, err = NewDaemonSessionStatusEvidenceLogAppendState(plan, h.clock)
		if err != nil {
			return DaemonSessionStatusEvidenceLogAppendPlan{}, false
		}
		created = true
	}
	appendPlan, err := ApplyDaemonSessionStatusEvidenceLogFilesystemAppendForPlan(DaemonSessionStatusEvidenceLogFilesystemAppendConfig{
		State:         state,
		Filesystem:    h.filesystem,
		DirectoryMode: h.dirMode,
		FileMode:      h.fileMode,
	}, plan, entry)
	if err != nil {
		return DaemonSessionStatusEvidenceLogAppendPlan{}, false
	}
	if appendPlan.Decision == DaemonSessionStatusEvidenceLogAppendAccept || appendPlan.Decision == DaemonSessionStatusEvidenceLogAppendRotateThenAppend {
		if created {
			h.states[plan.EvidenceLogPath] = state
		}
	}
	return appendPlan, true
}

func (h *DaemonSessionStatusEvidenceLogHandler) evidenceLogConfigForSnapshot(snapshot DaemonSessionStatusSnapshot) DaemonSessionStatusEvidenceLogConfig {
	cfg := DefaultDaemonSessionStatusEvidenceLogConfig()
	if h.evidenceCfg.MaxEntryBytes != 0 {
		cfg.MaxEntryBytes = h.evidenceCfg.MaxEntryBytes
	}
	if h.evidenceCfg.MaxLogBytes != 0 {
		cfg.MaxLogBytes = h.evidenceCfg.MaxLogBytes
	}
	if h.evidenceCfg.MaxRotatedFiles != 0 {
		cfg.MaxRotatedFiles = h.evidenceCfg.MaxRotatedFiles
	}
	cfg.CustodyPlan = h.custody
	cfg.Snapshot = copyDaemonSessionStatusSnapshot(snapshot)
	return cfg
}

func (h *DaemonSessionStatusEvidenceLogHandler) evidenceLogPathForSession(sessionID string) string {
	if h == nil || strings.TrimSpace(sessionID) == "" {
		return ""
	}
	stateDir := cleanPath(h.custody.StateDir)
	if stateDir == "" {
		return ""
	}
	return filepath.Join(stateDir, "evidence", "sessions", daemonSessionHandoffSessionKey(sessionID)+".evlog")
}
