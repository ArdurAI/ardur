// Package main is the entry point for ardur-kernelcaptured, the Ardur
// kernel-capture daemon (Slice 1 — foreground/dev mode).
//
// The daemon wires the existing kernelcapture library components into a running
// process:
//   - Unix-socket control plane (ListenDaemonUnixSocketServer + SO_PEERCRED auth)
//   - Session registry (DaemonSessionRegistry) honoring register_session TTL
//   - eBPF event consumer (Linux only; degrades gracefully on unsupported platforms)
//   - Correlator routing events to registered sessions
//   - Evidence-log JSONL writer per session
//
// Claim boundary for Slice 1:
//   - Starts and serves the socket control plane.
//   - On Linux: loads the process-exec eBPF program, attaches sched/sched_process_exec
//     and sched/sched_process_exit tracepoints, routes events to registered sessions,
//     and appends SyntheticKernelReceipts to per-session JSONL evidence logs.
//   - On non-Linux: control plane only; eBPF consumer is unavailable.
//
// NOT in Slice 1 (explicitly out-of-scope):
//   - Privileged system-service install / systemd unit (Slice 2).
//   - cgroup creation and assignment (left to the ardur-run bridge, PR #81).
//   - Enforcement / kill-switch actions (Slice 4).
//   - File, network, or syscall capture beyond process exec/exit metadata.
//   - Production hardening: persistent socket path ownership, bpffs map pinning,
//     or crash-recovery.
//
// Refs: Epic A (#63), task #66 (daemon/launcher).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

const (
	defaultSocketPath   = "/run/ardur/kernelcapture/control.sock"
	defaultEvidenceDir  = "/var/lib/ardur/kernelcapture/evidence"
	defaultStateDir     = "/var/lib/ardur/kernelcapture/state"
	defaultSocketMode   = fs.FileMode(0o660)
	KernelReceiptSchema = "ardur.kernel.receipt.v1"
)

// KernelReceiptEntry is the JSONL record appended to
// <evidenceDir>/<sessionID>/kernel_receipts.jsonl for each observed process
// event that is correlated to a registered session.
type KernelReceiptEntry struct {
	SchemaVersion string                               `json:"schema_version"`
	SessionID     string                               `json:"session_id"`
	RecordedAt    time.Time                            `json:"recorded_at"`
	Event         kernelcapture.ProcessEvent           `json:"event"`
	Receipt       kernelcapture.SyntheticKernelReceipt `json:"receipt"`
}

// daemon holds all shared state for the running daemon process.
type daemon struct {
	log         *slog.Logger
	registry    *kernelcapture.DaemonSessionRegistry
	custodyPlan kernelcapture.DaemonCustodyPlan
	peerPolicy  kernelcapture.DaemonPeerAuthorizationPolicy
	evidenceDir string

	// Routing index: cgroup_id → session_id, maintained under mu.
	// Populated on register_session, removed on end_session / expiry.
	mu          sync.RWMutex
	cgroupIndex map[uint64]string
	treeScopes  map[string]*kernelcapture.ProcessTreeScope
	correlators map[string]*kernelcapture.Correlator

	// enforce_events state, maintained under mu (session-scoped) plus two
	// daemon-lifetime singletons for events that cannot be attributed to any
	// session (enforceOrphanChain/enforceOrphanSummary; see daemon_enforce.go).
	enforceChains        map[string]*kernelcapture.EnforceReceiptChain
	enforceSummaries     map[string]*kernelcapture.EnforceEventSummaryAccumulator
	enforceOrphanChain   *kernelcapture.EnforceReceiptChain
	enforceOrphanSummary *kernelcapture.EnforceEventSummaryAccumulator

	// OS filesystem for JSONL append (interface for test injection).
	fs evidenceFS
}

func newDaemon(log *slog.Logger, socketPath, evidenceDir, stateDir string, ownerUID uint32) (*daemon, error) {
	cfg := kernelcapture.DefaultDaemonCustodyConfig()
	if socketPath != "" {
		cfg.SocketPath = socketPath
		cfg.RunDir = filepath.Dir(socketPath)
	}
	if stateDir != "" {
		cfg.StateDir = stateDir
	}
	custodyPlan, err := kernelcapture.BuildDaemonCustodyPlan(cfg)
	if err != nil {
		return nil, fmt.Errorf("build custody plan: %w", err)
	}

	registry := kernelcapture.NewDaemonSessionRegistry()

	// Allow the daemon's own UID and, if root, also UID 0. In production this
	// should be locked down further; for Slice 1 (foreground/dev) we allow the
	// launching user to register sessions.
	allowedUIDs := []uint32{ownerUID}
	if ownerUID != 0 {
		allowedUIDs = append(allowedUIDs, 0)
	}
	peerPolicy := kernelcapture.DaemonPeerAuthorizationPolicy{
		AllowedUIDs: allowedUIDs,
	}

	return &daemon{
		log:                  log,
		registry:             registry,
		custodyPlan:          custodyPlan,
		peerPolicy:           peerPolicy,
		evidenceDir:          evidenceDir,
		cgroupIndex:          make(map[uint64]string),
		treeScopes:           make(map[string]*kernelcapture.ProcessTreeScope),
		correlators:          make(map[string]*kernelcapture.Correlator),
		enforceChains:        make(map[string]*kernelcapture.EnforceReceiptChain),
		enforceSummaries:     make(map[string]*kernelcapture.EnforceEventSummaryAccumulator),
		enforceOrphanChain:   kernelcapture.NewEnforceReceiptChain(),
		enforceOrphanSummary: kernelcapture.NewEnforceEventSummaryAccumulator(),
		fs:                   osEvidenceFS{},
	}, nil
}

// handleAuthorizedRequest is the DaemonAuthorizedProtocolHandler wired into the
// socket server. It delegates to the registry and maintains the cgroup routing
// index as a side effect of successful register/end-session responses.
func (d *daemon) handleAuthorizedRequest(ctx context.Context, req kernelcapture.DaemonProtocolRequest, handshake kernelcapture.DaemonProtocolPeerHandshake) kernelcapture.DaemonProtocolResponse {
	resp := d.registry.HandleAuthorizedRequest(ctx, req, handshake)
	if !resp.OK {
		return resp
	}
	switch req.Method {
	case kernelcapture.DaemonProtocolMethodRegisterSession:
		if req.RegisterSession != nil {
			d.onSessionRegistered(req.RegisterSession, resp.SessionID)
		}
	case kernelcapture.DaemonProtocolMethodEndSession:
		if sessionID := req.EndSession; sessionID != nil {
			d.onSessionEnded(sessionID.SessionID)
		}
	case kernelcapture.DaemonProtocolMethodSessionStatus:
		if summary, ok := d.enforceSummaryForScope(resp.SessionID); ok {
			resp.Enforcement = &summary
		}
	}
	return resp
}

// onSessionRegistered adds the session to the cgroup routing index.
func (d *daemon) onSessionRegistered(reg *kernelcapture.DaemonRegisterSessionRequest, sessionID string) {
	if sessionID == "" || reg == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if reg.CgroupID != 0 {
		d.cgroupIndex[reg.CgroupID] = sessionID
	}

	scope := kernelcapture.NewProcessTreeScope(reg.RootPID, reg.CgroupID)
	scope.SessionID = sessionID
	d.treeScopes[sessionID] = &scope

	d.correlators[sessionID] = kernelcapture.NewCorrelator(kernelcapture.CorrelatorOptions{
		Platform:         "linux",
		CaptureBackend:   "linux_ebpf",
		CorrelationGrace: 5 * time.Second,
		RestartGrace:     3 * time.Second,
	})
	d.enforceChains[sessionID] = kernelcapture.NewEnforceReceiptChain()
	d.enforceSummaries[sessionID] = kernelcapture.NewEnforceEventSummaryAccumulator()

	d.log.Info("session registered",
		"session_id", sessionID,
		"root_pid", reg.RootPID,
		"cgroup_id", reg.CgroupID,
		"event_classes", reg.EventClasses,
		"ttl_s", reg.TTLSeconds,
	)
}

// onSessionEnded removes the session from the routing index.
func (d *daemon) onSessionEnded(sessionID string) {
	if sessionID == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if scope, ok := d.treeScopes[sessionID]; ok {
		if scope.CgroupID != 0 {
			delete(d.cgroupIndex, scope.CgroupID)
		}
	}
	delete(d.treeScopes, sessionID)
	delete(d.correlators, sessionID)
	delete(d.enforceChains, sessionID)
	delete(d.enforceSummaries, sessionID)

	d.log.Info("session ended", "session_id", sessionID)
}

// routeEvent finds the session for a raw kernel event, runs process-tree
// tracking, and returns the session_id + correlator. Returns ("", nil) if the
// event belongs to no registered session.
func (d *daemon) routeEvent(evt *kernelcapture.ProcessEvent) (string, *kernelcapture.Correlator) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Fast path: cgroup match.
	if evt.CgroupID != 0 {
		if sid, ok := d.cgroupIndex[evt.CgroupID]; ok {
			scope := d.treeScopes[sid]
			if scope != nil && scope.MatchesAndTrack(*evt) {
				evt.SessionID = sid
				return sid, d.correlators[sid]
			}
		}
	}
	// Slow path: walk all sessions and check process tree membership.
	// This handles subtree events where the child has escaped to a new cgroup
	// (uncommon but possible).
	for sid, scope := range d.treeScopes {
		if scope.MatchesAndTrack(*evt) {
			evt.SessionID = sid
			return sid, d.correlators[sid]
		}
	}
	return "", nil
}

// appendKernelReceipt writes one KernelReceiptEntry as a JSONL line to
// <evidenceDir>/<sessionID>/kernel_receipts.jsonl.
func (d *daemon) appendKernelReceipt(sessionID string, evt kernelcapture.ProcessEvent, receipt kernelcapture.SyntheticKernelReceipt) {
	entry := KernelReceiptEntry{
		SchemaVersion: KernelReceiptSchema,
		SessionID:     sessionID,
		RecordedAt:    time.Now().UTC(),
		Event:         evt,
		Receipt:       receipt,
	}
	line, err := json.Marshal(entry)
	if err != nil {
		d.log.Warn("marshal kernel receipt entry", "session_id", sessionID, "error", err)
		return
	}
	line = append(line, '\n')

	dir := filepath.Join(d.evidenceDir, sanitizeSessionID(sessionID))
	path := filepath.Join(dir, "kernel_receipts.jsonl")
	if err := prevalidateKernelReceiptAppendPath(d.fs, d.evidenceDir, dir, path); err != nil {
		d.log.Warn("prevalidate kernel receipt path", "path", path, "error", err)
		return
	}
	if err := d.fs.MkdirAll(dir, 0o700); err != nil {
		d.log.Warn("create evidence log dir", "path", dir, "error", err)
		return
	}
	if err := d.fs.AppendFile(path, line, 0o600); err != nil {
		d.log.Warn("append kernel receipt", "path", path, "error", err)
	}
}

// processKernelEvent is called by the platform-specific event loop for each
// event that arrives from the eBPF ringbuf.
func (d *daemon) processKernelEvent(evt kernelcapture.ProcessEvent, loss kernelcapture.CaptureLoss) {
	sid, correlator := d.routeEvent(&evt)
	if sid == "" || correlator == nil {
		return
	}

	ctx := kernelcapture.EventContext{
		CaptureLoss: loss,
	}
	receipt := correlator.Correlate(evt, ctx)

	d.log.Debug("kernel event",
		"session_id", sid,
		"type", evt.Type,
		"pid", evt.PID,
		"comm", evt.Comm,
		"cgroup", evt.CgroupID,
		"correlation", receipt.CorrelationMethod+"/"+receipt.CorrelationConfidence,
		"verdict", receipt.Verdict,
	)
	d.appendKernelReceipt(sid, evt, receipt)
}

// pruneExpiredSessions removes sessions that the registry has expired so the
// cgroup index does not leak indefinitely.
func (d *daemon) pruneExpiredSessions() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for sid, scope := range d.treeScopes {
		if _, err := d.registry.ActiveSession(sid); err != nil {
			if scope.CgroupID != 0 {
				delete(d.cgroupIndex, scope.CgroupID)
			}
			delete(d.treeScopes, sid)
			delete(d.correlators, sid)
			delete(d.enforceChains, sid)
			delete(d.enforceSummaries, sid)
			d.log.Info("pruned expired session", "session_id", sid)
		}
	}
}

// sanitizeSessionID strips characters that are unsafe in filesystem paths.
func sanitizeSessionID(id string) string {
	var b strings.Builder
	for _, c := range id {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

// evidenceFS is the minimal filesystem interface used for writing JSONL
// evidence log entries. Using an interface here allows test injection.
type evidenceFS interface {
	Lstat(path string) (fs.FileInfo, error)
	MkdirAll(path string, perm fs.FileMode) error
	AppendFile(path string, data []byte, perm fs.FileMode) error
}

// osEvidenceFS is the OS-backed production implementation of evidenceFS.
type osEvidenceFS struct{}

func (osEvidenceFS) Lstat(path string) (fs.FileInfo, error) {
	return os.Lstat(path)
}

func (osEvidenceFS) MkdirAll(path string, perm fs.FileMode) error {
	return os.MkdirAll(path, perm)
}

func prevalidateKernelReceiptAppendPath(fsys evidenceFS, evidenceDir string, parentDir string, receiptPath string) error {
	if fsys == nil {
		return fmt.Errorf("filesystem is required")
	}
	if err := prevalidateKernelReceiptParentChain(fsys, evidenceDir, parentDir); err != nil {
		return err
	}
	if err := prevalidateKernelReceiptPathNotSymlink(fsys, receiptPath, "kernel receipt path"); err != nil {
		return err
	}
	return nil
}

func prevalidateKernelReceiptParentChain(fsys evidenceFS, evidenceDir string, parentDir string) error {
	parents, err := kernelReceiptParentChain(evidenceDir, parentDir)
	if err != nil {
		return err
	}
	for _, parent := range parents {
		info, err := fsys.Lstat(parent)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("prevalidate kernel receipt parent %q failed: %w", parent, err)
		}
		mode := info.Mode()
		if mode&fs.ModeSymlink != 0 {
			return fmt.Errorf("prevalidate kernel receipt parent %q failed: symlink parent is not allowed", parent)
		}
		if !mode.IsDir() {
			return fmt.Errorf("prevalidate kernel receipt parent %q failed: parent is not a directory", parent)
		}
	}
	return nil
}

func kernelReceiptParentChain(evidenceDir string, parentDir string) ([]string, error) {
	evidenceDir = filepath.Clean(evidenceDir)
	parentDir = filepath.Clean(parentDir)
	rel, err := filepath.Rel(evidenceDir, parentDir)
	if err != nil {
		return nil, fmt.Errorf("derive kernel receipt parent chain failed: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("kernel receipt parent %q escaped evidence directory %q", parentDir, evidenceDir)
	}
	parents := []string{evidenceDir}
	if rel == "." {
		return parents, nil
	}
	current := evidenceDir
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return nil, fmt.Errorf("kernel receipt parent %q escaped evidence directory %q", parentDir, evidenceDir)
		}
		current = filepath.Join(current, part)
		parents = append(parents, current)
	}
	return parents, nil
}

func prevalidateKernelReceiptPathNotSymlink(fsys evidenceFS, path string, label string) error {
	info, err := fsys.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("prevalidate %s %q failed: %w", label, path, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("prevalidate %s %q failed: symlink path is not allowed", label, path)
	}
	return nil
}

func (osEvidenceFS) AppendFile(path string, data []byte, perm fs.FileMode) (err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, perm)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}()
	written, err := f.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return err
}

func main() {
	var (
		socketPath  = flag.String("socket", defaultSocketPath, "Unix-domain control socket path")
		evidenceDir = flag.String("evidence-dir", defaultEvidenceDir, "Directory for per-session kernel receipt JSONL logs")
		stateDir    = flag.String("state-dir", defaultStateDir, "Daemon state directory")
		noRingbuf   = flag.Bool("no-ringbuf", false, "Skip eBPF ringbuf consumer (socket control plane only)")
		debug       = flag.Bool("debug", false, "Enable debug-level logging")
		pruneEvery  = flag.Duration("prune-interval", 30*time.Second, "Interval to prune expired session routing entries")
	)
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	log.Info("ardur-kernelcaptured starting",
		"socket", *socketPath,
		"evidence_dir", *evidenceDir,
		"state_dir", *stateDir,
		"no_ringbuf", *noRingbuf,
		"platform", platformName(),
	)

	ownerUID := uint32(os.Getuid())
	d, err := newDaemon(log, *socketPath, *evidenceDir, *stateDir, ownerUID)
	if err != nil {
		log.Error("init daemon", "error", err)
		os.Exit(1)
	}

	// Ensure socket directory exists.
	if mkErr := os.MkdirAll(filepath.Dir(*socketPath), 0o755); mkErr != nil {
		log.Error("create socket directory", "path", filepath.Dir(*socketPath), "error", mkErr)
		os.Exit(1)
	}
	// Remove stale socket file from a previous run.
	_ = os.Remove(*socketPath)

	svr, err := kernelcapture.ListenDaemonUnixSocketServer(
		kernelcapture.DaemonUnixSocketServerConfig{
			CustodyPlan:             d.custodyPlan,
			PeerAuthorizationPolicy: d.peerPolicy,
			SocketMode:              defaultSocketMode,
			HandleAuthorizedRequest: d.handleAuthorizedRequest,
			ObservePeerCredentials:  kernelcapture.ObserveLinuxUnixPeerCredentials,
		},
	)
	if err != nil {
		log.Error("bind control socket", "socket", *socketPath, "error", err)
		os.Exit(1)
	}
	log.Info("control socket listening", "socket", svr.SocketPath())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup

	// Control-plane goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := svr.Serve(ctx); err != nil && ctx.Err() == nil {
			log.Error("control socket serve", "error", err)
		}
	}()

	// Session expiry pruner.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(*pruneEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.pruneExpiredSessions()
			}
		}
	}()

	// Data-plane goroutine: eBPF ringbuf consumer (platform-specific).
	if !*noRingbuf {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runEBPFConsumer(ctx, d, log); err != nil && ctx.Err() == nil {
				log.Error("eBPF consumer stopped", "error", err)
			}
		}()
	} else {
		log.Info("eBPF ringbuf consumer disabled (--no-ringbuf)")
	}

	// Notify systemd that the daemon is ready (Type=notify in the unit).
	// Non-fatal: if not running under systemd NOTIFY_SOCKET is unset and
	// sdNotify is a no-op.
	if err := sdNotify("READY=1"); err != nil {
		log.Warn("sd_notify READY failed", "error", err)
	}

	// Watchdog keepalive goroutine: sends WATCHDOG=1 at half the unit's
	// WatchdogSec=30 interval so systemd never times out during normal
	// operation.
	wg.Add(1)
	go func() {
		defer wg.Done()
		runWatchdog(ctx, 15*time.Second, log)
	}()

	<-ctx.Done()
	log.Info("shutting down", "reason", ctx.Err())
	_ = sdNotify("STOPPING=1")
	svr.Close()
	wg.Wait()
	log.Info("ardur-kernelcaptured stopped")
}
