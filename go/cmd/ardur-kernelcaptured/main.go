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
	defaultSocketPath        = "/run/ardur/kernelcapture/control.sock"
	defaultSeccompSocketPath = "/run/ardur/kernelcapture/seccomp.sock"
	defaultEvidenceDir       = "/var/lib/ardur/kernelcapture/evidence"
	defaultStateDir          = "/var/lib/ardur/kernelcapture/state"
	defaultSocketMode        = fs.FileMode(0o660)
	KernelReceiptSchema      = "ardur.kernel.receipt.v1"
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

// sessionRoute owns mutable process-tree routing state for one session. Its
// identity and correlator are immutable after publication. A successful
// lockIfMatches leaves mu locked so the caller can hold a route lease through
// correlation and evidence append; callers must invoke unlock afterward.
type sessionRoute struct {
	mu         sync.Mutex
	sessionID  string
	scope      *kernelcapture.ProcessTreeScope
	correlator *kernelcapture.Correlator
	active     bool
}

func newSessionRoute(sessionID string, scope *kernelcapture.ProcessTreeScope, correlator *kernelcapture.Correlator) *sessionRoute {
	return &sessionRoute{
		sessionID:  sessionID,
		scope:      scope,
		correlator: correlator,
		active:     true,
	}
}

func (r *sessionRoute) lockIfMatches(evt *kernelcapture.ProcessEvent) bool {
	if r == nil || evt == nil {
		return false
	}
	r.mu.Lock()
	if !r.active || r.scope == nil || !r.scope.MatchesAndTrack(*evt) {
		r.mu.Unlock()
		return false
	}
	evt.SessionID = r.sessionID
	return true
}

func (r *sessionRoute) unlock() {
	if r != nil {
		r.mu.Unlock()
	}
}

// daemon holds all shared state for the running daemon process.
type daemon struct {
	log         *slog.Logger
	registry    *kernelcapture.DaemonSessionRegistry
	custodyPlan kernelcapture.DaemonCustodyPlan
	peerPolicy  kernelcapture.DaemonPeerAuthorizationPolicy
	evidenceDir string

	// Routing indexes are published under mu. routeIndex resolves immutable
	// route pointers; mutable ProcessTreeScope state is protected by each
	// route's own mutex. fallbackRoutes is copy-on-write and contains only
	// zero-cgroup test/replay scopes, since nonzero scopes reject cgroup escape.
	// Lock order is lifecycleDropMu -> mu -> sessionRoute.mu.
	mu             sync.RWMutex
	cgroupIndex    map[uint64]string
	treeScopes     map[string]*kernelcapture.ProcessTreeScope
	correlators    map[string]*kernelcapture.Correlator
	routeIndex     map[string]*sessionRoute
	fallbackRoutes []*sessionRoute

	// enforce_events state, maintained under mu (session-scoped) plus two
	// daemon-lifetime singletons for events that cannot be attributed to any
	// session (enforceOrphanChain/enforceOrphanSummary; see daemon_enforce.go).
	enforceChains        map[string]*kernelcapture.EnforceReceiptChain
	enforceSummaries     map[string]*kernelcapture.EnforceEventSummaryAccumulator
	enforceOrphanChain   *kernelcapture.EnforceReceiptChain
	enforceOrphanSummary *kernelcapture.EnforceEventSummaryAccumulator
	// lifecycleCaptureSummaries retain daemon-global exec/exit capture gaps for
	// every session that was active when each gap occurred. lossEpoch is a
	// daemon-lifetime monotonic identifier shared by all affected sessions.
	lifecycleCaptureSummaries map[string]*kernelcapture.LifecycleCaptureSummaryAccumulator
	lifecycleCaptureLossEpoch uint64
	// lifecycleDropMu protects daemon-lifetime producer-drop baselining. The
	// source is installed by the Linux lifecycle consumer and sampled at event
	// and session boundaries so final drops do not need a later valid event.
	// Code that needs both locks must acquire lifecycleDropMu before d.mu.
	lifecycleDropMu          sync.Mutex
	lifecycleDropTotal       func() (uint64, bool)
	lifecycleDropLast        uint64
	lifecycleDropBaselineSet bool
	lifecycleDropReadFailed  bool
	lifecycleDropSourceGone  bool
	// lifecycleFilter owns the process-exec producer allowlist. It has its own
	// lock because map updates must not run under routing or policy-map locks.
	lifecycleFilter *lifecycleFilterManager

	// OS filesystem for JSONL append (interface for test injection).
	fs evidenceFS

	// policyMaps holds the writable BPF map handles for the process_guard
	// enforcement program. On non-Linux platforms PolicyMaps is a zero struct and
	// ApplyPolicyMaps / RemovePolicyMaps return an error immediately.
	policyMaps kernelcapture.PolicyMaps

	// tamperChain hash-chains every tamper-audit tick (see daemon_guard_linux.go
	// on Linux); nil until the guard has loaded at least once. expectedKillSwitchEngaged
	// tracks what the daemon itself last set via set_kill_switch (or apply_policy's
	// degraded path never engages it), so a self-audit tick can tell a legitimate
	// state change from external tampering.
	tamperChain               *kernelcapture.TamperReceiptChain
	expectedKillSwitchEngaged bool
	// tamperWriteMu serializes the live-state snapshot, kill-switch mutation,
	// transactional chain append, and JSONL write. This keeps audit ticks from
	// observing a new map state before its attributed change receipt and keeps
	// the on-disk line order identical to Seq order. Distinct from applyMu: a
	// kill-switch change holds applyMu (a map mutation) but audit ticks do not,
	// so applyMu cannot serialize both evidence writers.
	tamperWriteMu sync.Mutex

	// seccompPolicy holds the seccomp tier's OP_NET_CONNECT policy (plan
	// E4) — always kept in sync by handleApplyPolicy regardless of which
	// tier is active, so a session's policy is already in place by the time
	// (if ever) a seccomp listener attaches for it. Non-nil on every
	// platform; on non-Linux it simply never gets a listener to serve.
	seccompPolicy *kernelcapture.SeccompPolicyStore
	// seccompListeners tracks the cancel func for each session's seccomp
	// supervisor goroutine (Linux only; always empty elsewhere), keyed by
	// session_id and guarded by mu like the other session-scoped maps above.
	seccompListeners map[string]context.CancelFunc

	// activeTier is decided once at startup (see main(): "prefer BPF-LSM
	// when active, fall back to seccomp when it isn't") and advertised on
	// health responses so a launcher can decide whether routing a governed
	// process through ardur-exec-shim (the seccomp tier's on-ramp) is
	// necessary at all. One of the daemonTier* constants.
	//
	// Not just startup-once, though: if the BPF-LSM guard consumer exits
	// mid-run (issue #121 — e.g. the ringbuf closes because the guard was
	// force-detached externally, or a real error), degradeGuardTier moves
	// this back to daemonTierNone so health never keeps advertising bpf_lsm
	// once nothing is actually attached. Read/write only via getActiveTier /
	// setActiveTier, which take mu — this field is written from the guard
	// goroutine and read from every socket-handling goroutine concurrently.
	activeTier string

	// applyMu serializes every BPF policy-map mutation — ApplyPolicyMaps,
	// RemovePolicyMaps, SetKillSwitch. Those run in per-connection goroutines
	// (and RemovePolicyMaps also on session-end), and ApplyPolicyMaps' double
	// buffer is a read-active-slot / write-inactive-slot / flip sequence that is
	// only atomic if writers are serialized. Distinct from mu (routing index).
	applyMu sync.Mutex

	// appliedAllow tracks, per session, the path/net allowlist entries most
	// recently written to the (non-double-buffered) cgroup_file_allow /
	// cgroup_net_allow maps, so a re-apply that drops an entry can delete the
	// stale one and session end can release them all. Guarded by mu.
	appliedAllow map[string]*appliedAllowRecord

	// cgroupVerifier gates register_session on the peer owning the claimed
	// cgroup/root_pid. Injected so tests (which register synthetic PIDs) can
	// substitute a no-op; production wires verifyRegisterSessionCgroup.
	cgroupVerifier func(kernelcapture.DaemonProtocolPeerHandshake, *kernelcapture.DaemonRegisterSessionRequest, *slog.Logger) error
}

// appliedAllowRecord is the last allowlist set written for a session.
type appliedAllowRecord struct {
	cgroupID uint64
	paths    map[string]struct{}
	nets     map[string]struct{}
}

type lifecycleCaptureLossKind uint8

const (
	lifecycleCaptureLossGeneric lifecycleCaptureLossKind = iota
	lifecycleCaptureLossMalformed
	lifecycleCaptureLossProducer
)

const (
	daemonTierNone    = "none"
	daemonTierBPFLSM  = "bpf_lsm"
	daemonTierSeccomp = "seccomp"
)

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
		log:                       log,
		registry:                  registry,
		custodyPlan:               custodyPlan,
		peerPolicy:                peerPolicy,
		evidenceDir:               evidenceDir,
		cgroupIndex:               make(map[uint64]string),
		treeScopes:                make(map[string]*kernelcapture.ProcessTreeScope),
		correlators:               make(map[string]*kernelcapture.Correlator),
		routeIndex:                make(map[string]*sessionRoute),
		enforceChains:             make(map[string]*kernelcapture.EnforceReceiptChain),
		enforceSummaries:          make(map[string]*kernelcapture.EnforceEventSummaryAccumulator),
		enforceOrphanChain:        kernelcapture.NewEnforceReceiptChain(),
		enforceOrphanSummary:      kernelcapture.NewEnforceEventSummaryAccumulator(),
		lifecycleCaptureSummaries: make(map[string]*kernelcapture.LifecycleCaptureSummaryAccumulator),
		lifecycleFilter:           newLifecycleFilterManager(),
		fs:                        osEvidenceFS{},
		tamperChain:               kernelcapture.NewTamperReceiptChain(),
		seccompPolicy:             kernelcapture.NewSeccompPolicyStore(),
		seccompListeners:          make(map[string]context.CancelFunc),
		activeTier:                daemonTierNone,
		appliedAllow:              make(map[string]*appliedAllowRecord),
		cgroupVerifier:            verifyRegisterSessionCgroup,
	}, nil
}

// registerSeccompListener records that sessionID now has a live seccomp
// supervisor, returning false (without recording anything) if one is already
// registered — callers must treat false as "reject this handoff," not as a
// signal to replace the existing listener.
func (d *daemon) registerSeccompListener(sessionID string, cancel context.CancelFunc) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.seccompListeners[sessionID]; exists {
		return false
	}
	d.seccompListeners[sessionID] = cancel
	return true
}

// unregisterSeccompListener stops (if still running) and forgets sessionID's
// seccomp supervisor. Safe to call even if no listener was ever registered.
func (d *daemon) unregisterSeccompListener(sessionID string) {
	d.mu.Lock()
	cancel, ok := d.seccompListeners[sessionID]
	delete(d.seccompListeners, sessionID)
	d.mu.Unlock()
	if ok && cancel != nil {
		cancel()
	}
}

// seccompListenerAttached reports whether sessionID currently has a live
// seccomp supervisor goroutine — i.e. whether some ardur-exec-shim's handoff
// for it has actually completed (registerSeccompListener succeeded) and
// hasn't since torn down (session end, listener error, daemon shutdown).
// Backs DaemonProtocolResponse.SeccompListenerAttached on session_status
// (issue #104: apply_policy succeeding is not proof of this).
func (d *daemon) seccompListenerAttached(sessionID string) bool {
	if sessionID == "" {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.seccompListeners[sessionID]
	return ok
}

// handleAuthorizedRequest is the DaemonAuthorizedProtocolHandler wired into the
// socket server. It delegates to the registry and maintains the cgroup routing
// index as a side effect of successful register/end-session responses.
func (d *daemon) handleAuthorizedRequest(ctx context.Context, req kernelcapture.DaemonProtocolRequest, handshake kernelcapture.DaemonProtocolPeerHandshake) kernelcapture.DaemonProtocolResponse {
	// apply_policy and set_kill_switch are handled locally — the registry has
	// no BPF awareness. Both take the peer handshake so they can enforce
	// per-session ownership (apply_policy) / admin identity (set_kill_switch)
	// rather than trusting any authorized-UID peer with a client-supplied
	// session_id or the global kill switch.
	switch req.Method {
	case kernelcapture.DaemonProtocolMethodApplyPolicy:
		return d.handleApplyPolicy(req, handshake)
	case kernelcapture.DaemonProtocolMethodSetKillSwitch:
		return d.handleSetKillSwitch(req, handshake)
	}

	// register_session binds a client-supplied cgroup_id (and root_pid) to a
	// session; apply_policy later writes BPF enforcement to that cgroup. Verify
	// the claim is one the peer legitimately owns before the registry accepts
	// it, so a peer cannot register (and then govern/tamper) a cgroup belonging
	// to another workload.
	lifecycleFilterAdded := false
	if req.Method == kernelcapture.DaemonProtocolMethodRegisterSession && req.RegisterSession != nil {
		if err := d.cgroupVerifier(handshake, req.RegisterSession, d.log); err != nil {
			return kernelcapture.DaemonProtocolResponse{
				ProtocolVersion: kernelcapture.DaemonProtocolVersion,
				Method:          req.Method,
				SessionID:       req.RegisterSession.SessionID,
				OK:              false,
				Error:           fmt.Sprintf("register_session cgroup ownership check failed: %v", err),
			}
		}
		// #119 collision guard: even a claim that passes ownership verification
		// must not be allowed to bind a cgroup_id that another live session
		// already holds — two sessions must never be able to govern the same
		// cgroup concurrently. See checkCgroupCollision's doc comment for the
		// residual race this does not fully close.
		if err := d.checkCgroupCollision(req.RegisterSession); err != nil {
			return kernelcapture.DaemonProtocolResponse{
				ProtocolVersion: kernelcapture.DaemonProtocolVersion,
				Method:          req.Method,
				SessionID:       req.RegisterSession.SessionID,
				OK:              false,
				Error:           fmt.Sprintf("register_session cgroup collision check failed: %v", err),
			}
		}
		var err error
		lifecycleFilterAdded, err = d.lifecycleFilter.prepare(ctx, req.RegisterSession.SessionID, req.RegisterSession.CgroupID)
		if err != nil {
			return kernelcapture.DaemonProtocolResponse{
				ProtocolVersion: kernelcapture.DaemonProtocolVersion,
				Method:          req.Method,
				SessionID:       req.RegisterSession.SessionID,
				OK:              false,
				Error:           fmt.Sprintf("register_session lifecycle cgroup filter failed: %v", err),
			}
		}
	}

	resp := d.registry.HandleAuthorizedRequest(ctx, req, handshake)
	if !resp.OK {
		if lifecycleFilterAdded {
			if err := d.lifecycleFilter.remove(req.RegisterSession.SessionID); err != nil {
				d.log.Warn("roll back lifecycle cgroup filter after rejected registration",
					"session_id", req.RegisterSession.SessionID, "error", err)
			}
		}
		return resp
	}
	switch req.Method {
	case kernelcapture.DaemonProtocolMethodRegisterSession:
		if req.RegisterSession != nil {
			d.sampleLifecycleProducerLoss()
			d.onSessionRegistered(req.RegisterSession, resp.SessionID)
			d.sampleLifecycleProducerLoss()
		}
	case kernelcapture.DaemonProtocolMethodEndSession:
		if sessionID := req.EndSession; sessionID != nil {
			d.sampleLifecycleProducerLoss()
			if summary, ok := d.lifecycleCaptureSummaryForSession(sessionID.SessionID); ok {
				resp.LifecycleCapture = &summary
			}
			d.onSessionEnded(sessionID.SessionID)
		}
	case kernelcapture.DaemonProtocolMethodSessionStatus:
		d.sampleLifecycleProducerLoss()
		if summary, ok := d.enforceSummaryForScope(resp.SessionID); ok {
			resp.Enforcement = &summary
		}
		if summary, ok := d.lifecycleCaptureSummaryForSession(resp.SessionID); ok {
			resp.LifecycleCapture = &summary
		}
		resp.SeccompListenerAttached = d.seccompListenerAttached(resp.SessionID)
	case kernelcapture.DaemonProtocolMethodHealth:
		// Advertise which enforcement tier is live so a launcher can decide
		// whether routing a governed process through ardur-exec-shim (the
		// seccomp tier's on-ramp) is necessary before it ever spawns one.
		resp.EnforcementTier = d.enforcementTier()
	}
	return resp
}

// enforcementTier reports which kernel-enforcement backend is currently live —
// EnforcementTierBPFLSM, daemonTierSeccomp, or EnforcementTierNone.
//
// The authoritative source is activeTier, which main()'s startup tier selection
// sets to bpf_lsm, seccomp, or none (E4 added the seccomp fallback; a plain
// PolicyMapsReady probe can't tell seccomp from none, since the seccomp tier
// holds no BPF policy maps). When activeTier hasn't been decided yet — the
// zero value or the daemonTierNone default, e.g. a unit test that populates
// policyMaps directly without going through startup — fall back to a live
// policyMaps probe so a loaded guard still reports bpf_lsm. In real runtime
// activeTier is set to bpf_lsm exactly when the maps load, so the two never
// disagree there; the fallback only matters for that bypass path.
func (d *daemon) enforcementTier() string {
	if tier := d.getActiveTier(); tier != "" && tier != daemonTierNone {
		return tier
	}
	if kernelcapture.PolicyMapsReady(d.policyMaps) {
		return kernelcapture.EnforcementTierBPFLSM
	}
	return kernelcapture.EnforcementTierNone
}

// getActiveTier returns the current activeTier under mu. See activeTier's
// doc comment: this is read from every socket-handling goroutine and written
// from both main()'s startup tier selection and degradeGuardTier.
func (d *daemon) getActiveTier() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.activeTier
}

// setActiveTier atomically updates activeTier under mu.
func (d *daemon) setActiveTier(tier string) {
	d.mu.Lock()
	d.activeTier = tier
	d.mu.Unlock()
}

// degradeGuardTier handles the guard consumer goroutine returning while ctx
// is still live — i.e. NOT normal shutdown (issue #121).
//
// This fires for two distinct causes, both of which mean the same thing to a
// health caller: process_guard is no longer attached and enforce_events is no
// longer flowing. (a) cause != nil: a real read/decode failure. (b) cause ==
// nil: consumeEnforceEvents returned via a clean io.EOF, which
// ringbufEnforceEventReader also produces when the ringbuf was closed for a
// reason OTHER than this daemon's own ctx-cancellation watcher — e.g. the
// guard was force-detached externally (bpftool link detach, or the same
// external-tamper class RunTamperAudit checks for on its own timer). Either
// way, d.policyMaps was already cleared to its zero value by runGuardConsumer's
// defer by the time this runs; activeTier must not keep claiming bpf_lsm past
// that point.
//
// No-op if activeTier was never actually bpf_lsm — covers the startup-load-
// failure case, where runGuardConsumer returns immediately (before this
// goroutine's caller's ready-channel select has run) and there is nothing to
// degrade from.
//
// Deliberately does not attempt to stand up the seccomp fallback tier
// retroactively: that tier's supervisor goroutine and socket lifecycle are
// wired only at startup (main()'s "if activeTier != bpf_lsm" branch), and
// retrofitting a second start site here would need its own careful
// wg/cancellation handling for a case that is already rare and already
// correctly reported once this function returns. Loudly signalling the true
// (degraded) tier — never silently keeping a stale bpf_lsm claim alive — is
// the fix; auto-failover is a larger, separate change.
func (d *daemon) degradeGuardTier(cause error, log *slog.Logger) {
	previous := d.getActiveTier()
	if previous != daemonTierBPFLSM {
		return
	}
	d.setActiveTier(daemonTierNone)

	detail := fmt.Sprintf(
		"guard consumer exited while the daemon is still running; enforcement tier downgraded from %q to %q",
		previous, daemonTierNone,
	)
	if cause != nil {
		detail = fmt.Sprintf("%s: %v", detail, cause)
	}
	log.Error("BPF-LSM guard consumer exited mid-run: enforcement tier degraded", "cause", cause, "previous_tier", previous)
	d.recordTamperAudit(kernelcapture.TamperAuditResult{
		CheckedAt: time.Now().UTC(),
		Drift:     true,
		Checks: []kernelcapture.TamperCheckResult{{
			Name:   "guard_consumer",
			OK:     false,
			Detail: detail,
		}},
	}, log)
}

// handleApplyPolicy validates the session, resolves its cgroup_id, and writes
// the policy into the BPF enforcement maps.
func (d *daemon) handleApplyPolicy(req kernelcapture.DaemonProtocolRequest, handshake kernelcapture.DaemonProtocolPeerHandshake) kernelcapture.DaemonProtocolResponse {
	ap := req.ApplyPolicy
	errResp := func(msg string) kernelcapture.DaemonProtocolResponse {
		return kernelcapture.DaemonProtocolResponse{
			ProtocolVersion: kernelcapture.DaemonProtocolVersion,
			Method:          kernelcapture.DaemonProtocolMethodApplyPolicy,
			OK:              false,
			Error:           msg,
		}
	}

	// Ownership gate: only the peer that registered this session may rewrite its
	// policy — mirrors end_session/session_status. Without this, any authorized-
	// UID peer could apply policy to a session (and thus a cgroup) it does not
	// own, including neutralizing another workload's enforcement or a sandboxed
	// process disabling its own.
	record, err := d.registry.ActiveSessionForPeer(ap.SessionID, handshake)
	if err != nil {
		return errResp(fmt.Sprintf("session not found, not active, or not owned by this peer: %v", err))
	}

	// Serialize all BPF policy-map mutations so a concurrent apply/remove for the
	// same cgroup cannot interleave the double-buffer slot read-modify-write.
	d.applyMu.Lock()
	defer d.applyMu.Unlock()
	if record.CgroupID == 0 {
		return errResp("session has no cgroup_id; cannot apply BPF policy")
	}

	// Always keep the seccomp tier's in-memory policy in sync, regardless of
	// which tier (if any) is actually active on this host: a session's
	// policy must already be in place by the time — if ever — an
	// ardur-exec-shim hands off a listener for it, and apply_policy commonly
	// runs before that handoff. This can only fail on malformed net_allow
	// entries (the same CIDR-or-bare-IP acceptance ApplyPolicyMaps' LPM key
	// builder uses), so failing here before any BPF map write is strictly
	// better than discovering the same bad input deeper in ApplyPolicyMaps.
	if err := kernelcapture.ApplySeccompPolicy(d.seccompPolicy, ap.SessionID, *ap); err != nil {
		d.log.Error("apply_policy failed (seccomp tier policy)", "session_id", ap.SessionID, "error", err)
		return errResp(fmt.Sprintf("apply seccomp policy: %v", err))
	}

	if err := kernelcapture.ApplyPolicyMaps(d.policyMaps, record.CgroupID, *ap); err != nil {
		if errors.Is(err, kernelcapture.ErrPolicyMapsUnavailable) {
			if d.getActiveTier() == daemonTierSeccomp && seccompFullyCoversPolicy(ap) {
				// BPF-LSM being unavailable isn't a degradation here: the
				// active tier on this host is seccomp user-notify, and every
				// op this request asks for (OP_NET_CONNECT only) is within
				// that tier's scope — ApplySeccompPolicy above already
				// stored it, so this genuinely is applied, not degraded.
				d.log.Info("apply_policy applied via seccomp tier (BPF-LSM inactive on this host)",
					"session_id", ap.SessionID, "cgroup_id", record.CgroupID)
				return kernelcapture.DaemonProtocolResponse{
					ProtocolVersion: kernelcapture.DaemonProtocolVersion,
					Method:          kernelcapture.DaemonProtocolMethodApplyPolicy,
					OK:              true,
					SessionID:       ap.SessionID,
					Status:          "applied_seccomp_tier",
				}
			}
			if ap.EnforceMode != kernelcapture.BpfEnforceModeEnforce {
				// Permissive mode: the whole point of PERMISSIVE is "log,
				// don't block". Treat a missing BPF-LSM guard (with no
				// seccomp fallback covering this request) the same way —
				// record the degradation loudly but don't fail the
				// caller's request.
				d.log.Warn("apply_policy degraded: BPF-LSM guard unavailable, enforcement not active for this session",
					"session_id", ap.SessionID, "cgroup_id", record.CgroupID)
				return kernelcapture.DaemonProtocolResponse{
					ProtocolVersion: kernelcapture.DaemonProtocolVersion,
					Method:          kernelcapture.DaemonProtocolMethodApplyPolicy,
					OK:              true,
					SessionID:       ap.SessionID,
					Status:          "degraded_no_enforcement",
				}
			}
		}
		// ENFORCE_STRICT (or any other failure): fail loudly. Silently
		// accepting a policy that can never be enforced is worse than
		// refusing it — the caller must know enforcement is not active.
		d.log.Error("apply_policy failed", "session_id", ap.SessionID, "cgroup_id", record.CgroupID, "error", err)
		return errResp(fmt.Sprintf("apply policy maps: %v", err))
	}

	// Revoke any allowlist entries this session had that the new policy drops,
	// and record the new set. Runs only on the BPF-write success path (the
	// degraded/seccomp returns above never reach the cgroup_file_allow /
	// cgroup_net_allow maps). Under applyMu, so serialized with other applies.
	d.pruneAndRecordAllowlists(ap.SessionID, record.CgroupID, ap.PathAllow, ap.NetAllow)

	d.log.Info("policy applied",
		"session_id", ap.SessionID,
		"cgroup_id", record.CgroupID,
		"generation", ap.Generation,
		"op_policies", len(ap.OpPolicies),
		"path_allow", len(ap.PathAllow),
		"net_allow", len(ap.NetAllow),
	)
	return kernelcapture.DaemonProtocolResponse{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodApplyPolicy,
		OK:              true,
		SessionID:       ap.SessionID,
	}
}

// pruneAndRecordAllowlists deletes the path/net allowlist entries this session
// previously wrote that are absent from the new set (revoking them from the BPF
// maps, which — unlike op_policy — are not double-buffered and would otherwise
// keep a dropped path/host allowed), then records the new set. Caller holds
// applyMu; this briefly takes mu for the appliedAllow map.
func (d *daemon) pruneAndRecordAllowlists(sessionID string, cgroupID uint64, newPaths, newNets []string) {
	newPathSet := stringSet(newPaths)
	newNetSet := stringSet(newNets)

	d.mu.Lock()
	prev := d.appliedAllow[sessionID]
	d.mu.Unlock()

	var stalePaths, staleNets []string
	if prev != nil {
		for p := range prev.paths {
			if _, keep := newPathSet[p]; !keep {
				stalePaths = append(stalePaths, p)
			}
		}
		for n := range prev.nets {
			if _, keep := newNetSet[n]; !keep {
				staleNets = append(staleNets, n)
			}
		}
	}
	if len(stalePaths) > 0 || len(staleNets) > 0 {
		if err := kernelcapture.DeleteAllowlistEntries(d.policyMaps, cgroupID, stalePaths, staleNets); err != nil {
			d.log.Warn("prune stale allowlist entries on re-apply",
				"session_id", sessionID, "cgroup_id", cgroupID, "error", err)
		}
	}

	d.mu.Lock()
	d.appliedAllow[sessionID] = &appliedAllowRecord{cgroupID: cgroupID, paths: newPathSet, nets: newNetSet}
	d.mu.Unlock()
}

// stringSet builds a set from a slice, ignoring empties.
func stringSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, it := range items {
		if it != "" {
			set[it] = struct{}{}
		}
	}
	return set
}

// setKeys returns a set's members as a slice.
func setKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

// seccompFullyCoversPolicy reports whether every op an apply_policy request
// asks for is within the seccomp tier's scope — OP_NET_CONNECT only (see
// seccomp_policy.go's header comment for why exec/file-open aren't). An
// empty OpPolicies list is trivially covered: there is nothing to enforce
// either way.
func seccompFullyCoversPolicy(ap *kernelcapture.DaemonApplyPolicyRequest) bool {
	for _, p := range ap.OpPolicies {
		if p.Op != kernelcapture.BpfOpNetConnect {
			return false
		}
	}
	return true
}

// handleSetKillSwitch engages or disengages the global BPF-LSM kill switch.
// Unlike apply_policy, a missing guard is always a hard failure here: there
// is no "degraded" reading of "the caller asked to change enforcement state
// and nothing happened" — the caller must know the call had no effect.
//
// The kill switch is GLOBAL and fail-open (engaged ⇒ every op passes on every
// governed cgroup), so it is gated to an admin identity — a UID-0 (root) peer —
// rather than any UID on the socket's allowlist. A non-root allowed peer (e.g.
// the very workload being sandboxed, which typically shares the launching UID)
// must not be able to disable enforcement host-wide.
func (d *daemon) handleSetKillSwitch(req kernelcapture.DaemonProtocolRequest, handshake kernelcapture.DaemonProtocolPeerHandshake) kernelcapture.DaemonProtocolResponse {
	if handshake.Authorization.UID != 0 {
		d.log.Warn("set_kill_switch denied: caller is not root",
			"peer_uid", handshake.Authorization.UID, "peer_pid", handshake.Authorization.PID, "engaged", req.SetKillSwitch != nil && req.SetKillSwitch.Engaged)
		return kernelcapture.DaemonProtocolResponse{
			ProtocolVersion: kernelcapture.DaemonProtocolVersion,
			Method:          kernelcapture.DaemonProtocolMethodSetKillSwitch,
			OK:              false,
			Error:           "set_kill_switch requires an admin (uid 0) peer; the global kill switch is not delegable to non-root callers",
		}
	}
	d.applyMu.Lock()
	defer d.applyMu.Unlock()
	d.tamperWriteMu.Lock()
	defer d.tamperWriteMu.Unlock()
	sw := req.SetKillSwitch
	prior := d.expectedKillSwitch()
	if err := kernelcapture.SetKillSwitch(d.policyMaps, sw.Engaged); err != nil {
		d.log.Error("set_kill_switch failed", "engaged", sw.Engaged, "error", err)
		return kernelcapture.DaemonProtocolResponse{
			ProtocolVersion: kernelcapture.DaemonProtocolVersion,
			Method:          kernelcapture.DaemonProtocolMethodSetKillSwitch,
			OK:              false,
			Error:           fmt.Sprintf("set kill switch: %v", err),
		}
	}
	if prior == sw.Engaged {
		d.log.Info("kill switch already in requested state", "engaged", sw.Engaged,
			"peer_uid", handshake.Authorization.UID, "peer_pid", handshake.Authorization.PID)
		return kernelcapture.DaemonProtocolResponse{
			ProtocolVersion: kernelcapture.DaemonProtocolVersion,
			Method:          kernelcapture.DaemonProtocolMethodSetKillSwitch,
			OK:              true,
		}
	}
	// Record the transition as an attributed, hash-chained tamper receipt (#123)
	// BEFORE returning OK, so a caller that sees success can rely on the change
	// having been committed to the evidence stream, not just the kernel map.
	finalized, err := d.recordKillSwitchChangeLocked(prior, sw.Engaged, handshake.Authorization)
	if err != nil {
		rollbackErr := kernelcapture.SetKillSwitch(d.policyMaps, prior)
		if rollbackErr != nil {
			d.mu.Lock()
			d.expectedKillSwitchEngaged = sw.Engaged
			for _, summary := range d.enforceSummaries {
				summary.RecordKillSwitchEvidenceGap(sw.Engaged)
			}
			d.mu.Unlock()
			d.log.Error("kill switch changed without durable evidence and rollback failed",
				"engaged", sw.Engaged, "prior", prior, "evidence_error", err,
				"rollback_error", rollbackErr, "peer_uid", handshake.Authorization.UID,
				"peer_pid", handshake.Authorization.PID)
			return kernelcapture.DaemonProtocolResponse{
				ProtocolVersion: kernelcapture.DaemonProtocolVersion,
				Method:          kernelcapture.DaemonProtocolMethodSetKillSwitch,
				OK:              false,
				Error:           fmt.Sprintf("kill switch changed but evidence persistence failed and rollback failed; kernel state requires inspection: evidence=%v; rollback=%v", err, rollbackErr),
			}
		}
		d.mu.Lock()
		for _, summary := range d.enforceSummaries {
			summary.RecordKillSwitchEvidenceGap(false)
		}
		d.mu.Unlock()
		d.log.Error("kill switch evidence persistence failed; kernel state rolled back",
			"requested", sw.Engaged, "restored", prior, "error", err,
			"peer_uid", handshake.Authorization.UID, "peer_pid", handshake.Authorization.PID)
		return kernelcapture.DaemonProtocolResponse{
			ProtocolVersion: kernelcapture.DaemonProtocolVersion,
			Method:          kernelcapture.DaemonProtocolMethodSetKillSwitch,
			OK:              false,
			Error:           fmt.Sprintf("persist kill switch evidence: %v; kernel state restored to engaged=%v", err, prior),
		}
	}
	d.mu.Lock()
	d.expectedKillSwitchEngaged = sw.Engaged
	for _, summary := range d.enforceSummaries {
		summary.RecordKillSwitchChange(sw.Engaged)
	}
	d.mu.Unlock()
	d.log.Warn("kill switch changed", "engaged", sw.Engaged, "prior", prior,
		"tamper_seq", finalized.Seq, "peer_uid", handshake.Authorization.UID,
		"peer_pid", handshake.Authorization.PID)
	return kernelcapture.DaemonProtocolResponse{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodSetKillSwitch,
		OK:              true,
	}
}

// checkCgroupCollision (issue #119) rejects a register_session whose claimed
// cgroup_id is already bound to another live session, so two sessions can
// never claim enforcement authority over the same cgroup at once — even a
// claim that independently passes cgroupVerifier's ownership check. Platform-
// neutral: this is a plain index lookup, no /proc dependency, so it applies
// (and is tested) on every platform, unlike the Linux-only ownership check.
//
// Re-registering the SAME session_id against the SAME cgroup_id it already
// holds is not a collision (a client may legitimately retry register_session
// for its own session) and is allowed through.
//
// Residual race, accepted: there is a narrow window between this check and
// onSessionRegistered's index write (below) where two concurrent
// register_session calls for the identical cgroup_id could both pass this
// check before either commits. Closing that fully would require moving
// session admission under the same lock as the registry's own accept path —
// out of scope for this fix. cgroupVerifier's ownership check is the primary
// defense against the actual #119 threat (a peer cannot fabricate "root_pid
// is really a member of this cgroup"); this guard is defense-in-depth on top
// of that, not the last line, so the residual window is a low-severity gap
// between two requests that would BOTH have to already be making a
// legitimately-ownership-verified claim to the same cgroup — an unusual
// double-registration, not an unauthorized one.
func (d *daemon) checkCgroupCollision(reg *kernelcapture.DaemonRegisterSessionRequest) error {
	if reg == nil || reg.CgroupID == 0 {
		return nil
	}
	d.mu.RLock()
	existing, ok := d.cgroupIndex[reg.CgroupID]
	d.mu.RUnlock()
	if ok && existing != reg.SessionID {
		return fmt.Errorf("cgroup_id %d is already bound to session %q", reg.CgroupID, existing)
	}
	return nil
}

// onSessionRegistered adds the session to the cgroup routing index.
func (d *daemon) onSessionRegistered(reg *kernelcapture.DaemonRegisterSessionRequest, sessionID string) {
	if sessionID == "" || reg == nil {
		return
	}
	producerCounterGap := d.lifecycleProducerCounterEvidenceGapActive()
	d.tamperWriteMu.Lock()
	defer d.tamperWriteMu.Unlock()
	d.mu.Lock()

	if reg.CgroupID != 0 {
		d.cgroupIndex[reg.CgroupID] = sessionID
	}

	scope := kernelcapture.NewProcessTreeScope(reg.RootPID, reg.CgroupID)
	scope.SessionID = sessionID
	d.treeScopes[sessionID] = &scope

	correlator := kernelcapture.NewCorrelator(kernelcapture.CorrelatorOptions{
		Platform:         "linux",
		CaptureBackend:   "linux_ebpf",
		CorrelationGrace: 5 * time.Second,
		RestartGrace:     3 * time.Second,
	})
	d.correlators[sessionID] = correlator
	d.publishSessionRouteLocked(newSessionRoute(sessionID, &scope, correlator))
	d.enforceChains[sessionID] = kernelcapture.NewEnforceReceiptChain()
	summary := kernelcapture.NewEnforceEventSummaryAccumulator()
	lastTamperSeq, _ := d.tamperChain.Head()
	summary.InitializeTamperWindow(lastTamperSeq+1, d.expectedKillSwitchEngaged)
	d.enforceSummaries[sessionID] = summary
	captureSummary := kernelcapture.NewLifecycleCaptureSummaryAccumulator()
	if producerCounterGap {
		captureSummary.RecordProducerCounterEvidenceGap()
	}
	d.lifecycleCaptureSummaries[sessionID] = captureSummary

	d.log.Info("session registered",
		"session_id", sessionID,
		"root_pid", reg.RootPID,
		"cgroup_id", reg.CgroupID,
		"event_classes", reg.EventClasses,
		"ttl_s", reg.TTLSeconds,
	)
	d.mu.Unlock()

	// Close the transition window between the first counter-state snapshot and
	// publishing the new summary. A failure recorded before publication cannot
	// update this session, while a failure after publication will update it
	// under d.mu. This second snapshot covers the former case without reversing
	// the lifecycleDropMu -> d.mu lock order used by producer sampling.
	if !producerCounterGap && d.lifecycleProducerCounterEvidenceGapActive() {
		captureSummary.RecordProducerCounterEvidenceGap()
	}
}

// onSessionEnded removes the session from the routing index and clears BPF maps.
func (d *daemon) onSessionEnded(sessionID string) {
	if sessionID == "" {
		return
	}
	// applyMu is acquired OUTSIDE d.mu (same order as handleApplyPolicy/
	// handleSetKillSwitch) so the RemovePolicyMaps below is serialized against
	// concurrent apply_policy for the same cgroup, with no lock-order inversion.
	d.applyMu.Lock()
	defer d.applyMu.Unlock()
	d.mu.Lock()
	d.retireSessionRouteLocked(sessionID)

	// Best-effort: remove enforcement state from BPF maps — op_policy + managed
	// gate (keyed by the routing scope's cgroup), then the (non-double-buffered)
	// path/net allowlist entries this session applied, keyed by the cgroup they
	// were actually written under (tracked in appliedAllow), so they don't
	// linger allowed for a future session that reuses the cgroup id.
	prevAllow := d.appliedAllow[sessionID]
	if scope, ok := d.treeScopes[sessionID]; ok && scope.CgroupID != 0 {
		delete(d.cgroupIndex, scope.CgroupID)
		if err := kernelcapture.RemovePolicyMaps(d.policyMaps, scope.CgroupID); err != nil {
			d.log.Warn("remove policy maps on session end",
				"session_id", sessionID, "cgroup_id", scope.CgroupID, "error", err)
		}
	}
	if prevAllow != nil && prevAllow.cgroupID != 0 {
		if err := kernelcapture.DeleteAllowlistEntries(d.policyMaps, prevAllow.cgroupID, setKeys(prevAllow.paths), setKeys(prevAllow.nets)); err != nil {
			d.log.Warn("remove allowlist entries on session end",
				"session_id", sessionID, "cgroup_id", prevAllow.cgroupID, "error", err)
		}
	}
	delete(d.appliedAllow, sessionID)
	delete(d.treeScopes, sessionID)
	delete(d.correlators, sessionID)
	delete(d.enforceChains, sessionID)
	delete(d.enforceSummaries, sessionID)
	delete(d.lifecycleCaptureSummaries, sessionID)
	// Grab (and forget) the seccomp listener's cancel func here, under the
	// same lock as the map deletes above; call it below, outside the lock,
	// since the supervisor goroutine it stops may itself try to touch
	// d.mu-guarded state on its way out.
	seccompCancel, hadSeccompListener := d.seccompListeners[sessionID]
	delete(d.seccompListeners, sessionID)
	d.mu.Unlock()
	if err := d.lifecycleFilter.remove(sessionID); err != nil {
		d.log.Warn("remove lifecycle cgroup filter on session end",
			"session_id", sessionID, "error", err)
	}

	kernelcapture.RemoveSeccompPolicy(d.seccompPolicy, sessionID)
	if hadSeccompListener && seccompCancel != nil {
		seccompCancel()
	}

	d.log.Info("session ended", "session_id", sessionID)
}

// publishSessionRouteLocked publishes route while d.mu is held. The fallback
// snapshot is copy-on-write so event readers can use an old slice after
// releasing d.mu without racing registration or retirement.
func (d *daemon) publishSessionRouteLocked(route *sessionRoute) {
	if route == nil || route.sessionID == "" {
		return
	}
	d.retireSessionRouteLocked(route.sessionID)
	if d.routeIndex == nil {
		d.routeIndex = make(map[string]*sessionRoute)
	}
	d.routeIndex[route.sessionID] = route
	if route.scope != nil && route.scope.CgroupID == 0 {
		next := make([]*sessionRoute, len(d.fallbackRoutes)+1)
		copy(next, d.fallbackRoutes)
		next[len(d.fallbackRoutes)] = route
		d.fallbackRoutes = next
	}
}

// retireSessionRouteLocked marks one route inactive and removes it from future
// lookups while d.mu is held. Taking route.mu waits for an already-matched
// event to finish correlation and evidence append before teardown continues.
func (d *daemon) retireSessionRouteLocked(sessionID string) {
	route := d.routeIndex[sessionID]
	if route == nil {
		return
	}
	route.mu.Lock()
	route.active = false
	isFallback := route.scope != nil && route.scope.CgroupID == 0
	route.mu.Unlock()
	delete(d.routeIndex, sessionID)
	if !isFallback {
		return
	}
	next := make([]*sessionRoute, 0, len(d.fallbackRoutes)-1)
	for _, candidate := range d.fallbackRoutes {
		if candidate != route {
			next = append(next, candidate)
		}
	}
	d.fallbackRoutes = next
}

// lockRouteEvent finds and locks the route for evt. A non-nil result owns the
// route mutex; the caller must invoke route.unlock().
func (d *daemon) lockRouteEvent(evt *kernelcapture.ProcessEvent) *sessionRoute {
	if evt == nil {
		return nil
	}
	d.mu.RLock()
	var fastRoute *sessionRoute
	if evt.CgroupID != 0 {
		if sessionID, ok := d.cgroupIndex[evt.CgroupID]; ok {
			fastRoute = d.routeIndex[sessionID]
		}
	}
	fallbackRoutes := d.fallbackRoutes
	d.mu.RUnlock()

	if fastRoute != nil && fastRoute.lockIfMatches(evt) {
		return fastRoute
	}
	// Only zero-cgroup test/replay scopes can match outside the cgroup index.
	// Nonzero production scopes enforce exact cgroup equality in MatchesAndTrack.
	start := 0
	if len(fallbackRoutes) > 0 {
		start = int(evt.PID % uint32(len(fallbackRoutes)))
	}
	for offset := range fallbackRoutes {
		route := fallbackRoutes[(start+offset)%len(fallbackRoutes)]
		if route != fastRoute && route.lockIfMatches(evt) {
			return route
		}
	}
	return nil
}

// routeEvent is the lookup-only test seam. Production event processing uses
// lockRouteEvent directly and holds the route lease through evidence append.
func (d *daemon) routeEvent(evt *kernelcapture.ProcessEvent) (string, *kernelcapture.Correlator) {
	route := d.lockRouteEvent(evt)
	if route == nil {
		return "", nil
	}
	sessionID, correlator := route.sessionID, route.correlator
	route.unlock()
	return sessionID, correlator
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

// expectedKillSwitch returns the kill-switch state the daemon itself last
// set (via set_kill_switch), for a tamper-audit tick to compare the live map
// value against. Defaults to false (disengaged): a freshly loaded guard
// starts disengaged and no set_kill_switch call has happened yet.
func (d *daemon) expectedKillSwitch() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.expectedKillSwitchEngaged
}

// recordTamperAudit hash-chains one tamper-audit tick and appends it as a
// JSONL line to <evidenceDir>/_tamper/tamper_audit.jsonl. Every tick is
// chained and written regardless of Drift, so the chain itself is evidence
// that audits kept running — a gap in Seq is as suspicious as a drift entry.
func (d *daemon) recordTamperAudit(result kernelcapture.TamperAuditResult, log *slog.Logger) {
	d.tamperWriteMu.Lock()
	defer d.tamperWriteMu.Unlock()
	d.recordTamperAuditLocked(result, log)
}

// recordCurrentTamperAudit serializes the live-state snapshot with explicit
// kill-switch changes, so an audit tick cannot observe the new map state before
// its attributed change receipt is committed.
func (d *daemon) recordCurrentTamperAudit(auditor kernelcapture.GuardLinkAuditor, log *slog.Logger) {
	d.tamperWriteMu.Lock()
	defer d.tamperWriteMu.Unlock()
	d.recordTamperAuditLocked(kernelcapture.RunTamperAudit(auditor, d.expectedKillSwitch()), log)
}

func (d *daemon) recordTamperAuditLocked(result kernelcapture.TamperAuditResult, log *slog.Logger) {
	entry := kernelcapture.TamperReceiptEntry{
		SchemaVersion: kernelcapture.TamperReceiptSchema,
		RecordedAt:    time.Now().UTC(),
		Result:        result,
	}
	finalized, err := d.appendAndPersistTamperEntryLocked(entry)
	if err != nil {
		log.Warn("persist tamper audit receipt", "error", err)
		return
	}
	if result.Drift {
		log.Error("tamper audit detected drift", "seq", finalized.Seq, "checks", result.Checks)
	} else {
		log.Debug("tamper audit tick clean", "seq", finalized.Seq)
	}
}

// recordKillSwitchChangeLocked hash-chains one set_kill_switch state transition into
// the same tamper-evidence stream as the audit ticks (issue #123), attributed
// to the peer that requested it, so toggling the global fail-open kill switch
// leaves an offline-verifiable receipt instead of only a stderr line the next
// audit tick can't even see. handleSetKillSwitch holds tamperWriteMu across the
// map write and this call, and treats an error as a failed operation with a
// compensating map rollback.
func (d *daemon) recordKillSwitchChangeLocked(prior, engaged bool, actor kernelcapture.DaemonPeerAuthorization) (kernelcapture.TamperReceiptEntry, error) {
	now := time.Now().UTC()
	entry := kernelcapture.TamperReceiptEntry{
		SchemaVersion: kernelcapture.TamperReceiptSchema,
		RecordedAt:    now,
		KillSwitch: &kernelcapture.KillSwitchChangeEvent{
			ChangedAt:    now,
			PriorEngaged: prior,
			Engaged:      engaged,
			ActorUID:     actor.UID,
			ActorPID:     actor.PID,
		},
	}
	return d.appendAndPersistTamperEntryLocked(entry)
}

// appendAndPersistTamperEntryLocked assigns a sequence/hash and appends the
// JSONL line while tamperWriteMu is held. The chain commits only after the
// append succeeds, so a persistence failure cannot create a hidden sequence
// gap in the next successful on-disk entry.
func (d *daemon) appendAndPersistTamperEntryLocked(entry kernelcapture.TamperReceiptEntry) (kernelcapture.TamperReceiptEntry, error) {
	dir := filepath.Join(d.evidenceDir, "_tamper")
	path := filepath.Join(dir, "tamper_audit.jsonl")
	if err := prevalidateKernelReceiptAppendPath(d.fs, d.evidenceDir, dir, path); err != nil {
		return kernelcapture.TamperReceiptEntry{}, fmt.Errorf("prevalidate tamper receipt path %q: %w", path, err)
	}
	if err := d.fs.MkdirAll(dir, 0o700); err != nil {
		return kernelcapture.TamperReceiptEntry{}, fmt.Errorf("create tamper evidence directory %q: %w", dir, err)
	}
	return d.tamperChain.AppendPersisted(entry, func(finalized kernelcapture.TamperReceiptEntry) error {
		line, err := json.Marshal(finalized)
		if err != nil {
			return fmt.Errorf("marshal tamper receipt: %w", err)
		}
		line = append(line, '\n')
		if err := d.fs.AppendFile(path, line, 0o600); err != nil {
			return fmt.Errorf("append tamper receipt %q: %w", path, err)
		}
		return nil
	})
}

// processKernelEvent is called by the platform-specific event loop for each
// event that arrives from the eBPF ringbuf.
func (d *daemon) processKernelEvent(evt kernelcapture.ProcessEvent) {
	route := d.lockRouteEvent(&evt)
	if route == nil {
		return
	}
	defer route.unlock()
	if route.correlator == nil {
		return
	}
	sid, correlator := route.sessionID, route.correlator

	receipt := correlator.Correlate(evt, kernelcapture.EventContext{})

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

// recordLifecycleCaptureLoss records one daemon-global process lifecycle loss
// epoch against every session active at that instant. It deliberately does not
// attach host-global loss to a later event because session attribution would be
// arbitrary. The summaries remain available for every session_status response
// until the session ends.
func (d *daemon) recordLifecycleCaptureLoss(loss kernelcapture.CaptureLoss) uint64 {
	return d.recordLifecycleCaptureLossKind(loss, lifecycleCaptureLossGeneric)
}

func (d *daemon) recordLifecycleCaptureLossKind(loss kernelcapture.CaptureLoss, kind lifecycleCaptureLossKind) uint64 {
	if loss.RingbufDropped == 0 && loss.DaemonQueueDropped == 0 {
		return 0
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.lifecycleCaptureLossEpoch++
	epoch := d.lifecycleCaptureLossEpoch
	for _, summary := range d.lifecycleCaptureSummaries {
		switch kind {
		case lifecycleCaptureLossMalformed:
			summary.RecordMalformedRecord(epoch)
		case lifecycleCaptureLossProducer:
			summary.RecordProducerRingbufDropped(loss.RingbufDropped, epoch)
		default:
			summary.RecordLoss(loss, epoch)
		}
	}
	return epoch
}

func (d *daemon) recordMalformedLifecycleRecord() uint64 {
	return d.recordLifecycleCaptureLossKind(kernelcapture.CaptureLoss{RingbufDropped: 1}, lifecycleCaptureLossMalformed)
}

// setLifecycleDropCounter installs a daemon-lifetime monotonic producer-drop
// source and snapshots its current value. A nonzero inherited total is a prior
// lifetime baseline and is not replayed into current sessions.
func (d *daemon) setLifecycleDropCounter(source func() (uint64, bool)) {
	d.lifecycleDropMu.Lock()
	previousSourceInstalled := d.lifecycleDropTotal != nil
	d.lifecycleDropTotal = source
	d.lifecycleDropLast = 0
	d.lifecycleDropBaselineSet = false
	d.lifecycleDropReadFailed = false
	if source != nil {
		d.lifecycleDropSourceGone = false
	}
	var baseline uint64
	var baselineSet bool
	if source != nil {
		baseline, baselineSet = source()
		if baselineSet {
			d.lifecycleDropLast = baseline
			d.lifecycleDropBaselineSet = true
		} else {
			d.lifecycleDropReadFailed = true
		}
	}
	removedLiveSource := source == nil && previousSourceInstalled
	if removedLiveSource {
		d.lifecycleDropSourceGone = true
	}
	if (source != nil && !baselineSet) || removedLiveSource {
		d.recordLifecycleProducerCounterEvidenceGap()
	}
	d.lifecycleDropMu.Unlock()
	if baselineSet && baseline > 0 {
		d.log.Warn("lifecycle drop counter nonzero at consumer load (prior daemon lifetime; not replayed)",
			"kernel_dropped_total", baseline)
	}
	if source != nil && !baselineSet {
		d.log.Warn("lifecycle drop counter unavailable at consumer load; active sessions will carry an evidence gap")
	}
	if removedLiveSource {
		d.log.Warn("lifecycle drop counter source removed; active sessions will carry an evidence gap")
	}
}

func (d *daemon) lifecycleProducerCounterEvidenceGapActive() bool {
	d.lifecycleDropMu.Lock()
	defer d.lifecycleDropMu.Unlock()
	return d.lifecycleDropReadFailed || d.lifecycleDropSourceGone
}

// sampleLifecycleProducerLoss records newly observed in-kernel reservation
// failures against every currently active session. The first successful read is
// always a baseline, including after an initially unavailable counter.
func (d *daemon) sampleLifecycleProducerLoss() uint64 {
	d.lifecycleDropMu.Lock()
	if d.lifecycleDropTotal == nil {
		d.lifecycleDropMu.Unlock()
		return 0
	}
	total, ok := d.lifecycleDropTotal()
	if !ok {
		firstFailure := !d.lifecycleDropReadFailed
		d.lifecycleDropReadFailed = true
		d.recordLifecycleProducerCounterEvidenceGap()
		d.lifecycleDropMu.Unlock()
		if firstFailure {
			d.log.Warn("lifecycle drop counter read failed; capture completeness is unknown")
		}
		return 0
	}
	recovered := d.lifecycleDropReadFailed
	d.lifecycleDropReadFailed = false
	if !d.lifecycleDropBaselineSet {
		d.lifecycleDropLast = total
		d.lifecycleDropBaselineSet = true
		d.lifecycleDropMu.Unlock()
		if recovered {
			d.log.Info("lifecycle drop counter read recovered; current total established as a new baseline",
				"kernel_dropped_total", total)
		}
		return 0
	}
	if total < d.lifecycleDropLast {
		prior := d.lifecycleDropLast
		d.lifecycleDropLast = total
		d.recordLifecycleProducerCounterEvidenceGap()
		d.lifecycleDropMu.Unlock()
		d.log.Warn("lifecycle drop counter moved backwards; capture completeness is unknown",
			"prior_kernel_dropped_total", prior, "kernel_dropped_total", total)
		return 0
	}
	if total == d.lifecycleDropLast {
		d.lifecycleDropMu.Unlock()
		return 0
	}
	delta := total - d.lifecycleDropLast
	d.lifecycleDropLast = total
	epoch := d.recordLifecycleCaptureLossKind(kernelcapture.CaptureLoss{RingbufDropped: delta}, lifecycleCaptureLossProducer)
	d.lifecycleDropMu.Unlock()
	d.log.Warn("lifecycle ringbuf producer drops observed",
		"drop_count", delta, "kernel_dropped_total", total, "loss_epoch", epoch)
	return delta
}

func (d *daemon) recordLifecycleProducerCounterEvidenceGap() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, summary := range d.lifecycleCaptureSummaries {
		summary.RecordProducerCounterEvidenceGap()
	}
}

func (d *daemon) lifecycleCaptureSummaryForSession(sessionID string) (kernelcapture.LifecycleCaptureSummary, bool) {
	d.mu.RLock()
	summary, ok := d.lifecycleCaptureSummaries[sessionID]
	d.mu.RUnlock()
	if !ok || summary == nil {
		return kernelcapture.LifecycleCaptureSummary{}, false
	}
	return summary.Snapshot(), true
}

// pruneExpiredSessions removes sessions that the registry has expired so the
// cgroup index does not leak indefinitely.
func (d *daemon) pruneExpiredSessions() {
	type expiredPolicy struct {
		cgroupID uint64
		paths    []string
		nets     []string
	}
	d.mu.Lock()
	var expiredSeccompCancels []context.CancelFunc
	var expiredSessionIDs []string
	var expiredPolicies []expiredPolicy
	for sid, scope := range d.treeScopes {
		if _, err := d.registry.ActiveSession(sid); err != nil {
			d.retireSessionRouteLocked(sid)
			if scope.CgroupID != 0 {
				delete(d.cgroupIndex, scope.CgroupID)
				ep := expiredPolicy{cgroupID: scope.CgroupID}
				if prev := d.appliedAllow[sid]; prev != nil {
					ep.paths = setKeys(prev.paths)
					ep.nets = setKeys(prev.nets)
				}
				expiredPolicies = append(expiredPolicies, ep)
			}
			delete(d.appliedAllow, sid)
			delete(d.treeScopes, sid)
			delete(d.correlators, sid)
			delete(d.enforceChains, sid)
			delete(d.enforceSummaries, sid)
			delete(d.lifecycleCaptureSummaries, sid)
			if cancel, ok := d.seccompListeners[sid]; ok {
				expiredSeccompCancels = append(expiredSeccompCancels, cancel)
				delete(d.seccompListeners, sid)
			}
			expiredSessionIDs = append(expiredSessionIDs, sid)
			d.log.Info("pruned expired session", "session_id", sid)
		}
	}
	d.mu.Unlock()
	for _, sid := range expiredSessionIDs {
		if err := d.lifecycleFilter.remove(sid); err != nil {
			d.log.Warn("remove lifecycle cgroup filter on session expiry",
				"session_id", sid, "error", err)
		}
	}

	// Release BPF enforcement state for expired sessions (op_policy + managed
	// gate + allowlist entries), so a TTL-expired session's policy doesn't
	// linger in the kernel. applyMu is taken alone here (d.mu already released),
	// serializing with concurrent apply_policy.
	if len(expiredPolicies) > 0 {
		d.applyMu.Lock()
		for _, ep := range expiredPolicies {
			if err := kernelcapture.RemovePolicyMaps(d.policyMaps, ep.cgroupID); err != nil {
				d.log.Warn("remove policy maps on session expiry", "cgroup_id", ep.cgroupID, "error", err)
			}
			if len(ep.paths) > 0 || len(ep.nets) > 0 {
				if err := kernelcapture.DeleteAllowlistEntries(d.policyMaps, ep.cgroupID, ep.paths, ep.nets); err != nil {
					d.log.Warn("remove allowlist entries on session expiry", "cgroup_id", ep.cgroupID, "error", err)
				}
			}
		}
		d.applyMu.Unlock()
	}

	for _, sid := range expiredSessionIDs {
		kernelcapture.RemoveSeccompPolicy(d.seccompPolicy, sid)
	}
	for _, cancel := range expiredSeccompCancels {
		if cancel != nil {
			cancel()
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

func (osEvidenceFS) AppendFile(path string, data []byte, perm fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, perm)
	if err != nil {
		return err
	}
	start, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return errors.Join(err, f.Close())
	}
	rollback := func(cause error) error {
		truncateErr := f.Truncate(start)
		var syncErr error
		if truncateErr == nil {
			syncErr = f.Sync()
		}
		return errors.Join(cause, truncateErr, syncErr, f.Close())
	}
	written, err := f.Write(data)
	if err != nil {
		return rollback(err)
	}
	if written != len(data) {
		return rollback(io.ErrShortWrite)
	}
	if err := f.Sync(); err != nil {
		return rollback(err)
	}
	if err := f.Close(); err != nil {
		// A successful fsync committed the complete line, but report close
		// failure only after restoring the original append offset when possible.
		truncateErr := os.Truncate(path, start)
		return errors.Join(err, truncateErr)
	}
	return nil
}

func main() {
	var (
		socketPath        = flag.String("socket", defaultSocketPath, "Unix-domain control socket path")
		seccompSocketPath = flag.String("seccomp-socket", defaultSeccompSocketPath, "Unix-domain socket ardur-exec-shim hands off its seccomp listener fd on (seccomp tier, plan E4)")
		evidenceDir       = flag.String("evidence-dir", defaultEvidenceDir, "Directory for per-session kernel receipt JSONL logs")
		stateDir          = flag.String("state-dir", defaultStateDir, "Daemon state directory")
		noRingbuf         = flag.Bool("no-ringbuf", false, "Skip eBPF ringbuf consumer (socket control plane only)")
		disableBPFLSM     = flag.Bool("disable-bpf-lsm", false, "Skip the BPF-LSM guard tier and force the seccomp user-notify fallback, even on hosts where BPF-LSM is available. Exec/exit observation still runs; only the BPF-LSM enforcement tier is suppressed. Used to exercise the seccomp path where BPF-LSM would otherwise win tier selection.")
		debug             = flag.Bool("debug", false, "Enable debug-level logging")
		pruneEvery        = flag.Duration("prune-interval", 30*time.Second, "Interval to prune expired session routing entries")
		guardReadyTimeout = flag.Duration("guard-ready-timeout", 10*time.Second, "How long to wait for the BPF-LSM guard to report load success/failure before falling back to the seccomp tier")
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
	if *noRingbuf {
		d.lifecycleFilter.markUnavailable(errors.New("process lifecycle ringbuf disabled by --no-ringbuf"))
	}

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

	// Data-plane goroutine: eBPF exec/exit tracepoint ringbuf consumer, plus
	// tier selection (plan E4): prefer BPF-LSM when it actually loads, fall
	// back to seccomp user-notify otherwise. guardOutcome receives exactly
	// one value from runGuardConsumer — nil on a successful load, the load
	// error otherwise — before that goroutine does anything blocking, so
	// the decision below is made synchronously instead of inferred from
	// preflight (which can pass while the real load still fails for
	// reasons preflight doesn't check).
	//
	// Both kernel-enforcement mechanisms ride on the same --no-ringbuf
	// switch: it means "socket control plane only," so leaving it set
	// leaves activeTier at daemonTierNone rather than standing up a
	// seccomp handoff server nothing will ever mean to use.
	if !*noRingbuf {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runEBPFConsumer(ctx, d, log); err != nil {
				d.lifecycleFilter.markUnavailable(err)
				if ctx.Err() == nil {
					log.Error("eBPF consumer stopped", "error", err)
				}
			}
		}()

		// BPF-LSM enforcement consumer: loads process_guard, populates policyMaps.
		// Degrades gracefully on kernels without BPF-LSM (warn, not fatal).
		// Skipped entirely when --disable-bpf-lsm forces the seccomp tier.
		if !*disableBPFLSM {
			guardOutcome := make(chan error, 1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := runGuardConsumer(ctx, d, log, guardOutcome)
				if ctx.Err() != nil {
					return // normal shutdown
				}
				if err != nil {
					log.Warn("BPF-LSM guard unavailable (enforcement degraded to seccomp-advertised)",
						"error", err)
				}
				// Reached whether runGuardConsumer failed mid-run (err != nil)
				// or its ringbuf closed cleanly for a reason other than our
				// own shutdown watcher (err == nil — e.g. an external force-
				// detach); either way the guard is no longer attached. Issue
				// #121: never leave activeTier claiming bpf_lsm past this point.
				d.degradeGuardTier(err, log)
			}()

			select {
			case err := <-guardOutcome:
				if err == nil {
					d.setActiveTier(daemonTierBPFLSM)
				} else {
					log.Warn("BPF-LSM tier not active, falling back to seccomp tier", "error", err)
				}
			case <-time.After(*guardReadyTimeout):
				log.Warn("BPF-LSM guard did not report readiness in time, falling back to seccomp tier",
					"timeout", guardReadyTimeout.String())
			case <-ctx.Done():
			}
		} else {
			log.Warn("BPF-LSM guard tier disabled via --disable-bpf-lsm; forcing seccomp user-notify tier")
		}

		if d.getActiveTier() != daemonTierBPFLSM && ctx.Err() == nil {
			d.setActiveTier(daemonTierSeccomp)
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := runSeccompHandoffServer(ctx, *seccompSocketPath, d, log); err != nil && ctx.Err() == nil {
					log.Error("seccomp handoff server stopped", "error", err)
				}
			}()
		}
		log.Info("enforcement tier selected", "tier", d.getActiveTier(), "seccomp_socket", *seccompSocketPath)
	} else {
		log.Info("eBPF ringbuf consumers disabled (--no-ringbuf); enforcement tiers unavailable")
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
