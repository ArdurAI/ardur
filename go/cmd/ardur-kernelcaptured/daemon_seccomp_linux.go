//go:build linux

package main

// daemon_seccomp_linux.go — seccomp user-notify enforcement tier (Epic A
// #63, plan E4): the daemon side of the fd handoff from ardur-exec-shim, and
// the per-session supervisor that services connect(2) notifications.
//
// Claim boundary: this is the fallback tier for hosts where BPF-LSM never
// loads (stock distros that ship CONFIG_BPF_LSM=y but don't put "bpf" in the
// boot lsm= list — the common case this plan targets). See
// go/pkg/kernelcapture/seccomp_policy.go's header comment for the tier's
// scope (OP_NET_CONNECT only) and its documented weaker-than-BPF-LSM
// security claim against a racing multithreaded adversary.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
	"golang.org/x/sys/unix"
)

// seccompHandoffRequest is the JSON header ardur-exec-shim sends alongside
// the listener fd (as SCM_RIGHTS ancillary data) over the seccomp handoff
// socket. This is a distinct, minimal socket from the main JSON-line control
// plane (daemon_socket_server.go's DaemonUnixSocketServer) specifically
// because that server's request reader uses a plain byte-stream Read(),
// which silently discards ancillary data — retrofitting fd-passing onto it
// would risk the well-tested existing protocol path for a use case that
// touches it only once per governed session. Passing a real fd needs
// ReadMsgUnix with an out-of-band buffer, so this gets its own small,
// dedicated accept loop instead.
type seccompHandoffRequest struct {
	SessionID string `json:"session_id"`
}

type seccompHandoffResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type receivedSeccompListenerHandoff struct {
	sessionID     string
	fd            int
	observation   kernelcapture.DaemonSocketPeerObservation
	authorization kernelcapture.DaemonPeerAuthorization
}

const (
	seccompHandoffMaxHeaderBytes = 4096
	seccompHandoffReadTimeout    = 10 * time.Second
	// Linux caps one SCM_RIGHTS message at 253 descriptors. Receive enough
	// control space to inspect and close every descriptor before enforcing the
	// stricter Ardur contract of exactly one.
	seccompHandoffMaxReceivedFDs = 253
)

// runSeccompHandoffServer accepts ardur-exec-shim connections on socketPath,
// authorizes the peer with the same UID/GID policy as the main control
// socket, extracts the handed-off listener fd, and starts a supervisor
// goroutine for it. Returns when ctx is cancelled.
func runSeccompHandoffServer(ctx context.Context, socketPath string, d *daemon, log *slog.Logger) error {
	_ = os.Remove(socketPath)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return fmt.Errorf("create seccomp handoff socket directory: %w", err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("bind seccomp handoff socket: %w", err)
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		listener.Close()
		return fmt.Errorf("set seccomp handoff socket mode: %w", err)
	}
	defer func() {
		listener.Close()
		_ = os.Remove(socketPath)
	}()

	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stop:
		}
	}()
	defer close(stop)

	log.Info("seccomp handoff socket listening", "socket", socketPath)

	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("accept seccomp handoff connection: %w", err)
		}
		go d.handleSeccompHandoffConnection(ctx, conn, socketPath, log)
	}
}

func (d *daemon) handleSeccompHandoffConnection(ctx context.Context, conn *net.UnixConn, socketPath string, log *slog.Logger) {
	defer conn.Close()
	// Freeze register/end/expiry transitions from credential observation
	// through acknowledgment. The bounded read deadline below limits how long
	// even an authorized peer can retain this shared lifecycle lease.
	d.seccompSessionMu.RLock()
	defer d.seccompSessionMu.RUnlock()

	handoff, err := receiveSeccompListenerHandoff(conn, socketPath, d.peerPolicy)
	if err != nil {
		log.Warn("seccomp handoff rejected", "error", err)
		_ = sendSeccompHandoffResponse(conn, false, err.Error())
		return
	}
	sessionID := handoff.sessionID
	fd := handoff.fd

	record, err := d.registry.ActiveSessionForDelegatedRootPeer(sessionID, handoff.observation, handoff.authorization)
	if err != nil {
		log.Warn("seccomp handoff for unknown, inactive, or differently owned session", "session_id", sessionID, "error", err)
		_ = sendSeccompHandoffResponse(conn, false, "session not found or not active")
		unix.Close(fd)
		return
	}

	superviseCtx, cancel := context.WithCancel(ctx)
	if !d.registerSeccompListener(sessionID, record.RegistrationGeneration, cancel) {
		// A listener for this session is already being supervised — most
		// likely a retried handoff. Refuse the duplicate rather than run two
		// supervisors racing to answer the same notifications.
		log.Warn("seccomp handoff duplicate listener for session, closing new one", "session_id", sessionID)
		cancel()
		_ = sendSeccompHandoffResponse(conn, false, "a seccomp listener is already attached for this session")
		unix.Close(fd)
		return
	}
	// Close the lookup-to-insert race with end_session: if session end landed
	// before insertion, its cleanup could not see this listener. Revalidating
	// after insertion either rejects/removes that stale attach, or guarantees a
	// later end_session will observe and cancel the registered listener.
	if _, err := d.registry.ActiveSessionForDelegatedRootPeerGeneration(sessionID, handoff.observation, handoff.authorization, record.RegistrationGeneration); err != nil {
		log.Warn("seccomp handoff session ended, was replaced, or ownership changed during listener attachment", "session_id", sessionID, "error", err)
		d.unregisterSeccompListener(sessionID, record.RegistrationGeneration)
		_ = sendSeccompHandoffResponse(conn, false, "session not found or not active")
		unix.Close(fd)
		return
	}

	if err := sendSeccompHandoffResponse(conn, true, ""); err != nil {
		log.Warn("ack seccomp handoff", "session_id", sessionID, "error", err)
		d.unregisterSeccompListener(sessionID, record.RegistrationGeneration)
		cancel()
		unix.Close(fd)
		return
	}

	log.Info("seccomp connect-notify listener attached",
		"session_id", sessionID, "cgroup_id", record.CgroupID, "root_pid", record.RootPID)
	go func() {
		defer d.unregisterSeccompListener(sessionID, record.RegistrationGeneration)
		defer unix.Close(fd)
		superviseSeccompListener(superviseCtx, fd, sessionID, record.RegistrationGeneration, record.CgroupID, d, log)
	}()
}

// receiveSeccompListenerHandoff reads the JSON header + ancillary listener fd
// from one shim connection, authorizing the peer first via the same
// SO_PEERCRED + UID/GID policy the main control socket uses. On any error the
// received fd (if one was successfully parsed before the error) is closed —
// callers must not assume the fd is still open after a non-nil error.
func receiveSeccompListenerHandoff(conn *net.UnixConn, socketPath string, policy kernelcapture.DaemonPeerAuthorizationPolicy) (receivedSeccompListenerHandoff, error) {
	observation, err := kernelcapture.ObserveLinuxUnixPeerCredentials(conn, socketPath)
	if err != nil {
		return receivedSeccompListenerHandoff{}, fmt.Errorf("observe peer credentials: %w", err)
	}
	authorization, err := kernelcapture.AuthorizeObservedDaemonPeer(observation.Credentials, policy)
	if err != nil {
		return receivedSeccompListenerHandoff{}, fmt.Errorf("unauthorized peer: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(seccompHandoffReadTimeout)); err != nil {
		return receivedSeccompListenerHandoff{}, fmt.Errorf("set read deadline: %w", err)
	}

	msgBuf := make([]byte, seccompHandoffMaxHeaderBytes)
	oobBuf := make([]byte, unix.CmsgSpace(4*seccompHandoffMaxReceivedFDs))
	n, oobn, flags, _, err := conn.ReadMsgUnix(msgBuf, oobBuf)
	if err != nil {
		return receivedSeccompListenerHandoff{}, fmt.Errorf("read handoff message: %w", err)
	}
	if flags&unix.MSG_CTRUNC != 0 {
		closeSeccompHandoffRights(oobBuf[:oobn])
		return receivedSeccompListenerHandoff{}, errors.New("handoff ancillary data was truncated")
	}
	if oobn == 0 {
		return receivedSeccompListenerHandoff{}, errors.New("handoff message carried no ancillary data (no fd)")
	}

	scms, err := unix.ParseSocketControlMessage(oobBuf[:oobn])
	if err != nil {
		return receivedSeccompListenerHandoff{}, fmt.Errorf("parse control message: %w", err)
	}
	if len(scms) != 1 {
		closeSeccompHandoffRights(oobBuf[:oobn])
		return receivedSeccompListenerHandoff{}, fmt.Errorf("expected exactly one control message, got %d", len(scms))
	}
	fds, err := unix.ParseUnixRights(&scms[0])
	if err != nil {
		return receivedSeccompListenerHandoff{}, fmt.Errorf("parse unix rights: %w", err)
	}
	if len(fds) != 1 {
		for _, extra := range fds {
			unix.Close(extra)
		}
		return receivedSeccompListenerHandoff{}, fmt.Errorf("expected exactly one fd, got %d", len(fds))
	}
	fd := fds[0]

	var header seccompHandoffRequest
	if err := json.Unmarshal(msgBuf[:n], &header); err != nil {
		unix.Close(fd)
		return receivedSeccompListenerHandoff{}, fmt.Errorf("decode handoff header: %w", err)
	}
	if header.SessionID == "" {
		unix.Close(fd)
		return receivedSeccompListenerHandoff{}, errors.New("handoff header missing session_id")
	}
	return receivedSeccompListenerHandoff{
		sessionID:     header.SessionID,
		fd:            fd,
		observation:   observation,
		authorization: authorization,
	}, nil
}

func closeSeccompHandoffRights(oob []byte) {
	scms, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return
	}
	for i := range scms {
		fds, err := unix.ParseUnixRights(&scms[i])
		if err != nil {
			continue
		}
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}
}

func sendSeccompHandoffResponse(conn *net.UnixConn, ok bool, errMsg string) error {
	data, err := json.Marshal(seccompHandoffResponse{OK: ok, Error: errMsg})
	if err != nil {
		return err
	}
	if err := conn.SetWriteDeadline(time.Now().Add(seccompHandoffReadTimeout)); err != nil {
		return err
	}
	_, err = conn.Write(data)
	return err
}

// superviseSeccompListener services connect(2) notifications on fd until ctx
// is cancelled or the listener errors out — most commonly because the
// governed process tree exited, closing the last reference to the seccomp
// filter the notifications were flowing from. The caller is the listener's
// sole owner and closer; cancellation wakes the poll below through a separate
// eventfd rather than closing fd from another goroutine.
func superviseSeccompListener(ctx context.Context, fd int, sessionID string, registrationGeneration, cgroupID uint64, d *daemon, log *slog.Logger) {
	cancelFD, stopCancellationWatcher, err := newSeccompListenerCancellation(ctx)
	if err != nil {
		log.Error("create seccomp listener cancellation event", "session_id", sessionID, "error", err)
		return
	}
	defer stopCancellationWatcher()

	for {
		if ctx.Err() != nil {
			return
		}
		ready, err := waitForSeccompListenerEvent(fd, cancelFD)
		if err != nil {
			log.Info("seccomp listener poll stopped supervisor", "session_id", sessionID, "error", err)
			return
		}
		if !ready || ctx.Err() != nil {
			return
		}
		notif, err := kernelcapture.RecvSeccompNotif(fd)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Info("seccomp listener closed, stopping supervisor", "session_id", sessionID, "error", err)
			return
		}
		d.seccompSessionMu.RLock()
		if _, err := d.registry.ActiveSessionGeneration(sessionID, registrationGeneration); err != nil {
			if sendErr := kernelcapture.SendSeccompNotifResp(fd, notif.ID, -1, int32(unix.EPERM), false); sendErr != nil {
				log.Warn("seccomp notif send (stale registration deny)", "session_id", sessionID, "error", sendErr)
			}
			d.seccompSessionMu.RUnlock()
			log.Warn("seccomp listener registration ended or was replaced", "session_id", sessionID, "registration_generation", registrationGeneration, "error", err)
			return
		}
		d.handleSeccompConnectNotif(fd, notif, sessionID, cgroupID, log)
		d.seccompSessionMu.RUnlock()
	}
}

// newSeccompListenerCancellation returns an eventfd that becomes readable
// when ctx is cancelled. cleanup first stops and joins the watcher, then
// closes the eventfd, so the watcher can never write to a reused descriptor.
// It intentionally never closes the seccomp listener itself.
func newSeccompListenerCancellation(ctx context.Context) (cancelFD int, cleanup func(), err error) {
	cancelFD, err = unix.Eventfd(0, unix.EFD_CLOEXEC)
	if err != nil {
		return -1, nil, fmt.Errorf("create eventfd: %w", err)
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			var signal [8]byte
			binary.NativeEndian.PutUint64(signal[:], 1)
			for {
				if _, writeErr := unix.Write(cancelFD, signal[:]); !errors.Is(writeErr, unix.EINTR) {
					return
				}
			}
		case <-stop:
		}
	}()

	cleanup = func() {
		close(stop)
		<-done
		_ = unix.Close(cancelFD)
	}
	return cancelFD, cleanup, nil
}

// waitForSeccompListenerEvent blocks without consuming either event. A true
// result means the kernel reported that the following notification receive
// ioctl will not block. A false result means cancellation won the race.
func waitForSeccompListenerEvent(listenerFD, cancelFD int) (bool, error) {
	pollFDs := []unix.PollFd{
		{Fd: int32(listenerFD), Events: unix.POLLIN},
		{Fd: int32(cancelFD), Events: unix.POLLIN},
	}
	for {
		_, err := unix.Poll(pollFDs, -1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("poll listener and cancellation event: %w", err)
		}

		cancelEvents := pollFDs[1].Revents
		if cancelEvents&unix.POLLIN != 0 {
			return false, nil
		}
		if cancelEvents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return false, fmt.Errorf("cancellation eventfd reported poll events %#x", cancelEvents)
		}

		listenerEvents := pollFDs[0].Revents
		if listenerEvents&unix.POLLIN != 0 {
			return true, nil
		}
		if listenerEvents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return false, fmt.Errorf("seccomp listener reported poll events %#x", listenerEvents)
		}
	}
}

// handleSeccompConnectNotif decides one connect(2) notification and responds.
//
// Fail-closed contract: any error resolving the target address (memory read
// failure, TOCTOU re-validation failure via ReadTargetSockaddr, unparseable
// sockaddr) denies the connect. SECCOMP_USER_NOTIF_FLAG_CONTINUE is set only
// on a confirmed, policy-resolved ALLOW — never as a default for an
// ambiguous or error case.
func (d *daemon) handleSeccompConnectNotif(listenerFD int, notif kernelcapture.SeccompNotif, sessionID string, cgroupID uint64, log *slog.Logger) {
	// connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
	addrPtr := notif.Args[1]
	addrLen := uint32(notif.Args[2])

	raw, err := kernelcapture.ReadTargetSockaddr(listenerFD, notif.ID, notif.PID, addrPtr, addrLen)
	if err != nil {
		d.respondSeccompFailClosed(listenerFD, notif, sessionID, cgroupID, log, "read target sockaddr: "+err.Error())
		return
	}
	ip, port, err := kernelcapture.ParseConnectSockaddr(raw)
	if err != nil {
		d.respondSeccompFailClosed(listenerFD, notif, sessionID, cgroupID, log, "parse sockaddr: "+err.Error())
		return
	}

	if trustedIP, trustedPort, controlPlane := kernelcapture.MatchSeccompControlPlaneEndpoint(
		d.seccompPolicy, sessionID, ip, port,
	); controlPlane {
		if err := kernelcapture.EmulateSeccompControlPlaneConnect(listenerFD, notif, trustedIP, trustedPort); err != nil {
			d.respondSeccompControlPlaneFailClosed(listenerFD, notif, sessionID, log, err)
			return
		}
		if err := kernelcapture.SendSeccompNotifResp(listenerFD, notif.ID, 0, 0, false); err != nil {
			log.Warn("seccomp notif send (control-plane emulated success)", "session_id", sessionID, "error", err)
		}
		log.Debug("seccomp control-plane connect emulated", "session_id", sessionID, "pid", notif.PID, "endpoint", fmt.Sprintf("%s:%d", trustedIP, trustedPort))
		return
	}

	decision := kernelcapture.EvaluateSeccompConnect(d.seccompPolicy, sessionID, ip)
	if !decision.HasPolicy {
		// No OP_NET_CONNECT rule for this session: pass through untouched
		// and unlogged, exactly like an ungoverned cgroup on the BPF tier
		// (process_guard.bpf.c's decide(): "cgroup not governed — untouched").
		if err := kernelcapture.SendSeccompNotifResp(listenerFD, notif.ID, 0, 0, true); err != nil {
			log.Warn("seccomp notif send (no-policy allow)", "session_id", sessionID, "error", err)
		}
		return
	}

	if decision.Allowed {
		if err := kernelcapture.SendSeccompNotifResp(listenerFD, notif.ID, 0, 0, true); err != nil {
			log.Warn("seccomp notif send (allow)", "session_id", sessionID, "error", err)
		}
	} else if err := kernelcapture.SendSeccompNotifResp(listenerFD, notif.ID, -1, int32(unix.EPERM), false); err != nil {
		log.Warn("seccomp notif send (deny)", "session_id", sessionID, "error", err)
	}

	// ActionTaken is normalized to ALLOW/DENY, matching process_guard.bpf.c's
	// decide(): an ACT_ALLOWLIST policy's emitted event never carries
	// ARDUR_ACT_ALLOWLIST itself, only whichever of ALLOW/DENY the allowlist
	// check resolved to, so the two tiers' events look identical downstream
	// (enforceEventVerdict, TierCoverage) regardless of which policy action
	// type produced them.
	actionTaken := kernelcapture.BpfActionDeny
	if decision.Matched {
		actionTaken = kernelcapture.BpfActionAllow
	}
	d.emitSeccompConnectEvent(cgroupID, notif.PID, actionTaken, decision.EnforceMode, ip, port, log)
}

func (d *daemon) respondSeccompControlPlaneFailClosed(listenerFD int, notif kernelcapture.SeccompNotif, sessionID string, log *slog.Logger, cause error) {
	log.Warn("seccomp control-plane connect denied: emulation failed", "session_id", sessionID, "pid", notif.PID, "error", cause)
	if err := kernelcapture.SendSeccompNotifResp(listenerFD, notif.ID, -1, int32(unix.EPERM), false); err != nil {
		log.Warn("seccomp notif send (control-plane fail-closed deny)", "session_id", sessionID, "error", err)
	}
}

// respondSeccompFailClosed answers a notification with EPERM and logs why,
// used for every ambiguous/error case in handleSeccompConnectNotif — the
// "prefer deny on ambiguity" contract from the plan.
func (d *daemon) respondSeccompFailClosed(listenerFD int, notif kernelcapture.SeccompNotif, sessionID string, cgroupID uint64, log *slog.Logger, reason string) {
	log.Warn("seccomp connect denied: could not resolve target safely", "session_id", sessionID, "pid", notif.PID, "reason", reason)
	if err := kernelcapture.SendSeccompNotifResp(listenerFD, notif.ID, -1, int32(unix.EPERM), false); err != nil {
		log.Warn("seccomp notif send (fail-closed deny)", "session_id", sessionID, "error", err)
	}
	d.emitSeccompConnectEvent(cgroupID, notif.PID, kernelcapture.BpfActionDeny, kernelcapture.BpfEnforceModeEnforce, nil, 0, log)
}

// emitSeccompConnectEvent routes a seccomp-tier connect(2) decision through
// the same processEnforceEvent pipeline the BPF-LSM tier's ringbuf consumer
// uses (sequencing, hash-chaining, correlation, evidence-log append).
//
// Path carries "ip:port" for this tier's OP_NET_CONNECT events, unlike the
// BPF tier's (which are always empty — process_guard.bpf.c never passes a
// path_src for net-connect ops). BpfEnforceEvent has no dedicated network-
// address field; repurposing Path is a deliberate, tier-specific evidence
// enrichment, not a schema change (the JSON shape and EnforceReceiptSchema
// version are unchanged), and is strictly more informative than the gap it
// works around.
func (d *daemon) emitSeccompConnectEvent(cgroupID uint64, pid uint32, action kernelcapture.BpfAction, mode kernelcapture.BpfEnforceMode, ip net.IP, port uint16, log *slog.Logger) {
	path := ""
	if ip != nil {
		path = fmt.Sprintf("%s:%d", ip, port)
	}
	ev := kernelcapture.BpfEnforceEvent{
		CgroupID:    cgroupID,
		PID:         pid,
		Op:          kernelcapture.BpfOpNetConnect,
		ActionTaken: action,
		EnforceMode: mode,
		ObservedNS:  uint64(time.Now().UnixNano()),
		Path:        path,
	}
	d.processEnforceEvent(ev, seccompEventTier(mode), log)
}

// seccompEventTier mirrors enforceEventTier's bpf_lsm:* naming for the
// seccomp tier, keyed by enforce mode the same way.
func seccompEventTier(mode kernelcapture.BpfEnforceMode) string {
	if mode == kernelcapture.BpfEnforceModeEnforce {
		return "seccomp:enforce"
	}
	return "seccomp:permissive"
}
