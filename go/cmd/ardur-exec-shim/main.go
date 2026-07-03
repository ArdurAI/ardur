//go:build linux

// Command ardur-exec-shim is the on-ramp for the seccomp user-notify
// enforcement tier (Epic A #63, plan E4) — the common-case fallback for
// hosts where BPF-LSM never loads (stock distros that ship CONFIG_BPF_LSM=y
// but don't put "bpf" in the boot lsm= list, so the BPF-LSM tier in
// daemon_guard_linux.go silently isn't active).
//
// It installs a connect(2)-scoped SECCOMP_RET_USER_NOTIF filter in itself
// (kernelcapture.InstallConnectUserNotifyFilter), hands the resulting
// notification listener fd to ardur-kernelcaptured over a dedicated Unix
// socket via SCM_RIGHTS (see go/cmd/ardur-kernelcaptured/daemon_seccomp_linux.go),
// then execve()s into the target command — replacing itself, so the governed
// process tree keeps the shim's PID and the filter (installed before exec,
// inherited across it by seccomp's design) carries over unchanged. One
// filter, installed once here, covers every descendant that process tree
// forks or execs afterward — no per-child re-registration.
//
// Claim boundary: this only covers connect(2). Everything else about this
// tier's scope and its documented weaker-than-BPF-LSM security claim is in
// go/pkg/kernelcapture/seccomp_policy.go's header comment.
//
// Fail-closed without a supervisor: if the handoff to the daemon fails, or
// the daemon later dies without a replacement attaching, the kernel's own
// seccomp-notify semantics take over — a USER_NOTIF-returning filter with no
// live listener answers every trapped syscall with -ENOSYS
// (Documentation/userspace-api/seccomp_filter.rst). So a missing or lost
// supervisor blocks connect(2) outright rather than letting it through
// unfiltered; there is deliberately no separate "abort, don't exec at all"
// fallback path here — the filter itself is already the fail-closed
// mechanism, and refusing to run the target at all would only be a *weaker*
// guarantee (no filter, but also no program) for a caller who asked to run
// something.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
	"golang.org/x/sys/unix"
)

const (
	defaultSeccompSocketPath = "/run/ardur/kernelcapture/seccomp.sock"

	handoffDialTimeout  = 5 * time.Second
	handoffWriteTimeout = 5 * time.Second
	handoffReadTimeout  = 10 * time.Second
	handoffMaxRespBytes = 4096

	// A brief bounded retry, not a long one: this is here to absorb the
	// ordinary "daemon is still finishing startup" race, not to paper over a
	// daemon that is actually down — see the package doc comment for what
	// happens to connect(2) in the target process when the handoff never
	// succeeds.
	handoffAttempts  = 3
	handoffRetryWait = 500 * time.Millisecond
)

func main() {
	// seccomp filters attach to the calling OS thread (propagating to
	// threads/processes created afterward via clone/exec on *that* thread),
	// not to the Go process as a whole. Without this, the Go scheduler is
	// free to migrate main's goroutine to a different OS thread between
	// InstallConnectUserNotifyFilter and the later unix.Exec — one that
	// never had the filter installed — silently running the target
	// completely unfiltered. Caught empirically: the first end-to-end run
	// of this shim let a policy-denied connect() straight through.
	runtime.LockOSThread()

	var (
		sessionID     = flag.String("session-id", "", "ardur session_id this shim's connect(2) decisions are evaluated against (required)")
		seccompSocket = flag.String("seccomp-socket", defaultSeccompSocketPath, "ardur-kernelcaptured's seccomp handoff socket path")
	)
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if *sessionID == "" || len(args) == 0 {
		usage()
		os.Exit(2)
	}

	if err := run(*sessionID, *seccompSocket, args); err != nil {
		fmt.Fprintf(os.Stderr, "ardur-exec-shim: %v\n", err)
		os.Exit(1)
	}
	// run only returns on a setup failure before exec; a successful exec
	// replaces this process image and control never comes back here.
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s --session-id ID [--seccomp-socket PATH] -- COMMAND [ARGS...]\n", os.Args[0])
	flag.PrintDefaults()
}

func run(sessionID, seccompSocketPath string, args []string) error {
	target, err := lookupTarget(args[0])
	if err != nil {
		return err
	}

	// Establish (and retry, if needed) the handoff connection to the
	// daemon BEFORE installing the seccomp filter below. This ordering is
	// load-bearing, not stylistic: seccomp intercepts connect(2) by
	// syscall number alone, with no awareness of socket address family —
	// once the filter is live, this process's own connect() to the
	// daemon's AF_UNIX handoff socket would be trapped by the very
	// listener it's trying to hand off, and since nothing services that
	// listener until the handoff completes, the connect() would block
	// forever (a self-deadlock, caught empirically: the first end-to-end
	// run of this shim hung exactly here). Dialing first sidesteps it:
	// the connection already exists by the time the filter goes live, so
	// writing the header+fd and reading the response over it afterward
	// are plain read/write on an already-open fd, not new syscalls the
	// filter would ever see.
	handoffConn, dialErr := dialHandoffWithRetry(seccompSocketPath)

	listenerFD, err := kernelcapture.InstallConnectUserNotifyFilter()
	if err != nil {
		if handoffConn != nil {
			handoffConn.Close()
		}
		return fmt.Errorf("install seccomp connect-notify filter: %w", err)
	}

	handoffErr := dialErr
	if dialErr == nil {
		handoffErr = sendHandoff(handoffConn, sessionID, listenerFD)
		handoffConn.Close()
	}
	if handoffErr != nil {
		fmt.Fprintf(os.Stderr,
			"ardur-exec-shim: warning: seccomp handoff to daemon failed, connect(2) will fail closed (ENOSYS) until a listener attaches: %v\n", handoffErr)
	}
	// Whether or not the handoff above succeeded, this process's own
	// reference to listenerFD must not survive into the target: on success
	// the daemon holds an independent SCM_RIGHTS-duplicated reference, so
	// closing ours is just cleanup; on failure closing it removes the *last*
	// reference, which is what makes the kernel answer -ENOSYS rather than
	// leaving connect(2) calls blocked forever waiting on a notification
	// nobody will ever read. It also isn't safe to just let exec's implicit
	// CLOEXEC handling deal with this: the fd came back from a raw
	// SYS_SECCOMP syscall, not one of Go's fd-tracking open paths, so
	// CLOEXEC was never set on it — leaving it open would leak a working
	// listener fd straight into the governed process's own fd table.
	_ = unix.Close(listenerFD)

	return unix.Exec(target, args, os.Environ())
}

// lookupTarget resolves argv[0] to an executable path, matching the PATH
// search execve(2) itself does not do (unix.Exec, like the raw syscall,
// requires an already-resolved path).
func lookupTarget(name string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	resolved, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("resolve %q in PATH: %w", name, err)
	}
	return resolved, nil
}

// seccompHandoffRequest/seccompHandoffResponse mirror (by JSON shape only —
// this is a separate binary, there is no shared Go type) the daemon's
// seccompHandoffRequest/seccompHandoffResponse in
// go/cmd/ardur-kernelcaptured/daemon_seccomp_linux.go.
type seccompHandoffRequest struct {
	SessionID string `json:"session_id"`
}

type seccompHandoffResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// dialHandoffWithRetry connects to the daemon's seccomp handoff socket,
// retrying a bounded number of times to absorb the daemon-still-starting
// race. Must run before the seccomp filter is installed — see run's comment
// for why redialing after that point would deadlock.
func dialHandoffWithRetry(socketPath string) (*net.UnixConn, error) {
	var lastErr error
	for attempt := 0; attempt < handoffAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(handoffRetryWait)
		}
		conn, err := net.DialTimeout("unix", socketPath, handoffDialTimeout)
		if err != nil {
			lastErr = fmt.Errorf("dial seccomp handoff socket %s: %w", socketPath, err)
			continue
		}
		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			return nil, fmt.Errorf("dial seccomp handoff socket %s: unexpected connection type %T", socketPath, conn)
		}
		return unixConn, nil
	}
	return nil, lastErr
}

// sendHandoff writes the session_id header and listenerFD (via SCM_RIGHTS)
// on an already-connected conn and reads the daemon's response. No retry
// here: retrying would require a new connect(), which — once the seccomp
// filter this fd belongs to is installed — would deadlock the same way a
// fresh dial would (see run's comment). A single already-open connection
// gets exactly one request/response, matching the daemon's one-shot handoff
// handler (it closes the connection after responding either way).
func sendHandoff(conn *net.UnixConn, sessionID string, listenerFD int) error {
	header, err := json.Marshal(seccompHandoffRequest{SessionID: sessionID})
	if err != nil {
		return fmt.Errorf("encode handoff header: %w", err)
	}

	if err := conn.SetWriteDeadline(time.Now().Add(handoffWriteTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	if _, _, err := conn.WriteMsgUnix(header, unix.UnixRights(listenerFD), nil); err != nil {
		return fmt.Errorf("send handoff message: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(handoffReadTimeout)); err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}
	respBuf := make([]byte, handoffMaxRespBytes)
	n, err := conn.Read(respBuf)
	if err != nil {
		return fmt.Errorf("read handoff response: %w", err)
	}

	var resp seccompHandoffResponse
	if err := json.Unmarshal(respBuf[:n], &resp); err != nil {
		return fmt.Errorf("decode handoff response: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("daemon rejected handoff: %s", resp.Error)
	}
	return nil
}
