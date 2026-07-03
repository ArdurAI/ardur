//go:build linux

package main

// daemon_cgroup_verify_linux.go — register_session cgroup-ownership check.
//
// register_session binds a client-supplied cgroup_id (and root_pid) to a
// session; apply_policy later writes BPF enforcement keyed by that cgroup_id.
// Without a check, any authorized-UID peer could register a cgroup_id belonging
// to another workload and then govern/tamper it. This closes that by requiring
// root_pid to be a process the peer actually spawned.
//
// Why an ancestry check and NOT a literal "claimed cgroup_id == inode of
// /proc/<peerPID>/cgroup" comparison: in the real `ardur run` flow the socket
// peer (the launcher) does not enter the cgroup — it creates a cgroup and
// adopts the *agent child* into it (run_bridge.py), so the peer's own cgroup
// is not the registered one. Worse, cgroup namespaces make /proc/<pid>/cgroup
// report a namespace-relative path (a governed agent commonly reads its own as
// "0::/"), so the daemon cannot reliably resolve it back to the kernel cgroup
// id the launcher derived via stat().st_ino across a namespace boundary — a
// literal inode match there rejects the legitimate, end-to-end-verified flow.
//
// The ancestry check is namespace-robust (PID ancestry within the daemon's own
// /proc view) and delivers the property that matters: a peer may only register
// a session whose root_pid is a process it spawned. Since kernel enforcement
// keys on each process's *actual* runtime cgroup and a peer can only name its
// own descendants — which live in cgroups the peer itself controls — a peer
// cannot bind a session to, and then govern, a cgroup it does not own.

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

// maxCgroupAncestryHops bounds the /proc parent-chain walk so a pathological or
// racing process table can never spin the handler. A launcher-spawned agent is
// a direct child (1 hop); the generous bound tolerates intervening wrapper
// processes without ever being unbounded.
const maxCgroupAncestryHops = 64

func verifyRegisterSessionCgroup(handshake kernelcapture.DaemonProtocolPeerHandshake, reg *kernelcapture.DaemonRegisterSessionRequest, log *slog.Logger) error {
	peerPID := handshake.Authorization.PID
	rootPID := reg.RootPID
	// register_session validation already requires root_pid != 0 and
	// cgroup_id != 0; peerPID comes from SO_PEERCRED. If either is missing
	// there is nothing to bind — let the registry's own validation speak.
	if peerPID == 0 || rootPID == 0 {
		return nil
	}
	// The peer registering its own process is trivially owned.
	if rootPID == peerPID {
		return nil
	}
	// A root (uid 0) peer is already fully privileged on the host — it can move
	// any process between cgroups directly, so this ancestry check adds nothing
	// against it. The check exists to constrain a NON-root allowed peer (the
	// sandboxed-workload threat) from binding a session to a process tree it did
	// not spawn. Skipping root also lets tiers that register a placeholder
	// root_pid (the seccomp tier enforces per-shim'd-process, not by cgroup, and
	// its smoke registers root_pid=1) work when the daemon and client are root.
	// Per-session ownership on apply_policy still applies to every peer.
	if handshake.Authorization.UID == 0 {
		return nil
	}
	// Confirm the peer itself is visible in the daemon's /proc view. If it is
	// not (an unusual cross-PID-namespace deployment where the daemon cannot
	// see client PIDs at all), we cannot establish ancestry either way — skip
	// rather than reject and break such a deployment, but say so loudly.
	if _, err := os.Stat("/proc/" + strconv.FormatUint(uint64(peerPID), 10)); err != nil {
		log.Warn("register_session cgroup ownership check skipped: peer pid not visible in /proc (cross-namespace daemon?)",
			"peer_pid", peerPID, "root_pid", rootPID)
		return nil
	}
	// Walk root_pid's parent chain; it must reach the registering peer.
	cur := rootPID
	for hops := 0; hops < maxCgroupAncestryHops; hops++ {
		ppid, err := procParentPID(cur)
		if err != nil {
			return fmt.Errorf("root_pid %d is not a live process visible to the daemon (%v); a peer may only register a process it spawned", rootPID, err)
		}
		if ppid == peerPID {
			return nil
		}
		if ppid == 0 || ppid == cur {
			break
		}
		cur = ppid
	}
	return fmt.Errorf("root_pid %d is not a descendant of the registering peer pid %d; a peer may only register process trees it spawned", rootPID, peerPID)
}

// procParentPID reads the PPID (field 4) from /proc/<pid>/stat. The comm field
// (field 2) is wrapped in parentheses and may itself contain spaces and ')',
// so the stable parse is: take everything after the LAST ')'.
func procParentPID(pid uint32) (uint32, error) {
	data, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/stat")
	if err != nil {
		return 0, err
	}
	s := string(data)
	rparen := strings.LastIndexByte(s, ')')
	if rparen < 0 || rparen+2 >= len(s) {
		return 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	// After ") " come: state (field 3) ppid (field 4) ...
	fields := strings.Fields(s[rparen+2:])
	if len(fields) < 2 {
		return 0, fmt.Errorf("malformed /proc/%d/stat fields", pid)
	}
	ppid, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse ppid from /proc/%d/stat: %w", pid, err)
	}
	return uint32(ppid), nil
}
