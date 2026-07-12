//go:build linux

package main

// daemon_cgroup_verify_linux.go — register_session cgroup-ownership check.
//
// register_session binds a client-supplied cgroup_id (and root_pid) to a
// session; apply_policy later writes BPF enforcement keyed by that cgroup_id.
// Without a check, any authorized-UID peer could register a cgroup_id belonging
// to another workload and then govern/tamper it. This closes that with TWO
// independent checks, both required:
//
//  1. Ancestry — root_pid must be a process the peer actually spawned (PID
//     ancestry within the daemon's own /proc view, namespace-robust).
//  2. Ownership (issue #119) — root_pid's ACTUAL cgroup, as resolved by the
//     daemon, must match the client-claimed cgroup_id.
//
// #115 shipped only (1) and reasoned that (2) could not be done reliably: its
// comment argued that in the real `ardur run` flow the socket peer (the
// launcher) does not itself enter the cgroup — it creates one and adopts the
// *agent child* into it (run_bridge.py) — and that cgroup namespaces make
// /proc/<pid>/cgroup report a namespace-relative path the daemon cannot
// resolve back to a real inode across a namespace boundary.
//
// That reasoning is correct about resolving the PEER's own cgroup, but #119
// shows it was applied to the wrong process: this package never needs the
// peer's cgroup. It needs root_pid's cgroup, resolved by the daemon itself —
// and the daemon runs host-side, in the init cgroup namespace. /proc/<pid>/cgroup
// read from a process outside a container's cgroup namespace (the daemon)
// reports the path relative to the READER's namespace, i.e. the real,
// non-namespace-relative host path — not root_pid's own view. resolveCgroupID
// below does exactly that: read /proc/<root_pid>/cgroup as the daemon sees
// it, resolve to the cgroup directory's inode (the same value
// bpf_get_current_cgroup_id() returns, and what the Python run bridge computes
// via os.stat().st_ino when it creates the session's cgroup), and require it
// equal reg.CgroupID.
//
// Without check (2), ancestry alone let a non-root allowed peer register
// {root_pid: <its own child>, cgroup_id: <any other live cgroup>} — ancestry
// passes trivially (root_pid really is its child), but nothing had ever
// verified that child was actually IN the claimed cgroup. The peer could then
// apply_policy against a cgroup — and workload — it does not own. This was
// demonstrated live against a build with only check (1); see
// daemon_cgroup_verify_linux_test.go's TestVerifyRegisterSessionCgroup_Issue119Poc*
// for the reproduction, now asserting rejection.
//
// A third, independent guard (checkCgroupCollision, daemon.go — platform-
// neutral, no /proc dependency) rejects registering a cgroup_id already bound
// to another live session, so even a race or a legitimate-looking claim can
// never let two sessions govern the same cgroup concurrently.

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

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
	// cgroup_id != 0. If rootPID is missing there is no claim to inspect; let
	// the registry's own validation reject the malformed request.
	if rootPID == 0 {
		return nil
	}
	// A root (uid 0) peer is already fully privileged on the host — it can move
	// any process between cgroups directly, so neither check below adds anything
	// against it. Both checks exist to constrain a NON-root allowed peer (the
	// sandboxed-workload threat) from binding a session to a cgroup/process tree
	// it does not own. Skipping root also lets tiers that register a placeholder
	// root_pid (the seccomp tier enforces per-shim'd-process, not by cgroup, and
	// its smoke registers root_pid=1, whose real cgroup is the hierarchy root —
	// never a session's claimed leaf cgroup) work when the daemon and client are
	// root. Per-session ownership on apply_policy still applies to every peer.
	if handshake.Authorization.UID == 0 {
		return nil
	}
	// peerPID comes from SO_PEERCRED and is translated into the receiver's PID
	// namespace. A zero/unavailable value cannot bind this socket peer to the
	// claimed process tree, so UID authorization alone is insufficient.
	if peerPID == 0 {
		log.Warn("register_session rejected: peer pid unavailable for cgroup ownership verification",
			"root_pid", rootPID, "cgroup_id", reg.CgroupID)
		return fmt.Errorf("peer pid is unavailable in the daemon pid namespace; cannot verify ownership of root_pid %d and cgroup_id %d", rootPID, reg.CgroupID)
	}
	// Confirm the peer itself is visible in the daemon's /proc view. /proc is
	// tied to the PID namespace that mounted it; if lookup fails, ancestry and
	// ownership cannot be established. Failing open here would restore the
	// cross-workload enforcement path closed by issue #119.
	if _, err := os.Stat("/proc/" + strconv.FormatUint(uint64(peerPID), 10)); err != nil {
		log.Warn("register_session rejected: peer pid not visible for cgroup ownership verification",
			"peer_pid", peerPID, "root_pid", rootPID, "cgroup_id", reg.CgroupID, "error", err)
		return fmt.Errorf("peer pid %d is not visible in the daemon /proc view (%w); cannot verify ownership of root_pid %d and cgroup_id %d", peerPID, err, rootPID, reg.CgroupID)
	}

	// Check 1: ancestry. The peer registering its own process is trivially a
	// (zero-hop) descendant; anything else must be found by walking parents.
	if rootPID != peerPID {
		if err := verifyCgroupAncestry(rootPID, peerPID); err != nil {
			return err
		}
	}

	// Check 2 (#119): ownership. root_pid's actual cgroup, resolved by the
	// daemon, must match the claimed cgroup_id. Applies even to the
	// rootPID==peerPID case above — a peer claiming its OWN pid as root_pid
	// with a mismatched cgroup_id is the same vulnerability class, just
	// without the extra step of spawning a child first.
	if reg.CgroupID != 0 {
		resolved, err := resolveCgroupID(rootPID)
		if err != nil {
			return fmt.Errorf("root_pid %d cgroup could not be resolved (%v); a peer may only register a cgroup_id its root_pid actually occupies", rootPID, err)
		}
		if resolved != reg.CgroupID {
			return fmt.Errorf("root_pid %d is in cgroup %d, not the claimed cgroup_id %d; a peer may only register a cgroup_id its root_pid actually occupies", rootPID, resolved, reg.CgroupID)
		}
	}

	return nil
}

// verifyCgroupAncestry walks rootPID's parent chain looking for peerPID.
func verifyCgroupAncestry(rootPID, peerPID uint32) error {
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

// resolveCgroupID reads pid's cgroup v2 unified-hierarchy membership from
// /proc/<pid>/cgroup as observed BY THE DAEMON — which runs host-side, in the
// init cgroup namespace — and resolves it to the cgroup directory's inode:
// the same value bpf_get_current_cgroup_id() returns for that cgroup, and
// what the Python run bridge computes via os.stat().st_ino when it creates a
// session's cgroup (python/vibap/kernel_correlation.py's create_run_cgroup).
// See this file's header comment for why this is namespace-robust in the
// direction that matters (resolving root_pid's cgroup from OUTSIDE any
// container it might run in), unlike resolving the socket peer's own cgroup.
func resolveCgroupID(pid uint32) (uint64, error) {
	cgroupPath, err := resolveCgroupPath(pid)
	if err != nil {
		return 0, err
	}
	var st syscall.Stat_t
	if err := syscall.Stat(cgroupPath, &st); err != nil {
		return 0, fmt.Errorf("stat cgroup path %q (pid %d): %w", cgroupPath, pid, err)
	}
	if st.Ino == 0 {
		return 0, fmt.Errorf("stat cgroup path %q returned inode 0", cgroupPath)
	}
	return st.Ino, nil
}

// resolveCgroupPath returns the absolute, daemon-side cgroupfs path for pid's
// cgroup v2 unified-hierarchy membership (split out of resolveCgroupID so
// tests can locate a real, writable cgroup subtree to create a child under —
// see daemon_cgroup_verify_linux_test.go's cgroupV2SelfDir).
func resolveCgroupPath(pid uint32) (string, error) {
	path := "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/cgroup"
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[0] != "0" || parts[1] != "" {
			continue // not the cgroup v2 unified-hierarchy entry (hierarchy-id 0, no controllers)
		}
		rel := strings.TrimPrefix(parts[2], "/")
		return filepath.Join("/sys/fs/cgroup", rel), nil
	}
	return "", fmt.Errorf("no cgroup v2 unified-hierarchy entry found for pid %d in %q", pid, strings.TrimSpace(string(data)))
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
