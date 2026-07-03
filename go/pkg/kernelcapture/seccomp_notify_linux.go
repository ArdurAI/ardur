//go:build linux

package kernelcapture

// seccomp_notify_linux.go — kernel-facing primitives for the seccomp
// user-notify enforcement tier (Epic A #63, plan E4): installing a
// SECCOMP_RET_USER_NOTIF filter scoped to connect(2), and the
// receive/respond/id-valid ioctls a supervisor uses to service it.
//
// golang.org/x/sys/unix v0.46.0 (this module's pinned version) has no
// seccomp user-notify support at all — no SeccompNotif/SeccompNotifResp
// structs, no SECCOMP_IOCTL_NOTIF_* constants, no seccomp(2) wrapper (only
// the legacy prctl(PR_SET_SECCOMP) path, which doesn't support
// SECCOMP_FILTER_FLAG_NEW_LISTENER at all). This file defines the kernel
// UAPI shapes and ioctl numbers directly from <linux/seccomp.h>, matching
// field-for-field.
//
// Claim boundary: this file only intercepts connect(2). See
// seccomp_policy.go's header comment for why (exec/file-open have no safe
// seccomp-user-notify equivalent in this design) and for the weaker-than-
// BPF-LSM security claim this whole tier makes.

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// --- Kernel UAPI shapes (linux/seccomp.h) -----------------------------------
// Field order and sizes are kernel ABI — do not reorder or resize.

type seccompData struct {
	Nr                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

type seccompNotif struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Data  seccompData
}

type seccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

const (
	seccompSetModeFilter         = 1      // SECCOMP_SET_MODE_FILTER
	seccompFilterFlagNewListener = 1 << 3 // SECCOMP_FILTER_FLAG_NEW_LISTENER

	// seccompUserNotifFlagContinue tells the kernel to let the original
	// syscall proceed with whatever arguments are in the tracee's registers
	// *at the moment the kernel resumes it* — not necessarily the ones the
	// supervisor read via NOTIF_RECV. It is only ever set on a
	// confirmed-safe ALLOW decision in seccomp_supervisor_linux.go, never as
	// a default — see that file's decide function for the fail-closed
	// contract.
	seccompUserNotifFlagContinue = 1 << 0

	seccompRetAllow       = 0x7fff0000 // SECCOMP_RET_ALLOW
	seccompRetUserNotif   = 0x7fc00000 // SECCOMP_RET_USER_NOTIF
	seccompRetKillProcess = 0x80000000 // SECCOMP_RET_KILL_PROCESS

	// Linux audit architecture tokens (linux/audit.h). Only the two this
	// project builds for are defined; nativeSeccompAuditArch fails closed
	// for anything else rather than silently omitting the arch check.
	auditArchX86_64  = 0xc000003e
	auditArchAarch64 = 0xc00000b7
)

// --- Linux ioctl encoding (asm-generic/ioctl.h) -----------------------------
//
// dir(2 bits)<<30 | size(14 bits)<<16 | type(8 bits)<<8 | nr(8 bits).
// Computed from the actual Go struct sizes above rather than hardcoded, so a
// struct-layout mistake surfaces as a wrong-but-checkable ioctl number
// (TestSeccompIoctlNumbers pins the values every other seccomp-notify
// implementation — runc, containerd — hardcodes) instead of a silent
// runtime ENOTTY.

const (
	iocWrite = 1
	iocRead  = 2

	seccompIOCMagic = uintptr('!')
)

func iocEncode(dir, typ, nr, size uintptr) uintptr {
	return (dir << 30) | (size << 16) | (typ << 8) | nr
}

var (
	seccompIoctlNotifRecv    = iocEncode(iocRead|iocWrite, seccompIOCMagic, 0, unsafe.Sizeof(seccompNotif{}))
	seccompIoctlNotifSend    = iocEncode(iocRead|iocWrite, seccompIOCMagic, 1, unsafe.Sizeof(seccompNotifResp{}))
	seccompIoctlNotifIDValid = iocEncode(iocWrite, seccompIOCMagic, 2, unsafe.Sizeof(uint64(0)))
)

func seccompIoctl(fd int, req uintptr, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

// --- Classic BPF (cBPF) filter assembly (linux/filter.h) -------------------
//
// SECCOMP_SET_MODE_FILTER takes a *classic* BPF program (struct sock_filter
// arrays), not eBPF — the same instruction encoding as SO_ATTACH_FILTER.

type sockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// sockFprog mirrors struct sock_fprog: `unsigned short len` followed by
// (after the compiler's natural 6-byte pad to align the pointer field)
// `struct sock_filter *filter`. The explicit padding field documents that
// layout rather than relying on the Go compiler's default alignment to
// happen to match it.
type sockFprog struct {
	Len    uint16
	_      [6]byte
	Filter *sockFilter
}

const (
	bpfLd  = 0x00
	bpfJmp = 0x05
	bpfRet = 0x06

	bpfW   = 0x00
	bpfAbs = 0x20

	bpfJeq = 0x10
	bpfK   = 0x00
)

func bpfStmt(code uint16, k uint32) sockFilter {
	return sockFilter{Code: code, K: k}
}

func bpfJump(code uint16, k uint32, jt, jf uint8) sockFilter {
	return sockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// connectNotifyFilterProgram builds the filter guard_bprm-style hooks don't
// need but a userspace syscall trap does: reject any syscall entered via an
// unexpected ABI outright (a 32-bit compat syscall on a 64-bit target has a
// *different* number for the same operation — checking only `nr` without
// also pinning `arch` is the classic seccomp filter bypass: an attacker
// invokes connect via the 32-bit syscall table, `nr` doesn't match
// SYS_CONNECT for the 64-bit ABI this filter was built for, and the
// unfiltered call falls through to ALLOW), then trap only connect(2),
// allowing everything else through untouched.
//
//	0: A = seccomp_data.arch
//	1: if A != nativeArch: goto 6 (KILL_PROCESS)
//	2: A = seccomp_data.nr
//	3: if A != connectNr: goto 5 (ALLOW)
//	4: return USER_NOTIF
//	5: return ALLOW
//	6: return KILL_PROCESS
func connectNotifyFilterProgram(nativeArch uint32, connectNr uint32) []sockFilter {
	const archOffset = 4 // offsetof(struct seccomp_data, arch)
	const nrOffset = 0   // offsetof(struct seccomp_data, nr)
	return []sockFilter{
		bpfStmt(bpfLd|bpfW|bpfAbs, archOffset),
		bpfJump(bpfJmp|bpfJeq|bpfK, nativeArch, 0, 4),
		bpfStmt(bpfLd|bpfW|bpfAbs, nrOffset),
		bpfJump(bpfJmp|bpfJeq|bpfK, connectNr, 0, 1),
		bpfStmt(bpfRet|bpfK, seccompRetUserNotif),
		bpfStmt(bpfRet|bpfK, seccompRetAllow),
		bpfStmt(bpfRet|bpfK, seccompRetKillProcess),
	}
}

func nativeSeccompAuditArch() (uint32, error) {
	switch runtime.GOARCH {
	case "amd64":
		return auditArchX86_64, nil
	case "arm64":
		return auditArchAarch64, nil
	default:
		return 0, fmt.Errorf("kernelcapture: seccomp connect-notify filter is only implemented for amd64/arm64, got GOARCH=%s", runtime.GOARCH)
	}
}

// --- Public API --------------------------------------------------------

// InstallConnectUserNotifyFilter installs a seccomp filter in the calling
// process (and, by seccomp's design, every process it execve()s into
// afterward — filters are inherited across exec, which is the whole
// mechanism ardur-exec-shim relies on) that traps connect(2) via
// SECCOMP_RET_USER_NOTIF and allows every other syscall through unfiltered.
// Returns the notification listener fd on success.
//
// Sets PR_SET_NO_NEW_PRIVS first: the kernel requires either that or
// CAP_SYS_ADMIN in the caller's user namespace before installing *any*
// seccomp filter as an unprivileged process. Requiring no_new_privs (rather
// than documenting a CAP_SYS_ADMIN requirement) means ardur-exec-shim needs
// no elevated capability to protect its own child.
func InstallConnectUserNotifyFilter() (int, error) {
	arch, err := nativeSeccompAuditArch()
	if err != nil {
		return -1, err
	}
	prog := connectNotifyFilterProgram(arch, uint32(unix.SYS_CONNECT))

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return -1, fmt.Errorf("kernelcapture: prctl(PR_SET_NO_NEW_PRIVS): %w", err)
	}

	fprog := sockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	fd, _, errno := unix.Syscall(uintptr(unix.SYS_SECCOMP),
		seccompSetModeFilter,
		seccompFilterFlagNewListener,
		uintptr(unsafe.Pointer(&fprog)),
	)
	if errno != 0 {
		return -1, fmt.Errorf("kernelcapture: seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER): %w", errno)
	}
	return int(fd), nil
}

// SeccompNotif is the caller-facing projection of one notification: enough
// to make a policy decision and to read the target's memory for
// syscall-argument-dependent ones (connect's sockaddr pointer is Args[1],
// its length is Args[2] — the standard connect(2) ABI: connect(int sockfd,
// const struct sockaddr *addr, socklen_t addrlen)).
type SeccompNotif struct {
	ID   uint64
	PID  uint32
	Nr   int32
	Args [6]uint64
}

// RecvSeccompNotif blocks until a notification is available on listenerFD
// (SECCOMP_IOCTL_NOTIF_RECV) or the listener is closed/an error occurs.
func RecvSeccompNotif(listenerFD int) (SeccompNotif, error) {
	var raw seccompNotif
	if err := seccompIoctl(listenerFD, seccompIoctlNotifRecv, unsafe.Pointer(&raw)); err != nil {
		return SeccompNotif{}, fmt.Errorf("kernelcapture: SECCOMP_IOCTL_NOTIF_RECV: %w", err)
	}
	return SeccompNotif{ID: raw.ID, PID: raw.PID, Nr: raw.Data.Nr, Args: raw.Data.Args}, nil
}

// SendSeccompNotifResp responds to notification id on listenerFD.
// continueSyscall sets SECCOMP_USER_NOTIF_FLAG_CONTINUE (let the syscall
// proceed normally); when false, the syscall returns -1 to the tracee with
// errno set to errno (val is ignored by the kernel in that case). errno is a
// natural positive value in this API (e.g. unix.EPERM, matching every other
// errno in this codebase) — the kernel's own seccomp_notif_resp.error field
// uses the raw syscall-return convention instead (a *negative* -errno), so
// this function negates it before writing the struct. Getting this backwards
// is silent and severe: the kernel treats a non-negative raw return value as
// success, so a positive `error` doesn't deny the syscall, it lets it
// through with a nonsense return value — caught empirically, the first
// end-to-end run of the seccomp tier let a policy-denied connect() through
// for exactly this reason. Callers must not set both a continue response and
// a non-zero errno — SendSeccompNotifResp does not itself enforce that
// exclusivity, so get it right at the call site (see daemon_seccomp_linux.go,
// which never does both).
func SendSeccompNotifResp(listenerFD int, id uint64, val int64, errno int32, continueSyscall bool) error {
	resp := buildSeccompNotifResp(id, val, errno, continueSyscall)
	if err := seccompIoctl(listenerFD, seccompIoctlNotifSend, unsafe.Pointer(&resp)); err != nil {
		return fmt.Errorf("kernelcapture: SECCOMP_IOCTL_NOTIF_SEND: %w", err)
	}
	return nil
}

// buildSeccompNotifResp is SendSeccompNotifResp's struct construction,
// split out so the positive-errno-in/negative-errno-in-the-kernel-struct-out
// sign flip can be unit-tested without a live listener fd (see
// TestBuildSeccompNotifResp_NegatesErrno for the regression this guards).
func buildSeccompNotifResp(id uint64, val int64, errno int32, continueSyscall bool) seccompNotifResp {
	var flags uint32
	if continueSyscall {
		flags = seccompUserNotifFlagContinue
	}
	return seccompNotifResp{ID: id, Val: val, Error: -errno, Flags: flags}
}

// SeccompNotifIDValid reports whether notification id on listenerFD is still
// live — the target thread that generated it hasn't exited, and (critically)
// its pid hasn't been reused for an unrelated process since. See
// ReadTargetSockaddr's doc comment for how this is used to bound the TOCTOU
// window around reading target memory.
func SeccompNotifIDValid(listenerFD int, id uint64) bool {
	localID := id
	return seccompIoctl(listenerFD, seccompIoctlNotifIDValid, unsafe.Pointer(&localID)) == nil
}

// maxReadableSockaddrLen caps how many bytes ReadTargetSockaddr will read
// regardless of what addrlen the tracee claims: enough for sockaddr_in6 (28
// bytes) with generous headroom, small enough that a corrupt/hostile addrlen
// value can't turn this into an unbounded read.
const maxReadableSockaddrLen = 128

// ReadTargetSockaddr reads addrLen bytes (capped at maxReadableSockaddrLen)
// from pid's memory at addr, for a connect(2) notification identified by id
// on listenerFD.
//
// Re-validates id via SECCOMP_IOCTL_NOTIF_ID_VALID both immediately before
// opening /proc/pid/mem (catching a target that has already exited/been
// reaped since RECV) and immediately after the read (catching a target that
// exited *during* the read, whose pid could otherwise have been recycled for
// an unrelated process by the time this function returns bytes the caller is
// about to trust). This is the standard seccomp_unotify(2) TOCTOU mitigation
// pattern (Documentation/userspace-api/seccomp_filter.rst): checking only
// once, before OR after the read, leaves a window where the bytes returned
// belong to a different process than the one the caller believes it is
// evaluating.
//
// This closes the PID-reuse race. It does not close every race — a
// still-live, still-correctly-identified target can still mutate its own
// memory from another thread between this read and the supervisor's
// eventual SECCOMP_IOCTL_NOTIF_SEND. See seccomp_policy.go's claim-boundary
// comment: that is the documented, load-bearing difference between this
// tier and an in-kernel LSM hook.
func ReadTargetSockaddr(listenerFD int, id uint64, pid uint32, addr uint64, addrLen uint32) ([]byte, error) {
	if addrLen == 0 {
		return nil, fmt.Errorf("kernelcapture: connect(2) addrlen is 0")
	}
	if addrLen > maxReadableSockaddrLen {
		addrLen = maxReadableSockaddrLen
	}

	if !SeccompNotifIDValid(listenerFD, id) {
		return nil, fmt.Errorf("kernelcapture: notification %d no longer valid before memory read (target exited or was reaped)", id)
	}

	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil, fmt.Errorf("kernelcapture: open /proc/%d/mem: %w", pid, err)
	}
	defer mem.Close()

	buf := make([]byte, addrLen)
	n, err := mem.ReadAt(buf, int64(addr))
	if err != nil {
		return nil, fmt.Errorf("kernelcapture: read /proc/%d/mem at %#x: %w", pid, addr, err)
	}
	if uint32(n) != addrLen {
		return nil, fmt.Errorf("kernelcapture: short read from /proc/%d/mem: got %d, want %d", pid, n, addrLen)
	}

	if !SeccompNotifIDValid(listenerFD, id) {
		return nil, fmt.Errorf("kernelcapture: notification %d no longer valid after memory read (target exited mid-read; discarding bytes read from a possibly-recycled pid)", id)
	}
	return buf, nil
}
