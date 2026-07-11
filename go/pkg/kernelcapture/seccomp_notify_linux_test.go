//go:build linux

package kernelcapture

// seccomp_notify_linux_test.go — unit tests for the seccomp user-notify
// kernel UAPI layer (seccomp_notify_linux.go): ioctl number pinning, classic
// BPF filter assembly, and struct layout ABI checks.
//
// These deliberately stop short of calling seccomp(2)/ioctl(2) against a
// real listener — installing SECCOMP_RET_USER_NOTIF in the test process
// itself would attach an irrevocable filter to `go test`'s own process for
// the rest of the binary's run (seccomp filters can only be added, never
// removed), which would risk hanging or breaking any later test that
// touches the network in-process if nothing ever answers the notification.
// That end-to-end proof belongs in a dedicated, isolated harness (plan E4's
// privileged-container verification step, mirroring ardur-guard-smoke's
// separate-binary pattern for the BPF-LSM tier), not go test ./....

import (
	"encoding/binary"
	"net"
	"reflect"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestTrustedSeccompControlPlaneSockaddr(t *testing.T) {
	t.Parallel()

	v4, err := trustedSeccompControlPlaneSockaddr(net.ParseIP("127.0.0.1"), 43210)
	if err != nil {
		t.Fatalf("IPv4 sockaddr: %v", err)
	}
	v4addr, ok := v4.(*unix.SockaddrInet4)
	if !ok || v4addr.Port != 43210 || v4addr.Addr != [4]byte{127, 0, 0, 1} {
		t.Fatalf("IPv4 sockaddr = %#v, want 127.0.0.1:43210", v4)
	}

	v6, err := trustedSeccompControlPlaneSockaddr(net.ParseIP("::1"), 43211)
	if err != nil {
		t.Fatalf("IPv6 sockaddr: %v", err)
	}
	v6addr, ok := v6.(*unix.SockaddrInet6)
	wantV6 := [16]byte{}
	wantV6[15] = 1
	if !ok || v6addr.Port != 43211 || v6addr.Addr != wantV6 {
		t.Fatalf("IPv6 sockaddr = %#v, want [::1]:43211", v6)
	}
}

func TestTrustedSeccompControlPlaneSockaddrRejectsWidenedTargets(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		ip   net.IP
		port uint16
	}{
		{name: "remote IPv4", ip: net.ParseIP("192.0.2.10"), port: 443},
		{name: "unspecified IPv4", ip: net.ParseIP("0.0.0.0"), port: 443},
		{name: "nil IP", ip: nil, port: 443},
		{name: "zero port", ip: net.ParseIP("127.0.0.1"), port: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := trustedSeccompControlPlaneSockaddr(tc.ip, tc.port); err == nil {
				t.Fatal("expected invalid control-plane tuple to be rejected")
			}
		})
	}
}

func TestSeccompSockaddrMatchesEndpointRequiresExactIPAndPort(t *testing.T) {
	t.Parallel()

	v4 := &unix.SockaddrInet4{Port: 43210, Addr: [4]byte{127, 0, 0, 1}}
	if !seccompSockaddrMatchesEndpoint(v4, net.ParseIP("127.0.0.1"), 43210) {
		t.Fatal("exact IPv4 endpoint did not match")
	}
	if seccompSockaddrMatchesEndpoint(v4, net.ParseIP("127.0.0.1"), 43211) {
		t.Fatal("adjacent IPv4 port matched")
	}
	if seccompSockaddrMatchesEndpoint(v4, net.ParseIP("127.0.0.2"), 43210) {
		t.Fatal("adjacent IPv4 address matched")
	}

	v6 := &unix.SockaddrInet6{Port: 43211}
	v6.Addr[15] = 1
	if !seccompSockaddrMatchesEndpoint(v6, net.ParseIP("::1"), 43211) {
		t.Fatal("exact IPv6 endpoint did not match")
	}
	if seccompSockaddrMatchesEndpoint(v6, net.ParseIP("127.0.0.1"), 43211) {
		t.Fatal("IPv4 endpoint matched an IPv6 peer")
	}
}

func TestConnectTrustedSeccompSocketCompletesNonblockingConnect(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	tcpAddr := listener.Addr().(*net.TCPAddr)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("create nonblocking socket: %v", err)
	}
	defer unix.Close(fd)
	destination, err := trustedSeccompControlPlaneSockaddr(tcpAddr.IP, uint16(tcpAddr.Port))
	if err != nil {
		t.Fatalf("trusted sockaddr: %v", err)
	}
	if err := connectTrustedSeccompSocket(fd, destination, tcpAddr.IP, uint16(tcpAddr.Port)); err != nil {
		t.Fatalf("connect nonblocking trusted socket: %v", err)
	}

	tcpListener := listener.(*net.TCPListener)
	if err := tcpListener.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set accept deadline: %v", err)
	}
	conn, err := tcpListener.Accept()
	if err != nil {
		t.Fatalf("accept emulated connection: %v", err)
	}
	conn.Close()
}

// TestSeccompIoctlNumbers pins the three ioctl request values this file
// computes via iocEncode against the same numbers every other
// seccomp-notify implementation (runc, containerd) hardcodes. A
// seccompNotif/seccompNotifResp struct-layout mistake changes the encoded
// size field and surfaces here as a wrong-but-checkable number instead of a
// silent ENOTTY at runtime.
func TestSeccompIoctlNumbers(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"SECCOMP_IOCTL_NOTIF_RECV", seccompIoctlNotifRecv, 0xc0502100},
		{"SECCOMP_IOCTL_NOTIF_SEND", seccompIoctlNotifSend, 0xc0182101},
		{"SECCOMP_IOCTL_NOTIF_ID_VALID", seccompIoctlNotifIDValid, 0x40082102},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %#x, want %#x", tc.name, tc.got, tc.want)
		}
	}
}

func TestNativeSeccompAuditArch(t *testing.T) {
	arch, err := nativeSeccompAuditArch()
	if err != nil {
		t.Fatalf("nativeSeccompAuditArch() on GOARCH=%s: %v", runtime.GOARCH, err)
	}
	var want uint32
	switch runtime.GOARCH {
	case "amd64":
		want = auditArchX86_64
	case "arm64":
		want = auditArchAarch64
	default:
		t.Skipf("no expected AUDIT_ARCH_* constant for GOARCH=%s in this test", runtime.GOARCH)
	}
	if arch != want {
		t.Errorf("nativeSeccompAuditArch() = %#x, want %#x", arch, want)
	}
}

// TestSockFprogLayoutMatchesKernelABI guards struct sock_fprog's memory
// layout — the value InstallConnectUserNotifyFilter passes a raw pointer to
// in the SYS_SECCOMP syscall, so a layout drift here would corrupt what the
// kernel reads as the filter length and pointer without returning any Go
// compile error.
func TestSockFprogLayoutMatchesKernelABI(t *testing.T) {
	var f sockFprog
	// struct sock_fprog { unsigned short len; struct sock_filter *filter; }
	// On a 64-bit target: 2-byte len, 6-byte compiler pad, 8-byte pointer.
	if got, want := unsafe.Sizeof(f), uintptr(16); got != want {
		t.Errorf("unsafe.Sizeof(sockFprog{}) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(f.Filter), uintptr(8); got != want {
		t.Errorf("unsafe.Offsetof(sockFprog{}.Filter) = %d, want %d", got, want)
	}
}

// runClassicBPF is a minimal classic-BPF (cBPF) interpreter supporting only
// the instruction subset connectNotifyFilterProgram emits (BPF_LD|W|ABS,
// BPF_JMP|JEQ|K, BPF_RET|K) — enough to prove the assembled filter's actual
// decision logic against synthetic seccomp_data inputs the way the kernel
// itself would evaluate it, independent of re-deriving the same instruction
// literals the implementation under test uses.
func runClassicBPF(t *testing.T, prog []sockFilter, data seccompData) uint32 {
	t.Helper()
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&data)), unsafe.Sizeof(data))
	var a uint32
	pc := 0
	for steps := 0; ; steps++ {
		if steps > 100 {
			t.Fatal("BPF interpreter: too many steps, probable infinite loop in the program under test")
		}
		if pc < 0 || pc >= len(prog) {
			t.Fatalf("program counter %d out of range (program length %d)", pc, len(prog))
		}
		ins := prog[pc]
		switch ins.Code {
		case bpfLd | bpfW | bpfAbs:
			if int(ins.K)+4 > len(raw) {
				t.Fatalf("BPF_LD|W|ABS at pc=%d: offset %d out of range (seccomp_data is %d bytes)", pc, ins.K, len(raw))
			}
			a = binary.NativeEndian.Uint32(raw[ins.K : ins.K+4])
			pc++
		case bpfJmp | bpfJeq | bpfK:
			if a == ins.K {
				pc += 1 + int(ins.Jt)
			} else {
				pc += 1 + int(ins.Jf)
			}
		case bpfRet | bpfK:
			return ins.K
		default:
			t.Fatalf("unsupported instruction code %#x at pc=%d (interpreter only implements what connectNotifyFilterProgram emits)", ins.Code, pc)
		}
	}
}

// TestConnectNotifyFilterProgram_DecisionLogic runs the actual assembled
// filter program against synthetic seccomp_data through runClassicBPF,
// proving the three-way decision the package doc comment documents:
// mismatched arch always kills the process (closing the 32-bit-compat
// syscall bypass) regardless of nr; matching arch + connect's nr traps to
// USER_NOTIF; matching arch + any other nr is allowed through untouched.
func TestConnectNotifyFilterProgram_DecisionLogic(t *testing.T) {
	arch, err := nativeSeccompAuditArch()
	if err != nil {
		t.Fatalf("nativeSeccompAuditArch: %v", err)
	}
	const connectNr = 1000
	const otherNr = 1001
	const wrongArch = 0xdeadbeef

	prog := connectNotifyFilterProgram(arch, connectNr)
	if len(prog) == 0 {
		t.Fatal("connectNotifyFilterProgram returned an empty program")
	}

	cases := []struct {
		name string
		data seccompData
		want uint32
	}{
		{"matching arch and connect nr traps to USER_NOTIF", seccompData{Nr: connectNr, Arch: arch}, seccompRetUserNotif},
		{"matching arch, unrelated nr is allowed", seccompData{Nr: otherNr, Arch: arch}, seccompRetAllow},
		{"mismatched arch kills even for connect's own nr", seccompData{Nr: connectNr, Arch: wrongArch}, seccompRetKillProcess},
		{"mismatched arch kills for an unrelated nr too", seccompData{Nr: otherNr, Arch: wrongArch}, seccompRetKillProcess},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runClassicBPF(t, prog, tc.data)
			if got != tc.want {
				t.Errorf("got return value %#x, want %#x", got, tc.want)
			}
		})
	}
}

// TestConnectNotifyFilterProgram_StructuralShape is a coarser guard on top
// of the decision-logic test: exactly 7 instructions, and every instruction
// is one of the three opcodes the interpreter above (and the real kernel
// classic-BPF verifier) expects from this filter — an unexpected opcode
// creeping in would either be rejected by the kernel's BPF verifier at
// filter-install time or silently change behavior, neither of which the
// decision-logic test alone would necessarily catch if it happened to
// preserve the four decisions already exercised there.
func TestConnectNotifyFilterProgram_StructuralShape(t *testing.T) {
	prog := connectNotifyFilterProgram(auditArchX86_64, 42)
	if len(prog) != 7 {
		t.Fatalf("len(prog) = %d, want 7", len(prog))
	}
	allowedCodes := map[uint16]bool{
		bpfLd | bpfW | bpfAbs:  true,
		bpfJmp | bpfJeq | bpfK: true,
		bpfRet | bpfK:          true,
	}
	for i, ins := range prog {
		if !allowedCodes[ins.Code] {
			t.Errorf("prog[%d].Code = %#x, not one of the expected LD|W|ABS / JMP|JEQ|K / RET|K opcodes", i, ins.Code)
		}
	}
	// The final instruction is unconditionally reachable only via a jump
	// (nothing falls through to it), and must be the fail-closed
	// KILL_PROCESS terminator.
	last := prog[len(prog)-1]
	if last.Code != bpfRet|bpfK || last.K != seccompRetKillProcess {
		t.Errorf("final instruction = %+v, want RET|K KILL_PROCESS", last)
	}
}

// TestBuildSeccompNotifResp_NegatesErrno is a regression test for a bug
// caught only by the E4 kernel-in-loop verification (not by any prior pure-Go
// or structural test): the kernel's seccomp_notif_resp.error field uses the
// raw syscall-return convention (a *negative* -errno), unlike every other
// errno in this codebase (positive, e.g. unix.EPERM). Passing a positive
// value there doesn't deny the syscall — the kernel treats a non-negative
// raw return as success, so a policy-denied connect() was silently let
// through with a nonsense return value until this was found and fixed.
func TestBuildSeccompNotifResp_NegatesErrno(t *testing.T) {
	resp := buildSeccompNotifResp(42, -1, int32(unix.EPERM), false)
	if resp.Error != -int32(unix.EPERM) {
		t.Errorf("resp.Error = %d, want %d (negated EPERM — the kernel's raw syscall-return convention)", resp.Error, -int32(unix.EPERM))
	}
	if resp.Error >= 0 {
		t.Fatal("resp.Error is non-negative: the kernel would treat this as success, not a denial")
	}
	if resp.ID != 42 {
		t.Errorf("resp.ID = %d, want 42", resp.ID)
	}
	if resp.Flags != 0 {
		t.Errorf("resp.Flags = %#x, want 0 (continueSyscall=false)", resp.Flags)
	}
}

func TestBuildSeccompNotifResp_ContinueSetsFlagAndLeavesErrnoUnnegatedZero(t *testing.T) {
	resp := buildSeccompNotifResp(7, 0, 0, true)
	if resp.Flags != seccompUserNotifFlagContinue {
		t.Errorf("resp.Flags = %#x, want SECCOMP_USER_NOTIF_FLAG_CONTINUE (%#x)", resp.Flags, seccompUserNotifFlagContinue)
	}
	if resp.Error != 0 {
		t.Errorf("resp.Error = %d, want 0", resp.Error)
	}
}

// TestConnectNotifyFilterProgram_DifferentInputsProduceDifferentPrograms is
// a sanity check that nativeArch/connectNr actually parameterize the
// program rather than being ignored constants baked in elsewhere.
func TestConnectNotifyFilterProgram_DifferentInputsProduceDifferentPrograms(t *testing.T) {
	a := connectNotifyFilterProgram(auditArchX86_64, 42)
	b := connectNotifyFilterProgram(auditArchAarch64, 42)
	if reflect.DeepEqual(a, b) {
		t.Error("programs for different nativeArch values are identical, want the arch-check instruction's K to differ")
	}
	c := connectNotifyFilterProgram(auditArchX86_64, 99)
	if reflect.DeepEqual(a, c) {
		t.Error("programs for different connectNr values are identical, want the nr-check instruction's K to differ")
	}
}
