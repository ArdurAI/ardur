package kernelcapture

// seccomp_sockaddr.go — connect(2) sockaddr decoding for the seccomp
// user-notify enforcement tier (Epic A #63, plan E4).
//
// Pure Go, no build tag: decoding a byte slice already read from the target
// process's memory has no kernel/syscall dependency, so this is testable on
// darwin/CI with synthetic buffers, the same way bpf_policy_apply.go's key
// serialization helpers are. The privileged part — actually reading those
// bytes out of another process's address space, and doing so safely under
// the seccomp-notify TOCTOU constraints — lives in seccomp_notify_linux.go.

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Linux sa_family_t values this tier resolves. Matches <linux/socket.h>.
const (
	linuxAFInet  = 2
	linuxAFInet6 = 10
)

// Linux struct sockaddr_in / sockaddr_in6 sizes (bytes). Both are fixed,
// stable UAPI layouts — see the identical rationale in
// process_guard.bpf.c's guard_socket_connect for the BPF-LSM tier, which
// decodes the same wire shapes via raw offsets for the same reason.
const (
	sockaddrInLen  = 16
	sockaddrIn6Len = 28
)

// ParseConnectSockaddr decodes the raw bytes of a struct sockaddr passed as
// connect(2)'s second argument into an IP address and port.
//
// raw must be at least as long as the family-specific struct — a short read
// is rejected rather than zero-padded. Silently treating a truncated read as
// "the rest is zero" would let a read failure masquerade as a specific (and
// wrong) address, which could then spuriously match — or spuriously miss —
// an allowlist entry. The caller (seccomp_notify_linux.go) is expected to
// fail the connect closed on any error from here, not fall back to a default
// address.
//
// sa_family is native-endian (it's a kernel ABI field read in the same
// process's byte order by definition, unlike sin_port/sin_addr which are
// always network byte order per BSD sockets convention regardless of host
// endianness).
func ParseConnectSockaddr(raw []byte) (net.IP, uint16, error) {
	if len(raw) < 2 {
		return nil, 0, fmt.Errorf("kernelcapture: sockaddr too short to read sa_family: %d byte(s)", len(raw))
	}
	family := binary.NativeEndian.Uint16(raw[0:2])
	switch family {
	case linuxAFInet:
		if len(raw) < sockaddrInLen {
			return nil, 0, fmt.Errorf("kernelcapture: sockaddr_in too short: %d byte(s), want %d", len(raw), sockaddrInLen)
		}
		port := binary.BigEndian.Uint16(raw[2:4])
		ip := net.IPv4(raw[4], raw[5], raw[6], raw[7])
		return ip, port, nil
	case linuxAFInet6:
		if len(raw) < sockaddrIn6Len {
			return nil, 0, fmt.Errorf("kernelcapture: sockaddr_in6 too short: %d byte(s), want %d", len(raw), sockaddrIn6Len)
		}
		port := binary.BigEndian.Uint16(raw[2:4])
		// sin6_family(2) + sin6_port(2) + sin6_flowinfo(4) = offset 8.
		ip := make(net.IP, net.IPv6len)
		copy(ip, raw[8:8+net.IPv6len])
		return ip, port, nil
	default:
		return nil, 0, fmt.Errorf("kernelcapture: unsupported sockaddr family %d (only AF_INET=%d and AF_INET6=%d are policy-evaluable; connect(2) to any other address family is denied by the caller, not allowed by default)",
			family, linuxAFInet, linuxAFInet6)
	}
}
