package kernelcapture

// seccomp_sockaddr_test.go — unit tests for ParseConnectSockaddr
// (seccomp_sockaddr.go), the seccomp tier's connect(2) sockaddr decoder.
// Pure Go, no build tag, no kernel dependency: these exercise the decoder
// against synthetic byte buffers shaped like what ReadTargetSockaddr
// (seccomp_notify_linux.go, Linux-only) hands it at runtime.

import (
	"encoding/binary"
	"net"
	"testing"
)

func buildSockaddrIn(family, port uint16, ip [4]byte) []byte {
	buf := make([]byte, sockaddrInLen)
	binary.NativeEndian.PutUint16(buf[0:2], family)
	binary.BigEndian.PutUint16(buf[2:4], port)
	copy(buf[4:8], ip[:])
	return buf
}

func buildSockaddrIn6(family, port uint16, ip [16]byte) []byte {
	buf := make([]byte, sockaddrIn6Len)
	binary.NativeEndian.PutUint16(buf[0:2], family)
	binary.BigEndian.PutUint16(buf[2:4], port)
	copy(buf[8:8+16], ip[:])
	return buf
}

func TestParseConnectSockaddr_IPv4(t *testing.T) {
	raw := buildSockaddrIn(linuxAFInet, 443, [4]byte{93, 184, 216, 34})
	ip, port, err := ParseConnectSockaddr(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if port != 443 {
		t.Errorf("port = %d, want 443", port)
	}
	want := net.IPv4(93, 184, 216, 34)
	if !ip.Equal(want) {
		t.Errorf("ip = %v, want %v", ip, want)
	}
}

func TestParseConnectSockaddr_IPv4ExactLengthBoundary(t *testing.T) {
	raw := buildSockaddrIn(linuxAFInet, 80, [4]byte{10, 0, 0, 1})
	if len(raw) != sockaddrInLen {
		t.Fatalf("test setup: raw len = %d, want exactly %d", len(raw), sockaddrInLen)
	}
	if _, _, err := ParseConnectSockaddr(raw); err != nil {
		t.Errorf("exact-length sockaddr_in rejected: %v", err)
	}
}

func TestParseConnectSockaddr_IPv6(t *testing.T) {
	var addr [16]byte
	addr[0], addr[1] = 0x20, 0x01 // 2001:db8::1
	addr[2], addr[3] = 0x0d, 0xb8
	addr[15] = 0x01
	raw := buildSockaddrIn6(linuxAFInet6, 8443, addr)
	ip, port, err := ParseConnectSockaddr(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if port != 8443 {
		t.Errorf("port = %d, want 8443", port)
	}
	want := net.IP(addr[:])
	if !ip.Equal(want) {
		t.Errorf("ip = %v, want %v", ip, want)
	}
}

func TestParseConnectSockaddr_IPv6TrailingBytesIgnored(t *testing.T) {
	var addr [16]byte
	addr[15] = 0x7f
	raw := buildSockaddrIn6(linuxAFInet6, 1234, addr)
	// sockaddr_in6 in the real UAPI carries a trailing sin6_scope_id (4
	// bytes) this decoder doesn't need; a longer-than-minimum buffer must
	// still parse cleanly rather than being rejected as malformed.
	raw = append(raw, 0, 0, 0, 0)
	ip, port, err := ParseConnectSockaddr(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if port != 1234 || !ip.Equal(net.IP(addr[:])) {
		t.Errorf("ip/port = %v/%d, want %v/1234", ip, port, net.IP(addr[:]))
	}
}

func TestParseConnectSockaddr_TooShortForFamily(t *testing.T) {
	for _, n := range []int{0, 1} {
		if _, _, err := ParseConnectSockaddr(make([]byte, n)); err == nil {
			t.Errorf("len=%d: expected error reading sa_family from a too-short buffer, got nil", n)
		}
	}
}

func TestParseConnectSockaddr_TruncatedIPv4Rejected(t *testing.T) {
	full := buildSockaddrIn(linuxAFInet, 443, [4]byte{1, 2, 3, 4})
	for n := 2; n < sockaddrInLen; n++ {
		if _, _, err := ParseConnectSockaddr(full[:n]); err == nil {
			t.Errorf("len=%d: expected truncated sockaddr_in to be rejected, got nil error", n)
		}
	}
}

func TestParseConnectSockaddr_TruncatedIPv6Rejected(t *testing.T) {
	var addr [16]byte
	full := buildSockaddrIn6(linuxAFInet6, 443, addr)
	for n := 2; n < sockaddrIn6Len; n++ {
		if _, _, err := ParseConnectSockaddr(full[:n]); err == nil {
			t.Errorf("len=%d: expected truncated sockaddr_in6 to be rejected, got nil error", n)
		}
	}
}

func TestParseConnectSockaddr_UnsupportedFamily(t *testing.T) {
	const linuxAFUnix = 1
	raw := buildSockaddrIn(linuxAFUnix, 0, [4]byte{})
	if _, _, err := ParseConnectSockaddr(raw); err == nil {
		t.Error("expected an error for an unsupported sa_family, got nil")
	}
}

// TestParseConnectSockaddr_NeverZeroPadsShortReads guards the documented
// "reject, don't zero-pad" contract: a short buffer must never be silently
// treated as a valid (if wrong) address, since that could spuriously match —
// or spuriously miss — an allowlist entry.
func TestParseConnectSockaddr_NeverZeroPadsShortReads(t *testing.T) {
	raw := buildSockaddrIn(linuxAFInet, 443, [4]byte{1, 2, 3, 4})[:sockaddrInLen-1]
	ip, port, err := ParseConnectSockaddr(raw)
	if err == nil {
		t.Fatalf("expected error for a one-byte-short sockaddr_in, got ip=%v port=%d", ip, port)
	}
}
