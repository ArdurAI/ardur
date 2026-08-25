package kernelcapture

// The extra -I/usr/include/$(uname -m)-linux-gnu resolves <asm/types.h> etc.
// on Debian/Ubuntu, where clang's implicit header search for a foreign
// -target bpf doesn't include the host's multiarch uapi header directory.
//go:generate sh -c "go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel processGuard process_guard.bpf.c -- -I/usr/include -I/usr/include/$(uname -m)-linux-gnu"
