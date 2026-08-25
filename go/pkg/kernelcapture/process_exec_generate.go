package kernelcapture

// See process_guard_generate.go for why the multiarch -I is needed.
//go:generate sh -c "go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel processExec process_exec.bpf.c -- -I/usr/include -I/usr/include/$(uname -m)-linux-gnu"
