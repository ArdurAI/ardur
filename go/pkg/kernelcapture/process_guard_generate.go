package kernelcapture

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel processGuard process_guard.bpf.c -- -I/usr/include
