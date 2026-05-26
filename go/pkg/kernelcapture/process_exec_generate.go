package kernelcapture

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel processExec process_exec.bpf.c -- -I/usr/include
