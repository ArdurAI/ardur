package kernelcapture

// The optional launcher observer is generated separately so its BPF-LSM
// program is loaded only when launcher fingerprints are configured.
//go:generate sh -c "go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel launcherIdentity launcher_identity.bpf.c -- -I/usr/include -I/usr/include/$(uname -m)-linux-gnu"
