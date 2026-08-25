//go:build !linux

package kernelcapture

// KernelCapReport holds the result of all preflight kernel capability checks.
type KernelCapReport struct {
	Findings   []KernelCapFinding
	CanInstall bool
}

// KernelCapFinding is the result of one preflight check.
type KernelCapFinding struct {
	Check  string
	OK     bool
	Detail string
}

// CheckKernelCapabilities always returns CanInstall=false on non-Linux platforms.
// The eBPF capture backend and systemd service are Linux-only.
func CheckKernelCapabilities() KernelCapReport {
	return KernelCapReport{
		CanInstall: false,
		Findings: []KernelCapFinding{
			{Check: "platform", OK: false, Detail: "kernel capability checks require Linux"},
		},
	}
}
