//go:build !linux

package kernelcapture

// bpf_policy_apply_unsupported.go — stub for non-Linux platforms.
//
// BPF map writes require Linux; these types and functions exist solely so that
// non-Linux builds (macOS CI, unit tests) can import the package without
// resolution errors for the shared protocol types defined in daemon_protocol.go.

import "fmt"

// ProcessGuardHandles is an opaque stub on unsupported platforms.
type ProcessGuardHandles struct{}

// Close is a no-op on unsupported platforms.
func (h *ProcessGuardHandles) Close() {}

// PolicyMaps is an opaque stub on unsupported platforms.
type PolicyMaps struct{}

// PolicyMapsFromHandles returns a zero-value stub.
func PolicyMapsFromHandles(_ *ProcessGuardHandles) PolicyMaps { return PolicyMaps{} }

// LoadAndAttachProcessGuardEBPF always returns an error on unsupported platforms.
func LoadAndAttachProcessGuardEBPF() (*ProcessGuardHandles, error) {
	return nil, fmt.Errorf("kernelcapture: process_guard BPF-LSM is not supported on this platform")
}

// ApplyPolicyMaps always returns an error on unsupported platforms.
func ApplyPolicyMaps(_ PolicyMaps, _ uint64, _ DaemonApplyPolicyRequest) error {
	return fmt.Errorf("kernelcapture: BPF policy maps are not supported on this platform")
}

// RemovePolicyMaps always returns an error on unsupported platforms.
func RemovePolicyMaps(_ PolicyMaps, _ uint64) error {
	return fmt.Errorf("kernelcapture: BPF policy maps are not supported on this platform")
}

// SetKillSwitch always returns an error on unsupported platforms.
func SetKillSwitch(_ PolicyMaps, _ bool) error {
	return fmt.Errorf("kernelcapture: kill_switch map is not supported on this platform")
}
