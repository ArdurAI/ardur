//go:build !linux

package kernelcapture

// bpf_policy_apply_unsupported.go — stub for non-Linux platforms.
//
// Only the BPF program loading path is platform-specific; ApplyPolicyMaps /
// RemovePolicyMaps / SetKillSwitch (bpf_policy_apply.go) run unmodified here
// too — PolicyMapsFromHandles returns the zero PolicyMaps{}, so
// policyMapsReady is false and those calls return ErrPolicyMapsUnavailable
// cleanly, the same way they do on a Linux host where BPF-LSM never loaded.

import "fmt"

// ProcessGuardHandles is an opaque stub on unsupported platforms.
type ProcessGuardHandles struct{}

// Close is a no-op on unsupported platforms.
func (h *ProcessGuardHandles) Close() {}

// PolicyMapsFromHandles returns a zero-value stub.
func PolicyMapsFromHandles(_ *ProcessGuardHandles) PolicyMaps { return PolicyMaps{} }

// LoadAndAttachProcessGuardEBPF always returns an error on unsupported platforms.
func LoadAndAttachProcessGuardEBPF() (*ProcessGuardHandles, error) {
	return nil, fmt.Errorf("kernelcapture: process_guard BPF-LSM is not supported on this platform")
}
