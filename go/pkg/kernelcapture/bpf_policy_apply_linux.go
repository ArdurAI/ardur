//go:build linux

package kernelcapture

// bpf_policy_apply_linux.go — loads the process_guard BPF-LSM program and
// exposes its maps through the platform-neutral PolicyMaps type (defined in
// bpf_policy_apply.go, which holds all of the actual map-write logic).
//
// This file is compiled only on Linux because it references processGuardMaps
// from the bpf2go-generated processguard_bpfel.go (which must be present
// after running `go generate ./go/pkg/kernelcapture/...` on a Linux host with
// clang and Linux kernel headers installed).

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// ProcessGuardHandles holds the loaded BPF objects for the process_guard program.
// Call LoadAndAttachProcessGuardEBPF to obtain one; call Close when done.
type ProcessGuardHandles struct {
	objs           processGuardObjects
	bprmLink       link.Link
	fileOpenLink   link.Link
	socketConnLink link.Link
	reader         *ringbuf.Reader
}

// Reader returns the ringbuf reader for enforce_events. The caller must not
// close it independently; Close() on the handles cleans it up.
func (h *ProcessGuardHandles) Reader() *ringbuf.Reader { return h.reader }

// Close releases all BPF objects in reverse-acquisition order.
func (h *ProcessGuardHandles) Close() {
	if h.reader != nil {
		h.reader.Close()
	}
	if h.socketConnLink != nil {
		h.socketConnLink.Close()
	}
	if h.fileOpenLink != nil {
		h.fileOpenLink.Close()
	}
	if h.bprmLink != nil {
		h.bprmLink.Close()
	}
	h.objs.Close()
}

// PolicyMapsFromHandles extracts the writable map set from loaded handles.
// *ebpf.Map satisfies policyMapWriter/policyMapReadWriter structurally, so no
// adapter/wrapper is needed here.
func PolicyMapsFromHandles(h *ProcessGuardHandles) PolicyMaps {
	return PolicyMaps{
		CgroupOpPolicy:  h.objs.CgroupOpPolicy,
		CgroupPathAllow: h.objs.CgroupPathAllow,
		CgroupFileAllow: h.objs.CgroupFileAllow,
		CgroupNetAllow:  h.objs.CgroupNetAllow,
		CgroupManaged:   h.objs.CgroupManaged,
		KillSwitch:      h.objs.KillSwitch,
	}
}

// LoadAndAttachProcessGuardEBPF loads the process_guard BPF object, attaches
// the three LSM hooks, and opens the enforce_events ringbuf reader.
//
// Requires CAP_BPF (or CAP_SYS_ADMIN on older kernels), CONFIG_BPF_LSM=y,
// and "bpf" listed in /sys/kernel/security/lsm (or the lsm= kernel cmdline).
func LoadAndAttachProcessGuardEBPF() (*ProcessGuardHandles, error) {
	h := &ProcessGuardHandles{}

	if err := loadProcessGuardObjects(&h.objs, nil); err != nil {
		return nil, fmt.Errorf("kernelcapture: load process_guard objects: %w", err)
	}

	var err error
	h.bprmLink, err = link.AttachLSM(link.LSMOptions{
		Program: h.objs.GuardBprmCheck,
	})
	if err != nil {
		h.objs.Close()
		return nil, fmt.Errorf("kernelcapture: attach lsm/bprm_check_security: %w", err)
	}

	h.fileOpenLink, err = link.AttachLSM(link.LSMOptions{
		Program: h.objs.GuardFileOpen,
	})
	if err != nil {
		h.bprmLink.Close()
		h.objs.Close()
		return nil, fmt.Errorf("kernelcapture: attach lsm.s/file_open: %w", err)
	}

	h.socketConnLink, err = link.AttachLSM(link.LSMOptions{
		Program: h.objs.GuardSocketConnect,
	})
	if err != nil {
		h.fileOpenLink.Close()
		h.bprmLink.Close()
		h.objs.Close()
		return nil, fmt.Errorf("kernelcapture: attach lsm/socket_connect: %w", err)
	}

	h.reader, err = ringbuf.NewReader(h.objs.EnforceEvents)
	if err != nil {
		h.socketConnLink.Close()
		h.fileOpenLink.Close()
		h.bprmLink.Close()
		h.objs.Close()
		return nil, fmt.Errorf("kernelcapture: open enforce_events ringbuf: %w", err)
	}

	return h, nil
}
