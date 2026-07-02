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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// ProcessGuardHandles holds the loaded BPF objects for the process_guard program.
// Call LoadAndAttachProcessGuardEBPF to obtain one; call Close when done.
//
// The *ProgID fields record the program each link was attached to at load
// time, for AuditLinks' tamper-drift comparison (tamper_audit.go) — see that
// file's header comment for the claim boundary of what this can and cannot
// detect.
type ProcessGuardHandles struct {
	objs           processGuardObjects
	bprmLink       link.Link
	fileOpenLink   link.Link
	socketConnLink link.Link
	reader         *ringbuf.Reader

	bprmProgID       ebpf.ProgramID
	fileOpenProgID   ebpf.ProgramID
	socketConnProgID ebpf.ProgramID
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
	if h.bprmProgID, err = attachedProgramID(h.objs.GuardBprmCheck); err != nil {
		h.bprmLink.Close()
		h.objs.Close()
		return nil, fmt.Errorf("kernelcapture: read program id for lsm/bprm_check_security: %w", err)
	}

	h.fileOpenLink, err = link.AttachLSM(link.LSMOptions{
		Program: h.objs.GuardFileOpen,
	})
	if err != nil {
		h.bprmLink.Close()
		h.objs.Close()
		return nil, fmt.Errorf("kernelcapture: attach lsm.s/file_open: %w", err)
	}
	if h.fileOpenProgID, err = attachedProgramID(h.objs.GuardFileOpen); err != nil {
		h.fileOpenLink.Close()
		h.bprmLink.Close()
		h.objs.Close()
		return nil, fmt.Errorf("kernelcapture: read program id for lsm.s/file_open: %w", err)
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
	if h.socketConnProgID, err = attachedProgramID(h.objs.GuardSocketConnect); err != nil {
		h.socketConnLink.Close()
		h.fileOpenLink.Close()
		h.bprmLink.Close()
		h.objs.Close()
		return nil, fmt.Errorf("kernelcapture: read program id for lsm/socket_connect: %w", err)
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

// attachedProgramID reads back the kernel-assigned ID for prog immediately
// after a successful attach, so AuditLinks has a known-good baseline to
// compare future ticks against.
func attachedProgramID(prog *ebpf.Program) (ebpf.ProgramID, error) {
	info, err := prog.Info()
	if err != nil {
		return 0, fmt.Errorf("program info: %w", err)
	}
	id, ok := info.ID()
	if !ok {
		return 0, fmt.Errorf("program id unavailable (requires a Linux kernel that reports it)")
	}
	return id, nil
}

// AuditLinks satisfies GuardLinkAuditor: it re-verifies each of the three
// held LSM links still reports the program it was attached to at load time.
// See tamper_audit.go for the claim boundary of what this detects.
func (h *ProcessGuardHandles) AuditLinks() []TamperCheckResult {
	checks := []struct {
		name     string
		l        link.Link
		expected ebpf.ProgramID
	}{
		{"link:bprm_check_security", h.bprmLink, h.bprmProgID},
		{"link:file_open", h.fileOpenLink, h.fileOpenProgID},
		{"link:socket_connect", h.socketConnLink, h.socketConnProgID},
	}
	results := make([]TamperCheckResult, 0, len(checks))
	for _, c := range checks {
		results = append(results, auditGuardLink(c.name, c.l, c.expected))
	}
	return results
}

func auditGuardLink(name string, l link.Link, expected ebpf.ProgramID) TamperCheckResult {
	if l == nil {
		return TamperCheckResult{Name: name, OK: false, Detail: "link handle is nil (guard was never fully attached)"}
	}
	info, err := l.Info()
	if err != nil {
		return TamperCheckResult{
			Name: name, OK: false,
			Detail: fmt.Sprintf("link.Info() failed: %v (link may have been closed or force-detached externally)", err),
		}
	}
	if info.Program != expected {
		return TamperCheckResult{
			Name: name, OK: false,
			Detail: fmt.Sprintf("program id drifted: attached=%d now=%d (link was likely force-detached, possibly reattached to a different program)", expected, info.Program),
		}
	}
	return TamperCheckResult{Name: name, OK: true, Detail: fmt.Sprintf("program id %d unchanged", expected)}
}

// AuditKillSwitch satisfies GuardLinkAuditor: it re-reads the kill_switch map
// and reports drift if the value does not match expectedEngaged, the state
// the daemon itself last set (see daemon.expectedKillSwitchEngaged in
// ardur-kernelcaptured).
func (h *ProcessGuardHandles) AuditKillSwitch(expectedEngaged bool) TamperCheckResult {
	const name = "kill_switch"
	if h.objs.KillSwitch == nil {
		return TamperCheckResult{Name: name, OK: false, Detail: "kill_switch map handle is nil"}
	}
	idx := uint32(KillSwitchIndex)
	var v uint32
	if err := h.objs.KillSwitch.Lookup(&idx, &v); err != nil {
		return TamperCheckResult{Name: name, OK: false, Detail: fmt.Sprintf("lookup failed: %v", err)}
	}
	engaged := v != 0
	if engaged != expectedEngaged {
		return TamperCheckResult{
			Name: name, OK: false,
			Detail: fmt.Sprintf("expected engaged=%v, found engaged=%v (map may have been written outside set_kill_switch)", expectedEngaged, engaged),
		}
	}
	return TamperCheckResult{Name: name, OK: true, Detail: fmt.Sprintf("engaged=%v matches expected state", engaged)}
}
