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
	"io"
	"os"
	"path/filepath"

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

// DroppedEventsMap returns the enforce_events_dropped counter map (issue #122):
// a single-slot BPF_MAP_TYPE_ARRAY the BPF program increments with an atomic
// add every time a ringbuf reserve fails, i.e. every enforcement event the
// kernel decided but could not deliver to userspace. The daemon reads this to
// report kernel-side drops the ringbuf's own LostSamples (a ring-full count the
// verifier reports only on some kernels) does not surface. May be nil on the
// error paths that never populate objs; callers must nil-check.
func (h *ProcessGuardHandles) DroppedEventsMap() *ebpf.Map { return h.objs.EnforceEventsDropped }

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
// Requires BPF syscall authority via effective CAP_BPF/CAP_SYS_ADMIN (the
// supported Ardur installer path) or an explicitly delegated BPF token,
// plus CONFIG_BPF_LSM=y and "bpf" listed in /sys/kernel/security/lsm.
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

// PinnedGuardPaths holds the bpffs paths used for pinning the process_guard
// BPF-LSM links and its policy-state maps (issue #124).
//
// Unlike the process-exec tracepoint (PinnedEBPFPaths: 2 links + ringbuf +
// producer-drop counter), the durable guard state has three LSM links and eight
// maps: six policy maps plus the enforce_events ringbuf and its drop counter
// (enforce_events_dropped, issue #122). The three additional per-CPU scratch
// maps (file_allow_scratch, net_lpm_scratch, path_lpm_scratch) are working
// memory the BPF program repopulates on every invocation; they carry no state
// worth preserving across a restart and are safe to recreate empty on every
// load.
type PinnedGuardPaths struct {
	BprmLinkPath       string
	FileOpenLinkPath   string
	SocketConnLinkPath string

	CgroupOpPolicyPath  string
	CgroupPathAllowPath string
	CgroupFileAllowPath string
	CgroupNetAllowPath  string
	CgroupManagedPath   string
	KillSwitchPath      string
	EnforceEventsPath   string
	// EnforceEventsDroppedPath pins the enforce_events_dropped counter map
	// (issue #122). The BPF program increments it whenever a ringbuf reserve
	// fails, so a restarted daemon can keep reading a monotonic drop total the
	// still-attached programs never reset — without a pin the fresh reload would
	// see a zeroed map and under-report kernel-side drops as it does today.
	EnforceEventsDroppedPath string
}

// allPaths returns every pin path, for the "ensure directory, then pin"
// and "load every pin, all-or-nothing" loops below.
func (p PinnedGuardPaths) allPaths() []string {
	return []string{
		p.BprmLinkPath, p.FileOpenLinkPath, p.SocketConnLinkPath,
		p.CgroupOpPolicyPath, p.CgroupPathAllowPath, p.CgroupFileAllowPath,
		p.CgroupNetAllowPath, p.CgroupManagedPath, p.KillSwitchPath,
		p.EnforceEventsPath, p.EnforceEventsDroppedPath,
	}
}

// DefaultPinnedGuardPaths returns the standard bpffs pin paths under the
// ardur-owned bpffs namespace (/sys/fs/bpf/ardur/), alongside
// DefaultPinnedEBPFPaths' tracepoint pins.
func DefaultPinnedGuardPaths() PinnedGuardPaths {
	const base = "/sys/fs/bpf/ardur/"
	return PinnedGuardPaths{
		BprmLinkPath:        base + "guard_bprm_link",
		FileOpenLinkPath:    base + "guard_file_open_link",
		SocketConnLinkPath:  base + "guard_socket_connect_link",
		CgroupOpPolicyPath:  base + "cgroup_op_policy",
		CgroupPathAllowPath: base + "cgroup_path_allow",
		CgroupFileAllowPath: base + "cgroup_file_allow",
		CgroupNetAllowPath:  base + "cgroup_net_allow",
		CgroupManagedPath:   base + "cgroup_managed",
		KillSwitchPath:      base + "kill_switch",
		EnforceEventsPath:   base + "enforce_events",

		EnforceEventsDroppedPath: base + "enforce_events_dropped",
	}
}

// LoadAndAttachProcessGuardEBPFPinned is like LoadAndAttachProcessGuardEBPF
// but adds BPF link- and map-pinning for restart survival (issue #124: prior
// to this, every daemon restart detached the guard's LSM hooks and dropped
// every applied policy — cgroup_managed, cgroup_op_policy, etc. all rebuilt
// empty — so a governed agent ran completely unenforced from the moment the
// daemon process exited until apply_policy was called again, if ever).
//
// On first start (no pinned state at paths): loads and attaches the eBPF
// program as usual (LoadAndAttachProcessGuardEBPF), then pins all three LSM
// links and the six policy-state maps (+ the enforce_events ringbuf map and
// its enforce_events_dropped drop counter) to bpffs. The pinned links keep the
// LSM hooks — and thus enforcement — live in
// the kernel even after this daemon process exits; the pinned maps keep every
// applied policy's contents intact, so there is nothing to "re-apply" after a
// restart that successfully reuses these pins: the kernel never stopped
// enforcing what was already applied.
//
// On restart (all eleven pins present): loads them back without re-attaching or
// re-applying anything, matching the tracepoint's restart path. The three LSM
// programs have been continuously attached and enforcing in the kernel since
// the prior daemon start; this call just re-establishes this process's
// userspace handle on that unbroken state, including a fresh ringbuf.Reader
// bound to the exact (still-being-written-to) enforce_events map.
//
// If any pin is missing (a prior pin attempt partially failed, or this is
// truly the first start), the pinned state is treated as unusable in its
// entirety and this falls back to a fresh load/attach/pin — never a partial
// reuse, which could bind a reader or policy write path to inconsistent state.
//
// If pinning itself fails (e.g. bpffs not mounted, insufficient permissions),
// the function returns the handles without pins and logs nothing itself (the
// caller — runGuardConsumer — already logs guard-load outcomes); the daemon
// still enforces for this run, it just loses the restart-survival property,
// identical to the tracepoint's accepted degradation in that case.
//
// Caller must call Close on the returned handles when done. Close does NOT
// remove the bpffs pins; call RemovePinnedGuardState to do that explicitly.
func LoadAndAttachProcessGuardEBPFPinned(paths PinnedGuardPaths) (*ProcessGuardHandles, error) {
	if h, ok := tryLoadPinnedGuardState(paths); ok {
		return h, nil
	}

	h, err := LoadAndAttachProcessGuardEBPF()
	if err != nil {
		return nil, err
	}

	// Each pin is independently non-fatal: a partial pin set (e.g. links
	// pinned but a map pin fails) makes tryLoadPinnedGuardState fail on the
	// next restart — by design, since it requires all eleven — falling back to
	// this fresh-load path again rather than reusing inconsistent state.
	pins := []struct {
		path string
		pin  func(string) error
	}{
		{paths.BprmLinkPath, h.bprmLink.Pin},
		{paths.FileOpenLinkPath, h.fileOpenLink.Pin},
		{paths.SocketConnLinkPath, h.socketConnLink.Pin},
		{paths.CgroupOpPolicyPath, h.objs.CgroupOpPolicy.Pin},
		{paths.CgroupPathAllowPath, h.objs.CgroupPathAllow.Pin},
		{paths.CgroupFileAllowPath, h.objs.CgroupFileAllow.Pin},
		{paths.CgroupNetAllowPath, h.objs.CgroupNetAllow.Pin},
		{paths.CgroupManagedPath, h.objs.CgroupManaged.Pin},
		{paths.KillSwitchPath, h.objs.KillSwitch.Pin},
		{paths.EnforceEventsPath, h.objs.EnforceEvents.Pin},
		{paths.EnforceEventsDroppedPath, h.objs.EnforceEventsDropped.Pin},
	}
	for _, p := range pins {
		if mkErr := os.MkdirAll(filepath.Dir(p.path), 0o700); mkErr == nil {
			_ = p.pin(p.path)
		}
	}

	return h, nil
}

// RemovePinnedGuardState removes every bpffs pin in paths, if present. Used
// to force a truly fresh load (e.g. an operator-invoked "unstick" path) —
// not called anywhere in the normal daemon lifecycle.
func RemovePinnedGuardState(paths PinnedGuardPaths) {
	for _, p := range paths.allPaths() {
		_ = os.Remove(p)
	}
}

// tryLoadPinnedGuardState attempts to load all three LSM links and all eight
// (six policy + enforce_events + its drop counter) maps from bpffs. Returns
// ok=true only if every one of the eleven succeeds; otherwise it closes any
// partially-opened
// handles and returns ok=false so the caller falls back to a fresh
// load/attach/pin rather than binding a reader or policy maps to inconsistent
// state (e.g. links attached but pointing at maps this process never
// verified are the matching generation).
func tryLoadPinnedGuardState(paths PinnedGuardPaths) (*ProcessGuardHandles, bool) {
	var opened []io.Closer
	closeAll := func() {
		for i := len(opened) - 1; i >= 0; i-- {
			opened[i].Close()
		}
	}

	loadLink := func(path string) (link.Link, bool) {
		l, err := link.LoadPinnedLink(path, nil)
		if err != nil {
			return nil, false
		}
		opened = append(opened, l)
		return l, true
	}
	loadMap := func(path string) (*ebpf.Map, bool) {
		m, err := ebpf.LoadPinnedMap(path, nil)
		if err != nil {
			return nil, false
		}
		opened = append(opened, m)
		return m, true
	}

	bprmLink, ok := loadLink(paths.BprmLinkPath)
	if !ok {
		closeAll()
		return nil, false
	}
	fileOpenLink, ok := loadLink(paths.FileOpenLinkPath)
	if !ok {
		closeAll()
		return nil, false
	}
	socketConnLink, ok := loadLink(paths.SocketConnLinkPath)
	if !ok {
		closeAll()
		return nil, false
	}

	cgroupOpPolicy, ok := loadMap(paths.CgroupOpPolicyPath)
	if !ok {
		closeAll()
		return nil, false
	}
	cgroupPathAllow, ok := loadMap(paths.CgroupPathAllowPath)
	if !ok {
		closeAll()
		return nil, false
	}
	cgroupFileAllow, ok := loadMap(paths.CgroupFileAllowPath)
	if !ok {
		closeAll()
		return nil, false
	}
	cgroupNetAllow, ok := loadMap(paths.CgroupNetAllowPath)
	if !ok {
		closeAll()
		return nil, false
	}
	cgroupManaged, ok := loadMap(paths.CgroupManagedPath)
	if !ok {
		closeAll()
		return nil, false
	}
	killSwitch, ok := loadMap(paths.KillSwitchPath)
	if !ok {
		closeAll()
		return nil, false
	}
	enforceEvents, ok := loadMap(paths.EnforceEventsPath)
	if !ok {
		closeAll()
		return nil, false
	}
	enforceEventsDropped, ok := loadMap(paths.EnforceEventsDroppedPath)
	if !ok {
		closeAll()
		return nil, false
	}

	bprmProgID, err := linkProgramID(bprmLink)
	if err != nil {
		closeAll()
		return nil, false
	}
	fileOpenProgID, err := linkProgramID(fileOpenLink)
	if err != nil {
		closeAll()
		return nil, false
	}
	socketConnProgID, err := linkProgramID(socketConnLink)
	if err != nil {
		closeAll()
		return nil, false
	}

	reader, err := ringbuf.NewReader(enforceEvents)
	if err != nil {
		closeAll()
		return nil, false
	}

	h := &ProcessGuardHandles{
		bprmLink:         bprmLink,
		fileOpenLink:     fileOpenLink,
		socketConnLink:   socketConnLink,
		bprmProgID:       bprmProgID,
		fileOpenProgID:   fileOpenProgID,
		socketConnProgID: socketConnProgID,
		reader:           reader,
	}
	h.objs.CgroupOpPolicy = cgroupOpPolicy
	h.objs.CgroupPathAllow = cgroupPathAllow
	h.objs.CgroupFileAllow = cgroupFileAllow
	h.objs.CgroupNetAllow = cgroupNetAllow
	h.objs.CgroupManaged = cgroupManaged
	h.objs.KillSwitch = killSwitch
	h.objs.EnforceEvents = enforceEvents
	h.objs.EnforceEventsDropped = enforceEventsDropped
	// processGuardPrograms fields are left at their zero value (nil
	// *ebpf.Program): cilium/ebpf's Program.Close() and Map.Close() are both
	// nil-receiver-safe, so ProcessGuardHandles.Close() -> objs.Close() works
	// unchanged; nothing on the restart-reuse path needs the *ebpf.Program
	// handles themselves, only the program IDs already captured above via
	// each pinned link's own Info().
	return h, true
}

// linkProgramID reads back the program ID a pinned link currently reports
// itself attached to — the restart-path equivalent of attachedProgramID,
// which needs a live *ebpf.Program this path never loads. Using the link's
// own Info() instead is exactly as trustworthy: it is the same call
// AuditLinks later uses to detect drift, just invoked once here to establish
// the post-restart baseline.
func linkProgramID(l link.Link) (ebpf.ProgramID, error) {
	info, err := l.Info()
	if err != nil {
		return 0, fmt.Errorf("link info: %w", err)
	}
	return info.Program, nil
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
