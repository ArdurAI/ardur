//go:build linux

package kernelcapture

// bpf_policy_apply_linux.go — daemon-side BPF map write path (Linux only).
//
// ApplyPolicyMaps writes one full policy generation into the six BPF maps used
// by process_guard.bpf.c. The write order is:
//   1. cgroup_op_policy  — per-op action/enforce-mode entries
//   2. cgroup_path_allow — path LPM trie entries
//   3. cgroup_net_allow  — network CIDR LPM trie entries
//   4. cgroup_managed    — governed flag + generation (LAST, atomic gate)
//
// The BPF program ignores cgroup_op_policy entries whose generation does not
// match the current cgroup_managed generation, so stale entries from prior
// cycles are effectively invisible until the managed record is updated.
//
// This file is compiled only on Linux because it references processGuardMaps
// from the bpf2go-generated processguard_bpfel.go (which must be present after
// running `go generate ./go/pkg/kernelcapture/...` on a Linux host with clang
// and Linux kernel headers installed).

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
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

// PolicyMaps is a thin view of the BPF maps needed for policy writes.
// Extracted from ProcessGuardHandles so map-write logic can be unit-tested
// with manually constructed *ebpf.Map objects.
type PolicyMaps struct {
	CgroupOpPolicy  *ebpf.Map
	CgroupPathAllow *ebpf.Map
	CgroupNetAllow  *ebpf.Map
	CgroupManaged   *ebpf.Map
	KillSwitch      *ebpf.Map
}

// PolicyMapsFromHandles extracts the writable map set from loaded handles.
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

// ApplyPolicyMaps writes the policy described by req into maps for cgroupID.
// cgroupID must be the kernel cgroup_id for the session (from register_session).
//
// Write order is generation-atomic: op/path/net entries first, managed gate last.
// Stale entries from prior generations survive in the map but are invisible to
// the BPF program until the managed record is updated.
func ApplyPolicyMaps(maps PolicyMaps, cgroupID uint64, req DaemonApplyPolicyRequest) error {
	gen := req.Generation

	// 1. Write per-op policy entries.
	for _, p := range req.OpPolicies {
		k := cgroupOpKey(cgroupID, p.Op)
		v := cgroupOpValue(p.Action, p.EnforceMode, gen)
		if err := maps.CgroupOpPolicy.Put(k, v); err != nil {
			return fmt.Errorf("kernelcapture: apply_policy cgroup_op_policy put (op=%s): %w", p.Op, err)
		}
	}

	// 2. Write path allow trie entries.
	for _, path := range req.PathAllow {
		k, err := pathLpmKey(cgroupID, path)
		if err != nil {
			return fmt.Errorf("kernelcapture: apply_policy path_allow put (%q): %w", path, err)
		}
		var v uint64 = 1
		if err := maps.CgroupPathAllow.Put(k, &v); err != nil {
			return fmt.Errorf("kernelcapture: apply_policy cgroup_path_allow put (%q): %w", path, err)
		}
	}

	// 3. Write net allow trie entries.
	for _, cidr := range req.NetAllow {
		k, err := netLpmKey(cgroupID, cidr)
		if err != nil {
			return fmt.Errorf("kernelcapture: apply_policy net_allow put (%q): %w", cidr, err)
		}
		var v uint64 = 1
		if err := maps.CgroupNetAllow.Put(k, &v); err != nil {
			return fmt.Errorf("kernelcapture: apply_policy cgroup_net_allow put (%q): %w", cidr, err)
		}
	}

	// 4. Write cgroup_managed LAST — the BPF program uses this as the gate.
	// strict flag = 1 when enforce_mode is ENFORCE (fail-closed on no-rule).
	var flags uint32
	if req.EnforceMode == BpfEnforceModeEnforce {
		flags = 1
	}
	mk := managedKey(cgroupID)
	mv := managedValue(flags, gen)
	if err := maps.CgroupManaged.Put(mk, mv); err != nil {
		return fmt.Errorf("kernelcapture: apply_policy cgroup_managed put: %w", err)
	}

	return nil
}

// RemovePolicyMaps clears all governance entries for cgroupID from the maps.
// This is called when a session ends to release enforcement state.
// Errors on individual deletes are collected and returned as a combined error.
func RemovePolicyMaps(maps PolicyMaps, cgroupID uint64) error {
	var errs []string

	// Delete managed gate first — BPF program then treats cgroup as ungoverned.
	mk := managedKey(cgroupID)
	if err := maps.CgroupManaged.Delete(mk); err != nil && !isNotFound(err) {
		errs = append(errs, fmt.Sprintf("cgroup_managed: %v", err))
	}

	// Delete op policy entries for all known ops.
	for _, op := range []BpfOp{BpfOpExec, BpfOpFileRead, BpfOpFileWrite, BpfOpNetConnect, BpfOpExternalSend} {
		k := cgroupOpKey(cgroupID, op)
		if err := maps.CgroupOpPolicy.Delete(k); err != nil && !isNotFound(err) {
			errs = append(errs, fmt.Sprintf("cgroup_op_policy (op=%s): %v", op, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("kernelcapture: remove_policy_maps for cgroup %d: %s", cgroupID, strings.Join(errs, "; "))
	}
	return nil
}

// SetKillSwitch writes the global kill-switch value.
// engaged=true suspends all enforcement (all ops pass through); false re-enables.
func SetKillSwitch(maps PolicyMaps, engaged bool) error {
	var v uint32
	if engaged {
		v = 1
	}
	idx := uint32(KillSwitchIndex)
	if err := maps.KillSwitch.Put(&idx, &v); err != nil {
		return fmt.Errorf("kernelcapture: set kill_switch: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// BPF map key/value serialization helpers
// ---------------------------------------------------------------------------

// cgroupOpKeyLayout must exactly match struct ardur_cgroup_op_key in process_guard.bpf.c.
// Layout: cgroup_id(8) + op(4) = 12 bytes, no padding needed (u64 then u32 then implicit 4-byte pad to 16).
// We use unsafe.Sizeof to let cilium/ebpf derive the size; the struct is plain POD.
type cgroupOpKeyLayout struct {
	CgroupID uint64
	Op       uint32
	_        [4]byte // padding to 16 bytes (hash map needs power-of-2 key size)
}

type cgroupOpValueLayout struct {
	Action      uint32
	EnforceMode uint32
	Generation  uint32
	_           [4]byte // padding
}

func cgroupOpKey(cgroupID uint64, op BpfOp) unsafe.Pointer {
	k := cgroupOpKeyLayout{CgroupID: cgroupID, Op: uint32(op)}
	return unsafe.Pointer(&k)
}

func cgroupOpValue(action BpfAction, enforceMode BpfEnforceMode, gen uint32) unsafe.Pointer {
	v := cgroupOpValueLayout{Action: uint32(action), EnforceMode: uint32(enforceMode), Generation: gen}
	return unsafe.Pointer(&v)
}

// managedKeyLayout matches struct ardur_managed_key: cgroup_raw[8].
type managedKeyLayout struct {
	CgroupRaw [8]byte
}

// managedValueLayout matches struct ardur_managed_value: flags(4) + generation(4).
type managedValueLayout struct {
	Flags      uint32
	Generation uint32
}

func managedKey(cgroupID uint64) unsafe.Pointer {
	var k managedKeyLayout
	binary.NativeEndian.PutUint64(k.CgroupRaw[:], cgroupID)
	return unsafe.Pointer(&k)
}

func managedValue(flags, generation uint32) unsafe.Pointer {
	v := managedValueLayout{Flags: flags, Generation: generation}
	return unsafe.Pointer(&v)
}

// pathLpmKeyLayout matches struct ardur_path_lpm_key: prefixlen(4) + cgroup_raw[8] + path[256].
const bpfPathLen = 256

type pathLpmKeyLayout struct {
	Prefixlen uint32
	CgroupRaw [8]byte
	Path      [bpfPathLen]byte
}

func pathLpmKey(cgroupID uint64, pathPrefix string) (unsafe.Pointer, error) {
	if !strings.HasPrefix(pathPrefix, "/") {
		return nil, fmt.Errorf("path must be absolute, got %q", pathPrefix)
	}
	pathBytes := []byte(pathPrefix)
	if len(pathBytes) > bpfPathLen-1 {
		pathBytes = pathBytes[:bpfPathLen-1]
	}

	var k pathLpmKeyLayout
	binary.NativeEndian.PutUint64(k.CgroupRaw[:], cgroupID)
	copy(k.Path[:], pathBytes)
	// prefixlen: 64 bits for cgroup_raw + path prefix bytes (excluding null terminator)
	k.Prefixlen = 64 + uint32(len(pathBytes))*8
	return unsafe.Pointer(&k), nil
}

// netLpmKeyLayout matches struct ardur_net_lpm_key: prefixlen(4) + cgroup_raw[8] + addr[16].
type netLpmKeyLayout struct {
	Prefixlen uint32
	CgroupRaw [8]byte
	Addr      [16]byte
}

func netLpmKey(cgroupID uint64, cidr string) (unsafe.Pointer, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try parsing as bare host address.
		ip := net.ParseIP(cidr)
		if ip == nil {
			return nil, fmt.Errorf("invalid CIDR/IP %q: %w", cidr, err)
		}
		if ip4 := ip.To4(); ip4 != nil {
			ipNet = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
		} else {
			ipNet = &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}
		}
	}

	var k netLpmKeyLayout
	binary.NativeEndian.PutUint64(k.CgroupRaw[:], cgroupID)

	prefixBits, _ := ipNet.Mask.Size()
	if ip4 := ipNet.IP.To4(); ip4 != nil {
		copy(k.Addr[:4], ip4)
		k.Prefixlen = 64 + uint32(prefixBits)
	} else {
		copy(k.Addr[:], ipNet.IP.To16())
		k.Prefixlen = 64 + uint32(prefixBits)
	}
	return unsafe.Pointer(&k), nil
}

func isNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found")
}
