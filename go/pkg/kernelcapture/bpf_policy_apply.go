package kernelcapture

// bpf_policy_apply.go — daemon-side BPF map write path, shared across all
// platforms.
//
// This file intentionally has NO build tag and does not import
// "github.com/cilium/ebpf". PolicyMaps' fields are small interfaces
// (policyMapWriter / policyMapReadWriter) instead of concrete *ebpf.Map types,
// so the write-ordering, double-buffer, and fail-closed logic below is pure Go
// and unit-testable on darwin/CI without a Linux kernel or BPF-LSM. *ebpf.Map
// satisfies these interfaces structurally (it has matching Put/Delete/Lookup
// methods), so real map handles built by bpf_policy_apply_linux.go plug in
// without any adapter code.
//
// Write order per ApplyPolicyMaps call (generation-atomic):
//  1. cgroup_op_policy  — written into the INACTIVE double-buffer slot only.
//     The slot currently referenced by cgroup_managed.active_slot is never
//     touched, so a reader never observes a half-written generation.
//  2. cgroup_path_allow — path LPM trie entries.
//  3. cgroup_net_allow  — network CIDR LPM trie entries.
//  4. cgroup_managed    — governed flag + active_slot (LAST, atomic gate).
//
// A zero-value PolicyMaps{} (BPF-LSM unavailable: darwin, or a Linux host
// without BPF-LSM where runGuardConsumer never populated d.policyMaps) is
// rejected up front by policyMapsReady rather than reaching a nil Put/Delete
// call — that nil-pointer panic was a crash-loop DoS: any client could take
// down the daemon by calling apply_policy against an unloaded guard.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
)

// ErrPolicyMapsUnavailable is returned by ApplyPolicyMaps / RemovePolicyMaps /
// SetKillSwitch when the BPF-LSM guard is not loaded (PolicyMaps is the zero
// value). Callers must not treat this as a transient error to retry blindly —
// it means enforcement is unavailable on this host right now.
var ErrPolicyMapsUnavailable = errors.New("kernelcapture: BPF-LSM policy maps unavailable (guard not loaded)")

// policyMapWriter is the minimal map-mutation surface ApplyPolicyMaps/
// RemovePolicyMaps/SetKillSwitch need. *ebpf.Map satisfies this today.
type policyMapWriter interface {
	Put(key, value interface{}) error
	Delete(key interface{}) error
}

// policyMapReadWriter additionally allows reading back a value, needed only
// for cgroup_managed (to discover the currently active double-buffer slot
// before writing the next generation into the other one).
type policyMapReadWriter interface {
	policyMapWriter
	Lookup(key, valueOut interface{}) error
}

// PolicyMaps is a thin view of the BPF maps needed for policy writes.
// Fields are nil (not merely unusable) when the BPF-LSM guard has not been
// loaded — see policyMapsReady.
type PolicyMaps struct {
	CgroupOpPolicy policyMapWriter
	// CgroupPathAllow is the cgroup_path_allow LPM trie. Nothing in this
	// codebase writes to it today — ApplyPolicyMaps routes req.PathAllow to
	// CgroupFileAllow instead, because the only hook that currently gets
	// ACT_ALLOWLIST path entries (guard_file_open, via bpf_lower.py's
	// SubpathPolicy/resource_scope lowering) is sleepable and cannot use an
	// LPM trie (see process_guard.bpf.c). This field, and the map behind it,
	// are kept wired for a hypothetical future OP_EXEC path-allowlist, which
	// WOULD go through the non-sleepable guard_bprm_check → decide() →
	// path_is_allowed path and could use LPM prefix matching correctly.
	CgroupPathAllow policyMapWriter
	// CgroupFileAllow is the cgroup_file_allow HASH map backing
	// OP_FILE_READ/OP_FILE_WRITE ACT_ALLOWLIST — see fileAllowKey and
	// process_guard.bpf.c's ardur_file_allow_key doc comment.
	CgroupFileAllow policyMapWriter
	CgroupNetAllow  policyMapWriter
	CgroupManaged   policyMapReadWriter
	KillSwitch      policyMapWriter
}

// policyMapsReady reports whether every map handle needed for a full
// apply_policy write is present. A partially populated PolicyMaps (which
// should never happen in practice — PolicyMapsFromHandles sets all fields
// together) is treated as not-ready to stay fail-closed.
//
// CgroupPathAllow is deliberately NOT checked here: nothing currently writes
// to it (see its doc comment on PolicyMaps), so requiring it would make
// every apply_policy call fail on a real daemon that never populates it.
func policyMapsReady(maps PolicyMaps) bool {
	return maps.CgroupOpPolicy != nil &&
		maps.CgroupFileAllow != nil &&
		maps.CgroupNetAllow != nil &&
		maps.CgroupManaged != nil &&
		maps.KillSwitch != nil
}

// PolicyMapsReady reports whether the BPF-LSM guard is currently loaded —
// i.e. whether maps has every handle needed for a full apply_policy write.
// Exported for callers outside this package (e.g. the daemon's health
// response, see EnforcementTier) that need to know kernel-enforcement
// availability without attempting a write.
func PolicyMapsReady(maps PolicyMaps) bool {
	return policyMapsReady(maps)
}

// ApplyPolicyMaps writes the policy described by req into maps for cgroupID.
// cgroupID must be the kernel cgroup_id for the session (from register_session).
//
// Returns ErrPolicyMapsUnavailable if the BPF-LSM guard is not loaded. Callers
// (handleApplyPolicy) decide how loud that failure should be: under
// ENFORCE_STRICT (req.EnforceMode == BpfEnforceModeEnforce) it must surface as
// a hard request failure — silently accepting a policy that can never be
// enforced is worse than refusing it. Under permissive mode a caller may
// choose to log a degradation instead of failing the request outright.
func ApplyPolicyMaps(maps PolicyMaps, cgroupID uint64, req DaemonApplyPolicyRequest) error {
	if !policyMapsReady(maps) {
		return ErrPolicyMapsUnavailable
	}

	newSlot := nextPolicySlot(maps.CgroupManaged, cgroupID)

	// 0. Clear the INACTIVE slot before writing the new generation into it.
	// The slot is a double buffer reused every other apply for this cgroup, so
	// without this an op rule written two generations ago (same slot) but
	// omitted from req survives — and becomes live again on the flip below,
	// silently mis-enforcing (e.g. a dropped NET_CONNECT:ALLOW lingering). The
	// slot is not the active one, so deleting from it is invisible to readers.
	for _, op := range allKnownBpfOps {
		if err := maps.CgroupOpPolicy.Delete(cgroupOpKey(cgroupID, op, newSlot)); err != nil && !isNotFound(err) {
			return fmt.Errorf("kernelcapture: apply_policy clear inactive slot (op=%s): %w", op, err)
		}
	}

	// 1. Write per-op policy entries into the INACTIVE slot.
	for _, p := range req.OpPolicies {
		k := cgroupOpKey(cgroupID, p.Op, newSlot)
		v := cgroupOpValue(p.Action, p.EnforceMode, req.Generation)
		if err := maps.CgroupOpPolicy.Put(k, v); err != nil {
			return fmt.Errorf("kernelcapture: apply_policy cgroup_op_policy put (op=%s): %w", p.Op, err)
		}
	}

	// 2. Write file allow hash entries. Targets CgroupFileAllow (HASH), not
	// CgroupPathAllow (LPM trie) — see PolicyMaps.CgroupPathAllow's doc
	// comment for why: req.PathAllow only ever carries OP_FILE_READ/WRITE
	// allowlist entries today, and the hook that enforces those
	// (guard_file_open) is sleepable and cannot reach an LPM trie.
	for _, path := range req.PathAllow {
		k, err := fileAllowKey(cgroupID, path)
		if err != nil {
			return fmt.Errorf("kernelcapture: apply_policy path_allow put (%q): %w", path, err)
		}
		var v uint64 = 1
		if err := maps.CgroupFileAllow.Put(k, &v); err != nil {
			return fmt.Errorf("kernelcapture: apply_policy cgroup_file_allow put (%q): %w", path, err)
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

	// 4. Flip the gate: write cgroup_managed LAST, pointing active_slot at the
	// slot just populated above. Until this Put lands, the BPF program keeps
	// reading the previous slot in full — true double-buffer, no partial
	// visibility of an in-progress update.
	var flags uint32
	if req.EnforceMode == BpfEnforceModeEnforce {
		flags = 1
	}
	mk := managedKey(cgroupID)
	mv := managedValue(flags, req.Generation, newSlot)
	if err := maps.CgroupManaged.Put(mk, mv); err != nil {
		return fmt.Errorf("kernelcapture: apply_policy cgroup_managed put: %w", err)
	}

	return nil
}

// RemovePolicyMaps clears all governance entries for cgroupID from the maps.
// This is called when a session ends to release enforcement state.
// Errors on individual deletes are collected and returned as a combined error.
func RemovePolicyMaps(maps PolicyMaps, cgroupID uint64) error {
	if !policyMapsReady(maps) {
		return ErrPolicyMapsUnavailable
	}

	var errs []string

	// Delete managed gate first — BPF program then treats cgroup as ungoverned.
	mk := managedKey(cgroupID)
	if err := maps.CgroupManaged.Delete(mk); err != nil && !isNotFound(err) {
		errs = append(errs, fmt.Sprintf("cgroup_managed: %v", err))
	}

	// Delete op policy entries for all known ops, in both double-buffer slots.
	for _, op := range allKnownBpfOps {
		for _, slot := range [2]uint32{0, 1} {
			k := cgroupOpKey(cgroupID, op, slot)
			if err := maps.CgroupOpPolicy.Delete(k); err != nil && !isNotFound(err) {
				errs = append(errs, fmt.Sprintf("cgroup_op_policy (op=%s, slot=%d): %v", op, slot, err))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("kernelcapture: remove_policy_maps for cgroup %d: %s", cgroupID, strings.Join(errs, "; "))
	}
	return nil
}

// DeleteAllowlistEntries removes specific path (cgroup_file_allow) and net
// (cgroup_net_allow) allowlist entries for cgroupID. Unlike cgroup_op_policy,
// these maps are NOT double-buffered — a re-apply only Puts the new entries, so
// an entry from a prior generation that the new policy drops would otherwise
// linger and stay allowed (silently defeating a tightened allowlist), and
// nothing removes them at session end. The daemon tracks what it applied per
// session and calls this with the stale (or, at session end, the full) set;
// deletes are best-effort (a missing key is not an error). Building the exact
// keys from the same path/CIDR strings avoids having to iterate the maps.
func DeleteAllowlistEntries(maps PolicyMaps, cgroupID uint64, paths []string, cidrs []string) error {
	if maps.CgroupFileAllow == nil || maps.CgroupNetAllow == nil {
		return ErrPolicyMapsUnavailable
	}
	var errs []string
	for _, path := range paths {
		k, err := fileAllowKey(cgroupID, path)
		if err != nil {
			errs = append(errs, fmt.Sprintf("file_allow key (%q): %v", path, err))
			continue
		}
		if err := maps.CgroupFileAllow.Delete(k); err != nil && !isNotFound(err) {
			errs = append(errs, fmt.Sprintf("cgroup_file_allow (%q): %v", path, err))
		}
	}
	for _, cidr := range cidrs {
		k, err := netLpmKey(cgroupID, cidr)
		if err != nil {
			errs = append(errs, fmt.Sprintf("net_allow key (%q): %v", cidr, err))
			continue
		}
		if err := maps.CgroupNetAllow.Delete(k); err != nil && !isNotFound(err) {
			errs = append(errs, fmt.Sprintf("cgroup_net_allow (%q): %v", cidr, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("kernelcapture: delete_allowlist_entries for cgroup %d: %s", cgroupID, strings.Join(errs, "; "))
	}
	return nil
}

// allKnownBpfOps is every op the enforcement layer recognises. Used to clear a
// double-buffer slot before writing (ApplyPolicyMaps) and to release all op
// entries on session end (RemovePolicyMaps).
var allKnownBpfOps = []BpfOp{BpfOpExec, BpfOpFileRead, BpfOpFileWrite, BpfOpNetConnect, BpfOpExternalSend}

// SetKillSwitch writes the global kill-switch value.
// engaged=true suspends all enforcement (all ops pass through); false re-enables.
func SetKillSwitch(maps PolicyMaps, engaged bool) error {
	if !policyMapsReady(maps) {
		return ErrPolicyMapsUnavailable
	}
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

// cgroupOpKeyLayout must exactly match struct ardur_cgroup_op_key in
// process_guard.bpf.c: cgroup_id(8) + op(4) + slot(4) = 16 bytes, naturally
// aligned (no implicit padding).
type cgroupOpKeyLayout struct {
	CgroupID uint64
	Op       uint32
	Slot     uint32
}

type cgroupOpValueLayout struct {
	Action      uint32
	EnforceMode uint32
	Generation  uint32
}

func cgroupOpKey(cgroupID uint64, op BpfOp, slot uint32) unsafe.Pointer {
	k := cgroupOpKeyLayout{CgroupID: cgroupID, Op: uint32(op), Slot: slot}
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

// managedValueLayout matches struct ardur_managed_value:
// flags(4) + generation(4) + active_slot(4) = 12 bytes.
type managedValueLayout struct {
	Flags      uint32
	Generation uint32
	ActiveSlot uint32
}

func managedKey(cgroupID uint64) unsafe.Pointer {
	var k managedKeyLayout
	binary.NativeEndian.PutUint64(k.CgroupRaw[:], cgroupID)
	return unsafe.Pointer(&k)
}

func managedValue(flags, generation, activeSlot uint32) unsafe.Pointer {
	v := managedValueLayout{Flags: flags, Generation: generation, ActiveSlot: activeSlot}
	return unsafe.Pointer(&v)
}

// nextPolicySlot returns the double-buffer slot ApplyPolicyMaps should write
// the new generation into: the slot NOT currently referenced by
// cgroup_managed for cgroupID. Returns 0 if no prior entry exists (first
// apply_policy call for this cgroup) or if the lookup fails for any other
// reason — either way there is no live slot to avoid colliding with yet, so
// starting at 0 is safe.
//
// This reads the current state back from the map rather than deriving the
// slot from req.Generation's parity: the protocol only requires Generation to
// be non-zero, not strictly +1 per call, so parity of an externally supplied
// counter cannot be trusted to alternate correctly.
func nextPolicySlot(cm policyMapReadWriter, cgroupID uint64) uint32 {
	mk := managedKey(cgroupID)
	var mv managedValueLayout
	if err := cm.Lookup(mk, unsafe.Pointer(&mv)); err != nil {
		return 0
	}
	return 1 - (mv.ActiveSlot & 1)
}

// fileAllowKeyLayout matches struct ardur_file_allow_key: cgroup_raw[8] +
// path[bpfPathLen]. Unlike pathLpmKeyLayout there is no prefixlen field —
// this is a HASH map key (exact match on the full fixed-size struct,
// zero-padding included), not an LPM trie key. See ardur_file_allow_key's
// doc comment in process_guard.bpf.c for the directory-boundary-aware
// ancestor-walk matching this enables on the read (BPF) side.
const bpfPathLen = 256

type fileAllowKeyLayout struct {
	CgroupRaw [8]byte
	Path      [bpfPathLen]byte
}

// fileAllowKey builds a cgroup_file_allow lookup/write key for one allowed
// path (a directory root or an exact file). Longer-than-bpfPathLen paths are
// truncated the same way pathLpmKey truncates oversize LPM entries — the
// truncated form just won't be found by the ancestor walk in
// file_path_is_allowed if the walk's cap (ARDUR_FILE_ALLOW_MAX_ANCESTORS)
// would have stopped short of it first anyway.
func fileAllowKey(cgroupID uint64, pathPrefix string) (unsafe.Pointer, error) {
	if !strings.HasPrefix(pathPrefix, "/") {
		return nil, fmt.Errorf("path must be absolute, got %q", pathPrefix)
	}
	pathBytes := []byte(pathPrefix)
	if len(pathBytes) > bpfPathLen {
		pathBytes = pathBytes[:bpfPathLen]
	}

	var k fileAllowKeyLayout
	binary.NativeEndian.PutUint64(k.CgroupRaw[:], cgroupID)
	copy(k.Path[:], pathBytes)
	return unsafe.Pointer(&k), nil
}

// pathLpmKeyLayout matches struct ardur_path_lpm_key:
// prefixlen(4) + cgroup_raw[8] + path[bpfPathLpmDataLen].
//
// bpfPathLpmDataLen is 248, not 256: BPF_MAP_TYPE_LPM_TRIE hard-caps a key's
// data portion (everything after prefixlen) at 256 bytes in the kernel
// (LPM_DATA_SIZE_MAX in kernel/bpf/lpm_trie.c) — map creation fails with
// EINVAL above that, taking every path/net allowlist policy down with it,
// not just long-path entries. cgroup_raw's 8 bytes come out of that budget,
// leaving 248 for the path itself. See ARDUR_PATH_LPM_DATA_LEN in
// process_guard.bpf.c, which this must match exactly.
const bpfPathLpmDataLen = 256 - 8

type pathLpmKeyLayout struct {
	Prefixlen uint32
	CgroupRaw [8]byte
	Path      [bpfPathLpmDataLen]byte
}

func pathLpmKey(cgroupID uint64, pathPrefix string) (unsafe.Pointer, error) {
	if !strings.HasPrefix(pathPrefix, "/") {
		return nil, fmt.Errorf("path must be absolute, got %q", pathPrefix)
	}
	pathBytes := []byte(pathPrefix)
	if len(pathBytes) > bpfPathLpmDataLen-1 {
		pathBytes = pathBytes[:bpfPathLpmDataLen-1]
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
	// ebpf.ErrKeyNotExist's message is "key does not exist", not "not found" —
	// match the real sentinel via errors.Is. The substring fallback covers
	// fakes (e.g. tests) that return a plain error without wrapping it.
	return err != nil &&
		(errors.Is(err, ebpf.ErrKeyNotExist) || strings.Contains(err.Error(), "key does not exist") || strings.Contains(err.Error(), "not found"))
}
