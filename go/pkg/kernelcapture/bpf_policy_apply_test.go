package kernelcapture

// bpf_policy_apply_test.go — unit tests for the platform-independent BPF
// policy-map write path (bpf_policy_apply.go). These exercise the
// nil-guard/fail-closed behaviour, double-buffer slot selection, write
// ordering, and key/value layouts using a fake in-memory map — no BPF-LSM,
// kernel, or Linux build tag required, so this suite runs on darwin and
// Linux alike (see the Slice 4.2 review: this logic was previously only
// reachable through the //go:build linux implementation and untested).

import (
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"unsafe"
)

// fakeBPFMap is a minimal in-memory stand-in for *ebpf.Map, keyed by the raw
// bytes at the unsafe.Pointer key/value ApplyPolicyMaps passes in. It records
// call order so tests can assert write sequencing.
type fakeBPFMap struct {
	name      string
	keySize   uintptr
	valSize   uintptr
	data      map[string][]byte
	calls     *[]string // shared across a PolicyMaps set to assert cross-map ordering
	putErr    error
	deleteErr error
	failName  string // if non-empty, Put on this name returns putErr
}

func newFakeMap(name string, keySize, valSize uintptr, calls *[]string) *fakeBPFMap {
	return &fakeBPFMap{name: name, keySize: keySize, valSize: valSize, data: map[string][]byte{}, calls: calls}
}

// pointerFromAny extracts the raw address behind v, where v is either an
// unsafe.Pointer (used by cgroupOpKey/managedKey/pathLpmKey/netLpmKey — a
// raw-bytes-of-known-size contract) or an ordinary typed pointer such as
// *uint32 (used by SetKillSwitch). Real cilium/ebpf.Map.Put/Delete/Lookup
// accept both forms, so the fake must too.
func pointerFromAny(v interface{}) unsafe.Pointer {
	if up, ok := v.(unsafe.Pointer); ok {
		return up
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		panic("fakeBPFMap: key/value must be a non-nil pointer or unsafe.Pointer")
	}
	return unsafe.Pointer(rv.Pointer())
}

func bytesFromAny(v interface{}, size uintptr) []byte {
	src := unsafe.Slice((*byte)(pointerFromAny(v)), int(size))
	out := make([]byte, size)
	copy(out, src)
	return out
}

func (m *fakeBPFMap) Put(key, value interface{}) error {
	if m.calls != nil {
		*m.calls = append(*m.calls, "put:"+m.name)
	}
	if m.putErr != nil && m.name == m.failName {
		return m.putErr
	}
	kb := bytesFromAny(key, m.keySize)
	vb := bytesFromAny(value, m.valSize)
	m.data[string(kb)] = vb
	return nil
}

func (m *fakeBPFMap) Delete(key interface{}) error {
	if m.calls != nil {
		*m.calls = append(*m.calls, "delete:"+m.name)
	}
	if m.deleteErr != nil {
		return m.deleteErr
	}
	kb := bytesFromAny(key, m.keySize)
	if _, ok := m.data[string(kb)]; !ok {
		return errors.New("key does not exist")
	}
	delete(m.data, string(kb))
	return nil
}

func (m *fakeBPFMap) Lookup(key, valueOut interface{}) error {
	kb := bytesFromAny(key, m.keySize)
	v, ok := m.data[string(kb)]
	if !ok {
		return errors.New("key does not exist")
	}
	dst := unsafe.Slice((*byte)(pointerFromAny(valueOut)), int(m.valSize))
	copy(dst, v)
	return nil
}

const (
	cgroupOpKeySize               = unsafe.Sizeof(cgroupOpKeyLayout{})
	cgroupOpValueSize             = unsafe.Sizeof(cgroupOpValueLayout{})
	managedKeySize                = unsafe.Sizeof(managedKeyLayout{})
	managedValueSize              = unsafe.Sizeof(managedValueLayout{})
	pathLpmKeySize                = unsafe.Sizeof(pathLpmKeyLayout{})
	fileAllowKeySize              = unsafe.Sizeof(fileAllowKeyLayout{})
	bootstrapFileKeySize          = unsafe.Sizeof(bootstrapFileKeyLayout{})
	bootstrapObservationKeySize   = unsafe.Sizeof(bootstrapObservationKeyLayout{})
	bootstrapObservationValueSize = unsafe.Sizeof(bootstrapObservationValueLayout{})
	controlPlaneAllowKeySize      = unsafe.Sizeof(controlPlaneAllowKeyLayout{})
	trustedRootValueSize          = unsafe.Sizeof(trustedRootValueLayout{})
	bootstrapFileValueSize        = unsafe.Sizeof(bootstrapFileValueLayout{})
	netLpmKeySize                 = unsafe.Sizeof(netLpmKeyLayout{})
	lpmAllowedValueSize           = unsafe.Sizeof(uint64(0))
)

// fakePolicyMaps returns a fully-populated PolicyMaps backed by fakeBPFMap,
// plus the shared call-order log and a handle to each individual fake map.
func fakePolicyMaps() (PolicyMaps, *[]string, map[string]*fakeBPFMap) {
	calls := &[]string{}
	opPolicy := newFakeMap("cgroup_op_policy", cgroupOpKeySize, cgroupOpValueSize, calls)
	pathAllow := newFakeMap("cgroup_path_allow", pathLpmKeySize, lpmAllowedValueSize, calls)
	fileAllow := newFakeMap("cgroup_file_allow", fileAllowKeySize, lpmAllowedValueSize, calls)
	bootstrapFileAllow := newFakeMap("cgroup_bootstrap_file_allow", bootstrapFileKeySize, bootstrapFileValueSize, calls)
	bootstrapObservation := newFakeMap("bootstrap_file_observation", bootstrapObservationKeySize, bootstrapObservationValueSize, calls)
	controlPlaneAllow := newFakeMap("cgroup_control_plane_allow", controlPlaneAllowKeySize, unsafe.Sizeof(uint32(0)), calls)
	trustedRoot := newFakeMap("cgroup_trusted_root", managedKeySize, trustedRootValueSize, calls)
	netAllow := newFakeMap("cgroup_net_allow", netLpmKeySize, lpmAllowedValueSize, calls)
	managed := newFakeMap("cgroup_managed", managedKeySize, managedValueSize, calls)
	killSwitch := newFakeMap("kill_switch", unsafe.Sizeof(uint32(0)), unsafe.Sizeof(uint32(0)), calls)

	maps := PolicyMaps{
		CgroupOpPolicy:           opPolicy,
		CgroupPathAllow:          pathAllow,
		CgroupFileAllow:          fileAllow,
		CgroupBootstrapFileAllow: bootstrapFileAllow,
		BootstrapFileObservation: bootstrapObservation,
		CgroupControlPlaneAllow:  controlPlaneAllow,
		CgroupTrustedRoot:        trustedRoot,
		CgroupNetAllow:           netAllow,
		CgroupManaged:            managed,
		KillSwitch:               killSwitch,
	}
	handles := map[string]*fakeBPFMap{
		"cgroup_op_policy":            opPolicy,
		"cgroup_path_allow":           pathAllow,
		"cgroup_file_allow":           fileAllow,
		"cgroup_bootstrap_file_allow": bootstrapFileAllow,
		"bootstrap_file_observation":  bootstrapObservation,
		"cgroup_control_plane_allow":  controlPlaneAllow,
		"cgroup_trusted_root":         trustedRoot,
		"cgroup_net_allow":            netAllow,
		"cgroup_managed":              managed,
		"kill_switch":                 killSwitch,
	}
	return maps, calls, handles
}

func samplePolicyReq(gen BpfPolicyGeneration, mode BpfEnforceMode) DaemonApplyPolicyRequest {
	return DaemonApplyPolicyRequest{
		SessionID:   "ses-test",
		Generation:  gen,
		EnforceMode: mode,
		OpPolicies: []DaemonOpPolicy{
			{Op: BpfOpExec, Action: BpfActionDeny, EnforceMode: BpfEnforceModeEnforce},
		},
	}
}

// --- Nil-guard / fail-closed -----------------------------------------------

func TestApplyPolicyMaps_NilMapsFailsCleanly(t *testing.T) {
	t.Parallel()
	err := ApplyPolicyMaps(PolicyMaps{}, 42, samplePolicyReq(1, BpfEnforceModeEnforce))
	if !errors.Is(err, ErrPolicyMapsUnavailable) {
		t.Fatalf("ApplyPolicyMaps with zero-value maps: got %v, want ErrPolicyMapsUnavailable", err)
	}
}

func TestApplyPolicyMaps_PartiallyPopulatedMapsFailsCleanly(t *testing.T) {
	t.Parallel()
	maps, _, _ := fakePolicyMaps()
	maps.KillSwitch = nil // simulate a partially-initialized handle set
	err := ApplyPolicyMaps(maps, 42, samplePolicyReq(1, BpfEnforceModeEnforce))
	if !errors.Is(err, ErrPolicyMapsUnavailable) {
		t.Fatalf("ApplyPolicyMaps with partial maps: got %v, want ErrPolicyMapsUnavailable", err)
	}
}

func TestRemovePolicyMaps_NilMapsFailsCleanly(t *testing.T) {
	t.Parallel()
	err := RemovePolicyMaps(PolicyMaps{}, 42)
	if !errors.Is(err, ErrPolicyMapsUnavailable) {
		t.Fatalf("RemovePolicyMaps with zero-value maps: got %v, want ErrPolicyMapsUnavailable", err)
	}
}

func TestSetKillSwitch_NilMapsFailsCleanly(t *testing.T) {
	t.Parallel()
	err := SetKillSwitch(PolicyMaps{}, true)
	if !errors.Is(err, ErrPolicyMapsUnavailable) {
		t.Fatalf("SetKillSwitch with zero-value maps: got %v, want ErrPolicyMapsUnavailable", err)
	}
}

func TestSetKillSwitch_WritesExpectedValue(t *testing.T) {
	t.Parallel()
	maps, _, handles := fakePolicyMaps()
	if err := SetKillSwitch(maps, true); err != nil {
		t.Fatalf("SetKillSwitch(engaged=true): unexpected error: %v", err)
	}
	idx := uint32(KillSwitchIndex)
	var v uint32
	if err := handles["kill_switch"].Lookup(unsafe.Pointer(&idx), unsafe.Pointer(&v)); err != nil {
		t.Fatalf("lookup kill_switch after engage: %v", err)
	}
	if v != 1 {
		t.Errorf("kill_switch value after engage = %d, want 1", v)
	}

	if err := SetKillSwitch(maps, false); err != nil {
		t.Fatalf("SetKillSwitch(engaged=false): unexpected error: %v", err)
	}
	if err := handles["kill_switch"].Lookup(unsafe.Pointer(&idx), unsafe.Pointer(&v)); err != nil {
		t.Fatalf("lookup kill_switch after disengage: %v", err)
	}
	if v != 0 {
		t.Errorf("kill_switch value after disengage = %d, want 0", v)
	}
}

// --- Write ordering (generation-atomic) -------------------------------------

func TestApplyPolicyMaps_WritesManagedGateLast(t *testing.T) {
	t.Parallel()
	maps, calls, _ := fakePolicyMaps()
	req := samplePolicyReq(1, BpfEnforceModePermissive)
	req.PathAllow = []string{"/data/"}
	req.NetAllow = []string{"10.0.0.0/8"}

	if err := ApplyPolicyMaps(maps, 7, req); err != nil {
		t.Fatalf("ApplyPolicyMaps: unexpected error: %v", err)
	}

	got := *calls
	if len(got) == 0 {
		t.Fatal("no map writes recorded")
	}
	last := got[len(got)-1]
	if last != "put:cgroup_managed" {
		t.Errorf("last write = %q, want put:cgroup_managed (managed gate must be written last)", last)
	}
	for _, c := range got[:len(got)-1] {
		if c == "put:cgroup_managed" {
			t.Errorf("cgroup_managed written before the end of the call sequence: %v", got)
		}
	}
}

// TestApplyPolicyMaps_PathAllowWritesToFileAllowMapNotLPM is the reconciliation
// regression test: req.PathAllow must land in cgroup_file_allow (the HASH map
// guard_file_open's sleepable ACT_ALLOWLIST branch can actually read), not
// cgroup_path_allow (the LPM trie it cannot touch — see
// ardur_file_allow_key's doc comment in process_guard.bpf.c). Before this
// fix, ApplyPolicyMaps wrote path_allow entries into an LPM trie that no
// live enforcement hook could ever read for file ops, so SubpathPolicy-based
// file allowlisting silently never worked (fail-closed under ENFORCE_STRICT,
// fail-open under PERMISSIVE) despite bpf_lower.py promising it was enforced.
func TestApplyPolicyMaps_PathAllowWritesToFileAllowMapNotLPM(t *testing.T) {
	t.Parallel()
	maps, _, handles := fakePolicyMaps()
	req := samplePolicyReq(1, BpfEnforceModeEnforce)
	req.PathAllow = []string{"/workspace"}

	if err := ApplyPolicyMaps(maps, 7, req); err != nil {
		t.Fatalf("ApplyPolicyMaps: unexpected error: %v", err)
	}

	k, err := fileAllowKey(7, "/workspace")
	if err != nil {
		t.Fatalf("fileAllowKey: %v", err)
	}
	var v uint64
	if err := handles["cgroup_file_allow"].Lookup(k, unsafe.Pointer(&v)); err != nil {
		t.Fatalf("expected /workspace entry in cgroup_file_allow, lookup failed: %v", err)
	}
	if v == 0 {
		t.Error("cgroup_file_allow entry for /workspace has value 0, want nonzero (allowed)")
	}

	if len(handles["cgroup_path_allow"].data) != 0 {
		t.Errorf("cgroup_path_allow got %d entries, want 0 — path_allow must not also write the LPM trie no sleepable hook can read", len(handles["cgroup_path_allow"].data))
	}
}

func TestApplyPolicyMaps_TrustedRuntimeEntriesBindRootAndGeneration(t *testing.T) {
	t.Parallel()
	maps, calls, handles := fakePolicyMaps()
	req := samplePolicyReq(7, BpfEnforceModeEnforce)
	req.RootPID = 4242
	req.BootstrapReadAllow = []string{"/usr"}
	req.BootstrapFiles = []BootstrapFile{{Path: "/workspace/agent.py", KernelDevice: 17, Inode: 29}}
	req.ControlPlaneEndpoint = &DaemonControlPlaneEndpoint{IP: "127.0.0.1", Port: 43210}

	if err := ApplyPolicyMaps(maps, 99, req); err != nil {
		t.Fatalf("ApplyPolicyMaps: %v", err)
	}
	var generation uint32
	var trusted trustedRootValueLayout
	if err := handles["cgroup_trusted_root"].Lookup(managedKey(99), &trusted); err != nil {
		t.Fatalf("trusted-root lookup: %v", err)
	}
	if trusted.RootTGID != 4242 || trusted.Generation != 7 || trusted.AllowMask != bootstrapAllowUsr {
		t.Fatalf("trusted root = %+v, want root=4242 generation=7 mask=%d", trusted, bootstrapAllowUsr)
	}
	bootstrapKey, err := bootstrapFileKey(99, req.BootstrapFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	var bootstrap bootstrapFileValueLayout
	if err := handles["cgroup_bootstrap_file_allow"].Lookup(bootstrapKey, &bootstrap); err != nil {
		t.Fatalf("bootstrap-file lookup: %v", err)
	}
	if bootstrap.Generation != 7 {
		t.Fatalf("bootstrap file = %+v, want generation=7", bootstrap)
	}
	controlKey, err := controlPlaneAllowKey(99, 4242, *req.ControlPlaneEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	if err := handles["cgroup_control_plane_allow"].Lookup(controlKey, &generation); err != nil {
		t.Fatalf("control-plane lookup: %v", err)
	}
	if generation != 7 {
		t.Fatalf("control-plane generation = %d, want 7", generation)
	}
	if got := (*calls)[len(*calls)-1]; got != "put:cgroup_managed" {
		t.Fatalf("last write = %q, want managed generation gate", got)
	}

}

func TestApplyPolicyMaps_RejectsInvalidBootstrapFileIdentities(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		files []BootstrapFile
	}{
		{name: "relative", files: []BootstrapFile{{Path: "agent.py", KernelDevice: 1, Inode: 1}}},
		{name: "zero inode", files: []BootstrapFile{{Path: "/agent.py", KernelDevice: 1}}},
		{name: "zero device", files: []BootstrapFile{{Path: "/agent.py", Inode: 1}}},
		{name: "duplicate", files: []BootstrapFile{{Path: "/agent.py", KernelDevice: 1, Inode: 1}, {Path: "/agent-link.py", KernelDevice: 1, Inode: 1}}},
		{name: "too many", files: []BootstrapFile{{Path: "/1", KernelDevice: 1, Inode: 1}, {Path: "/2", KernelDevice: 1, Inode: 2}, {Path: "/3", KernelDevice: 1, Inode: 3}, {Path: "/4", KernelDevice: 1, Inode: 4}, {Path: "/5", KernelDevice: 1, Inode: 5}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maps, _, _ := fakePolicyMaps()
			req := samplePolicyReq(1, BpfEnforceModeEnforce)
			req.RootPID = 42
			req.BootstrapFiles = tt.files
			if err := ApplyPolicyMaps(maps, 99, req); err == nil {
				t.Fatal("invalid bootstrap file identities were accepted")
			}
		})
	}
}

func TestApplyPolicyMaps_TrustedRuntimeEntriesRequireDaemonRoot(t *testing.T) {
	t.Parallel()
	maps, _, _ := fakePolicyMaps()
	req := samplePolicyReq(1, BpfEnforceModeEnforce)
	req.BootstrapReadAllow = []string{"/usr"}
	if err := ApplyPolicyMaps(maps, 99, req); err == nil {
		t.Fatal("trusted runtime exception without daemon root PID was accepted")
	}
}

func TestBootstrapReadAllowMaskIncludesDistroLibraryRoots(t *testing.T) {
	t.Parallel()
	want := bootstrapAllowUsr | bootstrapAllowLib | bootstrapAllowLib64
	if got := bootstrapReadAllowMask([]string{"/usr", "/lib", "/lib64"}); got != want {
		t.Fatalf("bootstrapReadAllowMask = %#x, want %#x", got, want)
	}
}

func TestRegisterBootstrapFileEntries_RequiresLSMAcknowledgement(t *testing.T) {
	t.Parallel()
	maps, _, handles := fakePolicyMaps()
	files := []BootstrapFile{{Path: "/workspace/agent.py", Inode: 29}}

	registered, err := RegisterBootstrapFileEntries(
		maps, 99, 7, 4242, files,
		func(path string) error {
			if path != files[0].Path {
				t.Fatalf("trigger path = %q, want %q", path, files[0].Path)
			}
			key := bootstrapObservationKeyLayout{ObserverTGID: 4242, Inode: 29}
			var value bootstrapObservationValueLayout
			if err := handles["bootstrap_file_observation"].Lookup(&key, &value); err != nil {
				t.Fatalf("lookup armed observation: %v", err)
			}
			value.Registered = 1
			value.Device = 48
			return handles["bootstrap_file_observation"].Put(&key, &value)
		},
	)
	if err != nil {
		t.Fatalf("RegisterBootstrapFileEntries: %v", err)
	}
	if len(registered) != 1 || registered[0].KernelDevice != 48 || registered[0].Inode != 29 {
		t.Fatalf("registered = %+v, want device=48 inode=29", registered)
	}
	if len(handles["bootstrap_file_observation"].data) != 0 {
		t.Fatal("one-shot observation request remains after acknowledgement")
	}

	if _, err := RegisterBootstrapFileEntries(maps, 99, 8, 4242, files, func(string) error { return nil }); err == nil {
		t.Fatal("registration without LSM acknowledgement succeeded")
	}
}

func TestRegisterBootstrapFileEntries_ReportsObservationCleanupFailure(t *testing.T) {
	t.Parallel()
	maps, _, handles := fakePolicyMaps()
	files := []BootstrapFile{{Path: "/workspace/agent.py", Inode: 29}}
	wantErr := errors.New("synthetic observation delete failure")

	_, err := RegisterBootstrapFileEntries(
		maps, 99, 7, 4242, files,
		func(string) error {
			key := bootstrapObservationKeyLayout{ObserverTGID: 4242, Inode: 29}
			var value bootstrapObservationValueLayout
			if err := handles["bootstrap_file_observation"].Lookup(&key, &value); err != nil {
				t.Fatalf("lookup armed observation: %v", err)
			}
			value.Registered = 1
			value.Device = 48
			if err := handles["bootstrap_file_observation"].Put(&key, &value); err != nil {
				t.Fatalf("acknowledge observation: %v", err)
			}
			handles["bootstrap_file_observation"].deleteErr = wantErr
			return nil
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("RegisterBootstrapFileEntries error = %v, want cleanup failure", err)
	}
}

// TestApplyPolicyMaps_SucceedsWithNilCgroupPathAllow proves policyMapsReady
// does not require CgroupPathAllow: PolicyMapsFromHandles always sets it (a
// live map handle exists), but nothing writes to it anymore (see its doc
// comment on PolicyMaps), so a hypothetical caller that leaves it nil must
// not be treated as fail-closed the way a genuinely missing required map is.
func TestApplyPolicyMaps_SucceedsWithNilCgroupPathAllow(t *testing.T) {
	t.Parallel()
	maps, _, _ := fakePolicyMaps()
	maps.CgroupPathAllow = nil
	if err := ApplyPolicyMaps(maps, 7, samplePolicyReq(1, BpfEnforceModeEnforce)); err != nil {
		t.Fatalf("ApplyPolicyMaps with nil CgroupPathAllow: unexpected error: %v", err)
	}
}

// --- Double buffering --------------------------------------------------------

func TestApplyPolicyMaps_FirstApplyUsesSlotZero(t *testing.T) {
	t.Parallel()
	maps, _, handles := fakePolicyMaps()
	if err := ApplyPolicyMaps(maps, 7, samplePolicyReq(1, BpfEnforceModeEnforce)); err != nil {
		t.Fatalf("ApplyPolicyMaps: %v", err)
	}
	var mv managedValueLayout
	if err := handles["cgroup_managed"].Lookup(managedKey(7), unsafe.Pointer(&mv)); err != nil {
		t.Fatalf("lookup cgroup_managed: %v", err)
	}
	if mv.ActiveSlot != 0 {
		t.Errorf("ActiveSlot after first apply = %d, want 0", mv.ActiveSlot)
	}
}

// TestApplyPolicyMaps_SecondApplyDoesNotMutateActiveSlot is the core
// double-buffer regression test from the Slice 4.2 review: a second
// apply_policy call must write into the OTHER slot and leave the
// still-active slot's entries byte-for-byte untouched until the final
// cgroup_managed flip. Under the old single-buffer design (key = {cgroup,op},
// no slot), the second Put would overwrite the first generation's entry in
// place — this test fails against that implementation.
func TestApplyPolicyMaps_SecondApplyDoesNotMutateActiveSlot(t *testing.T) {
	t.Parallel()
	maps, _, handles := fakePolicyMaps()
	cgroupID := uint64(7)

	first := samplePolicyReq(1, BpfEnforceModeEnforce)
	first.OpPolicies = []DaemonOpPolicy{{Op: BpfOpExec, Action: BpfActionDeny, EnforceMode: BpfEnforceModeEnforce}}
	if err := ApplyPolicyMaps(maps, cgroupID, first); err != nil {
		t.Fatalf("first ApplyPolicyMaps: %v", err)
	}

	// Capture the slot-0 entry exactly as the first apply left it.
	var slot0Before cgroupOpValueLayout
	if err := handles["cgroup_op_policy"].Lookup(cgroupOpKey(cgroupID, BpfOpExec, 0), unsafe.Pointer(&slot0Before)); err != nil {
		t.Fatalf("lookup slot 0 after first apply: %v", err)
	}
	if slot0Before.Action != uint32(BpfActionDeny) {
		t.Fatalf("slot 0 action after first apply = %d, want ACT_DENY", slot0Before.Action)
	}

	// Second apply: different action, different generation.
	second := samplePolicyReq(2, BpfEnforceModeEnforce)
	second.OpPolicies = []DaemonOpPolicy{{Op: BpfOpExec, Action: BpfActionAllow, EnforceMode: BpfEnforceModePermissive}}
	if err := ApplyPolicyMaps(maps, cgroupID, second); err != nil {
		t.Fatalf("second ApplyPolicyMaps: %v", err)
	}

	// Slot 0 must be byte-identical to what the first apply wrote.
	var slot0After cgroupOpValueLayout
	if err := handles["cgroup_op_policy"].Lookup(cgroupOpKey(cgroupID, BpfOpExec, 0), unsafe.Pointer(&slot0After)); err != nil {
		t.Fatalf("lookup slot 0 after second apply: %v", err)
	}
	if slot0After != slot0Before {
		t.Errorf("slot 0 entry mutated by second apply: before=%+v after=%+v (double-buffer violated: old generation must survive until the gate flips)", slot0Before, slot0After)
	}

	// Slot 1 must hold the second apply's data.
	var slot1 cgroupOpValueLayout
	if err := handles["cgroup_op_policy"].Lookup(cgroupOpKey(cgroupID, BpfOpExec, 1), unsafe.Pointer(&slot1)); err != nil {
		t.Fatalf("lookup slot 1 after second apply: %v", err)
	}
	if slot1.Action != uint32(BpfActionAllow) {
		t.Errorf("slot 1 action = %d, want ACT_ALLOW", slot1.Action)
	}

	// The gate must now point at slot 1.
	var mv managedValueLayout
	if err := handles["cgroup_managed"].Lookup(managedKey(cgroupID), unsafe.Pointer(&mv)); err != nil {
		t.Fatalf("lookup cgroup_managed: %v", err)
	}
	if mv.ActiveSlot != 1 {
		t.Errorf("ActiveSlot after second apply = %d, want 1", mv.ActiveSlot)
	}
}

// TestNextPolicySlot_IgnoresGenerationParity proves slot selection depends on
// the map's recorded ActiveSlot, not on parity of the caller-supplied
// generation number — the protocol only requires Generation to be non-zero,
// not consecutive, so parity-of-generation would be unsafe (see
// bpf_policy_apply.go's nextPolicySlot doc comment).
func TestNextPolicySlot_IgnoresGenerationParity(t *testing.T) {
	t.Parallel()
	_, _, handles := fakePolicyMaps()
	cgroupID := uint64(99)

	// No prior entry: slot defaults to 0.
	if got := nextPolicySlot(handles["cgroup_managed"], cgroupID); got != 0 {
		t.Errorf("nextPolicySlot with no prior entry = %d, want 0", got)
	}

	// Seed an entry with a large ODD generation but ActiveSlot=1.
	if err := handles["cgroup_managed"].Put(managedKey(cgroupID), managedValue(0, 101, 1)); err != nil {
		t.Fatalf("seed cgroup_managed: %v", err)
	}
	if got := nextPolicySlot(handles["cgroup_managed"], cgroupID); got != 0 {
		t.Errorf("nextPolicySlot with ActiveSlot=1 = %d, want 0 (opposite slot)", got)
	}

	// Now seed generation=102 (even) but still ActiveSlot=1 (simulating a
	// generation jump of +1 that did NOT flip parity the way naive gen&1
	// slot selection would assume).
	if err := handles["cgroup_managed"].Put(managedKey(cgroupID), managedValue(0, 102, 1)); err != nil {
		t.Fatalf("seed cgroup_managed: %v", err)
	}
	if got := nextPolicySlot(handles["cgroup_managed"], cgroupID); got != 0 {
		t.Errorf("nextPolicySlot after generation changed but ActiveSlot unchanged = %d, want 0", got)
	}
}

// --- RemovePolicyMaps ---------------------------------------------------

func TestRemovePolicyMaps_DeletesBothSlots(t *testing.T) {
	t.Parallel()
	maps, _, handles := fakePolicyMaps()
	cgroupID := uint64(55)

	// Seed entries for BpfOpExec in both slots plus the managed gate.
	if err := handles["cgroup_op_policy"].Put(cgroupOpKey(cgroupID, BpfOpExec, 0), cgroupOpValue(BpfActionDeny, BpfEnforceModeEnforce, 1)); err != nil {
		t.Fatalf("seed slot 0: %v", err)
	}
	if err := handles["cgroup_op_policy"].Put(cgroupOpKey(cgroupID, BpfOpExec, 1), cgroupOpValue(BpfActionAllow, BpfEnforceModePermissive, 2)); err != nil {
		t.Fatalf("seed slot 1: %v", err)
	}
	if err := handles["cgroup_managed"].Put(managedKey(cgroupID), managedValue(0, 2, 1)); err != nil {
		t.Fatalf("seed managed: %v", err)
	}

	if err := RemovePolicyMaps(maps, cgroupID); err != nil {
		t.Fatalf("RemovePolicyMaps: unexpected error: %v", err)
	}

	var v cgroupOpValueLayout
	if err := handles["cgroup_op_policy"].Lookup(cgroupOpKey(cgroupID, BpfOpExec, 0), unsafe.Pointer(&v)); err == nil {
		t.Error("slot 0 entry still present after RemovePolicyMaps")
	}
	if err := handles["cgroup_op_policy"].Lookup(cgroupOpKey(cgroupID, BpfOpExec, 1), unsafe.Pointer(&v)); err == nil {
		t.Error("slot 1 entry still present after RemovePolicyMaps")
	}
	var mv managedValueLayout
	if err := handles["cgroup_managed"].Lookup(managedKey(cgroupID), unsafe.Pointer(&mv)); err == nil {
		t.Error("cgroup_managed entry still present after RemovePolicyMaps")
	}
}

func TestRemovePolicyMaps_MissingEntriesAreNotErrors(t *testing.T) {
	t.Parallel()
	maps, _, _ := fakePolicyMaps()
	// Nothing seeded — every Delete call hits a missing key.
	if err := RemovePolicyMaps(maps, 12345); err != nil {
		t.Fatalf("RemovePolicyMaps on empty maps: unexpected error: %v", err)
	}
}

func TestDeleteBootstrapFileEntries_RemovesExactPathIdentity(t *testing.T) {
	t.Parallel()
	maps, _, handles := fakePolicyMaps()
	const cgroupID = uint64(91)
	file := BootstrapFile{Path: "/workspace/agent.py", KernelDevice: 17, Inode: 29}
	req := samplePolicyReq(7, BpfEnforceModeEnforce)
	req.RootPID = 4242
	req.BootstrapFiles = []BootstrapFile{file}
	if err := ApplyPolicyMaps(maps, cgroupID, req); err != nil {
		t.Fatalf("ApplyPolicyMaps: %v", err)
	}

	key, err := bootstrapFileKey(cgroupID, file)
	if err != nil {
		t.Fatal(err)
	}
	if err := DeleteBootstrapFileEntries(maps, cgroupID, []BootstrapFile{file}); err != nil {
		t.Fatalf("DeleteBootstrapFileEntries: %v", err)
	}
	var value bootstrapFileValueLayout
	if err := handles["cgroup_bootstrap_file_allow"].Lookup(key, &value); err == nil {
		t.Fatal("bootstrap file entry remains after deletion")
	}
}

// --- isNotFound --------------------------------------------------------

func TestIsNotFound_MatchesRealSentinelMessage(t *testing.T) {
	t.Parallel()
	// This is the exact message cilium/ebpf.ErrKeyNotExist carries — a prior
	// version of isNotFound matched the substring "not found", which never
	// appears in this message, so RemovePolicyMaps treated every ordinary
	// missing-key delete as a real error.
	if !isNotFound(errors.New("key does not exist")) {
		t.Error(`isNotFound(errors.New("key does not exist")) = false, want true`)
	}
}

func TestIsNotFound_NilAndUnrelatedErrors(t *testing.T) {
	t.Parallel()
	if isNotFound(nil) {
		t.Error("isNotFound(nil) = true, want false")
	}
	if isNotFound(errors.New("permission denied")) {
		t.Error(`isNotFound(errors.New("permission denied")) = true, want false`)
	}
}

// --- Key/value layout ----------------------------------------------------

func TestCgroupOpKeyLayout_FieldsRoundTrip(t *testing.T) {
	t.Parallel()
	p := cgroupOpKey(1234, BpfOpNetConnect, 1)
	k := (*cgroupOpKeyLayout)(p)
	if k.CgroupID != 1234 || k.Op != uint32(BpfOpNetConnect) || k.Slot != 1 {
		t.Errorf("cgroupOpKey layout = %+v, want {CgroupID:1234 Op:%d Slot:1}", k, BpfOpNetConnect)
	}
	if got := unsafe.Sizeof(cgroupOpKeyLayout{}); got != 16 {
		t.Errorf("cgroupOpKeyLayout size = %d, want 16 (must match struct ardur_cgroup_op_key in process_guard.bpf.c)", got)
	}
}

func TestManagedValueLayout_Size(t *testing.T) {
	t.Parallel()
	if got := unsafe.Sizeof(managedValueLayout{}); got != 12 {
		t.Errorf("managedValueLayout size = %d, want 12 (must match struct ardur_managed_value in process_guard.bpf.c)", got)
	}
}

// TestPathLpmKeyLayout_DataPortionFitsKernelLPMCap catches a bug that only a
// real kernel could otherwise surface: BPF_MAP_TYPE_LPM_TRIE caps a key's
// data portion (everything after the leading __u32 prefixlen) at 256 bytes
// (LPM_DATA_SIZE_MAX in kernel/bpf/lpm_trie.c). Map *creation* fails with
// EINVAL above that — taking every path-allowlist policy down with it, not
// just long-path entries — which is exactly what happened when
// ardur_path_lpm_key was cgroup_raw[8] + path[256] (264 bytes of data, 8
// over the cap): confirmed on a real BPF-LSM kernel via the kernel-smoke CI
// job ("map cgroup_path_allow: map create: invalid argument"), something
// darwin-only unit tests and a non-privileged Linux build can't catch.
func TestPathLpmKeyLayout_DataPortionFitsKernelLPMCap(t *testing.T) {
	t.Parallel()
	const kernelLPMDataCap = 256
	prefixlenSize := unsafe.Sizeof(uint32(0))
	dataPortion := unsafe.Sizeof(pathLpmKeyLayout{}) - prefixlenSize
	if dataPortion > kernelLPMDataCap {
		t.Errorf("ardur_path_lpm_key data portion = %d bytes, exceeds the kernel's %d-byte BPF_MAP_TYPE_LPM_TRIE cap by %d bytes — cgroup_path_allow map creation will fail with EINVAL on every real kernel",
			dataPortion, kernelLPMDataCap, dataPortion-kernelLPMDataCap)
	}
}

// TestNetLpmKeyLayout_DataPortionFitsKernelLPMCap is the same guard as
// TestPathLpmKeyLayout_DataPortionFitsKernelLPMCap, for cgroup_net_allow.
// It's nowhere near the 256-byte cap today (cgroup_raw[8] + addr[16] = 24
// bytes), but a future change to widen the address field should trip this
// rather than fail EINVAL only on a real kernel.
func TestNetLpmKeyLayout_DataPortionFitsKernelLPMCap(t *testing.T) {
	t.Parallel()
	const kernelLPMDataCap = 256
	prefixlenSize := unsafe.Sizeof(uint32(0))
	dataPortion := unsafe.Sizeof(netLpmKeyLayout{}) - prefixlenSize
	if dataPortion > kernelLPMDataCap {
		t.Errorf("ardur_net_lpm_key data portion = %d bytes, exceeds the kernel's %d-byte BPF_MAP_TYPE_LPM_TRIE cap by %d bytes",
			dataPortion, kernelLPMDataCap, dataPortion-kernelLPMDataCap)
	}
}

func TestPathLpmKey_RejectsRelativePath(t *testing.T) {
	t.Parallel()
	if _, err := pathLpmKey(1, "relative/path"); err == nil {
		t.Error("pathLpmKey with relative path: expected error, got nil")
	}
}

func TestPathLpmKey_TruncatesOversizePath(t *testing.T) {
	t.Parallel()
	p, err := pathLpmKey(1, "/"+repeatByte('a', bpfPathLpmDataLen*2))
	if err != nil {
		t.Fatalf("pathLpmKey: unexpected error: %v", err)
	}
	k := (*pathLpmKeyLayout)(p)
	if k.Prefixlen > 64+uint32(bpfPathLpmDataLen-1)*8 {
		t.Errorf("prefixlen = %d, exceeds max representable path length", k.Prefixlen)
	}
}

// --- fileAllowKey ------------------------------------------------------

func TestFileAllowKey_RejectsRelativePath(t *testing.T) {
	t.Parallel()
	if _, err := fileAllowKey(1, "relative/path"); err == nil {
		t.Error("fileAllowKey with relative path: expected error, got nil")
	}
}

func TestFileAllowKey_TruncatesOversizePath(t *testing.T) {
	t.Parallel()
	p, err := fileAllowKey(1, "/"+repeatByte('a', bpfPathLen*2))
	if err != nil {
		t.Fatalf("fileAllowKey: unexpected error: %v", err)
	}
	k := (*fileAllowKeyLayout)(p)
	if len(k.Path) != bpfPathLen {
		t.Fatalf("Path field size = %d, want %d", len(k.Path), bpfPathLen)
	}
}

// TestFileAllowKey_FieldsRoundTrip mirrors TestCgroupOpKeyLayout_FieldsRoundTrip
// for the new hash key: same cgroup scoping, and the path bytes land exactly
// where ardur_file_allow_key (process_guard.bpf.c) expects them, with the
// remainder zero-padded (required for exact-match HASH lookups: two keys
// with the same path prefix but different padding would otherwise never
// compare equal to what the BPF side writes via bpf_probe_read_kernel into a
// zeroed scratch buffer).
func TestFileAllowKey_FieldsRoundTrip(t *testing.T) {
	t.Parallel()
	p, err := fileAllowKey(1234, "/workspace")
	if err != nil {
		t.Fatalf("fileAllowKey: %v", err)
	}
	k := (*fileAllowKeyLayout)(p)

	var wantCgroup [8]byte
	binary.NativeEndian.PutUint64(wantCgroup[:], 1234)
	if k.CgroupRaw != wantCgroup {
		t.Errorf("CgroupRaw = %v, want %v", k.CgroupRaw, wantCgroup)
	}

	wantPath := "/workspace"
	if got := string(k.Path[:len(wantPath)]); got != wantPath {
		t.Errorf("Path prefix = %q, want %q", got, wantPath)
	}
	for i := len(wantPath); i < len(k.Path); i++ {
		if k.Path[i] != 0 {
			t.Fatalf("Path[%d] = %d, want 0 (zero-padded tail)", i, k.Path[i])
		}
	}
}

// TestFileAllowKey_DistinctPrefixesProduceDistinctKeys guards the exact-match
// property a HASH map depends on: "/data" and "/database" must NOT collide,
// unlike the LPM trie's byte-prefix matching (see ardur_file_allow_key's doc
// comment on the SubpathPolicy boundary-matching fix this enables).
func TestFileAllowKey_DistinctPrefixesProduceDistinctKeys(t *testing.T) {
	t.Parallel()
	p1, err := fileAllowKey(1, "/data")
	if err != nil {
		t.Fatalf("fileAllowKey(/data): %v", err)
	}
	p2, err := fileAllowKey(1, "/database")
	if err != nil {
		t.Fatalf("fileAllowKey(/database): %v", err)
	}
	k1 := (*fileAllowKeyLayout)(p1)
	k2 := (*fileAllowKeyLayout)(p2)
	if *k1 == *k2 {
		t.Error("fileAllowKey(/data) == fileAllowKey(/database), want distinct keys")
	}
}

func repeatByte(b byte, n int) string {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = b
	}
	return string(buf)
}

func TestNetLpmKey_IPv4AndIPv6(t *testing.T) {
	t.Parallel()
	p4, err := netLpmKey(1, "10.0.0.0/8")
	if err != nil {
		t.Fatalf("netLpmKey IPv4: %v", err)
	}
	k4 := (*netLpmKeyLayout)(p4)
	if k4.Prefixlen != 64+8 {
		t.Errorf("IPv4 prefixlen = %d, want 72", k4.Prefixlen)
	}

	p6, err := netLpmKey(1, "2001:db8::/32")
	if err != nil {
		t.Fatalf("netLpmKey IPv6: %v", err)
	}
	k6 := (*netLpmKeyLayout)(p6)
	if k6.Prefixlen != 64+32 {
		t.Errorf("IPv6 prefixlen = %d, want 96", k6.Prefixlen)
	}
}

func TestNetLpmKey_InvalidAddressErrors(t *testing.T) {
	t.Parallel()
	if _, err := netLpmKey(1, "not-an-address"); err == nil {
		t.Error("netLpmKey with invalid address: expected error, got nil")
	}
}
