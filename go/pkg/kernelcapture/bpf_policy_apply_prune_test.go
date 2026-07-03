package kernelcapture

// bpf_policy_apply_prune_test.go — regression tests for the stale-policy-state
// fix: ApplyPolicyMaps now clears the inactive double-buffer slot before
// writing, and DeleteAllowlistEntries revokes specific path/net allowlist
// entries (the daemon calls it on re-apply and session end). See the
// stale-policy-state finding these close.

import (
	"testing"
	"unsafe"
)

// TestApplyPolicyMaps_ClearsInactiveSlotBeforeWrite proves an op rule written
// two generations ago (same slot) does NOT survive the slot flip when a later
// generation omits that op. Before the fix, the stale rule became live again.
func TestApplyPolicyMaps_ClearsInactiveSlotBeforeWrite(t *testing.T) {
	maps, _, h := fakePolicyMaps()
	cg := uint64(4242)

	gen1 := DaemonApplyPolicyRequest{SessionID: "s", Generation: 1, EnforceMode: BpfEnforceModeEnforce,
		OpPolicies: []DaemonOpPolicy{
			{Op: BpfOpExec, Action: BpfActionDeny, EnforceMode: BpfEnforceModeEnforce},
			{Op: BpfOpNetConnect, Action: BpfActionAllow, EnforceMode: BpfEnforceModeEnforce}, // NET allowed
		}}
	onlyExec := func(gen BpfPolicyGeneration) DaemonApplyPolicyRequest {
		return DaemonApplyPolicyRequest{SessionID: "s", Generation: gen, EnforceMode: BpfEnforceModeEnforce,
			OpPolicies: []DaemonOpPolicy{{Op: BpfOpExec, Action: BpfActionDeny, EnforceMode: BpfEnforceModeEnforce}}}
	}
	for _, req := range []DaemonApplyPolicyRequest{gen1, onlyExec(2), onlyExec(3)} {
		if err := ApplyPolicyMaps(maps, cg, req); err != nil {
			t.Fatalf("apply gen %d: %v", req.Generation, err)
		}
	}

	var mv managedValueLayout
	if err := h["cgroup_managed"].Lookup(managedKey(cg), unsafe.Pointer(&mv)); err != nil {
		t.Fatalf("managed lookup: %v", err)
	}
	var netv cgroupOpValueLayout
	if err := h["cgroup_op_policy"].Lookup(cgroupOpKey(cg, BpfOpNetConnect, mv.ActiveSlot), unsafe.Pointer(&netv)); err == nil {
		t.Fatalf("stale NET_CONNECT rule (action=%d gen=%d) survived in the active slot %d; the inactive slot was not cleared before write", netv.Action, netv.Generation, mv.ActiveSlot)
	}
	// The op the later generations DID specify must still be present.
	var execv cgroupOpValueLayout
	if err := h["cgroup_op_policy"].Lookup(cgroupOpKey(cg, BpfOpExec, mv.ActiveSlot), unsafe.Pointer(&execv)); err != nil {
		t.Fatalf("EXEC rule missing from active slot %d after apply: %v", mv.ActiveSlot, err)
	}
}

// TestDeleteAllowlistEntries_RemovesOnlyNamedKeys proves the revocation helper
// deletes exactly the path/net keys it is given and leaves the rest.
func TestDeleteAllowlistEntries_RemovesOnlyNamedKeys(t *testing.T) {
	maps, _, h := fakePolicyMaps()
	cg := uint64(777)

	req := DaemonApplyPolicyRequest{SessionID: "s", Generation: 1, EnforceMode: BpfEnforceModeEnforce,
		OpPolicies: []DaemonOpPolicy{{Op: BpfOpFileRead, Action: BpfActionAllowlist, EnforceMode: BpfEnforceModeEnforce}},
		PathAllow:  []string{"/tmp/a", "/tmp/b"},
		NetAllow:   []string{"10.0.0.0/24", "192.168.1.0/24"}}
	if err := ApplyPolicyMaps(maps, cg, req); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Revoke /tmp/b and 10.0.0.0/24 only.
	if err := DeleteAllowlistEntries(maps, cg, []string{"/tmp/b"}, []string{"10.0.0.0/24"}); err != nil {
		t.Fatalf("delete allowlist entries: %v", err)
	}

	present := func(mapName string, key unsafe.Pointer) bool {
		var v uint64
		return h[mapName].Lookup(key, unsafe.Pointer(&v)) == nil
	}
	kA, _ := fileAllowKey(cg, "/tmp/a")
	kB, _ := fileAllowKey(cg, "/tmp/b")
	if !present("cgroup_file_allow", kA) {
		t.Error("/tmp/a should remain after revoking only /tmp/b")
	}
	if present("cgroup_file_allow", kB) {
		t.Error("/tmp/b should be gone after revocation (allowlist revocation must actually revoke)")
	}
	kNetGone, _ := netLpmKey(cg, "10.0.0.0/24")
	kNetKeep, _ := netLpmKey(cg, "192.168.1.0/24")
	if present("cgroup_net_allow", kNetGone) {
		t.Error("10.0.0.0/24 should be gone after revocation")
	}
	if !present("cgroup_net_allow", kNetKeep) {
		t.Error("192.168.1.0/24 should remain")
	}
}

// TestDeleteAllowlistEntries_NotFoundIsNotAnError confirms deleting a key that
// was never written is a no-op, not a failure (best-effort revocation).
func TestDeleteAllowlistEntries_NotFoundIsNotAnError(t *testing.T) {
	maps, _, _ := fakePolicyMaps()
	if err := DeleteAllowlistEntries(maps, 999, []string{"/never/written"}, []string{"8.8.8.8/32"}); err != nil {
		t.Fatalf("deleting absent allowlist keys should be a no-op, got: %v", err)
	}
}
