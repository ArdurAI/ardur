package main

// daemon_authz_test.go — regression tests for the enforcement-surface security
// fixes: per-session ownership on apply_policy + admin-only set_kill_switch
// (missing-authorization finding), allowlist revocation on re-apply / session
// end (stale-policy-state finding), and serialized policy-map mutation
// (double-buffer race finding).

import (
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

// countingPolicyMap is a minimal policyMapReadWriter that records how many
// Put/Delete calls it received. Lookup always reports "not found" so
// nextPolicySlot falls back to slot 0 (slot mechanics are covered elsewhere).
// Its counters are plain ints on purpose: with the daemon's applyMu absent,
// concurrent apply_policy would write them unsynchronized and `go test -race`
// would flag it — making the concurrency test non-vacuous.
type countingPolicyMap struct {
	puts    int
	deletes int
}

var errCountingNotFound = errors.New("key does not exist")

func (m *countingPolicyMap) Put(_, _ interface{}) error    { m.puts++; return nil }
func (m *countingPolicyMap) Delete(_ interface{}) error    { m.deletes++; return nil }
func (m *countingPolicyMap) Lookup(_, _ interface{}) error { return errCountingNotFound }

func countingPolicyMaps() (kernelcapture.PolicyMaps, map[string]*countingPolicyMap) {
	op := &countingPolicyMap{}
	path := &countingPolicyMap{}
	file := &countingPolicyMap{}
	bootstrapFile := &countingPolicyMap{}
	bootstrapObservation := &countingPolicyMap{}
	control := &countingPolicyMap{}
	trustedRoot := &countingPolicyMap{}
	net := &countingPolicyMap{}
	managed := &countingPolicyMap{}
	kill := &countingPolicyMap{}
	return kernelcapture.PolicyMaps{
		CgroupOpPolicy:           op,
		CgroupPathAllow:          path,
		CgroupFileAllow:          file,
		CgroupBootstrapFileAllow: bootstrapFile,
		BootstrapFileObservation: bootstrapObservation,
		CgroupControlPlaneAllow:  control,
		CgroupTrustedRoot:        trustedRoot,
		CgroupNetAllow:           net,
		CgroupManaged:            managed,
		KillSwitch:               kill,
	}, map[string]*countingPolicyMap{"op": op, "path": path, "file": file, "bootstrap_file": bootstrapFile, "bootstrap_observation": bootstrapObservation, "control": control, "trusted_root": trustedRoot, "net": net, "managed": managed, "kill": kill}
}

// --- #108: apply_policy ownership --------------------------------------------

func TestHandleApplyPolicy_ForeignPeerRejected(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	registerTestSession(t, d, "ses-owned", 4200) // registered by the uid-501/pid-4321 peer

	// A DIFFERENT peer (same uid, different pid+start-time) must be rejected.
	foreign := testPeerHandshakeUID("", kernelcapture.DaemonProtocolMethodApplyPolicy, 501)
	foreign.Authorization.PID = 9999
	foreign.ProcessStartTimeTicks = 123456
	foreign.Authorization.ProcessStartTimeTicks = 123456

	resp := d.handleApplyPolicy(applyPolicyReqFor("ses-owned", kernelcapture.BpfEnforceModePermissive), foreign)
	if resp.OK {
		t.Fatalf("foreign peer apply_policy: OK = true, want false (must be rejected): %+v", resp)
	}
	if !strings.Contains(resp.Error, "owned by a different peer") {
		t.Fatalf("foreign peer apply_policy: error = %q, want it to name the ownership failure", resp.Error)
	}

	// The OWNING peer is not rejected for ownership (it degrades on the missing
	// guard instead — a different, non-ownership outcome).
	owner := testPeerHandshake("", kernelcapture.DaemonProtocolMethodApplyPolicy)
	respOwner := d.handleApplyPolicy(applyPolicyReqFor("ses-owned", kernelcapture.BpfEnforceModePermissive), owner)
	if strings.Contains(respOwner.Error, "owned by a different peer") {
		t.Fatalf("owning peer apply_policy was wrongly rejected for ownership: %+v", respOwner)
	}
}

func TestHandleApplyPolicy_ForeignPeerCannotInstallControlPlaneEndpoint(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	d.activeTier = daemonTierSeccomp
	registerTestSession(t, d, "ses-control-owned", 4201)

	req := applyNetConnectPolicyReqFor(
		"ses-control-owned", kernelcapture.BpfActionDeny, kernelcapture.BpfEnforceModeEnforce,
	)
	req.ApplyPolicy.ControlPlaneEndpoint = &kernelcapture.DaemonControlPlaneEndpoint{
		IP: "127.0.0.1", Port: 43210,
	}

	foreign := testPeerHandshakeUID("", kernelcapture.DaemonProtocolMethodApplyPolicy, 501)
	foreign.Authorization.PID = 9999
	foreign.ProcessStartTimeTicks = 123456
	foreign.Authorization.ProcessStartTimeTicks = 123456
	if resp := d.handleApplyPolicy(req, foreign); resp.OK {
		t.Fatalf("foreign peer installed control-plane endpoint: %+v", resp)
	}
	if _, _, ok := kernelcapture.MatchSeccompControlPlaneEndpoint(
		d.seccompPolicy, "ses-control-owned", net.ParseIP("127.0.0.1"), 43210,
	); ok {
		t.Fatal("foreign peer rejection still mutated the seccomp control-plane store")
	}

	owner := testPeerHandshake("", kernelcapture.DaemonProtocolMethodApplyPolicy)
	if resp := d.handleApplyPolicy(req, owner); !resp.OK {
		t.Fatalf("session-owning peer could not install control-plane endpoint: %+v", resp)
	}
	if _, _, ok := kernelcapture.MatchSeccompControlPlaneEndpoint(
		d.seccompPolicy, "ses-control-owned", net.ParseIP("127.0.0.1"), 43210,
	); !ok {
		t.Fatal("session-owning peer did not install the exact control-plane endpoint")
	}
}

// --- #108: set_kill_switch admin-only ----------------------------------------

func TestHandleSetKillSwitch_RequiresRootAdmin(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	req := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodSetKillSwitch,
		SetKillSwitch:   &kernelcapture.DaemonSetKillSwitchRequest{Engaged: true},
	}
	// Non-root allowed peer: rejected on the admin gate, before touching maps.
	nonRoot := d.handleSetKillSwitch(req, testPeerHandshakeUID("", kernelcapture.DaemonProtocolMethodSetKillSwitch, 501))
	if nonRoot.OK || !strings.Contains(nonRoot.Error, "admin") {
		t.Fatalf("non-root set_kill_switch: want OK=false with an admin error, got %+v", nonRoot)
	}
	// Root peer passes the admin gate (then fails on the absent guard — NOT the
	// admin error), proving the gate is what blocks the non-root caller.
	root := d.handleSetKillSwitch(req, testPeerHandshakeUID("", kernelcapture.DaemonProtocolMethodSetKillSwitch, 0))
	if strings.Contains(root.Error, "admin") {
		t.Fatalf("root set_kill_switch was wrongly blocked by the admin gate: %+v", root)
	}
}

// --- #109: allowlist revocation on re-apply / session end --------------------

func TestHandleApplyPolicy_ReapplyRevokesDroppedAllowlist(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	maps, h := countingPolicyMaps()
	d.policyMaps = maps
	registerTestSession(t, d, "ses-prune", 5500)
	owner := testPeerHandshake("", kernelcapture.DaemonProtocolMethodApplyPolicy)

	apply := func(gen kernelcapture.BpfPolicyGeneration, paths []string) {
		ap := &kernelcapture.DaemonApplyPolicyRequest{
			SessionID: "ses-prune", Generation: gen, EnforceMode: kernelcapture.BpfEnforceModeEnforce,
			OpPolicies: []kernelcapture.DaemonOpPolicy{{Op: kernelcapture.BpfOpFileRead, Action: kernelcapture.BpfActionAllowlist, EnforceMode: kernelcapture.BpfEnforceModeEnforce}},
			PathAllow:  paths,
		}
		resp := d.handleApplyPolicy(kernelcapture.DaemonProtocolRequest{
			ProtocolVersion: kernelcapture.DaemonProtocolVersion,
			Method:          kernelcapture.DaemonProtocolMethodApplyPolicy,
			ApplyPolicy:     ap,
		}, owner)
		if !resp.OK {
			t.Fatalf("apply gen %d: %+v", gen, resp)
		}
	}

	apply(1, []string{"/tmp/a", "/tmp/b"})
	before := h["file"].deletes
	apply(2, []string{"/tmp/a"}) // drops /tmp/b
	if got := h["file"].deletes - before; got != 1 {
		t.Fatalf("re-apply dropping /tmp/b: file-allow deletes = %d, want 1 (the dropped entry must be revoked)", got)
	}

	// Session end must release the remaining allowlist entry too.
	endDeletes := h["file"].deletes
	d.onSessionEnded("ses-prune")
	if h["file"].deletes <= endDeletes {
		t.Fatalf("session end: file-allow deletes did not increase (remaining allowlist entry not released)")
	}
}

// --- #110: concurrent apply_policy is serialized -----------------------------

func TestHandleApplyPolicy_ConcurrentAppliesSerialized(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	maps, h := countingPolicyMaps()
	d.policyMaps = maps
	registerTestSession(t, d, "ses-conc", 6600)
	owner := testPeerHandshake("", kernelcapture.DaemonProtocolMethodApplyPolicy)

	const n = 32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(gen kernelcapture.BpfPolicyGeneration) {
			defer wg.Done()
			ap := &kernelcapture.DaemonApplyPolicyRequest{
				SessionID: "ses-conc", Generation: gen, EnforceMode: kernelcapture.BpfEnforceModeEnforce,
				OpPolicies: []kernelcapture.DaemonOpPolicy{{Op: kernelcapture.BpfOpExec, Action: kernelcapture.BpfActionDeny, EnforceMode: kernelcapture.BpfEnforceModeEnforce}},
			}
			d.handleApplyPolicy(kernelcapture.DaemonProtocolRequest{
				ProtocolVersion: kernelcapture.DaemonProtocolVersion,
				Method:          kernelcapture.DaemonProtocolMethodApplyPolicy,
				ApplyPolicy:     ap,
			}, owner)
		}(kernelcapture.BpfPolicyGeneration(i + 1))
	}
	wg.Wait()

	// Each apply writes cgroup_managed exactly once. Under applyMu the counter
	// increments are serialized, so all n land; a missing applyMu would race
	// (caught by -race) and could also lose increments.
	if h["managed"].puts != n {
		t.Fatalf("cgroup_managed puts = %d, want %d — concurrent applies were not serialized", h["managed"].puts, n)
	}
}
