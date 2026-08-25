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

// countingPolicyMap is a minimal policyMapReadWriter that records Put/Delete
// counts and can optionally trace call order or inject a delete failure. Lookup
// always reports "not found" so nextPolicySlot falls back to slot 0 (slot
// mechanics are covered elsewhere). Its counters are plain ints on purpose:
// with the daemon's applyMu absent, concurrent apply_policy would write them
// unsynchronized and `go test -race` would flag it — making the concurrency
// test non-vacuous.
type countingPolicyMap struct {
	name      string
	events    *[]string
	puts      int
	deletes   int
	deleteErr error
}

var errCountingNotFound = errors.New("key does not exist")

func (m *countingPolicyMap) Put(_, _ interface{}) error {
	m.puts++
	if m.events != nil {
		*m.events = append(*m.events, "put:"+m.name)
	}
	return nil
}

func (m *countingPolicyMap) Delete(_ interface{}) error {
	m.deletes++
	if m.events != nil {
		*m.events = append(*m.events, "delete:"+m.name)
	}
	return m.deleteErr
}

func (m *countingPolicyMap) Lookup(_, _ interface{}) error { return errCountingNotFound }

func countingPolicyMaps() (kernelcapture.PolicyMaps, map[string]*countingPolicyMap) {
	return countingPolicyMapsWithEvents(nil)
}

func countingPolicyMapsWithEvents(events *[]string) (kernelcapture.PolicyMaps, map[string]*countingPolicyMap) {
	newMap := func(name string) *countingPolicyMap {
		return &countingPolicyMap{name: name, events: events}
	}
	op := newMap("op")
	path := newMap("path")
	file := newMap("file")
	bootstrapFile := newMap("bootstrap_file")
	bootstrapObservation := newMap("bootstrap_observation")
	control := newMap("control")
	trustedRoot := newMap("trusted_root")
	net := newMap("net")
	managed := newMap("managed")
	kill := newMap("kill")
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
	var events []string
	maps, h := countingPolicyMapsWithEvents(&events)
	d.activatePolicyMaps(maps)
	registerTestSession(t, d, "ses-prune", 5500)
	owner := testPeerHandshake("", kernelcapture.DaemonProtocolMethodApplyPolicy)

	apply := func(gen kernelcapture.BpfPolicyGeneration, paths, nets []string) {
		ap := &kernelcapture.DaemonApplyPolicyRequest{
			SessionID: "ses-prune", Generation: gen, EnforceMode: kernelcapture.BpfEnforceModeEnforce,
			OpPolicies: []kernelcapture.DaemonOpPolicy{
				{Op: kernelcapture.BpfOpFileRead, Action: kernelcapture.BpfActionAllowlist, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
				{Op: kernelcapture.BpfOpNetConnect, Action: kernelcapture.BpfActionAllowlist, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
			},
			PathAllow: paths,
			NetAllow:  nets,
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

	apply(1, []string{"/tmp/a", "/tmp/b"}, []string{"10.0.0.0/8", "192.0.2.0/24"})
	beforeFile := h["file"].deletes
	beforeNet := h["net"].deletes
	events = nil
	apply(2, []string{"/tmp/a"}, []string{"10.0.0.0/8"}) // drops /tmp/b and 192.0.2.0/24
	if got := h["file"].deletes - beforeFile; got != 1 {
		t.Fatalf("re-apply dropping /tmp/b: file-allow deletes = %d, want 1 (the dropped entry must be revoked)", got)
	}
	if got := h["net"].deletes - beforeNet; got != 1 {
		t.Fatalf("re-apply dropping 192.0.2.0/24: net-allow deletes = %d, want 1 (the dropped entry must be revoked)", got)
	}
	fileDeleteIndex, netDeleteIndex, gateIndex := -1, -1, -1
	for i, event := range events {
		switch event {
		case "delete:file":
			fileDeleteIndex = i
		case "delete:net":
			netDeleteIndex = i
		case "put:managed":
			gateIndex = i
		}
	}
	if fileDeleteIndex < 0 || netDeleteIndex < 0 || gateIndex < 0 || fileDeleteIndex >= gateIndex || netDeleteIndex >= gateIndex {
		t.Fatalf("re-apply event order = %v, want stale file/net deletes before managed generation gate", events)
	}

	// Session end must release the remaining allowlist entry too.
	endDeletes := h["file"].deletes
	d.onSessionEnded("ses-prune")
	if h["file"].deletes <= endDeletes {
		t.Fatalf("session end: file-allow deletes did not increase (remaining allowlist entry not released)")
	}
}

func TestHandleApplyPolicy_StaleAllowlistDeleteFailurePreventsGenerationFlip(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mapName  string
		oldPaths []string
		newPaths []string
		oldNets  []string
		newNets  []string
	}{
		{name: "file hash", mapName: "file", oldPaths: []string{"/tmp/a", "/tmp/b"}, newPaths: []string{"/tmp/a"}},
		{name: "network LPM", mapName: "net", oldNets: []string{"10.0.0.0/8", "192.0.2.0/24"}, newNets: []string{"10.0.0.0/8"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := newTestDaemon(t)
			maps, h := countingPolicyMaps()
			d.activatePolicyMaps(maps)
			sessionID := "ses-prune-fail-" + tc.mapName
			registerTestSession(t, d, sessionID, 5501)
			owner := testPeerHandshake("", kernelcapture.DaemonProtocolMethodApplyPolicy)

			apply := func(gen kernelcapture.BpfPolicyGeneration, paths, nets []string) kernelcapture.DaemonProtocolResponse {
				return d.handleApplyPolicy(kernelcapture.DaemonProtocolRequest{
					ProtocolVersion: kernelcapture.DaemonProtocolVersion,
					Method:          kernelcapture.DaemonProtocolMethodApplyPolicy,
					ApplyPolicy: &kernelcapture.DaemonApplyPolicyRequest{
						SessionID: sessionID, Generation: gen, EnforceMode: kernelcapture.BpfEnforceModeEnforce,
						OpPolicies: []kernelcapture.DaemonOpPolicy{
							{Op: kernelcapture.BpfOpFileRead, Action: kernelcapture.BpfActionAllowlist, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
							{Op: kernelcapture.BpfOpNetConnect, Action: kernelcapture.BpfActionAllowlist, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
						},
						PathAllow: paths,
						NetAllow:  nets,
					},
				}, owner)
			}

			if resp := apply(1, tc.oldPaths, tc.oldNets); !resp.OK {
				t.Fatalf("initial apply: %+v", resp)
			}
			managedPuts := h["managed"].puts
			h[tc.mapName].deleteErr = errors.New("injected stale-entry delete failure")

			resp := apply(2, tc.newPaths, tc.newNets)
			if resp.OK {
				t.Fatalf("re-apply with failed stale revocation returned OK: %+v", resp)
			}
			if !strings.Contains(resp.Error, "revoke stale allowlist") {
				t.Fatalf("re-apply error = %q, want stale-revocation context", resp.Error)
			}
			if h["managed"].puts != managedPuts {
				t.Fatalf("managed gate puts = %d, want %d after failed stale revocation", h["managed"].puts, managedPuts)
			}
		})
	}
}

// --- #110: concurrent apply_policy is serialized -----------------------------

func TestHandleApplyPolicy_ConcurrentAppliesSerialized(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	maps, h := countingPolicyMaps()
	d.activatePolicyMaps(maps)
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
