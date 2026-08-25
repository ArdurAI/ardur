package main

// daemon_apply_policy_test.go — tests for the daemon-side apply_policy /
// set_kill_switch dispatch (main.go). These exercise the ENFORCE_STRICT vs
// permissive degradation behaviour from the Slice 4.2 review: on a host
// where the BPF-LSM guard never loaded (d.policyMaps is the zero value —
// exactly what happens on darwin, or on Linux without BPF-LSM), apply_policy
// must fail loudly under ENFORCE_STRICT and record a degradation (without
// hard-failing the request) under PERMISSIVE. Neither path may panic.

import (
	"context"
	"net"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

// registerTestSession registers sessionID with cgroupID directly through the
// registry's authorized-request path (mirrors
// daemonSessionRegistryTestHandshake in the kernelcapture package's own
// tests) so handleApplyPolicy's d.registry.ActiveSession lookup succeeds.
// testPeerHandshake returns a valid allow-verdict handshake for a fixed test
// peer (uid 501). registerTestSession and the apply_policy call sites use the
// SAME peer identity so the ownership gate handleApplyPolicy now enforces
// (session must be owned by the calling peer) is satisfied on the happy path.
// Use testPeerHandshakeUID with uid=0 to exercise the admin identity
// set_kill_switch requires, or a different uid/pid to simulate a foreign peer.
func testPeerHandshake(sessionID, method string) kernelcapture.DaemonProtocolPeerHandshake {
	return testPeerHandshakeUID(sessionID, method, 501)
}

func testPeerHandshakeUID(sessionID, method string, uid uint32) kernelcapture.DaemonProtocolPeerHandshake {
	return kernelcapture.DaemonProtocolPeerHandshake{
		ProtocolVersion:       kernelcapture.DaemonProtocolVersion,
		Method:                method,
		SessionID:             sessionID,
		SocketPath:            "/run/ardur/kernelcapture/control.sock",
		CredentialSource:      kernelcapture.DaemonPeerCredentialSourceLinuxSOPeerCred,
		ProcessStartTimeTicks: 900001,
		Authorization: kernelcapture.DaemonPeerAuthorization{
			Verdict:               kernelcapture.DaemonPeerAuthorizationVerdictAllow,
			Reason:                "test",
			UID:                   uid,
			GID:                   20,
			PID:                   4321,
			ProcessStartTimeTicks: 900001,
			Matched:               "uid",
		},
	}
}

func registerTestSession(t *testing.T, d *daemon, sessionID string, cgroupID uint64) {
	t.Helper()
	handshake := testPeerHandshake(sessionID, kernelcapture.DaemonProtocolMethodRegisterSession)
	req := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodRegisterSession,
		RegisterSession: &kernelcapture.DaemonRegisterSessionRequest{
			SessionID:    sessionID,
			RootPID:      4321,
			CgroupID:     cgroupID,
			EventClasses: []string{kernelcapture.DaemonProtocolEventProcessLifecycle},
			TTLSeconds:   60,
		},
	}
	resp := d.registry.HandleAuthorizedRequest(context.Background(), req, handshake)
	if !resp.OK {
		t.Fatalf("registerTestSession: register_session failed: %+v", resp)
	}
}

func applyPolicyReqFor(sessionID string, mode kernelcapture.BpfEnforceMode) kernelcapture.DaemonProtocolRequest {
	ap := &kernelcapture.DaemonApplyPolicyRequest{
		SessionID:   sessionID,
		Generation:  1,
		EnforceMode: mode,
		OpPolicies: []kernelcapture.DaemonOpPolicy{
			{Op: kernelcapture.BpfOpExec, Action: kernelcapture.BpfActionDeny, EnforceMode: mode},
		},
	}
	return kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodApplyPolicy,
		ApplyPolicy:     ap,
	}
}

// TestHandleApplyPolicy_EnforceStrictFailsLoudlyWithoutGuard is the
// ENFORCE_STRICT half of the review's nil-guard requirement: with no BPF-LSM
// guard loaded (d.policyMaps is the zero value), apply_policy under ENFORCE
// mode must return a clean OK:false response — never panic, never silently
// report success for a policy that can never be enforced.
func TestHandleApplyPolicy_EnforceStrictFailsLoudlyWithoutGuard(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	registerTestSession(t, d, "ses-strict", 111)

	resp := d.handleApplyPolicy(applyPolicyReqFor("ses-strict", kernelcapture.BpfEnforceModeEnforce), testPeerHandshake("", kernelcapture.DaemonProtocolMethodApplyPolicy))
	if resp.OK {
		t.Fatalf("apply_policy under ENFORCE with no guard loaded: OK = true, want false (must fail loudly): %+v", resp)
	}
	if resp.Error == "" {
		t.Error("apply_policy under ENFORCE with no guard loaded: Error is empty, want a description of the failure")
	}
}

// TestHandleApplyPolicy_PermissiveDegradesWithoutFailingRequest is the
// permissive half: the same missing-guard condition must not hard-fail the
// request, since PERMISSIVE's whole contract is "log, don't block" — but it
// must still be visible to the caller via Status, not silently swallowed.
func TestHandleApplyPolicy_PermissiveDegradesWithoutFailingRequest(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	registerTestSession(t, d, "ses-permissive", 112)

	resp := d.handleApplyPolicy(applyPolicyReqFor("ses-permissive", kernelcapture.BpfEnforceModePermissive), testPeerHandshake("", kernelcapture.DaemonProtocolMethodApplyPolicy))
	if !resp.OK {
		t.Fatalf("apply_policy under PERMISSIVE with no guard loaded: OK = false, want true (degrade, don't block): %+v", resp)
	}
	if resp.Status == "" {
		t.Error("apply_policy under PERMISSIVE with no guard loaded: Status is empty, want a degradation marker")
	}
}

func TestHandleApplyPolicy_UnknownSessionFailsCleanly(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	resp := d.handleApplyPolicy(applyPolicyReqFor("does-not-exist", kernelcapture.BpfEnforceModeEnforce), testPeerHandshake("", kernelcapture.DaemonProtocolMethodApplyPolicy))
	if resp.OK {
		t.Fatal("apply_policy for an unregistered session: OK = true, want false")
	}
}

// --- seccomp tier (plan E4) ---------------------------------------------

func applyNetConnectPolicyReqFor(sessionID string, action kernelcapture.BpfAction, mode kernelcapture.BpfEnforceMode, netAllow ...string) kernelcapture.DaemonProtocolRequest {
	ap := &kernelcapture.DaemonApplyPolicyRequest{
		SessionID:   sessionID,
		Generation:  1,
		EnforceMode: mode,
		OpPolicies: []kernelcapture.DaemonOpPolicy{
			{Op: kernelcapture.BpfOpNetConnect, Action: action, EnforceMode: mode},
		},
		NetAllow: netAllow,
	}
	return kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodApplyPolicy,
		ApplyPolicy:     ap,
	}
}

// TestHandleApplyPolicy_SyncsSeccompStoreEvenWhenBPFTierHardFails asserts the
// seccomp tier's in-memory policy is populated as a side effect of
// handleApplyPolicy regardless of the overall response: a session's seccomp
// policy must already be in place by the time — if ever — a listener
// attaches for it, and apply_policy commonly runs well before that handoff.
func TestHandleApplyPolicy_SyncsSeccompStoreEvenWhenBPFTierHardFails(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	registerTestSession(t, d, "ses-net-enforce", 113)

	resp := d.handleApplyPolicy(applyNetConnectPolicyReqFor("ses-net-enforce", kernelcapture.BpfActionAllow, kernelcapture.BpfEnforceModeEnforce), testPeerHandshake("", kernelcapture.DaemonProtocolMethodApplyPolicy))
	if resp.OK {
		t.Fatalf("apply_policy under ENFORCE with no active tier: OK = true, want false: %+v", resp)
	}

	decision := kernelcapture.EvaluateSeccompConnect(d.seccompPolicy, "ses-net-enforce", net.ParseIP("1.2.3.4"))
	if !decision.HasPolicy || !decision.Allowed {
		t.Errorf("seccomp store not populated despite the overall apply_policy failure: %+v", decision)
	}
}

// TestHandleApplyPolicy_AppliesViaSeccompTierWhenActive is the E4 success
// path: on a host where the seccomp tier (not BPF-LSM) is active, an
// apply_policy request whose ops are entirely within the seccomp tier's
// scope (OP_NET_CONNECT) must be reported as genuinely applied, not
// degraded — BPF-LSM being unavailable isn't a degradation when it was never
// the active tier to begin with.
func TestHandleApplyPolicy_AppliesViaSeccompTierWhenActive(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	d.activeTier = daemonTierSeccomp
	registerTestSession(t, d, "ses-net-seccomp", 114)

	resp := d.handleApplyPolicy(applyNetConnectPolicyReqFor("ses-net-seccomp", kernelcapture.BpfActionDeny, kernelcapture.BpfEnforceModeEnforce), testPeerHandshake("", kernelcapture.DaemonProtocolMethodApplyPolicy))
	if !resp.OK {
		t.Fatalf("apply_policy under ENFORCE with active seccomp tier: OK = false, want true: %+v", resp)
	}
	if resp.Status != "applied_seccomp_tier" {
		t.Errorf("Status = %q, want %q", resp.Status, "applied_seccomp_tier")
	}

	decision := kernelcapture.EvaluateSeccompConnect(d.seccompPolicy, "ses-net-seccomp", net.ParseIP("1.2.3.4"))
	if !decision.HasPolicy || decision.Allowed {
		t.Errorf("seccomp store should reflect the DENY policy: %+v", decision)
	}
}

// TestHandleApplyPolicy_SeccompTierDoesNotCoverNonNetOps confirms the
// applied_seccomp_tier success branch only fires when the request is fully
// within the seccomp tier's scope — a request that also asks for OP_EXEC
// enforcement can't be satisfied by this tier and must still fail loudly
// under ENFORCE mode, exactly like the no-tier-active case.
func TestHandleApplyPolicy_SeccompTierDoesNotCoverNonNetOps(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	d.activeTier = daemonTierSeccomp
	registerTestSession(t, d, "ses-mixed-ops", 115)

	ap := &kernelcapture.DaemonApplyPolicyRequest{
		SessionID:   "ses-mixed-ops",
		Generation:  1,
		EnforceMode: kernelcapture.BpfEnforceModeEnforce,
		OpPolicies: []kernelcapture.DaemonOpPolicy{
			{Op: kernelcapture.BpfOpNetConnect, Action: kernelcapture.BpfActionAllow, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
			{Op: kernelcapture.BpfOpExec, Action: kernelcapture.BpfActionDeny, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
		},
	}
	req := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodApplyPolicy,
		ApplyPolicy:     ap,
	}
	resp := d.handleApplyPolicy(req, testPeerHandshake("", kernelcapture.DaemonProtocolMethodApplyPolicy))
	if resp.OK {
		t.Fatalf("apply_policy mixing OP_EXEC into a seccomp-tier-only host: OK = true, want false: %+v", resp)
	}
}

func TestHandleApplyPolicy_InvalidNetAllowFailsBeforeAnyStoreWrite(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	registerTestSession(t, d, "ses-bad-cidr", 116)

	resp := d.handleApplyPolicy(applyNetConnectPolicyReqFor("ses-bad-cidr", kernelcapture.BpfActionAllowlist, kernelcapture.BpfEnforceModePermissive, "not-a-cidr"), testPeerHandshake("", kernelcapture.DaemonProtocolMethodApplyPolicy))
	if resp.OK {
		t.Fatalf("apply_policy with a malformed net_allow entry: OK = true, want false: %+v", resp)
	}
	decision := kernelcapture.EvaluateSeccompConnect(d.seccompPolicy, "ses-bad-cidr", net.ParseIP("1.2.3.4"))
	if decision.HasPolicy {
		t.Errorf("a rejected apply_policy must not leave a partial seccomp policy in place: %+v", decision)
	}
}

// --- set_kill_switch ---------------------------------------------------

func TestHandleSetKillSwitch_FailsCleanlyWithoutGuard(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	req := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodSetKillSwitch,
		SetKillSwitch:   &kernelcapture.DaemonSetKillSwitchRequest{Engaged: true},
	}
	resp := d.handleSetKillSwitch(req, testPeerHandshakeUID("", kernelcapture.DaemonProtocolMethodSetKillSwitch, 0))
	if resp.OK {
		t.Fatalf("set_kill_switch with no guard loaded: OK = true, want false: %+v", resp)
	}
	if resp.Error == "" {
		t.Error("set_kill_switch with no guard loaded: Error is empty")
	}
}

func TestHandleAuthorizedRequest_DispatchesSetKillSwitch(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	req := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodSetKillSwitch,
		SetKillSwitch:   &kernelcapture.DaemonSetKillSwitchRequest{Engaged: true},
	}
	// handleAuthorizedRequest must route set_kill_switch to handleSetKillSwitch
	// directly (bypassing the session registry, which has no BPF awareness)
	// rather than falling through to registry.HandleAuthorizedRequest, which
	// would reject it as an unsupported method.
	resp := d.handleAuthorizedRequest(context.Background(), req, kernelcapture.DaemonProtocolPeerHandshake{})
	if resp.Method != kernelcapture.DaemonProtocolMethodSetKillSwitch {
		t.Fatalf("handleAuthorizedRequest(set_kill_switch): Method = %q, want %q (not dispatched to handleSetKillSwitch)", resp.Method, kernelcapture.DaemonProtocolMethodSetKillSwitch)
	}
}
