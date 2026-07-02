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
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

// registerTestSession registers sessionID with cgroupID directly through the
// registry's authorized-request path (mirrors
// daemonSessionRegistryTestHandshake in the kernelcapture package's own
// tests) so handleApplyPolicy's d.registry.ActiveSession lookup succeeds.
func registerTestSession(t *testing.T, d *daemon, sessionID string, cgroupID uint64) {
	t.Helper()
	handshake := kernelcapture.DaemonProtocolPeerHandshake{
		ProtocolVersion:       kernelcapture.DaemonProtocolVersion,
		Method:                kernelcapture.DaemonProtocolMethodRegisterSession,
		SessionID:             sessionID,
		SocketPath:            "/run/ardur/kernelcapture/control.sock",
		CredentialSource:      kernelcapture.DaemonPeerCredentialSourceLinuxSOPeerCred,
		ProcessStartTimeTicks: 900001,
		Authorization: kernelcapture.DaemonPeerAuthorization{
			Verdict:               kernelcapture.DaemonPeerAuthorizationVerdictAllow,
			Reason:                "test",
			UID:                   501,
			GID:                   20,
			PID:                   4321,
			ProcessStartTimeTicks: 900001,
			Matched:               "uid",
		},
	}
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

	resp := d.handleApplyPolicy(applyPolicyReqFor("ses-strict", kernelcapture.BpfEnforceModeEnforce))
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

	resp := d.handleApplyPolicy(applyPolicyReqFor("ses-permissive", kernelcapture.BpfEnforceModePermissive))
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
	resp := d.handleApplyPolicy(applyPolicyReqFor("does-not-exist", kernelcapture.BpfEnforceModeEnforce))
	if resp.OK {
		t.Fatal("apply_policy for an unregistered session: OK = true, want false")
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
	resp := d.handleSetKillSwitch(req)
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
