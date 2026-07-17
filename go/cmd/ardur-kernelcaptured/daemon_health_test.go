package main

// daemon_health_test.go — tests for the health response's EnforcementTier
// field (Epic A #63, Slice 2 remainder). ardur-sensor status uses this to
// report which enforcement backend is live without any special privilege
// beyond what the socket's peer-authorization policy already grants.

import (
	"context"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

func validHealthHandshake() kernelcapture.DaemonProtocolPeerHandshake {
	return kernelcapture.DaemonProtocolPeerHandshake{
		ProtocolVersion:       kernelcapture.DaemonProtocolVersion,
		Method:                kernelcapture.DaemonProtocolMethodHealth,
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
}

func healthReq() kernelcapture.DaemonProtocolRequest {
	return kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodHealth,
		Health:          &kernelcapture.DaemonHealthRequest{},
	}
}

// TestHandleAuthorizedRequest_HealthReportsNoneWithoutGuard is the common
// case: no BPF-LSM guard loaded (d.policyMaps is the zero value — exactly
// what happens on darwin, or on Linux without BPF-LSM). health must report
// EnforcementTierNone, not panic or fail the request.
func TestHandleAuthorizedRequest_HealthReportsNoneWithoutGuard(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)

	resp := d.handleAuthorizedRequest(context.Background(), healthReq(), validHealthHandshake())
	if !resp.OK {
		t.Fatalf("health response = %+v, want OK", resp)
	}
	if resp.Method != kernelcapture.DaemonProtocolMethodHealth {
		t.Fatalf("Method = %q, want %q", resp.Method, kernelcapture.DaemonProtocolMethodHealth)
	}
	if resp.EnforcementTier != kernelcapture.EnforcementTierNone {
		t.Fatalf("EnforcementTier = %q, want %q", resp.EnforcementTier, kernelcapture.EnforcementTierNone)
	}
}

// TestHandleAuthorizedRequest_HealthReportsBPFLSMWhenGuardLoaded proves the
// tier flips to "bpf_lsm" once policyMaps is populated (what runGuardConsumer
// does on a successful load) — using the same fakePolicyMap doubles
// TestApplyPolicyMaps_HappyPath uses in bpf_policy_apply_test.go, satisfying
// PolicyMaps' structural interfaces without any real BPF/kernel dependency.
func TestHandleAuthorizedRequest_HealthReportsBPFLSMWhenGuardLoaded(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	d.activatePolicyMaps(readyHealthPolicyMaps())

	resp := d.handleAuthorizedRequest(context.Background(), healthReq(), validHealthHandshake())
	if !resp.OK {
		t.Fatalf("health response = %+v, want OK", resp)
	}
	if resp.EnforcementTier != kernelcapture.EnforcementTierBPFLSM {
		t.Fatalf("EnforcementTier = %q, want %q", resp.EnforcementTier, kernelcapture.EnforcementTierBPFLSM)
	}
}

func TestHandleAuthorizedRequest_HealthReportsMonotonicCaptureAndRecognitionAccounting(t *testing.T) {
	d := newTestDaemon(t)
	if err := d.enableAgentRecognition(kernelcapture.AgentRecognizerOptions{AllowAgentTypes: []string{"codex_cli"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.disableAgentRecognition)
	d.setLifecycleDropCounter(scriptedLifecycleDropTotal(
		lifecycleDropSample{total: 7, ok: true},
		lifecycleDropSample{total: 9, ok: true},
	))
	d.processKernelEvent(kernelcapture.ProcessEvent{PID: 42, Type: kernelcapture.ProcessEventExec, Comm: "codex", ExecutableBasename: "codex"})
	if delta := d.sampleLifecycleProducerLoss(); delta != 2 {
		t.Fatalf("producer drop delta = %d, want 2", delta)
	}
	d.recordMalformedLifecycleRecord()

	resp := d.handleAuthorizedRequest(context.Background(), healthReq(), validHealthHandshake())
	if !resp.OK || resp.LifecycleCaptureHealth == nil || resp.AgentRecognition == nil {
		t.Fatalf("health response = %+v", resp)
	}
	if got := resp.LifecycleCaptureHealth; got.DeliveredTotal != 1 || got.ProducerRingbufDroppedTotal != 2 || got.MalformedRecordsTotal != 1 || !got.ProducerCounterAvailable || got.ProducerCounterEvidenceGap {
		t.Fatalf("lifecycle capture health = %+v", got)
	}
	if got := resp.AgentRecognition; !got.Enabled || got.Counters.CandidatesTotal != 1 || got.Counters.Recognized != 1 || got.Counters.Ambiguous != 0 || got.RegistryVersion == "" || got.RegistrySHA256 == "" {
		t.Fatalf("agent recognition health = %+v", got)
	}
}

func TestHandleAuthorizedRequest_HealthReportsDisabledRecognitionCounters(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	d.agentCandidatesTotal.Store(5)
	d.agentRecognizedTotal.Store(3)
	d.agentAmbiguousTotal.Store(2)

	resp := d.handleAuthorizedRequest(context.Background(), healthReq(), validHealthHandshake())
	if !resp.OK || resp.AgentRecognition == nil {
		t.Fatalf("health response = %+v", resp)
	}
	if got := resp.AgentRecognition; got.Enabled || got.RegistryVersion != "" || got.RegistrySHA256 != "" || got.Counters.CandidatesTotal != 5 || got.Counters.Recognized != 3 || got.Counters.Ambiguous != 2 {
		t.Fatalf("disabled recognition health = %+v", got)
	}
}

func TestHandleAuthorizedRequest_HealthSamplesTerminalProducerDrops(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	d.setLifecycleDropCounter(scriptedLifecycleDropTotal(
		lifecycleDropSample{total: 3, ok: true},
		lifecycleDropSample{total: 8, ok: true},
	))

	resp := d.handleAuthorizedRequest(context.Background(), healthReq(), validHealthHandshake())
	if !resp.OK || resp.LifecycleCaptureHealth == nil {
		t.Fatalf("health response = %+v", resp)
	}
	if got := resp.LifecycleCaptureHealth.ProducerRingbufDroppedTotal; got != 5 {
		t.Fatalf("producer drops = %d, want 5", got)
	}
}

func readyHealthPolicyMaps() kernelcapture.PolicyMaps {
	return kernelcapture.PolicyMaps{
		CgroupOpPolicy:           &fakeHealthPolicyMap{},
		CgroupPathAllow:          &fakeHealthPolicyMap{},
		CgroupFileAllow:          &fakeHealthPolicyMap{},
		CgroupBootstrapFileAllow: &fakeHealthPolicyMap{},
		BootstrapFileObservation: &fakeHealthPolicyMap{},
		CgroupControlPlaneAllow:  &fakeHealthPolicyMap{},
		CgroupTrustedRoot:        &fakeHealthPolicyMap{},
		CgroupNetAllow:           &fakeHealthPolicyMap{},
		CgroupManaged:            &fakeHealthPolicyMap{},
		KillSwitch:               &fakeHealthPolicyMap{},
	}
}

// fakeHealthPolicyMap satisfies both policyMapWriter and policyMapReadWriter
// structurally (Put/Delete/Lookup) so it plugs into every PolicyMaps field,
// including CgroupManaged which additionally requires Lookup.
type fakeHealthPolicyMap struct{}

func (fakeHealthPolicyMap) Put(_, _ interface{}) error    { return nil }
func (fakeHealthPolicyMap) Delete(_ interface{}) error    { return nil }
func (fakeHealthPolicyMap) Lookup(_, _ interface{}) error { return nil }
