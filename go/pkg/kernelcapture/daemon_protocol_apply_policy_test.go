package kernelcapture_test

// daemon_protocol_apply_policy_test.go — protocol encode/decode/validate tests
// for the apply_policy method (Slice 4.2).
//
// These tests exercise the protocol layer only: JSON round-trip, validation
// rules, and error messages. No BPF maps, kernel state, or Linux-only code is
// used; the suite runs on macOS and Linux alike.

import (
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

// validApplyPolicyReq returns a minimal valid apply_policy request for tests
// that need a clean baseline.
func validApplyPolicyReq() kernelcapture.DaemonApplyPolicyRequest {
	return kernelcapture.DaemonApplyPolicyRequest{
		SessionID:   "ses-test-01",
		Generation:  1,
		EnforceMode: kernelcapture.BpfEnforceModePermissive,
		OpPolicies: []kernelcapture.DaemonOpPolicy{
			{
				Op:          kernelcapture.BpfOpExec,
				Action:      kernelcapture.BpfActionAllow,
				EnforceMode: kernelcapture.BpfEnforceModePermissive,
			},
		},
	}
}

func applyPolicyRequest(ap kernelcapture.DaemonApplyPolicyRequest) kernelcapture.DaemonProtocolRequest {
	return kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodApplyPolicy,
		ApplyPolicy:     &ap,
	}
}

func TestApplyPolicy_EncodeDecodRoundTrip(t *testing.T) {
	t.Parallel()
	req := applyPolicyRequest(validApplyPolicyReq())
	data, err := kernelcapture.EncodeDaemonProtocolRequest(req)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := kernelcapture.DecodeDaemonProtocolRequest(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Method != kernelcapture.DaemonProtocolMethodApplyPolicy {
		t.Errorf("method = %q, want %q", got.Method, kernelcapture.DaemonProtocolMethodApplyPolicy)
	}
	if got.ApplyPolicy == nil {
		t.Fatal("ApplyPolicy payload is nil after decode")
	}
	if got.ApplyPolicy.SessionID != "ses-test-01" {
		t.Errorf("session_id = %q, want %q", got.ApplyPolicy.SessionID, "ses-test-01")
	}
	if got.ApplyPolicy.Generation != 1 {
		t.Errorf("generation = %d, want 1", got.ApplyPolicy.Generation)
	}
}

func TestApplyPolicy_WithPathAndNetAllow(t *testing.T) {
	t.Parallel()
	ap := validApplyPolicyReq()
	ap.PathAllow = []string{"/data/", "/tmp/ardur/"}
	ap.NetAllow = []string{"10.0.0.0/8", "192.168.1.0/24"}
	ap.OpPolicies = append(ap.OpPolicies, kernelcapture.DaemonOpPolicy{
		Op:          kernelcapture.BpfOpNetConnect,
		Action:      kernelcapture.BpfActionAllowlist,
		EnforceMode: kernelcapture.BpfEnforceModeEnforce,
	})
	req := applyPolicyRequest(ap)
	data, err := kernelcapture.EncodeDaemonProtocolRequest(req)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := kernelcapture.DecodeDaemonProtocolRequest(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.ApplyPolicy.PathAllow) != 2 {
		t.Errorf("path_allow len = %d, want 2", len(got.ApplyPolicy.PathAllow))
	}
	if len(got.ApplyPolicy.NetAllow) != 2 {
		t.Errorf("net_allow len = %d, want 2", len(got.ApplyPolicy.NetAllow))
	}
}

func TestApplyPolicy_ValidationEmptySessionID(t *testing.T) {
	t.Parallel()
	ap := validApplyPolicyReq()
	ap.SessionID = ""
	_, err := kernelcapture.EncodeDaemonProtocolRequest(applyPolicyRequest(ap))
	if err == nil {
		t.Fatal("expected error for empty session_id, got nil")
	}
}

func TestApplyPolicy_ValidationGenerationZero(t *testing.T) {
	t.Parallel()
	ap := validApplyPolicyReq()
	ap.Generation = 0
	_, err := kernelcapture.EncodeDaemonProtocolRequest(applyPolicyRequest(ap))
	if err == nil {
		t.Fatal("expected error for generation=0, got nil")
	}
}

func TestApplyPolicy_ValidationRelativePath(t *testing.T) {
	t.Parallel()
	ap := validApplyPolicyReq()
	ap.PathAllow = []string{"relative/path"}
	_, err := kernelcapture.EncodeDaemonProtocolRequest(applyPolicyRequest(ap))
	if err == nil {
		t.Fatal("expected error for relative path in path_allow, got nil")
	}
}

func TestApplyPolicy_ValidationUnknownOp(t *testing.T) {
	t.Parallel()
	ap := validApplyPolicyReq()
	ap.OpPolicies = []kernelcapture.DaemonOpPolicy{
		{Op: 99, Action: kernelcapture.BpfActionAllow, EnforceMode: kernelcapture.BpfEnforceModePermissive},
	}
	_, err := kernelcapture.EncodeDaemonProtocolRequest(applyPolicyRequest(ap))
	if err == nil {
		t.Fatal("expected error for unknown op, got nil")
	}
}

func TestApplyPolicy_ValidationDuplicateOp(t *testing.T) {
	t.Parallel()
	ap := validApplyPolicyReq()
	ap.OpPolicies = []kernelcapture.DaemonOpPolicy{
		{Op: kernelcapture.BpfOpExec, Action: kernelcapture.BpfActionAllow, EnforceMode: kernelcapture.BpfEnforceModePermissive},
		{Op: kernelcapture.BpfOpExec, Action: kernelcapture.BpfActionDeny, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
	}
	_, err := kernelcapture.EncodeDaemonProtocolRequest(applyPolicyRequest(ap))
	if err == nil {
		t.Fatal("expected error for duplicate op, got nil")
	}
}

func TestApplyPolicy_ValidationUnknownAction(t *testing.T) {
	t.Parallel()
	ap := validApplyPolicyReq()
	ap.OpPolicies = []kernelcapture.DaemonOpPolicy{
		{Op: kernelcapture.BpfOpExec, Action: 99, EnforceMode: kernelcapture.BpfEnforceModePermissive},
	}
	_, err := kernelcapture.EncodeDaemonProtocolRequest(applyPolicyRequest(ap))
	if err == nil {
		t.Fatal("expected error for unknown action, got nil")
	}
}

func TestApplyPolicy_ValidationUnknownEnforceMode(t *testing.T) {
	t.Parallel()
	ap := validApplyPolicyReq()
	ap.EnforceMode = 99
	_, err := kernelcapture.EncodeDaemonProtocolRequest(applyPolicyRequest(ap))
	if err == nil {
		t.Fatal("expected error for unknown enforce_mode, got nil")
	}
}

func TestApplyPolicy_MutualExclusionWithOtherPayloads(t *testing.T) {
	t.Parallel()
	ap := validApplyPolicyReq()
	req := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodApplyPolicy,
		ApplyPolicy:     &ap,
		Health:          &kernelcapture.DaemonHealthRequest{},
	}
	if err := kernelcapture.ValidateDaemonProtocolRequest(req); err == nil {
		t.Fatal("expected error when apply_policy + health are both set")
	}
}

func TestApplyPolicy_AllOpsValid(t *testing.T) {
	t.Parallel()
	ops := []kernelcapture.BpfOp{
		kernelcapture.BpfOpExec,
		kernelcapture.BpfOpFileRead,
		kernelcapture.BpfOpFileWrite,
		kernelcapture.BpfOpNetConnect,
		kernelcapture.BpfOpExternalSend,
	}
	for _, op := range ops {
		ap := kernelcapture.DaemonApplyPolicyRequest{
			SessionID:   "ses-allops",
			Generation:  1,
			EnforceMode: kernelcapture.BpfEnforceModePermissive,
			OpPolicies: []kernelcapture.DaemonOpPolicy{
				{Op: op, Action: kernelcapture.BpfActionDeny, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
			},
		}
		if _, err := kernelcapture.EncodeDaemonProtocolRequest(applyPolicyRequest(ap)); err != nil {
			t.Errorf("op %s: unexpected encode error: %v", op, err)
		}
	}
}

func TestApplyPolicy_ResponseDecodeRoundTrip(t *testing.T) {
	t.Parallel()
	resp := kernelcapture.DaemonProtocolResponse{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodApplyPolicy,
		OK:              true,
		SessionID:       "ses-test-01",
	}
	data, err := kernelcapture.EncodeDaemonProtocolResponse(resp)
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	got, err := kernelcapture.DecodeDaemonProtocolResponse(data)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.OK {
		t.Errorf("OK = false, want true")
	}
	if got.Method != kernelcapture.DaemonProtocolMethodApplyPolicy {
		t.Errorf("method = %q, want %q", got.Method, kernelcapture.DaemonProtocolMethodApplyPolicy)
	}
}

func TestApplyPolicy_ErrorResponse(t *testing.T) {
	t.Parallel()
	resp := kernelcapture.DaemonProtocolResponse{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodApplyPolicy,
		OK:              false,
		Error:           "session not found or not active",
	}
	data, err := kernelcapture.EncodeDaemonProtocolResponse(resp)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := kernelcapture.DecodeDaemonProtocolResponse(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.OK {
		t.Errorf("OK = true, want false")
	}
	if got.Error == "" {
		t.Errorf("Error is empty, want non-empty")
	}
}
