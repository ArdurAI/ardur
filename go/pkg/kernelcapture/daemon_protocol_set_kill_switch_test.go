package kernelcapture_test

// daemon_protocol_set_kill_switch_test.go — protocol encode/decode/validate
// tests for the set_kill_switch method (Slice 4.2 review: "kill switch is
// unreachable — there is no protocol method or CLI to engage it"). These
// exercise the protocol layer only; no BPF maps or Linux-only code.

import (
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

func setKillSwitchRequest(engaged bool) kernelcapture.DaemonProtocolRequest {
	return kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodSetKillSwitch,
		SetKillSwitch:   &kernelcapture.DaemonSetKillSwitchRequest{Engaged: engaged},
	}
}

func TestSetKillSwitch_EncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()
	data, err := kernelcapture.EncodeDaemonProtocolRequest(setKillSwitchRequest(true))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := kernelcapture.DecodeDaemonProtocolRequest(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Method != kernelcapture.DaemonProtocolMethodSetKillSwitch {
		t.Errorf("method = %q, want %q", got.Method, kernelcapture.DaemonProtocolMethodSetKillSwitch)
	}
	if got.SetKillSwitch == nil || !got.SetKillSwitch.Engaged {
		t.Fatalf("SetKillSwitch payload = %+v, want Engaged=true", got.SetKillSwitch)
	}
}

func TestSetKillSwitch_Disengage(t *testing.T) {
	t.Parallel()
	data, err := kernelcapture.EncodeDaemonProtocolRequest(setKillSwitchRequest(false))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := kernelcapture.DecodeDaemonProtocolRequest(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SetKillSwitch == nil || got.SetKillSwitch.Engaged {
		t.Fatalf("SetKillSwitch payload = %+v, want Engaged=false", got.SetKillSwitch)
	}
}

func TestSetKillSwitch_MutualExclusionWithOtherPayloads(t *testing.T) {
	t.Parallel()
	req := setKillSwitchRequest(true)
	req.Health = &kernelcapture.DaemonHealthRequest{}
	if err := kernelcapture.ValidateDaemonProtocolRequest(req); err == nil {
		t.Fatal("expected error when set_kill_switch + health are both set")
	}
}

func TestSetKillSwitch_RejectedAsPayloadOnOtherMethods(t *testing.T) {
	t.Parallel()
	req := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodHealth,
		Health:          &kernelcapture.DaemonHealthRequest{},
		SetKillSwitch:   &kernelcapture.DaemonSetKillSwitchRequest{Engaged: true},
	}
	if err := kernelcapture.ValidateDaemonProtocolRequest(req); err == nil {
		t.Fatal("expected error when health method carries a set_kill_switch payload")
	}
}

func TestSetKillSwitch_ResponseDecodeRoundTrip(t *testing.T) {
	t.Parallel()
	resp := kernelcapture.DaemonProtocolResponse{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodSetKillSwitch,
		OK:              true,
	}
	data, err := kernelcapture.EncodeDaemonProtocolResponse(resp)
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	got, err := kernelcapture.DecodeDaemonProtocolResponse(data)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.OK || got.Method != kernelcapture.DaemonProtocolMethodSetKillSwitch {
		t.Errorf("decoded response = %+v", got)
	}
}
