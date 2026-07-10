package main

import (
	"context"
	"testing"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

func TestDaemonObservabilityGapRequiresOwnerAndMeasuresCapturedEffects(t *testing.T) {
	d := newTestDaemon(t)
	const (
		sessionID = "observability-gap-session"
		cgroupID  = 44001
	)
	register := kernelcapture.DaemonProtocolRequest{
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
	owner := testPeerHandshake(sessionID, register.Method)
	if response := d.handleAuthorizedRequest(context.Background(), register, owner); !response.OK {
		t.Fatalf("register_session failed: %+v", response)
	}

	receiptRequest := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodRegisterReceipt,
		RegisterReceipt: &kernelcapture.DaemonRegisterReceiptRequest{
			SessionID: sessionID,
			ReceiptID: "receipt:governed-action",
		},
	}
	foreign := testPeerHandshake(sessionID, receiptRequest.Method)
	foreign.Authorization.PID++
	if response := d.handleAuthorizedRequest(context.Background(), receiptRequest, foreign); response.OK {
		t.Fatalf("foreign peer registered receipt: %+v", response)
	}
	owner.Method = receiptRequest.Method
	if response := d.handleAuthorizedRequest(context.Background(), receiptRequest, owner); !response.OK || response.Status != "registered" {
		t.Fatalf("owner register_receipt failed: %+v", response)
	}
	if response := d.handleAuthorizedRequest(context.Background(), receiptRequest, owner); !response.OK || response.Status != "already_registered" {
		t.Fatalf("duplicate register_receipt was not idempotent: %+v", response)
	}

	now := time.Now().UTC()
	d.processKernelEvent(kernelcapture.ProcessEvent{
		EventID:  "exec-correlated",
		Type:     kernelcapture.ProcessEventExec,
		PID:      5000,
		PPID:     4321,
		CgroupID: cgroupID,
	})
	d.processKernelEvent(kernelcapture.ProcessEvent{
		EventID:    "exit-outside-window",
		Type:       kernelcapture.ProcessEventExit,
		PID:        5000,
		PPID:       4321,
		CgroupID:   cgroupID,
		ObservedAt: now.Add(10 * time.Second),
	})

	status := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodSessionStatus,
		SessionStatus:   &kernelcapture.DaemonSessionStatusRequest{SessionID: sessionID},
	}
	owner.Method = status.Method
	response := d.handleAuthorizedRequest(context.Background(), status, owner)
	if !response.OK || response.ObservabilityGap == nil {
		t.Fatalf("session_status observability gap = %+v", response)
	}
	gap := response.ObservabilityGap
	if gap.Status != kernelcapture.ObservabilityGapStatusMeasured || gap.CapturedEffects != 2 || gap.CorrelatedEffects != 1 || gap.UncorrelatedEffects != 1 {
		t.Fatalf("measured observability gap = %+v", gap)
	}
	if gap.RegisteredReceipts != 1 || gap.CorroboratedReceipts != 1 || gap.UnobservedReceipts != 0 {
		t.Fatalf("receipt corroboration = %+v", gap)
	}
	if gap.ObservedEffectGapRatio == nil || *gap.ObservedEffectGapRatio != 0.5 {
		t.Fatalf("observed effect gap ratio = %v, want 0.5", gap.ObservedEffectGapRatio)
	}

	d.recordLifecycleCaptureLoss(kernelcapture.CaptureLoss{RingbufDropped: 1})
	response = d.handleAuthorizedRequest(context.Background(), status, owner)
	if response.ObservabilityGap == nil || response.ObservabilityGap.Status != kernelcapture.ObservabilityGapStatusDegraded {
		t.Fatalf("capture loss did not degrade observability gap: %+v", response.ObservabilityGap)
	}
}

func TestDaemonObservabilityGapEmptySampleIsNotMeasured(t *testing.T) {
	d := newTestDaemon(t)
	const sessionID = "observability-empty-session"
	register := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodRegisterSession,
		RegisterSession: &kernelcapture.DaemonRegisterSessionRequest{
			SessionID:    sessionID,
			RootPID:      4321,
			CgroupID:     44002,
			EventClasses: []string{kernelcapture.DaemonProtocolEventProcessLifecycle},
			TTLSeconds:   60,
		},
	}
	owner := testPeerHandshake(sessionID, register.Method)
	if response := d.handleAuthorizedRequest(context.Background(), register, owner); !response.OK {
		t.Fatalf("register_session failed: %+v", response)
	}
	status := kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodSessionStatus,
		SessionStatus:   &kernelcapture.DaemonSessionStatusRequest{SessionID: sessionID},
	}
	owner.Method = status.Method
	response := d.handleAuthorizedRequest(context.Background(), status, owner)
	if !response.OK || response.ObservabilityGap == nil || response.ObservabilityGap.Status != kernelcapture.ObservabilityGapStatusNotMeasured || response.ObservabilityGap.ObservedEffectGapRatio != nil {
		t.Fatalf("empty observability gap = %+v", response)
	}
}
