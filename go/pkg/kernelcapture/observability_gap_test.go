package kernelcapture

import (
	"fmt"
	"math"
	"testing"
)

func TestObservabilityGapAccumulatorMeasuredDirectionalSummary(t *testing.T) {
	acc := NewObservabilityGapAccumulator()
	for _, receiptID := range []string{"receipt:a", "receipt:b"} {
		added, err := acc.RegisterReceipt(receiptID)
		if err != nil || !added {
			t.Fatalf("RegisterReceipt(%q) = (%v, %v), want (true, nil)", receiptID, added, err)
		}
	}
	if added, err := acc.RegisterReceipt("receipt:a"); err != nil || added {
		t.Fatalf("duplicate RegisterReceipt = (%v, %v), want (false, nil)", added, err)
	}

	acc.RecordEffect(SyntheticKernelReceipt{CausedByReceiptID: "receipt:a"})
	acc.RecordEffect(SyntheticKernelReceipt{})
	acc.RecordEffect(SyntheticKernelReceipt{CausedByReceiptID: "receipt:not-registered"})

	got := acc.Snapshot(LifecycleCaptureSummary{CoverageStatus: LifecycleCaptureCoverageComplete})
	if got.Status != ObservabilityGapStatusMeasured || got.CoverageStatus != LifecycleCaptureCoverageComplete {
		t.Fatalf("status = %q coverage = %q", got.Status, got.CoverageStatus)
	}
	if got.RegisteredReceipts != 2 || got.CorroboratedReceipts != 1 || got.UnobservedReceipts != 1 {
		t.Fatalf("receipt counts = %+v", got)
	}
	if got.CapturedEffects != 3 || got.CorrelatedEffects != 1 || got.UncorrelatedEffects != 2 {
		t.Fatalf("effect counts = %+v", got)
	}
	if got.ObservedEffectGapRatio == nil || math.Abs(*got.ObservedEffectGapRatio-(2.0/3.0)) > 1e-12 {
		t.Fatalf("observed_effect_gap_ratio = %v, want 2/3", got.ObservedEffectGapRatio)
	}
	if got.EffectScope != ObservabilityGapEffectScopeProcessLifecycle || got.ReceiptSourceAssurance != ObservabilityGapReceiptAssurance {
		t.Fatalf("claim scope = %+v", got)
	}
}

func TestObservabilityGapAccumulatorEmptyAndDegraded(t *testing.T) {
	acc := NewObservabilityGapAccumulator()
	empty := acc.Snapshot(LifecycleCaptureSummary{CoverageStatus: LifecycleCaptureCoverageComplete})
	if empty.Status != ObservabilityGapStatusNotMeasured || empty.ObservedEffectGapRatio != nil {
		t.Fatalf("empty summary = %+v", empty)
	}

	acc.RecordEffect(SyntheticKernelReceipt{})
	degraded := acc.Snapshot(LifecycleCaptureSummary{CoverageStatus: LifecycleCaptureCoverageDegraded})
	if degraded.Status != ObservabilityGapStatusDegraded || degraded.ObservedEffectGapRatio == nil || *degraded.ObservedEffectGapRatio != 1 {
		t.Fatalf("degraded summary = %+v", degraded)
	}
}

func TestObservabilityGapAccumulatorBoundsReceipts(t *testing.T) {
	acc := NewObservabilityGapAccumulator()
	for i := 0; i < MaxObservabilityGapReceiptsPerSession; i++ {
		if added, err := acc.RegisterReceipt(fmt.Sprintf("receipt:%d", i)); err != nil || !added {
			t.Fatalf("registration %d = (%v, %v)", i, added, err)
		}
	}
	if _, err := acc.RegisterReceipt("over-capacity"); err == nil {
		t.Fatal("over-capacity receipt registration succeeded")
	}
}
