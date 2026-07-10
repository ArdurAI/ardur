package kernelcapture

import "testing"

func TestLifecycleCaptureSummaryAccumulator(t *testing.T) {
	acc := NewLifecycleCaptureSummaryAccumulator()
	if got := acc.Snapshot(); got.CoverageStatus != LifecycleCaptureCoverageComplete {
		t.Fatalf("initial coverage_status = %q, want complete", got.CoverageStatus)
	}

	acc.RecordLoss(CaptureLoss{}, 1)
	acc.RecordLoss(CaptureLoss{RingbufDropped: 2}, 4)
	acc.RecordLoss(CaptureLoss{DaemonQueueDropped: 3}, 7)

	got := acc.Snapshot()
	if got.CoverageStatus != LifecycleCaptureCoverageDegraded {
		t.Fatalf("coverage_status = %q, want degraded", got.CoverageStatus)
	}
	if got.RingbufDropped != 2 || got.DaemonQueueDropped != 3 {
		t.Fatalf("loss counters = %+v, want ringbuf=2 queue=3", got)
	}
	if got.LossEpochStart != 4 || got.LossEpochEnd != 7 {
		t.Fatalf("loss epoch = %d..%d, want 4..7", got.LossEpochStart, got.LossEpochEnd)
	}
}
