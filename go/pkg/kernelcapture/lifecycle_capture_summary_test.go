package kernelcapture

import "testing"

func TestLifecycleCaptureSummaryAccumulator(t *testing.T) {
	acc := NewLifecycleCaptureSummaryAccumulator()
	if got := acc.Snapshot(); got.CoverageStatus != LifecycleCaptureCoverageComplete {
		t.Fatalf("initial coverage_status = %q, want complete", got.CoverageStatus)
	}

	acc.RecordLoss(CaptureLoss{}, 1)
	acc.RecordProducerRingbufDropped(2, 4)
	acc.RecordMalformedRecord(5)
	acc.RecordProducerCounterEvidenceGap()
	acc.RecordLoss(CaptureLoss{DaemonQueueDropped: 3}, 7)

	got := acc.Snapshot()
	if got.CoverageStatus != LifecycleCaptureCoverageDegraded {
		t.Fatalf("coverage_status = %q, want degraded", got.CoverageStatus)
	}
	if got.RingbufDropped != 3 || got.ProducerRingbufDropped != 2 || got.MalformedRecords != 1 || got.DaemonQueueDropped != 3 {
		t.Fatalf("loss counters = %+v, want total=3 producer=2 malformed=1 queue=3", got)
	}
	if !got.ProducerCounterEvidenceGap {
		t.Fatal("producer counter evidence gap was not retained")
	}
	if got.LossEpochStart != 4 || got.LossEpochEnd != 7 {
		t.Fatalf("loss epoch = %d..%d, want 4..7", got.LossEpochStart, got.LossEpochEnd)
	}
}
