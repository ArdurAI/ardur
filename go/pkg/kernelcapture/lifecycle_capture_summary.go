package kernelcapture

import "sync"

const (
	LifecycleCaptureCoverageComplete = "complete"
	LifecycleCaptureCoverageDegraded = "degraded"
)

// LifecycleCaptureSummary reports daemon-global process lifecycle loss that
// occurred while one session was active. The loss cannot be attributed to a
// particular session, so every session active during the same loss epoch sees
// the same increment in its own session-window summary.
type LifecycleCaptureSummary struct {
	CoverageStatus     string `json:"coverage_status"`
	RingbufDropped     uint64 `json:"ringbuf_dropped"`
	DaemonQueueDropped uint64 `json:"daemon_queue_dropped"`
	LossEpochStart     uint64 `json:"loss_epoch_start,omitempty"`
	LossEpochEnd       uint64 `json:"loss_epoch_end,omitempty"`
}

// LifecycleCaptureSummaryAccumulator builds a concurrent session-window
// LifecycleCaptureSummary.
type LifecycleCaptureSummaryAccumulator struct {
	mu      sync.Mutex
	summary LifecycleCaptureSummary
}

// NewLifecycleCaptureSummaryAccumulator returns a complete, loss-free summary.
func NewLifecycleCaptureSummaryAccumulator() *LifecycleCaptureSummaryAccumulator {
	return &LifecycleCaptureSummaryAccumulator{
		summary: LifecycleCaptureSummary{CoverageStatus: LifecycleCaptureCoverageComplete},
	}
}

// RecordLoss adds daemon-global loss observed while this session was active.
// epoch is a daemon-lifetime monotonic identifier for one observed loss window.
func (a *LifecycleCaptureSummaryAccumulator) RecordLoss(loss CaptureLoss, epoch uint64) {
	if loss.RingbufDropped == 0 && loss.DaemonQueueDropped == 0 {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.summary.CoverageStatus = LifecycleCaptureCoverageDegraded
	a.summary.RingbufDropped += loss.RingbufDropped
	a.summary.DaemonQueueDropped += loss.DaemonQueueDropped
	if a.summary.LossEpochStart == 0 || epoch < a.summary.LossEpochStart {
		a.summary.LossEpochStart = epoch
	}
	if epoch > a.summary.LossEpochEnd {
		a.summary.LossEpochEnd = epoch
	}
}

// Snapshot returns a detached point-in-time summary.
func (a *LifecycleCaptureSummaryAccumulator) Snapshot() LifecycleCaptureSummary {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.summary
}
