package kernelcapture

import (
	"errors"
	"fmt"
	"sync"
)

const (
	ObservabilityGapStatusNotMeasured = "not_measured"
	ObservabilityGapStatusMeasured    = "measured"
	ObservabilityGapStatusDegraded    = "degraded"

	ObservabilityGapEffectScopeProcessLifecycle = "process_lifecycle"
	ObservabilityGapReceiptAssurance            = "authenticated_session_owner"
	MaxObservabilityGapReceiptsPerSession       = 4096
)

var ErrObservabilityGap = errors.New("kernelcapture: observability gap")

// ObservabilityGapSummary is a directional comparison between governance
// receipts reported by the authenticated session owner and process lifecycle
// effects actually captured by the daemon. Ratios describe only the captured
// sample and are omitted when that sample is empty.
type ObservabilityGapSummary struct {
	Status                 string   `json:"status"`
	EffectScope            string   `json:"effect_scope"`
	EventClasses           []string `json:"event_classes"`
	ReceiptSourceAssurance string   `json:"receipt_source_assurance"`
	CoverageStatus         string   `json:"coverage_status"`
	RegisteredReceipts     uint64   `json:"registered_receipts"`
	CorroboratedReceipts   uint64   `json:"corroborated_receipts"`
	UnobservedReceipts     uint64   `json:"unobserved_receipts"`
	CapturedEffects        uint64   `json:"captured_effects"`
	CorrelatedEffects      uint64   `json:"correlated_effects"`
	UncorrelatedEffects    uint64   `json:"uncorrelated_effects"`
	ObservedEffectGapRatio *float64 `json:"observed_effect_gap_ratio,omitempty"`
	ClaimBoundary          string   `json:"claim_boundary"`
}

// ObservabilityGapAccumulator keeps bounded, deduplicated per-session state.
// It is safe for concurrent receipt registration, event processing, and status
// snapshots.
type ObservabilityGapAccumulator struct {
	mu                   sync.Mutex
	registeredReceipts   map[string]struct{}
	corroboratedReceipts map[string]struct{}
	capturedEffects      uint64
	correlatedEffects    uint64
}

func NewObservabilityGapAccumulator() *ObservabilityGapAccumulator {
	return &ObservabilityGapAccumulator{
		registeredReceipts:   make(map[string]struct{}),
		corroboratedReceipts: make(map[string]struct{}),
	}
}

// RegisterReceipt records one unique identifier. It returns true only when the
// receipt was newly added; duplicate registrations are idempotent.
func (a *ObservabilityGapAccumulator) RegisterReceipt(receiptID string) (bool, error) {
	if a == nil {
		return false, fmt.Errorf("%w: accumulator is required", ErrObservabilityGap)
	}
	if receiptID == "" {
		return false, fmt.Errorf("%w: receipt_id is required", ErrObservabilityGap)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.registeredReceipts[receiptID]; exists {
		return false, nil
	}
	if len(a.registeredReceipts) >= MaxObservabilityGapReceiptsPerSession {
		return false, fmt.Errorf("%w: receipt capacity exceeded: max %d", ErrObservabilityGap, MaxObservabilityGapReceiptsPerSession)
	}
	a.registeredReceipts[receiptID] = struct{}{}
	return true, nil
}

func (a *ObservabilityGapAccumulator) RecordEffect(receipt SyntheticKernelReceipt) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.capturedEffects++
	if receipt.CausedByReceiptID == "" {
		return
	}
	if _, registered := a.registeredReceipts[receipt.CausedByReceiptID]; !registered {
		return
	}
	a.correlatedEffects++
	a.corroboratedReceipts[receipt.CausedByReceiptID] = struct{}{}
}

func (a *ObservabilityGapAccumulator) Snapshot(capture LifecycleCaptureSummary) ObservabilityGapSummary {
	summary := ObservabilityGapSummary{
		Status:                 ObservabilityGapStatusNotMeasured,
		EffectScope:            ObservabilityGapEffectScopeProcessLifecycle,
		EventClasses:           []string{"process_exec", "process_exit"},
		ReceiptSourceAssurance: ObservabilityGapReceiptAssurance,
		CoverageStatus:         capture.CoverageStatus,
		ClaimBoundary:          "captured Linux process lifecycle sample only; excludes universal file, network, and host-effect coverage",
	}
	if a == nil {
		return summary
	}

	a.mu.Lock()
	summary.RegisteredReceipts = uint64(len(a.registeredReceipts))
	summary.CorroboratedReceipts = uint64(len(a.corroboratedReceipts))
	summary.CapturedEffects = a.capturedEffects
	summary.CorrelatedEffects = a.correlatedEffects
	a.mu.Unlock()

	summary.UnobservedReceipts = summary.RegisteredReceipts - summary.CorroboratedReceipts
	summary.UncorrelatedEffects = summary.CapturedEffects - summary.CorrelatedEffects
	if summary.CapturedEffects == 0 {
		return summary
	}
	ratio := float64(summary.UncorrelatedEffects) / float64(summary.CapturedEffects)
	summary.ObservedEffectGapRatio = &ratio
	if capture.CoverageStatus == LifecycleCaptureCoverageComplete {
		summary.Status = ObservabilityGapStatusMeasured
	} else {
		summary.Status = ObservabilityGapStatusDegraded
	}
	return summary
}
