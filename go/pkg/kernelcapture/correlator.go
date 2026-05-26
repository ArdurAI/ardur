package kernelcapture

import (
	"sync"
	"time"
)

// Correlator links process lifecycle observations to prior tool receipts.
//
// Correlator is safe for concurrent use by multiple goroutines.
type Correlator struct {
	mu                   sync.RWMutex
	opts                 CorrelatorOptions
	receipts             map[string][]ToolReceipt
	restartedAt          time.Time
	restartedMonotonicNS uint64
}

// NewCorrelator creates a correlator for one capture backend/platform tuple.
func NewCorrelator(opts CorrelatorOptions) *Correlator {
	if opts.Platform == "" {
		opts.Platform = "unknown"
	}
	if opts.CaptureBackend == "" {
		opts.CaptureBackend = "unknown"
	}
	if opts.RestartGrace <= 0 {
		opts.RestartGrace = 3 * time.Second
	}
	if opts.CorrelationGrace <= 0 {
		opts.CorrelationGrace = 5 * time.Second
	}
	return &Correlator{
		opts:     opts,
		receipts: make(map[string][]ToolReceipt),
	}
}

// RegisterReceipt registers a candidate tool-call receipt for future correlation.
func (c *Correlator) RegisterReceipt(r ToolReceipt) {
	if r.SessionID == "" || r.ReceiptID == "" {
		return
	}

	if r.SpanStart.IsZero() && !r.ObservedAt.IsZero() {
		r.SpanStart = r.ObservedAt.Add(-c.opts.CorrelationGrace)
	}
	if r.SpanEnd.IsZero() && !r.ObservedAt.IsZero() {
		r.SpanEnd = r.ObservedAt.Add(c.opts.CorrelationGrace)
	}
	if !r.SpanStart.IsZero() && !r.SpanEnd.IsZero() && r.SpanEnd.Before(r.SpanStart) {
		r.SpanStart, r.SpanEnd = r.SpanEnd, r.SpanStart
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.receipts[r.SessionID] = append(c.receipts[r.SessionID], r)
}

// NoteDaemonRestart records a daemon restart wall-clock boundary.
func (c *Correlator) NoteDaemonRestart(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.restartedAt = at
}

// NoteDaemonRestartMonotonic records the daemon restart monotonic timestamp.
func (c *Correlator) NoteDaemonRestartMonotonic(monotonicNS uint64) {
	if monotonicNS == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.restartedMonotonicNS = monotonicNS
}

// Correlate maps one process event to a synthetic kernel-effect receipt.
func (c *Correlator) Correlate(evt ProcessEvent, ctx EventContext) SyntheticKernelReceipt {
	receipt := SyntheticKernelReceipt{
		EventID:               evt.EventID,
		EventClass:            "kernel_effect",
		CaptureBackend:        c.opts.CaptureBackend,
		Platform:              c.opts.Platform,
		KernelEventType:       kernelEventType(evt.Type),
		CoverageStatus:        "complete",
		CorrelationMethod:     "ambiguous",
		CorrelationConfidence: "ambiguous",
		CaptureLoss:           ctx.CaptureLoss,
		Verdict:               "compliant",
	}

	sessionReceipts := c.sessionReceiptsSnapshot(evt.SessionID)
	strongPIDMatches, weakPIDMatches, cgroupMatches := c.matchCandidates(evt, sessionReceipts)

	switch {
	case len(strongPIDMatches) == 1:
		receipt.CorrelationMethod = "explicit_pid"
		receipt.CorrelationConfidence = "high"
		receipt.CausedByReceiptID = strongPIDMatches[0].ReceiptID
	case len(strongPIDMatches) > 1:
		receipt.CorrelationMethod = "ambiguous"
		receipt.CorrelationConfidence = "ambiguous"
	case len(weakPIDMatches) > 0:
		receipt.CorrelationMethod = "ambiguous"
		receipt.CorrelationConfidence = "ambiguous"
	case len(cgroupMatches) == 1:
		receipt.CorrelationMethod = "cgroup_time_window"
		receipt.CorrelationConfidence = "medium"
		receipt.CausedByReceiptID = cgroupMatches[0].ReceiptID
	case len(cgroupMatches) > 1:
		receipt.CorrelationMethod = "ambiguous"
		receipt.CorrelationConfidence = "ambiguous"
	default:
		receipt.CorrelationMethod = "ambiguous"
		receipt.CorrelationConfidence = "ambiguous"
	}

	if c.isWithinRestartGap(evt) {
		receipt.CoverageStatus = "unknown"
	}
	if ctx.CaptureLoss.RingbufDropped > 0 || ctx.CaptureLoss.DaemonQueueDropped > 0 || ctx.ConsumerLag {
		if receipt.CoverageStatus != "unknown" {
			receipt.CoverageStatus = "degraded"
		}
	}

	if receipt.CorrelationMethod == "ambiguous" || receipt.CorrelationConfidence == "low" || receipt.CorrelationConfidence == "ambiguous" {
		if receipt.CoverageStatus == "complete" {
			receipt.CoverageStatus = "degraded"
		}
		markInsufficientEvidence(&receipt, "kernel.correlation_ambiguous")
	}
	if receipt.CoverageStatus == "degraded" || receipt.CoverageStatus == "dropped" || receipt.CoverageStatus == "unknown" {
		code := "kernel.coverage_degraded"
		switch receipt.CoverageStatus {
		case "unknown":
			if c.isWithinRestartGap(evt) {
				code = "kernel.daemon_restart_gap"
			} else {
				code = "kernel.coverage_unknown"
			}
		case "degraded":
			if ctx.CaptureLoss.RingbufDropped > 0 || ctx.CaptureLoss.DaemonQueueDropped > 0 || ctx.ConsumerLag {
				code = "kernel.capture_loss"
			}
		case "dropped":
			code = "kernel.capture_dropped"
		}
		if code == "kernel.coverage_degraded" && receipt.InternalDenialCode == "kernel.correlation_ambiguous" {
			// Preserve attribution ambiguity as the primary denial code.
		} else {
			markInsufficientEvidence(&receipt, code)
		}
	}

	return receipt
}

type pidMatchStrength uint8

const (
	pidMatchNone pidMatchStrength = iota
	pidMatchWeak
	pidMatchStrong
)

func (c *Correlator) matchCandidates(evt ProcessEvent, receipts []ToolReceipt) (strongPID []ToolReceipt, weakPID []ToolReceipt, cgroupMatches []ToolReceipt) {
	for _, r := range receipts {
		if r.PID != 0 && r.PID == evt.PID {
			strength := c.pidCandidateStrength(evt, r)
			switch strength {
			case pidMatchStrong:
				strongPID = append(strongPID, r)
			case pidMatchWeak:
				weakPID = append(weakPID, r)
			}
			continue
		}
		if r.CgroupID != 0 && evt.CgroupID != 0 && r.CgroupID == evt.CgroupID && c.inCorrelationWindow(evt, r) {
			cgroupMatches = append(cgroupMatches, r)
		}
	}
	return strongPID, weakPID, cgroupMatches
}

func (c *Correlator) pidCandidateStrength(evt ProcessEvent, r ToolReceipt) pidMatchStrength {
	if r.PID == 0 || evt.PID == 0 || r.PID != evt.PID {
		return pidMatchNone
	}
	if r.CgroupID != 0 && evt.CgroupID != 0 && r.CgroupID != evt.CgroupID {
		return pidMatchNone
	}
	if r.PIDNamespaceID != 0 && evt.PIDNamespaceID != 0 && r.PIDNamespaceID != evt.PIDNamespaceID {
		return pidMatchNone
	}
	if r.ProcessStartMonotonicNS != 0 && evt.ProcessStartMonotonicNS != 0 && r.ProcessStartMonotonicNS != evt.ProcessStartMonotonicNS {
		return pidMatchNone
	}

	windowMatched := c.inCorrelationWindow(evt, r)
	cgroupConfirmed := r.CgroupID != 0 && evt.CgroupID != 0 && r.CgroupID == evt.CgroupID
	namespaceConfirmed := r.PIDNamespaceID != 0 && evt.PIDNamespaceID != 0 && r.PIDNamespaceID == evt.PIDNamespaceID
	startConfirmed := r.ProcessStartMonotonicNS != 0 && evt.ProcessStartMonotonicNS != 0 && r.ProcessStartMonotonicNS == evt.ProcessStartMonotonicNS

	if windowMatched && cgroupConfirmed && (namespaceConfirmed || startConfirmed) {
		return pidMatchStrong
	}
	return pidMatchWeak
}

func (c *Correlator) inCorrelationWindow(evt ProcessEvent, r ToolReceipt) bool {
	if evt.ObservedAt.IsZero() {
		return false
	}
	start, end := c.receiptWindow(r)
	if start.IsZero() || end.IsZero() {
		return false
	}
	if evt.ObservedAt.Before(start) || evt.ObservedAt.After(end) {
		return false
	}
	return true
}

func (c *Correlator) receiptWindow(r ToolReceipt) (time.Time, time.Time) {
	start := r.SpanStart
	end := r.SpanEnd

	if start.IsZero() && !r.ObservedAt.IsZero() {
		start = r.ObservedAt.Add(-c.opts.CorrelationGrace)
	}
	if end.IsZero() && !r.ObservedAt.IsZero() {
		end = r.ObservedAt.Add(c.opts.CorrelationGrace)
	}
	if start.IsZero() || end.IsZero() {
		return time.Time{}, time.Time{}
	}
	if end.Before(start) {
		start, end = end, start
	}
	return start, end
}

func (c *Correlator) isWithinRestartGap(evt ProcessEvent) bool {
	c.mu.RLock()
	restartedAt := c.restartedAt
	restartedMonotonicNS := c.restartedMonotonicNS
	restartGrace := c.opts.RestartGrace
	c.mu.RUnlock()

	if evt.ObservedMonotonicNS > 0 && restartedMonotonicNS > 0 {
		if evt.ObservedMonotonicNS < restartedMonotonicNS {
			return false
		}
		if restartGrace <= 0 {
			return false
		}
		gapNS := evt.ObservedMonotonicNS - restartedMonotonicNS
		return gapNS <= uint64(restartGrace)
	}
	if restartedAt.IsZero() || evt.ObservedAt.IsZero() {
		return false
	}
	if evt.ObservedAt.Before(restartedAt) {
		return false
	}
	return evt.ObservedAt.Sub(restartedAt) <= restartGrace
}

func (c *Correlator) sessionReceiptsSnapshot(sessionID string) []ToolReceipt {
	if sessionID == "" {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	receipts := c.receipts[sessionID]
	if len(receipts) == 0 {
		return nil
	}
	cp := make([]ToolReceipt, len(receipts))
	copy(cp, receipts)
	return cp
}

func markInsufficientEvidence(receipt *SyntheticKernelReceipt, code string) {
	receipt.Verdict = "insufficient_evidence"
	receipt.PublicDenialReason = "insufficient_evidence"
	receipt.InternalDenialCode = code
}

func kernelEventType(kind ProcessEventType) string {
	switch kind {
	case ProcessEventExec:
		return "execve"
	case ProcessEventExit:
		return "exit"
	default:
		return "process_event"
	}
}
