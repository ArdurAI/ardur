package kernelcapture

import (
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCorrelateExecEventProducesCompliantReceiptWhenCorrelationIsClear(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_778_200_000, 0).UTC()
	c := NewCorrelator(CorrelatorOptions{
		Platform:       "linux",
		CaptureBackend: "linux_ebpf",
	})
	c.RegisterReceipt(ToolReceipt{
		ReceiptID:               "receipt:tool-1",
		SessionID:               "session-a",
		PID:                     4242,
		PIDNamespaceID:          4026531836,
		ProcessStartMonotonicNS: 9_100_000_000,
		CgroupID:                77,
		SpanStart:               now.Add(-200 * time.Millisecond),
		SpanEnd:                 now.Add(200 * time.Millisecond),
		ObservedAt:              now.Add(-100 * time.Millisecond),
	})

	receipt := c.Correlate(ProcessEvent{
		EventID:                 "evt-1",
		SessionID:               "session-a",
		Type:                    ProcessEventExec,
		PID:                     4242,
		PPID:                    4000,
		TID:                     4242,
		PIDNamespaceID:          4026531836,
		ProcessStartMonotonicNS: 9_100_000_000,
		CgroupID:                77,
		Comm:                    "bash",
		ObservedAt:              now,
	}, EventContext{})

	if receipt.KernelEventType != "execve" {
		t.Fatalf("kernel_event_type = %q, want execve", receipt.KernelEventType)
	}
	if receipt.CorrelationMethod != "explicit_pid" {
		t.Fatalf("correlation_method = %q, want explicit_pid", receipt.CorrelationMethod)
	}
	if receipt.CorrelationConfidence != "high" {
		t.Fatalf("correlation_confidence = %q, want high", receipt.CorrelationConfidence)
	}
	if receipt.CoverageStatus != "complete" {
		t.Fatalf("coverage_status = %q, want complete", receipt.CoverageStatus)
	}
	if receipt.CausedByReceiptID != "receipt:tool-1" {
		t.Fatalf("caused_by_receipt_id = %q, want receipt:tool-1", receipt.CausedByReceiptID)
	}
	if receipt.Verdict != "compliant" {
		t.Fatalf("verdict = %q, want compliant", receipt.Verdict)
	}
	if receipt.PublicDenialReason != "" || receipt.InternalDenialCode != "" {
		t.Fatalf("expected empty denial fields, got reason=%q code=%q", receipt.PublicDenialReason, receipt.InternalDenialCode)
	}
}

func TestCorrelateExitEventProducesCompliantReceiptWhenCorrelationIsClear(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_778_200_050, 0).UTC()
	c := NewCorrelator(CorrelatorOptions{
		Platform:       "linux",
		CaptureBackend: "linux_ebpf",
	})
	c.RegisterReceipt(ToolReceipt{
		ReceiptID:               "receipt:tool-exit-1",
		SessionID:               "session-a",
		PID:                     6001,
		PIDNamespaceID:          4026531836,
		ProcessStartMonotonicNS: 9_200_000_000,
		CgroupID:                88,
		SpanStart:               now.Add(-200 * time.Millisecond),
		SpanEnd:                 now.Add(200 * time.Millisecond),
		ObservedAt:              now.Add(-100 * time.Millisecond),
	})

	receipt := c.Correlate(ProcessEvent{
		EventID:                 "evt-exit-1",
		SessionID:               "session-a",
		Type:                    ProcessEventExit,
		PID:                     6001,
		PPID:                    5999,
		TID:                     6001,
		PIDNamespaceID:          4026531836,
		ProcessStartMonotonicNS: 9_200_000_000,
		CgroupID:                88,
		Comm:                    "python3",
		ObservedAt:              now,
	}, EventContext{})

	if receipt.KernelEventType != "exit" {
		t.Fatalf("kernel_event_type = %q, want exit", receipt.KernelEventType)
	}
	if receipt.CorrelationMethod != "explicit_pid" {
		t.Fatalf("correlation_method = %q, want explicit_pid", receipt.CorrelationMethod)
	}
	if receipt.CorrelationConfidence != "high" {
		t.Fatalf("correlation_confidence = %q, want high", receipt.CorrelationConfidence)
	}
	if receipt.CoverageStatus != "complete" {
		t.Fatalf("coverage_status = %q, want complete", receipt.CoverageStatus)
	}
	if receipt.CausedByReceiptID != "receipt:tool-exit-1" {
		t.Fatalf("caused_by_receipt_id = %q, want receipt:tool-exit-1", receipt.CausedByReceiptID)
	}
	if receipt.Verdict != "compliant" {
		t.Fatalf("verdict = %q, want compliant", receipt.Verdict)
	}
}

func TestCorrelateEventMarksAmbiguousAttributionAsInsufficientEvidence(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_778_200_100, 0).UTC()
	c := NewCorrelator(CorrelatorOptions{
		Platform:       "linux",
		CaptureBackend: "linux_ebpf",
	})
	c.RegisterReceipt(ToolReceipt{ReceiptID: "receipt:tool-1", SessionID: "session-a", CgroupID: 100, ObservedAt: now.Add(-150 * time.Millisecond)})
	c.RegisterReceipt(ToolReceipt{ReceiptID: "receipt:tool-2", SessionID: "session-a", CgroupID: 100, ObservedAt: now.Add(-80 * time.Millisecond)})

	receipt := c.Correlate(ProcessEvent{
		EventID:    "evt-ambiguous",
		SessionID:  "session-a",
		Type:       ProcessEventExit,
		PID:        9001,
		PPID:       1,
		TID:        9001,
		CgroupID:   100,
		Comm:       "python",
		ObservedAt: now,
	}, EventContext{})

	if receipt.CorrelationMethod != "ambiguous" {
		t.Fatalf("correlation_method = %q, want ambiguous", receipt.CorrelationMethod)
	}
	if receipt.CorrelationConfidence != "ambiguous" {
		t.Fatalf("correlation_confidence = %q, want ambiguous", receipt.CorrelationConfidence)
	}
	if receipt.CoverageStatus != "degraded" {
		t.Fatalf("coverage_status = %q, want degraded", receipt.CoverageStatus)
	}
	if receipt.Verdict != "insufficient_evidence" {
		t.Fatalf("verdict = %q, want insufficient_evidence", receipt.Verdict)
	}
	if receipt.PublicDenialReason != "insufficient_evidence" {
		t.Fatalf("public_denial_reason = %q, want insufficient_evidence", receipt.PublicDenialReason)
	}
	if receipt.InternalDenialCode != "kernel.correlation_ambiguous" {
		t.Fatalf("internal_denial_code = %q, want kernel.correlation_ambiguous", receipt.InternalDenialCode)
	}
}

func TestCorrelateEventMarksCaptureLossAsDegradedInsufficientEvidence(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_778_200_200, 0).UTC()
	c := NewCorrelator(CorrelatorOptions{
		Platform:       "linux",
		CaptureBackend: "linux_ebpf",
	})
	c.RegisterReceipt(ToolReceipt{
		ReceiptID:               "receipt:tool-3",
		SessionID:               "session-a",
		PID:                     5100,
		PIDNamespaceID:          4026531836,
		ProcessStartMonotonicNS: 7_500_000_000,
		CgroupID:                300,
		SpanStart:               now.Add(-150 * time.Millisecond),
		SpanEnd:                 now.Add(150 * time.Millisecond),
		ObservedAt:              now.Add(-50 * time.Millisecond),
	})

	receipt := c.Correlate(ProcessEvent{
		EventID:                 "evt-loss",
		SessionID:               "session-a",
		Type:                    ProcessEventExec,
		PID:                     5100,
		PPID:                    5000,
		TID:                     5100,
		PIDNamespaceID:          4026531836,
		ProcessStartMonotonicNS: 7_500_000_000,
		CgroupID:                300,
		Comm:                    "curl",
		ObservedAt:              now,
	}, EventContext{
		CaptureLoss: CaptureLoss{
			RingbufDropped:     5,
			DaemonQueueDropped: 0,
		},
		ConsumerLag: true,
	})

	if receipt.CoverageStatus != "degraded" {
		t.Fatalf("coverage_status = %q, want degraded", receipt.CoverageStatus)
	}
	if receipt.Verdict != "insufficient_evidence" {
		t.Fatalf("verdict = %q, want insufficient_evidence", receipt.Verdict)
	}
	if receipt.PublicDenialReason != "insufficient_evidence" {
		t.Fatalf("public_denial_reason = %q, want insufficient_evidence", receipt.PublicDenialReason)
	}
	if receipt.InternalDenialCode != "kernel.capture_loss" {
		t.Fatalf("internal_denial_code = %q, want kernel.capture_loss", receipt.InternalDenialCode)
	}
	if receipt.CaptureLoss.RingbufDropped != 5 {
		t.Fatalf("ringbuf_dropped = %d, want 5", receipt.CaptureLoss.RingbufDropped)
	}
}

func TestCorrelateEventAfterDaemonRestartForcesCoverageUnknown(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_778_200_300, 0).UTC()
	c := NewCorrelator(CorrelatorOptions{
		Platform:       "linux",
		CaptureBackend: "linux_ebpf",
		RestartGrace:   2 * time.Second,
	})
	c.RegisterReceipt(ToolReceipt{
		ReceiptID:               "receipt:tool-4",
		SessionID:               "session-a",
		PID:                     7000,
		PIDNamespaceID:          4026531836,
		ProcessStartMonotonicNS: 6_000_000_000,
		CgroupID:                500,
		SpanStart:               now.Add(-100 * time.Millisecond),
		SpanEnd:                 now.Add(1500 * time.Millisecond),
		ObservedAt:              now.Add(-100 * time.Millisecond),
	})
	c.NoteDaemonRestart(now)

	receipt := c.Correlate(ProcessEvent{
		EventID:                 "evt-restart",
		SessionID:               "session-a",
		Type:                    ProcessEventExit,
		PID:                     7000,
		PPID:                    6999,
		TID:                     7000,
		PIDNamespaceID:          4026531836,
		ProcessStartMonotonicNS: 6_000_000_000,
		CgroupID:                500,
		Comm:                    "bash",
		ObservedAt:              now.Add(500 * time.Millisecond),
	}, EventContext{})

	if receipt.CoverageStatus != "unknown" {
		t.Fatalf("coverage_status = %q, want unknown", receipt.CoverageStatus)
	}
	if receipt.Verdict != "insufficient_evidence" {
		t.Fatalf("verdict = %q, want insufficient_evidence", receipt.Verdict)
	}
	if receipt.InternalDenialCode != "kernel.daemon_restart_gap" {
		t.Fatalf("internal_denial_code = %q, want kernel.daemon_restart_gap", receipt.InternalDenialCode)
	}
}

func TestCorrelateDecodedRingbufSampleUsesMonotonicRestartGap(t *testing.T) {
	t.Parallel()

	eventMonotonic := uint64(9_500_000_000)
	raw := buildRingbufSample(1, eventMonotonic, 7000, 6999, 7000, 4026531836, 500, "bash")
	evt, err := decodeRingbufRecord(raw)
	if err != nil {
		t.Fatalf("decodeRingbufRecord error: %v", err)
	}
	evt.EventID = "evt-ringbuf-restart"
	evt.SessionID = "session-a"
	if evt.PIDNamespaceID != 4026531836 {
		t.Fatalf("pid_namespace_id = %d, want 4026531836", evt.PIDNamespaceID)
	}

	c := NewCorrelator(CorrelatorOptions{
		Platform:       "linux",
		CaptureBackend: "linux_ebpf",
		RestartGrace:   2 * time.Second,
	})
	c.NoteDaemonRestartMonotonic(eventMonotonic - 500_000_000)

	receipt := c.Correlate(evt, EventContext{})
	if receipt.CoverageStatus != "unknown" {
		t.Fatalf("coverage_status = %q, want unknown", receipt.CoverageStatus)
	}
	if receipt.Verdict != "insufficient_evidence" {
		t.Fatalf("verdict = %q, want insufficient_evidence", receipt.Verdict)
	}
	if receipt.InternalDenialCode != "kernel.daemon_restart_gap" {
		t.Fatalf("internal_denial_code = %q, want kernel.daemon_restart_gap", receipt.InternalDenialCode)
	}
}

func TestCorrelateRejectsPIDMatchOutsideReceiptWindow(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_778_200_350, 0).UTC()
	c := NewCorrelator(CorrelatorOptions{Platform: "linux", CaptureBackend: "linux_ebpf"})
	c.RegisterReceipt(ToolReceipt{
		ReceiptID:               "receipt:stale",
		SessionID:               "session-a",
		PID:                     4242,
		PIDNamespaceID:          1,
		ProcessStartMonotonicNS: 100,
		CgroupID:                77,
		SpanStart:               now.Add(-12 * time.Second),
		SpanEnd:                 now.Add(-10 * time.Second),
		ObservedAt:              now.Add(-11 * time.Second),
	})

	receipt := c.Correlate(ProcessEvent{
		EventID:                 "evt-stale",
		SessionID:               "session-a",
		Type:                    ProcessEventExec,
		PID:                     4242,
		PIDNamespaceID:          1,
		ProcessStartMonotonicNS: 100,
		CgroupID:                77,
		ObservedAt:              now,
	}, EventContext{})

	if receipt.CorrelationMethod != "ambiguous" || receipt.CorrelationConfidence != "ambiguous" {
		t.Fatalf("expected ambiguous correlation for stale receipt, got method=%q confidence=%q", receipt.CorrelationMethod, receipt.CorrelationConfidence)
	}
	if receipt.Verdict != "insufficient_evidence" || receipt.InternalDenialCode != "kernel.correlation_ambiguous" {
		t.Fatalf("expected insufficient evidence for stale receipt, got verdict=%q code=%q", receipt.Verdict, receipt.InternalDenialCode)
	}
}

func TestCorrelateRejectsSamePIDDifferentCgroup(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_778_200_360, 0).UTC()
	c := NewCorrelator(CorrelatorOptions{Platform: "linux", CaptureBackend: "linux_ebpf"})
	c.RegisterReceipt(ToolReceipt{
		ReceiptID:               "receipt:cgroup-a",
		SessionID:               "session-a",
		PID:                     4242,
		PIDNamespaceID:          22,
		ProcessStartMonotonicNS: 200,
		CgroupID:                77,
		SpanStart:               now.Add(-time.Second),
		SpanEnd:                 now.Add(time.Second),
	})

	receipt := c.Correlate(ProcessEvent{
		EventID:                 "evt-cgroup-mismatch",
		SessionID:               "session-a",
		Type:                    ProcessEventExec,
		PID:                     4242,
		PIDNamespaceID:          22,
		ProcessStartMonotonicNS: 200,
		CgroupID:                88,
		ObservedAt:              now,
	}, EventContext{})

	if receipt.CorrelationMethod != "ambiguous" || receipt.CorrelationConfidence != "ambiguous" {
		t.Fatalf("expected ambiguous correlation for cgroup mismatch, got method=%q confidence=%q", receipt.CorrelationMethod, receipt.CorrelationConfidence)
	}
}

func TestCorrelateMarksOverlappingPIDSpansAmbiguous(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_778_200_370, 0).UTC()
	c := NewCorrelator(CorrelatorOptions{Platform: "linux", CaptureBackend: "linux_ebpf"})
	for i := 0; i < 2; i++ {
		c.RegisterReceipt(ToolReceipt{
			ReceiptID:               fmt.Sprintf("receipt:overlap-%d", i+1),
			SessionID:               "session-a",
			PID:                     5151,
			PIDNamespaceID:          42,
			ProcessStartMonotonicNS: 1_000,
			CgroupID:                55,
			SpanStart:               now.Add(-500 * time.Millisecond),
			SpanEnd:                 now.Add(500 * time.Millisecond),
		})
	}

	receipt := c.Correlate(ProcessEvent{
		EventID:                 "evt-overlap",
		SessionID:               "session-a",
		Type:                    ProcessEventExec,
		PID:                     5151,
		PIDNamespaceID:          42,
		ProcessStartMonotonicNS: 1_000,
		CgroupID:                55,
		ObservedAt:              now,
	}, EventContext{})

	if receipt.CorrelationMethod != "ambiguous" || receipt.CorrelationConfidence != "ambiguous" {
		t.Fatalf("expected ambiguous correlation for overlapping spans, got method=%q confidence=%q", receipt.CorrelationMethod, receipt.CorrelationConfidence)
	}
	if receipt.Verdict != "insufficient_evidence" {
		t.Fatalf("expected insufficient evidence verdict, got %q", receipt.Verdict)
	}
}

func TestCorrelateRejectsNamespaceMismatch(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_778_200_380, 0).UTC()
	c := NewCorrelator(CorrelatorOptions{Platform: "linux", CaptureBackend: "linux_ebpf"})
	c.RegisterReceipt(ToolReceipt{
		ReceiptID:               "receipt:ns-a",
		SessionID:               "session-a",
		PID:                     9000,
		PIDNamespaceID:          100,
		ProcessStartMonotonicNS: 12_345,
		CgroupID:                222,
		SpanStart:               now.Add(-time.Second),
		SpanEnd:                 now.Add(time.Second),
	})

	receipt := c.Correlate(ProcessEvent{
		EventID:                 "evt-ns-mismatch",
		SessionID:               "session-a",
		Type:                    ProcessEventExec,
		PID:                     9000,
		PIDNamespaceID:          101,
		ProcessStartMonotonicNS: 12_345,
		CgroupID:                222,
		ObservedAt:              now,
	}, EventContext{})

	if receipt.CorrelationMethod != "ambiguous" || receipt.CorrelationConfidence != "ambiguous" {
		t.Fatalf("expected ambiguous correlation for namespace mismatch, got method=%q confidence=%q", receipt.CorrelationMethod, receipt.CorrelationConfidence)
	}
}

func TestCorrelatorConcurrentRegisterAndCorrelate(t *testing.T) {
	t.Parallel()

	base := time.Unix(1_778_200_450, 0).UTC()
	c := NewCorrelator(CorrelatorOptions{Platform: "linux", CaptureBackend: "linux_ebpf"})

	const workers = 6
	const perWorker = 250

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		workerID := w
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				pid := uint32(3000 + (i % 20))
				ns := uint64(500 + workerID)
				start := uint64(900_000 + i)
				now := base.Add(time.Duration(workerID*perWorker+i) * time.Millisecond)
				receiptID := fmt.Sprintf("receipt:w%d:%d", workerID, i)
				c.RegisterReceipt(ToolReceipt{
					ReceiptID:               receiptID,
					SessionID:               "session-race",
					PID:                     pid,
					PIDNamespaceID:          ns,
					ProcessStartMonotonicNS: start,
					CgroupID:                321,
					SpanStart:               now.Add(-500 * time.Millisecond),
					SpanEnd:                 now.Add(500 * time.Millisecond),
				})
				_ = c.Correlate(ProcessEvent{
					EventID:                 fmt.Sprintf("event:w%d:%d", workerID, i),
					SessionID:               "session-race",
					Type:                    ProcessEventExec,
					PID:                     pid,
					PIDNamespaceID:          ns,
					ProcessStartMonotonicNS: start,
					CgroupID:                321,
					ObservedAt:              now,
				}, EventContext{})
			}
		}()
	}
	wg.Wait()

	final := c.Correlate(ProcessEvent{
		EventID:                 "event:final",
		SessionID:               "session-race",
		Type:                    ProcessEventExec,
		PID:                     3000,
		PIDNamespaceID:          500,
		ProcessStartMonotonicNS: 900_000,
		CgroupID:                321,
		ObservedAt:              base.Add(10 * time.Minute),
	}, EventContext{})
	if final.EventClass != "kernel_effect" {
		t.Fatalf("event_class = %q, want kernel_effect", final.EventClass)
	}
}

func TestReplayEventSourceYieldsExecExitForSessionScope(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_778_200_400, 0).UTC()
	source := NewReplayEventSource([]ProcessEvent{
		{EventID: "evt-1", SessionID: "session-a", Type: ProcessEventExec, PID: 10, CgroupID: 1, ObservedAt: now},
		{EventID: "evt-2", SessionID: "session-a", Type: ProcessEventExit, PID: 10, CgroupID: 1, ObservedAt: now.Add(time.Millisecond)},
		{EventID: "evt-3", SessionID: "session-b", Type: ProcessEventExec, PID: 11, CgroupID: 2, ObservedAt: now.Add(2 * time.Millisecond)},
	})
	scope := SessionScope{SessionID: "session-a", CgroupID: 1}

	event1, ok := source.Next(scope)
	if !ok {
		t.Fatal("expected first scoped event")
	}
	if event1.Type != ProcessEventExec {
		t.Fatalf("event1 type = %q, want exec", event1.Type)
	}

	event2, ok := source.Next(scope)
	if !ok {
		t.Fatal("expected second scoped event")
	}
	if event2.Type != ProcessEventExit {
		t.Fatalf("event2 type = %q, want exit", event2.Type)
	}

	if _, ok := source.Next(scope); ok {
		t.Fatal("expected no further scoped events")
	}
}

func BenchmarkCorrelateExecEvent(b *testing.B) {
	now := time.Unix(1_778_200_500, 0).UTC()
	c := NewCorrelator(CorrelatorOptions{Platform: "linux", CaptureBackend: "linux_ebpf"})
	c.RegisterReceipt(ToolReceipt{
		ReceiptID:               "receipt:bench",
		SessionID:               "session-bench",
		PID:                     8080,
		PIDNamespaceID:          77,
		ProcessStartMonotonicNS: 7_777_777,
		CgroupID:                9,
		SpanStart:               now.Add(-200 * time.Millisecond),
		SpanEnd:                 now.Add(200 * time.Millisecond),
		ObservedAt:              now,
	})
	evt := ProcessEvent{
		EventID:                 "evt-bench",
		SessionID:               "session-bench",
		Type:                    ProcessEventExec,
		PID:                     8080,
		PPID:                    8000,
		TID:                     8080,
		PIDNamespaceID:          77,
		ProcessStartMonotonicNS: 7_777_777,
		CgroupID:                9,
		Comm:                    "bash",
		ObservedAt:              now,
	}

	ctx := EventContext{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.Correlate(evt, ctx)
	}
}

func buildRingbufSample(rawType uint8, monotonicNS uint64, pid, ppid, tid, pidNamespaceID uint32, cgroupID uint64, comm string) []byte {
	sample := make([]byte, ringbufRecordMinSize)
	sample[0] = rawType
	binary.LittleEndian.PutUint64(sample[8:16], monotonicNS)
	binary.LittleEndian.PutUint32(sample[16:20], pid)
	binary.LittleEndian.PutUint32(sample[20:24], ppid)
	binary.LittleEndian.PutUint32(sample[24:28], tid)
	binary.LittleEndian.PutUint32(sample[28:32], pidNamespaceID)
	binary.LittleEndian.PutUint64(sample[32:40], cgroupID)
	copy(sample[44:60], []byte(comm))
	return sample
}
