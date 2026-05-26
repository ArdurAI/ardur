package kernelcapture

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

type scriptedRingbufRead struct {
	sample []byte
	err    error
}

type scriptedRingbufReader struct {
	reads     []scriptedRingbufRead
	next      int
	deadlines []time.Time
}

func (r *scriptedRingbufReader) SetDeadline(deadline time.Time) {
	r.deadlines = append(r.deadlines, deadline)
}

func (r *scriptedRingbufReader) ReadSample() ([]byte, error) {
	if r.next >= len(r.reads) {
		return nil, io.EOF
	}
	current := r.reads[r.next]
	r.next++
	return current.sample, current.err
}

func TestNextRingbufProcessEventContextCanceledWithoutDeadline(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := &scriptedRingbufReader{reads: []scriptedRingbufRead{{err: os.ErrDeadlineExceeded}}}

	_, _, err := nextRingbufProcessEvent(ctx, reader, SessionScope{}, time.Millisecond)
	var typed *RingbufNextError
	if !errors.As(err, &typed) {
		t.Fatalf("expected RingbufNextError, got %T (%v)", err, err)
	}
	if typed.Kind != RingbufErrorContextCanceled {
		t.Fatalf("kind = %q, want %q", typed.Kind, RingbufErrorContextCanceled)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestNextRingbufProcessEventDeadlineExceeded(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	reader := &scriptedRingbufReader{reads: []scriptedRingbufRead{{err: os.ErrDeadlineExceeded}}}

	_, _, err := nextRingbufProcessEvent(ctx, reader, SessionScope{}, time.Millisecond)
	var typed *RingbufNextError
	if !errors.As(err, &typed) {
		t.Fatalf("expected RingbufNextError, got %T (%v)", err, err)
	}
	if typed.Kind != RingbufErrorDeadlineExceeded {
		t.Fatalf("kind = %q, want %q", typed.Kind, RingbufErrorDeadlineExceeded)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestNextRingbufProcessEventMalformedRecordAndGapPropagation(t *testing.T) {
	t.Parallel()

	reader := &scriptedRingbufReader{reads: []scriptedRingbufRead{{sample: []byte{1, 2, 3}}}}
	_, _, err := nextRingbufProcessEvent(context.Background(), reader, SessionScope{}, time.Millisecond)
	var typed *RingbufNextError
	if !errors.As(err, &typed) {
		t.Fatalf("expected RingbufNextError, got %T (%v)", err, err)
	}
	if typed.Kind != RingbufErrorMalformedRecord {
		t.Fatalf("kind = %q, want %q", typed.Kind, RingbufErrorMalformedRecord)
	}
	if !errors.Is(err, ErrRingbufRecordTooSmall) {
		t.Fatalf("expected ErrRingbufRecordTooSmall, got %v", err)
	}

	loss := RingbufCaptureLoss(err)
	if loss.RingbufDropped != 1 || loss.DaemonQueueDropped != 0 {
		t.Fatalf("unexpected loss mapping: %+v", loss)
	}

	eventCtx := EventContext{}
	if !ApplyRingbufCaptureLoss(&eventCtx, err) {
		t.Fatalf("expected ApplyRingbufCaptureLoss to apply increment")
	}
	if eventCtx.CaptureLoss.RingbufDropped != 1 {
		t.Fatalf("ringbuf_dropped = %d, want 1", eventCtx.CaptureLoss.RingbufDropped)
	}
}

func TestApplyRingbufCaptureLossNoopOnNonLossError(t *testing.T) {
	t.Parallel()

	eventCtx := EventContext{}
	err := &RingbufNextError{Kind: RingbufErrorDeadlineExceeded, Err: context.DeadlineExceeded}
	if ApplyRingbufCaptureLoss(&eventCtx, err) {
		t.Fatalf("expected no loss increment for deadline exceeded")
	}
	if eventCtx.CaptureLoss.RingbufDropped != 0 || eventCtx.CaptureLoss.DaemonQueueDropped != 0 {
		t.Fatalf("expected zero loss counters, got %+v", eventCtx.CaptureLoss)
	}
}

func TestDecodeRingbufRecordExitIncludesExitCode(t *testing.T) {
	t.Parallel()

	raw := make([]byte, ringbufRecordMinSize)
	raw[0] = 2
	binary.LittleEndian.PutUint64(raw[8:16], 9_900_000_000)
	binary.LittleEndian.PutUint32(raw[16:20], 5151)
	binary.LittleEndian.PutUint32(raw[20:24], 5000)
	binary.LittleEndian.PutUint32(raw[24:28], 5151)
	binary.LittleEndian.PutUint32(raw[28:32], 4026531836)
	binary.LittleEndian.PutUint64(raw[32:40], 777)
	exitCode := int32(-13)
	binary.LittleEndian.PutUint32(raw[40:44], uint32(exitCode))
	copy(raw[44:60], []byte("python3"))

	evt, err := decodeRingbufRecord(raw)
	if err != nil {
		t.Fatalf("decodeRingbufRecord error: %v", err)
	}
	if evt.Type != ProcessEventExit {
		t.Fatalf("type = %q, want exit", evt.Type)
	}
	if evt.ExitCode != -13 {
		t.Fatalf("exit_code = %d, want -13", evt.ExitCode)
	}
	if evt.PID != 5151 || evt.PPID != 5000 || evt.TID != 5151 {
		t.Fatalf("unexpected pid tuple: pid=%d ppid=%d tid=%d", evt.PID, evt.PPID, evt.TID)
	}
	if evt.PIDNamespaceID != 4026531836 {
		t.Fatalf("pid_namespace_id = %d, want 4026531836", evt.PIDNamespaceID)
	}
	if evt.CgroupID != 777 {
		t.Fatalf("cgroup_id = %d, want 777", evt.CgroupID)
	}
	if evt.ObservedMonotonicNS != 9_900_000_000 {
		t.Fatalf("observed_monotonic_ns = %d, want 9900000000", evt.ObservedMonotonicNS)
	}
	if evt.Comm != "python3" {
		t.Fatalf("comm = %q, want python3", evt.Comm)
	}
}

func TestProcessTreeScopeTracksDescendantsAndRejectsSiblings(t *testing.T) {
	t.Parallel()

	scope := NewProcessTreeScope(100, 77)
	root := ProcessEvent{Type: ProcessEventExec, PID: 100, PPID: 90, CgroupID: 77, ProcessStartMonotonicNS: 1_000}
	if !scope.MatchesAndTrack(root) {
		t.Fatalf("expected root process to match")
	}

	child := ProcessEvent{Type: ProcessEventExec, PID: 101, PPID: 100, CgroupID: 77, ProcessStartMonotonicNS: 1_100}
	if !scope.MatchesAndTrack(child) {
		t.Fatalf("expected direct child to match and be tracked")
	}

	grandchild := ProcessEvent{Type: ProcessEventExec, PID: 102, PPID: 101, CgroupID: 77, ProcessStartMonotonicNS: 1_200}
	if !scope.MatchesAndTrack(grandchild) {
		t.Fatalf("expected grandchild of tracked process to match")
	}

	sibling := ProcessEvent{Type: ProcessEventExec, PID: 200, PPID: 90, CgroupID: 77, ProcessStartMonotonicNS: 2_000}
	if scope.MatchesAndTrack(sibling) {
		t.Fatalf("did not expect unrelated process in same cgroup to match")
	}

	otherCgroupChild := ProcessEvent{Type: ProcessEventExec, PID: 103, PPID: 100, CgroupID: 88, ProcessStartMonotonicNS: 1_300}
	if scope.MatchesAndTrack(otherCgroupChild) {
		t.Fatalf("did not expect child with mismatched cgroup to match")
	}
}

func TestProcessTreeScopeRetiresExitedPIDBeforeReuse(t *testing.T) {
	t.Parallel()

	scope := NewProcessTreeScope(100, 77)
	if !scope.MatchesAndTrack(ProcessEvent{Type: ProcessEventExec, PID: 100, PPID: 90, CgroupID: 77, ProcessStartMonotonicNS: 1_000}) {
		t.Fatalf("expected root process to match")
	}
	if !scope.MatchesAndTrack(ProcessEvent{Type: ProcessEventExec, PID: 101, PPID: 100, CgroupID: 77, ProcessStartMonotonicNS: 1_100}) {
		t.Fatalf("expected child process to match")
	}
	if !scope.MatchesAndTrack(ProcessEvent{Type: ProcessEventExit, PID: 101, PPID: 100, CgroupID: 77, ProcessStartMonotonicNS: 1_100}) {
		t.Fatalf("expected child exit to match")
	}

	reusedSiblingPID := ProcessEvent{Type: ProcessEventExec, PID: 101, PPID: 90, CgroupID: 77, ProcessStartMonotonicNS: 9_999}
	if scope.MatchesAndTrack(reusedSiblingPID) {
		t.Fatalf("did not expect reused PID outside tracked lineage to match")
	}
}
