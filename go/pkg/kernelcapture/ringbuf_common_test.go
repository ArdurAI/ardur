package kernelcapture

import (
	"context"
	"encoding/binary"
	"encoding/json"
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

func TestCloseRingbufHandlesClosesReaderAndMap(t *testing.T) {
	t.Parallel()

	closed := []string{}
	err := closeRingbufHandles(
		func() error {
			closed = append(closed, "reader")
			return nil
		},
		func() error {
			closed = append(closed, "map")
			return nil
		},
	)
	if err != nil {
		t.Fatalf("closeRingbufHandles error: %v", err)
	}
	if len(closed) != 2 || closed[0] != "reader" || closed[1] != "map" {
		t.Fatalf("closed = %#v, want reader then map", closed)
	}
}

func TestCloseRingbufHandlesReturnsReaderAndMapErrors(t *testing.T) {
	t.Parallel()

	readerErr := errors.New("reader close failed")
	mapErr := errors.New("map close failed")
	err := closeRingbufHandles(
		func() error { return readerErr },
		func() error { return mapErr },
	)
	if !errors.Is(err, readerErr) {
		t.Fatalf("expected reader error in %v", err)
	}
	if !errors.Is(err, mapErr) {
		t.Fatalf("expected map error in %v", err)
	}
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

func TestNextRingbufProcessEventUsesPollDeadlineBeforeFarContextDeadline(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
	defer cancel()
	pollInterval := 25 * time.Millisecond
	reader := &scriptedRingbufReader{reads: []scriptedRingbufRead{{sample: []byte{1, 2, 3}}}}

	started := time.Now()
	_, _, err := nextRingbufProcessEvent(ctx, reader, SessionScope{}, pollInterval)
	var typed *RingbufNextError
	if !errors.As(err, &typed) || typed.Kind != RingbufErrorMalformedRecord {
		t.Fatalf("expected malformed-record sentinel after one read, got %T (%v)", err, err)
	}
	if len(reader.deadlines) != 1 {
		t.Fatalf("deadlines recorded = %d, want 1", len(reader.deadlines))
	}
	deadline := reader.deadlines[0]
	if deadline.After(started.Add(time.Second)) {
		t.Fatalf("deadline = %s, want short poll deadline near %s, not far context deadline", deadline, started.Add(pollInterval))
	}
	if deadline.Before(started) {
		t.Fatalf("deadline = %s, want future poll deadline", deadline)
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
	copy(raw[72:88], []byte("python3"))
	copy(raw[88:152], []byte("agent.py"))

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
	if evt.ExecutableBasename != "agent.py" {
		t.Fatalf("executable_basename = %q, want agent.py", evt.ExecutableBasename)
	}
}

func TestDecodeRingbufRecordLauncherIdentityIsBoundedAndNonPath(t *testing.T) {
	t.Parallel()

	raw := make([]byte, ringbufRecordMinSize)
	raw[0] = 1
	raw[1] = 1
	raw[2] = 1
	binary.LittleEndian.PutUint32(raw[16:20], 7001)
	binary.LittleEndian.PutUint32(raw[44:48], 2)
	binary.LittleEndian.PutUint64(raw[48:56], 9988)
	binary.LittleEndian.PutUint64(raw[56:64], 77)
	binary.LittleEndian.PutUint32(raw[64:68], 8)
	binary.LittleEndian.PutUint32(raw[68:72], 1)
	copy(raw[72:88], []byte("codex"))
	copy(raw[88:152], []byte("codex"))
	copy(raw[152:216], []byte("python3"))

	evt, err := decodeRingbufRecord(raw)
	if err != nil {
		t.Fatalf("decodeRingbufRecord error: %v", err)
	}
	if !evt.InterpreterBacked || !evt.LauncherScript || evt.LauncherInterpreter != "python3" {
		t.Fatalf("launcher shape = interpreted:%t script:%t interpreter:%q", evt.InterpreterBacked, evt.LauncherScript, evt.LauncherInterpreter)
	}
	want := (LauncherObjectIdentity{Present: true, DeviceMajor: 8, DeviceMinor: 1, Inode: 9988, MountID: 77, LinkCount: 2})
	if evt.LauncherIdentity != want {
		t.Fatal("launcher identity fields did not decode to the expected bounded values")
	}
	serialized, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal process event: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(serialized, &fields); err != nil {
		t.Fatalf("decode serialized process event: %v", err)
	}
	for _, privateField := range []string{"InterpreterBacked", "LauncherScript", "LauncherIdentity", "LauncherInterpreter"} {
		if _, exposed := fields[privateField]; exposed {
			t.Fatalf("private launcher resolution field %q was serialized", privateField)
		}
	}

	raw[1] = 2
	raw[2] = 0
	unknown, err := decodeRingbufRecord(raw)
	if err != nil {
		t.Fatalf("decode interpreter-backed record: %v", err)
	}
	if !unknown.InterpreterBacked || unknown.LauncherScript || unknown.LauncherIdentity.Present {
		t.Fatalf("unsupported interpreter shape = interpreted:%t script:%t identity:%t", unknown.InterpreterBacked, unknown.LauncherScript, unknown.LauncherIdentity.Present)
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
