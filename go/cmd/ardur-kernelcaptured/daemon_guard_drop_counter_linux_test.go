//go:build linux

package main

// daemon_guard_drop_counter_linux_test.go — unit tests for the enforce_events
// ringbuf drop-counter accounting (issue #122). These exercise the
// kernel-drop-delta logic (newRingbufEnforceEventReaderFromSource /
// droppedSinceLast) with a scripted counter source, so they need no live BPF
// map; the end-to-end "a real kernel reserve failure bumps the counter" claim
// is covered separately by the guard smoke test on a real kernel.

import (
	"log/slog"
	"testing"
)

// scriptedDropTotal returns a dropTotal func that yields the given sequence of
// totals on successive calls (the last value repeats once exhausted), plus ok.
// An empty sequence models an unavailable counter (ok=false).
func scriptedDropTotal(available bool, totals ...uint64) func() (uint64, bool) {
	i := 0
	return func() (uint64, bool) {
		if !available {
			return 0, false
		}
		v := totals[i]
		if i < len(totals)-1 {
			i++
		}
		return v, true
	}
}

func TestDroppedSinceLast_ReportsMonotonicDeltas(t *testing.T) {
	// Counter starts at 0 (fresh load), then advances. Each call to
	// droppedSinceLast should report only the increase since the previous call.
	src := scriptedDropTotal(true, 0, 0, 3, 3, 10)
	a := newRingbufEnforceEventReaderFromSource(nil, src, nil)

	// Baseline snapshot consumed the leading 0; lastDropCount == 0.
	if a.lastDropCount != 0 {
		t.Fatalf("baseline: got lastDropCount=%d want 0", a.lastDropCount)
	}

	cases := []uint64{0, 3, 0, 7} // deltas for totals 0->0, 0->3, 3->3, 3->10
	for i, want := range cases {
		if got := a.droppedSinceLast(); got != want {
			t.Fatalf("call %d: droppedSinceLast=%d want %d", i, got, want)
		}
	}
}

func TestDroppedSinceLast_BaselineSuppressesInheritedTotal(t *testing.T) {
	// A restart reuses the pinned, monotonic counter: it already reads 5 at
	// load. The snapshot baseline must suppress those 5 (a prior daemon
	// lifetime's drops), so only NEW drops beyond 5 are reported.
	src := scriptedDropTotal(true, 5, 5, 8)
	a := newRingbufEnforceEventReaderFromSource(nil, src, nil)

	if a.lastDropCount != 5 {
		t.Fatalf("baseline: got lastDropCount=%d want 5", a.lastDropCount)
	}
	if got := a.droppedSinceLast(); got != 0 { // total still 5
		t.Fatalf("first: droppedSinceLast=%d want 0 (inherited total must not replay)", got)
	}
	if got := a.droppedSinceLast(); got != 3 { // total 5 -> 8
		t.Fatalf("second: droppedSinceLast=%d want 3", got)
	}
}

func TestDroppedSinceLast_NilOrUnavailableCounterReportsZero(t *testing.T) {
	// nil source (older pin set without the counter map) and an available=false
	// source (transient lookup failure) must both degrade to 0, never stalling
	// or fabricating a loss.
	for name, src := range map[string]func() (uint64, bool){
		"nil":         nil,
		"unavailable": scriptedDropTotal(false),
	} {
		t.Run(name, func(t *testing.T) {
			a := newRingbufEnforceEventReaderFromSource(nil, src, nil)
			if a.lastDropCount != 0 {
				t.Fatalf("baseline: got lastDropCount=%d want 0", a.lastDropCount)
			}
			for i := 0; i < 3; i++ {
				if got := a.droppedSinceLast(); got != 0 {
					t.Fatalf("call %d: droppedSinceLast=%d want 0", i, got)
				}
			}
		})
	}
}

func TestDroppedSinceLast_BackwardsCounterRebaselinesToZero(t *testing.T) {
	// If the counter appears to go backwards (e.g. a fresh unpinned map after a
	// restart resets the frame of reference), we must re-baseline and report 0,
	// never an enormous unsigned underflow spike.
	src := scriptedDropTotal(true, 100, 100, 4, 9)
	a := newRingbufEnforceEventReaderFromSource(nil, src, nil)

	if a.lastDropCount != 100 {
		t.Fatalf("baseline: got lastDropCount=%d want 100", a.lastDropCount)
	}
	if got := a.droppedSinceLast(); got != 0 { // 100 -> 100
		t.Fatalf("steady: got %d want 0", got)
	}
	if got := a.droppedSinceLast(); got != 0 { // 100 -> 4 (backwards): rebaseline, no spike
		t.Fatalf("backwards: got %d want 0 (must not underflow)", got)
	}
	if a.lastDropCount != 4 {
		t.Fatalf("post-rebaseline: got lastDropCount=%d want 4", a.lastDropCount)
	}
	if got := a.droppedSinceLast(); got != 5 { // 4 -> 9
		t.Fatalf("resume: got %d want 5", got)
	}
}

func TestNewReaderLogsNonzeroBaselineOnce(t *testing.T) {
	// A nonzero baseline (inherited drops) should be surfaced via a warning at
	// construction. We just assert construction with a logger doesn't panic and
	// sets the baseline; the exact log line is not contract.
	log := slog.New(slog.NewTextHandler(discardWriter{}, nil))
	a := newRingbufEnforceEventReaderFromSource(nil, scriptedDropTotal(true, 7), log)
	if a.lastDropCount != 7 {
		t.Fatalf("got lastDropCount=%d want 7", a.lastDropCount)
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
