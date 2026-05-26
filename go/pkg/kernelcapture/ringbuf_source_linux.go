//go:build linux

package kernelcapture

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// RingbufProcessSource consumes process lifecycle records from a pinned ringbuf map.
type RingbufProcessSource struct {
	reader  ringbufSampleReader
	closeFn func() error
}

// NewRingbufProcessSource opens a pinned ringbuf map for process lifecycle events.
//
// Trust boundary:
//   - pinnedMapPath must come from daemon-owned privileged configuration.
//   - repository/mission-controlled config must not select this path.
//   - privileged daemon deployments should use a root-owned restrictive bpffs
//     namespace and root-owned daemon config for map/producer ownership.
func NewRingbufProcessSource(pinnedMapPath string) (*RingbufProcessSource, error) {
	m, err := ebpf.LoadPinnedMap(pinnedMapPath, nil)
	if err != nil {
		return nil, fmt.Errorf("load pinned ringbuf map %q: %w", pinnedMapPath, err)
	}
	defer m.Close()

	r, err := ringbuf.NewReader(m)
	if err != nil {
		return nil, fmt.Errorf("open ringbuf reader %q: %w", pinnedMapPath, err)
	}

	adapter := &linuxRingbufReader{reader: r}
	return &RingbufProcessSource{reader: adapter, closeFn: r.Close}, nil
}

// Close releases the ringbuf reader.
func (s *RingbufProcessSource) Close() error {
	if s == nil || s.closeFn == nil {
		return nil
	}
	return s.closeFn()
}

// Next reads one ringbuf sample and returns a scoped process event when matched.
//
// Error contract:
//   - context cancellation/deadline returns *RingbufNextError kind
//     context_canceled/deadline_exceeded.
//   - malformed samples return *RingbufNextError kind malformed_record; callers
//     should propagate RingbufCaptureLoss into EventContext.
//   - non-timeout read failures return *RingbufNextError kind read_error.
func (s *RingbufProcessSource) Next(ctx context.Context, scope SessionScope) (ProcessEvent, bool, error) {
	if s == nil {
		return ProcessEvent{}, false, fmt.Errorf("ringbuf source is not initialized")
	}
	return nextRingbufProcessEvent(ctx, s.reader, scope, defaultRingbufPollInterval)
}

type linuxRingbufReader struct {
	reader *ringbuf.Reader
}

func (r *linuxRingbufReader) SetDeadline(deadline time.Time) {
	r.reader.SetDeadline(deadline)
}

func (r *linuxRingbufReader) ReadSample() ([]byte, error) {
	record, err := r.reader.Read()
	if err != nil {
		return nil, err
	}
	return record.RawSample, nil
}
