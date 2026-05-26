//go:build !linux

package kernelcapture

import (
	"context"
)

// RingbufProcessSource is unavailable on non-Linux runtimes.
type RingbufProcessSource struct{}

// NewRingbufProcessSource returns ErrRingbufUnsupported on non-Linux hosts.
func NewRingbufProcessSource(_ string) (*RingbufProcessSource, error) {
	return nil, ErrRingbufUnsupported
}

// Close is a no-op for the unsupported source.
func (s *RingbufProcessSource) Close() error {
	return nil
}

// Next always reports unsupported on non-Linux hosts.
func (s *RingbufProcessSource) Next(_ context.Context, _ SessionScope) (ProcessEvent, bool, error) {
	return ProcessEvent{}, false, ErrRingbufUnsupported
}
