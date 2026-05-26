//go:build !linux

package kernelcapture

import (
	"context"
	"errors"
	"testing"
)

func TestRingbufSourceIsUnsupportedOnNonLinux(t *testing.T) {
	t.Parallel()

	source, err := NewRingbufProcessSource("/sys/fs/bpf/ardur_ringbuf")
	if !errors.Is(err, ErrRingbufUnsupported) {
		t.Fatalf("expected ErrRingbufUnsupported, got %v", err)
	}
	if source != nil {
		t.Fatalf("expected nil source, got %#v", source)
	}

	stub := &RingbufProcessSource{}
	if _, ok, err := stub.Next(context.Background(), SessionScope{}); !errors.Is(err, ErrRingbufUnsupported) || ok {
		t.Fatalf("expected unsupported error + ok=false, got ok=%v err=%v", ok, err)
	}
}
