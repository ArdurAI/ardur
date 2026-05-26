package kernelcapture

import (
	"errors"
	"fmt"
)

var (
	// ErrRingbufUnsupported is returned when the runtime is not Linux.
	ErrRingbufUnsupported = errors.New("kernelcapture: ringbuf source is linux-only")
	// ErrRingbufRecordTooSmall indicates an invalid ringbuf sample payload.
	ErrRingbufRecordTooSmall = errors.New("kernelcapture: ringbuf sample too small")
)

// RingbufErrorKind classifies ringbuf-reader behavior for caller policy.
type RingbufErrorKind string

const (
	RingbufErrorContextCanceled  RingbufErrorKind = "context_canceled"
	RingbufErrorDeadlineExceeded RingbufErrorKind = "deadline_exceeded"
	RingbufErrorMalformedRecord  RingbufErrorKind = "malformed_record"
	RingbufErrorRead             RingbufErrorKind = "read_error"
)

// RingbufNextError is the typed error returned by ringbuf event reads.
type RingbufNextError struct {
	Kind RingbufErrorKind
	Err  error
}

func (e *RingbufNextError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return fmt.Sprintf("kernelcapture: ringbuf %s", e.Kind)
	}
	return fmt.Sprintf("kernelcapture: ringbuf %s: %v", e.Kind, e.Err)
}

func (e *RingbufNextError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// RingbufCaptureLoss maps a ringbuf read error into capture-loss counters that a
// caller can propagate into EventContext for downstream correlation honesty.
func RingbufCaptureLoss(err error) CaptureLoss {
	var typed *RingbufNextError
	if !errors.As(err, &typed) {
		return CaptureLoss{}
	}
	switch typed.Kind {
	case RingbufErrorMalformedRecord:
		return CaptureLoss{RingbufDropped: 1}
	default:
		return CaptureLoss{}
	}
}

// ApplyRingbufCaptureLoss adds inferred ringbuf loss counters into ctx.
// Returns true if any loss counters were incremented.
func ApplyRingbufCaptureLoss(ctx *EventContext, err error) bool {
	if ctx == nil {
		return false
	}
	loss := RingbufCaptureLoss(err)
	if loss.RingbufDropped == 0 && loss.DaemonQueueDropped == 0 {
		return false
	}
	ctx.CaptureLoss.RingbufDropped += loss.RingbufDropped
	ctx.CaptureLoss.DaemonQueueDropped += loss.DaemonQueueDropped
	return true
}
