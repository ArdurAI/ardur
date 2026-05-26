package kernelcapture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"time"
)

const ringbufRecordMinSize = 60

const defaultRingbufPollInterval = 200 * time.Millisecond

type ringbufSampleReader interface {
	SetDeadline(time.Time)
	ReadSample() ([]byte, error)
}

func nextRingbufProcessEvent(ctx context.Context, reader ringbufSampleReader, scope SessionScope, pollInterval time.Duration) (ProcessEvent, bool, error) {
	if reader == nil {
		return ProcessEvent{}, false, errors.New("ringbuf source is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if pollInterval <= 0 {
		pollInterval = defaultRingbufPollInterval
	}

	for {
		deadline := time.Now().Add(pollInterval)
		if ctxDeadline, ok := ctx.Deadline(); ok {
			deadline = ctxDeadline
		}
		reader.SetDeadline(deadline)

		raw, err := reader.ReadSample()
		if err != nil {
			if isRingbufReadTimeout(err) {
				if ctxErr := ctx.Err(); ctxErr != nil {
					if errors.Is(ctxErr, context.Canceled) {
						return ProcessEvent{}, false, &RingbufNextError{Kind: RingbufErrorContextCanceled, Err: ctxErr}
					}
					if errors.Is(ctxErr, context.DeadlineExceeded) {
						return ProcessEvent{}, false, &RingbufNextError{Kind: RingbufErrorDeadlineExceeded, Err: ctxErr}
					}
				}
				continue
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				if errors.Is(ctxErr, context.Canceled) {
					return ProcessEvent{}, false, &RingbufNextError{Kind: RingbufErrorContextCanceled, Err: ctxErr}
				}
				if errors.Is(ctxErr, context.DeadlineExceeded) {
					return ProcessEvent{}, false, &RingbufNextError{Kind: RingbufErrorDeadlineExceeded, Err: ctxErr}
				}
			}
			return ProcessEvent{}, false, &RingbufNextError{Kind: RingbufErrorRead, Err: err}
		}

		evt, err := decodeRingbufRecord(raw)
		if err != nil {
			return ProcessEvent{}, false, &RingbufNextError{Kind: RingbufErrorMalformedRecord, Err: err}
		}
		if scope.matches(evt) {
			return evt, true, nil
		}
	}
}

func isRingbufReadTimeout(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded)
}

func decodeRingbufRecord(raw []byte) (ProcessEvent, error) {
	if len(raw) < ringbufRecordMinSize {
		return ProcessEvent{}, ErrRingbufRecordTooSmall
	}

	reader := bytes.NewReader(raw)
	var rawType uint8
	if err := binary.Read(reader, binary.LittleEndian, &rawType); err != nil {
		return ProcessEvent{}, err
	}
	if _, err := reader.Seek(7, 1); err != nil {
		return ProcessEvent{}, err
	}

	var monotonicNS uint64
	if err := binary.Read(reader, binary.LittleEndian, &monotonicNS); err != nil {
		return ProcessEvent{}, err
	}

	var pid uint32
	if err := binary.Read(reader, binary.LittleEndian, &pid); err != nil {
		return ProcessEvent{}, err
	}
	var ppid uint32
	if err := binary.Read(reader, binary.LittleEndian, &ppid); err != nil {
		return ProcessEvent{}, err
	}
	var tid uint32
	if err := binary.Read(reader, binary.LittleEndian, &tid); err != nil {
		return ProcessEvent{}, err
	}

	var pidNamespaceID uint32
	if err := binary.Read(reader, binary.LittleEndian, &pidNamespaceID); err != nil {
		return ProcessEvent{}, err
	}

	var cgroupID uint64
	if err := binary.Read(reader, binary.LittleEndian, &cgroupID); err != nil {
		return ProcessEvent{}, err
	}

	var exitCode int32
	if err := binary.Read(reader, binary.LittleEndian, &exitCode); err != nil {
		return ProcessEvent{}, err
	}

	commBuf := make([]byte, 16)
	if _, err := reader.Read(commBuf); err != nil {
		return ProcessEvent{}, err
	}
	comm := strings.TrimRight(string(commBuf), "\x00")

	return ProcessEvent{
		Type:                decodeProcessEventType(rawType),
		PID:                 pid,
		PPID:                ppid,
		TID:                 tid,
		PIDNamespaceID:      uint64(pidNamespaceID),
		CgroupID:            cgroupID,
		Comm:                comm,
		ExitCode:            exitCode,
		ObservedMonotonicNS: monotonicNS,
	}, nil
}

func decodeProcessEventType(rawType uint8) ProcessEventType {
	switch rawType {
	case 1:
		return ProcessEventExec
	case 2:
		return ProcessEventExit
	default:
		return ProcessEventType("unknown")
	}
}
