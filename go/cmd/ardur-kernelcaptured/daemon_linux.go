//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

func platformName() string { return "linux" }

// runEBPFConsumer loads the embedded eBPF program, attaches exec/exit
// tracepoints, and streams ProcessEvents to d.processKernelEvent until ctx is
// cancelled.
//
// Claim boundary: loads the process-exec eBPF objects embedded in the binary,
// attaches sched/sched_process_exec and sched/sched_process_exit, reads events
// from the BPF ringbuf, and routes them to registered sessions. Does NOT pin
// maps on bpffs, create or join cgroups, install/start a system service, or
// enforce any action against the observed process.
func runEBPFConsumer(ctx context.Context, d *daemon, log *slog.Logger) error {
	btfPath := "/sys/kernel/btf/vmlinux"
	if _, err := os.Stat(btfPath); err != nil {
		return fmt.Errorf("BTF not available at %s (required for CO-RE eBPF): %w", btfPath, err)
	}

	kernelRelease, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	log.Info("loading eBPF objects",
		"kernel", string(kernelRelease),
		"btf", btfPath,
	)

	handles, err := kernelcapture.LoadAndAttachProcessExecEBPF()
	if err != nil {
		return fmt.Errorf("load and attach eBPF: %w", err)
	}
	defer handles.Close()

	log.Info("eBPF tracepoints attached",
		"exec", "sched/sched_process_exec",
		"exit", "sched/sched_process_exit",
	)

	source := kernelcapture.NewRingbufProcessSourceFromRingbufReader(handles.Reader())
	// No defer source.Close() here: handles.Close() owns the reader.

	var loss kernelcapture.CaptureLoss
	// Empty scope: all events reach the router (per-session filtering is done
	// in daemon.routeEvent via the cgroup index and ProcessTreeScope).
	scope := kernelcapture.SessionScope{}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		evt, ok, err := source.Next(ctx, scope)
		if err != nil {
			var ringErr *kernelcapture.RingbufNextError
			if errors.As(err, &ringErr) {
				switch ringErr.Kind {
				case kernelcapture.RingbufErrorContextCanceled, kernelcapture.RingbufErrorDeadlineExceeded:
					return ctx.Err()
				case kernelcapture.RingbufErrorMalformedRecord:
					loss.RingbufDropped++
					log.Warn("malformed ringbuf record", "drop_count", loss.RingbufDropped)
					continue
				}
			}
			return fmt.Errorf("ringbuf read: %w", err)
		}
		if !ok {
			continue
		}

		d.processKernelEvent(evt, loss)
	}
}
