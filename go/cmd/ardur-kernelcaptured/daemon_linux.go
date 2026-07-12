//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

func platformName() string { return "linux" }

// sdNotify sends a systemd notification state to the NOTIFY_SOCKET if one is
// configured. If the daemon is not running under systemd the env var is absent
// and the call is a no-op. Notification failure is non-fatal: the daemon
// continues to run and systemd falls back to its startup timeout.
func sdNotify(state string) error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	// NOTIFY_SOCKET may be prefixed with '@' for abstract sockets.
	network := "unixgram"
	addr := socket
	if len(addr) > 0 && addr[0] == '@' {
		addr = "\x00" + addr[1:]
	}
	conn, err := net.DialUnix(network, nil, &net.UnixAddr{Net: network, Name: addr})
	if err != nil {
		return fmt.Errorf("sd_notify dial: %w", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(state)); err != nil {
		return fmt.Errorf("sd_notify write: %w", err)
	}
	return nil
}

// runWatchdog sends WATCHDOG=1 keepalives to systemd on the given interval.
// The interval should be at most half of WatchdogSec in the unit file.
// The goroutine exits when ctx is cancelled.
func runWatchdog(ctx context.Context, interval time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := sdNotify("WATCHDOG=1"); err != nil {
				log.Warn("watchdog notify failed", "error", err)
			}
		}
	}
}

// runEBPFConsumer loads the embedded eBPF program, attaches exec/exit
// tracepoints, and streams ProcessEvents to d.processKernelEvent until ctx is
// cancelled.
//
// Claim boundary: loads the process-exec eBPF objects embedded in the binary,
// attaches raw sched_process_exec and sched/sched_process_exit, reads events
// from the BPF ringbuf, and routes them to registered sessions. Pins the
// tracepoint links and ringbuf map under the ardur-owned bpffs namespace
// (kernelcapture.DefaultPinnedEBPFPaths) so a daemon restart reuses the
// still-attached programs instead of re-attaching. Does NOT create or join
// cgroups, install/start a system service, or enforce any action against the
// observed process.
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

	handles, err := kernelcapture.LoadAndAttachProcessExecEBPFPinned(kernelcapture.DefaultPinnedEBPFPaths())
	if err != nil {
		return fmt.Errorf("load and attach eBPF: %w", err)
	}
	defer handles.Close()
	if pinErr := handles.PinningError(); pinErr != nil {
		log.Warn("process lifecycle pinning unavailable; restart survival disabled", "error", pinErr)
	}
	if err := d.lifecycleFilter.install(handles); err != nil {
		d.disableAgentRecognition()
		log.Warn("process lifecycle cgroup filter unavailable; using permissive capture when safe and rejecting registration otherwise", "error", err)
	} else {
		if recognitionErr := d.lifecycleFilter.agentRecognitionError(); recognitionErr != nil {
			d.disableAgentRecognition()
			log.Warn("agent recognition prefilter unavailable; recognition disabled while scoped lifecycle capture remains active", "error", recognitionErr)
		}
		defer func() {
			if err := d.lifecycleFilter.detach(handles); err != nil {
				log.Warn("quiesce process lifecycle cgroup filter", "error", err)
			}
		}()
	}
	d.setLifecycleDropCounter(handles.LifecycleDroppedTotal)
	defer d.setLifecycleDropCounter(nil)

	log.Info("eBPF tracepoints attached",
		"exec", "raw/sched_process_exec",
		"exit", "sched/sched_process_exit",
	)

	source := kernelcapture.NewRingbufProcessSourceFromRingbufReader(handles.Reader())
	// No defer source.Close() here: handles.Close() owns the reader.

	// Empty userspace scope: the BPF producer already limits delivery to daemon-
	// managed cgroups. The router still verifies ownership before persistence.
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
					epoch := d.recordMalformedLifecycleRecord()
					log.Warn("malformed ringbuf record", "loss_epoch", epoch)
					continue
				}
			}
			return fmt.Errorf("ringbuf read: %w", err)
		}
		if !ok {
			d.sampleLifecycleProducerLoss()
			continue
		}

		d.sampleLifecycleProducerLoss()
		d.processKernelEvent(evt)
	}
}
