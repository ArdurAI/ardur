//go:build linux

package kernelcapture

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// ProcessExecEBPFHandles holds the loaded eBPF objects and attached tracepoints
// for the process-exec/exit capture program. Call Close to release all
// resources.
type ProcessExecEBPFHandles struct {
	objs   processExecObjects
	execTP link.Link
	exitTP link.Link
	reader *ringbuf.Reader
}

// Reader returns the ringbuf.Reader for consuming process lifecycle events.
func (h *ProcessExecEBPFHandles) Reader() *ringbuf.Reader {
	return h.reader
}

// Close releases all eBPF resources in reverse order.
func (h *ProcessExecEBPFHandles) Close() {
	if h == nil {
		return
	}
	if h.reader != nil {
		_ = h.reader.Close()
	}
	if h.exitTP != nil {
		_ = h.exitTP.Close()
	}
	if h.execTP != nil {
		_ = h.execTP.Close()
	}
	_ = h.objs.Close()
}

// LoadAndAttachProcessExecEBPF loads the embedded CO-RE process-exec eBPF
// program, attaches the sched/sched_process_exec and sched/sched_process_exit
// tracepoints, and returns a handle that owns the ringbuf reader.
//
// The caller must call Close on the returned handle when done.
//
// Claim boundary: loads and attaches only the embedded process_exec.bpf.c
// object. Does NOT pin maps on bpffs, create/join cgroups, install/start a
// system service, or enforce any action against observed processes.
func LoadAndAttachProcessExecEBPF() (*ProcessExecEBPFHandles, error) {
	h := &ProcessExecEBPFHandles{}

	if err := loadProcessExecObjects(&h.objs, nil); err != nil {
		return nil, fmt.Errorf("load process-exec eBPF objects: %w", err)
	}

	var err error
	h.execTP, err = link.Tracepoint("sched", "sched_process_exec", h.objs.HandleSchedProcessExec, nil)
	if err != nil {
		h.objs.Close()
		return nil, fmt.Errorf("attach sched/sched_process_exec: %w", err)
	}

	h.exitTP, err = link.Tracepoint("sched", "sched_process_exit", h.objs.HandleSchedProcessExit, nil)
	if err != nil {
		_ = h.execTP.Close()
		_ = h.objs.Close()
		return nil, fmt.Errorf("attach sched/sched_process_exit: %w", err)
	}

	h.reader, err = ringbuf.NewReader(h.objs.Events)
	if err != nil {
		_ = h.exitTP.Close()
		_ = h.execTP.Close()
		_ = h.objs.Close()
		return nil, fmt.Errorf("open ringbuf reader: %w", err)
	}

	return h, nil
}

// NewRingbufProcessSourceFromRingbufReader creates a RingbufProcessSource from
// an already-open *ringbuf.Reader. This is used by the daemon to share the
// reader that LoadAndAttachProcessExecEBPF created, without re-opening it.
//
// The caller retains ownership of the reader lifecycle; Close on the returned
// source is a no-op for the reader.
func NewRingbufProcessSourceFromRingbufReader(r *ringbuf.Reader) *RingbufProcessSource {
	return &RingbufProcessSource{
		reader:  &linuxRingbufReader{reader: r},
		closeFn: nil, // caller owns the reader; daemon closes via handles.Close()
	}
}

// ensure ebpf package import is used (bpf2go generated code also imports it)
var _ = (*ebpf.CollectionSpec)(nil)
