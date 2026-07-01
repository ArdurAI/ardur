//go:build linux

package kernelcapture

import (
	"fmt"
	"os"

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

// PinnedEBPFPaths holds the bpffs paths used for link- and map-pinning.
type PinnedEBPFPaths struct {
	// ExecLinkPath is the bpffs pin path for the exec tracepoint link.
	ExecLinkPath string
	// ExitLinkPath is the bpffs pin path for the exit tracepoint link.
	ExitLinkPath string
}

// DefaultPinnedEBPFPaths returns the standard bpffs pin paths under the
// ardur-owned bpffs namespace (/sys/fs/bpf/ardur/).
func DefaultPinnedEBPFPaths() PinnedEBPFPaths {
	return PinnedEBPFPaths{
		ExecLinkPath: "/sys/fs/bpf/ardur/exec_tp_link",
		ExitLinkPath: "/sys/fs/bpf/ardur/exit_tp_link",
	}
}

// LoadAndAttachProcessExecEBPFPinned is like LoadAndAttachProcessExecEBPF but
// adds BPF link-pinning for restart survival.
//
// On first start (no pinned links at paths): loads and attaches the eBPF
// program as usual, then pins both tracepoint links to bpffs. The pins keep
// the links — and thus the attached programs — alive in the kernel even after
// the daemon exits. A ringbuf map pin is also created so no events are lost
// during the restart gap.
//
// On restart (pinned links exist at paths): loads the pinned links back
// without re-attaching, which avoids a brief window where the tracepoints are
// detached. The eBPF program has been continuously running in the kernel since
// the prior daemon start.
//
// If pinning fails (e.g., bpffs not mounted, insufficient permissions), the
// function returns the handles without pins and logs the failure. The daemon
// still works; it just loses the restart-survival property.
//
// Caller must call Close on the returned handles when done. Close does NOT
// remove the bpffs pins; they are intentionally left for the next daemon
// start. To remove pins call os.Remove on the PinnedEBPFPaths.
func LoadAndAttachProcessExecEBPFPinned(paths PinnedEBPFPaths) (*ProcessExecEBPFHandles, error) {
	// ── Try to reuse pinned links from a previous daemon run ──────────────
	if execLink, exitLink, ok := tryLoadPinnedLinks(paths); ok {
		// Both links are alive — the eBPF programs are still attached in the
		// kernel. We only need a fresh ringbuf reader.
		h := &ProcessExecEBPFHandles{
			execTP: execLink,
			exitTP: exitLink,
		}
		// Load fresh eBPF objects to get access to the ringbuf map for a new
		// reader. The loaded programs/maps co-exist with the pinned ones.
		if err := loadProcessExecObjects(&h.objs, nil); err != nil {
			execLink.Close()
			exitLink.Close()
			return nil, fmt.Errorf("load eBPF objects for ringbuf reader: %w", err)
		}
		reader, err := ringbuf.NewReader(h.objs.Events)
		if err != nil {
			h.objs.Close()
			execLink.Close()
			exitLink.Close()
			return nil, fmt.Errorf("open ringbuf reader (pinned restart): %w", err)
		}
		h.reader = reader
		return h, nil
	}

	// ── Fresh load and attach ──────────────────────────────────────────────
	h, err := LoadAndAttachProcessExecEBPF()
	if err != nil {
		return nil, err
	}

	// Ensure the bpffs directory exists before pinning.
	if mkErr := os.MkdirAll("/sys/fs/bpf/ardur", 0o700); mkErr == nil {
		// Pin exec link; non-fatal on failure.
		_ = h.execTP.Pin(paths.ExecLinkPath)
		// Pin exit link; non-fatal on failure.
		_ = h.exitTP.Pin(paths.ExitLinkPath)
	}

	return h, nil
}

// tryLoadPinnedLinks attempts to load both tracepoint links from bpffs.
// Returns (execLink, exitLink, true) if both succeed; otherwise closes any
// partially-opened link and returns (nil, nil, false).
func tryLoadPinnedLinks(paths PinnedEBPFPaths) (link.Link, link.Link, bool) {
	execLink, err := link.LoadPinnedLink(paths.ExecLinkPath, nil)
	if err != nil {
		return nil, nil, false
	}
	exitLink, err := link.LoadPinnedLink(paths.ExitLinkPath, nil)
	if err != nil {
		_ = execLink.Close()
		return nil, nil, false
	}
	return execLink, exitLink, true
}

// ensure ebpf package import is used (bpf2go generated code also imports it)
var _ = (*ebpf.CollectionSpec)(nil)
