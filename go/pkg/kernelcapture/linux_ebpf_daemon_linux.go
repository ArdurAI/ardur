//go:build linux

package kernelcapture

import (
	"fmt"
	"os"
	"path/filepath"

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
	// eventsMap is only set when reusing a pinned ringbuf map across a
	// daemon restart (see LoadAndAttachProcessExecEBPFPinned); on a fresh
	// load the map is owned by objs instead. Close must release it either
	// way.
	eventsMap *ebpf.Map
	reader    *ringbuf.Reader
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
	if h.eventsMap != nil {
		_ = h.eventsMap.Close()
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
	// EventsMapPath is the bpffs pin path for the process-lifecycle ringbuf
	// map. A restart reuses this exact map so the reader stays bound to
	// whatever the pinned (still-attached) programs are writing into.
	EventsMapPath string
}

// DefaultPinnedEBPFPaths returns the standard bpffs pin paths under the
// ardur-owned bpffs namespace (/sys/fs/bpf/ardur/). EventsMapPath matches the
// ringbuf map path recorded by BuildDaemonCustodyPlan.
func DefaultPinnedEBPFPaths() PinnedEBPFPaths {
	return PinnedEBPFPaths{
		ExecLinkPath:  "/sys/fs/bpf/ardur/exec_tp_link",
		ExitLinkPath:  "/sys/fs/bpf/ardur/exit_tp_link",
		EventsMapPath: "/sys/fs/bpf/ardur/process_lifecycle_events",
	}
}

// LoadAndAttachProcessExecEBPFPinned is like LoadAndAttachProcessExecEBPF but
// adds BPF link- and map-pinning for restart survival.
//
// On first start (no pinned state at paths): loads and attaches the eBPF
// program as usual, then pins both tracepoint links and the ringbuf map to
// bpffs. The pins keep the links — and thus the attached programs — alive in
// the kernel even after the daemon exits, and keep the ringbuf map reachable
// so no events are lost during the restart gap.
//
// On restart (pinned links AND the pinned ringbuf map all exist at paths):
// loads the pinned links back without re-attaching, which avoids a brief
// window where the tracepoints are detached, and loads the pinned map to open
// a new reader bound to the exact map the still-attached programs write into.
// The eBPF program has been continuously running in the kernel since the
// prior daemon start.
//
// If any of the three pins is missing (e.g. a prior pin attempt partially
// failed), the pinned state is treated as unusable and the function falls
// back to a fresh load/attach/pin, matching first-start behavior.
//
// If pinning fails (e.g., bpffs not mounted, insufficient permissions), the
// function returns the handles without pins and logs the failure. The daemon
// still works; it just loses the restart-survival property.
//
// Caller must call Close on the returned handles when done. Close does NOT
// remove the bpffs pins; they are intentionally left for the next daemon
// start. To remove pins call os.Remove on the PinnedEBPFPaths.
func LoadAndAttachProcessExecEBPFPinned(paths PinnedEBPFPaths) (*ProcessExecEBPFHandles, error) {
	// ── Try to reuse pinned links + map from a previous daemon run ────────
	if execLink, exitLink, eventsMap, ok := tryLoadPinnedState(paths); ok {
		// The links are alive — the eBPF programs are still attached in the
		// kernel and writing into eventsMap. Open a reader bound to that
		// same map so restart doesn't lose the events the programs emit.
		reader, err := ringbuf.NewReader(eventsMap)
		if err != nil {
			_ = eventsMap.Close()
			_ = exitLink.Close()
			_ = execLink.Close()
			return nil, fmt.Errorf("open ringbuf reader (pinned restart): %w", err)
		}
		return &ProcessExecEBPFHandles{
			execTP:    execLink,
			exitTP:    exitLink,
			eventsMap: eventsMap,
			reader:    reader,
		}, nil
	}

	// ── Fresh load and attach ──────────────────────────────────────────────
	h, err := LoadAndAttachProcessExecEBPF()
	if err != nil {
		return nil, err
	}

	// Ensure the bpffs directories for all three pin paths exist, then pin
	// the exec link, exit link, and ringbuf map; each Pin is non-fatal on
	// failure. A partial pin (e.g. links pinned but the map pin fails) makes
	// tryLoadPinnedState fail on the next restart, which falls back to this
	// fresh-load path again rather than reusing a stale link.
	if mkErr := os.MkdirAll(filepath.Dir(paths.ExecLinkPath), 0o700); mkErr == nil {
		_ = h.execTP.Pin(paths.ExecLinkPath)
	}
	if mkErr := os.MkdirAll(filepath.Dir(paths.ExitLinkPath), 0o700); mkErr == nil {
		_ = h.exitTP.Pin(paths.ExitLinkPath)
	}
	if mkErr := os.MkdirAll(filepath.Dir(paths.EventsMapPath), 0o700); mkErr == nil {
		_ = h.objs.Events.Pin(paths.EventsMapPath)
	}

	return h, nil
}

// tryLoadPinnedState attempts to load both tracepoint links and the ringbuf
// map from bpffs. Returns ok=true only if all three succeed; otherwise it
// closes any partially-opened handles and returns ok=false so the caller
// falls back to a fresh load rather than binding a reader to a map the
// attached programs are not writing into.
func tryLoadPinnedState(paths PinnedEBPFPaths) (execLink, exitLink link.Link, eventsMap *ebpf.Map, ok bool) {
	execLink, err := link.LoadPinnedLink(paths.ExecLinkPath, nil)
	if err != nil {
		return nil, nil, nil, false
	}
	exitLink, err = link.LoadPinnedLink(paths.ExitLinkPath, nil)
	if err != nil {
		_ = execLink.Close()
		return nil, nil, nil, false
	}
	eventsMap, err = ebpf.LoadPinnedMap(paths.EventsMapPath, nil)
	if err != nil {
		_ = exitLink.Close()
		_ = execLink.Close()
		return nil, nil, nil, false
	}
	return execLink, exitLink, eventsMap, true
}
