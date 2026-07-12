//go:build linux

package kernelcapture

import (
	"errors"
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
	// droppedEventsMap is set only when reusing the pinned lifecycle drop
	// counter. On a fresh load the same map is owned by objs.
	droppedEventsMap *ebpf.Map
	// filterControlMap and allowedCgroupsMap are set only when reusing the
	// pinned producer-filter maps. Fresh loads own the same maps through objs.
	filterControlMap      *ebpf.Map
	allowedCgroupsMap     *ebpf.Map
	recognitionControlMap *ebpf.Map
	recognitionCommsMap   *ebpf.Map
	pinningErr            error
	reader                *ringbuf.Reader
}

// Reader returns the ringbuf.Reader for consuming process lifecycle events.
func (h *ProcessExecEBPFHandles) Reader() *ringbuf.Reader {
	return h.reader
}

// LifecycleDroppedTotal returns the monotonic process lifecycle ringbuf
// reservation-failure total. A false result means the map is unavailable.
func (h *ProcessExecEBPFHandles) LifecycleDroppedTotal() (uint64, bool) {
	if h == nil {
		return 0, false
	}
	dropped := h.droppedEventsMap
	if dropped == nil {
		dropped = h.objs.LifecycleEventsDropped
	}
	if dropped == nil {
		return 0, false
	}
	var zero uint32
	var total uint64
	if err := dropped.Lookup(&zero, &total); err != nil {
		return 0, false
	}
	return total, true
}

// PinningError reports a non-fatal fresh-pin failure. The loaded consumer is
// still usable for this daemon lifetime, but restart survival is unavailable.
func (h *ProcessExecEBPFHandles) PinningError() error {
	if h == nil {
		return nil
	}
	return h.pinningErr
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
	if h.droppedEventsMap != nil {
		_ = h.droppedEventsMap.Close()
	}
	if h.allowedCgroupsMap != nil {
		_ = h.allowedCgroupsMap.Close()
	}
	if h.filterControlMap != nil {
		_ = h.filterControlMap.Close()
	}
	if h.recognitionCommsMap != nil {
		_ = h.recognitionCommsMap.Close()
	}
	if h.recognitionControlMap != nil {
		_ = h.recognitionControlMap.Close()
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
	// DroppedEventsMapPath is the bpffs pin path for the monotonic lifecycle
	// ringbuf reservation-failure counter.
	DroppedEventsMapPath string
	// FilterControlMapPath selects whether process lifecycle events are emitted
	// for every cgroup or only entries in AllowedCgroupsMapPath.
	FilterControlMapPath string
	// AllowedCgroupsMapPath is the daemon-managed process lifecycle cgroup set.
	AllowedCgroupsMapPath string
	// RecognitionControlMapPath enables the exact-comm candidate prefilter.
	RecognitionControlMapPath string
	// RecognitionCommsMapPath stores release-bound exact Linux comm keys.
	RecognitionCommsMapPath string
}

// DefaultPinnedEBPFPaths returns the standard bpffs pin paths under the
// ardur-owned bpffs namespace (/sys/fs/bpf/ardur/). The ringbuf and lifecycle
// drop-counter paths match the map paths recorded by BuildDaemonCustodyPlan.
func DefaultPinnedEBPFPaths() PinnedEBPFPaths {
	return PinnedEBPFPaths{
		ExecLinkPath:              "/sys/fs/bpf/ardur/exec_tp_link",
		ExitLinkPath:              "/sys/fs/bpf/ardur/exit_tp_link",
		EventsMapPath:             "/sys/fs/bpf/ardur/process_lifecycle_events",
		DroppedEventsMapPath:      "/sys/fs/bpf/ardur/process_lifecycle_events_dropped",
		FilterControlMapPath:      "/sys/fs/bpf/ardur/process_lifecycle_filter_control",
		AllowedCgroupsMapPath:     "/sys/fs/bpf/ardur/process_lifecycle_allowed_cgroups",
		RecognitionControlMapPath: "/sys/fs/bpf/ardur/process_recognition_filter_control",
		RecognitionCommsMapPath:   "/sys/fs/bpf/ardur/process_recognition_comms",
	}
}

// LoadAndAttachProcessExecEBPFPinned is like LoadAndAttachProcessExecEBPF but
// adds BPF link- and map-pinning for restart survival.
//
// On first start (no pinned state at paths): loads and attaches the eBPF
// program as usual, then pins both tracepoint links, the ringbuf map, the
// monotonic producer-drop counter, and both producer-filter maps to bpffs. The
// pins keep the links — and thus the attached programs — alive in the kernel
// even after the daemon exits, and keep their complete map generation reachable
// across daemon lifetimes.
//
// On restart (both pinned links and all six pinned maps exist at paths):
// loads the pinned links back without re-attaching, which avoids a brief
// window where the tracepoints are detached, and loads the pinned map to open
// a new reader bound to the exact map the still-attached programs write into.
// The eBPF program has been continuously running in the kernel since the
// prior daemon start.
//
// If any pin is missing, the generation is unusable. All surviving pins are
// removed before a fresh load/attach/pin so old and new tracepoint programs
// cannot remain attached concurrently and duplicate lifecycle evidence.
//
// If fresh pinning fails (e.g., bpffs not mounted), the function removes any
// partial new set and returns usable handles with PinningError populated. The
// daemon still works for this lifetime but logs that restart survival is off.
//
// Caller must call Close on the returned handles when done. Close does NOT
// remove the bpffs pins; they are intentionally left for the next daemon
// start. To remove pins call os.Remove on the PinnedEBPFPaths.
func LoadAndAttachProcessExecEBPFPinned(paths PinnedEBPFPaths) (*ProcessExecEBPFHandles, error) {
	paths = normalizePinnedEBPFPaths(paths)
	// ── Try to reuse one complete pinned generation ───────────────────────
	if execLink, exitLink, eventsMap, droppedEventsMap, filterControlMap, allowedCgroupsMap, recognitionControlMap, recognitionCommsMap, ok := tryLoadPinnedState(paths); ok {
		// The links are alive — the eBPF programs are still attached in the
		// kernel and writing into eventsMap. Open a reader bound to that
		// same map so restart doesn't lose the events the programs emit.
		reader, err := ringbuf.NewReader(eventsMap)
		if err != nil {
			_ = allowedCgroupsMap.Close()
			_ = filterControlMap.Close()
			_ = recognitionCommsMap.Close()
			_ = recognitionControlMap.Close()
			_ = droppedEventsMap.Close()
			_ = eventsMap.Close()
			_ = exitLink.Close()
			_ = execLink.Close()
			return nil, fmt.Errorf("open ringbuf reader (pinned restart): %w", err)
		}
		return &ProcessExecEBPFHandles{
			execTP:                execLink,
			exitTP:                exitLink,
			eventsMap:             eventsMap,
			droppedEventsMap:      droppedEventsMap,
			filterControlMap:      filterControlMap,
			allowedCgroupsMap:     allowedCgroupsMap,
			recognitionControlMap: recognitionControlMap,
			recognitionCommsMap:   recognitionCommsMap,
			reader:                reader,
		}, nil
	}
	if err := removePinnedProcessExecState(paths); err != nil {
		return nil, fmt.Errorf("remove stale or partial process-exec pin set before fresh attach: %w", err)
	}

	// ── Fresh load and attach ──────────────────────────────────────────────
	h, err := LoadAndAttachProcessExecEBPF()
	if err != nil {
		return nil, err
	}

	if pinErr := pinProcessExecState(h, paths); pinErr != nil {
		h.pinningErr = pinErr
	}

	return h, nil
}

// tryLoadPinnedState attempts to load both tracepoint links and all six maps
// from bpffs. An older six-pin generation is intentionally incomplete and is
// replaced before a fresh attach.
func tryLoadPinnedState(paths PinnedEBPFPaths) (execLink, exitLink link.Link, eventsMap, droppedEventsMap, filterControlMap, allowedCgroupsMap, recognitionControlMap, recognitionCommsMap *ebpf.Map, ok bool) {
	execLink, err := link.LoadPinnedLink(paths.ExecLinkPath, nil)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, false
	}
	exitLink, err = link.LoadPinnedLink(paths.ExitLinkPath, nil)
	if err != nil {
		_ = execLink.Close()
		return nil, nil, nil, nil, nil, nil, nil, nil, false
	}
	eventsMap, err = ebpf.LoadPinnedMap(paths.EventsMapPath, nil)
	if err != nil {
		_ = exitLink.Close()
		_ = execLink.Close()
		return nil, nil, nil, nil, nil, nil, nil, nil, false
	}
	droppedEventsMap, err = ebpf.LoadPinnedMap(paths.DroppedEventsMapPath, nil)
	if err != nil {
		_ = eventsMap.Close()
		_ = exitLink.Close()
		_ = execLink.Close()
		return nil, nil, nil, nil, nil, nil, nil, nil, false
	}
	filterControlMap, err = ebpf.LoadPinnedMap(paths.FilterControlMapPath, nil)
	if err != nil {
		_ = droppedEventsMap.Close()
		_ = eventsMap.Close()
		_ = exitLink.Close()
		_ = execLink.Close()
		return nil, nil, nil, nil, nil, nil, nil, nil, false
	}
	allowedCgroupsMap, err = ebpf.LoadPinnedMap(paths.AllowedCgroupsMapPath, nil)
	if err != nil {
		_ = filterControlMap.Close()
		_ = droppedEventsMap.Close()
		_ = eventsMap.Close()
		_ = exitLink.Close()
		_ = execLink.Close()
		return nil, nil, nil, nil, nil, nil, nil, nil, false
	}
	recognitionControlMap, err = ebpf.LoadPinnedMap(paths.RecognitionControlMapPath, nil)
	if err != nil {
		_ = allowedCgroupsMap.Close()
		_ = filterControlMap.Close()
		_ = droppedEventsMap.Close()
		_ = eventsMap.Close()
		_ = exitLink.Close()
		_ = execLink.Close()
		return nil, nil, nil, nil, nil, nil, nil, nil, false
	}
	recognitionCommsMap, err = ebpf.LoadPinnedMap(paths.RecognitionCommsMapPath, nil)
	if err != nil {
		_ = recognitionControlMap.Close()
		_ = allowedCgroupsMap.Close()
		_ = filterControlMap.Close()
		_ = droppedEventsMap.Close()
		_ = eventsMap.Close()
		_ = exitLink.Close()
		_ = execLink.Close()
		return nil, nil, nil, nil, nil, nil, nil, nil, false
	}
	return execLink, exitLink, eventsMap, droppedEventsMap, filterControlMap, allowedCgroupsMap, recognitionControlMap, recognitionCommsMap, true
}

func normalizePinnedEBPFPaths(paths PinnedEBPFPaths) PinnedEBPFPaths {
	if paths.DroppedEventsMapPath == "" && paths.EventsMapPath != "" {
		paths.DroppedEventsMapPath = filepath.Join(filepath.Dir(paths.EventsMapPath), "process_lifecycle_events_dropped")
	}
	if paths.FilterControlMapPath == "" && paths.EventsMapPath != "" {
		paths.FilterControlMapPath = filepath.Join(filepath.Dir(paths.EventsMapPath), "process_lifecycle_filter_control")
	}
	if paths.AllowedCgroupsMapPath == "" && paths.EventsMapPath != "" {
		paths.AllowedCgroupsMapPath = filepath.Join(filepath.Dir(paths.EventsMapPath), "process_lifecycle_allowed_cgroups")
	}
	if paths.RecognitionControlMapPath == "" && paths.EventsMapPath != "" {
		paths.RecognitionControlMapPath = filepath.Join(filepath.Dir(paths.EventsMapPath), "process_recognition_filter_control")
	}
	if paths.RecognitionCommsMapPath == "" && paths.EventsMapPath != "" {
		paths.RecognitionCommsMapPath = filepath.Join(filepath.Dir(paths.EventsMapPath), "process_recognition_comms")
	}
	return paths
}

func pinProcessExecState(h *ProcessExecEBPFHandles, paths PinnedEBPFPaths) error {
	for _, path := range pinnedProcessExecPaths(paths) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("create pin parent for %q: %w", path, err)
		}
	}
	pins := []struct {
		path string
		pin  func(string) error
	}{
		{paths.ExecLinkPath, h.execTP.Pin},
		{paths.ExitLinkPath, h.exitTP.Pin},
		{paths.EventsMapPath, h.objs.Events.Pin},
		{paths.DroppedEventsMapPath, h.objs.LifecycleEventsDropped.Pin},
		{paths.FilterControlMapPath, h.objs.FilterControl.Pin},
		{paths.AllowedCgroupsMapPath, h.objs.AllowedCgroups.Pin},
		{paths.RecognitionControlMapPath, h.objs.RecognitionControl.Pin},
		{paths.RecognitionCommsMapPath, h.objs.RecognitionComms.Pin},
	}
	for _, item := range pins {
		if err := item.pin(item.path); err != nil {
			cleanupErr := removePinnedProcessExecState(paths)
			return errors.Join(fmt.Errorf("pin process-exec object at %q: %w", item.path, err), cleanupErr)
		}
	}
	return nil
}

func removePinnedProcessExecState(paths PinnedEBPFPaths) error {
	var errs []error
	for _, path := range pinnedProcessExecPaths(paths) {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove pin %q: %w", path, err))
		}
	}
	return errors.Join(errs...)
}

func pinnedProcessExecPaths(paths PinnedEBPFPaths) []string {
	return []string{
		paths.ExecLinkPath,
		paths.ExitLinkPath,
		paths.EventsMapPath,
		paths.DroppedEventsMapPath,
		paths.FilterControlMapPath,
		paths.AllowedCgroupsMapPath,
		paths.RecognitionControlMapPath,
		paths.RecognitionCommsMapPath,
	}
}
