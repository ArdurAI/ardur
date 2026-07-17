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
	filterControlMap                  *ebpf.Map
	allowedCgroupsMap                 *ebpf.Map
	recognitionControlMap             *ebpf.Map
	recognitionCommsMap               *ebpf.Map
	recognitionExecutableBasenamesMap *ebpf.Map
	launcherExecStateMap              *ebpf.Map
	launcherIdentity                  *launcherIdentityObserver
	pinningErr                        error
	reader                            *ringbuf.Reader
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
	if h.launcherIdentity != nil {
		h.launcherIdentity.Close()
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
	if h.recognitionExecutableBasenamesMap != nil {
		_ = h.recognitionExecutableBasenamesMap.Close()
	}
	if h.launcherExecStateMap != nil {
		_ = h.launcherExecStateMap.Close()
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
// program, attaches raw sched_process_exec and sched/sched_process_exit, and
// returns a handle that owns the ringbuf reader.
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
	h.execTP, err = attachProcessExecProgram(h.objs.HandleSchedProcessExec)
	if err != nil {
		h.objs.Close()
		return nil, fmt.Errorf("attach raw sched_process_exec: %w", err)
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

func attachProcessExecProgram(program *ebpf.Program) (link.Link, error) {
	return link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exec",
		Program: program,
	})
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
	// RecognitionControlMapPath enables exact-name candidate prefiltering.
	RecognitionControlMapPath string
	// RecognitionCommsMapPath stores release-bound exact Linux comm keys.
	RecognitionCommsMapPath string
	// RecognitionExecutableBasenamesMapPath stores bounded successful-exec
	// filename basenames without retaining their parent paths.
	RecognitionExecutableBasenamesMapPath string
	// LauncherExecStateMapPath stores bounded, non-path original-object
	// identities between the optional BPF-LSM hook and successful exec.
	LauncherExecStateMapPath string
}

// DefaultPinnedEBPFPaths returns the standard bpffs pin paths under the
// ardur-owned bpffs namespace (/sys/fs/bpf/ardur/). The ringbuf and lifecycle
// drop-counter paths match the map paths recorded by BuildDaemonCustodyPlan.
func DefaultPinnedEBPFPaths() PinnedEBPFPaths {
	return PinnedEBPFPaths{
		ExecLinkPath:                          "/sys/fs/bpf/ardur/exec_tp_link",
		ExitLinkPath:                          "/sys/fs/bpf/ardur/exit_tp_link",
		EventsMapPath:                         "/sys/fs/bpf/ardur/process_lifecycle_events",
		DroppedEventsMapPath:                  "/sys/fs/bpf/ardur/process_lifecycle_events_dropped",
		FilterControlMapPath:                  "/sys/fs/bpf/ardur/process_lifecycle_filter_control",
		AllowedCgroupsMapPath:                 "/sys/fs/bpf/ardur/process_lifecycle_allowed_cgroups",
		RecognitionControlMapPath:             "/sys/fs/bpf/ardur/process_recognition_filter_control",
		RecognitionCommsMapPath:               "/sys/fs/bpf/ardur/process_recognition_comms",
		RecognitionExecutableBasenamesMapPath: "/sys/fs/bpf/ardur/process_recognition_executable_basenames",
		LauncherExecStateMapPath:              "/sys/fs/bpf/ardur/process_launcher_exec_state",
	}
}

// LoadAndAttachProcessExecEBPFPinned is like LoadAndAttachProcessExecEBPF but
// adds BPF link- and map-pinning for restart survival.
//
// On first start (no pinned state at paths): loads and attaches the eBPF
// program as usual, then pins both tracepoint links, the ringbuf map, the
// monotonic producer-drop counter, and all producer-filter maps to bpffs. The
// pins keep the links — and thus the attached programs — alive in the kernel
// even after the daemon exits, and keep their complete map generation reachable
// across daemon lifetimes.
//
// On restart (both pinned links and all eight pinned maps exist at paths):
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
	if pinned, ok := tryLoadPinnedState(paths); ok {
		// The links are alive — the eBPF programs are still attached in the
		// kernel and writing into eventsMap. Open a reader bound to that
		// same map so restart doesn't lose the events the programs emit.
		reader, err := ringbuf.NewReader(pinned.eventsMap)
		if err != nil {
			pinned.Close()
			return nil, fmt.Errorf("open ringbuf reader (pinned restart): %w", err)
		}
		return &ProcessExecEBPFHandles{
			execTP:                            pinned.execLink,
			exitTP:                            pinned.exitLink,
			eventsMap:                         pinned.eventsMap,
			droppedEventsMap:                  pinned.droppedEventsMap,
			filterControlMap:                  pinned.filterControlMap,
			allowedCgroupsMap:                 pinned.allowedCgroupsMap,
			recognitionControlMap:             pinned.recognitionControlMap,
			recognitionCommsMap:               pinned.recognitionCommsMap,
			recognitionExecutableBasenamesMap: pinned.recognitionExecutableBasenamesMap,
			launcherExecStateMap:              pinned.launcherExecStateMap,
			reader:                            reader,
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

// tryLoadPinnedState attempts to load both tracepoint links and all eight maps
// from bpffs. An older nine-pin generation is intentionally incomplete and is
// replaced before a fresh attach.
type pinnedProcessExecState struct {
	execLink                          link.Link
	exitLink                          link.Link
	eventsMap                         *ebpf.Map
	droppedEventsMap                  *ebpf.Map
	filterControlMap                  *ebpf.Map
	allowedCgroupsMap                 *ebpf.Map
	recognitionControlMap             *ebpf.Map
	recognitionCommsMap               *ebpf.Map
	recognitionExecutableBasenamesMap *ebpf.Map
	launcherExecStateMap              *ebpf.Map
}

func (s *pinnedProcessExecState) Close() {
	if s == nil {
		return
	}
	for _, m := range []*ebpf.Map{s.launcherExecStateMap, s.recognitionExecutableBasenamesMap, s.recognitionCommsMap, s.recognitionControlMap, s.allowedCgroupsMap, s.filterControlMap, s.droppedEventsMap, s.eventsMap} {
		if m != nil {
			_ = m.Close()
		}
	}
	if s.exitLink != nil {
		_ = s.exitLink.Close()
	}
	if s.execLink != nil {
		_ = s.execLink.Close()
	}
}

func tryLoadPinnedState(paths PinnedEBPFPaths) (*pinnedProcessExecState, bool) {
	s := &pinnedProcessExecState{}
	var err error
	fail := func() (*pinnedProcessExecState, bool) {
		s.Close()
		return nil, false
	}
	if s.execLink, err = link.LoadPinnedLink(paths.ExecLinkPath, nil); err != nil {
		return fail()
	}
	if s.exitLink, err = link.LoadPinnedLink(paths.ExitLinkPath, nil); err != nil {
		return fail()
	}
	loads := []struct {
		path string
		dst  **ebpf.Map
	}{
		{paths.EventsMapPath, &s.eventsMap},
		{paths.DroppedEventsMapPath, &s.droppedEventsMap},
		{paths.FilterControlMapPath, &s.filterControlMap},
		{paths.AllowedCgroupsMapPath, &s.allowedCgroupsMap},
		{paths.RecognitionControlMapPath, &s.recognitionControlMap},
		{paths.RecognitionCommsMapPath, &s.recognitionCommsMap},
		{paths.RecognitionExecutableBasenamesMapPath, &s.recognitionExecutableBasenamesMap},
		{paths.LauncherExecStateMapPath, &s.launcherExecStateMap},
	}
	for _, item := range loads {
		if *item.dst, err = ebpf.LoadPinnedMap(item.path, nil); err != nil {
			return fail()
		}
	}
	return s, true
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
	if paths.RecognitionExecutableBasenamesMapPath == "" && paths.EventsMapPath != "" {
		paths.RecognitionExecutableBasenamesMapPath = filepath.Join(filepath.Dir(paths.EventsMapPath), "process_recognition_executable_basenames")
	}
	if paths.LauncherExecStateMapPath == "" && paths.EventsMapPath != "" {
		paths.LauncherExecStateMapPath = filepath.Join(filepath.Dir(paths.EventsMapPath), "process_launcher_exec_state")
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
		{paths.RecognitionExecutableBasenamesMapPath, h.objs.RecognitionExecutableBasenames.Pin},
		{paths.LauncherExecStateMapPath, h.objs.LauncherExecState.Pin},
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
		paths.RecognitionExecutableBasenamesMapPath,
		paths.LauncherExecStateMapPath,
	}
}
