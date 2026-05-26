//go:build linux

package kernelcapture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	linuxEBPFExecTracepoint     = "sched/sched_process_exec"
	linuxEBPFExitTracepoint     = "sched/sched_process_exit"
	processExecFilterControlKey = uint32(0)
	processExecFilterDisabled   = uint8(0)
	processExecFilterEnabled    = uint8(1)
	processExecAllowedMarker    = uint8(1)
)

// LinuxEBPFExecSmokeOptions configures the narrow Phase 2 eBPF MVP smoke.
type LinuxEBPFExecSmokeOptions struct {
	SessionID string
	Command   string
	Args      []string
	Timeout   time.Duration
}

// LinuxEBPFExecSmokeResult is intentionally small and metadata-only. It is a
// local proof artifact, not a production daemon receipt.
type LinuxEBPFExecSmokeResult struct {
	Platform            string
	KernelRelease       string
	BTFAvailable        bool
	AttachedTracepoint  string
	AttachedTracepoints []string
	Command             []string
	ObservedEvents      int
	Event               ProcessEvent
	Receipt             SyntheticKernelReceipt
	ExecEvent           ProcessEvent
	ExitEvent           ProcessEvent
	Receipts            []SyntheticKernelReceipt
}

// LinuxEBPFSessionSmokeOptions configures a cgroup-guarded process-tree smoke.
type LinuxEBPFSessionSmokeOptions struct {
	SessionID string
	Command   string
	Args      []string
	Timeout   time.Duration
}

// LinuxEBPFSessionSmokeResult proves the local harness can scope a launched
// command session beyond one PID. It remains metadata-only and local-gated.
type LinuxEBPFSessionSmokeResult struct {
	Platform            string
	KernelRelease       string
	BTFAvailable        bool
	AttachedTracepoints []string
	Command             []string
	SessionCgroupID     uint64
	RootPID             uint32
	ObservedEvents      int
	Events              []ProcessEvent
	Receipts            []SyntheticKernelReceipt
	ChildExecPID        uint32
	ChildExitPID        uint32
}

// LinuxEBPFCgroupFilterSmokeOptions configures gated live proof for the
// optional kernel-side cgroup allowlist filter.
type LinuxEBPFCgroupFilterSmokeOptions struct {
	SessionID string
	Command   string
	Args      []string
	Timeout   time.Duration
}

// LinuxEBPFCgroupFilterSmokeResult records the narrow cgroup-map filtering
// evidence from the privileged Linux smoke harness.
type LinuxEBPFCgroupFilterSmokeResult struct {
	Platform             string
	KernelRelease        string
	BTFAvailable         bool
	AttachedTracepoints  []string
	Command              []string
	FilterEnabled        bool
	AllowedCgroupID      uint64
	TestRunnerCgroupID   uint64
	ObservedEvents       int
	ExecEvent            ProcessEvent
	ExitEvent            ProcessEvent
	TargetPID            uint32
	NegativeTargetPID    uint32
	NegativeTimedOut     bool
	UnexpectedTargetSeen bool
}

// RunLinuxEBPFExecSmoke loads the generated process lifecycle eBPF producer,
// attaches exec/exit tracepoints, runs one deterministic command, reads scoped
// ringbuf samples, and projects them through the existing correlation/receipt
// logic.
//
// This function requires a Linux host/container with privileges sufficient to
// load eBPF programs. It does not install a daemon, persist maps, expose a
// service, or collect argv/env/path/network payloads.
func RunLinuxEBPFExecSmoke(ctx context.Context, opts LinuxEBPFExecSmokeOptions) (*LinuxEBPFExecSmokeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.SessionID == "" {
		opts.SessionID = "phase2-ebpf-smoke"
	}
	if opts.Command == "" {
		opts.Command = "/usr/bin/true"
	}

	kernelRelease, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	btfAvailable := fileReadable("/sys/kernel/btf/vmlinux")

	// Best effort only: rootless Podman containers can have enough effective caps to
	// load a small smoke object while still denying rlimit changes. The object uses
	// a deliberately tiny ringbuf for the MVP smoke; if the active limit is still
	// too low, object loading below returns the authoritative failure.
	_ = rlimit.RemoveMemlock()

	var objs processExecObjects
	if err := loadProcessExecObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load process-exec eBPF objects: %w", err)
	}
	defer objs.Close()

	execTP, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleSchedProcessExec, nil)
	if err != nil {
		return nil, fmt.Errorf("attach %s tracepoint: %w", linuxEBPFExecTracepoint, err)
	}
	defer execTP.Close()

	exitTP, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleSchedProcessExit, nil)
	if err != nil {
		return nil, fmt.Errorf("attach %s tracepoint: %w", linuxEBPFExitTracepoint, err)
	}
	defer exitTP.Close()

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, fmt.Errorf("open eBPF ringbuf reader: %w", err)
	}
	source := &RingbufProcessSource{reader: &linuxRingbufReader{reader: reader}, closeFn: reader.Close}
	defer source.Close()

	smokeCtx, cancelSmoke := context.WithTimeout(ctx, opts.Timeout)
	defer cancelSmoke()

	cmd := exec.CommandContext(smokeCtx, opts.Command, opts.Args...)
	spanStart := time.Now().UTC().Add(-250 * time.Millisecond)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start smoke command %q: %w", opts.Command, err)
	}
	targetPID := uint32(cmd.Process.Pid)
	scope := SessionScope{PIDs: map[uint32]struct{}{targetPID: {}}}

	var execEvent ProcessEvent
	var exitEvent ProcessEvent
	haveExec := false
	haveExit := false
	var readErr error

	for !(haveExec && haveExit) {
		evt, ok, err := source.Next(smokeCtx, scope)
		if err != nil {
			readErr = err
			break
		}
		if !ok {
			continue
		}
		normalizeKernelSmokeEvent(&evt, opts.SessionID)

		switch evt.Type {
		case ProcessEventExec:
			if !haveExec {
				execEvent = evt
				haveExec = true
			}
		case ProcessEventExit:
			if !haveExit {
				exitEvent = evt
				haveExit = true
			}
		}
	}

	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, fmt.Errorf("read eBPF ringbuf lifecycle event for pid %d: %w", targetPID, readErr)
	}
	if !haveExec || !haveExit {
		return nil, fmt.Errorf("no scoped eBPF lifecycle exec+exit observed for pid %d (exec=%t exit=%t)", targetPID, haveExec, haveExit)
	}
	if waitErr != nil {
		return nil, fmt.Errorf("smoke command %q failed after event capture: %w", opts.Command, waitErr)
	}

	correlator := NewCorrelator(CorrelatorOptions{
		Platform:       "linux",
		CaptureBackend: "linux_ebpf",
	})
	correlator.RegisterReceipt(ToolReceipt{
		ReceiptID:      fmt.Sprintf("tool:phase2-smoke:%d", execEvent.PID),
		SessionID:      opts.SessionID,
		PID:            execEvent.PID,
		PIDNamespaceID: execEvent.PIDNamespaceID,
		CgroupID:       execEvent.CgroupID,
		SpanStart:      spanStart,
		SpanEnd:        time.Now().UTC().Add(250 * time.Millisecond),
		ObservedAt:     spanStart,
	})
	execReceipt := correlator.Correlate(execEvent, EventContext{})
	exitReceipt := correlator.Correlate(exitEvent, EventContext{})

	command := append([]string{opts.Command}, opts.Args...)
	return &LinuxEBPFExecSmokeResult{
		Platform:            "linux",
		KernelRelease:       strings.TrimSpace(string(kernelRelease)),
		BTFAvailable:        btfAvailable,
		AttachedTracepoint:  linuxEBPFExecTracepoint,
		AttachedTracepoints: []string{linuxEBPFExecTracepoint, linuxEBPFExitTracepoint},
		Command:             command,
		ObservedEvents:      2,
		Event:               execEvent,
		Receipt:             execReceipt,
		ExecEvent:           execEvent,
		ExitEvent:           exitEvent,
		Receipts:            []SyntheticKernelReceipt{execReceipt, exitReceipt},
	}, nil
}

func fileReadable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	return errors.Is(f.Close(), nil)
}

func enableProcessExecCgroupFilter(objs *processExecObjects) error {
	return setProcessExecCgroupFilter(objs, true)
}

func disableProcessExecCgroupFilter(objs *processExecObjects) error {
	return setProcessExecCgroupFilter(objs, false)
}

func setProcessExecCgroupFilter(objs *processExecObjects, enabled bool) error {
	if objs == nil || objs.FilterControl == nil {
		return fmt.Errorf("process-exec filter control map is not loaded")
	}
	value := processExecFilterDisabled
	if enabled {
		value = processExecFilterEnabled
	}
	if err := objs.FilterControl.Update(processExecFilterControlKey, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update process-exec filter control map: %w", err)
	}
	return nil
}

func allowProcessExecCgroup(objs *processExecObjects, cgroupID uint64) error {
	if objs == nil || objs.AllowedCgroups == nil {
		return fmt.Errorf("process-exec cgroup allowlist map is not loaded")
	}
	if cgroupID == 0 {
		return fmt.Errorf("cgroup id must be non-zero")
	}
	if err := objs.AllowedCgroups.Update(cgroupID, processExecAllowedMarker, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update process-exec cgroup allowlist map for cgroup %d: %w", cgroupID, err)
	}
	return nil
}

func disallowProcessExecCgroup(objs *processExecObjects, cgroupID uint64) error {
	if objs == nil || objs.AllowedCgroups == nil {
		return fmt.Errorf("process-exec cgroup allowlist map is not loaded")
	}
	if cgroupID == 0 {
		return nil
	}
	if err := objs.AllowedCgroups.Delete(cgroupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete process-exec cgroup allowlist map entry for cgroup %d: %w", cgroupID, err)
	}
	return nil
}

func currentUnifiedCgroupID() (uint64, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return 0, fmt.Errorf("read /proc/self/cgroup: %w", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] != "0" || parts[1] != "" {
			continue
		}
		rel := strings.TrimPrefix(parts[2], "/")
		cgroupPath := filepath.Join("/sys/fs/cgroup", rel)
		var st syscall.Stat_t
		if err := syscall.Stat(cgroupPath, &st); err != nil {
			return 0, fmt.Errorf("stat unified cgroup path %q: %w", cgroupPath, err)
		}
		if st.Ino == 0 {
			return 0, fmt.Errorf("stat unified cgroup path %q returned inode 0", cgroupPath)
		}
		return st.Ino, nil
	}
	return 0, fmt.Errorf("unified cgroup v2 entry not found in /proc/self/cgroup: %s", strconv.Quote(strings.TrimSpace(string(data))))
}

// RunLinuxEBPFCgroupFilterPositiveSmoke enables the kernel-side filter, adds
// the current test-runner cgroup to the allowlist map, and observes exec+exit
// from one deterministic child command. It does not create per-session cgroups.
func RunLinuxEBPFCgroupFilterPositiveSmoke(ctx context.Context, opts LinuxEBPFCgroupFilterSmokeOptions) (*LinuxEBPFCgroupFilterSmokeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.SessionID == "" {
		opts.SessionID = "phase2-ebpf-cgroup-filter-positive-smoke"
	}
	if opts.Command == "" {
		opts.Command = "/usr/bin/true"
	}

	kernelRelease, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	btfAvailable := fileReadable("/sys/kernel/btf/vmlinux")
	_ = rlimit.RemoveMemlock()

	var objs processExecObjects
	if err := loadProcessExecObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load process-exec eBPF objects: %w", err)
	}
	defer objs.Close()
	testRunnerCgroupID, err := currentUnifiedCgroupID()
	if err != nil {
		return nil, err
	}
	if err := ValidateCgroupFilterSequence(CgroupFilterSequence{Enable: true, AllowlistCgroupIDs: []uint64{testRunnerCgroupID}}); err != nil {
		return nil, err
	}
	if err := allowProcessExecCgroup(&objs, testRunnerCgroupID); err != nil {
		return nil, err
	}
	defer disallowProcessExecCgroup(&objs, testRunnerCgroupID)
	if err := enableProcessExecCgroupFilter(&objs); err != nil {
		return nil, err
	}
	defer disableProcessExecCgroupFilter(&objs)

	execTP, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleSchedProcessExec, nil)
	if err != nil {
		return nil, fmt.Errorf("attach %s tracepoint: %w", linuxEBPFExecTracepoint, err)
	}
	defer execTP.Close()
	exitTP, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleSchedProcessExit, nil)
	if err != nil {
		return nil, fmt.Errorf("attach %s tracepoint: %w", linuxEBPFExitTracepoint, err)
	}
	defer exitTP.Close()

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, fmt.Errorf("open eBPF ringbuf reader: %w", err)
	}
	source := &RingbufProcessSource{reader: &linuxRingbufReader{reader: reader}, closeFn: reader.Close}
	defer source.Close()

	smokeCtx, cancelSmoke := context.WithTimeout(ctx, opts.Timeout)
	defer cancelSmoke()

	cmd := exec.CommandContext(smokeCtx, opts.Command, opts.Args...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start cgroup-filter smoke command %q: %w", opts.Command, err)
	}
	targetPID := uint32(cmd.Process.Pid)
	scope := SessionScope{PIDs: map[uint32]struct{}{targetPID: {}}}

	var execEvent ProcessEvent
	var exitEvent ProcessEvent
	haveExec := false
	haveExit := false
	var readErr error
	for !(haveExec && haveExit) {
		evt, ok, err := source.Next(smokeCtx, scope)
		if err != nil {
			readErr = err
			break
		}
		if !ok {
			continue
		}
		normalizeKernelSmokeEvent(&evt, opts.SessionID)
		switch evt.Type {
		case ProcessEventExec:
			if !haveExec {
				execEvent = evt
				haveExec = true
			}
		case ProcessEventExit:
			if !haveExit {
				exitEvent = evt
				haveExit = true
			}
		}
	}

	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, fmt.Errorf("read kernel-filtered eBPF lifecycle event for pid %d: %w", targetPID, readErr)
	}
	if !haveExec || !haveExit {
		return nil, fmt.Errorf("no kernel-filtered eBPF lifecycle exec+exit observed for pid %d (exec=%t exit=%t)", targetPID, haveExec, haveExit)
	}
	if execEvent.CgroupID != testRunnerCgroupID || exitEvent.CgroupID != testRunnerCgroupID {
		return nil, fmt.Errorf("filtered events came from cgroup exec=%d exit=%d, want allowed cgroup %d", execEvent.CgroupID, exitEvent.CgroupID, testRunnerCgroupID)
	}
	if waitErr != nil {
		return nil, fmt.Errorf("cgroup-filter smoke command %q failed after event capture: %w", opts.Command, waitErr)
	}

	command := append([]string{opts.Command}, opts.Args...)
	return &LinuxEBPFCgroupFilterSmokeResult{
		Platform:            "linux",
		KernelRelease:       strings.TrimSpace(string(kernelRelease)),
		BTFAvailable:        btfAvailable,
		AttachedTracepoints: []string{linuxEBPFExecTracepoint, linuxEBPFExitTracepoint},
		Command:             command,
		FilterEnabled:       true,
		AllowedCgroupID:     testRunnerCgroupID,
		TestRunnerCgroupID:  testRunnerCgroupID,
		ObservedEvents:      2,
		ExecEvent:           execEvent,
		ExitEvent:           exitEvent,
		TargetPID:           targetPID,
	}, nil
}

// RunLinuxEBPFCgroupFilterNegativeSmoke enables the kernel-side filter without
// adding the current cgroup to the allowlist, launches one deterministic child,
// and expects no target PID events before timeout.
func RunLinuxEBPFCgroupFilterNegativeSmoke(ctx context.Context, opts LinuxEBPFCgroupFilterSmokeOptions) (*LinuxEBPFCgroupFilterSmokeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.SessionID == "" {
		opts.SessionID = "phase2-ebpf-cgroup-filter-negative-smoke"
	}
	if opts.Command == "" {
		opts.Command = "/usr/bin/true"
	}

	kernelRelease, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	btfAvailable := fileReadable("/sys/kernel/btf/vmlinux")
	_ = rlimit.RemoveMemlock()

	var objs processExecObjects
	if err := loadProcessExecObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load process-exec eBPF objects: %w", err)
	}
	defer objs.Close()

	testRunnerCgroupID, err := currentUnifiedCgroupID()
	if err != nil {
		return nil, err
	}
	nonMatchingCgroupID := testRunnerCgroupID + 1
	if nonMatchingCgroupID == 0 {
		nonMatchingCgroupID = 1
	}
	if err := ValidateCgroupFilterSequence(CgroupFilterSequence{Enable: true, AllowlistCgroupIDs: []uint64{nonMatchingCgroupID}}); err != nil {
		return nil, err
	}
	if err := allowProcessExecCgroup(&objs, nonMatchingCgroupID); err != nil {
		return nil, err
	}
	defer disallowProcessExecCgroup(&objs, nonMatchingCgroupID)
	if err := disallowProcessExecCgroup(&objs, testRunnerCgroupID); err != nil {
		return nil, err
	}
	if err := enableProcessExecCgroupFilter(&objs); err != nil {
		return nil, err
	}
	defer disableProcessExecCgroupFilter(&objs)

	execTP, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleSchedProcessExec, nil)
	if err != nil {
		return nil, fmt.Errorf("attach %s tracepoint: %w", linuxEBPFExecTracepoint, err)
	}
	defer execTP.Close()
	exitTP, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleSchedProcessExit, nil)
	if err != nil {
		return nil, fmt.Errorf("attach %s tracepoint: %w", linuxEBPFExitTracepoint, err)
	}
	defer exitTP.Close()

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, fmt.Errorf("open eBPF ringbuf reader: %w", err)
	}
	source := &RingbufProcessSource{reader: &linuxRingbufReader{reader: reader}, closeFn: reader.Close}
	defer source.Close()

	smokeCtx, cancelSmoke := context.WithTimeout(ctx, opts.Timeout)
	defer cancelSmoke()

	// Do not bind the child process to smokeCtx here. The negative proof expects
	// ringbuf polling to time out while the deterministic child exits normally;
	// using CommandContext(smokeCtx, ...) would kill or report the child as failed
	// when the polling timeout fires.
	cmd := exec.Command(opts.Command, opts.Args...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start cgroup-filter negative smoke command %q: %w", opts.Command, err)
	}
	targetPID := uint32(cmd.Process.Pid)
	scope := SessionScope{PIDs: map[uint32]struct{}{targetPID: {}}}

	unexpectedSeen := false
	negativeTimedOut := false
	for {
		evt, ok, err := source.Next(smokeCtx, scope)
		if err != nil {
			var nextErr *RingbufNextError
			if errors.As(err, &nextErr) && nextErr.Kind == RingbufErrorDeadlineExceeded {
				negativeTimedOut = true
				break
			}
			_ = cmd.Wait()
			return nil, fmt.Errorf("read negative cgroup-filter eBPF lifecycle event for pid %d: %w", targetPID, err)
		}
		if !ok {
			continue
		}
		normalizeKernelSmokeEvent(&evt, opts.SessionID)
		unexpectedSeen = true
		break
	}

	waitErr := cmd.Wait()
	if waitErr != nil {
		return nil, fmt.Errorf("cgroup-filter negative smoke command %q failed: %w", opts.Command, waitErr)
	}
	if unexpectedSeen {
		return nil, fmt.Errorf("kernel-side cgroup filter emitted target event for pid %d without an allowed cgroup", targetPID)
	}
	if !negativeTimedOut {
		return nil, fmt.Errorf("negative cgroup-filter smoke ended without observing timeout for pid %d", targetPID)
	}

	command := append([]string{opts.Command}, opts.Args...)
	return &LinuxEBPFCgroupFilterSmokeResult{
		Platform:            "linux",
		KernelRelease:       strings.TrimSpace(string(kernelRelease)),
		BTFAvailable:        btfAvailable,
		AttachedTracepoints: []string{linuxEBPFExecTracepoint, linuxEBPFExitTracepoint},
		Command:             command,
		FilterEnabled:       true,
		TestRunnerCgroupID:  testRunnerCgroupID,
		NegativeTargetPID:   targetPID,
		NegativeTimedOut:    negativeTimedOut,
	}, nil
}

// RunLinuxEBPFSessionSmoke attaches the same local eBPF lifecycle producer as
// RunLinuxEBPFExecSmoke, then launches a shell command that spawns a child. The
// harness seeds scope from the root PID, switches to the root cgroup, and uses a
// userspace process-tree tracker to retain only the launched session lineage.
func RunLinuxEBPFSessionSmoke(ctx context.Context, opts LinuxEBPFSessionSmokeOptions) (*LinuxEBPFSessionSmokeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.SessionID == "" {
		opts.SessionID = "phase2-ebpf-session-smoke"
	}
	if opts.Command == "" {
		opts.Command = "/bin/sh"
	}
	if len(opts.Args) == 0 {
		// Two external commands make the session-child requirement explicit even if
		// a shell optimizes its final command with exec.
		opts.Args = []string{"-c", "/usr/bin/true; /usr/bin/true"}
	}

	kernelRelease, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	btfAvailable := fileReadable("/sys/kernel/btf/vmlinux")
	_ = rlimit.RemoveMemlock()

	var objs processExecObjects
	if err := loadProcessExecObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load process-exec eBPF objects: %w", err)
	}
	defer objs.Close()

	execTP, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleSchedProcessExec, nil)
	if err != nil {
		return nil, fmt.Errorf("attach %s tracepoint: %w", linuxEBPFExecTracepoint, err)
	}
	defer execTP.Close()

	exitTP, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleSchedProcessExit, nil)
	if err != nil {
		return nil, fmt.Errorf("attach %s tracepoint: %w", linuxEBPFExitTracepoint, err)
	}
	defer exitTP.Close()

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, fmt.Errorf("open eBPF ringbuf reader: %w", err)
	}
	source := &RingbufProcessSource{reader: &linuxRingbufReader{reader: reader}, closeFn: reader.Close}
	defer source.Close()

	smokeCtx, cancelSmoke := context.WithTimeout(ctx, opts.Timeout)
	defer cancelSmoke()

	cmd := exec.CommandContext(smokeCtx, opts.Command, opts.Args...)
	spanStart := time.Now().UTC().Add(-250 * time.Millisecond)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start session smoke command %q: %w", opts.Command, err)
	}
	rootPID := uint32(cmd.Process.Pid)

	rootExec, err := readRootExecEvent(smokeCtx, source, opts.SessionID, rootPID)
	if err != nil {
		_ = cmd.Wait()
		return nil, err
	}

	treeScope := NewProcessTreeScope(rootPID, rootExec.CgroupID)
	treeScope.SessionID = opts.SessionID
	_ = treeScope.MatchesAndTrack(rootExec)
	events := []ProcessEvent{rootExec}
	childExec := make(map[uint32]struct{})
	childExit := make(map[uint32]struct{})
	var completedChildPID uint32
	haveRootExit := false
	haveChildLifecycle := false
	readErr := error(nil)

	for !(haveRootExit && haveChildLifecycle) {
		evt, ok, err := source.Next(smokeCtx, SessionScope{CgroupID: rootExec.CgroupID})
		if err != nil {
			readErr = err
			break
		}
		if !ok {
			continue
		}
		normalizeKernelSmokeEvent(&evt, opts.SessionID)
		if !treeScope.MatchesAndTrack(evt) {
			continue
		}
		events = append(events, evt)
		if evt.PID == rootPID && evt.Type == ProcessEventExit {
			haveRootExit = true
		}
		if evt.PID != rootPID {
			switch evt.Type {
			case ProcessEventExec:
				childExec[evt.PID] = struct{}{}
			case ProcessEventExit:
				childExit[evt.PID] = struct{}{}
			}
			if completedChildPID == 0 {
				if _, ok := childExec[evt.PID]; ok {
					if _, ok := childExit[evt.PID]; ok {
						completedChildPID = evt.PID
						haveChildLifecycle = true
					}
				}
			}
		}
	}

	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, fmt.Errorf("read cgroup-scoped eBPF process-tree lifecycle events for root pid %d: %w", rootPID, readErr)
	}
	if !haveRootExit || !haveChildLifecycle {
		return nil, fmt.Errorf("incomplete scoped eBPF session lifecycle for root pid %d (root_exit=%t child_lifecycle=%t events=%d)", rootPID, haveRootExit, haveChildLifecycle, len(events))
	}
	if waitErr != nil {
		return nil, fmt.Errorf("session smoke command %q failed after event capture: %w", opts.Command, waitErr)
	}

	correlator := NewCorrelator(CorrelatorOptions{Platform: "linux", CaptureBackend: "linux_ebpf"})
	correlator.RegisterReceipt(ToolReceipt{
		ReceiptID:      fmt.Sprintf("tool:phase2-session:%d", rootPID),
		SessionID:      opts.SessionID,
		PID:            rootExec.PID,
		PIDNamespaceID: rootExec.PIDNamespaceID,
		CgroupID:       rootExec.CgroupID,
		SpanStart:      spanStart,
		SpanEnd:        time.Now().UTC().Add(250 * time.Millisecond),
		ObservedAt:     spanStart,
	})
	receipts := make([]SyntheticKernelReceipt, 0, len(events))
	for _, evt := range events {
		receipts = append(receipts, correlator.Correlate(evt, EventContext{}))
	}

	command := append([]string{opts.Command}, opts.Args...)
	return &LinuxEBPFSessionSmokeResult{
		Platform:            "linux",
		KernelRelease:       strings.TrimSpace(string(kernelRelease)),
		BTFAvailable:        btfAvailable,
		AttachedTracepoints: []string{linuxEBPFExecTracepoint, linuxEBPFExitTracepoint},
		Command:             command,
		SessionCgroupID:     rootExec.CgroupID,
		RootPID:             rootPID,
		ObservedEvents:      len(events),
		Events:              events,
		Receipts:            receipts,
		ChildExecPID:        completedChildPID,
		ChildExitPID:        completedChildPID,
	}, nil
}

func readRootExecEvent(ctx context.Context, source *RingbufProcessSource, sessionID string, rootPID uint32) (ProcessEvent, error) {
	for {
		evt, ok, err := source.Next(ctx, SessionScope{PIDs: map[uint32]struct{}{rootPID: {}}})
		if err != nil {
			return ProcessEvent{}, fmt.Errorf("read root eBPF exec event for pid %d: %w", rootPID, err)
		}
		if !ok {
			continue
		}
		if evt.Type != ProcessEventExec {
			continue
		}
		normalizeKernelSmokeEvent(&evt, sessionID)
		return evt, nil
	}
}

func normalizeKernelSmokeEvent(evt *ProcessEvent, sessionID string) {
	evt.SessionID = sessionID
	evt.ObservedAt = time.Now().UTC()
	evt.EventID = fmt.Sprintf("kernel-%s:%d:%d", evt.Type, evt.PID, evt.ObservedMonotonicNS)
}
