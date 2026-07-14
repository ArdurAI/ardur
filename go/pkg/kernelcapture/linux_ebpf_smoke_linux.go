//go:build linux

package kernelcapture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	linuxEBPFExecTracepoint = "raw/sched_process_exec"
	linuxEBPFExitTracepoint = "sched/sched_process_exit"
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

// LinuxEBPFAgentRecognitionSmokeResult records a script-backed executable
// basename admission and a generic-command hard negative.
type LinuxEBPFAgentRecognitionSmokeResult struct {
	Platform                string
	KernelRelease           string
	BTFAvailable            bool
	AttachedTracepoint      string
	ExecutableBasename      string
	Event                   ProcessEvent
	NegativeCommand         string
	NegativePID             uint32
	NegativeTimedOut        bool
	UnexpectedNegativeEvent bool
}

// LinuxEBPFLauncherIdentitySmokeResult contains only the bounded labels needed
// to prove the launcher identity gate. Temporary paths, argv, environment,
// content, object identifiers, and computed digests are deliberately omitted.
type LinuxEBPFLauncherIdentitySmokeResult struct {
	Platform                 string
	LSMObserverAttached      bool
	PositiveMethod           string
	PositiveOutcome          string
	PositiveObjectState      string
	PositiveMatchedRuleCount int
	SpoofMethod              string
	SpoofOutcome             string
	SpoofObjectState         string
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

	execTP, err := attachProcessExecProgram(objs.HandleSchedProcessExec)
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
	execTP, err := attachProcessExecProgram(objs.HandleSchedProcessExec)
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

	execTP, err := attachProcessExecProgram(objs.HandleSchedProcessExec)
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

// RunLinuxEBPFAgentRecognitionSmoke denies the current cgroup, enables only
// the executable-basename recognition map, and proves that a script named
// codex is admitted while an unrelated executable is not. The temporary full
// path is never copied into the ringbuf event.
func RunLinuxEBPFAgentRecognitionSmoke(ctx context.Context, timeout time.Duration) (*LinuxEBPFAgentRecognitionSmokeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	kernelRelease, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	btfAvailable := fileReadable("/sys/kernel/btf/vmlinux")
	_ = rlimit.RemoveMemlock()

	var objs processExecObjects
	if err := loadProcessExecObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load process-exec eBPF objects: %w", err)
	}
	defer objs.Close()
	handles := &ProcessExecEBPFHandles{objs: objs}
	if err := handles.ConfigureAgentRecognitionNames(nil, []string{"codex"}); err != nil {
		return nil, err
	}
	if err := enableProcessExecCgroupFilter(&objs); err != nil {
		return nil, err
	}
	defer disableProcessExecCgroupFilter(&objs)

	execTP, err := attachProcessExecProgram(objs.HandleSchedProcessExec)
	if err != nil {
		return nil, fmt.Errorf("attach %s raw tracepoint: %w", linuxEBPFExecTracepoint, err)
	}
	defer execTP.Close()
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, fmt.Errorf("open eBPF ringbuf reader: %w", err)
	}
	source := &RingbufProcessSource{reader: &linuxRingbufReader{reader: reader}, closeFn: reader.Close}
	defer source.Close()

	scriptDir, err := os.MkdirTemp("", "ardur-agent-recognition-")
	if err != nil {
		return nil, fmt.Errorf("create agent-recognition smoke directory: %w", err)
	}
	defer os.RemoveAll(scriptDir)
	scriptPath := filepath.Join(scriptDir, "codex")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		return nil, fmt.Errorf("write script-backed agent smoke fixture: %w", err)
	}

	smokeCtx, cancelSmoke := context.WithTimeout(ctx, timeout)
	defer cancelSmoke()
	positive := exec.Command(scriptPath)
	if err := positive.Start(); err != nil {
		return nil, fmt.Errorf("start script-backed agent smoke fixture: %w", err)
	}
	positivePID := uint32(positive.Process.Pid)
	event, ok, readErr := source.Next(smokeCtx, SessionScope{})
	waitErr := positive.Wait()
	if readErr != nil {
		return nil, fmt.Errorf("read script-backed agent-recognition event for pid %d: %w", positivePID, readErr)
	}
	if !ok {
		return nil, fmt.Errorf("script-backed agent-recognition event for pid %d was not emitted", positivePID)
	}
	if waitErr != nil {
		return nil, fmt.Errorf("script-backed agent smoke fixture failed: %w", waitErr)
	}
	if event.Type != ProcessEventExec || event.ExecutableBasename != "codex" {
		return nil, fmt.Errorf("script-backed agent event = type %q basename %q, want exec/codex", event.Type, event.ExecutableBasename)
	}

	negative := exec.Command("/usr/bin/true")
	if err := negative.Start(); err != nil {
		return nil, fmt.Errorf("start agent-recognition hard negative: %w", err)
	}
	negativePID := uint32(negative.Process.Pid)
	negativeCtx, cancelNegative := context.WithTimeout(smokeCtx, 500*time.Millisecond)
	defer cancelNegative()
	unexpectedNegativeEvent := false
	negativeTimedOut := false
	for {
		_, ok, err := source.Next(negativeCtx, SessionScope{})
		if err != nil {
			var nextErr *RingbufNextError
			if errors.As(err, &nextErr) && nextErr.Kind == RingbufErrorDeadlineExceeded {
				negativeTimedOut = true
				break
			}
			_ = negative.Wait()
			return nil, fmt.Errorf("read agent-recognition hard negative for pid %d: %w", negativePID, err)
		}
		if ok {
			unexpectedNegativeEvent = true
			break
		}
	}
	if err := negative.Wait(); err != nil {
		return nil, fmt.Errorf("agent-recognition hard negative failed: %w", err)
	}
	if unexpectedNegativeEvent || !negativeTimedOut {
		return nil, fmt.Errorf("generic executable unexpectedly passed basename recognition (pid=%d event=%t timeout=%t)", negativePID, unexpectedNegativeEvent, negativeTimedOut)
	}

	return &LinuxEBPFAgentRecognitionSmokeResult{
		Platform:                "linux",
		KernelRelease:           strings.TrimSpace(string(kernelRelease)),
		BTFAvailable:            btfAvailable,
		AttachedTracepoint:      linuxEBPFExecTracepoint,
		ExecutableBasename:      "codex",
		Event:                   event,
		NegativeCommand:         "/usr/bin/true",
		NegativePID:             negativePID,
		NegativeTimedOut:        negativeTimedOut,
		UnexpectedNegativeEvent: unexpectedNegativeEvent,
	}, nil
}

// RunLinuxEBPFLauncherIdentitySmoke proves the optional BPF-LSM observation
// and userspace identity gate end to end. A positive script resolves against
// its kernel-observed object. A second process rewrites its mutable cmdline to
// a trusted, digest-matching fixture, but the opened object has a different
// kernel identity and therefore remains a bounded locator_mismatch.
//
// The smoke compiles a disposable interpreter because an ordinary shell does
// not provide a deterministic way to rewrite argv in place. It requires cc in
// addition to the privileges and kernel features required by the other eBPF
// smokes. No generated fixture or raw launch material survives the run.
func RunLinuxEBPFLauncherIdentitySmoke(ctx context.Context, timeout time.Duration) (*LinuxEBPFLauncherIdentitySmokeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	smokeCtx, cancelSmoke := context.WithTimeout(ctx, timeout)
	defer cancelSmoke()

	_ = rlimit.RemoveMemlock()
	handles, err := LoadAndAttachProcessExecEBPF()
	if err != nil {
		return nil, fmt.Errorf("load launcher-identity smoke lifecycle observer: %w", err)
	}
	defer handles.Close()
	if err := handles.ConfigureAgentRecognitionNames(nil, []string{"codex"}); err != nil {
		return nil, fmt.Errorf("configure launcher-identity smoke recognition: %w", err)
	}
	if err := enableProcessExecCgroupFilter(&handles.objs); err != nil {
		return nil, fmt.Errorf("enable launcher-identity smoke cgroup filter: %w", err)
	}
	defer disableProcessExecCgroupFilter(&handles.objs)
	if err := handles.AttachLauncherIdentityObserver(); err != nil {
		return nil, fmt.Errorf("attach launcher-identity smoke BPF-LSM observer: %w", err)
	}
	source := NewRingbufProcessSourceFromRingbufReader(handles.Reader())

	fixtureRoot, err := os.MkdirTemp("", "ardur-launcher-identity-")
	if err != nil {
		return nil, launcherSmokeOperationError("create launcher smoke fixtures", err)
	}
	defer os.RemoveAll(fixtureRoot)
	interpreterPath := filepath.Join(fixtureRoot, "launcher-interpreter")
	if err := compileLauncherSmokeInterpreter(smokeCtx, interpreterPath); err != nil {
		return nil, err
	}
	positiveDir := filepath.Join(fixtureRoot, "p")
	spoofDir := filepath.Join(fixtureRoot, "spoof", "longer")
	if err := os.MkdirAll(positiveDir, 0o700); err != nil {
		return nil, launcherSmokeOperationError("create positive launcher fixture", err)
	}
	if err := os.MkdirAll(spoofDir, 0o700); err != nil {
		return nil, launcherSmokeOperationError("create spoof launcher fixture", err)
	}
	positivePath := filepath.Join(positiveDir, "codex")
	spoofPath := filepath.Join(spoofDir, "codex")
	trustedPath := filepath.Join(fixtureRoot, "trusted")
	scriptContent := []byte("#!" + interpreterPath + "\n")
	for _, path := range []string{positivePath, spoofPath, trustedPath} {
		if err := os.WriteFile(path, scriptContent, 0o700); err != nil {
			return nil, launcherSmokeOperationError("write launcher smoke fixture", err)
		}
	}
	if len(trustedPath) > len(spoofPath) {
		return nil, fmt.Errorf("launcher smoke fixture bounds are invalid")
	}

	contentDigest := sha256.Sum256(scriptContent)
	registry, err := NewAgentFingerprintRegistry(AgentFingerprintRegistryDocument{
		SchemaVersion:   AgentFingerprintRegistrySchema,
		RegistryVersion: "launcher.smoke.v1",
		Rules: []AgentFingerprintRule{{
			RuleID:                     "launcher.codex.smoke",
			AgentType:                  "codex_cli",
			ExpectedLauncherSHA256:     []string{fmt.Sprintf("%x", contentDigest[:])},
			AllowedInterpreterProfiles: []string{filepath.Base(interpreterPath)},
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("build launcher smoke registry: %w", err)
	}
	observations := make(chan AgentFingerprintObservation, 2)
	worker, err := NewAgentFingerprintWorker(registry, AgentFingerprintWorkerOptions{
		QueueCapacity: 2,
		WorkerCount:   1,
		Timeout:       2 * time.Second,
		Observer: func(_ ProcessEvent, _ AgentRecognitionResult, observation AgentFingerprintObservation) {
			observations <- observation
		},
	})
	if err != nil {
		return nil, fmt.Errorf("start launcher smoke fingerprint worker: %w", err)
	}
	defer func() {
		closeCtx, cancelClose := context.WithTimeout(context.Background(), time.Second)
		defer cancelClose()
		_ = worker.Close(closeCtx)
	}()
	worker.SetLauncherIdentityAvailable(true)
	candidate := AgentRecognitionResult{
		Status:            AgentRecognitionStatusRecognized,
		AgentType:         "codex_cli",
		Confidence:        AgentRecognitionConfidenceLow,
		IdentityAssurance: "heuristic_process_metadata",
		GovernanceAction:  "observe_only",
	}

	positive, err := runLinuxLauncherFingerprintSmokeCase(smokeCtx, source, worker, observations, candidate, positivePath, "")
	if err != nil {
		return nil, err
	}
	spoof, err := runLinuxLauncherFingerprintSmokeCase(smokeCtx, source, worker, observations, candidate, spoofPath, trustedPath)
	if err != nil {
		return nil, err
	}

	return &LinuxEBPFLauncherIdentitySmokeResult{
		Platform:                 "linux",
		LSMObserverAttached:      true,
		PositiveMethod:           positive.Method,
		PositiveOutcome:          positive.Outcome,
		PositiveObjectState:      positive.ObjectState,
		PositiveMatchedRuleCount: len(positive.MatchedRuleIDs),
		SpoofMethod:              spoof.Method,
		SpoofOutcome:             spoof.Outcome,
		SpoofObjectState:         spoof.ObjectState,
	}, nil
}

const launcherSmokeInterpreterSource = `
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *spoof = getenv("ARDUR_TEST_SPOOF_LOCATOR");
    if (spoof != NULL && argc > 1) {
        size_t capacity = strlen(argv[1]);
        size_t length = strlen(spoof);
        if (length <= capacity) {
            memset(argv[1], 0, capacity);
            memcpy(argv[1], spoof, length);
        }
    }
    sleep(2);
    return 0;
}
`

const launcherSmokeSpoofLocatorEnv = "ARDUR_TEST_SPOOF_LOCATOR"

func compileLauncherSmokeInterpreter(ctx context.Context, outputPath string) error {
	compiler, err := exec.LookPath("cc")
	if err != nil {
		return fmt.Errorf("launcher smoke compiler unavailable")
	}
	sourcePath := outputPath + ".c"
	if err := os.WriteFile(sourcePath, []byte(launcherSmokeInterpreterSource), 0o600); err != nil {
		return launcherSmokeOperationError("write launcher smoke interpreter source", err)
	}
	command := exec.CommandContext(ctx, compiler, "-O2", "-o", outputPath, sourcePath)
	if err := command.Run(); err != nil {
		return launcherSmokeOperationError("compile launcher smoke interpreter", err)
	}
	return nil
}

func runLinuxLauncherFingerprintSmokeCase(
	ctx context.Context,
	source *RingbufProcessSource,
	worker *AgentFingerprintWorker,
	observations <-chan AgentFingerprintObservation,
	candidate AgentRecognitionResult,
	scriptPath string,
	spoofLocator string,
) (AgentFingerprintObservation, error) {
	command := exec.Command(scriptPath)
	for _, inherited := range os.Environ() {
		if strings.HasPrefix(inherited, launcherSmokeSpoofLocatorEnv+"=") {
			continue
		}
		command.Env = append(command.Env, inherited)
	}
	if spoofLocator != "" {
		command.Env = append(command.Env, launcherSmokeSpoofLocatorEnv+"="+spoofLocator)
	}
	if err := command.Start(); err != nil {
		return AgentFingerprintObservation{}, launcherSmokeOperationError("start launcher smoke process", err)
	}
	waited := false
	defer func() {
		if waited {
			return
		}
		_ = command.Process.Kill()
		_ = command.Wait()
	}()

	event, ok, err := source.Next(ctx, SessionScope{PIDs: map[uint32]struct{}{uint32(command.Process.Pid): {}}})
	if err != nil {
		return AgentFingerprintObservation{}, fmt.Errorf("read launcher smoke event: %w", err)
	}
	if !ok || event.Type != ProcessEventExec || event.ExecutableBasename != "codex" || !event.InterpreterBacked || !event.LauncherScript || !event.LauncherIdentity.Present || event.LauncherInterpreter != "launcher-interpreter" {
		return AgentFingerprintObservation{}, fmt.Errorf("launcher smoke event did not contain the required bounded identity labels")
	}
	if spoofLocator != "" {
		if err := waitForLauncherSmokeRewrite(ctx, uint32(command.Process.Pid), spoofLocator); err != nil {
			return AgentFingerprintObservation{}, err
		}
	}

	immediate := worker.Submit(event, candidate)
	var observation AgentFingerprintObservation
	if immediate != nil {
		observation = *immediate
	} else {
		select {
		case observation = <-observations:
		case <-ctx.Done():
			return AgentFingerprintObservation{}, fmt.Errorf("wait for launcher smoke fingerprint outcome: %w", ctx.Err())
		}
	}
	if err := command.Wait(); err != nil {
		waited = true
		return AgentFingerprintObservation{}, launcherSmokeOperationError("wait for launcher smoke process", err)
	}
	waited = true
	return observation, nil
}

func waitForLauncherSmokeRewrite(ctx context.Context, pid uint32, expectedLocator string) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err == nil && bytes.Contains(raw, []byte(expectedLocator)) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("launcher smoke rewrite readiness was not observed: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func launcherSmokeOperationError(operation string, err error) error {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		err = pathErr.Err
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return fmt.Errorf("%s failed", operation)
	}
	return fmt.Errorf("%s: %w", operation, err)
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

	execTP, err := attachProcessExecProgram(objs.HandleSchedProcessExec)
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
