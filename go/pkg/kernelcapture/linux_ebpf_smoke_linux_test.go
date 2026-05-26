//go:build linux

package kernelcapture

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLinuxEBPFExecSmoke(t *testing.T) {
	if os.Getenv("ARDUR_RUN_EBPF_SMOKE") != "1" {
		t.Skip("set ARDUR_RUN_EBPF_SMOKE=1 to run privileged Linux eBPF smoke")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := RunLinuxEBPFExecSmoke(ctx, LinuxEBPFExecSmokeOptions{
		SessionID: "phase2-ebpf-smoke-test",
		Command:   "/usr/bin/true",
		Timeout:   10 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunLinuxEBPFExecSmoke failed: %v", err)
	}
	if result.Platform != "linux" {
		t.Fatalf("platform = %q, want linux", result.Platform)
	}
	if result.AttachedTracepoint != linuxEBPFExecTracepoint {
		t.Fatalf("tracepoint = %q, want %q", result.AttachedTracepoint, linuxEBPFExecTracepoint)
	}
	if len(result.AttachedTracepoints) != 2 {
		t.Fatalf("attached tracepoints = %v, want exec+exit", result.AttachedTracepoints)
	}
	if result.AttachedTracepoints[0] != linuxEBPFExecTracepoint || result.AttachedTracepoints[1] != linuxEBPFExitTracepoint {
		t.Fatalf("attached tracepoints = %v, want [%q %q]", result.AttachedTracepoints, linuxEBPFExecTracepoint, linuxEBPFExitTracepoint)
	}
	if !result.BTFAvailable {
		t.Fatal("expected /sys/kernel/btf/vmlinux to be readable")
	}
	if result.ObservedEvents < 2 {
		t.Fatalf("observed events = %d, want >= 2", result.ObservedEvents)
	}
	if result.Event.Type != ProcessEventExec {
		t.Fatalf("event type = %q, want exec", result.Event.Type)
	}
	if result.Event.PID == 0 || result.Event.CgroupID == 0 || result.Event.ObservedMonotonicNS == 0 {
		t.Fatalf("incomplete event metadata: pid=%d cgroup=%d monotonic=%d", result.Event.PID, result.Event.CgroupID, result.Event.ObservedMonotonicNS)
	}
	if result.ExecEvent.Type != ProcessEventExec {
		t.Fatalf("exec event type = %q, want exec", result.ExecEvent.Type)
	}
	if result.ExitEvent.Type != ProcessEventExit {
		t.Fatalf("exit event type = %q, want exit", result.ExitEvent.Type)
	}
	if result.ExecEvent.PID == 0 || result.ExecEvent.CgroupID == 0 || result.ExecEvent.ObservedMonotonicNS == 0 {
		t.Fatalf("incomplete exec event metadata: pid=%d cgroup=%d monotonic=%d", result.ExecEvent.PID, result.ExecEvent.CgroupID, result.ExecEvent.ObservedMonotonicNS)
	}
	if result.ExitEvent.PID == 0 || result.ExitEvent.CgroupID == 0 || result.ExitEvent.ObservedMonotonicNS == 0 {
		t.Fatalf("incomplete exit event metadata: pid=%d cgroup=%d monotonic=%d", result.ExitEvent.PID, result.ExitEvent.CgroupID, result.ExitEvent.ObservedMonotonicNS)
	}
	if result.ExecEvent.PID != result.ExitEvent.PID {
		t.Fatalf("expected same process pid for exec/exit, got exec=%d exit=%d", result.ExecEvent.PID, result.ExitEvent.PID)
	}
	if result.ExitEvent.ExitCode != 0 {
		t.Fatalf("exit_code = %d, want 0 for /usr/bin/true", result.ExitEvent.ExitCode)
	}
	if result.Receipt.KernelEventType != "execve" {
		t.Fatalf("kernel event type = %q, want execve", result.Receipt.KernelEventType)
	}
	if result.Receipt.CorrelationConfidence != "high" {
		t.Fatalf("correlation confidence = %q, want high; receipt=%+v event=%+v", result.Receipt.CorrelationConfidence, result.Receipt, result.Event)
	}
	if result.Receipt.Verdict != "compliant" {
		t.Fatalf("verdict = %q, want compliant; receipt=%+v", result.Receipt.Verdict, result.Receipt)
	}
	if len(result.Receipts) != 2 {
		t.Fatalf("receipts len = %d, want 2", len(result.Receipts))
	}
	if result.Receipts[0].KernelEventType != "execve" || result.Receipts[1].KernelEventType != "exit" {
		t.Fatalf("kernel event types = [%q %q], want [execve exit]", result.Receipts[0].KernelEventType, result.Receipts[1].KernelEventType)
	}
	if result.Receipts[0].CorrelationConfidence != "high" || result.Receipts[1].CorrelationConfidence != "high" {
		t.Fatalf("unexpected correlation confidence values: [%q %q]", result.Receipts[0].CorrelationConfidence, result.Receipts[1].CorrelationConfidence)
	}
	if result.Receipts[0].Verdict != "compliant" || result.Receipts[1].Verdict != "compliant" {
		t.Fatalf("unexpected verdict values: [%q %q]", result.Receipts[0].Verdict, result.Receipts[1].Verdict)
	}

	t.Logf("kernel=%s btf=%t tracepoints=%v command=%v observed_events=%d exec_pid=%d exec_ppid=%d exec_tid=%d exec_pid_ns=%d exec_cgroup=%d exec_comm=%q exit_pid=%d exit_ppid=%d exit_tid=%d exit_pid_ns=%d exit_cgroup=%d exit_comm=%q exit_code=%d exec_coverage=%s exec_correlation=%s/%s exec_verdict=%s exit_coverage=%s exit_correlation=%s/%s exit_verdict=%s",
		result.KernelRelease,
		result.BTFAvailable,
		result.AttachedTracepoints,
		result.Command,
		result.ObservedEvents,
		result.ExecEvent.PID,
		result.ExecEvent.PPID,
		result.ExecEvent.TID,
		result.ExecEvent.PIDNamespaceID,
		result.ExecEvent.CgroupID,
		result.ExecEvent.Comm,
		result.ExitEvent.PID,
		result.ExitEvent.PPID,
		result.ExitEvent.TID,
		result.ExitEvent.PIDNamespaceID,
		result.ExitEvent.CgroupID,
		result.ExitEvent.Comm,
		result.ExitEvent.ExitCode,
		result.Receipts[0].CoverageStatus,
		result.Receipts[0].CorrelationMethod,
		result.Receipts[0].CorrelationConfidence,
		result.Receipts[0].Verdict,
		result.Receipts[1].CoverageStatus,
		result.Receipts[1].CorrelationMethod,
		result.Receipts[1].CorrelationConfidence,
		result.Receipts[1].Verdict,
	)
}

func TestLinuxEBPFSessionSmoke(t *testing.T) {
	if os.Getenv("ARDUR_RUN_EBPF_SMOKE") != "1" {
		t.Skip("set ARDUR_RUN_EBPF_SMOKE=1 to run privileged Linux eBPF session smoke")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	result, err := RunLinuxEBPFSessionSmoke(ctx, LinuxEBPFSessionSmokeOptions{
		SessionID: "phase2-ebpf-session-smoke-test",
		Command:   "/bin/sh",
		Args:      []string{"-c", "/usr/bin/true; /usr/bin/true"},
		Timeout:   10 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunLinuxEBPFSessionSmoke failed: %v", err)
	}
	if result.Platform != "linux" {
		t.Fatalf("platform = %q, want linux", result.Platform)
	}
	if !result.BTFAvailable {
		t.Fatal("expected /sys/kernel/btf/vmlinux to be readable")
	}
	if result.RootPID == 0 || result.SessionCgroupID == 0 {
		t.Fatalf("incomplete session metadata: root_pid=%d cgroup=%d", result.RootPID, result.SessionCgroupID)
	}
	if result.ObservedEvents < 4 {
		t.Fatalf("observed events = %d, want at least root exec/exit and child exec/exit", result.ObservedEvents)
	}
	if result.ChildExecPID == 0 || result.ChildExitPID == 0 || result.ChildExecPID != result.ChildExitPID {
		t.Fatalf("expected same child exec/exit pid, got exec=%d exit=%d", result.ChildExecPID, result.ChildExitPID)
	}
	if len(result.Events) != len(result.Receipts) {
		t.Fatalf("events len %d != receipts len %d", len(result.Events), len(result.Receipts))
	}
	childExecSeen := false
	childExitSeen := false
	rootExitSeen := false
	mediumCgroupCorrelationSeen := false
	for i, evt := range result.Events {
		if evt.SessionID != "phase2-ebpf-session-smoke-test" {
			t.Fatalf("event %d session_id = %q", i, evt.SessionID)
		}
		if evt.CgroupID != result.SessionCgroupID {
			t.Fatalf("event %d cgroup = %d, want %d", i, evt.CgroupID, result.SessionCgroupID)
		}
		if evt.PID == result.RootPID && evt.Type == ProcessEventExit {
			rootExitSeen = true
		}
		if evt.PID == result.ChildExecPID && evt.Type == ProcessEventExec {
			childExecSeen = true
		}
		if evt.PID == result.ChildExecPID && evt.Type == ProcessEventExit {
			childExitSeen = true
		}
		receipt := result.Receipts[i]
		if receipt.Verdict != "compliant" {
			t.Fatalf("receipt %d verdict=%q coverage=%q method=%q confidence=%q", i, receipt.Verdict, receipt.CoverageStatus, receipt.CorrelationMethod, receipt.CorrelationConfidence)
		}
		if evt.PID != result.RootPID && receipt.CorrelationMethod == "cgroup_time_window" && receipt.CorrelationConfidence == "medium" {
			mediumCgroupCorrelationSeen = true
		}
	}
	if !rootExitSeen || !childExecSeen || !childExitSeen {
		t.Fatalf("missing lifecycle events: root_exit=%t child_exec=%t child_exit=%t events=%+v", rootExitSeen, childExecSeen, childExitSeen, result.Events)
	}
	if !mediumCgroupCorrelationSeen {
		t.Fatalf("expected at least one child event correlated by cgroup_time_window/medium, receipts=%+v", result.Receipts)
	}

	t.Logf("kernel=%s btf=%t tracepoints=%v command=%v root_pid=%d cgroup=%d observed_events=%d child_pid=%d child_exit_pid=%d",
		result.KernelRelease,
		result.BTFAvailable,
		result.AttachedTracepoints,
		result.Command,
		result.RootPID,
		result.SessionCgroupID,
		result.ObservedEvents,
		result.ChildExecPID,
		result.ChildExitPID,
	)
}

func TestLinuxEBPFCgroupFilterPositiveSmoke(t *testing.T) {
	if os.Getenv("ARDUR_RUN_EBPF_SMOKE") != "1" {
		t.Skip("set ARDUR_RUN_EBPF_SMOKE=1 to run privileged Linux eBPF cgroup-filter smoke")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := RunLinuxEBPFCgroupFilterPositiveSmoke(ctx, LinuxEBPFCgroupFilterSmokeOptions{
		SessionID: "phase2-ebpf-cgroup-filter-positive-smoke-test",
		Command:   "/usr/bin/true",
		Timeout:   10 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunLinuxEBPFCgroupFilterPositiveSmoke failed: %v", err)
	}
	if result.Platform != "linux" {
		t.Fatalf("platform = %q, want linux", result.Platform)
	}
	if !result.FilterEnabled {
		t.Fatal("filter_enabled = false, want true")
	}
	if result.TestRunnerCgroupID == 0 || result.AllowedCgroupID != result.TestRunnerCgroupID {
		t.Fatalf("unexpected cgroup metadata: test_runner=%d allowed=%d", result.TestRunnerCgroupID, result.AllowedCgroupID)
	}
	if result.TargetPID == 0 {
		t.Fatal("target pid is zero")
	}
	if result.ExecEvent.Type != ProcessEventExec || result.ExitEvent.Type != ProcessEventExit {
		t.Fatalf("event types = [%q %q], want [exec exit]", result.ExecEvent.Type, result.ExitEvent.Type)
	}
	if result.ExecEvent.PID != result.TargetPID || result.ExitEvent.PID != result.TargetPID {
		t.Fatalf("event pids = [%d %d], want target pid %d", result.ExecEvent.PID, result.ExitEvent.PID, result.TargetPID)
	}
	if result.ExecEvent.CgroupID != result.AllowedCgroupID || result.ExitEvent.CgroupID != result.AllowedCgroupID {
		t.Fatalf("event cgroups = [%d %d], want allowed cgroup %d", result.ExecEvent.CgroupID, result.ExitEvent.CgroupID, result.AllowedCgroupID)
	}
	if result.ObservedEvents < 2 {
		t.Fatalf("observed events = %d, want >= 2", result.ObservedEvents)
	}

	t.Logf("kernel=%s btf=%t tracepoints=%v command=%v filter_enabled=%t allowed_cgroup=%d target_pid=%d exec_cgroup=%d exit_cgroup=%d",
		result.KernelRelease,
		result.BTFAvailable,
		result.AttachedTracepoints,
		result.Command,
		result.FilterEnabled,
		result.AllowedCgroupID,
		result.TargetPID,
		result.ExecEvent.CgroupID,
		result.ExitEvent.CgroupID,
	)
}

func TestLinuxEBPFCgroupFilterNegativeSmoke(t *testing.T) {
	if os.Getenv("ARDUR_RUN_EBPF_SMOKE") != "1" {
		t.Skip("set ARDUR_RUN_EBPF_SMOKE=1 to run privileged Linux eBPF cgroup-filter smoke")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := RunLinuxEBPFCgroupFilterNegativeSmoke(ctx, LinuxEBPFCgroupFilterSmokeOptions{
		SessionID: "phase2-ebpf-cgroup-filter-negative-smoke-test",
		Command:   "/usr/bin/true",
		Timeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunLinuxEBPFCgroupFilterNegativeSmoke failed: %v", err)
	}
	if result.Platform != "linux" {
		t.Fatalf("platform = %q, want linux", result.Platform)
	}
	if !result.FilterEnabled {
		t.Fatal("filter_enabled = false, want true")
	}
	if result.TestRunnerCgroupID == 0 || result.NegativeTargetPID == 0 {
		t.Fatalf("incomplete negative metadata: cgroup=%d pid=%d", result.TestRunnerCgroupID, result.NegativeTargetPID)
	}
	if !result.NegativeTimedOut {
		t.Fatal("negative smoke did not time out waiting for blocked target events")
	}
	if result.UnexpectedTargetSeen {
		t.Fatal("negative smoke observed a target event despite no matching allowed cgroup")
	}

	t.Logf("kernel=%s btf=%t tracepoints=%v command=%v filter_enabled=%t blocked_cgroup=%d target_pid=%d negative_timed_out=%t",
		result.KernelRelease,
		result.BTFAvailable,
		result.AttachedTracepoints,
		result.Command,
		result.FilterEnabled,
		result.TestRunnerCgroupID,
		result.NegativeTargetPID,
		result.NegativeTimedOut,
	)
}
