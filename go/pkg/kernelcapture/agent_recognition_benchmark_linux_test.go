//go:build linux

package kernelcapture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestParseSchedstatRuntimeNanoseconds(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		raw     string
		want    uint64
		wantErr bool
	}{
		{name: "runtime with wait and slices", raw: "12345 678 9\n", want: 12345},
		{name: "runtime only", raw: "42", want: 42},
		{name: "empty", wantErr: true},
		{name: "negative", raw: "-1 2 3", wantErr: true},
		{name: "non numeric", raw: "runtime 2 3", wantErr: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseSchedstatRuntimeNanoseconds([]byte(test.raw))
			if (err != nil) != test.wantErr {
				t.Fatalf("parseSchedstatRuntimeNanoseconds() error = %v, wantErr %v", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("parseSchedstatRuntimeNanoseconds() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestCountAgentRecognitionBenchmarkFingerprintLogs(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "daemon.jsonl")
	raw := []byte("{\"msg\":\"startup\"}\n{\"msg\":\"AI agent executable fingerprint observed\"}\n{\"msg\":\"AI agent executable fingerprint observed\"}\n{\"msg\":")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	observed, complete, err := countAgentRecognitionBenchmarkFingerprintLogs(file)
	if err != nil {
		t.Fatal(err)
	}
	if observed != 2 || complete {
		t.Fatalf("fingerprint log count = %d, complete = %v; want 2, false", observed, complete)
	}

	if err := os.WriteFile(path, append(raw, []byte("invalid}\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := countAgentRecognitionBenchmarkFingerprintLogs(file); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("malformed complete log error = %v", err)
	}
	if err := file.Truncate(agentRecognitionBenchmarkMaxDaemonLogBytes + 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := countAgentRecognitionBenchmarkFingerprintLogs(file); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("oversized log error = %v", err)
	}
}

func TestWaitForAgentRecognitionBenchmarkFingerprintLogsFailsClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "daemon.jsonl")
	if err := os.WriteFile(path, []byte("{\"msg\":\"AI agent executable fingerprint observed\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	daemon := &agentRecognitionBenchmarkDaemon{logFile: file}
	if err := daemon.waitForFingerprintObservationLogs(context.Background(), 0, time.Second); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("extra observation error = %v", err)
	}
	if err := daemon.waitForFingerprintObservationLogs(context.Background(), 2, time.Millisecond); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("missing observation timeout error = %v", err)
	}
	partial := []byte("{\"msg\":\"AI agent executable fingerprint observed\"}\n{\"msg\":")
	if err := os.WriteFile(path, partial, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := daemon.waitForFingerprintObservationLogs(context.Background(), 1, time.Millisecond); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("incomplete trailing observation timeout error = %v", err)
	}
	complete := []byte("{\"msg\":\"AI agent executable fingerprint observed\"}\n{\"msg\":\"AI agent executable fingerprint observed\"}\n")
	if err := os.WriteFile(path, complete, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := daemon.waitForFingerprintObservationLogs(context.Background(), 2, time.Second); err != nil {
		t.Fatalf("complete observation barrier error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := daemon.waitForFingerprintObservationLogs(ctx, 2, time.Second); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("canceled observation barrier error = %v", err)
	}
}

func TestAgentRecognitionBenchmarkAccountingSettled(t *testing.T) {
	t.Parallel()
	before := agentRecognitionBenchmarkSnapshot{
		capture:     DaemonLifecycleCaptureHealth{ProducerCounterAvailable: true},
		recognition: AgentRecognitionHealth{Enabled: true},
		fingerprint: AgentFingerprintHealth{Enabled: true},
	}
	after := before
	after.capture.DeliveredTotal = 1
	after.recognition.Counters = AgentRecognitionCounters{CandidatesTotal: 1, Recognized: 1}
	after.fingerprint.Counters.Success = 1
	settled, err := agentRecognitionBenchmarkAccountingSettled(true, before, after, 1)
	if err != nil || !settled {
		t.Fatalf("complete accounting settled = %v, error = %v", settled, err)
	}

	after.fingerprint.QueueDepth = 1
	settled, err = agentRecognitionBenchmarkAccountingSettled(true, before, after, 1)
	if err != nil || settled {
		t.Fatalf("queued accounting settled = %v, error = %v", settled, err)
	}

	after.fingerprint.QueueDepth = 0
	after.fingerprint.Counters.WorkerUnavailable = 1
	if _, err := agentRecognitionBenchmarkAccountingSettled(true, before, after, 1); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("post-terminal worker failure error = %v", err)
	}

	baselineBefore := agentRecognitionBenchmarkSnapshot{
		capture:     DaemonLifecycleCaptureHealth{ProducerCounterAvailable: true},
		recognition: AgentRecognitionHealth{Enabled: false},
	}
	settled, err = agentRecognitionBenchmarkAccountingSettled(false, baselineBefore, baselineBefore, 1)
	if err != nil || !settled {
		t.Fatalf("filtered baseline settled = %v, error = %v", settled, err)
	}
	baselineAfter := baselineBefore
	baselineAfter.capture.DeliveredTotal = 1
	if _, err := agentRecognitionBenchmarkAccountingSettled(false, baselineBefore, baselineAfter, 1); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("baseline leakage error = %v", err)
	}
}

func TestAgentRecognitionBenchmarkAccountingSettledRejectsCounterOverflow(t *testing.T) {
	t.Parallel()
	before := agentRecognitionBenchmarkSnapshot{
		capture:     DaemonLifecycleCaptureHealth{ProducerCounterAvailable: true},
		recognition: AgentRecognitionHealth{Enabled: true},
		fingerprint: AgentFingerprintHealth{Enabled: true},
	}
	max := ^uint64(0)
	tests := []struct {
		name   string
		mutate func(*agentRecognitionBenchmarkSnapshot)
	}{
		{
			name: "capture total",
			mutate: func(after *agentRecognitionBenchmarkSnapshot) {
				after.capture.DeliveredTotal = max
				after.capture.ProducerRingbufDroppedTotal = 1
			},
		},
		{
			name: "classified total",
			mutate: func(after *agentRecognitionBenchmarkSnapshot) {
				after.capture.DeliveredTotal = max
				after.recognition.Counters = AgentRecognitionCounters{CandidatesTotal: max, Recognized: max, Ambiguous: 1}
			},
		},
		{
			name: "terminal total",
			mutate: func(after *agentRecognitionBenchmarkSnapshot) {
				after.capture.DeliveredTotal = max
				after.recognition.Counters = AgentRecognitionCounters{CandidatesTotal: max, Recognized: max}
				after.fingerprint.Counters.Success = max
				after.fingerprint.Counters.DigestMismatch = 1
			},
		},
		{
			name: "unavailable total",
			mutate: func(after *agentRecognitionBenchmarkSnapshot) {
				after.capture.DeliveredTotal = max
				after.recognition.Counters = AgentRecognitionCounters{CandidatesTotal: max, Recognized: max}
				after.fingerprint.Counters.ResolutionDenied = max
				after.fingerprint.Counters.ProcessExited = 1
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			after := before
			test.mutate(&after)
			if _, err := agentRecognitionBenchmarkAccountingSettled(true, before, after, max); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
				t.Fatalf("overflow accounting error = %v", err)
			}
		})
	}
}

func TestResetProcessPeakRSSKiB(t *testing.T) {
	command := exec.Command("/bin/sleep", "5")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	if err := resetProcessPeakRSSKiB(command.Process.Pid); err != nil {
		t.Fatal(err)
	}
	if err := resetProcessPeakRSSKiB(0); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("invalid PID reset error = %v", err)
	}
}

func TestCalibrateAgentRecognitionBenchmarkProcessCPUIsBoundedAndDigestBound(t *testing.T) {
	payload := bytes.Repeat([]byte("ardur-calibration\n"), 128<<10)
	path := filepath.Join(t.TempDir(), "workload")
	if err := os.WriteFile(path, payload, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	calibration, err := calibrateAgentRecognitionBenchmarkProcessCPU(context.Background(), path, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAgentRecognitionBenchmarkCalibration(calibration); err != nil {
		t.Fatal(err)
	}
	if calibration.BytesPerSample < AgentRecognitionBenchmarkCalibrationTargetBytes || len(calibration.ProcessCPUSamplesNanoseconds) != AgentRecognitionBenchmarkCalibrationSamples {
		t.Fatalf("calibration = %+v", calibration)
	}
	if _, err := calibrateAgentRecognitionBenchmarkProcessCPU(context.Background(), path, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("digest mismatch error = %v", err)
	}
}

func TestCopyBenchmarkExecutableBindsBytesAndRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	payload := []byte("#!/bin/sh\nexit 0\n")
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, payload, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "destination")
	digest, err := copyBenchmarkExecutable(source, destination)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(payload)
	if digest != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("copied executable digest = %q", digest)
	}
	if copied, err := os.ReadFile(destination); err != nil || !bytes.Equal(copied, payload) {
		t.Fatalf("copied executable = %q, error = %v", copied, err)
	}

	link := filepath.Join(root, "source-link")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if _, err := copyBenchmarkExecutable(link, filepath.Join(root, "link-destination")); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("symlink copy error = %v", err)
	}
}

func TestAgentRecognitionBenchmarkRunnerContextParsersAreBounded(t *testing.T) {
	if got := parseAgentRecognitionBenchmarkCPUModel([]byte("processor: 0\nmodel name: Example Hosted CPU\n")); got != "Example Hosted CPU" {
		t.Fatalf("CPU model = %q", got)
	}
	if got := parseAgentRecognitionBenchmarkEffectiveCPUSet([]byte("Name:\ttest\nCpus_allowed_list:\t0-3,8\n")); got != "0-3,8" {
		t.Fatalf("effective CPU set = %q", got)
	}
	if got, ok := parseAgentRecognitionBenchmarkCgroupV2Path([]byte("0::/actions_job/abc\n")); !ok || got != "actions_job/abc" {
		t.Fatalf("cgroup path = %q, found=%v", got, ok)
	}
	if _, ok := parseAgentRecognitionBenchmarkCgroupV2Path([]byte("0::relative\n")); ok {
		t.Fatal("relative cgroup path was accepted")
	}

	environment := agentRecognitionBenchmarkEnvironment("ubuntu|24", "2026`07")
	for _, value := range []string{
		environment.CPUModel,
		environment.CgroupCPUMax,
		environment.EffectiveCPUSet,
		environment.RunnerImageOS,
		environment.RunnerImageVersion,
	} {
		if !validAgentRecognitionBenchmarkHostText(value) {
			t.Fatalf("unsafe runner context value = %q", value)
		}
	}
	if environment.RunnerImageOS != "ubuntu_24" || environment.RunnerImageVersion != "2026_07" {
		t.Fatalf("runner image context was not sanitized: %+v", environment)
	}
}

func TestDeltaFingerprintCountersAccountsForWorkerUnavailable(t *testing.T) {
	before := AgentFingerprintCounters{Success: 4, WorkerUnavailable: 2}
	after := AgentFingerprintCounters{Success: 5, WorkerUnavailable: 3}
	ledger, err := deltaFingerprintCounters(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if ledger.Success != 1 || ledger.Unavailable != 1 || ledger.WorkerUnavailable != 1 {
		t.Fatalf("fingerprint ledger = %+v, want one success and one worker_unavailable", ledger)
	}

	after.WorkerUnavailable = 1
	if _, err := deltaFingerprintCounters(before, after); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("backwards worker_unavailable error = %v", err)
	}
}
