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
