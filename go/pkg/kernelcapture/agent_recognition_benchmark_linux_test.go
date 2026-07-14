//go:build linux

package kernelcapture

import (
	"errors"
	"os/exec"
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
