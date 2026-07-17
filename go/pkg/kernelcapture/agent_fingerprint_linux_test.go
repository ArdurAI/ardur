//go:build linux

package kernelcapture

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLinuxAgentFingerprintResolverUsesPidfdAndProcExe(t *testing.T) {
	resolver := linuxAgentFingerprintResolver{}
	command := exec.Command("/bin/sleep", "5")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	target, outcome := resolver.Bind(uint32(command.Process.Pid))
	if outcome != "" {
		t.Fatalf("bind outcome = %q", outcome)
	}
	defer target.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	digest, outcome := resolver.Resolve(ctx, target, DefaultAgentFingerprintMaxFileBytes)
	if outcome != "" {
		t.Fatalf("resolve outcome = %q", outcome)
	}
	if digest.method != AgentFingerprintMethodSHA256ProcExe || digest.objectState != AgentFingerprintObjectLinked {
		t.Fatalf("digest metadata = %+v", digest)
	}
	expected := hashFileForLinuxFingerprintTest(t, fmt.Sprintf("/proc/%d/exe", command.Process.Pid))
	if digest.digest != expected {
		t.Fatalf("resolved digest did not match the live executable object")
	}
}

func TestLinuxAgentFingerprintResolverLabelsDeletedExecutable(t *testing.T) {
	source, err := os.Open("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	path := filepath.Join(t.TempDir(), "native-agent")
	destination, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(destination, source); err != nil {
		_ = destination.Close()
		t.Fatal(err)
	}
	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}
	expected := hashFileForLinuxFingerprintTest(t, path)

	command := exec.Command(path, "5")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	resolver := linuxAgentFingerprintResolver{}
	target, outcome := resolver.Bind(uint32(command.Process.Pid))
	if outcome != "" {
		t.Fatalf("bind outcome = %q", outcome)
	}
	defer target.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	digest, outcome := resolver.Resolve(ctx, target, DefaultAgentFingerprintMaxFileBytes)
	if outcome != "" {
		t.Fatalf("resolve outcome = %q", outcome)
	}
	if digest.objectState != AgentFingerprintObjectDeleted || digest.digest != expected {
		t.Fatalf("deleted executable digest = %+v", digest)
	}
}

func TestLinuxAgentFingerprintResolverReportsExitSizeAndDeadline(t *testing.T) {
	resolver := linuxAgentFingerprintResolver{}
	command := exec.Command("/bin/sleep", "5")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	target, outcome := resolver.Bind(uint32(command.Process.Pid))
	if outcome != "" {
		t.Fatalf("bind outcome = %q", outcome)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("killed command unexpectedly succeeded")
	}
	if _, outcome := resolver.Resolve(context.Background(), target, DefaultAgentFingerprintMaxFileBytes); outcome != AgentFingerprintOutcomeProcessExited {
		t.Fatalf("exited outcome = %q", outcome)
	}
	_ = target.Close()

	command = exec.Command("/bin/sleep", "5")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	target, outcome = resolver.Bind(uint32(command.Process.Pid))
	if outcome != "" {
		t.Fatalf("bind outcome = %q", outcome)
	}
	defer target.Close()
	if _, outcome := resolver.Resolve(context.Background(), target, 1); outcome != AgentFingerprintOutcomeSizeExceeded {
		t.Fatalf("size outcome = %q", outcome)
	}
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, outcome := resolver.Resolve(expired, target, DefaultAgentFingerprintMaxFileBytes); outcome != AgentFingerprintOutcomeDeadlineExceeded {
		t.Fatalf("deadline outcome = %q", outcome)
	}
}

func TestLinuxAgentFingerprintTargetExitedRetriesInterruptedPoll(t *testing.T) {
	calls := 0
	exited, outcome := linuxAgentFingerprintTargetExitedWithPoll(42, func(fds []unix.PollFd, timeout int) (int, error) {
		calls++
		if len(fds) != 1 || fds[0].Fd != 42 || timeout != 0 {
			t.Fatalf("poll arguments = %+v, timeout %d", fds, timeout)
		}
		if calls <= 2 {
			return -1, unix.EINTR
		}
		return 0, nil
	})
	if exited || outcome != "" || calls != 3 {
		t.Fatalf("exited=%v outcome=%q calls=%d", exited, outcome, calls)
	}

	calls = 0
	exited, outcome = linuxAgentFingerprintTargetExitedWithPoll(42, func([]unix.PollFd, int) (int, error) {
		calls++
		return -1, unix.EINTR
	})
	if exited || outcome != AgentFingerprintOutcomeUnsupported || calls != maxAgentFingerprintPollInterruptRetries+1 {
		t.Fatalf("bounded retry exited=%v outcome=%q calls=%d", exited, outcome, calls)
	}
}

func hashFileForLinuxFingerprintTest(t *testing.T, path string) [sha256.Size]byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		t.Fatal(err)
	}
	var result [sha256.Size]byte
	copy(result[:], hasher.Sum(nil))
	return result
}
