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
	"strings"
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
	target, outcome := resolver.Bind(ProcessEvent{PID: uint32(command.Process.Pid)})
	if outcome != "" {
		t.Fatalf("bind outcome = %q", outcome)
	}
	defer target.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	digest, outcome := resolver.Resolve(ctx, target, agentFingerprintResolveLimits{maxFileBytes: DefaultAgentFingerprintMaxFileBytes})
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
	target, outcome := resolver.Bind(ProcessEvent{PID: uint32(command.Process.Pid)})
	if outcome != "" {
		t.Fatalf("bind outcome = %q", outcome)
	}
	defer target.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	digest, outcome := resolver.Resolve(ctx, target, agentFingerprintResolveLimits{maxFileBytes: DefaultAgentFingerprintMaxFileBytes})
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
	target, outcome := resolver.Bind(ProcessEvent{PID: uint32(command.Process.Pid)})
	if outcome != "" {
		t.Fatalf("bind outcome = %q", outcome)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("killed command unexpectedly succeeded")
	}
	if _, outcome := resolver.Resolve(context.Background(), target, agentFingerprintResolveLimits{maxFileBytes: DefaultAgentFingerprintMaxFileBytes}); outcome != AgentFingerprintOutcomeProcessExited {
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
	target, outcome = resolver.Bind(ProcessEvent{PID: uint32(command.Process.Pid)})
	if outcome != "" {
		t.Fatalf("bind outcome = %q", outcome)
	}
	defer target.Close()
	if _, outcome := resolver.Resolve(context.Background(), target, agentFingerprintResolveLimits{maxFileBytes: 1}); outcome != AgentFingerprintOutcomeSizeExceeded {
		t.Fatalf("size outcome = %q", outcome)
	}
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, outcome := resolver.Resolve(expired, target, agentFingerprintResolveLimits{maxFileBytes: DefaultAgentFingerprintMaxFileBytes}); outcome != AgentFingerprintOutcomeDeadlineExceeded {
		t.Fatalf("deadline outcome = %q", outcome)
	}
}

func TestLinuxAgentLauncherResolverRejectsSpoofAndAcceptsBoundedArgumentShapes(t *testing.T) {
	dir := t.TempDir()
	trustedPath := filepath.Join(dir, "trusted-launcher")
	launcherPath := filepath.Join(dir, "codex")
	if err := os.WriteFile(trustedPath, []byte("trusted but not executed"), 0o700); err != nil {
		t.Fatal(err)
	}
	launcherBytes := []byte("actual kernel-observed launcher")
	if err := os.WriteFile(launcherPath, launcherBytes, 0o700); err != nil {
		t.Fatal(err)
	}
	identity := launcherIdentityForLinuxTest(t, launcherPath)

	command := exec.Command("/bin/sleep", "5")
	command.Dir = dir
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	resolver := linuxAgentFingerprintResolver{}
	rawTarget, outcome := resolver.Bind(ProcessEvent{PID: uint32(command.Process.Pid), LauncherScript: true, LauncherIdentity: identity})
	if outcome != "" {
		t.Fatalf("bind outcome = %q", outcome)
	}
	target := rawTarget.(*linuxAgentFingerprintTarget)
	defer target.Close()
	limits := agentFingerprintResolveLimits{
		maxFileBytes: DefaultAgentFingerprintMaxFileBytes, maxArgumentBytes: DefaultAgentFingerprintMaxArgumentBytes, maxArguments: DefaultAgentFingerprintMaxArguments,
	}

	if _, outcome := resolveLinuxAgentLauncherArguments(context.Background(), target, []string{trustedPath}, limits); outcome != AgentFingerprintOutcomeLocatorMismatch {
		t.Fatalf("rewritten trusted locator outcome = %q, want locator_mismatch", outcome)
	}
	digest, outcome := resolveLinuxAgentLauncherArguments(context.Background(), target, []string{"/bin/sh", "--flag", "missing", launcherPath}, limits)
	if outcome != "" {
		t.Fatalf("recursive/flagged launcher outcome = %q", outcome)
	}
	if digest.method != AgentFingerprintMethodSHA256KernelLauncher || digest.digest != sha256.Sum256(launcherBytes) {
		t.Fatalf("launcher digest metadata = %+v", digest)
	}
	digest, outcome = resolveLinuxAgentLauncherArguments(context.Background(), target, []string{"codex"}, limits)
	if outcome != "" || digest.digest != sha256.Sum256(launcherBytes) {
		t.Fatalf("relative launcher result = %+v outcome=%q", digest, outcome)
	}
}

func TestLinuxAgentLauncherResolverExplicitFailureOutcomes(t *testing.T) {
	dir := t.TempDir()
	launcherPath := filepath.Join(dir, "codex")
	if err := os.WriteFile(launcherPath, []byte("launcher"), 0o700); err != nil {
		t.Fatal(err)
	}
	identity := launcherIdentityForLinuxTest(t, launcherPath)
	command := exec.Command("/bin/sleep", "5")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	resolver := linuxAgentFingerprintResolver{}
	rawTarget, outcome := resolver.Bind(ProcessEvent{PID: uint32(command.Process.Pid), LauncherScript: true, LauncherIdentity: identity})
	if outcome != "" {
		t.Fatalf("bind outcome = %q", outcome)
	}
	target := rawTarget.(*linuxAgentFingerprintTarget)
	limits := agentFingerprintResolveLimits{
		maxFileBytes: DefaultAgentFingerprintMaxFileBytes, maxArgumentBytes: DefaultAgentFingerprintMaxArgumentBytes, maxArguments: DefaultAgentFingerprintMaxArguments,
	}

	magic := fmt.Sprintf("/proc/%d/exe", command.Process.Pid)
	if _, outcome := resolveLinuxAgentLauncherArguments(context.Background(), target, []string{magic}, limits); outcome != AgentFingerprintOutcomeResolutionDenied {
		t.Fatalf("fd/magic-link outcome = %q", outcome)
	}
	fifoPath := filepath.Join(dir, "launcher-fifo")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	target.launcherIdentity = launcherIdentityForLinuxTest(t, fifoPath)
	if _, outcome := resolveLinuxAgentLauncherArguments(context.Background(), target, []string{fifoPath}, limits); outcome != AgentFingerprintOutcomeUnsupportedFS {
		t.Fatalf("special-file launcher outcome = %q", outcome)
	}
	target.launcherIdentity = identity
	deletedIdentity := identity
	deletedIdentity.LinkCount = 0
	target.launcherIdentity = deletedIdentity
	if err := os.Remove(launcherPath); err != nil {
		t.Fatal(err)
	}
	digest, outcome := resolveLinuxAgentLauncherArguments(context.Background(), target, []string{launcherPath}, limits)
	if outcome != AgentFingerprintOutcomeMissingLocator || digest.objectState != AgentFingerprintObjectDeleted {
		t.Fatalf("deleted launcher result = %+v outcome=%q", digest, outcome)
	}
	if got := agentLauncherOpenOutcome(unix.EXDEV); got != AgentFingerprintOutcomeResolutionDenied {
		t.Fatalf("namespace escape outcome = %q", got)
	}
	if got := agentLauncherStatxOutcome(unix.EOPNOTSUPP); got != AgentFingerprintOutcomeUnsupportedFS {
		t.Fatalf("unsupported filesystem outcome = %q", got)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("killed command unexpectedly succeeded")
	}
	if _, outcome := resolveLinuxAgentLauncherArguments(context.Background(), target, []string{launcherPath}, limits); outcome != AgentFingerprintOutcomeProcessExited {
		t.Fatalf("early-exit launcher outcome = %q", outcome)
	}
	_ = target.Close()
}

func TestLinuxAgentLauncherCmdlineLimitsAreExplicit(t *testing.T) {
	marker := strings.Repeat("x", 128)
	command := exec.Command("/bin/sh", "-c", "while :; do sleep 1; done", "sh", marker)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	waitForLinuxCmdlineMarker(t, command.Process.Pid, marker)
	_, outcome := readLinuxAgentLauncherArguments(uint32(command.Process.Pid), agentFingerprintResolveLimits{maxArgumentBytes: 16, maxArguments: 64})
	if outcome != AgentFingerprintOutcomeArgumentLimit {
		t.Fatalf("cmdline limit outcome = %q", outcome)
	}
}

func waitForLinuxCmdlineMarker(t *testing.T, pid int, marker string) {
	t.Helper()
	path := fmt.Sprintf("/proc/%d/cmdline", pid)
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(path)
		lastErr = err
		if err == nil && strings.Contains(string(raw), marker) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("cmdline marker was not observable before the deadline (last read error: %v)", lastErr)
}

func launcherIdentityForLinuxTest(t *testing.T, path string) LauncherObjectIdentity {
	t.Helper()
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var stat unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_STATX_DONT_SYNC, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID, &stat); err != nil {
		t.Fatal(err)
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 {
		t.Fatal("statx mount id unavailable")
	}
	return LauncherObjectIdentity{
		Present: true, DeviceMajor: stat.Dev_major, DeviceMinor: stat.Dev_minor, Inode: stat.Ino, MountID: stat.Mnt_id, LinkCount: stat.Nlink,
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
