//go:build linux

package kernelcapture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	agentFingerprintReadBufferBytes         = 64 << 10
	maxAgentFingerprintPollInterruptRetries = 8
)

type linuxAgentFingerprintResolver struct{}

type linuxAgentFingerprintTarget struct {
	pid              uint32
	pidfd            int
	launcher         bool
	launcherIdentity LauncherObjectIdentity
}

func newPlatformAgentFingerprintResolver() agentFingerprintResolver {
	return linuxAgentFingerprintResolver{}
}

func (linuxAgentFingerprintResolver) Bind(event ProcessEvent) (agentFingerprintTarget, string) {
	if event.PID == 0 {
		return nil, AgentFingerprintOutcomeUnsupported
	}
	pidfd, err := unix.PidfdOpen(int(event.PID), 0)
	if err != nil {
		return nil, agentFingerprintLinuxErrorOutcome(err)
	}
	return &linuxAgentFingerprintTarget{
		pid:              event.PID,
		pidfd:            pidfd,
		launcher:         event.InterpreterBacked || event.LauncherScript,
		launcherIdentity: event.LauncherIdentity,
	}, ""
}

func (linuxAgentFingerprintResolver) Resolve(ctx context.Context, rawTarget agentFingerprintTarget, limits agentFingerprintResolveLimits) (agentFingerprintDigest, string) {
	target, ok := rawTarget.(*linuxAgentFingerprintTarget)
	if !ok || target == nil || target.pid == 0 || target.pidfd < 0 || limits.maxFileBytes <= 0 {
		return agentFingerprintDigest{}, AgentFingerprintOutcomeUnsupported
	}
	if outcome := agentFingerprintContextOutcome(ctx); outcome != "" {
		return agentFingerprintDigest{}, outcome
	}
	if exited, outcome := linuxAgentFingerprintTargetExited(target.pidfd); outcome != "" {
		return agentFingerprintDigest{}, outcome
	} else if exited {
		return agentFingerprintDigest{}, AgentFingerprintOutcomeProcessExited
	}
	if target.launcher {
		return resolveLinuxAgentLauncher(ctx, target, limits)
	}
	return resolveLinuxNativeExecutable(ctx, target, limits.maxFileBytes)
}

func resolveLinuxNativeExecutable(ctx context.Context, target *linuxAgentFingerprintTarget, maxFileBytes int64) (agentFingerprintDigest, string) {
	// The path is constructed only to acquire an fd and is never returned or
	// logged. Opening the procfs magic link opens the live executable object.
	file, err := os.Open(fmt.Sprintf("/proc/%d/exe", target.pid))
	if err != nil {
		return agentFingerprintDigest{}, agentFingerprintLinuxErrorOutcome(err)
	}
	defer file.Close()

	if exited, outcome := linuxAgentFingerprintTargetExited(target.pidfd); outcome != "" {
		return agentFingerprintDigest{}, outcome
	} else if exited {
		return agentFingerprintDigest{}, AgentFingerprintOutcomeProcessExited
	}

	info, err := file.Stat()
	if err != nil {
		return agentFingerprintDigest{}, agentFingerprintLinuxErrorOutcome(err)
	}
	objectState := AgentFingerprintObjectLinked
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink == 0 {
		objectState = AgentFingerprintObjectDeleted
	}
	digest := agentFingerprintDigest{method: AgentFingerprintMethodSHA256ProcExe, objectState: objectState}
	if !info.Mode().IsRegular() || info.Size() < 0 {
		return digest, AgentFingerprintOutcomeUnsupported
	}
	return hashAgentFingerprintFile(ctx, file, info.Size(), maxFileBytes, digest)
}

func resolveLinuxAgentLauncher(ctx context.Context, target *linuxAgentFingerprintTarget, limits agentFingerprintResolveLimits) (agentFingerprintDigest, string) {
	digest := agentFingerprintDigest{
		method:      AgentFingerprintMethodSHA256KernelLauncher,
		objectState: launcherFingerprintObjectState(target.launcherIdentity),
	}
	if !target.launcherIdentity.Present {
		return digest, AgentFingerprintOutcomeMissingIdentity
	}
	arguments, outcome := readLinuxAgentLauncherArguments(target.pid, limits)
	if outcome != "" {
		return digest, outcome
	}
	return resolveLinuxAgentLauncherArguments(ctx, target, arguments, limits)
}

func readLinuxAgentLauncherArguments(pid uint32, limits agentFingerprintResolveLimits) ([]string, string) {
	if limits.maxArgumentBytes <= 0 || limits.maxArguments <= 0 {
		return nil, AgentFingerprintOutcomeUnsupported
	}
	file, err := os.Open(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil, agentFingerprintLinuxErrorOutcome(err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limits.maxArgumentBytes+1))
	if err != nil {
		return nil, agentFingerprintLinuxErrorOutcome(err)
	}
	if int64(len(raw)) > limits.maxArgumentBytes {
		return nil, AgentFingerprintOutcomeArgumentLimit
	}
	raw = bytes.TrimRight(raw, "\x00")
	if len(raw) == 0 {
		return nil, AgentFingerprintOutcomeMissingLocator
	}
	parts := bytes.Split(raw, []byte{0})
	if len(parts) > limits.maxArguments {
		return nil, AgentFingerprintOutcomeArgumentLimit
	}
	arguments := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) != 0 {
			arguments = append(arguments, string(part))
		}
	}
	if len(arguments) == 0 {
		return nil, AgentFingerprintOutcomeMissingLocator
	}
	return arguments, ""
}

// resolveLinuxAgentLauncherArguments is separated from procfs acquisition so
// adversarial tests can supply rewritten cmdline candidates while exercising
// the real openat2/statx identity gate.
func resolveLinuxAgentLauncherArguments(ctx context.Context, target *linuxAgentFingerprintTarget, arguments []string, limits agentFingerprintResolveLimits) (agentFingerprintDigest, string) {
	digest := agentFingerprintDigest{
		method:      AgentFingerprintMethodSHA256KernelLauncher,
		objectState: launcherFingerprintObjectState(target.launcherIdentity),
	}
	if len(arguments) == 0 {
		return digest, AgentFingerprintOutcomeMissingLocator
	}
	if exited, outcome := linuxAgentFingerprintTargetExited(target.pidfd); outcome != "" {
		return digest, outcome
	} else if exited {
		return digest, AgentFingerprintOutcomeProcessExited
	}

	rootFD, err := unix.Open(fmt.Sprintf("/proc/%d/root", target.pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return digest, agentFingerprintLinuxErrorOutcome(err)
	}
	defer unix.Close(rootFD)

	bestOutcome := AgentFingerprintOutcomeMissingLocator
	cwd := ""
	cwdLoaded := false
	for _, argument := range arguments {
		if outcome := agentFingerprintContextOutcome(ctx); outcome != "" {
			return digest, outcome
		}
		if argument == "" || strings.HasPrefix(argument, "-") {
			continue
		}

		candidate := argument
		if filepath.IsAbs(candidate) {
			candidate = strings.TrimPrefix(filepath.Clean(candidate), string(filepath.Separator))
		} else {
			if !cwdLoaded {
				cwd, err = os.Readlink(fmt.Sprintf("/proc/%d/cwd", target.pid))
				cwdLoaded = true
				if err != nil {
					bestOutcome = preferLauncherOutcome(bestOutcome, agentFingerprintLinuxErrorOutcome(err))
					continue
				}
			}
			if !filepath.IsAbs(cwd) || strings.HasSuffix(cwd, " (deleted)") {
				bestOutcome = preferLauncherOutcome(bestOutcome, AgentFingerprintOutcomeMissingLocator)
				continue
			}
			candidate = strings.TrimPrefix(filepath.Clean(filepath.Join(cwd, candidate)), string(filepath.Separator))
		}
		if candidate == "" || candidate == "." {
			continue
		}

		fd, openErr := unix.Openat2(rootFD, candidate, &unix.OpenHow{
			Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK),
			Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
		})
		if openErr != nil {
			bestOutcome = preferLauncherOutcome(bestOutcome, agentLauncherOpenOutcome(openErr))
			continue
		}

		var stat unix.Statx_t
		statErr := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_STATX_DONT_SYNC, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID, &stat)
		if statErr != nil {
			_ = unix.Close(fd)
			bestOutcome = preferLauncherOutcome(bestOutcome, agentLauncherStatxOutcome(statErr))
			continue
		}
		if stat.Mask&unix.STATX_MNT_ID == 0 {
			_ = unix.Close(fd)
			bestOutcome = preferLauncherOutcome(bestOutcome, AgentFingerprintOutcomeUnsupportedFS)
			continue
		}
		if !launcherIdentityMatchesStatx(target.launcherIdentity, stat) {
			_ = unix.Close(fd)
			bestOutcome = preferLauncherOutcome(bestOutcome, AgentFingerprintOutcomeLocatorMismatch)
			continue
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG {
			_ = unix.Close(fd)
			return digest, AgentFingerprintOutcomeUnsupportedFS
		}
		if stat.Nlink == 0 {
			digest.objectState = AgentFingerprintObjectDeleted
		}
		file := os.NewFile(uintptr(fd), "agent-launcher")
		if file == nil {
			_ = unix.Close(fd)
			return digest, AgentFingerprintOutcomeUnsupportedFS
		}
		defer file.Close()
		return hashAgentFingerprintFile(ctx, file, int64(stat.Size), limits.maxFileBytes, digest)
	}

	if exited, outcome := linuxAgentFingerprintTargetExited(target.pidfd); outcome != "" {
		return digest, outcome
	} else if exited {
		return digest, AgentFingerprintOutcomeProcessExited
	}
	return digest, bestOutcome
}

func launcherIdentityMatchesStatx(identity LauncherObjectIdentity, stat unix.Statx_t) bool {
	return identity.Present &&
		identity.DeviceMajor == stat.Dev_major &&
		identity.DeviceMinor == stat.Dev_minor &&
		identity.Inode == stat.Ino &&
		identity.MountID == stat.Mnt_id
}

func agentLauncherOpenOutcome(err error) string {
	switch {
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL):
		return AgentFingerprintOutcomeUnsupportedKernel
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM), errors.Is(err, unix.EXDEV), errors.Is(err, unix.ELOOP):
		return AgentFingerprintOutcomeResolutionDenied
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENOTDIR):
		return AgentFingerprintOutcomeMissingLocator
	default:
		return AgentFingerprintOutcomeUnsupportedFS
	}
}

func agentLauncherStatxOutcome(err error) string {
	if errors.Is(err, unix.ENOSYS) {
		return AgentFingerprintOutcomeUnsupportedKernel
	}
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
		return AgentFingerprintOutcomeResolutionDenied
	}
	return AgentFingerprintOutcomeUnsupportedFS
}

func preferLauncherOutcome(current, candidate string) string {
	rank := map[string]int{
		AgentFingerprintOutcomeMissingLocator:    1,
		AgentFingerprintOutcomeUnsupportedFS:     2,
		AgentFingerprintOutcomeResolutionDenied:  3,
		AgentFingerprintOutcomeUnsupportedKernel: 4,
		AgentFingerprintOutcomeLocatorMismatch:   5,
	}
	if rank[candidate] > rank[current] {
		return candidate
	}
	return current
}

func hashAgentFingerprintFile(ctx context.Context, file *os.File, size, maxFileBytes int64, digest agentFingerprintDigest) (agentFingerprintDigest, string) {
	if file == nil || size < 0 {
		return digest, AgentFingerprintOutcomeUnsupported
	}
	if size > maxFileBytes {
		return digest, AgentFingerprintOutcomeSizeExceeded
	}
	hasher := sha256.New()
	buffer := make([]byte, agentFingerprintReadBufferBytes)
	var total int64
	for {
		if outcome := agentFingerprintContextOutcome(ctx); outcome != "" {
			return digest, outcome
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			total += int64(n)
			if total > maxFileBytes {
				return digest, AgentFingerprintOutcomeSizeExceeded
			}
			_, _ = hasher.Write(buffer[:n])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return digest, agentFingerprintLinuxErrorOutcome(readErr)
		}
	}
	if outcome := agentFingerprintContextOutcome(ctx); outcome != "" {
		return digest, outcome
	}
	copy(digest.digest[:], hasher.Sum(nil))
	return digest, ""
}

func (t *linuxAgentFingerprintTarget) Close() error {
	if t == nil || t.pidfd < 0 {
		return nil
	}
	fd := t.pidfd
	t.pidfd = -1
	return unix.Close(fd)
}

func linuxAgentFingerprintTargetExited(pidfd int) (bool, string) {
	return linuxAgentFingerprintTargetExitedWithPoll(pidfd, unix.Poll)
}

func linuxAgentFingerprintTargetExitedWithPoll(pidfd int, poll func([]unix.PollFd, int) (int, error)) (bool, string) {
	for interrupted := 0; ; interrupted++ {
		pollFDs := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
		n, err := poll(pollFDs, 0)
		if errors.Is(err, unix.EINTR) && interrupted < maxAgentFingerprintPollInterruptRetries {
			continue
		}
		if err != nil {
			return false, agentFingerprintLinuxErrorOutcome(err)
		}
		if n == 0 {
			return false, ""
		}
		return pollFDs[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0, ""
	}
}

func agentFingerprintContextOutcome(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	switch ctx.Err() {
	case nil:
		return ""
	case context.DeadlineExceeded:
		return AgentFingerprintOutcomeDeadlineExceeded
	default:
		return AgentFingerprintOutcomeWorkerUnavailable
	}
}

func agentFingerprintLinuxErrorOutcome(err error) string {
	if err == nil {
		return ""
	}
	if pathErr, ok := err.(*os.PathError); ok {
		err = pathErr.Err
	}
	switch {
	case errors.Is(err, unix.ESRCH), errors.Is(err, unix.ENOENT):
		return AgentFingerprintOutcomeProcessExited
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		return AgentFingerprintOutcomeResolutionDenied
	case errors.Is(err, context.DeadlineExceeded):
		return AgentFingerprintOutcomeDeadlineExceeded
	default:
		return AgentFingerprintOutcomeUnsupported
	}
}
