//go:build linux

package kernelcapture

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	agentFingerprintReadBufferBytes         = 64 << 10
	maxAgentFingerprintPollInterruptRetries = 8
)

type linuxAgentFingerprintResolver struct{}

type linuxAgentFingerprintTarget struct {
	pid   uint32
	pidfd int
}

func newPlatformAgentFingerprintResolver() agentFingerprintResolver {
	return linuxAgentFingerprintResolver{}
}

func (linuxAgentFingerprintResolver) Bind(pid uint32) (agentFingerprintTarget, string) {
	if pid == 0 {
		return nil, AgentFingerprintOutcomeUnsupported
	}
	pidfd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		return nil, agentFingerprintLinuxErrorOutcome(err)
	}
	return &linuxAgentFingerprintTarget{pid: pid, pidfd: pidfd}, ""
}

func (linuxAgentFingerprintResolver) Resolve(ctx context.Context, rawTarget agentFingerprintTarget, maxFileBytes int64) (agentFingerprintDigest, string) {
	target, ok := rawTarget.(*linuxAgentFingerprintTarget)
	if !ok || target == nil || target.pid == 0 || target.pidfd < 0 || maxFileBytes <= 0 {
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
	digest := agentFingerprintDigest{
		method:      AgentFingerprintMethodSHA256ProcExe,
		objectState: objectState,
	}
	if !info.Mode().IsRegular() || info.Size() < 0 {
		return digest, AgentFingerprintOutcomeUnsupported
	}
	if info.Size() > maxFileBytes {
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
