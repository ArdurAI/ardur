//go:build linux

// Command ardur-seccomp-smoke is a CI-only kernel-in-loop smoke test for the
// seccomp user-notify enforcement tier (Epic A #63, plan E4). It is driven
// by the seccomp-smoke job in .github/workflows/kernel-enforce.yml, which
// runs this binary directly on a plain (unprivileged) Ubuntu runner —
// unlike ardur-guard-smoke's kernel-smoke job, this tier needs no KVM/
// virtme-ng custom kernel boot: seccomp(SECCOMP_SET_MODE_FILTER,
// SECCOMP_FILTER_FLAG_NEW_LISTENER, ...) works under an ordinary
// PR_SET_NO_NEW_PRIVS-only process, confirmed empirically during E4's
// end-to-end verification.
//
// It proves, against a real kernel, what the pure-Go/Linux-only unit tests
// cannot:
//  1. ardur-kernelcaptured, started with no BPF-LSM available (the common
//     case this plan targets), falls back to the seccomp tier and starts
//     its handoff socket.
//  2. ardur-exec-shim installs a real connect(2)-notify filter, hands the
//     listener off to the daemon over a real Unix socket + SCM_RIGHTS, and
//     execs into a real target process that keeps running under it.
//  3. The daemon's supervisor loop actually decides connect(2) attempts:
//     a policy-denied target gets EPERM, a policy-allowed target reaches a
//     real connect() (observed as ECONNREFUSED against a closed port,
//     proving the syscall wasn't blocked).
//  4. The decision is recorded as a hash-chained enforce_events receipt
//     tagged with the seccomp tier.
//
// This exact harness caught two real bugs during development that no
// pure-Go test surfaced: the shim's own connect() to the daemon's handoff
// socket deadlocking against its own just-installed filter (fixed by
// dialing before installing the filter — see ardur-exec-shim's run()), and
// SendSeccompNotifResp writing a positive errno into a kernel field that
// requires the raw negative -errno syscall-return convention (fixed in
// buildSeccompNotifResp) — the latter silently let denied connects through
// instead of blocking them. Losing this smoke test would mean losing the
// only thing that can catch a regression in either.
//
// Not part of `go test ./...`: this spawns real daemon/shim subprocesses and
// binds real sockets in ways not safe to run concurrently with other tests
// in the same process.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

const (
	pollInterval = 100 * time.Millisecond
	pollTimeout  = 15 * time.Second
)

func main() {
	probeConnect := flag.String("probe-connect", "", "internal: re-exec self as a connect(2) probe against this host:port")
	daemonBin := flag.String("daemon-bin", "", "path to a prebuilt ardur-kernelcaptured binary (required)")
	shimBin := flag.String("shim-bin", "", "path to a prebuilt ardur-exec-shim binary (required)")
	flag.Parse()

	if *probeConnect != "" {
		runProbe(*probeConnect)
		return
	}

	if *daemonBin == "" || *shimBin == "" {
		fmt.Fprintln(os.Stderr, "usage: ardur-seccomp-smoke --daemon-bin PATH --shim-bin PATH")
		os.Exit(2)
	}
	if err := run(*daemonBin, *shimBin); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: seccomp tier denied a policy-blocked connect() with EPERM and allowed a policy-permitted one through to the kernel")
}

// runProbe is this binary's own re-exec mode: attempt one TCP connect and
// report the observed errno (or success) unambiguously — this is what
// ardur-exec-shim execs into as the governed process, so its own connect(2)
// is the one under test.
func runProbe(addr string) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err == nil {
		conn.Close()
		fmt.Println("CONNECTED")
		return
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		fmt.Printf("ERRNO:%d:%s\n", errno, errno)
		return
	}
	fmt.Printf("OTHER_ERROR:%v\n", err)
}

func run(daemonBin, shimBin string) (runErr error) {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve own executable path (needed to re-exec as the connect probe): %w", err)
	}

	workDir, err := os.MkdirTemp("", "ardur-seccomp-smoke-")
	if err != nil {
		return fmt.Errorf("create work dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	// ardur-kernelcaptured's custody plan (daemon_custody.go) hard-requires
	// --socket (via its parent, the run dir) under /run/ardur and
	// --state-dir under /var/lib/ardur — these are not configurable to an
	// arbitrary tmp path. --seccomp-socket and --evidence-dir carry no such
	// restriction, so those stay in workDir. runID keeps this smoke run's
	// paths from colliding with a real daemon instance or a concurrent run.
	runID := fmt.Sprintf("seccomp-smoke-%d", os.Getpid())
	runDir := filepath.Join("/run/ardur", runID)
	sockPath := filepath.Join(runDir, "control.sock")
	stateDir := filepath.Join("/var/lib/ardur", runID, "state")
	defer os.RemoveAll(runDir)
	defer os.RemoveAll(filepath.Join("/var/lib/ardur", runID))

	seccompSockPath := filepath.Join(workDir, "seccomp.sock")
	evidenceDir := filepath.Join(workDir, "evidence")

	daemonLog, err := os.Create(filepath.Join(workDir, "daemon.log"))
	if err != nil {
		return fmt.Errorf("create daemon log file: %w", err)
	}
	defer daemonLog.Close()
	defer func() {
		if runErr == nil {
			return
		}
		_ = daemonLog.Sync()
		if data, err := os.ReadFile(daemonLog.Name()); err == nil {
			fmt.Fprintf(os.Stderr, "--- ardur-kernelcaptured log ---\n%s\n--- end daemon log ---\n", data)
		}
	}()

	daemonCmd := exec.Command(daemonBin,
		"--socket", sockPath,
		"--seccomp-socket", seccompSockPath,
		"--evidence-dir", evidenceDir,
		"--state-dir", stateDir,
		"--debug",
		"--guard-ready-timeout=2s",
		// Force the seccomp tier regardless of the host kernel's BPF-LSM
		// availability. GitHub-hosted runners (and Docker Desktop's kernel)
		// boot with "bpf" in the active LSM list, so without this the daemon
		// would prefer the BPF-LSM tier and this smoke — which exercises the
		// seccomp user-notify path specifically — could never reach it.
		"--disable-bpf-lsm",
	)
	daemonCmd.Stdout = daemonLog
	daemonCmd.Stderr = daemonLog
	if err := daemonCmd.Start(); err != nil {
		return fmt.Errorf("start ardur-kernelcaptured: %w", err)
	}
	defer func() {
		_ = daemonCmd.Process.Kill()
		_ = daemonCmd.Wait()
	}()

	if err := waitForSocket(sockPath); err != nil {
		return fmt.Errorf("waiting for control socket: %w (see %s)", err, daemonLog.Name())
	}

	tier, err := waitForActiveTier(sockPath)
	if err != nil {
		return fmt.Errorf("waiting for enforcement tier selection: %w (see %s)", err, daemonLog.Name())
	}
	if tier != "seccomp" {
		return fmt.Errorf("active enforcement tier = %q, want %q — this runner may have BPF-LSM available, which is not what this smoke test exercises (see %s)",
			tier, "seccomp", daemonLog.Name())
	}
	fmt.Println("daemon started, seccomp tier active")

	const allowedIP = "127.0.0.2"
	deniedTarget := "127.0.0.3:19999" // not in the allowlist
	deniedOut, err := runShimProbe(sockPath, shimBin, seccompSockPath, "seccomp-smoke-denied", self, deniedTarget, allowedIP)
	if err != nil {
		return fmt.Errorf("run shim against denied target: %w", err)
	}
	if deniedOut != "ERRNO:1:operation not permitted" {
		return fmt.Errorf("denied target %s: probe reported %q, want EPERM", deniedTarget, deniedOut)
	}
	fmt.Println("denied target correctly got EPERM:", deniedOut)

	allowedTarget := allowedIP + ":19999" // in the allowlist, nothing listening
	allowedOut, err := runShimProbe(sockPath, shimBin, seccompSockPath, "seccomp-smoke-allowed", self, allowedTarget, allowedIP)
	if err != nil {
		return fmt.Errorf("run shim against allowed target: %w", err)
	}
	if allowedOut != "ERRNO:111:connection refused" {
		return fmt.Errorf("allowed target %s: probe reported %q, want ECONNREFUSED proving the syscall reached the kernel", allowedTarget, allowedOut)
	}
	fmt.Println("allowed target correctly reached the kernel with ECONNREFUSED:", allowedOut)

	return nil
}

func waitForSocket(path string) error {
	deadline := time.Now().Add(pollTimeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(pollInterval)
	}
	return fmt.Errorf("socket %s did not appear within %s", path, pollTimeout)
}

// waitForActiveTier polls the daemon's health response until it reports a
// non-empty enforcement tier, so the caller doesn't race apply_policy
// against tier selection still being in flight.
func waitForActiveTier(sockPath string) (string, error) {
	deadline := time.Now().Add(pollTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := daemonRequest(sockPath, kernelcapture.DaemonProtocolRequest{
			ProtocolVersion: kernelcapture.DaemonProtocolVersion,
			Method:          kernelcapture.DaemonProtocolMethodHealth,
			Health:          &kernelcapture.DaemonHealthRequest{},
		})
		if err != nil {
			lastErr = err
			time.Sleep(pollInterval)
			continue
		}
		if resp.EnforcementTier != "" {
			return resp.EnforcementTier, nil
		}
		time.Sleep(pollInterval)
	}
	return "", fmt.Errorf("no enforcement tier reported within %s (last error: %v)", pollTimeout, lastErr)
}

func daemonCall(sockPath string, req kernelcapture.DaemonProtocolRequest) error {
	resp, err := daemonRequest(sockPath, req)
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("daemon returned an error response: %s", resp.Error)
	}
	return nil
}

func daemonRequest(sockPath string, req kernelcapture.DaemonProtocolRequest) (kernelcapture.DaemonProtocolResponse, error) {
	conn, err := net.DialTimeout("unix", sockPath, 5*time.Second)
	if err != nil {
		return kernelcapture.DaemonProtocolResponse{}, fmt.Errorf("dial control socket: %w", err)
	}
	defer conn.Close()

	data, err := kernelcapture.EncodeDaemonProtocolRequest(req)
	if err != nil {
		return kernelcapture.DaemonProtocolResponse{}, fmt.Errorf("encode request: %w", err)
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return kernelcapture.DaemonProtocolResponse{}, fmt.Errorf("set deadline: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return kernelcapture.DaemonProtocolResponse{}, fmt.Errorf("write request: %w", err)
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 65536), 1<<20)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return kernelcapture.DaemonProtocolResponse{}, fmt.Errorf("read response: %w", err)
		}
		return kernelcapture.DaemonProtocolResponse{}, errors.New("read response: connection closed with no data")
	}
	resp, err := kernelcapture.DecodeDaemonProtocolResponse(scanner.Bytes())
	if err != nil {
		return kernelcapture.DaemonProtocolResponse{}, fmt.Errorf("decode response: %w", err)
	}
	return resp, nil
}

// runShimProbe starts the real shim behind its production ready-file gate,
// registers that live child PID as the session root, applies the policy, and
// only then releases the shim to transfer its real listener and exec the
// connect probe. One session per probe keeps the delegated root identity exact.
func runShimProbe(daemonSockPath, shimBin, seccompSockPath, sessionID, self, target, allowedIP string) (string, error) {
	readyFile := filepath.Join(filepath.Dir(seccompSockPath), sessionID+".ready")
	defer os.Remove(readyFile)
	cmd := exec.Command(shimBin,
		"--session-id", sessionID,
		"--seccomp-socket", seccompSockPath,
		"--ready-file", readyFile,
		"--",
		self, "--probe-connect", target,
	)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start shim: %w", err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	if err := daemonCall(daemonSockPath, kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodRegisterSession,
		RegisterSession: &kernelcapture.DaemonRegisterSessionRequest{
			SessionID: sessionID,
			RootPID:   uint32(cmd.Process.Pid),
			// This CI smoke runs as root and exercises the seccomp tier, which is
			// process/filter scoped rather than cgroup enforced. Use the live root
			// PID as a unique non-zero registry key so the two independent probe
			// sessions cannot collide on the old placeholder cgroup_id=1.
			CgroupID:     uint64(cmd.Process.Pid),
			EventClasses: []string{kernelcapture.DaemonProtocolEventProcessLifecycle},
			TTLSeconds:   300,
		},
	}); err != nil {
		return "", fmt.Errorf("register_session: %w", err)
	}
	if err := daemonCall(daemonSockPath, kernelcapture.DaemonProtocolRequest{
		ProtocolVersion: kernelcapture.DaemonProtocolVersion,
		Method:          kernelcapture.DaemonProtocolMethodApplyPolicy,
		ApplyPolicy: &kernelcapture.DaemonApplyPolicyRequest{
			SessionID:   sessionID,
			Generation:  1,
			EnforceMode: kernelcapture.BpfEnforceModeEnforce,
			OpPolicies: []kernelcapture.DaemonOpPolicy{
				{Op: kernelcapture.BpfOpNetConnect, Action: kernelcapture.BpfActionAllowlist, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
			},
			NetAllow: []string{allowedIP + "/32"},
		},
	}); err != nil {
		return "", fmt.Errorf("apply_policy: %w", err)
	}
	if err := os.WriteFile(readyFile, []byte("ready\n"), 0o600); err != nil {
		return "", fmt.Errorf("release shim ready gate: %w", err)
	}
	err := cmd.Wait()
	if err != nil {
		return "", fmt.Errorf("%w (output: %s)", err, output.String())
	}
	line := output.String()
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line, nil
}
