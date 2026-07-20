//go:build linux

package kernelcapture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	benchmarkFingerprintRegistryVersion            = "ardur.benchmark-agent-fingerprint.2026-07-14.v1"
	agentRecognitionBenchmarkFingerprintLogMessage = "AI agent executable fingerprint observed"
	agentRecognitionBenchmarkMaxDaemonLogBytes     = 16 << 20
)

type agentRecognitionBenchmarkDaemon struct {
	command *exec.Cmd
	wait    chan error
	done    bool
	waitErr error
	socket  string
	logFile *os.File
}

type agentRecognitionBenchmarkSnapshot struct {
	capture        DaemonLifecycleCaptureHealth
	recognition    AgentRecognitionHealth
	fingerprint    AgentFingerprintHealth
	hasRecognition bool
	hasFingerprint bool
}

func RunAgentRecognitionBenchmark(ctx context.Context, opts AgentRecognitionBenchmarkOptions) (*AgentRecognitionBenchmarkReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := normalizeAgentRecognitionBenchmarkOptions(&opts); err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("%w: real-Linux benchmark requires effective uid 0", ErrAgentRecognitionBenchmark)
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return nil, fmt.Errorf("%w: Linux BTF is unavailable", ErrAgentRecognitionBenchmark)
	}
	if !agentRecognitionBenchmarkTracefsAvailable() {
		return nil, fmt.Errorf("%w: Linux tracefs is unavailable", ErrAgentRecognitionBenchmark)
	}
	root, err := os.MkdirTemp("", "ardur-agent-recognition-benchmark-")
	if err != nil {
		return nil, fmt.Errorf("%w: create private benchmark workspace", ErrAgentRecognitionBenchmark)
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("%w: secure private benchmark workspace", ErrAgentRecognitionBenchmark)
	}

	daemonPath := filepath.Join(root, "ardur-kernelcaptured-current")
	daemonSHA256, err := copyBenchmarkExecutable(opts.DaemonPath, daemonPath)
	if err != nil {
		return nil, err
	}
	referenceDaemonPath := filepath.Join(root, "ardur-kernelcaptured-reference")
	referenceDaemonSHA256, err := copyBenchmarkExecutable(opts.ReferenceDaemonPath, referenceDaemonPath)
	if err != nil {
		return nil, err
	}
	opts.DaemonPath = daemonPath
	opts.ReferenceDaemonPath = referenceDaemonPath

	workloadPath := filepath.Join(root, "codex")
	workloadSHA256, err := copyBenchmarkExecutable(opts.WorkloadExecutablePath, workloadPath)
	if err != nil {
		return nil, err
	}
	calibration, err := calibrateAgentRecognitionBenchmarkProcessCPU(ctx, workloadPath, workloadSHA256)
	if err != nil {
		return nil, err
	}
	registry, registryPath, err := writeBenchmarkFingerprintRegistry(root, workloadSHA256)
	if err != nil {
		return nil, err
	}

	report := &AgentRecognitionBenchmarkReport{
		SchemaVersion:         AgentRecognitionBenchmarkReportSchema,
		GeneratedAt:           time.Now().UTC().Format(time.RFC3339Nano),
		SourceSHA:             opts.SourceSHA,
		ReferenceSourceSHA:    opts.ReferenceSourceSHA,
		Seed:                  opts.Seed,
		WarmupPairs:           opts.WarmupPairs,
		MeasuredPairs:         opts.MeasuredPairs,
		PairOrder:             "deterministic_six_arm_order_rotation",
		Environment:           agentRecognitionBenchmarkEnvironment(opts.RunnerImageOS, opts.RunnerImageVersion),
		DaemonSHA256:          daemonSHA256,
		ReferenceDaemonSHA256: referenceDaemonSHA256,
		WorkloadSHA256:        workloadSHA256,
		RegistryVersion:       registry.version,
		RegistrySHA256:        registry.digest,
		Calibration:           calibration,
		Limitations: []string{
			"Paired host evidence does not establish a universal recognition-overhead percentage.",
			"Shared-runner scheduling and CPU-frequency variation remain outside the daemon's control.",
			"The same-VM CPU comparison detects change relative to one exact reference revision, not an absolute capacity limit.",
			"The workload uses one deterministic native executable shape and does not estimate population accuracy.",
			"Recognition and fingerprinting remain observe-only and do not attest identity or authorize governance.",
			"The benchmark requires an isolated disposable host because the daemon uses a host-global bpffs pin namespace.",
		},
	}

	for warmup := 0; warmup < opts.WarmupPairs; warmup++ {
		if _, err := runAgentRecognitionBenchmarkPair(ctx, root, -(warmup + 1), opts, workloadPath, registryPath, registry.digest); err != nil {
			return nil, err
		}
	}
	for pairIndex := 0; pairIndex < opts.MeasuredPairs; pairIndex++ {
		pairs, err := runAgentRecognitionBenchmarkPair(ctx, root, pairIndex, opts, workloadPath, registryPath, registry.digest)
		if err != nil {
			return nil, err
		}
		report.Pairs = append(report.Pairs, pairs...)
	}
	return report, nil
}

func normalizeAgentRecognitionBenchmarkOptions(opts *AgentRecognitionBenchmarkOptions) error {
	if opts == nil || !isHexDigest(opts.SourceSHA, 40) || !isHexDigest(opts.ReferenceSourceSHA, 40) {
		return fmt.Errorf("%w: exact 40-character source and reference SHAs are required", ErrAgentRecognitionBenchmark)
	}
	if opts.Seed == 0 {
		opts.Seed = 302
	}
	if opts.WarmupPairs == 0 {
		opts.WarmupPairs = 1
	}
	if opts.MeasuredPairs == 0 {
		opts.MeasuredPairs = MinAgentRecognitionBenchmarkPairs
	}
	if opts.ArmStartupTimeout <= 0 {
		opts.ArmStartupTimeout = 10 * time.Second
	}
	if opts.AccountingTimeout <= 0 {
		opts.AccountingTimeout = 5 * time.Second
	}
	if len(opts.Profiles) == 0 {
		opts.Profiles = DefaultAgentRecognitionBenchmarkProfiles()
	}
	opts.RunnerImageOS = safeBenchmarkHostText(opts.RunnerImageOS)
	opts.RunnerImageVersion = safeBenchmarkHostText(opts.RunnerImageVersion)
	if opts.WarmupPairs < 1 || opts.WarmupPairs > 10 || opts.MeasuredPairs < MinAgentRecognitionBenchmarkPairs || opts.MeasuredPairs > 100 || opts.ArmStartupTimeout > time.Minute || opts.AccountingTimeout > time.Minute {
		return fmt.Errorf("%w: benchmark sample or timeout bounds are invalid", ErrAgentRecognitionBenchmark)
	}
	if len(opts.Profiles) != 3 {
		return fmt.Errorf("%w: low, sustained, and storm profiles are required", ErrAgentRecognitionBenchmark)
	}
	seen := make(map[string]struct{}, len(opts.Profiles))
	for _, profile := range opts.Profiles {
		if err := validateAgentRecognitionBenchmarkProfile(profile); err != nil {
			return err
		}
		seen[profile.Name] = struct{}{}
	}
	for _, name := range []string{"low", "sustained", "storm"} {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("%w: low, sustained, and storm profiles are required", ErrAgentRecognitionBenchmark)
		}
	}
	for _, path := range []string{opts.DaemonPath, opts.ReferenceDaemonPath, opts.WorkloadExecutablePath} {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("%w: benchmark executable paths must be absolute", ErrAgentRecognitionBenchmark)
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&0o111 == 0 {
			return fmt.Errorf("%w: benchmark executable must be a non-symlink executable regular file", ErrAgentRecognitionBenchmark)
		}
	}
	return nil
}

func runAgentRecognitionBenchmarkPair(ctx context.Context, root string, pairIndex int, opts AgentRecognitionBenchmarkOptions, workloadPath, registryPath, registrySHA256 string) ([]AgentRecognitionBenchmarkPair, error) {
	order := agentRecognitionBenchmarkReferenceOrder(pairIndex, opts.Seed)
	pairRoot, err := os.MkdirTemp(root, "pair-")
	if err != nil {
		return nil, fmt.Errorf("%w: create pair workspace", ErrAgentRecognitionBenchmark)
	}
	sequences := map[string][]string{
		"baseline_then_reference_then_enabled": {"baseline", "reference", "enabled"},
		"baseline_then_enabled_then_reference": {"baseline", "enabled", "reference"},
		"reference_then_baseline_then_enabled": {"reference", "baseline", "enabled"},
		"reference_then_enabled_then_baseline": {"reference", "enabled", "baseline"},
		"enabled_then_baseline_then_reference": {"enabled", "baseline", "reference"},
		"enabled_then_reference_then_baseline": {"enabled", "reference", "baseline"},
	}
	arms := make(map[string]map[string]AgentRecognitionBenchmarkArm, 3)
	for _, armName := range sequences[order] {
		armOptions := opts
		enabled := armName != "baseline"
		if armName == "reference" {
			armOptions.DaemonPath = opts.ReferenceDaemonPath
		}
		arm, armErr := runAgentRecognitionBenchmarkArm(ctx, filepath.Join(pairRoot, armName), armOptions, workloadPath, registryPath, registrySHA256, enabled)
		if armErr != nil {
			return nil, armErr
		}
		arms[armName] = arm
	}
	pairs := make([]AgentRecognitionBenchmarkPair, 0, len(opts.Profiles))
	for _, profile := range opts.Profiles {
		pair, err := NewAgentRecognitionBenchmarkReferencePair(pairIndex, order, profile, arms["baseline"][profile.Name], arms["reference"][profile.Name], arms["enabled"][profile.Name])
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, pair)
	}
	return pairs, nil
}

func runAgentRecognitionBenchmarkArm(ctx context.Context, root string, opts AgentRecognitionBenchmarkOptions, workloadPath, registryPath, registrySHA256 string, enabled bool) (map[string]AgentRecognitionBenchmarkArm, error) {
	runtimeRoot, err := makeAgentRecognitionBenchmarkCustodyDir("/run/ardur")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(runtimeRoot)
	stateRoot, err := makeAgentRecognitionBenchmarkCustodyDir("/var/lib/ardur")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stateRoot)

	for _, directory := range []string{root, filepath.Join(stateRoot, "evidence"), filepath.Join(root, "home"), filepath.Join(root, "tmp")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, fmt.Errorf("%w: create private daemon directory", ErrAgentRecognitionBenchmark)
		}
	}
	daemon, err := startAgentRecognitionBenchmarkDaemon(ctx, root, runtimeRoot, stateRoot, opts, registryPath, registrySHA256, enabled)
	if err != nil {
		return nil, err
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = daemon.stop()
		}
	}()

	results := make(map[string]AgentRecognitionBenchmarkArm, len(opts.Profiles))
	expectedFingerprintObservations := uint64(0)
	for _, profile := range opts.Profiles {
		before, err := daemon.snapshot(enabled, registrySHA256)
		if err != nil {
			return nil, err
		}
		if err := resetProcessPeakRSSKiB(daemon.command.Process.Pid); err != nil {
			return nil, err
		}
		cpuBefore, err := readProcessSchedstatNanoseconds(daemon.command.Process.Pid)
		if err != nil {
			return nil, err
		}
		completed, workloadElapsed, err := runAgentRecognitionBenchmarkWorkload(ctx, workloadPath, filepath.Join(root, "tmp"), profile)
		if err != nil {
			return nil, err
		}
		settleStarted := time.Now()
		after, err := daemon.waitForAccounting(enabled, registrySHA256, before, uint64(profile.EventCount), opts.AccountingTimeout)
		if err != nil {
			return nil, err
		}
		if enabled {
			profileObservations := uint64(profile.EventCount)
			if ^uint64(0)-expectedFingerprintObservations < profileObservations {
				return nil, fmt.Errorf("%w: cumulative fingerprint observation count overflowed", ErrAgentRecognitionBenchmark)
			}
			expectedFingerprintObservations += profileObservations
		}
		if err := daemon.waitForFingerprintObservationLogs(ctx, expectedFingerprintObservations, opts.AccountingTimeout); err != nil {
			return nil, err
		}
		after, err = daemon.snapshot(enabled, registrySHA256)
		if err != nil {
			return nil, err
		}
		settled, err := agentRecognitionBenchmarkAccountingSettled(enabled, before, after, uint64(profile.EventCount))
		if err != nil {
			return nil, err
		}
		if !settled {
			return nil, fmt.Errorf("%w: daemon accounting changed after observation publication", ErrAgentRecognitionBenchmark)
		}
		settleElapsed := time.Since(settleStarted)
		cpuAfter, err := readProcessSchedstatNanoseconds(daemon.command.Process.Pid)
		if err != nil {
			return nil, err
		}
		if cpuAfter < cpuBefore {
			return nil, fmt.Errorf("%w: daemon CPU counter moved backwards across the measured arm", ErrAgentRecognitionBenchmark)
		}
		peakRSS, err := readProcessPeakRSSKiB(daemon.command.Process.Pid)
		if err != nil {
			return nil, err
		}
		arm, err := buildAgentRecognitionBenchmarkArm(enabled, profile, completed, workloadElapsed, settleElapsed, cpuAfter-cpuBefore, peakRSS, before, after)
		if err != nil {
			return nil, err
		}
		results[profile.Name] = arm
	}
	if err := daemon.stop(); err != nil {
		return nil, err
	}
	stopped = true
	return results, nil
}

func startAgentRecognitionBenchmarkDaemon(ctx context.Context, root, runtimeRoot, stateRoot string, opts AgentRecognitionBenchmarkOptions, registryPath, registrySHA256 string, enabled bool) (*agentRecognitionBenchmarkDaemon, error) {
	socket := filepath.Join(runtimeRoot, "control.sock")
	arguments := []string{
		"--socket", socket,
		"--seccomp-socket", filepath.Join(runtimeRoot, "seccomp.sock"),
		"--evidence-dir", filepath.Join(stateRoot, "evidence"),
		"--state-dir", stateRoot,
		"--disable-bpf-lsm",
		"--prune-interval", "1h",
	}
	if enabled {
		arguments = append(arguments,
			"--agent-recognition",
			"--agent-recognition-allow", "codex_cli",
			"--agent-recognition-fingerprint-registry", registryPath,
		)
	}
	logPath := filepath.Join(root, "daemon.jsonl")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: create private daemon log", ErrAgentRecognitionBenchmark)
	}
	command := exec.Command(opts.DaemonPath, arguments...)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = logFile
	command.Dir = root
	command.Env = []string{"HOME=" + filepath.Join(root, "home"), "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "TMPDIR=" + filepath.Join(root, "tmp")}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("%w: daemon failed to start", ErrAgentRecognitionBenchmark)
	}
	daemon := &agentRecognitionBenchmarkDaemon{command: command, wait: make(chan error, 1), socket: socket, logFile: logFile}
	go func() {
		err := command.Wait()
		_ = logFile.Close()
		daemon.wait <- err
	}()
	deadline := time.NewTimer(opts.ArmStartupTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = daemon.stop()
			return nil, fmt.Errorf("%w: benchmark context ended during daemon startup", ErrAgentRecognitionBenchmark)
		case err := <-daemon.wait:
			daemon.done, daemon.waitErr = true, err
			return nil, fmt.Errorf("%w: daemon exited during startup", ErrAgentRecognitionBenchmark)
		case <-deadline.C:
			_ = daemon.stop()
			return nil, fmt.Errorf("%w: daemon startup timed out", ErrAgentRecognitionBenchmark)
		case <-ticker.C:
			snapshot, snapshotErr := daemon.snapshot(enabled, registrySHA256)
			if snapshotErr == nil && snapshot.capture.ProducerCounterAvailable && !snapshot.capture.ProducerCounterEvidenceGap {
				return daemon, nil
			}
		}
	}
}

func makeAgentRecognitionBenchmarkCustodyDir(base string) (string, error) {
	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", fmt.Errorf("%w: prepare daemon custody root", ErrAgentRecognitionBenchmark)
	}
	info, err := os.Lstat(base)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("%w: daemon custody root is not a protected directory", ErrAgentRecognitionBenchmark)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return "", fmt.Errorf("%w: daemon custody root is not root-owned", ErrAgentRecognitionBenchmark)
	}
	directory, err := os.MkdirTemp(base, "agent-recognition-benchmark-")
	if err != nil {
		return "", fmt.Errorf("%w: create private daemon custody directory", ErrAgentRecognitionBenchmark)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		return "", fmt.Errorf("%w: secure private daemon custody directory", ErrAgentRecognitionBenchmark)
	}
	return directory, nil
}

func (d *agentRecognitionBenchmarkDaemon) snapshot(enabled bool, registrySHA256 string) (agentRecognitionBenchmarkSnapshot, error) {
	if d == nil || d.done {
		return agentRecognitionBenchmarkSnapshot{}, fmt.Errorf("%w: daemon is not running", ErrAgentRecognitionBenchmark)
	}
	response, err := SendDaemonHealthRequest(d.socket)
	if err != nil || !response.OK || response.LifecycleCaptureHealth == nil {
		return agentRecognitionBenchmarkSnapshot{}, fmt.Errorf("%w: authenticated daemon health is unavailable", ErrAgentRecognitionBenchmark)
	}
	snapshot := agentRecognitionBenchmarkSnapshot{capture: *response.LifecycleCaptureHealth}
	if enabled {
		if response.AgentRecognition == nil || response.AgentFingerprint == nil || !response.AgentRecognition.Enabled || !response.AgentFingerprint.Enabled || response.AgentRecognition.RegistrySHA256 == "" || response.AgentFingerprint.RegistrySHA256 != registrySHA256 {
			return agentRecognitionBenchmarkSnapshot{}, fmt.Errorf("%w: enabled daemon recognition health is incomplete", ErrAgentRecognitionBenchmark)
		}
		snapshot.recognition = *response.AgentRecognition
		snapshot.fingerprint = *response.AgentFingerprint
		snapshot.hasRecognition = true
		snapshot.hasFingerprint = true
	} else {
		if response.AgentRecognition == nil || response.AgentRecognition.Enabled || response.AgentRecognition.RegistryVersion != "" || response.AgentRecognition.RegistrySHA256 != "" || response.AgentFingerprint != nil {
			return agentRecognitionBenchmarkSnapshot{}, fmt.Errorf("%w: baseline daemon recognition health is incomplete or enabled", ErrAgentRecognitionBenchmark)
		}
		snapshot.recognition = *response.AgentRecognition
	}
	return snapshot, nil
}

func (d *agentRecognitionBenchmarkDaemon) waitForAccounting(enabled bool, registrySHA256 string, before agentRecognitionBenchmarkSnapshot, expected uint64, timeout time.Duration) (agentRecognitionBenchmarkSnapshot, error) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		after, err := d.snapshot(enabled, registrySHA256)
		if err == nil {
			settled, settleErr := agentRecognitionBenchmarkAccountingSettled(enabled, before, after, expected)
			if settleErr != nil {
				return agentRecognitionBenchmarkSnapshot{}, settleErr
			}
			if settled {
				return after, nil
			}
		}
		select {
		case <-deadline.C:
			return agentRecognitionBenchmarkSnapshot{}, fmt.Errorf("%w: daemon accounting did not settle", ErrAgentRecognitionBenchmark)
		case <-ticker.C:
		}
	}
}

func agentRecognitionBenchmarkAccountingSettled(enabled bool, before, after agentRecognitionBenchmarkSnapshot, expected uint64) (bool, error) {
	capture, err := deltaCaptureHealth(before.capture, after.capture)
	if err != nil {
		return false, err
	}
	if !enabled {
		recognition, recognitionErr := deltaRecognitionCounters(before.recognition.Counters, after.recognition.Counters)
		if recognitionErr != nil {
			return false, fmt.Errorf("%w: baseline recognition counter moved backwards", ErrAgentRecognitionBenchmark)
		}
		if capture.Delivered == 0 && capture.ProducerDropped == 0 && capture.Malformed == 0 && recognition == (AgentRecognitionCounters{}) {
			return true, nil
		}
		return false, fmt.Errorf("%w: baseline observed recognition-filtered work", ErrAgentRecognitionBenchmark)
	}
	candidateDelta, candidateErr := deltaRecognitionCounters(before.recognition.Counters, after.recognition.Counters)
	fingerprint, fingerprintErr := deltaFingerprintCounters(before.fingerprint.Counters, after.fingerprint.Counters)
	if candidateErr != nil || fingerprintErr != nil {
		return false, fmt.Errorf("%w: daemon accounting counter moved backwards", ErrAgentRecognitionBenchmark)
	}
	captureTotal, captureTotalOK := sumAgentRecognitionBenchmarkCounters(capture.Delivered, capture.ProducerDropped, capture.Malformed)
	terminal, terminalOK := sumAgentRecognitionBenchmarkCounters(fingerprint.Success, fingerprint.Mismatch, fingerprint.Saturated, fingerprint.Unavailable)
	classified, classifiedOK := sumAgentRecognitionBenchmarkCounters(candidateDelta.Recognized, candidateDelta.Ambiguous)
	if !captureTotalOK || !terminalOK || !classifiedOK {
		return false, fmt.Errorf("%w: daemon accounting counter overflowed", ErrAgentRecognitionBenchmark)
	}
	if captureTotal > expected || candidateDelta.CandidatesTotal > capture.Delivered || classified > candidateDelta.CandidatesTotal || terminal > candidateDelta.Recognized {
		return false, fmt.Errorf("%w: daemon accounting exceeded produced work", ErrAgentRecognitionBenchmark)
	}
	return captureTotal == expected && candidateDelta.CandidatesTotal == capture.Delivered && classified == candidateDelta.CandidatesTotal && terminal == candidateDelta.Recognized && after.fingerprint.QueueDepth == 0, nil
}

func buildAgentRecognitionBenchmarkArm(enabled bool, profile AgentRecognitionBenchmarkProfile, completed int, workloadElapsed, settleElapsed time.Duration, daemonCPU, peakRSS uint64, before, after agentRecognitionBenchmarkSnapshot) (AgentRecognitionBenchmarkArm, error) {
	capture, err := deltaCaptureHealth(before.capture, after.capture)
	if err != nil {
		return AgentRecognitionBenchmarkArm{}, err
	}
	expected := uint64(0)
	arm := AgentRecognitionBenchmarkArm{
		RecognitionEnabled:          enabled,
		WorkloadCompletions:         completed,
		WorkloadElapsedNanoseconds:  uint64(workloadElapsed.Nanoseconds()),
		AccountingSettleNanoseconds: uint64(settleElapsed.Nanoseconds()),
		DaemonCPUNanoseconds:        daemonCPU,
		DaemonPeakRSSKiB:            peakRSS,
		DaemonHealthy:               after.capture.ProducerCounterAvailable && !after.capture.ProducerCounterEvidenceGap,
	}
	if enabled {
		expected = uint64(profile.EventCount)
		arm.RegistryVersion = after.fingerprint.RegistryVersion
		arm.RegistrySHA256 = after.fingerprint.RegistrySHA256
		recognition, err := deltaRecognitionCounters(before.recognition.Counters, after.recognition.Counters)
		if err != nil {
			return AgentRecognitionBenchmarkArm{}, err
		}
		fingerprint, err := deltaFingerprintCounters(before.fingerprint.Counters, after.fingerprint.Counters)
		if err != nil {
			return AgentRecognitionBenchmarkArm{}, err
		}
		arm.Recognition = AgentRecognitionBenchmarkRecognitionLedger{
			Candidates: recognition.CandidatesTotal,
			Recognized: recognition.Recognized,
			Rejected:   recognition.Ambiguous,
		}
		classified, classifiedOK := sumAgentRecognitionBenchmarkCounters(arm.Recognition.Recognized, arm.Recognition.Rejected)
		if !classifiedOK {
			return AgentRecognitionBenchmarkArm{}, fmt.Errorf("%w: recognition accounting counter overflowed", ErrAgentRecognitionBenchmark)
		}
		if classified <= arm.Recognition.Candidates {
			arm.Recognition.Unexplained = arm.Recognition.Candidates - classified
		} else {
			return AgentRecognitionBenchmarkArm{}, fmt.Errorf("%w: recognition accounting exceeded candidates", ErrAgentRecognitionBenchmark)
		}
		arm.Fingerprint = fingerprint
		arm.Fingerprint.Recognized = recognition.Recognized
		terminal, terminalOK := sumAgentRecognitionBenchmarkCounters(fingerprint.Success, fingerprint.Mismatch, fingerprint.Saturated, fingerprint.Unavailable)
		if !terminalOK {
			return AgentRecognitionBenchmarkArm{}, fmt.Errorf("%w: fingerprint accounting counter overflowed", ErrAgentRecognitionBenchmark)
		}
		if terminal <= recognition.Recognized {
			arm.Fingerprint.InFlight = recognition.Recognized - terminal
		} else {
			arm.Fingerprint.Unexplained = terminal - recognition.Recognized
		}
	}
	arm.Capture = capture
	arm.Capture.ExpectedEvents = expected
	accounted, accountedOK := sumAgentRecognitionBenchmarkCounters(capture.Delivered, capture.ProducerDropped, capture.Malformed)
	if !accountedOK {
		return AgentRecognitionBenchmarkArm{}, fmt.Errorf("%w: capture accounting counter overflowed", ErrAgentRecognitionBenchmark)
	}
	if accounted <= expected {
		arm.Capture.Unexplained = expected - accounted
	} else {
		return AgentRecognitionBenchmarkArm{}, fmt.Errorf("%w: capture accounting exceeded expected work", ErrAgentRecognitionBenchmark)
	}
	return arm, nil
}

func agentRecognitionBenchmarkTracefsAvailable() bool {
	for _, path := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		var stat unix.Statfs_t
		if err := unix.Statfs(path, &stat); err == nil && uint64(stat.Type) == uint64(unix.TRACEFS_MAGIC) {
			return true
		}
	}
	return false
}

func deltaCaptureHealth(before, after DaemonLifecycleCaptureHealth) (AgentRecognitionBenchmarkCaptureLedger, error) {
	if after.DeliveredTotal < before.DeliveredTotal || after.ProducerRingbufDroppedTotal < before.ProducerRingbufDroppedTotal || after.MalformedRecordsTotal < before.MalformedRecordsTotal || !after.ProducerCounterAvailable || after.ProducerCounterEvidenceGap {
		return AgentRecognitionBenchmarkCaptureLedger{}, fmt.Errorf("%w: lifecycle capture health is incomplete or moved backwards", ErrAgentRecognitionBenchmark)
	}
	return AgentRecognitionBenchmarkCaptureLedger{
		Delivered:       after.DeliveredTotal - before.DeliveredTotal,
		ProducerDropped: after.ProducerRingbufDroppedTotal - before.ProducerRingbufDroppedTotal,
		Malformed:       after.MalformedRecordsTotal - before.MalformedRecordsTotal,
	}, nil
}

func deltaRecognitionCounters(before, after AgentRecognitionCounters) (AgentRecognitionCounters, error) {
	if after.CandidatesTotal < before.CandidatesTotal || after.Recognized < before.Recognized || after.Ambiguous < before.Ambiguous {
		return AgentRecognitionCounters{}, fmt.Errorf("%w: recognition counter moved backwards", ErrAgentRecognitionBenchmark)
	}
	return AgentRecognitionCounters{CandidatesTotal: after.CandidatesTotal - before.CandidatesTotal, Recognized: after.Recognized - before.Recognized, Ambiguous: after.Ambiguous - before.Ambiguous}, nil
}

func deltaFingerprintCounters(before, after AgentFingerprintCounters) (AgentRecognitionBenchmarkFingerprintLedger, error) {
	if after.QueueSaturated < before.QueueSaturated || after.ResolutionDenied < before.ResolutionDenied || after.ProcessExited < before.ProcessExited || after.Unsupported < before.Unsupported || after.SizeExceeded < before.SizeExceeded || after.DeadlineExceeded < before.DeadlineExceeded || after.DigestMismatch < before.DigestMismatch || after.Success < before.Success || after.WorkerUnavailable < before.WorkerUnavailable {
		return AgentRecognitionBenchmarkFingerprintLedger{}, fmt.Errorf("%w: fingerprint counter moved backwards", ErrAgentRecognitionBenchmark)
	}
	resolutionDenied := after.ResolutionDenied - before.ResolutionDenied
	processExited := after.ProcessExited - before.ProcessExited
	unsupported := after.Unsupported - before.Unsupported
	sizeExceeded := after.SizeExceeded - before.SizeExceeded
	deadlineExceeded := after.DeadlineExceeded - before.DeadlineExceeded
	workerUnavailable := after.WorkerUnavailable - before.WorkerUnavailable
	unavailable, ok := sumAgentRecognitionBenchmarkCounters(resolutionDenied, processExited, unsupported, sizeExceeded, deadlineExceeded, workerUnavailable)
	if !ok {
		return AgentRecognitionBenchmarkFingerprintLedger{}, fmt.Errorf("%w: fingerprint unavailable counter overflowed", ErrAgentRecognitionBenchmark)
	}
	return AgentRecognitionBenchmarkFingerprintLedger{
		Success:           after.Success - before.Success,
		Mismatch:          after.DigestMismatch - before.DigestMismatch,
		Saturated:         after.QueueSaturated - before.QueueSaturated,
		Unavailable:       unavailable,
		ResolutionDenied:  resolutionDenied,
		ProcessExited:     processExited,
		Unsupported:       unsupported,
		SizeExceeded:      sizeExceeded,
		DeadlineExceeded:  deadlineExceeded,
		WorkerUnavailable: workerUnavailable,
	}, nil
}

func runAgentRecognitionBenchmarkWorkload(ctx context.Context, executable, root string, profile AgentRecognitionBenchmarkProfile) (int, time.Duration, error) {
	started := time.Now()
	semaphore := make(chan struct{}, profile.Concurrency)
	results := make(chan error, profile.EventCount)
	for index := 0; index < profile.EventCount; index++ {
		select {
		case semaphore <- struct{}{}:
		case <-ctx.Done():
			return 0, 0, fmt.Errorf("%w: benchmark context ended during workload", ErrAgentRecognitionBenchmark)
		}
		go func() {
			defer func() { <-semaphore }()
			command := exec.CommandContext(ctx, executable, "--workload-hold-milliseconds", strconv.Itoa(profile.HoldMilliseconds))
			command.Stdin = nil
			command.Stdout = io.Discard
			command.Stderr = io.Discard
			command.Dir = root
			command.Env = []string{"HOME=" + root, "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "TMPDIR=" + root}
			command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
			results <- command.Run()
		}()
		if profile.InterArrivalMicroseconds > 0 && index+1 < profile.EventCount {
			timer := time.NewTimer(time.Duration(profile.InterArrivalMicroseconds) * time.Microsecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return 0, 0, fmt.Errorf("%w: benchmark context ended during workload pacing", ErrAgentRecognitionBenchmark)
			}
		}
	}
	completed := 0
	for range profile.EventCount {
		if err := <-results; err != nil {
			return completed, 0, fmt.Errorf("%w: deterministic workload process failed", ErrAgentRecognitionBenchmark)
		}
		completed++
	}
	return completed, time.Since(started), nil
}

func (d *agentRecognitionBenchmarkDaemon) stop() error {
	if d == nil || d.done {
		if d != nil && d.waitErr != nil {
			return fmt.Errorf("%w: daemon exited unexpectedly", ErrAgentRecognitionBenchmark)
		}
		return nil
	}
	_ = syscall.Kill(-d.command.Process.Pid, syscall.SIGTERM)
	select {
	case err := <-d.wait:
		d.done, d.waitErr = true, err
		if err != nil {
			return fmt.Errorf("%w: daemon shutdown failed", ErrAgentRecognitionBenchmark)
		}
		return nil
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-d.command.Process.Pid, syscall.SIGKILL)
		err := <-d.wait
		d.done, d.waitErr = true, err
		return fmt.Errorf("%w: daemon shutdown timed out", ErrAgentRecognitionBenchmark)
	}
}

func copyBenchmarkExecutable(source, destination string) (string, error) {
	inputFD, err := unix.Open(source, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", fmt.Errorf("%w: open benchmark executable", ErrAgentRecognitionBenchmark)
	}
	input := os.NewFile(uintptr(inputFD), source)
	if input == nil {
		_ = unix.Close(inputFD)
		return "", fmt.Errorf("%w: open benchmark executable", ErrAgentRecognitionBenchmark)
	}
	defer input.Close()
	inputInfo, err := input.Stat()
	if err != nil || !inputInfo.Mode().IsRegular() || inputInfo.Mode()&0o111 == 0 || inputInfo.Size() <= 0 || inputInfo.Size() > DefaultAgentFingerprintMaxFileBytes {
		return "", fmt.Errorf("%w: benchmark executable is outside the bounded regular-file contract", ErrAgentRecognitionBenchmark)
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return "", fmt.Errorf("%w: create private workload executable", ErrAgentRecognitionBenchmark)
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(output, hasher), io.LimitReader(input, DefaultAgentFingerprintMaxFileBytes+1))
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		return "", fmt.Errorf("%w: copy workload executable", ErrAgentRecognitionBenchmark)
	}
	info, err := os.Stat(destination)
	if err != nil || info.Size() != inputInfo.Size() || info.Size() <= 0 || info.Size() > DefaultAgentFingerprintMaxFileBytes {
		return "", fmt.Errorf("%w: benchmark executable exceeds fingerprint bounds", ErrAgentRecognitionBenchmark)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func writeBenchmarkFingerprintRegistry(root, workloadSHA256 string) (*AgentFingerprintRegistry, string, error) {
	document := AgentFingerprintRegistryDocument{
		SchemaVersion:   AgentFingerprintRegistrySchema,
		RegistryVersion: benchmarkFingerprintRegistryVersion,
		Rules:           []AgentFingerprintRule{{RuleID: "benchmark.codex.native", AgentType: "codex_cli", ExpectedSHA256: []string{workloadSHA256}}},
	}
	registry, err := NewAgentFingerprintRegistry(document)
	if err != nil {
		return nil, "", fmt.Errorf("%w: construct benchmark fingerprint registry", ErrAgentRecognitionBenchmark)
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, "", fmt.Errorf("%w: encode benchmark fingerprint registry", ErrAgentRecognitionBenchmark)
	}
	path := filepath.Join(root, "fingerprint-registry.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return nil, "", fmt.Errorf("%w: write benchmark fingerprint registry", ErrAgentRecognitionBenchmark)
	}
	return registry, path, nil
}

func readProcessSchedstatNanoseconds(pid int) (uint64, error) {
	tasksRoot := filepath.Join("/proc", strconv.Itoa(pid), "task")
	tasks, err := os.ReadDir(tasksRoot)
	if err != nil {
		return 0, fmt.Errorf("%w: daemon CPU metric is unavailable", ErrAgentRecognitionBenchmark)
	}
	var total uint64
	observed := 0
	for _, task := range tasks {
		if !task.IsDir() {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(tasksRoot, task.Name(), "schedstat"))
		if readErr != nil {
			if os.IsNotExist(readErr) {
				continue
			}
			return 0, fmt.Errorf("%w: daemon CPU metric is unavailable", ErrAgentRecognitionBenchmark)
		}
		value, parseErr := parseSchedstatRuntimeNanoseconds(raw)
		if parseErr != nil || ^uint64(0)-total < value {
			return 0, fmt.Errorf("%w: daemon CPU metric is malformed", ErrAgentRecognitionBenchmark)
		}
		total += value
		observed++
	}
	if observed == 0 {
		return 0, fmt.Errorf("%w: daemon CPU metric is unavailable", ErrAgentRecognitionBenchmark)
	}
	return total, nil
}

func (d *agentRecognitionBenchmarkDaemon) waitForFingerprintObservationLogs(ctx context.Context, expected uint64, timeout time.Duration) error {
	if d == nil || d.logFile == nil || timeout <= 0 {
		return fmt.Errorf("%w: daemon observation log barrier is unavailable", ErrAgentRecognitionBenchmark)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: benchmark context ended before observation publication", ErrAgentRecognitionBenchmark)
	}
	deadlineAt := time.Now().Add(timeout)
	deadline := time.NewTimer(time.Until(deadlineAt))
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		observed, complete, err := countAgentRecognitionBenchmarkFingerprintLogs(d.logFile)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w: benchmark context ended before observation publication", ErrAgentRecognitionBenchmark)
		}
		if !time.Now().Before(deadlineAt) {
			return fmt.Errorf("%w: daemon fingerprint observations did not settle", ErrAgentRecognitionBenchmark)
		}
		if complete && observed > expected {
			return fmt.Errorf("%w: daemon published more fingerprint observations than produced work", ErrAgentRecognitionBenchmark)
		}
		if complete && observed == expected {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: benchmark context ended before observation publication", ErrAgentRecognitionBenchmark)
		case <-deadline.C:
			return fmt.Errorf("%w: daemon fingerprint observations did not settle", ErrAgentRecognitionBenchmark)
		case <-ticker.C:
		}
	}
}

func countAgentRecognitionBenchmarkFingerprintLogs(file *os.File) (uint64, bool, error) {
	if file == nil {
		return 0, false, fmt.Errorf("%w: daemon observation log is unavailable", ErrAgentRecognitionBenchmark)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > agentRecognitionBenchmarkMaxDaemonLogBytes {
		return 0, false, fmt.Errorf("%w: daemon observation log is unavailable or outside bounds", ErrAgentRecognitionBenchmark)
	}
	raw := make([]byte, int(info.Size()))
	if len(raw) > 0 {
		n, readErr := file.ReadAt(raw, 0)
		if readErr != nil || n != len(raw) {
			return 0, false, fmt.Errorf("%w: daemon observation log is unreadable", ErrAgentRecognitionBenchmark)
		}
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || after.Size() < 0 || after.Size() > agentRecognitionBenchmarkMaxDaemonLogBytes {
		return 0, false, fmt.Errorf("%w: daemon observation log is unavailable or outside bounds", ErrAgentRecognitionBenchmark)
	}
	if after.Size() != info.Size() {
		return 0, false, nil
	}
	lines := bytes.Split(raw, []byte{'\n'})
	var observed uint64
	for index, line := range lines {
		if len(line) == 0 {
			continue
		}
		if index == len(lines)-1 && raw[len(raw)-1] != '\n' {
			break
		}
		var record struct {
			Message string `json:"msg"`
		}
		if err := json.Unmarshal(line, &record); err != nil {
			return 0, false, fmt.Errorf("%w: daemon observation log contains malformed JSON", ErrAgentRecognitionBenchmark)
		}
		if record.Message == agentRecognitionBenchmarkFingerprintLogMessage {
			observed++
		}
	}
	complete := len(raw) == 0 || raw[len(raw)-1] == '\n'
	return observed, complete, nil
}

func parseSchedstatRuntimeNanoseconds(raw []byte) (uint64, error) {
	fields := strings.Fields(string(raw))
	if len(fields) < 1 {
		return 0, ErrAgentRecognitionBenchmark
	}
	value, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, ErrAgentRecognitionBenchmark
	}
	return value, nil
}

func readProcessPeakRSSKiB(pid int) (uint64, error) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, fmt.Errorf("%w: daemon RSS metric is unavailable", ErrAgentRecognitionBenchmark)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "VmHWM:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[2] != "kB" {
			break
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr == nil && value > 0 {
			return value, nil
		}
		break
	}
	return 0, fmt.Errorf("%w: daemon RSS metric is malformed", ErrAgentRecognitionBenchmark)
}

func resetProcessPeakRSSKiB(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("%w: daemon PID is invalid for peak RSS reset", ErrAgentRecognitionBenchmark)
	}
	path := filepath.Join("/proc", strconv.Itoa(pid), "clear_refs")
	if err := os.WriteFile(path, []byte("5\n"), 0); err != nil {
		return fmt.Errorf("%w: reset daemon peak RSS watermark", ErrAgentRecognitionBenchmark)
	}
	return nil
}

func agentRecognitionBenchmarkEnvironment(runnerImageOS, runnerImageVersion string) AgentRecognitionBenchmarkEnvironment {
	var uts unix.Utsname
	kernel := "unknown"
	if unix.Uname(&uts) == nil {
		kernel = strings.TrimRight(string(uts.Release[:]), "\x00")
	}
	return AgentRecognitionBenchmarkEnvironment{
		OS: "linux", Architecture: safeBenchmarkHostText(runtime.GOARCH), KernelRelease: safeBenchmarkHostText(kernel),
		GoVersion: safeBenchmarkHostText(runtime.Version()), CPUCount: runtime.NumCPU(),
		CPUModel:        safeBenchmarkHostText(readAgentRecognitionBenchmarkCPUModel()),
		CgroupCPUMax:    safeBenchmarkHostText(readAgentRecognitionBenchmarkCgroupCPUMax()),
		EffectiveCPUSet: safeBenchmarkHostText(readAgentRecognitionBenchmarkEffectiveCPUSet()),
		RunnerImageOS:   safeBenchmarkHostText(runnerImageOS), RunnerImageVersion: safeBenchmarkHostText(runnerImageVersion),
	}
}

func calibrateAgentRecognitionBenchmarkProcessCPU(ctx context.Context, workloadPath, workloadSHA256 string) (*AgentRecognitionBenchmarkCalibration, error) {
	payload, err := os.ReadFile(workloadPath)
	if err != nil || len(payload) < minAgentRecognitionBenchmarkCalibrationWorkloadBytes || len(payload) > DefaultAgentFingerprintMaxFileBytes {
		return nil, fmt.Errorf("%w: calibration workload is outside the bounded size contract", ErrAgentRecognitionBenchmark)
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != workloadSHA256 {
		return nil, fmt.Errorf("%w: calibration workload digest drifted", ErrAgentRecognitionBenchmark)
	}
	iterations := int((AgentRecognitionBenchmarkCalibrationTargetBytes + uint64(len(payload)) - 1) / uint64(len(payload)))
	if iterations < 1 || iterations > maxAgentRecognitionBenchmarkCalibrationIterations {
		return nil, fmt.Errorf("%w: calibration iteration bound is invalid", ErrAgentRecognitionBenchmark)
	}
	samples := make([]uint64, 0, AgentRecognitionBenchmarkCalibrationSamples)
	for sampleIndex := 0; sampleIndex < AgentRecognitionBenchmarkCalibrationSamples; sampleIndex++ {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%w: benchmark context ended during calibration", ErrAgentRecognitionBenchmark)
		}
		before, err := agentRecognitionBenchmarkProcessCPUNanoseconds()
		if err != nil {
			return nil, err
		}
		var observed [sha256.Size]byte
		for iteration := 0; iteration < iterations; iteration++ {
			if iteration%64 == 0 {
				select {
				case <-ctx.Done():
					return nil, fmt.Errorf("%w: benchmark context ended during calibration", ErrAgentRecognitionBenchmark)
				default:
				}
			}
			observed = sha256.Sum256(payload)
		}
		after, err := agentRecognitionBenchmarkProcessCPUNanoseconds()
		if err != nil || after <= before || observed != digest {
			return nil, fmt.Errorf("%w: process-CPU calibration measurement is invalid", ErrAgentRecognitionBenchmark)
		}
		samples = append(samples, after-before)
	}
	calibration := &AgentRecognitionBenchmarkCalibration{
		Algorithm:     AgentRecognitionBenchmarkCalibrationAlgorithm,
		WorkloadBytes: uint64(len(payload)), IterationsPerSample: iterations,
		BytesPerSample:               uint64(len(payload)) * uint64(iterations),
		ProcessCPUSamplesNanoseconds: samples,
		ProcessCPUNanoseconds:        benchmarkDistributionFromUint64(samples),
	}
	if err := validateAgentRecognitionBenchmarkCalibration(calibration); err != nil {
		return nil, err
	}
	return calibration, nil
}

func agentRecognitionBenchmarkProcessCPUNanoseconds() (uint64, error) {
	var value unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_PROCESS_CPUTIME_ID, &value); err != nil || value.Sec < 0 || value.Nsec < 0 || value.Nsec >= int64(time.Second) {
		return 0, fmt.Errorf("%w: process CPU clock is unavailable", ErrAgentRecognitionBenchmark)
	}
	seconds := uint64(value.Sec)
	if seconds > (^uint64(0)-uint64(value.Nsec))/uint64(time.Second) {
		return 0, fmt.Errorf("%w: process CPU clock overflowed", ErrAgentRecognitionBenchmark)
	}
	return seconds*uint64(time.Second) + uint64(value.Nsec), nil
}

func readAgentRecognitionBenchmarkCPUModel() string {
	raw, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "unknown"
	}
	return parseAgentRecognitionBenchmarkCPUModel(raw)
}

func parseAgentRecognitionBenchmarkCPUModel(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\n") {
		name, value, found := strings.Cut(line, ":")
		if found && strings.TrimSpace(name) == "model name" && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return "unknown"
}

func readAgentRecognitionBenchmarkCgroupCPUMax() string {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err == nil {
		if relative, found := parseAgentRecognitionBenchmarkCgroupV2Path(raw); found {
			value, readErr := os.ReadFile(filepath.Join("/sys/fs/cgroup", relative, "cpu.max"))
			if readErr == nil && strings.TrimSpace(string(value)) != "" {
				return strings.TrimSpace(string(value))
			}
		}
	}
	if value, fallbackErr := os.ReadFile("/sys/fs/cgroup/cpu.max"); fallbackErr == nil && strings.TrimSpace(string(value)) != "" {
		return strings.TrimSpace(string(value))
	}
	return "unknown"
}

func parseAgentRecognitionBenchmarkCgroupV2Path(raw []byte) (string, bool) {
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		path := strings.TrimSpace(strings.TrimPrefix(line, "0::"))
		if !strings.HasPrefix(path, "/") {
			return "", false
		}
		return strings.TrimPrefix(filepath.Clean(path), "/"), true
	}
	return "", false
}

func readAgentRecognitionBenchmarkEffectiveCPUSet() string {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "unknown"
	}
	return parseAgentRecognitionBenchmarkEffectiveCPUSet(raw)
}

func parseAgentRecognitionBenchmarkEffectiveCPUSet(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\n") {
		name, value, found := strings.Cut(line, ":")
		if found && name == "Cpus_allowed_list" && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return "unknown"
}

func safeBenchmarkHostText(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	var result strings.Builder
	for _, character := range value {
		if character >= 0x20 && character <= 0x7e && character != '`' && character != '|' {
			result.WriteRune(character)
		} else {
			result.WriteRune('_')
		}
		if result.Len() >= 128 {
			break
		}
	}
	if result.Len() == 0 {
		return "unknown"
	}
	return result.String()
}
