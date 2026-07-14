// ardur-agent-recognition-benchmark runs a bounded paired real-Linux
// recognition-off/on workload and emits one privacy-bounded JSON report.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

const reportFilename = "agent-recognition-benchmark.json"

type commandSummary struct {
	Condition      string `json:"condition"`
	ArtifactSHA256 string `json:"artifact_sha256,omitempty"`
	GateStatus     string `json:"gate_status,omitempty"`
	MeasuredPairs  int    `json:"measured_pairs,omitempty"`
	ProfileCount   int    `json:"profile_count,omitempty"`
	ErrorCode      string `json:"error_code,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

func run(args []string, stdout io.Writer) int {
	flags := flag.NewFlagSet("ardur-agent-recognition-benchmark", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	daemonPath := flags.String("daemon-bin", "", "absolute path to ardur-kernelcaptured")
	workloadPath := flags.String("workload-bin", "", "absolute path to the deterministic native benchmark workload")
	sourceSHA := flags.String("source-sha", "", "exact 40-character source commit SHA")
	outputDirectory := flags.String("output-dir", "", "private output directory")
	budgetPath := flags.String("budget", "", "optional reviewed benchmark budget JSON")
	profileSet := flags.String("profile", "ci", "bounded workload profile: ci or release")
	seed := flags.Uint64("seed", 302, "deterministic pair-order seed")
	warmupPairs := flags.Int("warmup-pairs", 1, "excluded warm-up pair count")
	measuredPairs := flags.Int("measured-pairs", kernelcapture.MinAgentRecognitionBenchmarkPairs, "measured pair count")
	overallTimeout := flags.Duration("timeout", 15*time.Minute, "overall benchmark timeout")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *daemonPath == "" || *workloadPath == "" || *sourceSHA == "" || *outputDirectory == "" || (*profileSet != "ci" && *profileSet != "release") {
		writeSummary(stdout, commandSummary{Condition: "agent_recognition_benchmark_failed", ErrorCode: "arguments_invalid"})
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *overallTimeout)
	defer cancel()
	profiles := kernelcapture.DefaultAgentRecognitionBenchmarkProfiles()
	if *profileSet == "release" {
		profiles = kernelcapture.ReleaseAgentRecognitionBenchmarkProfiles()
	}
	report, err := kernelcapture.RunAgentRecognitionBenchmark(ctx, kernelcapture.AgentRecognitionBenchmarkOptions{
		DaemonPath: *daemonPath, WorkloadExecutablePath: *workloadPath, SourceSHA: *sourceSHA,
		Seed: *seed, WarmupPairs: *warmupPairs, MeasuredPairs: *measuredPairs, Profiles: profiles,
	})
	if err != nil {
		writeSummary(stdout, commandSummary{Condition: "agent_recognition_benchmark_failed", ErrorCode: "measurement_failed"})
		return 2
	}
	var budget *kernelcapture.AgentRecognitionBenchmarkBudget
	var budgetSHA256 string
	if *budgetPath != "" {
		budget, budgetSHA256, err = kernelcapture.LoadAgentRecognitionBenchmarkBudget(*budgetPath)
		if err != nil {
			writeSummary(stdout, commandSummary{Condition: "agent_recognition_benchmark_failed", ErrorCode: "budget_invalid"})
			return 2
		}
	}
	if err := kernelcapture.FinalizeAgentRecognitionBenchmarkReport(report, budget, budgetSHA256); err != nil {
		writeSummary(stdout, commandSummary{Condition: "agent_recognition_benchmark_failed", ErrorCode: "report_invalid"})
		return 2
	}
	if err := writeReport(*outputDirectory, report); err != nil {
		writeSummary(stdout, commandSummary{Condition: "agent_recognition_benchmark_failed", ErrorCode: "output_failed"})
		return 2
	}
	condition := "agent_recognition_benchmark_written"
	exitCode := 0
	if report.Gate.Status == kernelcapture.AgentRecognitionBenchmarkGateFail {
		condition = "agent_recognition_benchmark_budget_failed"
		exitCode = 1
	}
	writeSummary(stdout, commandSummary{
		Condition: condition, ArtifactSHA256: report.ArtifactSHA256, GateStatus: report.Gate.Status,
		MeasuredPairs: report.MeasuredPairs, ProfileCount: len(report.Summaries),
	})
	return exitCode
}

func writeReport(outputDirectory string, report *kernelcapture.AgentRecognitionBenchmarkReport) error {
	if report == nil {
		return fmt.Errorf("report is required")
	}
	if err := os.MkdirAll(outputDirectory, 0o700); err != nil {
		return fmt.Errorf("create output directory")
	}
	info, err := os.Lstat(outputDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("output directory must be a non-symlink directory")
	}
	if err := os.Chmod(outputDirectory, 0o700); err != nil {
		return fmt.Errorf("secure output directory")
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode report")
	}
	raw = append(raw, '\n')
	temporary, err := os.OpenFile(filepath.Join(outputDirectory, ".agent-recognition-benchmark.tmp"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create report temporary file")
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	written, writeErr := temporary.Write(raw)
	if writeErr != nil || written != len(raw) {
		_ = temporary.Close()
		return errors.Join(fmt.Errorf("write report"), writeErr, io.ErrShortWrite)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync report")
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close report")
	}
	if err := os.Rename(temporaryPath, filepath.Join(outputDirectory, reportFilename)); err != nil {
		return fmt.Errorf("publish report")
	}
	removeTemporary = false
	return nil
}

func writeSummary(writer io.Writer, summary commandSummary) {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(summary)
}
