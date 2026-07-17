package kernelcapture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	AgentRecognitionBenchmarkReportSchemaV1 = "ardur.agent_recognition_benchmark_report.v0.1"
	AgentRecognitionBenchmarkReportSchemaV2 = "ardur.agent_recognition_benchmark_report.v0.2"
	AgentRecognitionBenchmarkBudgetSchemaV1 = "ardur.agent_recognition_benchmark_budget.v0.1"
	AgentRecognitionBenchmarkBudgetSchemaV2 = "ardur.agent_recognition_benchmark_budget.v0.2"

	AgentRecognitionBenchmarkReportSchema = AgentRecognitionBenchmarkReportSchemaV2
	AgentRecognitionBenchmarkBudgetSchema = AgentRecognitionBenchmarkBudgetSchemaV2

	AgentRecognitionBenchmarkCalibrationAlgorithm   = "sha256_workload_process_cpu.v1"
	AgentRecognitionBenchmarkGatePass               = "pass"
	AgentRecognitionBenchmarkGateFail               = "fail"
	AgentRecognitionBenchmarkGateNotRun             = "not_evaluated"
	MinAgentRecognitionBenchmarkPairs               = 20
	AgentRecognitionBenchmarkCalibrationSamples     = 3
	AgentRecognitionBenchmarkCalibrationTargetBytes = 256 << 20

	minAgentRecognitionBenchmarkCalibrationWorkloadBytes = 64 << 10
	maxAgentRecognitionBenchmarkCalibrationIterations    = 4096
	maxAgentRecognitionBenchmarkFileBytes                = 8 << 20
)

var ErrAgentRecognitionBenchmark = errors.New("kernelcapture: invalid agent recognition benchmark")

type AgentRecognitionBenchmarkProfile struct {
	Name                     string `json:"name"`
	EventCount               int    `json:"event_count"`
	Concurrency              int    `json:"concurrency"`
	InterArrivalMicroseconds int    `json:"inter_arrival_microseconds"`
	HoldMilliseconds         int    `json:"hold_milliseconds"`
}

type AgentRecognitionBenchmarkOptions struct {
	DaemonPath             string
	WorkloadExecutablePath string
	SourceSHA              string
	RunnerImageOS          string
	RunnerImageVersion     string
	Seed                   uint64
	WarmupPairs            int
	MeasuredPairs          int
	Profiles               []AgentRecognitionBenchmarkProfile
	ArmStartupTimeout      time.Duration
	AccountingTimeout      time.Duration
}

func DefaultAgentRecognitionBenchmarkProfiles() []AgentRecognitionBenchmarkProfile {
	return []AgentRecognitionBenchmarkProfile{
		{Name: "low", EventCount: 4, Concurrency: 1, InterArrivalMicroseconds: 5000, HoldMilliseconds: 300},
		{Name: "sustained", EventCount: 20, Concurrency: 4, InterArrivalMicroseconds: 1000, HoldMilliseconds: 300},
		{Name: "storm", EventCount: 80, Concurrency: 16, InterArrivalMicroseconds: 0, HoldMilliseconds: 300},
	}
}

func ReleaseAgentRecognitionBenchmarkProfiles() []AgentRecognitionBenchmarkProfile {
	return []AgentRecognitionBenchmarkProfile{
		{Name: "low", EventCount: 20, Concurrency: 1, InterArrivalMicroseconds: 25_000, HoldMilliseconds: 300},
		{Name: "sustained", EventCount: 200, Concurrency: 16, InterArrivalMicroseconds: 2_000, HoldMilliseconds: 300},
		{Name: "storm", EventCount: 800, Concurrency: 64, InterArrivalMicroseconds: 0, HoldMilliseconds: 300},
	}
}

type AgentRecognitionBenchmarkCaptureLedger struct {
	ExpectedEvents  uint64 `json:"expected_events"`
	Delivered       uint64 `json:"delivered"`
	ProducerDropped uint64 `json:"producer_dropped"`
	Malformed       uint64 `json:"malformed"`
	Unexplained     uint64 `json:"unexplained"`
}

type AgentRecognitionBenchmarkFingerprintLedger struct {
	Recognized       uint64 `json:"recognized"`
	Success          uint64 `json:"success"`
	Mismatch         uint64 `json:"mismatch"`
	Saturated        uint64 `json:"saturated"`
	Unavailable      uint64 `json:"unavailable"`
	ResolutionDenied uint64 `json:"resolution_denied"`
	ProcessExited    uint64 `json:"process_exited"`
	Unsupported      uint64 `json:"unsupported"`
	SizeExceeded     uint64 `json:"size_exceeded"`
	DeadlineExceeded uint64 `json:"deadline_exceeded"`
	InFlight         uint64 `json:"in_flight"`
	Unexplained      uint64 `json:"unexplained"`
}

type AgentRecognitionBenchmarkRecognitionLedger struct {
	Candidates  uint64 `json:"candidates"`
	Recognized  uint64 `json:"recognized"`
	Rejected    uint64 `json:"rejected"`
	Unexplained uint64 `json:"unexplained"`
}

type AgentRecognitionBenchmarkArm struct {
	RecognitionEnabled          bool                                       `json:"recognition_enabled"`
	WorkloadCompletions         int                                        `json:"workload_completions"`
	WorkloadElapsedNanoseconds  uint64                                     `json:"workload_elapsed_nanoseconds"`
	AccountingSettleNanoseconds uint64                                     `json:"accounting_settle_nanoseconds"`
	DaemonCPUNanoseconds        uint64                                     `json:"daemon_cpu_nanoseconds"`
	DaemonPeakRSSKiB            uint64                                     `json:"daemon_peak_rss_kib"`
	DaemonHealthy               bool                                       `json:"daemon_healthy"`
	RegistryVersion             string                                     `json:"registry_version,omitempty"`
	RegistrySHA256              string                                     `json:"registry_sha256,omitempty"`
	Capture                     AgentRecognitionBenchmarkCaptureLedger     `json:"capture"`
	Recognition                 AgentRecognitionBenchmarkRecognitionLedger `json:"recognition"`
	Fingerprint                 AgentRecognitionBenchmarkFingerprintLedger `json:"fingerprint"`
}

type AgentRecognitionBenchmarkOverhead struct {
	NumeratorNanoseconds   int64   `json:"numerator_nanoseconds"`
	DenominatorNanoseconds uint64  `json:"denominator_nanoseconds"`
	Percent                float64 `json:"percent"`
}

type AgentRecognitionBenchmarkPair struct {
	PairIndex                 int                               `json:"pair_index"`
	Order                     string                            `json:"order"`
	Profile                   AgentRecognitionBenchmarkProfile  `json:"profile"`
	Baseline                  AgentRecognitionBenchmarkArm      `json:"baseline"`
	Enabled                   AgentRecognitionBenchmarkArm      `json:"enabled"`
	WallOverhead              AgentRecognitionBenchmarkOverhead `json:"wall_overhead"`
	DaemonCPUDeltaNanoseconds int64                             `json:"daemon_cpu_delta_nanoseconds"`
}

type AgentRecognitionBenchmarkDistribution struct {
	SampleCount int     `json:"sample_count"`
	P50         float64 `json:"p50"`
	P95         float64 `json:"p95"`
	Min         float64 `json:"min"`
	Max         float64 `json:"max"`
	Mean        float64 `json:"mean"`
}

type AgentRecognitionBenchmarkProfileSummary struct {
	ProfileName                      string                                     `json:"profile_name"`
	PairedWallOverheadPercent        AgentRecognitionBenchmarkDistribution      `json:"paired_wall_overhead_percent"`
	EnabledDaemonCPUNanoseconds      AgentRecognitionBenchmarkDistribution      `json:"enabled_daemon_cpu_nanoseconds"`
	EnabledDaemonCPUCalibrationRatio *AgentRecognitionBenchmarkDistribution     `json:"enabled_daemon_cpu_calibration_ratio,omitempty"`
	MaxEnabledDaemonPeakRSSKiB       uint64                                     `json:"max_enabled_daemon_peak_rss_kib"`
	TotalCapture                     AgentRecognitionBenchmarkCaptureLedger     `json:"total_capture"`
	TotalRecognition                 AgentRecognitionBenchmarkRecognitionLedger `json:"total_recognition"`
	TotalFingerprint                 AgentRecognitionBenchmarkFingerprintLedger `json:"total_fingerprint"`
}

type AgentRecognitionBenchmarkEnvironment struct {
	OS                 string `json:"os"`
	Architecture       string `json:"architecture"`
	KernelRelease      string `json:"kernel_release"`
	GoVersion          string `json:"go_version"`
	CPUCount           int    `json:"cpu_count"`
	CPUModel           string `json:"cpu_model,omitempty"`
	CgroupCPUMax       string `json:"cgroup_cpu_max,omitempty"`
	EffectiveCPUSet    string `json:"effective_cpu_set,omitempty"`
	RunnerImageOS      string `json:"runner_image_os,omitempty"`
	RunnerImageVersion string `json:"runner_image_version,omitempty"`
}

type AgentRecognitionBenchmarkCalibration struct {
	Algorithm                    string                                `json:"algorithm"`
	WorkloadBytes                uint64                                `json:"workload_bytes"`
	IterationsPerSample          int                                   `json:"iterations_per_sample"`
	BytesPerSample               uint64                                `json:"bytes_per_sample"`
	ProcessCPUSamplesNanoseconds []uint64                              `json:"process_cpu_samples_nanoseconds"`
	ProcessCPUNanoseconds        AgentRecognitionBenchmarkDistribution `json:"process_cpu_nanoseconds"`
}

type AgentRecognitionBenchmarkGate struct {
	Status       string   `json:"status"`
	BudgetSHA256 string   `json:"budget_sha256,omitempty"`
	Violations   []string `json:"violations"`
}

type AgentRecognitionBenchmarkReport struct {
	SchemaVersion   string                                    `json:"schema_version"`
	GeneratedAt     string                                    `json:"generated_at"`
	SourceSHA       string                                    `json:"source_sha"`
	Seed            uint64                                    `json:"seed"`
	WarmupPairs     int                                       `json:"warmup_pairs"`
	MeasuredPairs   int                                       `json:"measured_pairs"`
	PairOrder       string                                    `json:"pair_order"`
	Environment     AgentRecognitionBenchmarkEnvironment      `json:"environment"`
	WorkloadSHA256  string                                    `json:"workload_sha256"`
	RegistryVersion string                                    `json:"registry_version"`
	RegistrySHA256  string                                    `json:"registry_sha256"`
	Calibration     *AgentRecognitionBenchmarkCalibration     `json:"calibration,omitempty"`
	Pairs           []AgentRecognitionBenchmarkPair           `json:"pairs"`
	Summaries       []AgentRecognitionBenchmarkProfileSummary `json:"summaries"`
	Gate            AgentRecognitionBenchmarkGate             `json:"gate"`
	ArtifactSHA256  string                                    `json:"artifact_sha256"`
	Limitations     []string                                  `json:"limitations"`
}

type AgentRecognitionBenchmarkBudgetProfile struct {
	ProfileName                                       string  `json:"profile_name"`
	EvidenceP50WallOverheadPercent                    float64 `json:"evidence_p50_wall_overhead_percent"`
	EvidenceP95WallOverheadPercent                    float64 `json:"evidence_p95_wall_overhead_percent"`
	WallOverheadTolerancePercentagePoints             float64 `json:"wall_overhead_tolerance_percentage_points"`
	EvidenceP95EnabledDaemonCPUNanoseconds            float64 `json:"evidence_p95_enabled_daemon_cpu_nanoseconds,omitempty"`
	DaemonCPURelativeTolerancePercent                 float64 `json:"daemon_cpu_relative_tolerance_percent,omitempty"`
	DaemonCPUAbsoluteToleranceNanoseconds             uint64  `json:"daemon_cpu_absolute_tolerance_nanoseconds,omitempty"`
	EvidenceP95EnabledDaemonCPUCalibrationRatio       float64 `json:"evidence_p95_enabled_daemon_cpu_calibration_ratio,omitempty"`
	DaemonCPUCalibrationRatioRelativeTolerancePercent float64 `json:"daemon_cpu_calibration_ratio_relative_tolerance_percent,omitempty"`
	DaemonCPUCalibrationRatioAbsoluteTolerance        float64 `json:"daemon_cpu_calibration_ratio_absolute_tolerance,omitempty"`
	EvidenceMaxEnabledDaemonPeakRSSKiB                uint64  `json:"evidence_max_enabled_daemon_peak_rss_kib"`
	PeakRSSToleranceKiB                               uint64  `json:"peak_rss_tolerance_kib"`
}

type AgentRecognitionBenchmarkBudget struct {
	SchemaVersion           string                                   `json:"schema_version"`
	BudgetVersion           string                                   `json:"budget_version"`
	EvidenceArtifactSHA256  string                                   `json:"evidence_artifact_sha256,omitempty"`
	EvidenceArtifactSHA256s []string                                 `json:"evidence_artifact_sha256s,omitempty"`
	MinimumMeasuredPairs    int                                      `json:"minimum_measured_pairs"`
	Profiles                []AgentRecognitionBenchmarkBudgetProfile `json:"profiles"`
}

func FinalizeAgentRecognitionBenchmarkReport(report *AgentRecognitionBenchmarkReport, budget *AgentRecognitionBenchmarkBudget, budgetSHA256 string) error {
	if report == nil {
		return fmt.Errorf("%w: report is required", ErrAgentRecognitionBenchmark)
	}
	report.Summaries = summarizeAgentRecognitionBenchmark(report.Pairs, report.Calibration)
	report.Gate = AgentRecognitionBenchmarkGate{Status: AgentRecognitionBenchmarkGateNotRun, Violations: []string{}}
	if budget != nil {
		report.Gate = EvaluateAgentRecognitionBenchmarkBudget(report, budget, budgetSHA256)
	} else if violations := agentRecognitionBenchmarkCorrectnessViolations(report.Summaries); len(violations) > 0 {
		report.Gate = AgentRecognitionBenchmarkGate{Status: AgentRecognitionBenchmarkGateFail, Violations: violations}
	}
	report.ArtifactSHA256 = ""
	payload, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("%w: marshal report for artifact digest", ErrAgentRecognitionBenchmark)
	}
	digest := sha256.Sum256(payload)
	report.ArtifactSHA256 = hex.EncodeToString(digest[:])
	return ValidateAgentRecognitionBenchmarkReport(report)
}

func ValidateAgentRecognitionBenchmarkReport(report *AgentRecognitionBenchmarkReport) error {
	if report == nil || (report.SchemaVersion != AgentRecognitionBenchmarkReportSchemaV1 && report.SchemaVersion != AgentRecognitionBenchmarkReportSchemaV2) {
		return fmt.Errorf("%w: report schema is unsupported", ErrAgentRecognitionBenchmark)
	}
	if _, err := time.Parse(time.RFC3339Nano, report.GeneratedAt); err != nil {
		return fmt.Errorf("%w: report timestamp is invalid", ErrAgentRecognitionBenchmark)
	}
	if !isHexDigest(report.SourceSHA, 40) || !isHexDigest(report.WorkloadSHA256, 64) || !isHexDigest(report.RegistrySHA256, 64) || !isHexDigest(report.ArtifactSHA256, 64) || strings.TrimSpace(report.RegistryVersion) == "" {
		return fmt.Errorf("%w: report digest metadata is invalid", ErrAgentRecognitionBenchmark)
	}
	if report.Seed == 0 || report.WarmupPairs < 1 || report.MeasuredPairs < MinAgentRecognitionBenchmarkPairs || report.MeasuredPairs > 100 || report.PairOrder != "deterministic_ab_ba_alternation" {
		return fmt.Errorf("%w: report sampling contract is invalid", ErrAgentRecognitionBenchmark)
	}
	if report.Environment.OS != "linux" || report.Environment.CPUCount < 1 || report.Environment.Architecture == "" || report.Environment.KernelRelease == "" || report.Environment.GoVersion == "" {
		return fmt.Errorf("%w: Linux environment metadata is incomplete", ErrAgentRecognitionBenchmark)
	}
	if report.SchemaVersion == AgentRecognitionBenchmarkReportSchemaV1 {
		if report.Calibration != nil || report.Environment.CPUModel != "" || report.Environment.CgroupCPUMax != "" || report.Environment.EffectiveCPUSet != "" || report.Environment.RunnerImageOS != "" || report.Environment.RunnerImageVersion != "" {
			return fmt.Errorf("%w: v0.1 report contains v0.2 runner metadata", ErrAgentRecognitionBenchmark)
		}
	} else {
		if err := validateAgentRecognitionBenchmarkCalibration(report.Calibration); err != nil {
			return err
		}
		for _, value := range []string{
			report.Environment.CPUModel,
			report.Environment.CgroupCPUMax,
			report.Environment.EffectiveCPUSet,
			report.Environment.RunnerImageOS,
			report.Environment.RunnerImageVersion,
		} {
			if !validAgentRecognitionBenchmarkHostText(value) {
				return fmt.Errorf("%w: v0.2 runner environment metadata is invalid", ErrAgentRecognitionBenchmark)
			}
		}
	}
	profiles := make(map[string]AgentRecognitionBenchmarkProfile)
	pairCounts := make(map[string]int)
	pairIndices := make(map[string]map[int]struct{})
	for index := range report.Pairs {
		pair := &report.Pairs[index]
		expectedOrder := "baseline_then_enabled"
		if (pair.PairIndex+int(report.Seed&1))%2 != 0 {
			expectedOrder = "enabled_then_baseline"
		}
		if pair.PairIndex < 0 || pair.PairIndex >= report.MeasuredPairs || pair.Order != expectedOrder {
			return fmt.Errorf("%w: pair ordering metadata is invalid", ErrAgentRecognitionBenchmark)
		}
		if err := validateAgentRecognitionBenchmarkProfile(pair.Profile); err != nil {
			return err
		}
		if existing, ok := profiles[pair.Profile.Name]; ok && existing != pair.Profile {
			return fmt.Errorf("%w: profile settings drifted across pairs", ErrAgentRecognitionBenchmark)
		}
		profiles[pair.Profile.Name] = pair.Profile
		pairCounts[pair.Profile.Name]++
		if pairIndices[pair.Profile.Name] == nil {
			pairIndices[pair.Profile.Name] = make(map[int]struct{}, report.MeasuredPairs)
		}
		if _, duplicated := pairIndices[pair.Profile.Name][pair.PairIndex]; duplicated {
			return fmt.Errorf("%w: pair index is duplicated", ErrAgentRecognitionBenchmark)
		}
		pairIndices[pair.Profile.Name][pair.PairIndex] = struct{}{}
		if err := validateAgentRecognitionBenchmarkArm(pair.Baseline, pair.Profile, false, "", ""); err != nil {
			return err
		}
		if err := validateAgentRecognitionBenchmarkArm(pair.Enabled, pair.Profile, true, report.RegistryVersion, report.RegistrySHA256); err != nil {
			return err
		}
		if pair.WallOverhead.DenominatorNanoseconds != pair.Baseline.WorkloadElapsedNanoseconds || pair.WallOverhead.NumeratorNanoseconds != int64(pair.Enabled.WorkloadElapsedNanoseconds)-int64(pair.Baseline.WorkloadElapsedNanoseconds) {
			return fmt.Errorf("%w: paired wall-overhead numerator or denominator drifted", ErrAgentRecognitionBenchmark)
		}
		wantPercent := (float64(pair.WallOverhead.NumeratorNanoseconds) / float64(pair.WallOverhead.DenominatorNanoseconds)) * 100
		if !nearlyEqual(pair.WallOverhead.Percent, wantPercent) || pair.DaemonCPUDeltaNanoseconds != int64(pair.Enabled.DaemonCPUNanoseconds)-int64(pair.Baseline.DaemonCPUNanoseconds) {
			return fmt.Errorf("%w: paired overhead calculation drifted", ErrAgentRecognitionBenchmark)
		}
	}
	requiredProfiles := map[string]struct{}{"low": {}, "sustained": {}, "storm": {}}
	if len(profiles) != len(requiredProfiles) || len(report.Pairs) != len(profiles)*report.MeasuredPairs {
		return fmt.Errorf("%w: pair/profile sample accounting is invalid", ErrAgentRecognitionBenchmark)
	}
	for name := range profiles {
		if _, required := requiredProfiles[name]; !required {
			return fmt.Errorf("%w: required workload profile is missing or unknown", ErrAgentRecognitionBenchmark)
		}
		if pairCounts[name] != report.MeasuredPairs {
			return fmt.Errorf("%w: profile sample count is incomplete", ErrAgentRecognitionBenchmark)
		}
	}
	wantSummaries := summarizeAgentRecognitionBenchmark(report.Pairs, report.Calibration)
	wantJSON, _ := json.Marshal(wantSummaries)
	gotJSON, _ := json.Marshal(report.Summaries)
	if !bytes.Equal(wantJSON, gotJSON) {
		return fmt.Errorf("%w: report summaries drifted from raw pairs", ErrAgentRecognitionBenchmark)
	}
	copyReport := *report
	copyReport.ArtifactSHA256 = ""
	payload, err := json.Marshal(&copyReport)
	if err != nil {
		return fmt.Errorf("%w: marshal report for verification", ErrAgentRecognitionBenchmark)
	}
	digest := sha256.Sum256(payload)
	if report.ArtifactSHA256 != hex.EncodeToString(digest[:]) {
		return fmt.Errorf("%w: report artifact digest mismatch", ErrAgentRecognitionBenchmark)
	}
	switch report.Gate.Status {
	case AgentRecognitionBenchmarkGateNotRun:
		if report.Gate.BudgetSHA256 != "" || len(report.Gate.Violations) != 0 || len(agentRecognitionBenchmarkCorrectnessViolations(report.Summaries)) != 0 {
			return fmt.Errorf("%w: unevaluated gate metadata is inconsistent", ErrAgentRecognitionBenchmark)
		}
	case AgentRecognitionBenchmarkGatePass:
		if !isHexDigest(report.Gate.BudgetSHA256, 64) || len(report.Gate.Violations) != 0 || len(agentRecognitionBenchmarkCorrectnessViolations(report.Summaries)) != 0 {
			return fmt.Errorf("%w: passing gate metadata is inconsistent", ErrAgentRecognitionBenchmark)
		}
	case AgentRecognitionBenchmarkGateFail:
		correctnessViolations := agentRecognitionBenchmarkCorrectnessViolations(report.Summaries)
		if len(report.Gate.Violations) == 0 || !sortedUniqueStrings(report.Gate.Violations) || (report.Gate.BudgetSHA256 != "" && !isHexDigest(report.Gate.BudgetSHA256, 64)) {
			return fmt.Errorf("%w: failing gate metadata is inconsistent", ErrAgentRecognitionBenchmark)
		}
		if report.Gate.BudgetSHA256 == "" {
			if !stringSlicesEqual(report.Gate.Violations, correctnessViolations) || len(correctnessViolations) == 0 {
				return fmt.Errorf("%w: budget-independent correctness gate drifted", ErrAgentRecognitionBenchmark)
			}
		} else {
			for _, violation := range correctnessViolations {
				if !sortedStringsContain(report.Gate.Violations, violation) {
					return fmt.Errorf("%w: failing budget gate omitted a correctness violation", ErrAgentRecognitionBenchmark)
				}
			}
		}
	default:
		return fmt.Errorf("%w: report gate status is invalid", ErrAgentRecognitionBenchmark)
	}
	return nil
}

func EvaluateAgentRecognitionBenchmarkBudget(report *AgentRecognitionBenchmarkReport, budget *AgentRecognitionBenchmarkBudget, budgetSHA256 string) AgentRecognitionBenchmarkGate {
	gate := AgentRecognitionBenchmarkGate{Status: AgentRecognitionBenchmarkGatePass, BudgetSHA256: budgetSHA256, Violations: []string{}}
	if report != nil {
		gate.Violations = append(gate.Violations, agentRecognitionBenchmarkCorrectnessViolations(report.Summaries)...)
	}
	if report == nil || !agentRecognitionBenchmarkSchemasMatch(report.SchemaVersion, budget) || ValidateAgentRecognitionBenchmarkBudget(budget) != nil || !isHexDigest(budgetSHA256, 64) {
		gate.Status = AgentRecognitionBenchmarkGateFail
		gate.Violations = append(gate.Violations, "budget.invalid")
		sort.Strings(gate.Violations)
		return gate
	}
	if report.MeasuredPairs < budget.MinimumMeasuredPairs {
		gate.Violations = append(gate.Violations, "samples.below_budget_floor")
	}
	summaries := make(map[string]AgentRecognitionBenchmarkProfileSummary, len(report.Summaries))
	for _, summary := range report.Summaries {
		summaries[summary.ProfileName] = summary
	}
	for _, profile := range budget.Profiles {
		summary, ok := summaries[profile.ProfileName]
		if !ok {
			gate.Violations = append(gate.Violations, "profile."+profile.ProfileName+".missing")
			continue
		}
		if summary.PairedWallOverheadPercent.P50 > profile.EvidenceP50WallOverheadPercent+profile.WallOverheadTolerancePercentagePoints {
			gate.Violations = append(gate.Violations, "budget."+profile.ProfileName+".p50_wall_overhead")
		}
		if budget.SchemaVersion == AgentRecognitionBenchmarkBudgetSchemaV1 {
			if summary.PairedWallOverheadPercent.P95 > profile.EvidenceP95WallOverheadPercent+profile.WallOverheadTolerancePercentagePoints {
				gate.Violations = append(gate.Violations, "budget."+profile.ProfileName+".p95_wall_overhead")
			}
			cpuTolerance := math.Max(float64(profile.DaemonCPUAbsoluteToleranceNanoseconds), profile.EvidenceP95EnabledDaemonCPUNanoseconds*(profile.DaemonCPURelativeTolerancePercent/100))
			if summary.EnabledDaemonCPUNanoseconds.P95 > profile.EvidenceP95EnabledDaemonCPUNanoseconds+cpuTolerance {
				gate.Violations = append(gate.Violations, "budget."+profile.ProfileName+".p95_daemon_cpu")
			}
		} else if summary.EnabledDaemonCPUCalibrationRatio == nil {
			gate.Violations = append(gate.Violations, "budget."+profile.ProfileName+".normalized_cpu_missing")
		} else {
			cpuTolerance := math.Max(profile.DaemonCPUCalibrationRatioAbsoluteTolerance, profile.EvidenceP95EnabledDaemonCPUCalibrationRatio*(profile.DaemonCPUCalibrationRatioRelativeTolerancePercent/100))
			if summary.EnabledDaemonCPUCalibrationRatio.P95 > profile.EvidenceP95EnabledDaemonCPUCalibrationRatio+cpuTolerance {
				gate.Violations = append(gate.Violations, "budget."+profile.ProfileName+".p95_normalized_daemon_cpu")
			}
		}
		if summary.MaxEnabledDaemonPeakRSSKiB > profile.EvidenceMaxEnabledDaemonPeakRSSKiB+profile.PeakRSSToleranceKiB {
			gate.Violations = append(gate.Violations, "budget."+profile.ProfileName+".peak_rss")
		}
		delete(summaries, profile.ProfileName)
	}
	for name := range summaries {
		gate.Violations = append(gate.Violations, "profile."+name+".unbudgeted")
	}
	sort.Strings(gate.Violations)
	if len(gate.Violations) > 0 {
		gate.Status = AgentRecognitionBenchmarkGateFail
	}
	return gate
}

func agentRecognitionBenchmarkCorrectnessViolations(summaries []AgentRecognitionBenchmarkProfileSummary) []string {
	violations := make([]string, 0)
	for _, summary := range summaries {
		if summary.TotalCapture.ProducerDropped != 0 || summary.TotalCapture.Malformed != 0 || summary.TotalCapture.Unexplained != 0 {
			violations = append(violations, "loss."+summary.ProfileName+".capture_nonzero")
		}
		if summary.TotalRecognition.Rejected != 0 || summary.TotalRecognition.Unexplained != 0 {
			violations = append(violations, "loss."+summary.ProfileName+".recognition_nonzero")
		}
		if summary.TotalFingerprint.Mismatch != 0 || summary.TotalFingerprint.Saturated != 0 || summary.TotalFingerprint.Unavailable != 0 || summary.TotalFingerprint.InFlight != 0 || summary.TotalFingerprint.Unexplained != 0 {
			violations = append(violations, "loss."+summary.ProfileName+".fingerprint_nonzero")
		}
	}
	sort.Strings(violations)
	return violations
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sortedStringsContain(values []string, want string) bool {
	index := sort.SearchStrings(values, want)
	return index < len(values) && values[index] == want
}

func sortedUniqueStrings(values []string) bool {
	if !sort.StringsAreSorted(values) {
		return false
	}
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return false
		}
	}
	return true
}

func ValidateAgentRecognitionBenchmarkBudget(budget *AgentRecognitionBenchmarkBudget) error {
	if budget == nil || (budget.SchemaVersion != AgentRecognitionBenchmarkBudgetSchemaV1 && budget.SchemaVersion != AgentRecognitionBenchmarkBudgetSchemaV2) || strings.TrimSpace(budget.BudgetVersion) == "" || budget.MinimumMeasuredPairs < MinAgentRecognitionBenchmarkPairs || budget.MinimumMeasuredPairs > 100 || len(budget.Profiles) != 3 {
		return fmt.Errorf("%w: benchmark budget metadata is invalid", ErrAgentRecognitionBenchmark)
	}
	if budget.SchemaVersion == AgentRecognitionBenchmarkBudgetSchemaV1 {
		if !isHexDigest(budget.EvidenceArtifactSHA256, 64) || len(budget.EvidenceArtifactSHA256s) != 0 {
			return fmt.Errorf("%w: v0.1 benchmark evidence metadata is invalid", ErrAgentRecognitionBenchmark)
		}
	} else {
		if budget.EvidenceArtifactSHA256 != "" || len(budget.EvidenceArtifactSHA256s) < AgentRecognitionBenchmarkCalibrationSamples {
			return fmt.Errorf("%w: v0.2 benchmark evidence metadata is invalid", ErrAgentRecognitionBenchmark)
		}
		seenEvidence := make(map[string]struct{}, len(budget.EvidenceArtifactSHA256s))
		for _, digest := range budget.EvidenceArtifactSHA256s {
			if !isHexDigest(digest, 64) {
				return fmt.Errorf("%w: v0.2 benchmark evidence digest is invalid", ErrAgentRecognitionBenchmark)
			}
			if _, duplicated := seenEvidence[digest]; duplicated {
				return fmt.Errorf("%w: v0.2 benchmark evidence digest is duplicated", ErrAgentRecognitionBenchmark)
			}
			seenEvidence[digest] = struct{}{}
		}
	}
	requiredProfiles := map[string]struct{}{"low": {}, "sustained": {}, "storm": {}}
	seen := make(map[string]struct{}, len(budget.Profiles))
	for _, profile := range budget.Profiles {
		if strings.TrimSpace(profile.ProfileName) == "" || !finite(profile.EvidenceP50WallOverheadPercent) || !finite(profile.EvidenceP95WallOverheadPercent) || !finiteNonnegative(profile.WallOverheadTolerancePercentagePoints) ||
			!finite(profile.EvidenceP50WallOverheadPercent+profile.WallOverheadTolerancePercentagePoints) ||
			!finite(profile.EvidenceP95WallOverheadPercent+profile.WallOverheadTolerancePercentagePoints) ||
			^uint64(0)-profile.EvidenceMaxEnabledDaemonPeakRSSKiB < profile.PeakRSSToleranceKiB {
			return fmt.Errorf("%w: benchmark budget profile is invalid", ErrAgentRecognitionBenchmark)
		}
		if budget.SchemaVersion == AgentRecognitionBenchmarkBudgetSchemaV1 {
			relativeTolerance := profile.EvidenceP95EnabledDaemonCPUNanoseconds * (profile.DaemonCPURelativeTolerancePercent / 100)
			cpuTolerance := math.Max(float64(profile.DaemonCPUAbsoluteToleranceNanoseconds), relativeTolerance)
			if !finiteNonnegative(profile.EvidenceP95EnabledDaemonCPUNanoseconds) || !finiteNonnegative(profile.DaemonCPURelativeTolerancePercent) || !finite(relativeTolerance) || !finite(profile.EvidenceP95EnabledDaemonCPUNanoseconds+cpuTolerance) || profile.EvidenceP95EnabledDaemonCPUCalibrationRatio != 0 || profile.DaemonCPUCalibrationRatioRelativeTolerancePercent != 0 || profile.DaemonCPUCalibrationRatioAbsoluteTolerance != 0 {
				return fmt.Errorf("%w: v0.1 benchmark CPU budget profile is invalid", ErrAgentRecognitionBenchmark)
			}
		} else {
			relativeTolerance := profile.EvidenceP95EnabledDaemonCPUCalibrationRatio * (profile.DaemonCPUCalibrationRatioRelativeTolerancePercent / 100)
			cpuTolerance := math.Max(profile.DaemonCPUCalibrationRatioAbsoluteTolerance, relativeTolerance)
			if !finite(profile.EvidenceP95EnabledDaemonCPUCalibrationRatio) || profile.EvidenceP95EnabledDaemonCPUCalibrationRatio <= 0 || !finiteNonnegative(profile.DaemonCPUCalibrationRatioRelativeTolerancePercent) || !finiteNonnegative(profile.DaemonCPUCalibrationRatioAbsoluteTolerance) || !finite(relativeTolerance) || !finite(profile.EvidenceP95EnabledDaemonCPUCalibrationRatio+cpuTolerance) || profile.EvidenceP95EnabledDaemonCPUNanoseconds != 0 || profile.DaemonCPURelativeTolerancePercent != 0 || profile.DaemonCPUAbsoluteToleranceNanoseconds != 0 {
				return fmt.Errorf("%w: v0.2 normalized CPU budget profile is invalid", ErrAgentRecognitionBenchmark)
			}
		}
		if _, exists := seen[profile.ProfileName]; exists {
			return fmt.Errorf("%w: benchmark budget profile is duplicated", ErrAgentRecognitionBenchmark)
		}
		if _, required := requiredProfiles[profile.ProfileName]; !required {
			return fmt.Errorf("%w: benchmark budget profile is unknown", ErrAgentRecognitionBenchmark)
		}
		seen[profile.ProfileName] = struct{}{}
	}
	return nil
}

func agentRecognitionBenchmarkSchemasMatch(reportSchema string, budget *AgentRecognitionBenchmarkBudget) bool {
	if budget == nil {
		return false
	}
	return (reportSchema == AgentRecognitionBenchmarkReportSchemaV1 && budget.SchemaVersion == AgentRecognitionBenchmarkBudgetSchemaV1) ||
		(reportSchema == AgentRecognitionBenchmarkReportSchemaV2 && budget.SchemaVersion == AgentRecognitionBenchmarkBudgetSchemaV2)
}

func LoadAgentRecognitionBenchmarkBudget(path string) (*AgentRecognitionBenchmarkBudget, string, error) {
	var budget AgentRecognitionBenchmarkBudget
	raw, err := loadAgentRecognitionBenchmarkJSON(path, "budget", &budget)
	if err != nil {
		return nil, "", err
	}
	if err := ValidateAgentRecognitionBenchmarkBudget(&budget); err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(raw)
	return &budget, hex.EncodeToString(digest[:]), nil
}

// LoadAgentRecognitionBenchmarkReport strictly loads and validates a bounded,
// non-symlink report file. It is used to keep committed evidence fixtures under
// the same schema, arithmetic, accounting, and artifact-digest checks as a live
// benchmark result.
func LoadAgentRecognitionBenchmarkReport(path string) (*AgentRecognitionBenchmarkReport, error) {
	var report AgentRecognitionBenchmarkReport
	if _, err := loadAgentRecognitionBenchmarkJSON(path, "report", &report); err != nil {
		return nil, err
	}
	if err := ValidateAgentRecognitionBenchmarkReport(&report); err != nil {
		return nil, err
	}
	return &report, nil
}

func loadAgentRecognitionBenchmarkJSON(path, label string, target any) ([]byte, error) {
	linkInfo, err := os.Lstat(path)
	if err != nil || linkInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: benchmark %s must be a non-symlink regular file", ErrAgentRecognitionBenchmark, label)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: benchmark %s is unreadable", ErrAgentRecognitionBenchmark, label)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(linkInfo, info) || info.Size() > maxAgentRecognitionBenchmarkFileBytes {
		return nil, fmt.Errorf("%w: benchmark %s must be a bounded regular file", ErrAgentRecognitionBenchmark, label)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxAgentRecognitionBenchmarkFileBytes+1))
	if err != nil || len(raw) > maxAgentRecognitionBenchmarkFileBytes {
		return nil, fmt.Errorf("%w: benchmark %s is unreadable", ErrAgentRecognitionBenchmark, label)
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return nil, fmt.Errorf("%w: benchmark %s JSON contains a duplicate key", ErrAgentRecognitionBenchmark, label)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return nil, fmt.Errorf("%w: benchmark %s JSON is invalid", ErrAgentRecognitionBenchmark, label)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("%w: benchmark %s contains trailing data", ErrAgentRecognitionBenchmark, label)
	}
	return raw, nil
}

func NewAgentRecognitionBenchmarkPair(pairIndex int, order string, profile AgentRecognitionBenchmarkProfile, baseline, enabled AgentRecognitionBenchmarkArm) (AgentRecognitionBenchmarkPair, error) {
	if baseline.WorkloadElapsedNanoseconds == 0 {
		return AgentRecognitionBenchmarkPair{}, fmt.Errorf("%w: baseline duration must be positive", ErrAgentRecognitionBenchmark)
	}
	numerator := int64(enabled.WorkloadElapsedNanoseconds) - int64(baseline.WorkloadElapsedNanoseconds)
	return AgentRecognitionBenchmarkPair{
		PairIndex: pairIndex, Order: order, Profile: profile, Baseline: baseline, Enabled: enabled,
		WallOverhead: AgentRecognitionBenchmarkOverhead{
			NumeratorNanoseconds:   numerator,
			DenominatorNanoseconds: baseline.WorkloadElapsedNanoseconds,
			Percent:                (float64(numerator) / float64(baseline.WorkloadElapsedNanoseconds)) * 100,
		},
		DaemonCPUDeltaNanoseconds: int64(enabled.DaemonCPUNanoseconds) - int64(baseline.DaemonCPUNanoseconds),
	}, nil
}

func summarizeAgentRecognitionBenchmark(pairs []AgentRecognitionBenchmarkPair, calibration *AgentRecognitionBenchmarkCalibration) []AgentRecognitionBenchmarkProfileSummary {
	type values struct {
		wall          []float64
		cpu           []float64
		normalizedCPU []float64
		rss           uint64
		capture       AgentRecognitionBenchmarkCaptureLedger
		recognition   AgentRecognitionBenchmarkRecognitionLedger
		fingerprint   AgentRecognitionBenchmarkFingerprintLedger
	}
	calibrationP50 := 0.0
	if calibration != nil && finite(calibration.ProcessCPUNanoseconds.P50) && calibration.ProcessCPUNanoseconds.P50 > 0 {
		calibrationP50 = calibration.ProcessCPUNanoseconds.P50
	}
	grouped := make(map[string]*values)
	for _, pair := range pairs {
		value := grouped[pair.Profile.Name]
		if value == nil {
			value = &values{}
			grouped[pair.Profile.Name] = value
		}
		value.wall = append(value.wall, pair.WallOverhead.Percent)
		value.cpu = append(value.cpu, float64(pair.Enabled.DaemonCPUNanoseconds))
		if calibrationP50 > 0 {
			value.normalizedCPU = append(value.normalizedCPU, float64(pair.Enabled.DaemonCPUNanoseconds)/calibrationP50)
		}
		if pair.Enabled.DaemonPeakRSSKiB > value.rss {
			value.rss = pair.Enabled.DaemonPeakRSSKiB
		}
		addCaptureLedger(&value.capture, pair.Enabled.Capture)
		addRecognitionLedger(&value.recognition, pair.Enabled.Recognition)
		addFingerprintLedger(&value.fingerprint, pair.Enabled.Fingerprint)
	}
	names := make([]string, 0, len(grouped))
	for name := range grouped {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]AgentRecognitionBenchmarkProfileSummary, 0, len(names))
	for _, name := range names {
		value := grouped[name]
		summary := AgentRecognitionBenchmarkProfileSummary{
			ProfileName:                 name,
			PairedWallOverheadPercent:   benchmarkDistribution(value.wall),
			EnabledDaemonCPUNanoseconds: benchmarkDistribution(value.cpu),
			MaxEnabledDaemonPeakRSSKiB:  value.rss,
			TotalCapture:                value.capture,
			TotalRecognition:            value.recognition,
			TotalFingerprint:            value.fingerprint,
		}
		if len(value.normalizedCPU) > 0 {
			distribution := benchmarkDistribution(value.normalizedCPU)
			summary.EnabledDaemonCPUCalibrationRatio = &distribution
		}
		result = append(result, summary)
	}
	return result
}

func benchmarkDistribution(values []float64) AgentRecognitionBenchmarkDistribution {
	if len(values) == 0 {
		return AgentRecognitionBenchmarkDistribution{}
	}
	ordered := append([]float64(nil), values...)
	sort.Float64s(ordered)
	sum := 0.0
	for _, value := range ordered {
		sum += value
	}
	return AgentRecognitionBenchmarkDistribution{
		SampleCount: len(ordered), P50: nearestRankFloat(ordered, 50), P95: nearestRankFloat(ordered, 95),
		Min: ordered[0], Max: ordered[len(ordered)-1], Mean: sum / float64(len(ordered)),
	}
}

func benchmarkDistributionFromUint64(values []uint64) AgentRecognitionBenchmarkDistribution {
	converted := make([]float64, len(values))
	for index, value := range values {
		converted[index] = float64(value)
	}
	return benchmarkDistribution(converted)
}

func nearestRankFloat(ordered []float64, percentile int) float64 {
	index := int(math.Ceil((float64(percentile)/100)*float64(len(ordered)))) - 1
	if index < 0 {
		index = 0
	}
	return ordered[index]
}

func validateAgentRecognitionBenchmarkCalibration(calibration *AgentRecognitionBenchmarkCalibration) error {
	if calibration == nil || calibration.Algorithm != AgentRecognitionBenchmarkCalibrationAlgorithm ||
		calibration.WorkloadBytes < minAgentRecognitionBenchmarkCalibrationWorkloadBytes ||
		calibration.WorkloadBytes > DefaultAgentFingerprintMaxFileBytes {
		return fmt.Errorf("%w: benchmark process-CPU calibration metadata is invalid", ErrAgentRecognitionBenchmark)
	}
	wantIterations := int((AgentRecognitionBenchmarkCalibrationTargetBytes + calibration.WorkloadBytes - 1) / calibration.WorkloadBytes)
	if wantIterations < 1 || wantIterations > maxAgentRecognitionBenchmarkCalibrationIterations ||
		calibration.IterationsPerSample != wantIterations ||
		calibration.BytesPerSample != calibration.WorkloadBytes*uint64(calibration.IterationsPerSample) ||
		len(calibration.ProcessCPUSamplesNanoseconds) != AgentRecognitionBenchmarkCalibrationSamples {
		return fmt.Errorf("%w: benchmark process-CPU calibration bounds are invalid", ErrAgentRecognitionBenchmark)
	}
	for _, sample := range calibration.ProcessCPUSamplesNanoseconds {
		if sample == 0 {
			return fmt.Errorf("%w: benchmark process-CPU calibration sample is invalid", ErrAgentRecognitionBenchmark)
		}
	}
	wantDistribution := benchmarkDistributionFromUint64(calibration.ProcessCPUSamplesNanoseconds)
	wantJSON, _ := json.Marshal(wantDistribution)
	gotJSON, _ := json.Marshal(calibration.ProcessCPUNanoseconds)
	if !bytes.Equal(wantJSON, gotJSON) || calibration.ProcessCPUNanoseconds.P50 <= 0 {
		return fmt.Errorf("%w: benchmark process-CPU calibration distribution drifted", ErrAgentRecognitionBenchmark)
	}
	return nil
}

func validAgentRecognitionBenchmarkHostText(value string) bool {
	if value == "" || len(value) > 128 || value != strings.Join(strings.Fields(value), " ") {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e || value[index] == '`' || value[index] == '|' {
			return false
		}
	}
	return true
}

func validateAgentRecognitionBenchmarkProfile(profile AgentRecognitionBenchmarkProfile) error {
	if strings.TrimSpace(profile.Name) == "" || profile.EventCount < 1 || profile.EventCount > 10000 || profile.Concurrency < 1 || profile.Concurrency > 256 || profile.InterArrivalMicroseconds < 0 || profile.InterArrivalMicroseconds > 1_000_000 || profile.HoldMilliseconds < 1 || profile.HoldMilliseconds > 10_000 {
		return fmt.Errorf("%w: workload profile is invalid", ErrAgentRecognitionBenchmark)
	}
	return nil
}

func validateAgentRecognitionBenchmarkArm(arm AgentRecognitionBenchmarkArm, profile AgentRecognitionBenchmarkProfile, enabled bool, registryVersion, registrySHA256 string) error {
	if arm.RecognitionEnabled != enabled || arm.WorkloadCompletions != profile.EventCount || arm.WorkloadElapsedNanoseconds == 0 || arm.AccountingSettleNanoseconds == 0 || arm.DaemonCPUNanoseconds == 0 || arm.DaemonPeakRSSKiB == 0 || !arm.DaemonHealthy {
		return fmt.Errorf("%w: benchmark arm health or resource metadata is invalid", ErrAgentRecognitionBenchmark)
	}
	wantExpected := uint64(0)
	if enabled {
		wantExpected = uint64(profile.EventCount)
		if arm.RegistryVersion != registryVersion || arm.RegistrySHA256 != registrySHA256 {
			return fmt.Errorf("%w: enabled arm registry metadata drifted", ErrAgentRecognitionBenchmark)
		}
	} else if arm.RegistryVersion != "" || arm.RegistrySHA256 != "" {
		return fmt.Errorf("%w: baseline arm unexpectedly reported recognition metadata", ErrAgentRecognitionBenchmark)
	}
	if arm.Capture.ExpectedEvents != wantExpected || arm.Capture.ExpectedEvents != arm.Capture.Delivered+arm.Capture.ProducerDropped+arm.Capture.Malformed+arm.Capture.Unexplained {
		return fmt.Errorf("%w: capture ledger is not exclusive and complete", ErrAgentRecognitionBenchmark)
	}
	if arm.Recognition.Candidates != arm.Recognition.Recognized+arm.Recognition.Rejected+arm.Recognition.Unexplained {
		return fmt.Errorf("%w: recognition ledger is not exclusive and complete", ErrAgentRecognitionBenchmark)
	}
	if arm.Fingerprint.Recognized != arm.Fingerprint.Success+arm.Fingerprint.Mismatch+arm.Fingerprint.Saturated+arm.Fingerprint.Unavailable+arm.Fingerprint.InFlight+arm.Fingerprint.Unexplained {
		return fmt.Errorf("%w: fingerprint ledger is not exclusive and complete", ErrAgentRecognitionBenchmark)
	}
	if arm.Fingerprint.Unavailable != arm.Fingerprint.ResolutionDenied+arm.Fingerprint.ProcessExited+arm.Fingerprint.Unsupported+arm.Fingerprint.SizeExceeded+arm.Fingerprint.DeadlineExceeded {
		return fmt.Errorf("%w: fingerprint unavailable causes are not exclusive and complete", ErrAgentRecognitionBenchmark)
	}
	if enabled && (arm.Capture.Delivered != arm.Recognition.Candidates || arm.Recognition.Recognized != arm.Fingerprint.Recognized || arm.Capture.Unexplained != 0 || arm.Recognition.Unexplained != 0 || arm.Fingerprint.InFlight != 0 || arm.Fingerprint.Unexplained != 0) {
		return fmt.Errorf("%w: enabled arm has unexplained or unsettled accounting", ErrAgentRecognitionBenchmark)
	}
	if !enabled && (arm.Capture.Delivered != 0 || arm.Capture.ProducerDropped != 0 || arm.Capture.Malformed != 0 || arm.Recognition.Candidates != 0 || arm.Fingerprint.Recognized != 0) {
		return fmt.Errorf("%w: baseline arm observed recognition work", ErrAgentRecognitionBenchmark)
	}
	return nil
}

func addCaptureLedger(total *AgentRecognitionBenchmarkCaptureLedger, value AgentRecognitionBenchmarkCaptureLedger) {
	total.ExpectedEvents += value.ExpectedEvents
	total.Delivered += value.Delivered
	total.ProducerDropped += value.ProducerDropped
	total.Malformed += value.Malformed
	total.Unexplained += value.Unexplained
}

func addRecognitionLedger(total *AgentRecognitionBenchmarkRecognitionLedger, value AgentRecognitionBenchmarkRecognitionLedger) {
	total.Candidates += value.Candidates
	total.Recognized += value.Recognized
	total.Rejected += value.Rejected
	total.Unexplained += value.Unexplained
}

func addFingerprintLedger(total *AgentRecognitionBenchmarkFingerprintLedger, value AgentRecognitionBenchmarkFingerprintLedger) {
	total.Recognized += value.Recognized
	total.Success += value.Success
	total.Mismatch += value.Mismatch
	total.Saturated += value.Saturated
	total.Unavailable += value.Unavailable
	total.ResolutionDenied += value.ResolutionDenied
	total.ProcessExited += value.ProcessExited
	total.Unsupported += value.Unsupported
	total.SizeExceeded += value.SizeExceeded
	total.DeadlineExceeded += value.DeadlineExceeded
	total.InFlight += value.InFlight
	total.Unexplained += value.Unexplained
}

func isHexDigest(value string, length int) bool {
	if len(value) != length {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func finiteNonnegative(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}

func finite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}

func nearlyEqual(left, right float64) bool {
	if !finiteNonnegative(math.Abs(left)) || !finiteNonnegative(math.Abs(right)) {
		return false
	}
	scale := math.Max(1, math.Max(math.Abs(left), math.Abs(right)))
	return math.Abs(left-right) <= scale*1e-9
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := readUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func readUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate key")
			}
			seen[key] = struct{}{}
			if err := readUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("unterminated object")
		}
	case '[':
		for decoder.More() {
			if err := readUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("unterminated array")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	return nil
}
