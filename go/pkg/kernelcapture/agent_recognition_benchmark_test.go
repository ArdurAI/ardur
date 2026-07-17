package kernelcapture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFinalizeAgentRecognitionBenchmarkReportRecomputesRawPairSummariesAndDigest(t *testing.T) {
	report := validAgentRecognitionBenchmarkReport(t)
	if err := FinalizeAgentRecognitionBenchmarkReport(&report, nil, ""); err != nil {
		t.Fatal(err)
	}
	if report.Gate.Status != AgentRecognitionBenchmarkGateNotRun || len(report.Summaries) != 3 || len(report.ArtifactSHA256) != 64 {
		t.Fatalf("finalized report = %+v", report)
	}
	if err := ValidateAgentRecognitionBenchmarkReport(&report); err != nil {
		t.Fatal(err)
	}

	tampered := report
	tampered.Pairs = append([]AgentRecognitionBenchmarkPair(nil), report.Pairs...)
	tampered.Pairs[0].Enabled.Capture.Unexplained = 1
	if err := ValidateAgentRecognitionBenchmarkReport(&tampered); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("tampered report error = %v", err)
	}

	tampered = report
	tampered.Pairs = append([]AgentRecognitionBenchmarkPair(nil), report.Pairs...)
	tampered.Pairs[3].PairIndex = tampered.Pairs[0].PairIndex
	tampered.Pairs[3].Order = tampered.Pairs[0].Order
	if err := ValidateAgentRecognitionBenchmarkReport(&tampered); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("duplicated pair index error = %v", err)
	}

	tampered = report
	tampered.Pairs = append([]AgentRecognitionBenchmarkPair(nil), report.Pairs...)
	tampered.Pairs[0].Order = "enabled_then_baseline"
	if err := ValidateAgentRecognitionBenchmarkReport(&tampered); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("drifted pair order error = %v", err)
	}
}

func TestAgentRecognitionBenchmarkBudgetFailsClosedOnLossAndDrift(t *testing.T) {
	report := validAgentRecognitionBenchmarkReport(t)
	if err := FinalizeAgentRecognitionBenchmarkReport(&report, nil, ""); err != nil {
		t.Fatal(err)
	}
	budget := budgetFromReport(report)
	budgetJSON, err := json.Marshal(budget)
	if err != nil {
		t.Fatal(err)
	}
	budgetDigest := benchmarkSHA256Hex(budgetJSON)
	gate := EvaluateAgentRecognitionBenchmarkBudget(&report, &budget, budgetDigest)
	if gate.Status != AgentRecognitionBenchmarkGatePass || len(gate.Violations) != 0 {
		t.Fatalf("passing gate = %+v", gate)
	}

	report.Summaries[0].TotalCapture.ProducerDropped = 1
	report.Summaries[1].PairedWallOverheadPercent.P50 += 1000
	gate = EvaluateAgentRecognitionBenchmarkBudget(&report, &budget, budgetDigest)
	if gate.Status != AgentRecognitionBenchmarkGateFail {
		t.Fatalf("failing gate = %+v", gate)
	}
	want := []string{
		"budget." + report.Summaries[1].ProfileName + ".p50_wall_overhead",
		"loss." + report.Summaries[0].ProfileName + ".capture_nonzero",
	}
	if !reflect.DeepEqual(gate.Violations, want) {
		t.Fatalf("violations = %v, want %v", gate.Violations, want)
	}
}

func TestAgentRecognitionBenchmarkV2GateNormalizesRunnerCPUAndIgnoresWallTailOnly(t *testing.T) {
	report := validAgentRecognitionBenchmarkReport(t)
	if err := FinalizeAgentRecognitionBenchmarkReport(&report, nil, ""); err != nil {
		t.Fatal(err)
	}
	budget := budgetFromReport(report)
	budgetJSON, err := json.Marshal(budget)
	if err != nil {
		t.Fatal(err)
	}
	budgetDigest := benchmarkSHA256Hex(budgetJSON)

	// Model an unchanged workload on a runner whose CPU is exactly twice as
	// slow. Both daemon CPU and the independent process-CPU calibration scale;
	// the normalized gate must remain stable.
	for pairIndex := range report.Pairs {
		report.Pairs[pairIndex].Baseline.DaemonCPUNanoseconds *= 2
		report.Pairs[pairIndex].Enabled.DaemonCPUNanoseconds *= 2
		report.Pairs[pairIndex].DaemonCPUDeltaNanoseconds *= 2
	}
	for sampleIndex := range report.Calibration.ProcessCPUSamplesNanoseconds {
		report.Calibration.ProcessCPUSamplesNanoseconds[sampleIndex] *= 2
	}
	report.Calibration.ProcessCPUNanoseconds = benchmarkDistributionFromUint64(report.Calibration.ProcessCPUSamplesNanoseconds)

	// Two scheduling stalls move nearest-rank p95 but not p50 for 20 samples.
	// The v0.2 hard wall decision is intentionally median-only; p95 remains in
	// the artifact for diagnosis.
	profileName := report.Pairs[0].Profile.Name
	changed := 0
	for pairIndex := range report.Pairs {
		if report.Pairs[pairIndex].Profile.Name != profileName || changed == 2 {
			continue
		}
		report.Pairs[pairIndex].Enabled.WorkloadElapsedNanoseconds = report.Pairs[pairIndex].Baseline.WorkloadElapsedNanoseconds * 3
		report.Pairs[pairIndex].WallOverhead.NumeratorNanoseconds = int64(report.Pairs[pairIndex].Enabled.WorkloadElapsedNanoseconds - report.Pairs[pairIndex].Baseline.WorkloadElapsedNanoseconds)
		report.Pairs[pairIndex].WallOverhead.Percent = 200
		changed++
	}
	if err := FinalizeAgentRecognitionBenchmarkReport(&report, &budget, budgetDigest); err != nil {
		t.Fatal(err)
	}
	if report.Gate.Status != AgentRecognitionBenchmarkGatePass {
		t.Fatalf("normalized slow-runner gate = %+v", report.Gate)
	}
	for _, summary := range report.Summaries {
		if summary.ProfileName == profileName && summary.PairedWallOverheadPercent.P95 <= 100 {
			t.Fatalf("tail evidence was not preserved: %+v", summary.PairedWallOverheadPercent)
		}
	}

	// Median drift is a regression and must fail.
	changed = 0
	for pairIndex := range report.Pairs {
		if report.Pairs[pairIndex].Profile.Name != profileName || changed == 11 {
			continue
		}
		report.Pairs[pairIndex].Enabled.WorkloadElapsedNanoseconds = report.Pairs[pairIndex].Baseline.WorkloadElapsedNanoseconds * 4
		report.Pairs[pairIndex].WallOverhead.NumeratorNanoseconds = int64(report.Pairs[pairIndex].Enabled.WorkloadElapsedNanoseconds - report.Pairs[pairIndex].Baseline.WorkloadElapsedNanoseconds)
		report.Pairs[pairIndex].WallOverhead.Percent = 300
		changed++
	}
	if err := FinalizeAgentRecognitionBenchmarkReport(&report, &budget, budgetDigest); err != nil {
		t.Fatal(err)
	}
	wantViolation := "budget." + profileName + ".p50_wall_overhead"
	if report.Gate.Status != AgentRecognitionBenchmarkGateFail || !reflect.DeepEqual(report.Gate.Violations, []string{wantViolation}) {
		t.Fatalf("median regression gate = %+v, want %q", report.Gate, wantViolation)
	}

	// Loss remains fail-closed and is never normalized away.
	report.Summaries[0].TotalCapture.ProducerDropped = 1
	report.Summaries[1].TotalFingerprint.Mismatch = 1
	gate := EvaluateAgentRecognitionBenchmarkBudget(&report, &budget, budgetDigest)
	if gate.Status != AgentRecognitionBenchmarkGateFail ||
		!containsString(gate.Violations, "loss."+report.Summaries[0].ProfileName+".capture_nonzero") ||
		!containsString(gate.Violations, "loss."+report.Summaries[1].ProfileName+".fingerprint_nonzero") {
		t.Fatalf("loss gate = %+v", gate)
	}
}

func TestAgentRecognitionBenchmarkEvidenceOnlyModeFailsClosedOnCorrectness(t *testing.T) {
	report := validAgentRecognitionBenchmarkReport(t)
	pair := &report.Pairs[0]
	pair.Enabled.Capture.Delivered--
	pair.Enabled.Capture.ProducerDropped++
	pair.Enabled.Recognition.Candidates--
	pair.Enabled.Recognition.Recognized--
	pair.Enabled.Fingerprint.Recognized--
	pair.Enabled.Fingerprint.Success--

	if err := FinalizeAgentRecognitionBenchmarkReport(&report, nil, ""); err != nil {
		t.Fatal(err)
	}
	want := []string{"loss." + pair.Profile.Name + ".capture_nonzero"}
	if report.Gate.Status != AgentRecognitionBenchmarkGateFail || report.Gate.BudgetSHA256 != "" || !reflect.DeepEqual(report.Gate.Violations, want) {
		t.Fatalf("evidence-only correctness gate = %+v, want %v", report.Gate, want)
	}
	if err := ValidateAgentRecognitionBenchmarkReport(&report); err != nil {
		t.Fatalf("failed evidence must remain publishable: %v", err)
	}
}

func TestValidateAgentRecognitionBenchmarkV2RequiresCalibrationAndRunnerContext(t *testing.T) {
	report := validAgentRecognitionBenchmarkReport(t)
	if err := FinalizeAgentRecognitionBenchmarkReport(&report, nil, ""); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != AgentRecognitionBenchmarkReportSchemaV2 || report.Calibration == nil {
		t.Fatalf("v0.2 report contract missing: %+v", report)
	}

	for name, mutate := range map[string]func(*AgentRecognitionBenchmarkReport){
		"calibration":          func(value *AgentRecognitionBenchmarkReport) { value.Calibration = nil },
		"cpu model":            func(value *AgentRecognitionBenchmarkReport) { value.Environment.CPUModel = "" },
		"cgroup cpu max":       func(value *AgentRecognitionBenchmarkReport) { value.Environment.CgroupCPUMax = "" },
		"effective cpu set":    func(value *AgentRecognitionBenchmarkReport) { value.Environment.EffectiveCPUSet = "" },
		"runner image os":      func(value *AgentRecognitionBenchmarkReport) { value.Environment.RunnerImageOS = "" },
		"runner image version": func(value *AgentRecognitionBenchmarkReport) { value.Environment.RunnerImageVersion = "" },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := report
			mutate(&tampered)
			if err := ValidateAgentRecognitionBenchmarkReport(&tampered); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
				t.Fatalf("missing %s error = %v", name, err)
			}
		})
	}
}

func TestAgentRecognitionBenchmarkV1EvidenceRemainsStrictlyLoadable(t *testing.T) {
	report, err := LoadAgentRecognitionBenchmarkReport(filepath.Join("testdata", "agent-recognition-benchmark-evidence-203c101.json"))
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != AgentRecognitionBenchmarkReportSchemaV1 || report.Calibration != nil {
		t.Fatalf("legacy report was reinterpreted: schema=%q calibration=%+v", report.SchemaVersion, report.Calibration)
	}
	for _, summary := range report.Summaries {
		if summary.EnabledDaemonCPUCalibrationRatio != nil {
			t.Fatalf("legacy summary gained normalized data: %+v", summary)
		}
	}
}

func TestAgentRecognitionBenchmarkV2BudgetRejectsAmbiguousEvidenceAndSchemaMixing(t *testing.T) {
	report := validAgentRecognitionBenchmarkReport(t)
	if err := FinalizeAgentRecognitionBenchmarkReport(&report, nil, ""); err != nil {
		t.Fatal(err)
	}
	budget := budgetFromReport(report)

	duplicated := budget
	duplicated.EvidenceArtifactSHA256s = append([]string(nil), budget.EvidenceArtifactSHA256s...)
	duplicated.EvidenceArtifactSHA256s[2] = duplicated.EvidenceArtifactSHA256s[1]
	if err := ValidateAgentRecognitionBenchmarkBudget(&duplicated); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("duplicated evidence error = %v", err)
	}

	ambiguous := budget
	ambiguous.Profiles = append([]AgentRecognitionBenchmarkBudgetProfile(nil), budget.Profiles...)
	ambiguous.Profiles[0].EvidenceP95EnabledDaemonCPUNanoseconds = 1
	if err := ValidateAgentRecognitionBenchmarkBudget(&ambiguous); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("mixed normalized/absolute budget error = %v", err)
	}

	for name, mutate := range map[string]func(*AgentRecognitionBenchmarkBudgetProfile){
		"wall threshold overflow": func(profile *AgentRecognitionBenchmarkBudgetProfile) {
			profile.EvidenceP50WallOverheadPercent = math.MaxFloat64
			profile.WallOverheadTolerancePercentagePoints = math.MaxFloat64
		},
		"normalized CPU threshold overflow": func(profile *AgentRecognitionBenchmarkBudgetProfile) {
			profile.EvidenceP95EnabledDaemonCPUCalibrationRatio = math.MaxFloat64
			profile.DaemonCPUCalibrationRatioRelativeTolerancePercent = 100
		},
	} {
		t.Run(name, func(t *testing.T) {
			overflow := budget
			overflow.Profiles = append([]AgentRecognitionBenchmarkBudgetProfile(nil), budget.Profiles...)
			mutate(&overflow.Profiles[0])
			if err := ValidateAgentRecognitionBenchmarkBudget(&overflow); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
				t.Fatalf("overflowing budget error = %v", err)
			}
		})
	}

	legacyBudget, legacyDigest, err := LoadAgentRecognitionBenchmarkBudget(filepath.Join("testdata", "agent-recognition-benchmark-budget-v0.1.json"))
	if err != nil {
		t.Fatal(err)
	}
	gate := EvaluateAgentRecognitionBenchmarkBudget(&report, legacyBudget, legacyDigest)
	if gate.Status != AgentRecognitionBenchmarkGateFail || !reflect.DeepEqual(gate.Violations, []string{"budget.invalid"}) {
		t.Fatalf("mixed v0.2 report/v0.1 budget gate = %+v", gate)
	}
}

func TestLoadAgentRecognitionBenchmarkBudgetRejectsUnknownDuplicateTrailingAndSymlink(t *testing.T) {
	report := validAgentRecognitionBenchmarkReport(t)
	if err := FinalizeAgentRecognitionBenchmarkReport(&report, nil, ""); err != nil {
		t.Fatal(err)
	}
	budget := budgetFromReport(report)
	raw, err := json.Marshal(budget)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	valid := filepath.Join(root, "budget.json")
	if err := os.WriteFile(valid, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, digest, err := LoadAgentRecognitionBenchmarkBudget(valid)
	if err != nil || loaded.BudgetVersion != budget.BudgetVersion || digest != benchmarkSHA256Hex(raw) {
		t.Fatalf("loaded budget=%+v digest=%q error=%v", loaded, digest, err)
	}

	for name, hostile := range map[string][]byte{
		"unknown":   append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...),
		"duplicate": append(raw[:len(raw)-1], []byte(`,"schema_version":"ardur.agent_recognition_benchmark_budget.v0.1"}`)...),
		"trailing":  append(append([]byte(nil), raw...), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, name+".json")
			if err := os.WriteFile(path, hostile, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := LoadAgentRecognitionBenchmarkBudget(path); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
				t.Fatalf("hostile budget error = %v", err)
			}
		})
	}

	link := filepath.Join(root, "budget-link.json")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadAgentRecognitionBenchmarkBudget(link); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("symlink budget error = %v", err)
	}
}

func TestLoadAgentRecognitionBenchmarkReportRejectsUnknownDuplicateTrailingAndSymlink(t *testing.T) {
	report := validAgentRecognitionBenchmarkReport(t)
	if err := FinalizeAgentRecognitionBenchmarkReport(&report, nil, ""); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	valid := filepath.Join(root, "report.json")
	if err := os.WriteFile(valid, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadAgentRecognitionBenchmarkReport(valid)
	if err != nil || loaded.ArtifactSHA256 != report.ArtifactSHA256 {
		t.Fatalf("loaded report=%+v error=%v", loaded, err)
	}

	for name, hostile := range map[string][]byte{
		"unknown":   append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...),
		"duplicate": append(raw[:len(raw)-1], []byte(`,"schema_version":"ardur.agent_recognition_benchmark_report.v0.1"}`)...),
		"trailing":  append(append([]byte(nil), raw...), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, name+".json")
			if err := os.WriteFile(path, hostile, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadAgentRecognitionBenchmarkReport(path); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
				t.Fatalf("hostile report error = %v", err)
			}
		})
	}

	link := filepath.Join(root, "report-link.json")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAgentRecognitionBenchmarkReport(link); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
		t.Fatalf("symlink report error = %v", err)
	}
}

func TestCommittedAgentRecognitionBenchmarkEvidenceMatchesBudget(t *testing.T) {
	report, err := LoadAgentRecognitionBenchmarkReport(filepath.Join("testdata", "agent-recognition-benchmark-evidence-203c101.json"))
	if err != nil {
		t.Fatal(err)
	}
	budget, budgetDigest, err := LoadAgentRecognitionBenchmarkBudget(filepath.Join("testdata", "agent-recognition-benchmark-budget-v0.1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if report.SourceSHA != "203c1016dbec3740608e8f1a9a5ce71e90f5de78" || report.Gate.Status != AgentRecognitionBenchmarkGatePass || report.Gate.BudgetSHA256 != "33aec8ad75d09e2831f9c65ad8dbfbe7e86a8fd6ef1e3b2b67c50ffba65fe94f" || len(report.Gate.Violations) != 0 {
		t.Fatalf("reviewed evidence provenance drifted: source=%q gate=%q", report.SourceSHA, report.Gate.Status)
	}
	if budget.EvidenceArtifactSHA256 != report.ArtifactSHA256 {
		t.Fatalf("budget evidence digest = %q, want %q", budget.EvidenceArtifactSHA256, report.ArtifactSHA256)
	}
	summaries := make(map[string]AgentRecognitionBenchmarkProfileSummary, len(report.Summaries))
	for _, summary := range report.Summaries {
		summaries[summary.ProfileName] = summary
	}
	for _, profile := range budget.Profiles {
		summary, ok := summaries[profile.ProfileName]
		if !ok || !nearlyEqual(profile.EvidenceP50WallOverheadPercent, summary.PairedWallOverheadPercent.P50) ||
			!nearlyEqual(profile.EvidenceP95WallOverheadPercent, summary.PairedWallOverheadPercent.P95) ||
			!nearlyEqual(profile.EvidenceP95EnabledDaemonCPUNanoseconds, summary.EnabledDaemonCPUNanoseconds.P95) ||
			profile.EvidenceMaxEnabledDaemonPeakRSSKiB != summary.MaxEnabledDaemonPeakRSSKiB {
			t.Fatalf("budget profile %q drifted from reviewed evidence", profile.ProfileName)
		}
	}
	gate := EvaluateAgentRecognitionBenchmarkBudget(report, budget, budgetDigest)
	if gate.Status != AgentRecognitionBenchmarkGatePass || len(gate.Violations) != 0 {
		t.Fatalf("reviewed baseline does not pass its bound budget: %+v", gate)
	}
}

func TestCommittedAgentRecognitionBenchmarkV2EvidenceMatchesBudget(t *testing.T) {
	evidenceFiles := []string{
		"agent-recognition-benchmark-evidence-a0bdcd9-run29575721818-attempt1.json",
		"agent-recognition-benchmark-evidence-a0bdcd9-run29575721818-attempt2.json",
		"agent-recognition-benchmark-evidence-a0bdcd9-run29575721818-attempt3.json",
	}
	type reviewedProfileEvidence struct {
		p50WallOverheadPercent              float64
		p95WallOverheadPercent              float64
		p95EnabledDaemonCPUCalibrationRatio float64
		maxEnabledDaemonPeakRSSKiB          uint64
	}
	aggregates := make(map[string]reviewedProfileEvidence, 3)
	reports := make([]*AgentRecognitionBenchmarkReport, 0, len(evidenceFiles))
	artifactDigests := make([]string, 0, len(evidenceFiles))
	cpuModels := make(map[string]struct{})
	var expectedEvents, deliveredEvents, recognizedEvents, fingerprintSuccesses uint64
	for _, evidenceFile := range evidenceFiles {
		report, err := LoadAgentRecognitionBenchmarkReport(filepath.Join("testdata", evidenceFile))
		if err != nil {
			t.Fatalf("load %s: %v", evidenceFile, err)
		}
		if report.SchemaVersion != AgentRecognitionBenchmarkReportSchemaV2 || report.SourceSHA != "a0bdcd981107631a45476ac27f84ed17da2d221d" || report.Calibration == nil ||
			report.Gate.Status != AgentRecognitionBenchmarkGateNotRun || report.Gate.BudgetSHA256 != "" || len(report.Gate.Violations) != 0 {
			t.Fatalf("reviewed v0.2 evidence provenance drifted for %s", evidenceFile)
		}
		reports = append(reports, report)
		artifactDigests = append(artifactDigests, report.ArtifactSHA256)
		cpuModels[report.Environment.CPUModel] = struct{}{}
		for _, summary := range report.Summaries {
			if summary.EnabledDaemonCPUCalibrationRatio == nil {
				t.Fatalf("reviewed v0.2 evidence %s profile %q has no normalized CPU distribution", evidenceFile, summary.ProfileName)
			}
			aggregate := aggregates[summary.ProfileName]
			aggregate.p50WallOverheadPercent = math.Max(aggregate.p50WallOverheadPercent, summary.PairedWallOverheadPercent.P50)
			aggregate.p95WallOverheadPercent = math.Max(aggregate.p95WallOverheadPercent, summary.PairedWallOverheadPercent.P95)
			aggregate.p95EnabledDaemonCPUCalibrationRatio = math.Max(aggregate.p95EnabledDaemonCPUCalibrationRatio, summary.EnabledDaemonCPUCalibrationRatio.P95)
			if summary.MaxEnabledDaemonPeakRSSKiB > aggregate.maxEnabledDaemonPeakRSSKiB {
				aggregate.maxEnabledDaemonPeakRSSKiB = summary.MaxEnabledDaemonPeakRSSKiB
			}
			aggregates[summary.ProfileName] = aggregate
			expectedEvents += summary.TotalCapture.ExpectedEvents
			deliveredEvents += summary.TotalCapture.Delivered
			recognizedEvents += summary.TotalRecognition.Recognized
			fingerprintSuccesses += summary.TotalFingerprint.Success
		}
	}
	if len(cpuModels) < 2 {
		t.Fatalf("reviewed evidence covers %d CPU model(s), want at least 2", len(cpuModels))
	}
	if expectedEvents != 6240 || deliveredEvents != expectedEvents || recognizedEvents != expectedEvents || fingerprintSuccesses != expectedEvents {
		t.Fatalf("reviewed evidence correctness totals: expected=%d delivered=%d recognized=%d fingerprint_success=%d", expectedEvents, deliveredEvents, recognizedEvents, fingerprintSuccesses)
	}

	budget, budgetDigest, err := LoadAgentRecognitionBenchmarkBudget(filepath.Join("testdata", "agent-recognition-benchmark-budget-v0.2.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !stringSlicesEqual(budget.EvidenceArtifactSHA256s, artifactDigests) {
		t.Fatalf("budget evidence digests = %v, want %v", budget.EvidenceArtifactSHA256s, artifactDigests)
	}
	for _, profile := range budget.Profiles {
		aggregate, ok := aggregates[profile.ProfileName]
		if !ok || !nearlyEqual(profile.EvidenceP50WallOverheadPercent, aggregate.p50WallOverheadPercent) ||
			!nearlyEqual(profile.EvidenceP95WallOverheadPercent, aggregate.p95WallOverheadPercent) ||
			!nearlyEqual(profile.EvidenceP95EnabledDaemonCPUCalibrationRatio, aggregate.p95EnabledDaemonCPUCalibrationRatio) ||
			profile.EvidenceMaxEnabledDaemonPeakRSSKiB != aggregate.maxEnabledDaemonPeakRSSKiB {
			t.Fatalf("budget profile %q drifted from reviewed v0.2 evidence", profile.ProfileName)
		}
	}
	for index, report := range reports {
		gate := EvaluateAgentRecognitionBenchmarkBudget(report, budget, budgetDigest)
		if gate.Status != AgentRecognitionBenchmarkGatePass || len(gate.Violations) != 0 {
			t.Fatalf("reviewed evidence %s does not pass its bound budget: %+v", evidenceFiles[index], gate)
		}
	}
}

func validAgentRecognitionBenchmarkReport(t *testing.T) AgentRecognitionBenchmarkReport {
	t.Helper()
	profiles := []AgentRecognitionBenchmarkProfile{
		{Name: "low", EventCount: 4, Concurrency: 1, InterArrivalMicroseconds: 5000, HoldMilliseconds: 5},
		{Name: "sustained", EventCount: 20, Concurrency: 4, InterArrivalMicroseconds: 1000, HoldMilliseconds: 5},
		{Name: "storm", EventCount: 80, Concurrency: 16, InterArrivalMicroseconds: 0, HoldMilliseconds: 5},
	}
	report := AgentRecognitionBenchmarkReport{
		SchemaVersion: AgentRecognitionBenchmarkReportSchemaV2,
		GeneratedAt:   time.Date(2026, 7, 14, 8, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		SourceSHA:     "0123456789abcdef0123456789abcdef01234567",
		Seed:          302, WarmupPairs: 1, MeasuredPairs: MinAgentRecognitionBenchmarkPairs,
		PairOrder: "deterministic_ab_ba_alternation",
		Environment: AgentRecognitionBenchmarkEnvironment{
			OS: "linux", Architecture: "amd64", KernelRelease: "6.8.0", GoVersion: "go1.26.5", CPUCount: 2,
			CPUModel: "Synthetic CPU", CgroupCPUMax: "200000 100000", EffectiveCPUSet: "0-1",
			RunnerImageOS: "ubuntu24", RunnerImageVersion: "20260714.1.0",
		},
		WorkloadSHA256:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RegistryVersion: "benchmark.registry.v1",
		RegistrySHA256:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Limitations:     []string{"Paired host evidence is not a universal performance claim."},
		Calibration: &AgentRecognitionBenchmarkCalibration{
			Algorithm:     AgentRecognitionBenchmarkCalibrationAlgorithm,
			WorkloadBytes: 2 << 20, IterationsPerSample: 128, BytesPerSample: 256 << 20,
			ProcessCPUSamplesNanoseconds: []uint64{100_000_000, 101_000_000, 99_000_000},
			ProcessCPUNanoseconds:        benchmarkDistributionFromUint64([]uint64{100_000_000, 101_000_000, 99_000_000}),
		},
	}
	for pairIndex := 0; pairIndex < report.MeasuredPairs; pairIndex++ {
		order := "baseline_then_enabled"
		if pairIndex%2 == 1 {
			order = "enabled_then_baseline"
		}
		for profileIndex, profile := range profiles {
			baseline := AgentRecognitionBenchmarkArm{
				WorkloadCompletions: profile.EventCount, WorkloadElapsedNanoseconds: uint64(1_000_000 + pairIndex*100 + profileIndex*1000),
				AccountingSettleNanoseconds: 500, DaemonCPUNanoseconds: 1000, DaemonPeakRSSKiB: 2048, DaemonHealthy: true,
				Capture: AgentRecognitionBenchmarkCaptureLedger{}, Fingerprint: AgentRecognitionBenchmarkFingerprintLedger{},
			}
			enabled := AgentRecognitionBenchmarkArm{
				RecognitionEnabled: true, WorkloadCompletions: profile.EventCount, WorkloadElapsedNanoseconds: baseline.WorkloadElapsedNanoseconds + 100_000,
				AccountingSettleNanoseconds: 700, DaemonCPUNanoseconds: 2000, DaemonPeakRSSKiB: 4096, DaemonHealthy: true,
				RegistryVersion: report.RegistryVersion, RegistrySHA256: report.RegistrySHA256,
				Capture:     AgentRecognitionBenchmarkCaptureLedger{ExpectedEvents: uint64(profile.EventCount), Delivered: uint64(profile.EventCount)},
				Recognition: AgentRecognitionBenchmarkRecognitionLedger{Candidates: uint64(profile.EventCount), Recognized: uint64(profile.EventCount)},
				Fingerprint: AgentRecognitionBenchmarkFingerprintLedger{Recognized: uint64(profile.EventCount), Success: uint64(profile.EventCount)},
			}
			pair, err := NewAgentRecognitionBenchmarkPair(pairIndex, order, profile, baseline, enabled)
			if err != nil {
				t.Fatal(err)
			}
			report.Pairs = append(report.Pairs, pair)
		}
	}
	return report
}

func budgetFromReport(report AgentRecognitionBenchmarkReport) AgentRecognitionBenchmarkBudget {
	budget := AgentRecognitionBenchmarkBudget{
		SchemaVersion: AgentRecognitionBenchmarkBudgetSchemaV2,
		BudgetVersion: "test.v2",
		EvidenceArtifactSHA256s: []string{
			strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64),
		},
		MinimumMeasuredPairs: MinAgentRecognitionBenchmarkPairs,
	}
	for _, summary := range report.Summaries {
		budget.Profiles = append(budget.Profiles, AgentRecognitionBenchmarkBudgetProfile{
			ProfileName:                                       summary.ProfileName,
			EvidenceP50WallOverheadPercent:                    summary.PairedWallOverheadPercent.P50,
			EvidenceP95WallOverheadPercent:                    summary.PairedWallOverheadPercent.P95,
			WallOverheadTolerancePercentagePoints:             5,
			EvidenceP95EnabledDaemonCPUCalibrationRatio:       summary.EnabledDaemonCPUCalibrationRatio.P95,
			DaemonCPUCalibrationRatioRelativeTolerancePercent: 25,
			DaemonCPUCalibrationRatioAbsoluteTolerance:        0.01,
			EvidenceMaxEnabledDaemonPeakRSSKiB:                summary.MaxEnabledDaemonPeakRSSKiB,
			PeakRSSToleranceKiB:                               1024,
		})
	}
	return budget
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func benchmarkSHA256Hex(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
