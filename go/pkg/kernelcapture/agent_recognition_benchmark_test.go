package kernelcapture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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
	report.Summaries[1].PairedWallOverheadPercent.P95 += 1000
	gate = EvaluateAgentRecognitionBenchmarkBudget(&report, &budget, budgetDigest)
	if gate.Status != AgentRecognitionBenchmarkGateFail {
		t.Fatalf("failing gate = %+v", gate)
	}
	want := []string{
		"budget." + report.Summaries[1].ProfileName + ".p95_wall_overhead",
		"loss." + report.Summaries[0].ProfileName + ".capture_nonzero",
	}
	if !reflect.DeepEqual(gate.Violations, want) {
		t.Fatalf("violations = %v, want %v", gate.Violations, want)
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
		"duplicate": []byte(`{"schema_version":"ardur.agent_recognition_benchmark_budget.v0.1","schema_version":"ardur.agent_recognition_benchmark_budget.v0.1"}`),
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
		"duplicate": []byte(`{"schema_version":"ardur.agent_recognition_benchmark_report.v0.1","schema_version":"ardur.agent_recognition_benchmark_report.v0.1"}`),
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

func TestCommittedAgentRecognitionBenchmarkBaselineMatchesBudget(t *testing.T) {
	report, err := LoadAgentRecognitionBenchmarkReport(filepath.Join("testdata", "agent-recognition-benchmark-baseline-967ba670.json"))
	if err != nil {
		t.Fatal(err)
	}
	budget, budgetDigest, err := LoadAgentRecognitionBenchmarkBudget(filepath.Join("testdata", "agent-recognition-benchmark-budget-v0.1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if report.SourceSHA != "967ba6702c721a351c9e52e665f16e591ac5d9b6" || report.Gate.Status != AgentRecognitionBenchmarkGateNotRun {
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

func validAgentRecognitionBenchmarkReport(t *testing.T) AgentRecognitionBenchmarkReport {
	t.Helper()
	profiles := []AgentRecognitionBenchmarkProfile{
		{Name: "low", EventCount: 4, Concurrency: 1, InterArrivalMicroseconds: 5000, HoldMilliseconds: 5},
		{Name: "sustained", EventCount: 20, Concurrency: 4, InterArrivalMicroseconds: 1000, HoldMilliseconds: 5},
		{Name: "storm", EventCount: 80, Concurrency: 16, InterArrivalMicroseconds: 0, HoldMilliseconds: 5},
	}
	report := AgentRecognitionBenchmarkReport{
		SchemaVersion: AgentRecognitionBenchmarkReportSchema,
		GeneratedAt:   time.Date(2026, 7, 14, 8, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		SourceSHA:     "0123456789abcdef0123456789abcdef01234567",
		Seed:          302, WarmupPairs: 1, MeasuredPairs: MinAgentRecognitionBenchmarkPairs,
		PairOrder:       "deterministic_ab_ba_alternation",
		Environment:     AgentRecognitionBenchmarkEnvironment{OS: "linux", Architecture: "amd64", KernelRelease: "6.8.0", GoVersion: "go1.26.5", CPUCount: 2},
		WorkloadSHA256:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RegistryVersion: "benchmark.registry.v1",
		RegistrySHA256:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Limitations:     []string{"Paired host evidence is not a universal performance claim."},
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
		SchemaVersion:          AgentRecognitionBenchmarkBudgetSchema,
		BudgetVersion:          "test.v1",
		EvidenceArtifactSHA256: report.ArtifactSHA256,
		MinimumMeasuredPairs:   MinAgentRecognitionBenchmarkPairs,
	}
	for _, summary := range report.Summaries {
		budget.Profiles = append(budget.Profiles, AgentRecognitionBenchmarkBudgetProfile{
			ProfileName:                            summary.ProfileName,
			EvidenceP50WallOverheadPercent:         summary.PairedWallOverheadPercent.P50,
			EvidenceP95WallOverheadPercent:         summary.PairedWallOverheadPercent.P95,
			WallOverheadTolerancePercentagePoints:  5,
			EvidenceP95EnabledDaemonCPUNanoseconds: summary.EnabledDaemonCPUNanoseconds.P95,
			DaemonCPURelativeTolerancePercent:      25,
			DaemonCPUAbsoluteToleranceNanoseconds:  1000,
			EvidenceMaxEnabledDaemonPeakRSSKiB:     summary.MaxEnabledDaemonPeakRSSKiB,
			PeakRSSToleranceKiB:                    1024,
		})
	}
	return budget
}

func benchmarkSHA256Hex(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
