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

func TestValidateAgentRecognitionBenchmarkArmRejectsLedgerOverflow(t *testing.T) {
	t.Parallel()
	report := validAgentRecognitionBenchmarkReport(t)
	profile := report.Pairs[0].Profile
	max := ^uint64(0)
	tests := []struct {
		name   string
		mutate func(*AgentRecognitionBenchmarkArm)
	}{
		{
			name: "capture",
			mutate: func(arm *AgentRecognitionBenchmarkArm) {
				arm.Capture.Delivered = max
				arm.Capture.ProducerDropped = uint64(profile.EventCount) + 1
			},
		},
		{
			name: "recognition",
			mutate: func(arm *AgentRecognitionBenchmarkArm) {
				arm.Recognition.Recognized = max
				arm.Recognition.Rejected = arm.Recognition.Candidates + 1
			},
		},
		{
			name: "fingerprint terminal",
			mutate: func(arm *AgentRecognitionBenchmarkArm) {
				arm.Fingerprint.Success = max
				arm.Fingerprint.Mismatch = arm.Fingerprint.Recognized + 1
			},
		},
		{
			name: "fingerprint unavailable",
			mutate: func(arm *AgentRecognitionBenchmarkArm) {
				arm.Fingerprint.Success = 0
				arm.Fingerprint.Unavailable = arm.Fingerprint.Recognized
				arm.Fingerprint.ResolutionDenied = max
				arm.Fingerprint.ProcessExited = arm.Fingerprint.Unavailable + 1
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			arm := report.Pairs[0].Enabled
			test.mutate(&arm)
			if err := validateAgentRecognitionBenchmarkArm(arm, profile, true, report.RegistryVersion, report.RegistrySHA256); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
				t.Fatalf("ledger overflow error = %v", err)
			}
		})
	}
}

func TestNewAgentRecognitionBenchmarkPairRejectsUnrepresentableSignedDeltas(t *testing.T) {
	t.Parallel()
	report := validAgentRecognitionBenchmarkReport(t)
	pair := report.Pairs[0]
	max := ^uint64(0)
	tests := []struct {
		name   string
		mutate func(*AgentRecognitionBenchmarkArm, *AgentRecognitionBenchmarkArm)
	}{
		{name: "baseline elapsed", mutate: func(baseline, _ *AgentRecognitionBenchmarkArm) { baseline.WorkloadElapsedNanoseconds = max }},
		{name: "enabled elapsed", mutate: func(_, enabled *AgentRecognitionBenchmarkArm) { enabled.WorkloadElapsedNanoseconds = max }},
		{name: "baseline CPU", mutate: func(baseline, _ *AgentRecognitionBenchmarkArm) { baseline.DaemonCPUNanoseconds = max }},
		{name: "enabled CPU", mutate: func(_, enabled *AgentRecognitionBenchmarkArm) { enabled.DaemonCPUNanoseconds = max }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			baseline := pair.Baseline
			enabled := pair.Enabled
			test.mutate(&baseline, &enabled)
			if _, err := NewAgentRecognitionBenchmarkPair(pair.PairIndex, pair.Order, pair.Profile, baseline, enabled); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
				t.Fatalf("unrepresentable delta error = %v", err)
			}
		})
	}
}

func TestNewAgentRecognitionBenchmarkReferencePairRejectsUnrepresentableOperands(t *testing.T) {
	t.Parallel()
	report := validAgentRecognitionBenchmarkReport(t)
	pair := report.Pairs[0]
	referenceArm := pair.Enabled
	max := ^uint64(0)
	tests := []struct {
		name   string
		mutate func(*AgentRecognitionBenchmarkArm)
	}{
		{name: "reference elapsed", mutate: func(reference *AgentRecognitionBenchmarkArm) { reference.WorkloadElapsedNanoseconds = max }},
		{name: "reference CPU", mutate: func(reference *AgentRecognitionBenchmarkArm) { reference.DaemonCPUNanoseconds = max }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			reference := referenceArm
			test.mutate(&reference)
			if _, err := NewAgentRecognitionBenchmarkReferencePair(pair.PairIndex, pair.Order, pair.Profile, pair.Baseline, reference, pair.Enabled); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) || !strings.Contains(err.Error(), "reference duration or CPU operand") {
				t.Fatalf("unrepresentable reference operand error = %v", err)
			}
		})
	}
}

func TestFinalizeAgentRecognitionBenchmarkReportRejectsSummaryOverflow(t *testing.T) {
	t.Parallel()
	max := ^uint64(0)
	tests := []struct {
		name   string
		mutate func(*AgentRecognitionBenchmarkPair)
	}{
		{name: "capture", mutate: func(pair *AgentRecognitionBenchmarkPair) { pair.Enabled.Capture.Delivered = max }},
		{name: "recognition", mutate: func(pair *AgentRecognitionBenchmarkPair) { pair.Enabled.Recognition.Candidates = max }},
		{name: "fingerprint", mutate: func(pair *AgentRecognitionBenchmarkPair) { pair.Enabled.Fingerprint.Success = max }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			report := validAgentRecognitionBenchmarkReport(t)
			test.mutate(&report.Pairs[0])
			if err := FinalizeAgentRecognitionBenchmarkReport(&report, nil, ""); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
				t.Fatalf("summary overflow error = %v", err)
			}
		})
	}
}

func TestLoadAgentRecognitionBenchmarkReportRejectsWrappedLossCancellation(t *testing.T) {
	t.Parallel()
	report := validAgentRecognitionBenchmarkReport(t)
	if err := FinalizeAgentRecognitionBenchmarkReport(&report, nil, ""); err != nil {
		t.Fatal(err)
	}
	lowPairs := make([]*AgentRecognitionBenchmarkPair, 0, 2)
	for index := range report.Pairs {
		if report.Pairs[index].Profile.Name == "low" {
			lowPairs = append(lowPairs, &report.Pairs[index])
			if len(lowPairs) == 2 {
				break
			}
		}
	}
	if len(lowPairs) != 2 {
		t.Fatalf("low-profile pairs = %d, want 2", len(lowPairs))
	}
	setDelivered := func(arm *AgentRecognitionBenchmarkArm, delivered, dropped uint64) {
		arm.Capture.Delivered = delivered
		arm.Capture.ProducerDropped = dropped
		arm.Recognition.Candidates = delivered
		arm.Recognition.Recognized = delivered
		arm.Fingerprint.Recognized = delivered
		arm.Fingerprint.Success = delivered
	}
	setDelivered(&lowPairs[0].Enabled, uint64(lowPairs[0].Profile.EventCount)-1, 1)
	setDelivered(&lowPairs[1].Enabled, uint64(lowPairs[1].Profile.EventCount)+1, ^uint64(0))

	path := writeAgentRecognitionBenchmarkReportWithDigest(t, &report, "wrapped-loss-report.json")
	if _, err := LoadAgentRecognitionBenchmarkReport(path); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) || !strings.Contains(err.Error(), "capture ledger counter overflowed") {
		t.Fatalf("wrapped loss report error = %v", err)
	}
}

func TestLoadAgentRecognitionBenchmarkReportRejectsUnrepresentableSignedDeltas(t *testing.T) {
	t.Parallel()
	report := validAgentRecognitionBenchmarkReport(t)
	if err := FinalizeAgentRecognitionBenchmarkReport(&report, nil, ""); err != nil {
		t.Fatal(err)
	}
	pair := &report.Pairs[0]
	pair.Enabled.WorkloadElapsedNanoseconds = ^uint64(0)
	pair.Enabled.DaemonCPUNanoseconds = ^uint64(0)
	pair.WallOverhead.NumeratorNanoseconds = int64(pair.Enabled.WorkloadElapsedNanoseconds) - int64(pair.Baseline.WorkloadElapsedNanoseconds)
	pair.WallOverhead.Percent = (float64(pair.WallOverhead.NumeratorNanoseconds) / float64(pair.WallOverhead.DenominatorNanoseconds)) * 100
	pair.DaemonCPUDeltaNanoseconds = int64(pair.Enabled.DaemonCPUNanoseconds) - int64(pair.Baseline.DaemonCPUNanoseconds)
	summaries, err := summarizeAgentRecognitionBenchmark(report.Pairs, report.Calibration)
	if err != nil {
		t.Fatal(err)
	}
	report.Summaries = summaries
	path := writeAgentRecognitionBenchmarkReportWithDigest(t, &report, "wrapped-signed-delta-report.json")
	if _, err := LoadAgentRecognitionBenchmarkReport(path); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) || !strings.Contains(err.Error(), "health or resource metadata is invalid") {
		t.Fatalf("unrepresentable signed delta report error = %v", err)
	}
}

func writeAgentRecognitionBenchmarkReportWithDigest(t *testing.T, report *AgentRecognitionBenchmarkReport, name string) string {
	t.Helper()
	report.ArtifactSHA256 = ""
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	report.ArtifactSHA256 = hex.EncodeToString(digest[:])
	payload, err = json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
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

func TestAgentRecognitionBenchmarkV3GateUsesSameVMReferenceCPU(t *testing.T) {
	report := validAgentRecognitionBenchmarkReferenceReport(t)
	if err := FinalizeAgentRecognitionBenchmarkReport(&report, nil, ""); err != nil {
		t.Fatal(err)
	}
	budget := budgetFromReferenceReport(report)
	budgetJSON, err := json.Marshal(budget)
	if err != nil {
		t.Fatal(err)
	}
	budgetDigest := benchmarkSHA256Hex(budgetJSON)
	if gate := EvaluateAgentRecognitionBenchmarkBudget(&report, &budget, budgetDigest); gate.Status != AgentRecognitionBenchmarkGatePass || len(gate.Violations) != 0 {
		t.Fatalf("passing same-VM gate = %+v", gate)
	}

	// A uniformly slower VM changes all raw daemon CPU values while the
	// current/reference ratio remains stable. Synthetic calibration is retained
	// as evidence but is not the v0.3 hard CPU decision.
	for pairIndex := range report.Pairs {
		pair := &report.Pairs[pairIndex]
		pair.Baseline.DaemonCPUNanoseconds *= 2
		pair.Enabled.DaemonCPUNanoseconds *= 2
		pair.ReferenceEnabled.DaemonCPUNanoseconds *= 2
		pair.DaemonCPUDeltaNanoseconds *= 2
		pair.EnabledToReferenceDaemonCPURatio = float64(pair.Enabled.DaemonCPUNanoseconds) / float64(pair.ReferenceEnabled.DaemonCPUNanoseconds)
	}
	if err := FinalizeAgentRecognitionBenchmarkReport(&report, &budget, budgetDigest); err != nil {
		t.Fatal(err)
	}
	if report.Gate.Status != AgentRecognitionBenchmarkGatePass {
		t.Fatalf("same-VM slow-runner gate = %+v", report.Gate)
	}

	// Current-only CPU growth remains a regression on the same VM.
	profileName := report.Pairs[0].Profile.Name
	for pairIndex := range report.Pairs {
		pair := &report.Pairs[pairIndex]
		if pair.Profile.Name != profileName {
			continue
		}
		pair.Enabled.DaemonCPUNanoseconds *= 2
		pair.DaemonCPUDeltaNanoseconds = int64(pair.Enabled.DaemonCPUNanoseconds) - int64(pair.Baseline.DaemonCPUNanoseconds)
		pair.EnabledToReferenceDaemonCPURatio = float64(pair.Enabled.DaemonCPUNanoseconds) / float64(pair.ReferenceEnabled.DaemonCPUNanoseconds)
	}
	if err := FinalizeAgentRecognitionBenchmarkReport(&report, &budget, budgetDigest); err != nil {
		t.Fatal(err)
	}
	wantViolation := "budget." + profileName + ".p95_enabled_to_reference_daemon_cpu"
	if report.Gate.Status != AgentRecognitionBenchmarkGateFail || !reflect.DeepEqual(report.Gate.Violations, []string{wantViolation}) {
		t.Fatalf("same-VM CPU regression gate = %+v, want %q", report.Gate, wantViolation)
	}
}

func TestAgentRecognitionBenchmarkV3ReferenceCorrectnessFailsClosed(t *testing.T) {
	report := validAgentRecognitionBenchmarkReferenceReport(t)
	pair := &report.Pairs[0]
	pair.ReferenceEnabled.Capture.Delivered--
	pair.ReferenceEnabled.Capture.ProducerDropped++
	pair.ReferenceEnabled.Recognition.Candidates--
	pair.ReferenceEnabled.Recognition.Recognized--
	pair.ReferenceEnabled.Fingerprint.Recognized--
	pair.ReferenceEnabled.Fingerprint.Success--

	if err := FinalizeAgentRecognitionBenchmarkReport(&report, nil, ""); err != nil {
		t.Fatal(err)
	}
	want := []string{"reference_loss." + pair.Profile.Name + ".capture_nonzero"}
	if report.Gate.Status != AgentRecognitionBenchmarkGateFail || !reflect.DeepEqual(report.Gate.Violations, want) {
		t.Fatalf("reference correctness gate = %+v, want %v", report.Gate, want)
	}
	if err := ValidateAgentRecognitionBenchmarkReport(&report); err != nil {
		t.Fatalf("failed reference evidence must remain publishable: %v", err)
	}
}

func TestAgentRecognitionBenchmarkV3PartialReferenceAccountingFailsClosed(t *testing.T) {
	report := validAgentRecognitionBenchmarkReferenceReport(t)
	if err := FinalizeAgentRecognitionBenchmarkReport(&report, nil, ""); err != nil {
		t.Fatal(err)
	}
	report.Summaries[0].ReferenceTotalFingerprint = nil

	gate := EvaluateAgentRecognitionBenchmarkBudget(&report, nil, "")
	want := []string{"budget.invalid", "reference_loss." + report.Summaries[0].ProfileName + ".accounting_missing"}
	if gate.Status != AgentRecognitionBenchmarkGateFail || !reflect.DeepEqual(gate.Violations, want) {
		t.Fatalf("partial reference accounting gate = %+v, want %v", gate, want)
	}
}

func TestValidateAgentRecognitionBenchmarkV3RequiresReferenceProvenanceAndOrder(t *testing.T) {
	report := validAgentRecognitionBenchmarkReferenceReport(t)
	if err := FinalizeAgentRecognitionBenchmarkReport(&report, nil, ""); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != AgentRecognitionBenchmarkReportSchemaV3 || report.ReferenceSourceSHA == "" || report.PairOrder != "deterministic_six_arm_order_rotation" {
		t.Fatalf("v0.3 report contract missing: %+v", report)
	}

	for name, mutate := range map[string]func(*AgentRecognitionBenchmarkReport){
		"reference source":        func(value *AgentRecognitionBenchmarkReport) { value.ReferenceSourceSHA = "" },
		"current daemon digest":   func(value *AgentRecognitionBenchmarkReport) { value.DaemonSHA256 = "" },
		"reference daemon digest": func(value *AgentRecognitionBenchmarkReport) { value.ReferenceDaemonSHA256 = "" },
		"reference arm": func(value *AgentRecognitionBenchmarkReport) {
			value.Pairs = append([]AgentRecognitionBenchmarkPair(nil), value.Pairs...)
			value.Pairs[0].ReferenceEnabled = nil
		},
		"pair order": func(value *AgentRecognitionBenchmarkReport) {
			value.Pairs = append([]AgentRecognitionBenchmarkPair(nil), value.Pairs...)
			value.Pairs[0].Order = "baseline_then_enabled"
		},
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

func TestAgentRecognitionBenchmarkV3BudgetRejectsLegacyFieldsOverflowAndSchemaMixing(t *testing.T) {
	report := validAgentRecognitionBenchmarkReferenceReport(t)
	if err := FinalizeAgentRecognitionBenchmarkReport(&report, nil, ""); err != nil {
		t.Fatal(err)
	}
	budget := budgetFromReferenceReport(report)

	for name, mutate := range map[string]func(*AgentRecognitionBenchmarkBudgetProfile){
		"absolute CPU field": func(profile *AgentRecognitionBenchmarkBudgetProfile) {
			profile.EvidenceP95EnabledDaemonCPUNanoseconds = 1
		},
		"calibrated CPU field": func(profile *AgentRecognitionBenchmarkBudgetProfile) {
			profile.EvidenceP95EnabledDaemonCPUCalibrationRatio = 1
		},
		"reference CPU threshold overflow": func(profile *AgentRecognitionBenchmarkBudgetProfile) {
			profile.EvidenceP95EnabledToReferenceDaemonCPURatio = math.MaxFloat64
			profile.EnabledToReferenceDaemonCPURatioRelativeTolerancePercent = 100
		},
	} {
		t.Run(name, func(t *testing.T) {
			tampered := budget
			tampered.Profiles = append([]AgentRecognitionBenchmarkBudgetProfile(nil), budget.Profiles...)
			mutate(&tampered.Profiles[0])
			if err := ValidateAgentRecognitionBenchmarkBudget(&tampered); err == nil || !errors.Is(err, ErrAgentRecognitionBenchmark) {
				t.Fatalf("invalid v0.3 budget error = %v", err)
			}
		})
	}

	v2Budget := budgetFromReport(validAgentRecognitionBenchmarkReport(t))
	v2Raw, err := json.Marshal(v2Budget)
	if err != nil {
		t.Fatal(err)
	}
	gate := EvaluateAgentRecognitionBenchmarkBudget(&report, &v2Budget, benchmarkSHA256Hex(v2Raw))
	if gate.Status != AgentRecognitionBenchmarkGateFail || !reflect.DeepEqual(gate.Violations, []string{"budget.invalid"}) {
		t.Fatalf("mixed v0.3 report/v0.2 budget gate = %+v", gate)
	}
}

func TestAgentRecognitionBenchmarkReferenceOrderRotatesAllArms(t *testing.T) {
	want := []string{
		"baseline_then_reference_then_enabled",
		"baseline_then_enabled_then_reference",
		"reference_then_baseline_then_enabled",
		"reference_then_enabled_then_baseline",
		"enabled_then_baseline_then_reference",
		"enabled_then_reference_then_baseline",
	}
	got := make([]string, 0, len(want))
	for pairIndex := 0; pairIndex < len(want); pairIndex++ {
		got = append(got, agentRecognitionBenchmarkReferenceOrder(pairIndex, 6))
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reference order rotation = %v, want %v", got, want)
	}
	if got := agentRecognitionBenchmarkReferenceOrder(-1, 6); got != want[len(want)-1] {
		t.Fatalf("negative warmup order = %q, want %q", got, want[len(want)-1])
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

func TestCommittedAgentRecognitionBenchmarkV3EvidenceMatchesBudget(t *testing.T) {
	evidenceFiles := []string{
		"agent-recognition-benchmark-evidence-9c5f16b-run29580498313.json",
		"agent-recognition-benchmark-evidence-9c5f16b-run29580918057.json",
		"agent-recognition-benchmark-evidence-9c5f16b-run29581341003.json",
	}
	wantArtifactDigests := []string{
		"a656f3ff388e67251bfc3848632cc03714fb455fe5ab5a4cb4a9d60a9cf57ba4",
		"b3682ba292fa1288300c429ed1c39599acfc125afc9227f855bf82107f97be7e",
		"32f3cc0c7f5811f4f72297310c1cbd11580130e1773b67e21f9da769c2fa2317",
	}
	type reviewedBudgetPolicy struct {
		wallTolerancePercentagePoints float64
		cpuRelativeTolerancePercent   float64
		cpuAbsoluteTolerance          float64
		peakRSSToleranceKiB           uint64
	}
	wantBudgetPolicies := map[string]reviewedBudgetPolicy{
		"low":       {wallTolerancePercentagePoints: 0.1, cpuRelativeTolerancePercent: 12, cpuAbsoluteTolerance: 0.02, peakRSSToleranceKiB: 4096},
		"sustained": {wallTolerancePercentagePoints: 0.05, cpuRelativeTolerancePercent: 3, cpuAbsoluteTolerance: 0.02, peakRSSToleranceKiB: 4096},
		"storm":     {wallTolerancePercentagePoints: 0.15, cpuRelativeTolerancePercent: 10, cpuAbsoluteTolerance: 0.02, peakRSSToleranceKiB: 4096},
	}
	type reviewedProfileEvidence struct {
		minP50WallOverheadPercent              float64
		maxP50WallOverheadPercent              float64
		maxP95WallOverheadPercent              float64
		minP95EnabledToReferenceDaemonCPURatio float64
		maxP95EnabledToReferenceDaemonCPURatio float64
		maxEnabledDaemonPeakRSSKiB             uint64
	}
	aggregates := make(map[string]reviewedProfileEvidence, 3)
	reports := make([]*AgentRecognitionBenchmarkReport, 0, len(evidenceFiles))
	artifactDigests := make([]string, 0, len(evidenceFiles))
	cpuModels := make(map[string]struct{})
	currentDaemonSHA256 := ""
	referenceDaemonSHA256 := ""
	var currentExpected, currentSuccess, referenceExpected, referenceSuccess uint64
	for _, evidenceFile := range evidenceFiles {
		report, err := LoadAgentRecognitionBenchmarkReport(filepath.Join("testdata", evidenceFile))
		if err != nil {
			t.Fatalf("load %s: %v", evidenceFile, err)
		}
		if report.SchemaVersion != AgentRecognitionBenchmarkReportSchemaV3 || report.SourceSHA != "9c5f16b2356f77bd63b3db6711c50e16e2407745" || report.ReferenceSourceSHA != "5df32e257d2e9c9a6750fa65638f43c8b0707484" ||
			report.Gate.Status != AgentRecognitionBenchmarkGateNotRun || report.Gate.BudgetSHA256 != "" || len(report.Gate.Violations) != 0 {
			t.Fatalf("reviewed v0.3 evidence provenance drifted for %s", evidenceFile)
		}
		if currentDaemonSHA256 == "" {
			currentDaemonSHA256 = report.DaemonSHA256
			referenceDaemonSHA256 = report.ReferenceDaemonSHA256
		} else if report.DaemonSHA256 != currentDaemonSHA256 || report.ReferenceDaemonSHA256 != referenceDaemonSHA256 {
			t.Fatalf("reviewed daemon digests drifted for %s", evidenceFile)
		}
		reports = append(reports, report)
		artifactDigests = append(artifactDigests, report.ArtifactSHA256)
		cpuModels[report.Environment.CPUModel] = struct{}{}
		for _, summary := range report.Summaries {
			if summary.EnabledToReferenceDaemonCPURatio == nil || summary.ReferenceTotalCapture == nil || summary.ReferenceTotalRecognition == nil || summary.ReferenceTotalFingerprint == nil {
				t.Fatalf("reviewed v0.3 evidence %s profile %q has incomplete reference data", evidenceFile, summary.ProfileName)
			}
			aggregate, exists := aggregates[summary.ProfileName]
			if !exists {
				aggregate.minP50WallOverheadPercent = math.Inf(1)
				aggregate.minP95EnabledToReferenceDaemonCPURatio = math.Inf(1)
			}
			aggregate.minP50WallOverheadPercent = math.Min(aggregate.minP50WallOverheadPercent, summary.PairedWallOverheadPercent.P50)
			aggregate.maxP50WallOverheadPercent = math.Max(aggregate.maxP50WallOverheadPercent, summary.PairedWallOverheadPercent.P50)
			aggregate.maxP95WallOverheadPercent = math.Max(aggregate.maxP95WallOverheadPercent, summary.PairedWallOverheadPercent.P95)
			aggregate.minP95EnabledToReferenceDaemonCPURatio = math.Min(aggregate.minP95EnabledToReferenceDaemonCPURatio, summary.EnabledToReferenceDaemonCPURatio.P95)
			aggregate.maxP95EnabledToReferenceDaemonCPURatio = math.Max(aggregate.maxP95EnabledToReferenceDaemonCPURatio, summary.EnabledToReferenceDaemonCPURatio.P95)
			if summary.MaxEnabledDaemonPeakRSSKiB > aggregate.maxEnabledDaemonPeakRSSKiB {
				aggregate.maxEnabledDaemonPeakRSSKiB = summary.MaxEnabledDaemonPeakRSSKiB
			}
			aggregates[summary.ProfileName] = aggregate
			currentExpected += summary.TotalCapture.ExpectedEvents
			currentSuccess += summary.TotalFingerprint.Success
			referenceExpected += summary.ReferenceTotalCapture.ExpectedEvents
			referenceSuccess += summary.ReferenceTotalFingerprint.Success
		}
	}
	if len(cpuModels) < 2 {
		t.Fatalf("reviewed v0.3 evidence covers %d CPU model(s), want at least 2", len(cpuModels))
	}
	if currentDaemonSHA256 != "46a1d6ecfebe984a1952aeb47652f5ec19e8bbf8906644427686a98a7fe57737" || referenceDaemonSHA256 != "02352ba197866c120395d75a4ff06bec52c8444691da4e406c94b7a799e3d8af" {
		t.Fatalf("reviewed daemon digests drifted: current=%q reference=%q", currentDaemonSHA256, referenceDaemonSHA256)
	}
	if !stringSlicesEqual(artifactDigests, wantArtifactDigests) {
		t.Fatalf("reviewed artifact digests = %v, want %v", artifactDigests, wantArtifactDigests)
	}
	if currentExpected != 6240 || currentSuccess != currentExpected || referenceExpected != 6240 || referenceSuccess != referenceExpected {
		t.Fatalf("reviewed v0.3 correctness totals: current=%d/%d reference=%d/%d", currentSuccess, currentExpected, referenceSuccess, referenceExpected)
	}

	budget, budgetDigest, err := LoadAgentRecognitionBenchmarkBudget(filepath.Join("testdata", "agent-recognition-benchmark-budget-v0.3.json"))
	if err != nil {
		t.Fatal(err)
	}
	if budget.BudgetVersion != "github-ubuntu-24.04-amd64.9c5f16b.v1" || budgetDigest != "a70c18f588e1bf3bc7f8de65e75661ca60281b887724ca22d2979f054d46a4bc" {
		t.Fatalf("reviewed v0.3 budget identity drifted: version=%q digest=%q", budget.BudgetVersion, budgetDigest)
	}
	if !stringSlicesEqual(budget.EvidenceArtifactSHA256s, artifactDigests) {
		t.Fatalf("budget evidence digests = %v, want %v", budget.EvidenceArtifactSHA256s, artifactDigests)
	}
	for _, profile := range budget.Profiles {
		policy, ok := wantBudgetPolicies[profile.ProfileName]
		if !ok {
			t.Fatalf("unexpected reviewed v0.3 budget profile %q", profile.ProfileName)
		}
		if profile.WallOverheadTolerancePercentagePoints != policy.wallTolerancePercentagePoints ||
			profile.EnabledToReferenceDaemonCPURatioRelativeTolerancePercent != policy.cpuRelativeTolerancePercent ||
			profile.EnabledToReferenceDaemonCPURatioAbsoluteTolerance != policy.cpuAbsoluteTolerance ||
			profile.PeakRSSToleranceKiB != policy.peakRSSToleranceKiB {
			t.Fatalf("budget profile %q policy drifted: %+v", profile.ProfileName, profile)
		}
		aggregate, ok := aggregates[profile.ProfileName]
		if !ok || !nearlyEqual(profile.EvidenceP50WallOverheadPercent, aggregate.maxP50WallOverheadPercent) ||
			!nearlyEqual(profile.EvidenceP95WallOverheadPercent, aggregate.maxP95WallOverheadPercent) ||
			!nearlyEqual(profile.EvidenceP95EnabledToReferenceDaemonCPURatio, aggregate.maxP95EnabledToReferenceDaemonCPURatio) ||
			profile.EvidenceMaxEnabledDaemonPeakRSSKiB != aggregate.maxEnabledDaemonPeakRSSKiB {
			t.Fatalf("budget profile %q drifted from reviewed v0.3 evidence", profile.ProfileName)
		}
		wallSpread := aggregate.maxP50WallOverheadPercent - aggregate.minP50WallOverheadPercent
		if profile.WallOverheadTolerancePercentagePoints < 2*wallSpread || profile.WallOverheadTolerancePercentagePoints > 2*wallSpread+0.03 {
			t.Fatalf("profile %q wall tolerance %f is not a tight upward rounding of twice spread %f", profile.ProfileName, profile.WallOverheadTolerancePercentagePoints, wallSpread)
		}
		relativeRatioSpreadPercent := ((aggregate.maxP95EnabledToReferenceDaemonCPURatio - aggregate.minP95EnabledToReferenceDaemonCPURatio) / aggregate.minP95EnabledToReferenceDaemonCPURatio) * 100
		if profile.EnabledToReferenceDaemonCPURatioRelativeTolerancePercent < 2*relativeRatioSpreadPercent || profile.EnabledToReferenceDaemonCPURatioRelativeTolerancePercent > 2*relativeRatioSpreadPercent+2 || profile.EnabledToReferenceDaemonCPURatioAbsoluteTolerance != 0.02 {
			t.Fatalf("profile %q CPU tolerance does not tightly bound twice relative spread %f", profile.ProfileName, relativeRatioSpreadPercent)
		}
	}
	for index, report := range reports {
		gate := EvaluateAgentRecognitionBenchmarkBudget(report, budget, budgetDigest)
		if gate.Status != AgentRecognitionBenchmarkGatePass || len(gate.Violations) != 0 {
			t.Fatalf("reviewed v0.3 evidence %s does not pass its bound budget: %+v", evidenceFiles[index], gate)
		}
	}
}

func TestCommittedAgentRecognitionBenchmarkV2FalsificationRemainsLoadable(t *testing.T) {
	report, err := LoadAgentRecognitionBenchmarkReport(filepath.Join("testdata", "agent-recognition-benchmark-evidence-aaac953-run29577544792.json"))
	if err != nil {
		t.Fatal(err)
	}
	const wantBudgetDigest = "0af01c486a5bbed5d6b25be12f1948b94bc9fadac67491957f96ce018fa2aeff"
	wantViolations := []string{
		"budget.low.p95_normalized_daemon_cpu",
		"budget.storm.p95_normalized_daemon_cpu",
		"budget.sustained.p95_normalized_daemon_cpu",
	}
	if report.SchemaVersion != AgentRecognitionBenchmarkReportSchemaV2 || report.SourceSHA != "aaac95363569710d692861e579561d7f4c3619e8" ||
		report.ArtifactSHA256 != "08a6d4125f11ead3593a5fe68888e28dcd07ee59e837ac8485b718f6749dfce0" || report.Gate.Status != AgentRecognitionBenchmarkGateFail ||
		!reflect.DeepEqual(report.Gate.Violations, wantViolations) {
		t.Fatalf("preserved v0.2 falsification drifted: source=%q artifact=%q gate=%+v", report.SourceSHA, report.ArtifactSHA256, report.Gate)
	}
	budget, budgetDigest, err := LoadAgentRecognitionBenchmarkBudget(filepath.Join("testdata", "agent-recognition-benchmark-budget-v0.2.json"))
	if err != nil {
		t.Fatal(err)
	}
	if budgetDigest != wantBudgetDigest || report.Gate.BudgetSHA256 != budgetDigest {
		t.Fatalf("preserved v0.2 budget identity drifted: loaded=%q report=%q", budgetDigest, report.Gate.BudgetSHA256)
	}
	evaluatedGate := EvaluateAgentRecognitionBenchmarkBudget(report, budget, budgetDigest)
	if !reflect.DeepEqual(evaluatedGate, report.Gate) {
		t.Fatalf("preserved v0.2 falsification no longer reproduces: evaluated=%+v stored=%+v", evaluatedGate, report.Gate)
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

func validAgentRecognitionBenchmarkReferenceReport(t *testing.T) AgentRecognitionBenchmarkReport {
	t.Helper()
	report := validAgentRecognitionBenchmarkReport(t)
	report.SchemaVersion = AgentRecognitionBenchmarkReportSchemaV3
	report.ReferenceSourceSHA = "fedcba9876543210fedcba9876543210fedcba98"
	report.DaemonSHA256 = strings.Repeat("c", 64)
	// The candidate may change only the benchmark harness, leaving the exact
	// current and reference production daemon bytes equal. That remains valid
	// and is still provenance-bound by two explicit digests.
	report.ReferenceDaemonSHA256 = report.DaemonSHA256
	report.PairOrder = "deterministic_six_arm_order_rotation"
	for pairIndex := range report.Pairs {
		pair := &report.Pairs[pairIndex]
		reference := pair.Enabled
		reference.DaemonCPUNanoseconds = pair.Enabled.DaemonCPUNanoseconds + 100
		reference.DaemonPeakRSSKiB = pair.Enabled.DaemonPeakRSSKiB + 64
		reference.WorkloadElapsedNanoseconds = pair.Enabled.WorkloadElapsedNanoseconds + 1000
		pair.ReferenceEnabled = &reference
		pair.EnabledToReferenceDaemonCPURatio = float64(pair.Enabled.DaemonCPUNanoseconds) / float64(reference.DaemonCPUNanoseconds)
		pair.Order = agentRecognitionBenchmarkReferenceOrder(pair.PairIndex, report.Seed)
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

func budgetFromReferenceReport(report AgentRecognitionBenchmarkReport) AgentRecognitionBenchmarkBudget {
	budget := AgentRecognitionBenchmarkBudget{
		SchemaVersion: AgentRecognitionBenchmarkBudgetSchemaV3,
		BudgetVersion: "test.v3",
		EvidenceArtifactSHA256s: []string{
			strings.Repeat("4", 64), strings.Repeat("5", 64), strings.Repeat("6", 64),
		},
		MinimumMeasuredPairs: MinAgentRecognitionBenchmarkPairs,
	}
	for _, summary := range report.Summaries {
		budget.Profiles = append(budget.Profiles, AgentRecognitionBenchmarkBudgetProfile{
			ProfileName:                                              summary.ProfileName,
			EvidenceP50WallOverheadPercent:                           summary.PairedWallOverheadPercent.P50,
			EvidenceP95WallOverheadPercent:                           summary.PairedWallOverheadPercent.P95,
			WallOverheadTolerancePercentagePoints:                    0.1,
			EvidenceP95EnabledToReferenceDaemonCPURatio:              summary.EnabledToReferenceDaemonCPURatio.P95,
			EnabledToReferenceDaemonCPURatioRelativeTolerancePercent: 10,
			EnabledToReferenceDaemonCPURatioAbsoluteTolerance:        0.02,
			EvidenceMaxEnabledDaemonPeakRSSKiB:                       summary.MaxEnabledDaemonPeakRSSKiB,
			PeakRSSToleranceKiB:                                      4096,
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
