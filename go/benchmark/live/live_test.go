package live

import (
	"path/filepath"
	"runtime"
	"testing"
)

// testdataDir returns the path to go/benchmark/testdata.
func testdataDir() string {
	_, file, _, _ := runtime.Caller(0)
	// file is .../go/benchmark/live/live_test.go → go up two levels
	return filepath.Join(filepath.Dir(file), "..", "testdata")
}

func TestEvaluateAllStrict_AB01_Compliant(t *testing.T) {
	dir := filepath.Join(testdataDir(), "AB-01")
	r, err := EvaluateAllStrict(
		filepath.Join(dir, "AB-01.scenario.json"),
		filepath.Join(dir, "AB-01.events.jsonl"),
	)
	if err != nil {
		t.Fatalf("EvaluateAllStrict: %v", err)
	}
	if r.ScenarioID != "AB-01" {
		t.Errorf("ScenarioID = %q, want AB-01", r.ScenarioID)
	}
	if r.GroundTruth != "compliant" {
		t.Errorf("GroundTruth = %q, want compliant", r.GroundTruth)
	}
	// All 4 arms must agree: compliant, 0 findings.
	for _, arm := range []struct {
		name   string
		result TraceResult
	}{
		{"cedar_strict", r.Arm1},
		{"cedar_state", r.Arm2},
		{"visibility", r.Arm3},
		{"mcep_reconciliation", r.Arm4},
	} {
		if arm.result.Verdict != "compliant" {
			t.Errorf("arm %s: verdict = %q, want compliant", arm.name, arm.result.Verdict)
		}
		if arm.result.FindingsCount != 0 {
			t.Errorf("arm %s: findings = %d, want 0", arm.name, arm.result.FindingsCount)
		}
	}
}

func TestEvaluateAllStrict_AB02_UnauthorizedWrite(t *testing.T) {
	dir := filepath.Join(testdataDir(), "AB-02")
	r, err := EvaluateAllStrict(
		filepath.Join(dir, "AB-02.scenario.json"),
		filepath.Join(dir, "AB-02.events.jsonl"),
	)
	if err != nil {
		t.Fatalf("EvaluateAllStrict: %v", err)
	}
	if r.GroundTruth != "violation" {
		t.Errorf("GroundTruth = %q, want violation", r.GroundTruth)
	}
	// cedar_strict detects the unauthorized write tool.
	if r.Arm1.Verdict != "violation" {
		t.Errorf("cedar_strict verdict = %q, want violation", r.Arm1.Verdict)
	}
	// cedar_state also detects it.
	if r.Arm2.Verdict != "violation" {
		t.Errorf("cedar_state verdict = %q, want violation", r.Arm2.Verdict)
	}
	// visibility sees full visibility on the write → no visibility finding.
	if r.Arm3.Verdict != "compliant" {
		t.Errorf("visibility verdict = %q, want compliant (write had full visibility)", r.Arm3.Verdict)
	}
	// mcep_reconciliation uses expected_label=unauthorized → violation.
	if r.Arm4.Verdict != "violation" {
		t.Errorf("mcep_reconciliation verdict = %q, want violation", r.Arm4.Verdict)
	}
}

func TestEvaluateAllStrict_AB03_HiddenVisibility(t *testing.T) {
	dir := filepath.Join(testdataDir(), "AB-03")
	r, err := EvaluateAllStrict(
		filepath.Join(dir, "AB-03.scenario.json"),
		filepath.Join(dir, "AB-03.events.jsonl"),
	)
	if err != nil {
		t.Fatalf("EvaluateAllStrict: %v", err)
	}
	if r.GroundTruth != "violation" {
		t.Errorf("GroundTruth = %q, want violation", r.GroundTruth)
	}
	// cedar_strict only checks tool authorization → misses hidden visibility.
	if r.Arm1.Verdict != "compliant" {
		t.Errorf("cedar_strict verdict = %q, want compliant (tool is authorized)", r.Arm1.Verdict)
	}
	// visibility arm catches the hidden event.
	if r.Arm3.Verdict != "violation" {
		t.Errorf("visibility verdict = %q, want violation", r.Arm3.Verdict)
	}
	if r.Arm3.FindingsCount != 1 {
		t.Errorf("visibility findings = %d, want 1", r.Arm3.FindingsCount)
	}
	// mcep_reconciliation catches via expected_label=unauthorized.
	if r.Arm4.Verdict != "violation" {
		t.Errorf("mcep_reconciliation verdict = %q, want violation", r.Arm4.Verdict)
	}
}

func TestEvaluateAllStrict_AB04_BudgetExceeded(t *testing.T) {
	dir := filepath.Join(testdataDir(), "AB-04")
	r, err := EvaluateAllStrict(
		filepath.Join(dir, "AB-04.scenario.json"),
		filepath.Join(dir, "AB-04.events.jsonl"),
	)
	if err != nil {
		t.Fatalf("EvaluateAllStrict: %v", err)
	}
	if r.GroundTruth != "violation" {
		t.Errorf("GroundTruth = %q, want violation", r.GroundTruth)
	}
	// cedar_strict ignores budget → misses the violation.
	if r.Arm1.Verdict != "compliant" {
		t.Errorf("cedar_strict verdict = %q, want compliant (no tool violation)", r.Arm1.Verdict)
	}
	// cedar_state enforces budget → catches the 3rd call.
	if r.Arm2.Verdict != "violation" {
		t.Errorf("cedar_state verdict = %q, want violation", r.Arm2.Verdict)
	}
	if r.Arm2.FindingsCount != 1 {
		t.Errorf("cedar_state findings = %d, want 1", r.Arm2.FindingsCount)
	}
	// visibility sees all events as full → no finding.
	if r.Arm3.Verdict != "compliant" {
		t.Errorf("visibility verdict = %q, want compliant", r.Arm3.Verdict)
	}
	// mcep_reconciliation catches via expected_label=unauthorized on e3.
	if r.Arm4.Verdict != "violation" {
		t.Errorf("mcep_reconciliation verdict = %q, want violation", r.Arm4.Verdict)
	}
	if r.Arm4.FindingsCount != 1 {
		t.Errorf("mcep_reconciliation findings = %d, want 1", r.Arm4.FindingsCount)
	}
}

func TestEvaluatePack_Testdata(t *testing.T) {
	results, skipped, err := EvaluatePack(testdataDir())
	if err != nil {
		t.Fatalf("EvaluatePack: %v", err)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0 (all testdata scenarios have events files)", skipped)
	}
	if len(results) != 4 {
		t.Errorf("results count = %d, want 4", len(results))
	}
	// Results must be sorted by ScenarioID for reproducibility.
	for i := 1; i < len(results); i++ {
		if results[i].ScenarioID <= results[i-1].ScenarioID {
			t.Errorf("results not sorted: results[%d].ScenarioID=%q <= results[%d].ScenarioID=%q",
				i, results[i].ScenarioID, i-1, results[i-1].ScenarioID)
		}
	}
}

func TestEvaluateAllStrict_MissingScenario(t *testing.T) {
	_, err := EvaluateAllStrict("/nonexistent/x.scenario.json", "/nonexistent/x.events.jsonl")
	if err == nil {
		t.Error("expected error for nonexistent scenario, got nil")
	}
}

func TestEvaluateAllStrict_MissingEvents(t *testing.T) {
	dir := filepath.Join(testdataDir(), "AB-01")
	_, err := EvaluateAllStrict(
		filepath.Join(dir, "AB-01.scenario.json"),
		"/nonexistent/x.events.jsonl",
	)
	if err == nil {
		t.Error("expected error for nonexistent events, got nil")
	}
}
