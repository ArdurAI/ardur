// Package live implements the four benchmark evaluation arms over a scenario
// and its corresponding event trace.
//
// Four arms are evaluated for each (scenario, trace) pair:
//
//   - cedar_strict: checks each event against the declared AllowedActions +
//     AllowedTools without tracking cumulative state.
//   - cedar_state: same as cedar_strict, plus tracks tool-call budget
//     consumption declared in the strong declaration's Budgets map.
//   - visibility: checks that every event carries full visibility; partial
//     or hidden events are findings regardless of tool authorization.
//   - mcep_reconciliation: oracle arm — uses per-event ExpectedLabel fields
//     as ground truth; any event labeled "unauthorized" makes the trace a
//     violation. This arm matches the ground truth when labels are accurate.
package live

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	benchmark "github.com/ArdurAI/ardur/go/benchmark"
)

// TraceResult holds one arm's verdict for a single (scenario, trace) pair.
type TraceResult struct {
	Verdict       string `json:"verdict"`
	FindingsCount int    `json:"findings_count"`
}

// BenchmarkResult holds the four arm verdicts for one evaluated pair.
type BenchmarkResult struct {
	Source      string      `json:"source"`
	ScenarioID  string      `json:"scenario_id"`
	GroundTruth string      `json:"ground_truth"`
	Arm1        TraceResult `json:"cedar_strict"`
	Arm2        TraceResult `json:"cedar_state"`
	Arm3        TraceResult `json:"visibility"`
	Arm4        TraceResult `json:"mcep_reconciliation"`
}

// EvaluateAllStrict loads a scenario file and its paired events file, then
// runs all four evaluation arms. scenarioPath must point to a
// *.scenario.json file; eventsPath must point to the companion *.events.jsonl
// file. Both files are validated before evaluation begins.
func EvaluateAllStrict(scenarioPath, eventsPath string) (BenchmarkResult, error) {
	scen, err := loadScenario(scenarioPath)
	if err != nil {
		return BenchmarkResult{}, fmt.Errorf("scenario %s: %w", scenarioPath, err)
	}
	events, err := loadEvents(eventsPath)
	if err != nil {
		return BenchmarkResult{}, fmt.Errorf("events %s: %w", eventsPath, err)
	}

	return BenchmarkResult{
		Source:      filepath.Base(filepath.Dir(scenarioPath)),
		ScenarioID:  scen.ID,
		GroundTruth: scen.GroundTruth.Label,
		Arm1:        evalCedarStrict(scen, events),
		Arm2:        evalCedarState(scen, events),
		Arm3:        evalVisibility(events),
		Arm4:        evalMCEPReconciliation(events),
	}, nil
}

// EvaluatePack walks packDir looking for *.scenario.json files, pairs each
// with its companion *.events.jsonl (same base name in the same directory),
// and runs EvaluateAllStrict for every pair it can match. Results are
// returned sorted by ScenarioID for byte-for-byte reproducibility. Pairs
// with a missing events file are skipped and counted in SkippedPairs.
func EvaluatePack(packDir string) ([]BenchmarkResult, int, error) {
	info, err := os.Stat(packDir)
	if err != nil {
		return nil, 0, fmt.Errorf("stat pack dir: %w", err)
	}
	if !info.IsDir() {
		return nil, 0, fmt.Errorf("not a directory: %s", packDir)
	}

	var scenarioPaths []string
	if err := filepath.WalkDir(packDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".scenario.json") {
			scenarioPaths = append(scenarioPaths, path)
		}
		return nil
	}); err != nil {
		return nil, 0, fmt.Errorf("walk pack: %w", err)
	}
	sort.Strings(scenarioPaths)

	var results []BenchmarkResult
	skipped := 0
	for _, sp := range scenarioPaths {
		eventsPath := strings.TrimSuffix(sp, ".scenario.json") + ".events.jsonl"
		if _, err := os.Stat(eventsPath); err != nil {
			skipped++
			continue
		}
		r, err := EvaluateAllStrict(sp, eventsPath)
		if err != nil {
			return nil, skipped, fmt.Errorf("evaluating %s: %w", sp, err)
		}
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].ScenarioID < results[j].ScenarioID
	})
	return results, skipped, nil
}

// loadScenario reads and validates a scenario JSON file.
func loadScenario(path string) (benchmark.Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return benchmark.Scenario{}, fmt.Errorf("read: %w", err)
	}
	var s benchmark.Scenario
	if err := json.Unmarshal(data, &s); err != nil {
		return benchmark.Scenario{}, fmt.Errorf("parse: %w", err)
	}
	if err := s.Validate(); err != nil {
		return benchmark.Scenario{}, fmt.Errorf("validate: %w", err)
	}
	return s, nil
}

// loadEvents reads and validates an events JSONL file.
func loadEvents(path string) ([]benchmark.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	var events []benchmark.Event
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev benchmark.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return nil, fmt.Errorf("line %d: parse: %w", lineNum, err)
		}
		if err := ev.Validate(); err != nil {
			return nil, fmt.Errorf("line %d: validate: %w", lineNum, err)
		}
		events = append(events, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	return events, nil
}

// setOf builds a case-insensitive membership set from a slice of strings.
func setOf(values []string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[strings.ToLower(strings.TrimSpace(v))] = true
	}
	return m
}

// inSet reports whether v (lowercased, trimmed) is in set m.
func inSet(m map[string]bool, v string) bool {
	return m[strings.ToLower(strings.TrimSpace(v))]
}

// verdictFor converts finding count to a verdict string.
func verdictFor(findings int) string {
	if findings == 0 {
		return "compliant"
	}
	return "violation"
}

// evalCedarStrict checks each event against the strong declaration's
// AllowedActions and AllowedTools. Stateless: no budget tracking.
func evalCedarStrict(s benchmark.Scenario, events []benchmark.Event) TraceResult {
	allowedActions := setOf(s.Declarations.Strong.AllowedActions)
	allowedTools := setOf(s.Declarations.Strong.AllowedTools)
	findings := 0
	for _, ev := range events {
		if !inSet(allowedActions, ev.ActionClass) || !inSet(allowedTools, ev.ToolName) {
			findings++
		}
	}
	return TraceResult{Verdict: verdictFor(findings), FindingsCount: findings}
}

// evalCedarState is like evalCedarStrict plus cumulative tool-call budget
// enforcement. It enforces budgets["tool_calls"] if set; calls that push the
// running total beyond the declared limit are counted as findings even when
// the action and tool are otherwise permitted.
func evalCedarState(s benchmark.Scenario, events []benchmark.Event) TraceResult {
	allowedActions := setOf(s.Declarations.Strong.AllowedActions)
	allowedTools := setOf(s.Declarations.Strong.AllowedTools)
	budgetLimit, hasBudget := s.Declarations.Strong.Budgets["tool_calls"]
	findings := 0
	toolCallCount := 0
	for _, ev := range events {
		toolCallCount++
		authViolation := !inSet(allowedActions, ev.ActionClass) || !inSet(allowedTools, ev.ToolName)
		budgetViolation := hasBudget && float64(toolCallCount) > budgetLimit
		if authViolation || budgetViolation {
			findings++
		}
	}
	return TraceResult{Verdict: verdictFor(findings), FindingsCount: findings}
}

// evalVisibility requires every event to have Visibility == "full".
// Any partial or hidden event is a finding regardless of tool authorization.
func evalVisibility(events []benchmark.Event) TraceResult {
	findings := 0
	for _, ev := range events {
		if strings.ToLower(strings.TrimSpace(ev.Visibility)) != "full" {
			findings++
		}
	}
	return TraceResult{Verdict: verdictFor(findings), FindingsCount: findings}
}

// evalMCEPReconciliation uses per-event ExpectedLabel as the oracle. Any
// event with ExpectedLabel != "authorized" (case-insensitive) constitutes a
// finding.
//
// ORACLE CIRCULARITY: This arm reads back the same ExpectedLabel field that
// defines the benchmark ground truth. Its accuracy is 100% by construction —
// it does not detect anything; it only reflects the labels. Report it as a
// sanity-check arm, not as a detection metric. A 100% accuracy figure for
// this arm says nothing about the harness's ability to identify violations
// independently; use cedar_strict, cedar_state, and visibility for that.
func evalMCEPReconciliation(events []benchmark.Event) TraceResult {
	findings := 0
	for _, ev := range events {
		if strings.ToLower(strings.TrimSpace(ev.ExpectedLabel)) != "authorized" {
			findings++
		}
	}
	return TraceResult{Verdict: verdictFor(findings), FindingsCount: findings}
}
