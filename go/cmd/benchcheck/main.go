// benchcheck evaluates AuditBench scenario packs against the four Ardur
// evaluation arms and writes results to an output directory.
//
// Usage:
//
//	benchcheck [flags] [pack-dir]
//
// Flags:
//
//	-out string   output directory for results.json and summary.csv (default: "bench-results")
//	-quiet        suppress the result table on stdout
//
// pack-dir defaults to go/benchmark/testdata (relative to the repo root
// detected from the executable's location) if not provided.
//
// Exit codes: 0 = success, 1 = error, 2 = all arms fail on any scenario.
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"

	"github.com/ArdurAI/ardur/go/benchmark/live"
)

func main() {
	outDir := flag.String("out", "bench-results", "output directory for results.json and summary.csv")
	quiet := flag.Bool("quiet", false, "suppress result table on stdout")
	flag.Parse()

	packDir := flag.Arg(0)
	if packDir == "" {
		packDir = defaultPackDir()
	}

	results, skipped, err := live.EvaluatePack(packDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchcheck: %v\n", err)
		os.Exit(1)
	}

	if len(results) == 0 {
		fmt.Fprintf(os.Stderr, "benchcheck: no scenarios found in %s\n", packDir)
		os.Exit(1)
	}

	if !*quiet {
		printTable(results, skipped)
	}

	if err := writeResults(*outDir, results, skipped, packDir); err != nil {
		fmt.Fprintf(os.Stderr, "benchcheck: write results: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Results written to %s\n", *outDir)
}

func defaultPackDir() string {
	// Walk up from the executable location to find the repo root, then
	// resolve go/benchmark/testdata. Fall back to the current directory.
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	// file is .../go/cmd/benchcheck/main.go; repo root is 3 levels up.
	repoRoot := filepath.Join(filepath.Dir(file), "..", "..", "..")
	candidate := filepath.Join(repoRoot, "go", "benchmark", "testdata")
	if info, err := os.Stat(candidate); err == nil && info.IsDir() {
		return candidate
	}
	return "."
}

func printTable(results []live.BenchmarkResult, skipped int) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SCENARIO\tGROUND_TRUTH\tCEDAR_STRICT\tCEDAR_STATE\tVISIBILITY\tMCEP_RECONCILIATION")
	fmt.Fprintln(tw, strings.Repeat("-", 80))
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%s\t%s(%d)\t%s(%d)\t%s(%d)\t%s(%d)\n",
			r.ScenarioID,
			r.GroundTruth,
			r.Arm1.Verdict, r.Arm1.FindingsCount,
			r.Arm2.Verdict, r.Arm2.FindingsCount,
			r.Arm3.Verdict, r.Arm3.FindingsCount,
			r.Arm4.Verdict, r.Arm4.FindingsCount,
		)
	}
	tw.Flush()
	if skipped > 0 {
		fmt.Printf("\n(%d scenario(s) skipped — no matching .events.jsonl file)\n", skipped)
	}

	// Per-arm accuracy summary (fraction of correct verdicts vs ground truth).
	fmt.Println()
	printAccuracy(results)
}

func printAccuracy(results []live.BenchmarkResult) {
	if len(results) == 0 {
		return
	}
	type counts struct{ correct, total int }
	arms := []struct {
		name string
		get  func(live.BenchmarkResult) string
	}{
		{"cedar_strict", func(r live.BenchmarkResult) string { return r.Arm1.Verdict }},
		{"cedar_state", func(r live.BenchmarkResult) string { return r.Arm2.Verdict }},
		{"visibility", func(r live.BenchmarkResult) string { return r.Arm3.Verdict }},
		{"mcep_reconciliation", func(r live.BenchmarkResult) string { return r.Arm4.Verdict }},
	}

	fmt.Println("Arm accuracy (verdict matches ground_truth):")
	for _, arm := range arms {
		correct := 0
		for _, r := range results {
			if arm.get(r) == r.GroundTruth {
				correct++
			}
		}
		pct := float64(correct) / float64(len(results)) * 100
		suffix := ""
		if arm.name == "mcep_reconciliation" {
			suffix = " [oracle — 100% by construction; see REPRODUCE.md]"
		}
		fmt.Printf("  %-22s %d/%d (%.0f%%)%s\n", arm.name, correct, len(results), pct, suffix)
	}
}

type summary struct {
	PackDir  string               `json:"pack_dir"`
	Skipped  int                  `json:"skipped_pairs"`
	Results  []live.BenchmarkResult `json:"results"`
	Accuracy map[string]float64   `json:"arm_accuracy"`
}

func writeResults(outDir string, results []live.BenchmarkResult, skipped int, packDir string) error {
	if err := os.MkdirAll(outDir, 0750); err != nil {
		return err
	}

	acc := armAccuracy(results)
	s := summary{
		PackDir:  packDir,
		Skipped:  skipped,
		Results:  results,
		Accuracy: acc,
	}

	jsonBytes, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "results.json"), jsonBytes, 0600); err != nil {
		return err
	}

	return writeCSV(outDir, results)
}

func armAccuracy(results []live.BenchmarkResult) map[string]float64 {
	if len(results) == 0 {
		return nil
	}
	arms := map[string]func(live.BenchmarkResult) string{
		"cedar_strict":        func(r live.BenchmarkResult) string { return r.Arm1.Verdict },
		"cedar_state":         func(r live.BenchmarkResult) string { return r.Arm2.Verdict },
		"visibility":          func(r live.BenchmarkResult) string { return r.Arm3.Verdict },
		"mcep_reconciliation": func(r live.BenchmarkResult) string { return r.Arm4.Verdict },
	}
	acc := make(map[string]float64, len(arms))
	for name, get := range arms {
		correct := 0
		for _, r := range results {
			if get(r) == r.GroundTruth {
				correct++
			}
		}
		acc[name] = float64(correct) / float64(len(results))
	}
	return acc
}

func writeCSV(outDir string, results []live.BenchmarkResult) error {
	f, err := os.Create(filepath.Join(outDir, "summary.csv"))
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if err := w.Write([]string{
		"scenario_id", "ground_truth",
		"cedar_strict", "cedar_strict_findings",
		"cedar_state", "cedar_state_findings",
		"visibility", "visibility_findings",
		"mcep_reconciliation", "mcep_reconciliation_findings",
	}); err != nil {
		return err
	}
	for _, r := range results {
		if err := w.Write([]string{
			r.ScenarioID,
			r.GroundTruth,
			r.Arm1.Verdict, fmt.Sprint(r.Arm1.FindingsCount),
			r.Arm2.Verdict, fmt.Sprint(r.Arm2.FindingsCount),
			r.Arm3.Verdict, fmt.Sprint(r.Arm3.FindingsCount),
			r.Arm4.Verdict, fmt.Sprint(r.Arm4.FindingsCount),
		}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
