package kernelcapture

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestEmbeddedAgentRecognitionCorpusGate(t *testing.T) {
	corpus, corpusSHA256, err := EmbeddedAgentRecognitionCorpus()
	if err != nil {
		t.Fatalf("load embedded corpus: %v", err)
	}
	thresholds, err := EmbeddedAgentRecognitionThresholds()
	if err != nil {
		t.Fatalf("load embedded thresholds: %v", err)
	}
	recognizer, err := NewEmbeddedAgentRecognizer(AgentRecognizerOptions{})
	if err != nil {
		t.Fatalf("new embedded recognizer: %v", err)
	}
	report, err := EvaluateAgentRecognitionCorpus(recognizer, corpus, corpusSHA256, thresholds)
	if err != nil {
		t.Fatalf("evaluate embedded corpus: %v", err)
	}
	if !report.Gate.Passed {
		t.Fatalf("embedded corpus gate failed: %v", report.Gate.Reasons)
	}
	if report.SampleCount != 28 || report.EvaluatedCount != 27 || report.UnavailableCount != 1 || report.UnknownCount != 12 || report.AmbiguousCount != 2 {
		t.Fatalf("unexpected corpus accounting: %+v", report)
	}
	if report.AggregatePrecision.Numerator != 13 || report.AggregatePrecision.Denominator != 13 || report.AggregateRecall.Numerator != 13 || report.AggregateRecall.Denominator != 17 {
		t.Fatalf("unexpected aggregate metrics: precision=%+v recall=%+v", report.AggregatePrecision, report.AggregateRecall)
	}
	if report.SupportedRecall.Numerator != 9 || report.SupportedRecall.Denominator != 9 || report.HardNegativeAccuracy.Numerator != 8 || report.HardNegativeAccuracy.Denominator != 8 {
		t.Fatalf("unexpected gated metrics: supported_recall=%+v hard_negative_accuracy=%+v", report.SupportedRecall, report.HardNegativeAccuracy)
	}
	wantFalseNegatives := []string{"claude.renamed", "codex.renamed", "gemini.renamed", "kimi.renamed"}
	if !reflect.DeepEqual(report.FalseNegativeSampleIDs, wantFalseNegatives) || len(report.FalsePositiveSampleIDs) != 0 || len(report.ExpectationMismatches) != 0 {
		t.Fatalf("unexpected error accounting: false_negatives=%v false_positives=%v expectation_mismatches=%v", report.FalseNegativeSampleIDs, report.FalsePositiveSampleIDs, report.ExpectationMismatches)
	}
	first, err := MarshalAgentRecognitionEvaluationReport(report)
	if err != nil {
		t.Fatal(err)
	}
	second, err := MarshalAgentRecognitionEvaluationReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("evaluation report serialization is not deterministic")
	}
}

func TestAgentRecognizerExactNamesRemainLowConfidence(t *testing.T) {
	recognizer, err := NewEmbeddedAgentRecognizer(AgentRecognizerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	low := recognizer.Classify(AgentRecognitionInput{Comm: "claude"})
	if low.Confidence != AgentRecognitionConfidenceLow {
		t.Fatalf("comm-only confidence = %q, want low", low.Confidence)
	}
	agreeing := recognizer.Classify(AgentRecognitionInput{Comm: "claude", ExecutableBasename: "claude"})
	if agreeing.Confidence != AgentRecognitionConfidenceLow || !reflect.DeepEqual(agreeing.MatchedSignalKinds, []string{"comm", "executable_basename"}) {
		t.Fatalf("agreeing exact-name result = %+v", agreeing)
	}
	ambiguous := recognizer.Classify(AgentRecognitionInput{Comm: "claude", ExecutableBasename: "codex"})
	if ambiguous.Status != AgentRecognitionStatusAmbiguous || ambiguous.AgentType != "" || len(ambiguous.MatchedRuleIDs) != 2 {
		t.Fatalf("conflicting signal result = %+v", ambiguous)
	}
}

func TestAgentRecognizerAggregatesMultipleRulesForOneAgentType(t *testing.T) {
	recognizer, err := NewAgentRecognizer("registry.v1", []AgentRecognitionRule{
		{RuleID: "rule.claude.comm", AgentType: "claude_code", ExactComms: []string{"claude"}},
		{RuleID: "rule.claude.alias", AgentType: "claude_code", ExactExecutableBasenames: []string{"claude-code"}},
	}, AgentRecognizerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	result := recognizer.Classify(AgentRecognitionInput{Comm: "claude", ExecutableBasename: "claude-code"})
	if result.Status != AgentRecognitionStatusRecognized || result.AgentType != "claude_code" {
		t.Fatalf("same-class rules produced conflicting result: %+v", result)
	}
	if result.Confidence != AgentRecognitionConfidenceLow || !reflect.DeepEqual(result.MatchedRuleIDs, []string{"rule.claude.alias", "rule.claude.comm"}) {
		t.Fatalf("same-class evidence was not aggregated: %+v", result)
	}
}

func TestAgentRecognizerOverridesApplyBeforePrefilter(t *testing.T) {
	recognizer, err := NewEmbeddedAgentRecognizer(AgentRecognizerOptions{
		AllowAgentTypes: []string{"claude_code", "codex_cli"},
		DenyAgentTypes:  []string{"codex_cli"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := recognizer.PrefilterComms(), []string{"claude"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("prefilter comms = %v, want %v", got, want)
	}
	if got := recognizer.Classify(AgentRecognitionInput{Comm: "codex"}); got.Status != AgentRecognitionStatusUnknown {
		t.Fatalf("denied class result = %+v, want unknown", got)
	}
}

func TestAgentRegistryDigestIsOrderIndependent(t *testing.T) {
	rulesA := []AgentRecognitionRule{
		{RuleID: "rule.b", AgentType: "type_b", ExactComms: []string{"beta", "b"}, ExactExecutableBasenames: []string{"beta-cli", "b-cli"}},
		{RuleID: "rule.a", AgentType: "type_a", ExactComms: []string{"alpha"}},
	}
	rulesB := []AgentRecognitionRule{
		{RuleID: "rule.a", AgentType: "type_a", ExactComms: []string{"alpha"}},
		{RuleID: "rule.b", AgentType: "type_b", ExactComms: []string{"b", "beta"}, ExactExecutableBasenames: []string{"b-cli", "beta-cli"}},
	}
	a, err := NewAgentRecognizer("registry.v1", rulesA, AgentRecognizerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAgentRecognizer("registry.v1", rulesB, AgentRecognizerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if a.digest != b.digest || len(a.digest) != 64 {
		t.Fatalf("registry digests differ: %q != %q", a.digest, b.digest)
	}
	removed, err := NewAgentRecognizer("registry.v1", rulesA[:1], AgentRecognizerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	addedRules := append(append([]AgentRecognitionRule(nil), rulesA...), AgentRecognitionRule{RuleID: "rule.c", AgentType: "type_c", ExactComms: []string{"charlie"}})
	added, err := NewAgentRecognizer("registry.v1", addedRules, AgentRecognizerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if removed.digest == a.digest || added.digest == a.digest || removed.digest == added.digest {
		t.Fatalf("adding or removing registry rules did not change the digest: original=%q removed=%q added=%q", a.digest, removed.digest, added.digest)
	}
}

func TestAgentRecognizerRejectsCollidingOrOversizedComms(t *testing.T) {
	tests := []struct {
		name  string
		rules []AgentRecognitionRule
	}{
		{
			name: "collision",
			rules: []AgentRecognitionRule{
				{RuleID: "rule.a", AgentType: "type_a", ExactComms: []string{"same"}},
				{RuleID: "rule.b", AgentType: "type_b", ExactComms: []string{"same"}},
			},
		},
		{name: "oversized comm", rules: []AgentRecognitionRule{{RuleID: "rule.a", AgentType: "type_a", ExactComms: []string{"sixteen-byte-name"}}}},
		{name: "oversized basename", rules: []AgentRecognitionRule{{RuleID: "rule.a", AgentType: "type_a", ExactExecutableBasenames: []string{strings.Repeat("a", 64)}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewAgentRecognizer("registry.v1", tt.rules, AgentRecognizerOptions{}); err == nil {
				t.Fatal("invalid registry unexpectedly accepted")
			}
		})
	}
}

func TestAgentRecognizerUsesCaseSensitiveKernelCommSemantics(t *testing.T) {
	recognizer, err := NewEmbeddedAgentRecognizer(AgentRecognizerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := recognizer.Classify(AgentRecognitionInput{Comm: "Codex"}); got.Status != AgentRecognitionStatusUnknown {
		t.Fatalf("case-mismatched comm result = %+v, want unknown", got)
	}
}

func TestAgentRecognizerRejectsRegistryLargerThanKernelPrefilter(t *testing.T) {
	rules := make([]AgentRecognitionRule, 0, 5)
	for index := 0; index < 5; index++ {
		comms := make([]string, 0, 13)
		for commIndex := 0; commIndex < 13; commIndex++ {
			comms = append(comms, fmt.Sprintf("agent-%02d-%02d", index, commIndex))
		}
		rules = append(rules, AgentRecognitionRule{
			RuleID:     fmt.Sprintf("rule.%d", index),
			AgentType:  fmt.Sprintf("type_%d", index),
			ExactComms: comms,
		})
	}
	if _, err := NewAgentRecognizer("registry.v1", rules, AgentRecognizerOptions{}); err == nil {
		t.Fatal("oversized prefilter registry unexpectedly accepted")
	}
}

func TestAgentRecognizerExecutableBasenamePrefilterHonorsOverrides(t *testing.T) {
	recognizer, err := NewEmbeddedAgentRecognizer(AgentRecognizerOptions{DenyAgentTypes: []string{"codex_cli"}})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(recognizer.PrefilterExecutableBasenames(), "codex") {
		t.Fatalf("denied basename remained in prefilter: %v", recognizer.PrefilterExecutableBasenames())
	}
	result := recognizer.Classify(AgentRecognitionInput{Comm: "node", ExecutableBasename: "codex"})
	if result.Status != AgentRecognitionStatusUnknown {
		t.Fatalf("denied script-backed candidate result = %+v", result)
	}
}
