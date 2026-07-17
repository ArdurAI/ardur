package kernelcapture

import (
	"bytes"
	"encoding/json"
	"math"
	"slices"
	"strings"
	"testing"
)

func TestAgentRecognitionCorpusDigestIsOrderIndependentAndContentAddressed(t *testing.T) {
	corpus, originalDigest, err := EmbeddedAgentRecognitionCorpus()
	if err != nil {
		t.Fatal(err)
	}

	reordered := *corpus
	reordered.Samples = append([]AgentRecognitionSample(nil), corpus.Samples...)
	slices.Reverse(reordered.Samples)
	_, reorderedDigest := parseTestAgentRecognitionCorpus(t, reordered)
	if reorderedDigest != originalDigest {
		t.Fatalf("reordered corpus digest = %q, want %q", reorderedDigest, originalDigest)
	}

	added := reordered
	additional := corpus.Samples[0]
	additional.SampleID = "claude.additional-supported-shape"
	additional.InstallationShape = "additional_supported_shape"
	added.Samples = append(append([]AgentRecognitionSample(nil), reordered.Samples...), additional)
	_, addedDigest := parseTestAgentRecognitionCorpus(t, added)
	if addedDigest == originalDigest {
		t.Fatal("adding a corpus sample did not change the canonical digest")
	}

	removed := *corpus
	removed.Samples = append([]AgentRecognitionSample(nil), corpus.Samples[1:]...)
	_, removedDigest := parseTestAgentRecognitionCorpus(t, removed)
	if removedDigest == originalDigest {
		t.Fatal("removing a corpus sample did not change the canonical digest")
	}
}

func TestAgentRecognitionCorpusParserRejectsUnreviewedOrContradictorySamples(t *testing.T) {
	corpus, _, err := EmbeddedAgentRecognitionCorpus()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*AgentRecognitionCorpus)
	}{
		{
			name: "duplicate sample id",
			mutate: func(candidate *AgentRecognitionCorpus) {
				candidate.Samples[1].SampleID = candidate.Samples[0].SampleID
			},
		},
		{
			name: "unsanitized provenance",
			mutate: func(candidate *AgentRecognitionCorpus) {
				candidate.Samples[0].Provenance.Sanitized = false
			},
		},
		{
			name: "host path provenance",
			mutate: func(candidate *AgentRecognitionCorpus) {
				candidate.Samples[0].Provenance.Reference = "/home/operator/private/session.log"
			},
		},
		{
			name: "signal value without availability",
			mutate: func(candidate *AgentRecognitionCorpus) {
				candidate.Samples[0].Signals.CommAvailable = false
			},
		},
		{
			name: "unavailable sample with signal",
			mutate: func(candidate *AgentRecognitionCorpus) {
				last := len(candidate.Samples) - 1
				candidate.Samples[last].Signals.CommAvailable = true
			},
		},
		{
			name: "hard negative labeled recognized",
			mutate: func(candidate *AgentRecognitionCorpus) {
				for index := range candidate.Samples {
					if candidate.Samples[index].EvaluationSet == AgentRecognitionEvaluationHardNegative {
						candidate.Samples[index].Expected = AgentRecognitionExpectation{Status: AgentRecognitionStatusRecognized, AgentType: "claude_code"}
						return
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := cloneTestAgentRecognitionCorpus(t, corpus)
			tt.mutate(&candidate)
			raw, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := ParseAgentRecognitionCorpus(bytes.NewReader(raw)); err == nil {
				t.Fatal("invalid corpus unexpectedly accepted")
			}
		})
	}
}

func TestAgentRecognitionCorpusParserRejectsUnknownFieldsAndTrailingValues(t *testing.T) {
	corpus, _, err := EmbeddedAgentRecognitionCorpus()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	withUnknownField := bytes.Replace(raw, []byte(`{"schema_version"`), []byte(`{"unexpected":true,"schema_version"`), 1)
	if _, _, err := ParseAgentRecognitionCorpus(bytes.NewReader(withUnknownField)); err == nil {
		t.Fatal("unknown field unexpectedly accepted")
	}
	if _, _, err := ParseAgentRecognitionCorpus(bytes.NewReader(append(raw, []byte(` {}`)...))); err == nil {
		t.Fatal("trailing JSON value unexpectedly accepted")
	}
}

func TestAgentRecognitionThresholdsRequireReviewedIntervalContract(t *testing.T) {
	thresholds, err := EmbeddedAgentRecognitionThresholds()
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*AgentRecognitionThresholds){
		func(candidate *AgentRecognitionThresholds) { candidate.ConfidenceIntervalMethod = "wald" },
		func(candidate *AgentRecognitionThresholds) { candidate.ConfidenceLevel = 0.99 },
		func(candidate *AgentRecognitionThresholds) { candidate.MinimumSupportedRecall = 1.01 },
		func(candidate *AgentRecognitionThresholds) { candidate.MaximumHardNegativeFalsePositives = -1 },
	} {
		candidate := *thresholds
		mutate(&candidate)
		raw, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentRecognitionThresholds(bytes.NewReader(raw)); err == nil {
			t.Fatalf("invalid thresholds unexpectedly accepted: %+v", candidate)
		}
	}
}

func TestAgentRecognitionWilsonIntervalMatchesPublishedScoreFormula(t *testing.T) {
	lower, upper := agentRecognitionWilsonInterval(8, 30)
	if math.Abs(lower-0.14182663319596317) > 1e-12 || math.Abs(upper-0.4444796169518888) > 1e-12 {
		t.Fatalf("Wilson interval for 8/30 = [%0.16f, %0.16f]", lower, upper)
	}
	if lower, upper := agentRecognitionWilsonInterval(0, 0); lower != 0 || upper != 0 {
		t.Fatalf("empty Wilson interval = [%v, %v], want [0, 0]", lower, upper)
	}
}

func TestAgentRecognitionEvaluationGateFailsBelowSupportedRecall(t *testing.T) {
	corpus, _, err := EmbeddedAgentRecognitionCorpus()
	if err != nil {
		t.Fatal(err)
	}
	candidate := cloneTestAgentRecognitionCorpus(t, corpus)
	for index := range candidate.Samples {
		if candidate.Samples[index].SampleID == "claude.native" {
			candidate.Samples[index].Input = AgentRecognitionInput{Comm: "renamed-claude", ExecutableBasename: "renamed-claude"}
		}
	}
	parsed, digest := parseTestAgentRecognitionCorpus(t, candidate)
	thresholds, err := EmbeddedAgentRecognitionThresholds()
	if err != nil {
		t.Fatal(err)
	}
	recognizer, err := NewEmbeddedAgentRecognizer(AgentRecognizerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	report, err := EvaluateAgentRecognitionCorpus(recognizer, parsed, digest, thresholds)
	if err != nil {
		t.Fatal(err)
	}
	if report.Gate.Passed || report.SupportedRecall.Numerator != 8 || report.SupportedRecall.Denominator != 9 {
		t.Fatalf("below-threshold corpus unexpectedly passed: %+v", report.Gate)
	}
	if !slices.Contains(report.Gate.Reasons, "supported-shape recall is below the maintained-corpus threshold") {
		t.Fatalf("gate omitted recall reason: %v", report.Gate.Reasons)
	}
}

func TestAgentRecognitionEvaluationAccountsForEverySample(t *testing.T) {
	corpus, digest, err := EmbeddedAgentRecognitionCorpus()
	if err != nil {
		t.Fatal(err)
	}
	thresholds, err := EmbeddedAgentRecognitionThresholds()
	if err != nil {
		t.Fatal(err)
	}
	recognizer, err := NewEmbeddedAgentRecognizer(AgentRecognizerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	report, err := EvaluateAgentRecognitionCorpus(recognizer, corpus, digest, thresholds)
	if err != nil {
		t.Fatal(err)
	}
	if report.SampleCount != len(report.Samples) || report.SampleCount != report.EvaluatedCount+report.UnavailableCount {
		t.Fatalf("sample accounting mismatch: samples=%d results=%d evaluated=%d unavailable=%d", report.SampleCount, len(report.Samples), report.EvaluatedCount, report.UnavailableCount)
	}
	if report.ClaimBoundary != "maintained_corpus_only_not_population_accuracy_or_identity_assurance" {
		t.Fatalf("unsafe claim boundary: %q", report.ClaimBoundary)
	}
	ratios := []AgentRecognitionRatio{report.AggregatePrecision, report.AggregateRecall, report.SupportedRecall, report.HardNegativeAccuracy}
	for _, class := range report.PerClass {
		ratios = append(ratios, class.Precision, class.Recall)
	}
	for _, ratio := range ratios {
		if ratio.Denominator <= 0 || ratio.Value == nil || ratio.Wilson == nil || ratio.Wilson.ConfidenceLevel != 0.95 || ratio.Wilson.Method != AgentRecognitionWilsonMethod {
			t.Fatalf("metric omitted its count or reviewed interval: %+v", ratio)
		}
	}
	for _, result := range report.Samples {
		if strings.TrimSpace(result.SampleID) == "" {
			t.Fatal("evaluation emitted a result without a sample id")
		}
	}
}

func TestAgentRecognitionEvaluationRejectsForgedDigestOrMutatedThresholds(t *testing.T) {
	corpus, digest, err := EmbeddedAgentRecognitionCorpus()
	if err != nil {
		t.Fatal(err)
	}
	thresholds, err := EmbeddedAgentRecognitionThresholds()
	if err != nil {
		t.Fatal(err)
	}
	recognizer, err := NewEmbeddedAgentRecognizer(AgentRecognizerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateAgentRecognitionCorpus(recognizer, corpus, strings.Repeat("0", 64), thresholds); err == nil {
		t.Fatal("forged corpus digest unexpectedly accepted")
	}
	invalidThresholds := *thresholds
	invalidThresholds.ConfidenceIntervalMethod = "wald"
	if _, err := EvaluateAgentRecognitionCorpus(recognizer, corpus, digest, &invalidThresholds); err == nil {
		t.Fatal("mutated unsupported thresholds unexpectedly accepted")
	}
}

func parseTestAgentRecognitionCorpus(t *testing.T, corpus AgentRecognitionCorpus) (*AgentRecognitionCorpus, string) {
	t.Helper()
	raw, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	parsed, digest, err := ParseAgentRecognitionCorpus(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return parsed, digest
}

func cloneTestAgentRecognitionCorpus(t *testing.T, corpus *AgentRecognitionCorpus) AgentRecognitionCorpus {
	t.Helper()
	raw, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	var cloned AgentRecognitionCorpus
	if err := json.Unmarshal(raw, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}
