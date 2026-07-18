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
			name: "signal availability without value",
			mutate: func(candidate *AgentRecognitionCorpus) {
				candidate.Samples[0].Input.Comm = ""
			},
		},
		{
			name: "executable basename value without availability",
			mutate: func(candidate *AgentRecognitionCorpus) {
				candidate.Samples[0].Signals.ExecutableBasenameAvailable = false
			},
		},
		{
			name: "executable basename availability without value",
			mutate: func(candidate *AgentRecognitionCorpus) {
				candidate.Samples[0].Input.ExecutableBasename = ""
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
		{
			name: "content fixture without availability",
			mutate: func(candidate *AgentRecognitionCorpus) {
				for index := range candidate.Samples {
					if candidate.Samples[index].SignalStratum == AgentRecognitionSignalStratumContentFingerprint {
						candidate.Samples[index].Signals.ContentFingerprintAvailable = false
						return
					}
				}
			},
		},
		{
			name: "unknown content fixture",
			mutate: func(candidate *AgentRecognitionCorpus) {
				for index := range candidate.Samples {
					if candidate.Samples[index].SignalStratum == AgentRecognitionSignalStratumContentFingerprint {
						candidate.Samples[index].ContentFingerprint.FixtureID = "unknown.fixture.v1"
						return
					}
				}
			},
		},
		{
			name: "content mismatch promoted",
			mutate: func(candidate *AgentRecognitionCorpus) {
				for index := range candidate.Samples {
					if candidate.Samples[index].Expected.FingerprintOutcome == AgentFingerprintOutcomeDigestMismatch {
						candidate.Samples[index].Expected.Confidence = AgentRecognitionConfidenceMedium
						return
					}
				}
			},
		},
		{
			name: "launcher missing observed interpreter",
			mutate: func(candidate *AgentRecognitionCorpus) {
				for index := range candidate.Samples {
					if candidate.Samples[index].SampleID == "content.codex.launcher.match" {
						candidate.Samples[index].ContentFingerprint.ObservedInterpreter = ""
						return
					}
				}
			},
		},
		{
			name: "launcher unsafe observed interpreter",
			mutate: func(candidate *AgentRecognitionCorpus) {
				for index := range candidate.Samples {
					if candidate.Samples[index].SampleID == "content.codex.launcher.match" {
						candidate.Samples[index].ContentFingerprint.ObservedInterpreter = "/usr/bin/node"
						return
					}
				}
			},
		},
		{
			name: "native observed interpreter",
			mutate: func(candidate *AgentRecognitionCorpus) {
				for index := range candidate.Samples {
					if candidate.Samples[index].SampleID == "content.claude.native.match" {
						candidate.Samples[index].ContentFingerprint.ObservedInterpreter = "node"
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
		func(candidate *AgentRecognitionThresholds) { candidate.MinimumContentFingerprintAccuracy = 1.01 },
		func(candidate *AgentRecognitionThresholds) { candidate.MaximumContentMismatchPromotions = -1 },
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

func TestAgentRecognitionEvaluationRejectsNaNThresholds(t *testing.T) {
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

	tests := []struct {
		name        string
		mutate      func(*AgentRecognitionThresholds)
		wantMessage string
	}{
		{
			name: "minimum supported recall",
			mutate: func(candidate *AgentRecognitionThresholds) {
				candidate.MinimumSupportedRecall = math.NaN()
			},
			wantMessage: "minimum supported recall must be within [0,1]",
		},
		{
			name: "minimum content-fingerprint accuracy",
			mutate: func(candidate *AgentRecognitionThresholds) {
				candidate.MinimumContentFingerprintAccuracy = math.NaN()
			},
			wantMessage: "minimum content-fingerprint accuracy must be within [0,1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := *thresholds
			tt.mutate(&candidate)
			report, err := EvaluateAgentRecognitionCorpus(recognizer, corpus, digest, &candidate)
			if err == nil {
				t.Fatal("NaN threshold unexpectedly accepted")
			}
			if report != nil {
				t.Fatalf("invalid thresholds produced a report containing NaN: %+v", report)
			}
			if !strings.Contains(err.Error(), tt.wantMessage) {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
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
	if report.Gate.Passed || report.NameOnly.SupportedRecall.Numerator != 8 || report.NameOnly.SupportedRecall.Denominator != 9 {
		t.Fatalf("below-threshold corpus unexpectedly passed: %+v", report.Gate)
	}
	if !slices.Contains(report.Gate.Reasons, "supported-shape recall is below the maintained-corpus threshold") {
		t.Fatalf("gate omitted recall reason: %v", report.Gate.Reasons)
	}
}

func TestAgentRecognitionContentFingerprintStratumFailsClosedAndNeverBlendsConfidence(t *testing.T) {
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
	for _, result := range report.Samples {
		if result.SignalStratum != AgentRecognitionSignalStratumContentFingerprint {
			continue
		}
		switch result.FingerprintOutcome {
		case AgentFingerprintOutcomeSuccess:
			if result.ActualConfidence != AgentRecognitionConfidenceMedium {
				t.Fatalf("content match did not promote only to medium: %+v", result)
			}
		case AgentFingerprintOutcomeDigestMismatch:
			if result.ActualConfidence != AgentRecognitionConfidenceLow {
				t.Fatalf("content mismatch changed low-confidence candidate: %+v", result)
			}
		default:
			t.Fatalf("content sample was not accounted as match or mismatch: %+v", result)
		}
	}

	mutated := cloneTestAgentRecognitionCorpus(t, corpus)
	for index := range mutated.Samples {
		if mutated.Samples[index].SampleID == "content.claude.native.match" {
			mutated.Samples[index].Input = AgentRecognitionInput{Comm: "codex", ExecutableBasename: "codex"}
			break
		}
	}
	parsed, mutatedDigest := parseTestAgentRecognitionCorpus(t, mutated)
	failed, err := EvaluateAgentRecognitionCorpus(recognizer, parsed, mutatedDigest, thresholds)
	if err != nil {
		t.Fatal(err)
	}
	if failed.Gate.Passed || failed.ContentFingerprint.CorrectCount != 7 || !slices.Contains(failed.ContentFingerprint.ExpectationMismatches, "content.claude.native.match") {
		t.Fatalf("mutated content transition unexpectedly passed: %+v", failed.ContentFingerprint)
	}
}

func TestAgentRecognitionLauncherEvaluationUsesIndependentObservedInterpreter(t *testing.T) {
	corpus, _, err := EmbeddedAgentRecognitionCorpus()
	if err != nil {
		t.Fatal(err)
	}
	mutated := cloneTestAgentRecognitionCorpus(t, corpus)
	for index := range mutated.Samples {
		if mutated.Samples[index].SampleID == "content.codex.launcher.match" {
			mutated.Samples[index].ContentFingerprint.ObservedInterpreter = "python3"
			break
		}
	}
	parsed, digest := parseTestAgentRecognitionCorpus(t, mutated)
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
	if report.Gate.Passed {
		t.Fatal("launcher sample with a disallowed observed interpreter unexpectedly passed")
	}
	for _, result := range report.Samples {
		if result.SampleID != "content.codex.launcher.match" {
			continue
		}
		if result.FingerprintOutcome != AgentFingerprintOutcomeInterpreterDenied || result.ActualConfidence != AgentRecognitionConfidenceLow || result.ExpectationMatched {
			t.Fatalf("mutated launcher result = %+v, want fail-closed interpreter denial", result)
		}
		return
	}
	t.Fatal("mutated launcher sample result was not emitted")
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
	if report.CorpusSampleCount != len(report.Samples) || report.NameOnly.SampleCount != report.NameOnly.EvaluatedCount+report.NameOnly.UnavailableCount || report.CorpusSampleCount != report.NameOnly.SampleCount+report.ContentFingerprint.SampleCount {
		t.Fatalf("sample accounting mismatch: corpus=%d results=%d name_only=%d evaluated=%d unavailable=%d content=%d", report.CorpusSampleCount, len(report.Samples), report.NameOnly.SampleCount, report.NameOnly.EvaluatedCount, report.NameOnly.UnavailableCount, report.ContentFingerprint.SampleCount)
	}
	if report.ClaimBoundary != "maintained_corpus_contract_only_not_population_accuracy_provenance_or_identity_assurance" {
		t.Fatalf("unsafe claim boundary: %q", report.ClaimBoundary)
	}
	ratios := []AgentRecognitionRatio{report.NameOnly.AggregatePrecision, report.NameOnly.AggregateRecall, report.NameOnly.SupportedRecall, report.NameOnly.HardNegativeAccuracy, report.ContentFingerprint.Accuracy}
	for _, class := range report.NameOnly.PerClass {
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
