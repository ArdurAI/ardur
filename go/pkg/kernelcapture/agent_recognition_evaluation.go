package kernelcapture

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	AgentRecognitionCorpusSchema                    = "ardur.agent_recognition_corpus.v0.2"
	AgentRecognitionThresholdsSchema                = "ardur.agent_recognition_thresholds.v0.2"
	AgentRecognitionEvaluationSchema                = "ardur.agent_recognition_evaluation.v0.2"
	AgentRecognitionSignalStratumNameOnly           = "name_only"
	AgentRecognitionSignalStratumContentFingerprint = "content_fingerprint"
	AgentRecognitionContentOutcomeNotAttempted      = "not_attempted"

	AgentRecognitionEvaluationSupportedPositive = "supported_positive"
	AgentRecognitionEvaluationKnownUnsupported  = "known_unsupported_positive"
	AgentRecognitionEvaluationHardNegative      = "hard_negative"
	AgentRecognitionEvaluationConflict          = "conflict"
	AgentRecognitionEvaluationUnavailable       = "unavailable"

	AgentRecognitionEvaluationStatusUnavailable = "unavailable"
	AgentRecognitionWilsonMethod                = "wilson_score"

	MaxAgentRecognitionCorpusBytes     = 1 << 20
	MaxAgentRecognitionThresholdBytes  = 64 << 10
	maxAgentRecognitionCorpusSamples   = 4096
	maxAgentRecognitionProvenanceBytes = 512
)

//go:embed testdata/agent_recognition_corpus.json
var embeddedAgentRecognitionCorpusJSON []byte

//go:embed testdata/agent_recognition_thresholds.json
var embeddedAgentRecognitionThresholdsJSON []byte

type AgentRecognitionCorpus struct {
	SchemaVersion string                   `json:"schema_version"`
	CorpusVersion string                   `json:"corpus_version"`
	Samples       []AgentRecognitionSample `json:"samples"`
}

type AgentRecognitionSample struct {
	SampleID           string                                   `json:"sample_id"`
	EvaluationSet      string                                   `json:"evaluation_set"`
	AgentType          string                                   `json:"agent_type,omitempty"`
	InstallationShape  string                                   `json:"installation_shape"`
	Platform           string                                   `json:"platform"`
	SignalStratum      string                                   `json:"signal_stratum"`
	Signals            AgentRecognitionSignals                  `json:"signals"`
	Input              AgentRecognitionInput                    `json:"input"`
	ContentFingerprint *AgentRecognitionContentFingerprintInput `json:"content_fingerprint,omitempty"`
	Expected           AgentRecognitionExpectation              `json:"expected"`
	NearMissFor        []string                                 `json:"near_miss_for,omitempty"`
	Provenance         AgentRecognitionProvenance               `json:"provenance"`
}

type AgentRecognitionSignals struct {
	CommAvailable               bool `json:"comm_available"`
	ExecutableBasenameAvailable bool `json:"executable_basename_available"`
	ContentFingerprintAvailable bool `json:"content_fingerprint_available"`
}

type AgentRecognitionContentFingerprintInput struct {
	FixtureID           string `json:"fixture_id,omitempty"`
	ObservedInterpreter string `json:"observed_interpreter,omitempty"`
}

type AgentRecognitionExpectation struct {
	Status             string `json:"status"`
	AgentType          string `json:"agent_type,omitempty"`
	Confidence         string `json:"confidence,omitempty"`
	FingerprintOutcome string `json:"fingerprint_outcome,omitempty"`
}

type AgentRecognitionProvenance struct {
	SourceKind string `json:"source_kind"`
	Reference  string `json:"reference"`
	ReviewedAt string `json:"reviewed_at"`
	Sanitized  bool   `json:"sanitized"`
}

type AgentRecognitionThresholds struct {
	SchemaVersion                     string  `json:"schema_version"`
	ThresholdVersion                  string  `json:"threshold_version"`
	MinimumSupportedRecall            float64 `json:"minimum_supported_recall"`
	MaximumHardNegativeFalsePositives int     `json:"maximum_hard_negative_false_positives"`
	MinimumContentFingerprintAccuracy float64 `json:"minimum_content_fingerprint_accuracy"`
	MaximumContentMismatchPromotions  int     `json:"maximum_content_mismatch_promotions"`
	ConfidenceLevel                   float64 `json:"confidence_level"`
	ConfidenceIntervalMethod          string  `json:"confidence_interval_method"`
}

type AgentRecognitionEvaluationReport struct {
	SchemaVersion      string                                   `json:"schema_version"`
	CorpusVersion      string                                   `json:"corpus_version"`
	CorpusSHA256       string                                   `json:"corpus_sha256"`
	RegistryVersion    string                                   `json:"registry_version"`
	RegistrySHA256     string                                   `json:"registry_sha256"`
	ThresholdVersion   string                                   `json:"threshold_version"`
	SignalStrata       []string                                 `json:"signal_strata"`
	CorpusSampleCount  int                                      `json:"corpus_sample_count"`
	NameOnly           AgentRecognitionNameOnlyReport           `json:"name_only"`
	ContentFingerprint AgentRecognitionContentFingerprintReport `json:"content_fingerprint"`
	Samples            []AgentRecognitionSampleResult           `json:"samples"`
	Gate               AgentRecognitionGateResult               `json:"gate"`
	ClaimBoundary      string                                   `json:"claim_boundary"`
}

type AgentRecognitionNameOnlyReport struct {
	SampleCount            int                             `json:"sample_count"`
	EvaluatedCount         int                             `json:"evaluated_count"`
	UnavailableCount       int                             `json:"unavailable_count"`
	UnknownCount           int                             `json:"unknown_count"`
	AmbiguousCount         int                             `json:"ambiguous_count"`
	ExpectationMismatches  []string                        `json:"expectation_mismatches"`
	FalsePositiveSampleIDs []string                        `json:"false_positive_sample_ids"`
	FalseNegativeSampleIDs []string                        `json:"false_negative_sample_ids"`
	ConfusionMatrix        []AgentRecognitionConfusionCell `json:"confusion_matrix"`
	PerClass               []AgentRecognitionClassMetrics  `json:"per_class"`
	AggregatePrecision     AgentRecognitionRatio           `json:"aggregate_precision"`
	AggregateRecall        AgentRecognitionRatio           `json:"aggregate_recall"`
	SupportedRecall        AgentRecognitionRatio           `json:"supported_recall"`
	HardNegativeAccuracy   AgentRecognitionRatio           `json:"hard_negative_accuracy"`
}

type AgentRecognitionContentFingerprintReport struct {
	FingerprintRegistryVersion string                `json:"fingerprint_registry_version"`
	FingerprintRegistrySHA256  string                `json:"fingerprint_registry_sha256"`
	SampleCount                int                   `json:"sample_count"`
	NativeSampleCount          int                   `json:"native_sample_count"`
	LauncherSampleCount        int                   `json:"launcher_sample_count"`
	MatchSampleCount           int                   `json:"match_sample_count"`
	MismatchSampleCount        int                   `json:"mismatch_sample_count"`
	CorrectCount               int                   `json:"correct_count"`
	MismatchPromotions         int                   `json:"mismatch_promotions"`
	Accuracy                   AgentRecognitionRatio `json:"accuracy"`
	ExpectationMismatches      []string              `json:"expectation_mismatches"`
}

type AgentRecognitionSampleResult struct {
	SampleID              string `json:"sample_id"`
	SignalStratum         string `json:"signal_stratum"`
	EvaluationSet         string `json:"evaluation_set"`
	GroundTruthAgentType  string `json:"ground_truth_agent_type,omitempty"`
	ActualStatus          string `json:"actual_status"`
	ActualAgentType       string `json:"actual_agent_type,omitempty"`
	ActualConfidence      string `json:"actual_confidence,omitempty"`
	FingerprintOutcome    string `json:"fingerprint_outcome,omitempty"`
	ExpectationMatched    bool   `json:"expectation_matched"`
	ClassificationCorrect bool   `json:"classification_correct"`
}

type AgentRecognitionConfusionCell struct {
	Actual    string `json:"actual"`
	Predicted string `json:"predicted"`
	Count     int    `json:"count"`
}

type AgentRecognitionClassMetrics struct {
	AgentType     string                `json:"agent_type"`
	TruePositive  int                   `json:"true_positive"`
	FalsePositive int                   `json:"false_positive"`
	FalseNegative int                   `json:"false_negative"`
	Precision     AgentRecognitionRatio `json:"precision"`
	Recall        AgentRecognitionRatio `json:"recall"`
}

type AgentRecognitionRatio struct {
	Numerator   int                                 `json:"numerator"`
	Denominator int                                 `json:"denominator"`
	Value       *float64                            `json:"value"`
	Wilson      *AgentRecognitionConfidenceInterval `json:"wilson,omitempty"`
}

type AgentRecognitionConfidenceInterval struct {
	Method          string  `json:"method"`
	ConfidenceLevel float64 `json:"confidence_level"`
	Lower           float64 `json:"lower"`
	Upper           float64 `json:"upper"`
}

type AgentRecognitionGateResult struct {
	Passed                             bool     `json:"passed"`
	MinimumSupportedRecall             float64  `json:"minimum_supported_recall"`
	MaximumHardNegativeFalsePositives  int      `json:"maximum_hard_negative_false_positives"`
	ObservedHardNegativeFalsePositives int      `json:"observed_hard_negative_false_positives"`
	MinimumContentFingerprintAccuracy  float64  `json:"minimum_content_fingerprint_accuracy"`
	MaximumContentMismatchPromotions   int      `json:"maximum_content_mismatch_promotions"`
	ObservedContentMismatchPromotions  int      `json:"observed_content_mismatch_promotions"`
	Reasons                            []string `json:"reasons"`
}

type agentRecognitionEvaluationFingerprintFixture struct {
	fixtureID   string
	agentType   string
	method      string
	interpreter string
	digest      [sha256.Size]byte
}

var agentRecognitionEvaluationFingerprintFixtures = func() []agentRecognitionEvaluationFingerprintFixture {
	definitions := []struct {
		fixtureID   string
		agentType   string
		method      string
		interpreter string
	}{
		{fixtureID: "claude.native.v1", agentType: "claude_code", method: AgentFingerprintMethodSHA256ProcExe},
		{fixtureID: "codex.native.v1", agentType: "codex_cli", method: AgentFingerprintMethodSHA256ProcExe},
		{fixtureID: "codex.launcher.node.v1", agentType: "codex_cli", method: AgentFingerprintMethodSHA256KernelLauncher, interpreter: "node"},
		{fixtureID: "gemini.launcher.node.v1", agentType: "gemini_cli", method: AgentFingerprintMethodSHA256KernelLauncher, interpreter: "node"},
		{fixtureID: "kimi.launcher.python3.v1", agentType: "kimi_cli", method: AgentFingerprintMethodSHA256KernelLauncher, interpreter: "python3"},
	}
	fixtures := make([]agentRecognitionEvaluationFingerprintFixture, 0, len(definitions))
	for _, definition := range definitions {
		fixtures = append(fixtures, agentRecognitionEvaluationFingerprintFixture{
			fixtureID:   definition.fixtureID,
			agentType:   definition.agentType,
			method:      definition.method,
			interpreter: definition.interpreter,
			digest:      sha256.Sum256([]byte("ardur.agent-recognition.synthetic-content-fixture.v1:" + definition.fixtureID)),
		})
	}
	return fixtures
}()

func agentRecognitionEvaluationFingerprintFixtureByID(fixtureID string) (agentRecognitionEvaluationFingerprintFixture, bool) {
	for _, fixture := range agentRecognitionEvaluationFingerprintFixtures {
		if fixture.fixtureID == fixtureID {
			return fixture, true
		}
	}
	return agentRecognitionEvaluationFingerprintFixture{}, false
}

func newAgentRecognitionEvaluationFingerprintRegistry() (*AgentFingerprintRegistry, error) {
	type groupedRule struct {
		nativeDigests   []string
		launcherDigests []string
		interpreters    []string
	}
	grouped := make(map[string]*groupedRule)
	for _, fixture := range agentRecognitionEvaluationFingerprintFixtures {
		rule := grouped[fixture.agentType]
		if rule == nil {
			rule = &groupedRule{}
			grouped[fixture.agentType] = rule
		}
		digest := hex.EncodeToString(fixture.digest[:])
		if fixture.method == AgentFingerprintMethodSHA256KernelLauncher {
			rule.launcherDigests = append(rule.launcherDigests, digest)
			rule.interpreters = append(rule.interpreters, fixture.interpreter)
		} else {
			rule.nativeDigests = append(rule.nativeDigests, digest)
		}
	}
	agentTypes := make([]string, 0, len(grouped))
	for agentType := range grouped {
		agentTypes = append(agentTypes, agentType)
	}
	sort.Strings(agentTypes)
	rules := make([]AgentFingerprintRule, 0, len(agentTypes))
	for _, agentType := range agentTypes {
		group := grouped[agentType]
		rules = append(rules, AgentFingerprintRule{
			RuleID:                     "evaluation." + agentType + ".content.v1",
			AgentType:                  agentType,
			ExpectedSHA256:             group.nativeDigests,
			ExpectedLauncherSHA256:     group.launcherDigests,
			AllowedInterpreterProfiles: group.interpreters,
		})
	}
	return NewAgentFingerprintRegistry(AgentFingerprintRegistryDocument{
		SchemaVersion:   AgentFingerprintRegistrySchema,
		RegistryVersion: "ardur.agent-recognition-evaluation-content.2026-07-17.v1",
		Rules:           rules,
	})
}

func ParseAgentRecognitionCorpus(r io.Reader) (*AgentRecognitionCorpus, string, error) {
	var corpus AgentRecognitionCorpus
	if err := decodeBoundedAgentRecognitionJSON(r, MaxAgentRecognitionCorpusBytes, &corpus); err != nil {
		return nil, "", fmt.Errorf("decode agent recognition corpus: %w", err)
	}
	canonical, err := canonicalAgentRecognitionCorpus(corpus)
	if err != nil {
		return nil, "", err
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, "", fmt.Errorf("marshal canonical agent recognition corpus: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return &canonical, hex.EncodeToString(digest[:]), nil
}

func ParseAgentRecognitionThresholds(r io.Reader) (*AgentRecognitionThresholds, error) {
	var thresholds AgentRecognitionThresholds
	if err := decodeBoundedAgentRecognitionJSON(r, MaxAgentRecognitionThresholdBytes, &thresholds); err != nil {
		return nil, fmt.Errorf("decode agent recognition thresholds: %w", err)
	}
	if err := validateAgentRecognitionThresholds(thresholds); err != nil {
		return nil, err
	}
	return &thresholds, nil
}

func validateAgentRecognitionThresholds(thresholds AgentRecognitionThresholds) error {
	if thresholds.SchemaVersion != AgentRecognitionThresholdsSchema {
		return fmt.Errorf("agent recognition threshold schema must be %q", AgentRecognitionThresholdsSchema)
	}
	if !agentRecognitionIdentifier.MatchString(thresholds.ThresholdVersion) {
		return fmt.Errorf("agent recognition threshold version is invalid")
	}
	if thresholds.MinimumSupportedRecall < 0 || thresholds.MinimumSupportedRecall > 1 {
		return fmt.Errorf("minimum supported recall must be within [0,1]")
	}
	if thresholds.MaximumHardNegativeFalsePositives < 0 {
		return fmt.Errorf("maximum hard-negative false positives must be non-negative")
	}
	if thresholds.MinimumContentFingerprintAccuracy < 0 || thresholds.MinimumContentFingerprintAccuracy > 1 {
		return fmt.Errorf("minimum content-fingerprint accuracy must be within [0,1]")
	}
	if thresholds.MaximumContentMismatchPromotions < 0 {
		return fmt.Errorf("maximum content-mismatch promotions must be non-negative")
	}
	if thresholds.ConfidenceIntervalMethod != AgentRecognitionWilsonMethod || thresholds.ConfidenceLevel != 0.95 {
		return fmt.Errorf("only a two-sided 95%% Wilson score interval is supported")
	}
	return nil
}

func EmbeddedAgentRecognitionCorpus() (*AgentRecognitionCorpus, string, error) {
	return ParseAgentRecognitionCorpus(bytes.NewReader(embeddedAgentRecognitionCorpusJSON))
}

func EmbeddedAgentRecognitionThresholds() (*AgentRecognitionThresholds, error) {
	return ParseAgentRecognitionThresholds(bytes.NewReader(embeddedAgentRecognitionThresholdsJSON))
}

func EvaluateAgentRecognitionCorpus(recognizer *AgentRecognizer, corpus *AgentRecognitionCorpus, corpusSHA256 string, thresholds *AgentRecognitionThresholds) (*AgentRecognitionEvaluationReport, error) {
	if recognizer == nil || corpus == nil || thresholds == nil {
		return nil, fmt.Errorf("recognizer, corpus, and thresholds are required")
	}
	canonical, err := canonicalAgentRecognitionCorpus(*corpus)
	if err != nil {
		return nil, fmt.Errorf("validate agent recognition corpus before evaluation: %w", err)
	}
	encodedCorpus, err := json.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical agent recognition corpus before evaluation: %w", err)
	}
	computedDigest := sha256.Sum256(encodedCorpus)
	if corpusSHA256 != hex.EncodeToString(computedDigest[:]) {
		return nil, fmt.Errorf("canonical corpus SHA-256 does not match the evaluated samples")
	}
	if err := validateAgentRecognitionThresholds(*thresholds); err != nil {
		return nil, fmt.Errorf("validate agent recognition thresholds before evaluation: %w", err)
	}
	corpus = &canonical
	registryVersion, registrySHA256 := recognizer.RegistryMetadata()
	agentTypes := recognizer.AgentTypes()
	knownTypes := make(map[string]struct{}, len(agentTypes))
	for _, agentType := range agentTypes {
		knownTypes[agentType] = struct{}{}
	}
	fingerprintRegistry, err := newAgentRecognitionEvaluationFingerprintRegistry()
	if err != nil {
		return nil, fmt.Errorf("build agent recognition content-fingerprint evaluation registry: %w", err)
	}
	if err := fingerprintRegistry.ValidateAgentTypes(agentTypes); err != nil {
		return nil, fmt.Errorf("validate content-fingerprint evaluation registry: %w", err)
	}

	report := &AgentRecognitionEvaluationReport{
		SchemaVersion:     AgentRecognitionEvaluationSchema,
		CorpusVersion:     corpus.CorpusVersion,
		CorpusSHA256:      corpusSHA256,
		RegistryVersion:   registryVersion,
		RegistrySHA256:    registrySHA256,
		ThresholdVersion:  thresholds.ThresholdVersion,
		SignalStrata:      []string{AgentRecognitionSignalStratumNameOnly, AgentRecognitionSignalStratumContentFingerprint},
		CorpusSampleCount: len(corpus.Samples),
		NameOnly: AgentRecognitionNameOnlyReport{
			ExpectationMismatches:  []string{},
			FalsePositiveSampleIDs: []string{},
			FalseNegativeSampleIDs: []string{},
			ConfusionMatrix:        []AgentRecognitionConfusionCell{},
			PerClass:               []AgentRecognitionClassMetrics{},
		},
		ContentFingerprint: AgentRecognitionContentFingerprintReport{
			FingerprintRegistryVersion: fingerprintRegistry.version,
			FingerprintRegistrySHA256:  fingerprintRegistry.digest,
			ExpectationMismatches:      []string{},
		},
		Samples:       []AgentRecognitionSampleResult{},
		ClaimBoundary: "maintained_corpus_contract_only_not_population_accuracy_provenance_or_identity_assurance",
	}
	nameOnly := &report.NameOnly
	contentFingerprint := &report.ContentFingerprint
	confusion := make(map[string]map[string]int)
	resultsByID := make(map[string]AgentRecognitionSampleResult, len(corpus.Samples))
	supportedShapes := make(map[string]map[string]struct{}, len(agentTypes))
	nearMisses := make(map[string]struct{}, len(agentTypes))
	contentMatchTypes := make(map[string]struct{}, len(agentTypes))
	contentMismatchTargets := make(map[string]struct{}, len(agentTypes))
	hardNegativeCount := 0
	hardNegativeCorrect := 0
	hardNegativeFalsePositives := 0
	supportedCorrect := 0
	supportedTotal := 0

	for _, sample := range corpus.Samples {
		for _, nearMissAgentType := range sample.NearMissFor {
			if _, ok := knownTypes[nearMissAgentType]; !ok {
				return nil, fmt.Errorf("sample %q references unknown near-miss agent type %q", sample.SampleID, nearMissAgentType)
			}
		}
		if sample.AgentType != "" {
			if _, ok := knownTypes[sample.AgentType]; !ok {
				return nil, fmt.Errorf("sample %q references unknown agent type %q", sample.SampleID, sample.AgentType)
			}
		}
		if sample.Expected.AgentType != "" {
			if _, ok := knownTypes[sample.Expected.AgentType]; !ok {
				return nil, fmt.Errorf("sample %q expects unknown agent type %q", sample.SampleID, sample.Expected.AgentType)
			}
		}
		result := AgentRecognitionSampleResult{
			SampleID:             sample.SampleID,
			SignalStratum:        sample.SignalStratum,
			EvaluationSet:        sample.EvaluationSet,
			GroundTruthAgentType: sample.AgentType,
		}
		if sample.SignalStratum == AgentRecognitionSignalStratumContentFingerprint {
			result, err = evaluateAgentRecognitionContentFingerprintSample(recognizer, fingerprintRegistry, sample)
			if err != nil {
				return nil, err
			}
			contentFingerprint.SampleCount++
			fixture, _ := agentRecognitionEvaluationFingerprintFixtureByID(sample.ContentFingerprint.FixtureID)
			if fixture.method == AgentFingerprintMethodSHA256KernelLauncher {
				contentFingerprint.LauncherSampleCount++
			} else {
				contentFingerprint.NativeSampleCount++
			}
			switch result.FingerprintOutcome {
			case AgentFingerprintOutcomeSuccess:
				contentFingerprint.MatchSampleCount++
			case AgentFingerprintOutcomeDigestMismatch:
				contentFingerprint.MismatchSampleCount++
				if result.ActualConfidence != AgentRecognitionConfidenceLow {
					contentFingerprint.MismatchPromotions++
				}
			}
			if result.ExpectationMatched {
				contentFingerprint.CorrectCount++
			} else {
				contentFingerprint.ExpectationMismatches = append(contentFingerprint.ExpectationMismatches, sample.SampleID)
			}
			if sample.Expected.FingerprintOutcome == AgentFingerprintOutcomeSuccess {
				contentMatchTypes[sample.AgentType] = struct{}{}
			} else if sample.Expected.FingerprintOutcome == AgentFingerprintOutcomeDigestMismatch {
				contentMismatchTargets[sample.Expected.AgentType] = struct{}{}
			}
			report.Samples = append(report.Samples, result)
			resultsByID[sample.SampleID] = result
			continue
		}

		nameOnly.SampleCount++
		for _, nearMissAgentType := range sample.NearMissFor {
			nearMisses[nearMissAgentType] = struct{}{}
		}
		if sample.EvaluationSet == AgentRecognitionEvaluationUnavailable {
			result.ActualStatus = AgentRecognitionEvaluationStatusUnavailable
			result.ExpectationMatched = sample.Expected.Status == result.ActualStatus
			result.ClassificationCorrect = true
			nameOnly.UnavailableCount++
			report.Samples = append(report.Samples, result)
			resultsByID[sample.SampleID] = result
			if !result.ExpectationMatched {
				nameOnly.ExpectationMismatches = append(nameOnly.ExpectationMismatches, sample.SampleID)
			}
			continue
		}

		classified := recognizer.Classify(sample.Input)
		result.ActualStatus = classified.Status
		result.ActualAgentType = classified.AgentType
		result.ActualConfidence = classified.Confidence
		result.ExpectationMatched = classified.Status == sample.Expected.Status && classified.AgentType == sample.Expected.AgentType
		nameOnly.EvaluatedCount++
		switch classified.Status {
		case AgentRecognitionStatusUnknown:
			nameOnly.UnknownCount++
		case AgentRecognitionStatusAmbiguous:
			nameOnly.AmbiguousCount++
		}
		if !result.ExpectationMatched {
			nameOnly.ExpectationMismatches = append(nameOnly.ExpectationMismatches, sample.SampleID)
		}

		actualClass := sample.AgentType
		if actualClass == "" {
			actualClass = "none"
		}
		predictedClass := "none"
		if classified.Status == AgentRecognitionStatusRecognized {
			predictedClass = classified.AgentType
		} else if classified.Status == AgentRecognitionStatusAmbiguous {
			predictedClass = "ambiguous"
		}
		if confusion[actualClass] == nil {
			confusion[actualClass] = make(map[string]int)
		}
		confusion[actualClass][predictedClass]++

		switch sample.EvaluationSet {
		case AgentRecognitionEvaluationSupportedPositive:
			supportedTotal++
			if supportedShapes[sample.AgentType] == nil {
				supportedShapes[sample.AgentType] = make(map[string]struct{})
			}
			supportedShapes[sample.AgentType][sample.InstallationShape] = struct{}{}
			result.ClassificationCorrect = classified.Status == AgentRecognitionStatusRecognized && classified.AgentType == sample.AgentType
			if result.ClassificationCorrect {
				supportedCorrect++
			} else {
				nameOnly.FalseNegativeSampleIDs = append(nameOnly.FalseNegativeSampleIDs, sample.SampleID)
			}
		case AgentRecognitionEvaluationKnownUnsupported:
			result.ClassificationCorrect = classified.Status == AgentRecognitionStatusRecognized && classified.AgentType == sample.AgentType
			if !result.ClassificationCorrect {
				nameOnly.FalseNegativeSampleIDs = append(nameOnly.FalseNegativeSampleIDs, sample.SampleID)
			}
		case AgentRecognitionEvaluationHardNegative:
			hardNegativeCount++
			result.ClassificationCorrect = classified.Status == AgentRecognitionStatusUnknown
			if result.ClassificationCorrect {
				hardNegativeCorrect++
			} else {
				hardNegativeFalsePositives++
				nameOnly.FalsePositiveSampleIDs = append(nameOnly.FalsePositiveSampleIDs, sample.SampleID)
			}
		case AgentRecognitionEvaluationConflict:
			result.ClassificationCorrect = classified.Status == AgentRecognitionStatusAmbiguous
		}
		report.Samples = append(report.Samples, result)
		resultsByID[sample.SampleID] = result
	}

	if nameOnly.EvaluatedCount+nameOnly.UnavailableCount != nameOnly.SampleCount || nameOnly.SampleCount+contentFingerprint.SampleCount != report.CorpusSampleCount || len(resultsByID) != report.CorpusSampleCount {
		return nil, fmt.Errorf("agent recognition evaluator skipped one or more corpus samples")
	}
	for actual, predictions := range confusion {
		for predicted, count := range predictions {
			nameOnly.ConfusionMatrix = append(nameOnly.ConfusionMatrix, AgentRecognitionConfusionCell{Actual: actual, Predicted: predicted, Count: count})
		}
	}
	sort.Slice(nameOnly.ConfusionMatrix, func(i, j int) bool {
		if nameOnly.ConfusionMatrix[i].Actual == nameOnly.ConfusionMatrix[j].Actual {
			return nameOnly.ConfusionMatrix[i].Predicted < nameOnly.ConfusionMatrix[j].Predicted
		}
		return nameOnly.ConfusionMatrix[i].Actual < nameOnly.ConfusionMatrix[j].Actual
	})

	var aggregateTP, aggregateFP, aggregateFN int
	for _, agentType := range agentTypes {
		metrics := AgentRecognitionClassMetrics{AgentType: agentType}
		for actual, predictions := range confusion {
			for predicted, count := range predictions {
				switch {
				case actual == agentType && predicted == agentType:
					metrics.TruePositive += count
				case actual != agentType && predicted == agentType:
					metrics.FalsePositive += count
				case actual == agentType && predicted != agentType:
					metrics.FalseNegative += count
				}
			}
		}
		metrics.Precision = agentRecognitionRatio(metrics.TruePositive, metrics.TruePositive+metrics.FalsePositive, thresholds.ConfidenceLevel)
		metrics.Recall = agentRecognitionRatio(metrics.TruePositive, metrics.TruePositive+metrics.FalseNegative, thresholds.ConfidenceLevel)
		nameOnly.PerClass = append(nameOnly.PerClass, metrics)
		aggregateTP += metrics.TruePositive
		aggregateFP += metrics.FalsePositive
		aggregateFN += metrics.FalseNegative
	}
	nameOnly.AggregatePrecision = agentRecognitionRatio(aggregateTP, aggregateTP+aggregateFP, thresholds.ConfidenceLevel)
	nameOnly.AggregateRecall = agentRecognitionRatio(aggregateTP, aggregateTP+aggregateFN, thresholds.ConfidenceLevel)
	nameOnly.SupportedRecall = agentRecognitionRatio(supportedCorrect, supportedTotal, thresholds.ConfidenceLevel)
	nameOnly.HardNegativeAccuracy = agentRecognitionRatio(hardNegativeCorrect, hardNegativeCount, thresholds.ConfidenceLevel)
	contentFingerprint.Accuracy = agentRecognitionRatio(contentFingerprint.CorrectCount, contentFingerprint.SampleCount, thresholds.ConfidenceLevel)

	report.Gate = AgentRecognitionGateResult{
		Passed:                             true,
		MinimumSupportedRecall:             thresholds.MinimumSupportedRecall,
		MaximumHardNegativeFalsePositives:  thresholds.MaximumHardNegativeFalsePositives,
		ObservedHardNegativeFalsePositives: hardNegativeFalsePositives,
		MinimumContentFingerprintAccuracy:  thresholds.MinimumContentFingerprintAccuracy,
		MaximumContentMismatchPromotions:   thresholds.MaximumContentMismatchPromotions,
		ObservedContentMismatchPromotions:  contentFingerprint.MismatchPromotions,
		Reasons:                            []string{},
	}
	if len(nameOnly.ExpectationMismatches) > 0 {
		report.Gate.Reasons = append(report.Gate.Reasons, "one or more samples did not match the reviewed regression expectation")
	}
	if nameOnly.SupportedRecall.Value == nil || *nameOnly.SupportedRecall.Value < thresholds.MinimumSupportedRecall {
		report.Gate.Reasons = append(report.Gate.Reasons, "supported-shape recall is below the maintained-corpus threshold")
	}
	if hardNegativeFalsePositives > thresholds.MaximumHardNegativeFalsePositives {
		report.Gate.Reasons = append(report.Gate.Reasons, "hard-negative false positives exceed the maintained-corpus threshold")
	}
	for _, agentType := range agentTypes {
		if len(supportedShapes[agentType]) < 2 {
			report.Gate.Reasons = append(report.Gate.Reasons, fmt.Sprintf("agent type %s has fewer than two supported installation shapes", agentType))
		}
		if _, ok := nearMisses[agentType]; !ok {
			report.Gate.Reasons = append(report.Gate.Reasons, fmt.Sprintf("agent type %s has no near-miss hard negative", agentType))
		}
		if _, ok := contentMatchTypes[agentType]; !ok {
			report.Gate.Reasons = append(report.Gate.Reasons, fmt.Sprintf("agent type %s has no content-fingerprint match sample", agentType))
		}
		if _, ok := contentMismatchTargets[agentType]; !ok {
			report.Gate.Reasons = append(report.Gate.Reasons, fmt.Sprintf("agent type %s has no content-fingerprint mismatch sample", agentType))
		}
	}
	if contentFingerprint.NativeSampleCount == 0 || contentFingerprint.LauncherSampleCount == 0 {
		report.Gate.Reasons = append(report.Gate.Reasons, "content-fingerprint stratum must cover native and kernel-bound launcher methods")
	}
	if len(contentFingerprint.ExpectationMismatches) > 0 {
		report.Gate.Reasons = append(report.Gate.Reasons, "one or more content-fingerprint samples did not match the reviewed transition expectation")
	}
	if contentFingerprint.Accuracy.Value == nil || *contentFingerprint.Accuracy.Value < thresholds.MinimumContentFingerprintAccuracy {
		report.Gate.Reasons = append(report.Gate.Reasons, "content-fingerprint transition accuracy is below the maintained-corpus threshold")
	}
	if contentFingerprint.MismatchPromotions > thresholds.MaximumContentMismatchPromotions {
		report.Gate.Reasons = append(report.Gate.Reasons, "content-fingerprint mismatches promoted candidate confidence")
	}
	report.Gate.Passed = len(report.Gate.Reasons) == 0
	sort.Strings(nameOnly.ExpectationMismatches)
	sort.Strings(nameOnly.FalsePositiveSampleIDs)
	sort.Strings(nameOnly.FalseNegativeSampleIDs)
	sort.Strings(contentFingerprint.ExpectationMismatches)
	sort.Strings(report.Gate.Reasons)
	return report, nil
}

func evaluateAgentRecognitionContentFingerprintSample(recognizer *AgentRecognizer, registry *AgentFingerprintRegistry, sample AgentRecognitionSample) (AgentRecognitionSampleResult, error) {
	result := AgentRecognitionSampleResult{
		SampleID:             sample.SampleID,
		SignalStratum:        sample.SignalStratum,
		EvaluationSet:        sample.EvaluationSet,
		GroundTruthAgentType: sample.AgentType,
	}
	fixture, ok := agentRecognitionEvaluationFingerprintFixtureByID(sample.ContentFingerprint.FixtureID)
	if !ok {
		return result, fmt.Errorf("sample %q references unknown content-fingerprint fixture", sample.SampleID)
	}
	classified := recognizer.Classify(sample.Input)
	result.ActualStatus = classified.Status
	result.ActualAgentType = classified.AgentType
	result.ActualConfidence = classified.Confidence
	result.FingerprintOutcome = AgentRecognitionContentOutcomeNotAttempted
	if classified.Status == AgentRecognitionStatusRecognized {
		var matched []string
		outcome := AgentFingerprintOutcomeDigestMismatch
		if fixture.method == AgentFingerprintMethodSHA256KernelLauncher {
			if registry.allowsLauncherInterpreter(classified.AgentType, sample.ContentFingerprint.ObservedInterpreter) {
				matched = registry.matchLauncher(classified.AgentType, fixture.digest, sample.ContentFingerprint.ObservedInterpreter)
			} else {
				outcome = AgentFingerprintOutcomeInterpreterDenied
			}
		} else {
			matched = registry.matchNative(classified.AgentType, fixture.digest)
		}
		if len(matched) > 0 {
			outcome = AgentFingerprintOutcomeSuccess
		}
		observation := agentFingerprintObservation(registry, classified, outcome, fixture.method, AgentFingerprintObjectLinked, matched)
		result.ActualConfidence = observation.Confidence
		result.FingerprintOutcome = observation.Outcome
	}
	result.ExpectationMatched = result.ActualStatus == sample.Expected.Status &&
		result.ActualAgentType == sample.Expected.AgentType &&
		result.ActualConfidence == sample.Expected.Confidence &&
		result.FingerprintOutcome == sample.Expected.FingerprintOutcome
	result.ClassificationCorrect = result.ExpectationMatched
	return result, nil
}

func MarshalAgentRecognitionEvaluationReport(report *AgentRecognitionEvaluationReport) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("agent recognition evaluation report is required")
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal agent recognition evaluation report: %w", err)
	}
	return append(encoded, '\n'), nil
}

func canonicalAgentRecognitionCorpus(corpus AgentRecognitionCorpus) (AgentRecognitionCorpus, error) {
	if corpus.SchemaVersion != AgentRecognitionCorpusSchema {
		return AgentRecognitionCorpus{}, fmt.Errorf("agent recognition corpus schema must be %q", AgentRecognitionCorpusSchema)
	}
	if !agentRecognitionIdentifier.MatchString(corpus.CorpusVersion) {
		return AgentRecognitionCorpus{}, fmt.Errorf("agent recognition corpus version is invalid")
	}
	if len(corpus.Samples) == 0 || len(corpus.Samples) > maxAgentRecognitionCorpusSamples {
		return AgentRecognitionCorpus{}, fmt.Errorf("agent recognition corpus must contain 1..%d samples", maxAgentRecognitionCorpusSamples)
	}
	canonical := AgentRecognitionCorpus{SchemaVersion: corpus.SchemaVersion, CorpusVersion: corpus.CorpusVersion, Samples: make([]AgentRecognitionSample, len(corpus.Samples))}
	seen := make(map[string]struct{}, len(corpus.Samples))
	for index, sample := range corpus.Samples {
		if err := validateAgentRecognitionSample(sample); err != nil {
			return AgentRecognitionCorpus{}, fmt.Errorf("agent recognition sample %d: %w", index, err)
		}
		if _, duplicate := seen[sample.SampleID]; duplicate {
			return AgentRecognitionCorpus{}, fmt.Errorf("agent recognition sample id %q is duplicated", sample.SampleID)
		}
		seen[sample.SampleID] = struct{}{}
		sample.NearMissFor = append([]string(nil), sample.NearMissFor...)
		if sample.ContentFingerprint != nil {
			contentFingerprint := *sample.ContentFingerprint
			sample.ContentFingerprint = &contentFingerprint
		}
		sort.Strings(sample.NearMissFor)
		canonical.Samples[index] = sample
	}
	sort.Slice(canonical.Samples, func(i, j int) bool { return canonical.Samples[i].SampleID < canonical.Samples[j].SampleID })
	return canonical, nil
}

func validateAgentRecognitionSample(sample AgentRecognitionSample) error {
	if !agentRecognitionIdentifier.MatchString(sample.SampleID) || !agentRecognitionIdentifier.MatchString(sample.InstallationShape) {
		return fmt.Errorf("sample id or installation shape is invalid")
	}
	if sample.AgentType != "" && !agentRecognitionIdentifier.MatchString(sample.AgentType) {
		return fmt.Errorf("agent type is invalid")
	}
	if sample.Expected.AgentType != "" && !agentRecognitionIdentifier.MatchString(sample.Expected.AgentType) {
		return fmt.Errorf("expected agent type is invalid")
	}
	validSet := map[string]bool{
		AgentRecognitionEvaluationSupportedPositive: true,
		AgentRecognitionEvaluationKnownUnsupported:  true,
		AgentRecognitionEvaluationHardNegative:      true,
		AgentRecognitionEvaluationConflict:          true,
		AgentRecognitionEvaluationUnavailable:       true,
	}
	if !validSet[sample.EvaluationSet] {
		return fmt.Errorf("evaluation set %q is unsupported", sample.EvaluationSet)
	}
	if sample.Platform != "linux" {
		return fmt.Errorf("only Linux recognition samples are supported")
	}
	if sample.SignalStratum != AgentRecognitionSignalStratumNameOnly && sample.SignalStratum != AgentRecognitionSignalStratumContentFingerprint {
		return fmt.Errorf("signal stratum %q is unsupported", sample.SignalStratum)
	}
	if !sample.Signals.CommAvailable && sample.Input.Comm != "" {
		return fmt.Errorf("comm input is present while its signal is unavailable")
	}
	if !sample.Signals.ExecutableBasenameAvailable && sample.Input.ExecutableBasename != "" {
		return fmt.Errorf("executable basename is present while its signal is unavailable")
	}
	fingerprintInputPresent := sample.ContentFingerprint != nil && sample.ContentFingerprint.FixtureID != ""
	if sample.Signals.ContentFingerprintAvailable != fingerprintInputPresent {
		return fmt.Errorf("content-fingerprint input and availability must agree")
	}
	validStatus := map[string]bool{
		AgentRecognitionStatusRecognized:            true,
		AgentRecognitionStatusUnknown:               true,
		AgentRecognitionStatusAmbiguous:             true,
		AgentRecognitionEvaluationStatusUnavailable: true,
	}
	if !validStatus[sample.Expected.Status] {
		return fmt.Errorf("expected status %q is unsupported", sample.Expected.Status)
	}
	if (sample.Expected.Status == AgentRecognitionStatusRecognized) != (sample.Expected.AgentType != "") {
		return fmt.Errorf("only recognized expectations may name an agent type")
	}
	if sample.SignalStratum == AgentRecognitionSignalStratumNameOnly {
		if sample.Signals.ContentFingerprintAvailable || sample.ContentFingerprint != nil {
			return fmt.Errorf("name-only sample cannot contain a content fingerprint")
		}
		positive := sample.EvaluationSet == AgentRecognitionEvaluationSupportedPositive || sample.EvaluationSet == AgentRecognitionEvaluationKnownUnsupported
		if positive != (sample.AgentType != "") {
			return fmt.Errorf("positive evaluation sets require one agent type and negative/conflict sets forbid it")
		}
		noNameSignals := !sample.Signals.CommAvailable && !sample.Signals.ExecutableBasenameAvailable
		if noNameSignals != (sample.EvaluationSet == AgentRecognitionEvaluationUnavailable) {
			return fmt.Errorf("unavailable samples must have no signals and all other samples require a signal")
		}
		if sample.Expected.Confidence != "" || sample.Expected.FingerprintOutcome != "" {
			return fmt.Errorf("name-only expectation cannot contain content-fingerprint fields")
		}
		if sample.EvaluationSet == AgentRecognitionEvaluationUnavailable && sample.Expected.Status != AgentRecognitionEvaluationStatusUnavailable {
			return fmt.Errorf("unavailable sample must expect unavailable status")
		}
		if sample.EvaluationSet == AgentRecognitionEvaluationSupportedPositive && (sample.Expected.Status != AgentRecognitionStatusRecognized || sample.Expected.AgentType != sample.AgentType) {
			return fmt.Errorf("supported positive must expect its ground-truth agent type to be recognized")
		}
		if sample.EvaluationSet == AgentRecognitionEvaluationKnownUnsupported && sample.Expected.Status == AgentRecognitionStatusRecognized && sample.Expected.AgentType != sample.AgentType {
			return fmt.Errorf("recognized known-unsupported expectation must match its ground-truth agent type")
		}
		if sample.EvaluationSet == AgentRecognitionEvaluationHardNegative && sample.Expected.Status != AgentRecognitionStatusUnknown {
			return fmt.Errorf("hard negative must expect unknown status")
		}
		if sample.EvaluationSet == AgentRecognitionEvaluationConflict && sample.Expected.Status != AgentRecognitionStatusAmbiguous {
			return fmt.Errorf("conflict sample must expect ambiguous status")
		}
	} else {
		if !sample.Signals.ContentFingerprintAvailable || sample.ContentFingerprint == nil {
			return fmt.Errorf("content-fingerprint sample requires a fixture")
		}
		if !sample.Signals.CommAvailable && !sample.Signals.ExecutableBasenameAvailable {
			return fmt.Errorf("content-fingerprint sample requires a bounded name candidate")
		}
		fixture, ok := agentRecognitionEvaluationFingerprintFixtureByID(sample.ContentFingerprint.FixtureID)
		if !ok {
			return fmt.Errorf("content-fingerprint fixture is unknown")
		}
		if fixture.method == AgentFingerprintMethodSHA256KernelLauncher {
			interpreter, ok := normalizeAgentExecutableBasename(sample.ContentFingerprint.ObservedInterpreter)
			if !ok || interpreter != sample.ContentFingerprint.ObservedInterpreter {
				return fmt.Errorf("launcher content-fingerprint sample requires a canonical observed interpreter")
			}
		} else if sample.ContentFingerprint.ObservedInterpreter != "" {
			return fmt.Errorf("native content-fingerprint sample cannot contain an observed interpreter")
		}
		if sample.EvaluationSet != AgentRecognitionEvaluationSupportedPositive && sample.EvaluationSet != AgentRecognitionEvaluationHardNegative {
			return fmt.Errorf("content-fingerprint samples support only matched positives and mismatch hard negatives")
		}
		if sample.Expected.Status != AgentRecognitionStatusRecognized {
			return fmt.Errorf("content-fingerprint sample must begin with a recognized name candidate")
		}
		if sample.EvaluationSet == AgentRecognitionEvaluationSupportedPositive {
			if sample.AgentType == "" || sample.Expected.AgentType != sample.AgentType || fixture.agentType != sample.AgentType {
				return fmt.Errorf("content-fingerprint positive must match its ground-truth class")
			}
			if sample.Expected.Confidence != AgentRecognitionConfidenceMedium || sample.Expected.FingerprintOutcome != AgentFingerprintOutcomeSuccess {
				return fmt.Errorf("content-fingerprint positive must expect a medium-confidence match")
			}
		} else {
			if sample.AgentType != "" || fixture.agentType == sample.Expected.AgentType {
				return fmt.Errorf("content-fingerprint mismatch must use another class fixture without ground truth")
			}
			if sample.Expected.Confidence != AgentRecognitionConfidenceLow || sample.Expected.FingerprintOutcome != AgentFingerprintOutcomeDigestMismatch {
				return fmt.Errorf("content-fingerprint mismatch must remain low confidence")
			}
		}
	}
	if sample.EvaluationSet != AgentRecognitionEvaluationHardNegative && len(sample.NearMissFor) > 0 {
		return fmt.Errorf("near-miss classes are allowed only on hard negatives")
	}
	seenNearMiss := make(map[string]struct{}, len(sample.NearMissFor))
	for _, agentType := range sample.NearMissFor {
		if !agentRecognitionIdentifier.MatchString(agentType) {
			return fmt.Errorf("near-miss agent type is invalid")
		}
		if _, duplicate := seenNearMiss[agentType]; duplicate {
			return fmt.Errorf("near-miss agent type %q is duplicated", agentType)
		}
		seenNearMiss[agentType] = struct{}{}
	}
	if err := validateAgentRecognitionProvenance(sample.Provenance); err != nil {
		return err
	}
	return nil
}

func validateAgentRecognitionProvenance(provenance AgentRecognitionProvenance) error {
	validKind := map[string]bool{"project_fixture": true, "public_install_shape": true, "adversarial_synthetic": true}
	if !validKind[provenance.SourceKind] || !provenance.Sanitized {
		return fmt.Errorf("provenance must have a supported source kind and sanitized=true")
	}
	reference := strings.TrimSpace(provenance.Reference)
	if reference == "" || len(reference) > maxAgentRecognitionProvenanceBytes || strings.Contains(reference, "\\") || strings.HasPrefix(reference, "/") || strings.Contains(reference, "../") {
		return fmt.Errorf("provenance reference is missing or unsafe")
	}
	if _, err := time.Parse("2006-01-02", provenance.ReviewedAt); err != nil {
		return fmt.Errorf("provenance reviewed_at must be YYYY-MM-DD")
	}
	return nil
}

func decodeBoundedAgentRecognitionJSON(r io.Reader, limit int64, target any) error {
	if r == nil {
		return fmt.Errorf("reader is required")
	}
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > limit {
		return fmt.Errorf("document exceeds %d bytes", limit)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return fmt.Errorf("trailing data: %w", err)
	}
	return nil
}

func agentRecognitionRatio(numerator, denominator int, confidenceLevel float64) AgentRecognitionRatio {
	ratio := AgentRecognitionRatio{Numerator: numerator, Denominator: denominator}
	if denominator == 0 {
		return ratio
	}
	value := float64(numerator) / float64(denominator)
	ratio.Value = &value
	lower, upper := agentRecognitionWilsonInterval(numerator, denominator)
	ratio.Wilson = &AgentRecognitionConfidenceInterval{
		Method:          AgentRecognitionWilsonMethod,
		ConfidenceLevel: confidenceLevel,
		Lower:           lower,
		Upper:           upper,
	}
	return ratio
}

func agentRecognitionWilsonInterval(successes, trials int) (float64, float64) {
	if trials <= 0 {
		return 0, 0
	}
	const z = 1.959963984540054
	n := float64(trials)
	p := float64(successes) / n
	zSquared := z * z
	denominator := 1 + zSquared/n
	center := (p + zSquared/(2*n)) / denominator
	margin := z * math.Sqrt((p*(1-p)+zSquared/(4*n))/n) / denominator
	return math.Max(0, center-margin), math.Min(1, center+margin)
}
