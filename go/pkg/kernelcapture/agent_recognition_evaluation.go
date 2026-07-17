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
	AgentRecognitionCorpusSchema          = "ardur.agent_recognition_corpus.v0.1"
	AgentRecognitionThresholdsSchema      = "ardur.agent_recognition_thresholds.v0.1"
	AgentRecognitionEvaluationSchema      = "ardur.agent_recognition_evaluation.v0.1"
	AgentRecognitionSignalStratumNameOnly = "name_only"

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
	SampleID          string                      `json:"sample_id"`
	EvaluationSet     string                      `json:"evaluation_set"`
	AgentType         string                      `json:"agent_type,omitempty"`
	InstallationShape string                      `json:"installation_shape"`
	Platform          string                      `json:"platform"`
	SignalStratum     string                      `json:"signal_stratum"`
	Signals           AgentRecognitionSignals     `json:"signals"`
	Input             AgentRecognitionInput       `json:"input"`
	Expected          AgentRecognitionExpectation `json:"expected"`
	NearMissFor       []string                    `json:"near_miss_for,omitempty"`
	Provenance        AgentRecognitionProvenance  `json:"provenance"`
}

type AgentRecognitionSignals struct {
	CommAvailable               bool `json:"comm_available"`
	ExecutableBasenameAvailable bool `json:"executable_basename_available"`
}

type AgentRecognitionExpectation struct {
	Status    string `json:"status"`
	AgentType string `json:"agent_type,omitempty"`
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
	ConfidenceLevel                   float64 `json:"confidence_level"`
	ConfidenceIntervalMethod          string  `json:"confidence_interval_method"`
}

type AgentRecognitionEvaluationReport struct {
	SchemaVersion          string                          `json:"schema_version"`
	CorpusVersion          string                          `json:"corpus_version"`
	CorpusSHA256           string                          `json:"corpus_sha256"`
	RegistryVersion        string                          `json:"registry_version"`
	RegistrySHA256         string                          `json:"registry_sha256"`
	ThresholdVersion       string                          `json:"threshold_version"`
	SignalStrata           []string                        `json:"signal_strata"`
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
	Samples                []AgentRecognitionSampleResult  `json:"samples"`
	Gate                   AgentRecognitionGateResult      `json:"gate"`
	ClaimBoundary          string                          `json:"claim_boundary"`
}

type AgentRecognitionSampleResult struct {
	SampleID              string `json:"sample_id"`
	EvaluationSet         string `json:"evaluation_set"`
	GroundTruthAgentType  string `json:"ground_truth_agent_type,omitempty"`
	ActualStatus          string `json:"actual_status"`
	ActualAgentType       string `json:"actual_agent_type,omitempty"`
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
	Reasons                            []string `json:"reasons"`
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

	report := &AgentRecognitionEvaluationReport{
		SchemaVersion:          AgentRecognitionEvaluationSchema,
		CorpusVersion:          corpus.CorpusVersion,
		CorpusSHA256:           corpusSHA256,
		RegistryVersion:        registryVersion,
		RegistrySHA256:         registrySHA256,
		ThresholdVersion:       thresholds.ThresholdVersion,
		SignalStrata:           []string{AgentRecognitionSignalStratumNameOnly},
		SampleCount:            len(corpus.Samples),
		ExpectationMismatches:  []string{},
		FalsePositiveSampleIDs: []string{},
		FalseNegativeSampleIDs: []string{},
		ConfusionMatrix:        []AgentRecognitionConfusionCell{},
		PerClass:               []AgentRecognitionClassMetrics{},
		Samples:                []AgentRecognitionSampleResult{},
		ClaimBoundary:          "maintained_corpus_only_not_population_accuracy_or_identity_assurance",
	}
	confusion := make(map[string]map[string]int)
	resultsByID := make(map[string]AgentRecognitionSampleResult, len(corpus.Samples))
	supportedShapes := make(map[string]map[string]struct{}, len(agentTypes))
	nearMisses := make(map[string]struct{}, len(agentTypes))
	hardNegativeCount := 0
	hardNegativeCorrect := 0
	hardNegativeFalsePositives := 0
	supportedCorrect := 0
	supportedTotal := 0

	for _, sample := range corpus.Samples {
		for _, agentType := range sample.NearMissFor {
			if _, ok := knownTypes[agentType]; !ok {
				return nil, fmt.Errorf("sample %q references unknown near-miss agent type %q", sample.SampleID, agentType)
			}
			nearMisses[agentType] = struct{}{}
		}
		if sample.AgentType != "" {
			if _, ok := knownTypes[sample.AgentType]; !ok {
				return nil, fmt.Errorf("sample %q references unknown agent type %q", sample.SampleID, sample.AgentType)
			}
		}
		result := AgentRecognitionSampleResult{
			SampleID:             sample.SampleID,
			EvaluationSet:        sample.EvaluationSet,
			GroundTruthAgentType: sample.AgentType,
		}
		if sample.EvaluationSet == AgentRecognitionEvaluationUnavailable {
			result.ActualStatus = AgentRecognitionEvaluationStatusUnavailable
			result.ExpectationMatched = sample.Expected.Status == result.ActualStatus
			result.ClassificationCorrect = true
			report.UnavailableCount++
			report.Samples = append(report.Samples, result)
			resultsByID[sample.SampleID] = result
			if !result.ExpectationMatched {
				report.ExpectationMismatches = append(report.ExpectationMismatches, sample.SampleID)
			}
			continue
		}

		classified := recognizer.Classify(sample.Input)
		result.ActualStatus = classified.Status
		result.ActualAgentType = classified.AgentType
		result.ExpectationMatched = classified.Status == sample.Expected.Status && classified.AgentType == sample.Expected.AgentType
		report.EvaluatedCount++
		switch classified.Status {
		case AgentRecognitionStatusUnknown:
			report.UnknownCount++
		case AgentRecognitionStatusAmbiguous:
			report.AmbiguousCount++
		}
		if !result.ExpectationMatched {
			report.ExpectationMismatches = append(report.ExpectationMismatches, sample.SampleID)
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
				report.FalseNegativeSampleIDs = append(report.FalseNegativeSampleIDs, sample.SampleID)
			}
		case AgentRecognitionEvaluationKnownUnsupported:
			result.ClassificationCorrect = classified.Status == AgentRecognitionStatusRecognized && classified.AgentType == sample.AgentType
			if !result.ClassificationCorrect {
				report.FalseNegativeSampleIDs = append(report.FalseNegativeSampleIDs, sample.SampleID)
			}
		case AgentRecognitionEvaluationHardNegative:
			hardNegativeCount++
			result.ClassificationCorrect = classified.Status == AgentRecognitionStatusUnknown
			if result.ClassificationCorrect {
				hardNegativeCorrect++
			} else {
				hardNegativeFalsePositives++
				report.FalsePositiveSampleIDs = append(report.FalsePositiveSampleIDs, sample.SampleID)
			}
		case AgentRecognitionEvaluationConflict:
			result.ClassificationCorrect = classified.Status == AgentRecognitionStatusAmbiguous
		}
		report.Samples = append(report.Samples, result)
		resultsByID[sample.SampleID] = result
	}

	if report.EvaluatedCount+report.UnavailableCount != report.SampleCount || len(resultsByID) != report.SampleCount {
		return nil, fmt.Errorf("agent recognition evaluator skipped one or more corpus samples")
	}
	for actual, predictions := range confusion {
		for predicted, count := range predictions {
			report.ConfusionMatrix = append(report.ConfusionMatrix, AgentRecognitionConfusionCell{Actual: actual, Predicted: predicted, Count: count})
		}
	}
	sort.Slice(report.ConfusionMatrix, func(i, j int) bool {
		if report.ConfusionMatrix[i].Actual == report.ConfusionMatrix[j].Actual {
			return report.ConfusionMatrix[i].Predicted < report.ConfusionMatrix[j].Predicted
		}
		return report.ConfusionMatrix[i].Actual < report.ConfusionMatrix[j].Actual
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
		report.PerClass = append(report.PerClass, metrics)
		aggregateTP += metrics.TruePositive
		aggregateFP += metrics.FalsePositive
		aggregateFN += metrics.FalseNegative
	}
	report.AggregatePrecision = agentRecognitionRatio(aggregateTP, aggregateTP+aggregateFP, thresholds.ConfidenceLevel)
	report.AggregateRecall = agentRecognitionRatio(aggregateTP, aggregateTP+aggregateFN, thresholds.ConfidenceLevel)
	report.SupportedRecall = agentRecognitionRatio(supportedCorrect, supportedTotal, thresholds.ConfidenceLevel)
	report.HardNegativeAccuracy = agentRecognitionRatio(hardNegativeCorrect, hardNegativeCount, thresholds.ConfidenceLevel)

	report.Gate = AgentRecognitionGateResult{
		Passed:                             true,
		MinimumSupportedRecall:             thresholds.MinimumSupportedRecall,
		MaximumHardNegativeFalsePositives:  thresholds.MaximumHardNegativeFalsePositives,
		ObservedHardNegativeFalsePositives: hardNegativeFalsePositives,
		Reasons:                            []string{},
	}
	if len(report.ExpectationMismatches) > 0 {
		report.Gate.Reasons = append(report.Gate.Reasons, "one or more samples did not match the reviewed regression expectation")
	}
	if report.SupportedRecall.Value == nil || *report.SupportedRecall.Value < thresholds.MinimumSupportedRecall {
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
	}
	report.Gate.Passed = len(report.Gate.Reasons) == 0
	sort.Strings(report.ExpectationMismatches)
	sort.Strings(report.FalsePositiveSampleIDs)
	sort.Strings(report.FalseNegativeSampleIDs)
	sort.Strings(report.Gate.Reasons)
	return report, nil
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
	positive := sample.EvaluationSet == AgentRecognitionEvaluationSupportedPositive || sample.EvaluationSet == AgentRecognitionEvaluationKnownUnsupported
	if positive != (sample.AgentType != "") {
		return fmt.Errorf("positive evaluation sets require one agent type and negative/conflict sets forbid it")
	}
	if sample.Platform != "linux" || sample.SignalStratum != AgentRecognitionSignalStratumNameOnly {
		return fmt.Errorf("only the Linux name-only signal stratum is supported")
	}
	if !sample.Signals.CommAvailable && sample.Input.Comm != "" {
		return fmt.Errorf("comm input is present while its signal is unavailable")
	}
	if !sample.Signals.ExecutableBasenameAvailable && sample.Input.ExecutableBasename != "" {
		return fmt.Errorf("executable basename is present while its signal is unavailable")
	}
	noSignals := !sample.Signals.CommAvailable && !sample.Signals.ExecutableBasenameAvailable
	if noSignals != (sample.EvaluationSet == AgentRecognitionEvaluationUnavailable) {
		return fmt.Errorf("unavailable samples must have no signals and all other samples require a signal")
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
