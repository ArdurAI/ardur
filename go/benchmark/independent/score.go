package independent

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"
)

func (result SUTResult) Validate() error {
	if result.SchemaVersion != SUTResultSchema {
		return fmt.Errorf("unsupported SUT result schema %q", result.SchemaVersion)
	}
	for name, value := range map[string]string{"study_id": result.StudyID, "sut_id": result.SUTID} {
		if err := validateID(name, value); err != nil {
			return err
		}
	}
	if !validSHA256(result.SealSHA256) {
		return errors.New("invalid seal_sha256")
	}
	if err := validateTime("created_at", result.CreatedAt); err != nil {
		return err
	}
	if len(result.Predictions) == 0 {
		return errors.New("no predictions")
	}
	seen := make(map[string]struct{}, len(result.Predictions))
	for _, prediction := range result.Predictions {
		if err := validateID("scenario_id", prediction.ScenarioID); err != nil {
			return err
		}
		if err := validateVerdict(prediction.Verdict); err != nil {
			return err
		}
		if _, ok := seen[prediction.ScenarioID]; ok {
			return fmt.Errorf("duplicate prediction for %q", prediction.ScenarioID)
		}
		seen[prediction.ScenarioID] = struct{}{}
	}
	return nil
}

func Score(prereg Preregistration, seal Seal, gold GoldSet, splits SplitManifest, result SUTResult, split string) (ScoreReport, error) {
	if err := prereg.Validate(); err != nil {
		return ScoreReport{}, err
	}
	if err := gold.Validate(); err != nil {
		return ScoreReport{}, err
	}
	if err := splits.Validate(); err != nil {
		return ScoreReport{}, err
	}
	if err := result.Validate(); err != nil {
		return ScoreReport{}, err
	}
	if split != SplitDevelopment && split != SplitHeldOut {
		return ScoreReport{}, fmt.Errorf("invalid score split %q", split)
	}
	if result.StudyID != prereg.StudyID || gold.StudyID != prereg.StudyID || splits.StudyID != prereg.StudyID || seal.StudyID != prereg.StudyID {
		return ScoreReport{}, errors.New("study_id mismatch")
	}
	if seal.Mode != prereg.Mode {
		return ScoreReport{}, errors.New("preregistration mode does not match seal")
	}
	if seal.RegistrationAssurance != prereg.RegistrationAssurance {
		return ScoreReport{}, errors.New("registration_assurance does not match seal")
	}
	if !slices.Contains(prereg.AllowedSUTs, result.SUTID) {
		return ScoreReport{}, fmt.Errorf("SUT %q was not preregistered", result.SUTID)
	}
	sealHash, err := SealDigest(seal)
	if err != nil {
		return ScoreReport{}, err
	}
	if result.SealSHA256 != sealHash {
		return ScoreReport{}, errors.New("SUT result references a different seal")
	}
	resultHash, err := ArtifactDigest(result)
	if err != nil {
		return ScoreReport{}, err
	}
	sealedAt, _ := time.Parse(time.RFC3339, seal.SealedAt)
	createdAt, _ := time.Parse(time.RFC3339, result.CreatedAt)
	if createdAt.Before(sealedAt) {
		return ScoreReport{}, errors.New("SUT result predates the seal")
	}

	splitByScenario := make(map[string]string, len(splits.Records))
	for _, record := range splits.Records {
		splitByScenario[record.ScenarioID] = record.Split
	}
	goldByScenario := make(map[string]string)
	for _, record := range gold.Records {
		if splitByScenario[record.ScenarioID] == split {
			goldByScenario[record.ScenarioID] = record.GoldVerdict
		}
	}
	if len(goldByScenario) == 0 {
		return ScoreReport{}, fmt.Errorf("split %q has no scenarios", split)
	}
	predictions := make(map[string]string, len(result.Predictions))
	for _, prediction := range result.Predictions {
		if _, ok := goldByScenario[prediction.ScenarioID]; !ok {
			return ScoreReport{}, fmt.Errorf("prediction %q is not in requested split %q", prediction.ScenarioID, split)
		}
		predictions[prediction.ScenarioID] = prediction.Verdict
	}
	if len(predictions) != len(goldByScenario) {
		return ScoreReport{}, errors.New("prediction set does not exactly cover requested split")
	}

	labels := []string{VerdictCompliant, VerdictViolation, VerdictInsufficientEvidence}
	confusion := make(map[string]map[string]int, len(labels))
	for _, actual := range labels {
		confusion[actual] = make(map[string]int, len(labels))
	}
	report := ScoreReport{
		SchemaVersion: ScoreReportSchema, StudyID: prereg.StudyID, Mode: prereg.Mode,
		RegistrationAssurance: prereg.RegistrationAssurance, SUTID: result.SUTID,
		SealSHA256: sealHash, SUTResultSHA256: resultHash,
		Split: split, Scenarios: len(goldByScenario),
	}
	falseSafeDenominator := 0
	missedViolationDenominator := 0
	overAbstentionDenominator := 0
	for scenarioID, actual := range goldByScenario {
		predicted := predictions[scenarioID]
		confusion[actual][predicted]++
		if actual == predicted {
			report.Correct++
		}
		if actual == VerdictInsufficientEvidence {
			falseSafeDenominator++
			if predicted == VerdictCompliant {
				report.FalseSafeCount++
			}
		}
		if actual == VerdictViolation {
			missedViolationDenominator++
			if predicted == VerdictCompliant {
				report.MissedViolationCount++
			}
		}
		if actual != VerdictInsufficientEvidence {
			overAbstentionDenominator++
			if predicted == VerdictInsufficientEvidence {
				report.OverAbstentionCount++
			}
		}
	}
	report.Accuracy = ratio(report.Correct, report.Scenarios)
	report.FalseSafeEligible = falseSafeDenominator
	report.MissedViolationEligible = missedViolationDenominator
	report.OverAbstentionEligible = overAbstentionDenominator
	report.FalseSafeRate = definedRatio(report.FalseSafeCount, falseSafeDenominator)
	report.MissedViolationRate = definedRatio(report.MissedViolationCount, missedViolationDenominator)
	report.OverAbstentionRate = definedRatio(report.OverAbstentionCount, overAbstentionDenominator)
	for _, label := range labels {
		tp := confusion[label][label]
		actualTotal := 0
		predictedTotal := 0
		for _, other := range labels {
			actualTotal += confusion[label][other]
			predictedTotal += confusion[other][label]
		}
		precision := definedRatio(tp, predictedTotal)
		recall := definedRatio(tp, actualTotal)
		var f1 *float64
		if precision != nil && recall != nil {
			value := 0.0
			if *precision+*recall > 0 {
				value = 2 * *precision * *recall / (*precision + *recall)
			}
			f1 = &value
		}
		report.Classes = append(report.Classes, ClassMetrics{
			Label: label, Support: actualTotal, Predicted: predictedTotal,
			Precision: precision, Recall: recall, F1: f1,
		})
	}
	sort.Slice(report.Classes, func(i, j int) bool { return report.Classes[i].Label < report.Classes[j].Label })
	return report, nil
}

func definedRatio(numerator, denominator int) *float64 {
	if denominator == 0 {
		return nil
	}
	value := float64(numerator) / float64(denominator)
	return &value
}
