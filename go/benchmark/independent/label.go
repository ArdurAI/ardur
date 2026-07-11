package independent

import (
	"errors"
	"fmt"
	"math"
	"sort"
)

type labelKey struct {
	scenario string
	view     string
}

func Adjudicate(studyID string, minimumAnnotators int, annotations []Annotation, decisions []Adjudication) (GoldSet, error) {
	if err := validateID("study_id", studyID); err != nil {
		return GoldSet{}, err
	}
	if minimumAnnotators < 2 {
		return GoldSet{}, errors.New("minimum annotators must be at least 2")
	}
	if len(annotations) == 0 {
		return GoldSet{}, errors.New("no annotations")
	}

	annotations = append([]Annotation(nil), annotations...)
	sort.Slice(annotations, func(i, j int) bool {
		if annotations[i].ScenarioID != annotations[j].ScenarioID {
			return annotations[i].ScenarioID < annotations[j].ScenarioID
		}
		if annotations[i].View != annotations[j].View {
			return annotations[i].View < annotations[j].View
		}
		return annotations[i].AnnotatorID < annotations[j].AnnotatorID
	})
	groups := make(map[labelKey][]Annotation)
	scenarioAnnotators := make(map[string]map[string]string)
	seenAnnotation := make(map[string]struct{})
	for _, annotation := range annotations {
		if err := annotation.Validate(); err != nil {
			return GoldSet{}, err
		}
		if annotation.StudyID != studyID {
			return GoldSet{}, fmt.Errorf("annotation study %q does not match %q", annotation.StudyID, studyID)
		}
		identity := annotation.ScenarioID + "\x00" + annotation.View + "\x00" + annotation.AnnotatorID
		if _, ok := seenAnnotation[identity]; ok {
			return GoldSet{}, fmt.Errorf("duplicate annotation from %q for %s/%s", annotation.AnnotatorID, annotation.ScenarioID, annotation.View)
		}
		seenAnnotation[identity] = struct{}{}
		if scenarioAnnotators[annotation.ScenarioID] == nil {
			scenarioAnnotators[annotation.ScenarioID] = make(map[string]string)
		}
		if otherView, ok := scenarioAnnotators[annotation.ScenarioID][annotation.AnnotatorID]; ok && otherView != annotation.View {
			return GoldSet{}, fmt.Errorf("annotator %q saw both blind views for scenario %q", annotation.AnnotatorID, annotation.ScenarioID)
		}
		scenarioAnnotators[annotation.ScenarioID][annotation.AnnotatorID] = annotation.View
		key := labelKey{scenario: annotation.ScenarioID, view: annotation.View}
		groups[key] = append(groups[key], annotation)
	}

	decisionByKey := make(map[labelKey]Adjudication)
	for _, decision := range decisions {
		if err := decision.Validate(); err != nil {
			return GoldSet{}, err
		}
		if decision.StudyID != studyID {
			return GoldSet{}, fmt.Errorf("adjudication study %q does not match %q", decision.StudyID, studyID)
		}
		key := labelKey{scenario: decision.ScenarioID, view: decision.View}
		if _, ok := decisionByKey[key]; ok {
			return GoldSet{}, fmt.Errorf("duplicate adjudication for %s/%s", decision.ScenarioID, decision.View)
		}
		if _, ok := scenarioAnnotators[decision.ScenarioID][decision.AdjudicatorID]; ok {
			return GoldSet{}, fmt.Errorf("adjudicator %q also annotated scenario %q", decision.AdjudicatorID, decision.ScenarioID)
		}
		decisionByKey[key] = decision
	}

	scenarios := make(map[string]struct{})
	for key, group := range groups {
		scenarios[key.scenario] = struct{}{}
		if len(group) < minimumAnnotators {
			return GoldSet{}, fmt.Errorf("%s/%s has %d annotators, need %d", key.scenario, key.view, len(group), minimumAnnotators)
		}
		bundleHash := group[0].BundleSHA256
		for _, annotation := range group[1:] {
			if annotation.BundleSHA256 != bundleHash {
				return GoldSet{}, fmt.Errorf("%s/%s annotations reference different bundles", key.scenario, key.view)
			}
		}
	}

	scenarioIDs := make([]string, 0, len(scenarios))
	for scenarioID := range scenarios {
		scenarioIDs = append(scenarioIDs, scenarioID)
	}
	sort.Strings(scenarioIDs)
	gold := make([]GoldRecord, 0, len(scenarioIDs))
	usedDecisions := make(map[labelKey]struct{})
	for _, scenarioID := range scenarioIDs {
		world, err := resolveLabel(labelKey{scenario: scenarioID, view: ViewOracle}, groups, decisionByKey, usedDecisions)
		if err != nil {
			return GoldSet{}, err
		}
		sufficiency, err := resolveLabel(labelKey{scenario: scenarioID, view: ViewEvidence}, groups, decisionByKey, usedDecisions)
		if err != nil {
			return GoldSet{}, err
		}
		verdict := VerdictInsufficientEvidence
		if sufficiency == EvidenceSufficient {
			switch world {
			case WorldCompliant:
				verdict = VerdictCompliant
			case WorldViolation:
				verdict = VerdictViolation
			}
		}
		gold = append(gold, GoldRecord{
			ScenarioID:           scenarioID,
			OracleBundleSHA256:   groups[labelKey{scenario: scenarioID, view: ViewOracle}][0].BundleSHA256,
			EvidenceBundleSHA256: groups[labelKey{scenario: scenarioID, view: ViewEvidence}][0].BundleSHA256,
			WorldTruth:           world,
			EvidenceSufficiency:  sufficiency, GoldVerdict: verdict,
		})
	}
	for key := range decisionByKey {
		if _, ok := usedDecisions[key]; !ok {
			return GoldSet{}, fmt.Errorf("unused adjudication for %s/%s", key.scenario, key.view)
		}
	}

	decisions = append([]Adjudication(nil), decisions...)
	sort.Slice(decisions, func(i, j int) bool {
		if decisions[i].ScenarioID != decisions[j].ScenarioID {
			return decisions[i].ScenarioID < decisions[j].ScenarioID
		}
		return decisions[i].View < decisions[j].View
	})
	evidenceHash, err := ArtifactDigest(struct {
		Annotations   []Annotation   `json:"annotations"`
		Adjudications []Adjudication `json:"adjudications"`
	}{Annotations: annotations, Adjudications: decisions})
	if err != nil {
		return GoldSet{}, err
	}
	return GoldSet{
		SchemaVersion:            GoldSetSchema,
		StudyID:                  studyID,
		MinimumAnnotatorsPerView: minimumAnnotators,
		AnnotationsSHA256:        evidenceHash,
		Records:                  gold,
		Agreement: []Agreement{
			calculateAgreement(ViewOracle, groups),
			calculateAgreement(ViewEvidence, groups),
		},
	}, nil
}

func resolveLabel(key labelKey, groups map[labelKey][]Annotation, decisions map[labelKey]Adjudication, used map[labelKey]struct{}) (string, error) {
	group := groups[key]
	if len(group) == 0 {
		return "", fmt.Errorf("missing %s annotations for scenario %q", key.view, key.scenario)
	}
	first := group[0].Label
	agree := true
	for _, annotation := range group[1:] {
		if annotation.Label != first {
			agree = false
			break
		}
	}
	if agree {
		if _, ok := decisions[key]; ok {
			return "", fmt.Errorf("adjudication supplied without disagreement for %s/%s", key.scenario, key.view)
		}
		return first, nil
	}
	decision, ok := decisions[key]
	if !ok {
		return "", fmt.Errorf("unresolved disagreement for %s/%s", key.scenario, key.view)
	}
	used[key] = struct{}{}
	return decision.FinalLabel, nil
}

func calculateAgreement(view string, groups map[labelKey][]Annotation) Agreement {
	labelCounts := make(map[string]int)
	items := 0
	ratings := 0
	agreeingPairs := 0
	totalPairs := 0
	for key, group := range groups {
		if key.view != view {
			continue
		}
		items++
		for _, annotation := range group {
			labelCounts[annotation.Label]++
			ratings++
		}
		for i := 0; i < len(group); i++ {
			for j := i + 1; j < len(group); j++ {
				totalPairs++
				if group[i].Label == group[j].Label {
					agreeingPairs++
				}
			}
		}
	}
	observed := ratio(agreeingPairs, totalPairs)
	expected := 0.0
	if ratings > 0 {
		for _, count := range labelCounts {
			p := float64(count) / float64(ratings)
			expected += p * p
		}
	}
	kappa := 0.0
	if math.Abs(1-expected) < 1e-12 {
		if math.Abs(1-observed) < 1e-12 {
			kappa = 1
		}
	} else {
		kappa = (observed - expected) / (1 - expected)
	}
	return Agreement{View: view, Items: items, Ratings: ratings, PairwiseAgreement: observed, Kappa: kappa}
}

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}
