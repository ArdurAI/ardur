package independent

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func validateID(name, value string) error {
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("invalid %s", name)
	}
	return nil
}

func validateTime(name, value string) error {
	if _, err := time.Parse(time.RFC3339, value); err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	return nil
}

func validateNonEmpty(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("missing %s", name)
	}
	return nil
}

func validateUniqueStrings(name string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s contains an empty value", name)
		}
		if _, ok := seen[value]; ok {
			return fmt.Errorf("%s contains duplicate %q", name, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateObservations(observations []Observation) error {
	if len(observations) == 0 {
		return errors.New("no observations")
	}
	seen := make(map[string]struct{}, len(observations))
	for i, observation := range observations {
		if err := validateID(fmt.Sprintf("observations[%d].id", i), observation.ID); err != nil {
			return err
		}
		if _, ok := seen[observation.ID]; ok {
			return fmt.Errorf("duplicate observation id %q", observation.ID)
		}
		seen[observation.ID] = struct{}{}
		for name, value := range map[string]string{
			"action": observation.Action, "resource": observation.Resource, "outcome": observation.Outcome,
		} {
			if err := validateNonEmpty(fmt.Sprintf("observations[%d].%s", i, name), value); err != nil {
				return err
			}
		}
	}
	return nil
}

func validatePolicy(policy EvaluationPolicy) error {
	if policy.DefaultDecision != "allow" && policy.DefaultDecision != "deny" {
		return fmt.Errorf("invalid policy default_decision %q", policy.DefaultDecision)
	}
	if len(policy.Rules) == 0 {
		return errors.New("policy has no rules")
	}
	seen := make(map[string]struct{}, len(policy.Rules))
	for i, rule := range policy.Rules {
		if err := validateID(fmt.Sprintf("policy.rules[%d].id", i), rule.ID); err != nil {
			return err
		}
		if _, ok := seen[rule.ID]; ok {
			return fmt.Errorf("duplicate policy rule id %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		if err := validateNonEmpty(fmt.Sprintf("policy.rules[%d].action", i), rule.Action); err != nil {
			return err
		}
		if err := validateNonEmpty(fmt.Sprintf("policy.rules[%d].resource", i), rule.Resource); err != nil {
			return err
		}
		if rule.Decision != "allow" && rule.Decision != "deny" {
			return fmt.Errorf("invalid policy rule decision %q", rule.Decision)
		}
	}
	return nil
}

func (capture Capture) Validate() error {
	if capture.SchemaVersion != CaptureSchema {
		return fmt.Errorf("unsupported capture schema %q", capture.SchemaVersion)
	}
	if err := validateID("scenario_id", capture.ScenarioID); err != nil {
		return err
	}
	if err := validateTime("captured_at", capture.CapturedAt); err != nil {
		return err
	}
	if err := validatePolicy(capture.Policy); err != nil {
		return err
	}
	if err := validateObservations(capture.Oracle.Observations); err != nil {
		return err
	}
	if err := validateUniqueStrings("evidence_projection.visible_observation_ids", capture.Evidence.VisibleObservationIDs); err != nil {
		return err
	}
	known := make(map[string]struct{}, len(capture.Oracle.Observations))
	for _, observation := range capture.Oracle.Observations {
		known[observation.ID] = struct{}{}
	}
	for _, id := range capture.Evidence.VisibleObservationIDs {
		if _, ok := known[id]; !ok {
			return fmt.Errorf("evidence projection references unknown observation %q", id)
		}
	}
	return nil
}

func validateView(view string) error {
	if view != ViewOracle && view != ViewEvidence {
		return fmt.Errorf("unsupported annotation view %q", view)
	}
	return nil
}

func validateLabel(view, label string) error {
	var allowed []string
	switch view {
	case ViewOracle:
		allowed = []string{WorldCompliant, WorldViolation, WorldUnknown}
	case ViewEvidence:
		allowed = []string{EvidenceSufficient, EvidenceInsufficient}
	default:
		return fmt.Errorf("unsupported annotation view %q", view)
	}
	if !slices.Contains(allowed, label) {
		return fmt.Errorf("label %q is invalid for %s view", label, view)
	}
	return nil
}

func (annotation Annotation) Validate() error {
	if annotation.SchemaVersion != AnnotationSchema {
		return fmt.Errorf("unsupported annotation schema %q", annotation.SchemaVersion)
	}
	for name, value := range map[string]string{
		"study_id": annotation.StudyID, "scenario_id": annotation.ScenarioID, "annotator_id": annotation.AnnotatorID,
	} {
		if err := validateID(name, value); err != nil {
			return err
		}
	}
	if err := validateView(annotation.View); err != nil {
		return err
	}
	if err := validateLabel(annotation.View, annotation.Label); err != nil {
		return err
	}
	if !validSHA256(annotation.BundleSHA256) {
		return errors.New("invalid bundle_sha256")
	}
	if err := validateNonEmpty("rationale", annotation.Rationale); err != nil {
		return err
	}
	return validateTime("created_at", annotation.CreatedAt)
}

func (adjudication Adjudication) Validate() error {
	if adjudication.SchemaVersion != AdjudicationSchema {
		return fmt.Errorf("unsupported adjudication schema %q", adjudication.SchemaVersion)
	}
	for name, value := range map[string]string{
		"study_id": adjudication.StudyID, "scenario_id": adjudication.ScenarioID, "adjudicator_id": adjudication.AdjudicatorID,
	} {
		if err := validateID(name, value); err != nil {
			return err
		}
	}
	if err := validateView(adjudication.View); err != nil {
		return err
	}
	if err := validateLabel(adjudication.View, adjudication.FinalLabel); err != nil {
		return err
	}
	if err := validateNonEmpty("rationale", adjudication.Rationale); err != nil {
		return err
	}
	return validateTime("created_at", adjudication.CreatedAt)
}

func (prereg Preregistration) Validate() error {
	if prereg.SchemaVersion != PreregistrationSchema {
		return fmt.Errorf("unsupported preregistration schema %q", prereg.SchemaVersion)
	}
	if err := validateID("study_id", prereg.StudyID); err != nil {
		return err
	}
	if prereg.Mode != ModePilot && prereg.Mode != ModeHeadline {
		return fmt.Errorf("unsupported preregistration mode %q", prereg.Mode)
	}
	if !validSHA256(prereg.ProtocolSHA256) {
		return errors.New("invalid protocol_sha256")
	}
	if err := validateTime("registered_at", prereg.RegisteredAt); err != nil {
		return err
	}
	if len(prereg.Metrics) == 0 {
		return errors.New("no preregistered metrics")
	}
	if err := validateUniqueStrings("metrics", prereg.Metrics); err != nil {
		return err
	}
	allowedMetrics := []string{"accuracy", "false_safe_rate", "missed_violation_rate", "over_abstention_rate", "per_class_prf"}
	for _, required := range allowedMetrics {
		if !slices.Contains(prereg.Metrics, required) {
			return fmt.Errorf("missing required preregistered metric %q", required)
		}
	}
	for _, metric := range prereg.Metrics {
		if !slices.Contains(allowedMetrics, metric) {
			return fmt.Errorf("unsupported preregistered metric %q", metric)
		}
	}
	if prereg.MinimumAnnotatorsPerView < 2 {
		return errors.New("minimum_annotators_per_view must be at least 2")
	}
	if prereg.HeldOutMinimumBasisPoints < 3000 || prereg.HeldOutMinimumBasisPoints > 10000 {
		return errors.New("held_out_minimum_basis_points must be between 3000 and 10000")
	}
	if len(prereg.AllowedSUTs) < 2 {
		return errors.New("allowed_suts must contain at least two systems")
	}
	if err := validateUniqueStrings("allowed_suts", prereg.AllowedSUTs); err != nil {
		return err
	}
	for _, sutID := range prereg.AllowedSUTs {
		if err := validateID("allowed_suts entry", sutID); err != nil {
			return err
		}
	}
	if prereg.Mode == ModeHeadline {
		parsed, err := url.Parse(prereg.RegistrationURI)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return errors.New("headline mode requires an HTTPS registration_uri")
		}
	}
	return nil
}

func (splits SplitManifest) Validate() error {
	if splits.SchemaVersion != SplitManifestSchema {
		return fmt.Errorf("unsupported split manifest schema %q", splits.SchemaVersion)
	}
	if err := validateID("study_id", splits.StudyID); err != nil {
		return err
	}
	if len(splits.Records) == 0 {
		return errors.New("empty split manifest")
	}
	seen := make(map[string]struct{}, len(splits.Records))
	for _, record := range splits.Records {
		if err := validateID("scenario_id", record.ScenarioID); err != nil {
			return err
		}
		if record.Split != SplitDevelopment && record.Split != SplitHeldOut {
			return fmt.Errorf("invalid split %q", record.Split)
		}
		if _, ok := seen[record.ScenarioID]; ok {
			return fmt.Errorf("duplicate split for scenario %q", record.ScenarioID)
		}
		seen[record.ScenarioID] = struct{}{}
	}
	return nil
}

func validateVerdict(verdict string) error {
	if verdict != VerdictCompliant && verdict != VerdictViolation && verdict != VerdictInsufficientEvidence {
		return fmt.Errorf("invalid verdict %q", verdict)
	}
	return nil
}
