package independent

import (
	"fmt"
	"path/filepath"
	"sort"
)

func NormalizeCapture(capture Capture) (OracleArtifact, EvidenceArtifact, error) {
	if err := capture.Validate(); err != nil {
		return OracleArtifact{}, EvidenceArtifact{}, err
	}
	captureBytes, err := MarshalArtifact(capture)
	if err != nil {
		return OracleArtifact{}, EvidenceArtifact{}, err
	}
	captureHash := SHA256Bytes(captureBytes)
	observations := append([]Observation(nil), capture.Oracle.Observations...)
	sort.Slice(observations, func(i, j int) bool { return observations[i].ID < observations[j].ID })
	oracle := OracleArtifact{
		SchemaVersion: OracleSchema,
		ScenarioID:    capture.ScenarioID, CapturedAt: capture.CapturedAt,
		Policy:       capture.Policy,
		Observations: observations, Limitations: append([]string(nil), capture.Oracle.Limitations...),
		CaptureSHA256: captureHash,
	}
	visible := make(map[string]struct{}, len(capture.Evidence.VisibleObservationIDs))
	for _, id := range capture.Evidence.VisibleObservationIDs {
		visible[id] = struct{}{}
	}
	projected := make([]Observation, 0, len(visible))
	for _, observation := range observations {
		if _, ok := visible[observation.ID]; ok {
			projected = append(projected, observation)
		}
	}
	evidence := EvidenceArtifact{
		SchemaVersion: EvidenceSchema,
		ScenarioID:    capture.ScenarioID, CapturedAt: capture.CapturedAt,
		Policy:       capture.Policy,
		Observations: projected, Limitations: append([]string(nil), capture.Evidence.Limitations...),
		CaptureSHA256: captureHash,
	}
	return oracle, evidence, nil
}

func NormalizeCaptureFile(inputPath, outputDir string) (OracleArtifact, EvidenceArtifact, error) {
	var capture Capture
	if err := ReadStrictJSON(inputPath, &capture); err != nil {
		return OracleArtifact{}, EvidenceArtifact{}, fmt.Errorf("read capture: %w", err)
	}
	oracle, evidence, err := NormalizeCapture(capture)
	if err != nil {
		return OracleArtifact{}, EvidenceArtifact{}, err
	}
	if err := WriteArtifact(filepath.Join(outputDir, capture.ScenarioID+".capture.json"), capture); err != nil {
		return OracleArtifact{}, EvidenceArtifact{}, err
	}
	if err := WriteArtifact(filepath.Join(outputDir, capture.ScenarioID+".oracle.json"), oracle); err != nil {
		return OracleArtifact{}, EvidenceArtifact{}, err
	}
	if err := WriteArtifact(filepath.Join(outputDir, capture.ScenarioID+".evidence.json"), evidence); err != nil {
		return OracleArtifact{}, EvidenceArtifact{}, err
	}
	return oracle, evidence, nil
}

func BuildLabelBundle(studyID, view, sourcePath string) (LabelBundle, error) {
	if err := validateID("study_id", studyID); err != nil {
		return LabelBundle{}, err
	}
	if err := validateView(view); err != nil {
		return LabelBundle{}, err
	}
	hash, _, err := SHA256File(sourcePath)
	if err != nil {
		return LabelBundle{}, err
	}
	bundle := LabelBundle{SchemaVersion: LabelBundleSchema, StudyID: studyID, View: view, SourceSHA256: hash}
	switch view {
	case ViewOracle:
		var artifact OracleArtifact
		if err := ReadStrictJSON(sourcePath, &artifact); err != nil {
			return LabelBundle{}, err
		}
		if artifact.SchemaVersion != OracleSchema {
			return LabelBundle{}, fmt.Errorf("expected %s source", OracleSchema)
		}
		if !validSHA256(artifact.CaptureSHA256) {
			return LabelBundle{}, fmt.Errorf("invalid capture_sha256")
		}
		bundle.ScenarioID = artifact.ScenarioID
		bundle.CapturedAt = artifact.CapturedAt
		bundle.Policy = artifact.Policy
		bundle.Observations = artifact.Observations
		bundle.Limitations = artifact.Limitations
		bundle.Rubric = AnnotationRubric{
			AllowedLabels: []string{WorldCompliant, WorldViolation, WorldUnknown},
			Question:      "What happened in the oracle-visible world? Do not infer from any system output.",
		}
	case ViewEvidence:
		var artifact EvidenceArtifact
		if err := ReadStrictJSON(sourcePath, &artifact); err != nil {
			return LabelBundle{}, err
		}
		if artifact.SchemaVersion != EvidenceSchema {
			return LabelBundle{}, fmt.Errorf("expected %s source", EvidenceSchema)
		}
		if !validSHA256(artifact.CaptureSHA256) {
			return LabelBundle{}, fmt.Errorf("invalid capture_sha256")
		}
		bundle.ScenarioID = artifact.ScenarioID
		bundle.CapturedAt = artifact.CapturedAt
		bundle.Policy = artifact.Policy
		bundle.Observations = artifact.Observations
		bundle.Limitations = artifact.Limitations
		bundle.Rubric = AnnotationRubric{
			AllowedLabels: []string{EvidenceSufficient, EvidenceInsufficient},
			Question:      "Is this projected evidence sufficient to establish the world outcome? Do not infer unseen effects.",
		}
	}
	if err := validateID("scenario_id", bundle.ScenarioID); err != nil {
		return LabelBundle{}, err
	}
	if err := validateTime("captured_at", bundle.CapturedAt); err != nil {
		return LabelBundle{}, err
	}
	if err := validatePolicy(bundle.Policy); err != nil {
		return LabelBundle{}, err
	}
	if view == ViewOracle {
		if err := validateObservations(bundle.Observations); err != nil {
			return LabelBundle{}, err
		}
	} else if len(bundle.Observations) > 0 {
		if err := validateObservations(bundle.Observations); err != nil {
			return LabelBundle{}, err
		}
	}
	return bundle, nil
}
