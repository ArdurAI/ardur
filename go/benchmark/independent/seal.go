package independent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxCorpusFiles = 10000

func (gold GoldSet) Validate() error {
	if gold.SchemaVersion != GoldSetSchema {
		return fmt.Errorf("unsupported gold set schema %q", gold.SchemaVersion)
	}
	if err := validateID("study_id", gold.StudyID); err != nil {
		return err
	}
	if gold.MinimumAnnotatorsPerView < 2 {
		return errors.New("gold set requires at least two annotators per view")
	}
	if !validSHA256(gold.AnnotationsSHA256) {
		return errors.New("invalid annotations_sha256")
	}
	if len(gold.Records) == 0 {
		return errors.New("empty gold set")
	}
	seen := make(map[string]struct{}, len(gold.Records))
	for _, record := range gold.Records {
		if err := validateID("scenario_id", record.ScenarioID); err != nil {
			return err
		}
		if _, ok := seen[record.ScenarioID]; ok {
			return fmt.Errorf("duplicate gold record %q", record.ScenarioID)
		}
		seen[record.ScenarioID] = struct{}{}
		if !validSHA256(record.OracleBundleSHA256) || !validSHA256(record.EvidenceBundleSHA256) {
			return fmt.Errorf("gold record %q has invalid bundle hashes", record.ScenarioID)
		}
		if err := validateLabel(ViewOracle, record.WorldTruth); err != nil {
			return err
		}
		if err := validateLabel(ViewEvidence, record.EvidenceSufficiency); err != nil {
			return err
		}
		expected := VerdictInsufficientEvidence
		if record.EvidenceSufficiency == EvidenceSufficient {
			if record.WorldTruth == WorldCompliant {
				expected = VerdictCompliant
			} else if record.WorldTruth == WorldViolation {
				expected = VerdictViolation
			}
		}
		if record.GoldVerdict != expected {
			return fmt.Errorf("gold verdict for %q is inconsistent with labels", record.ScenarioID)
		}
	}
	if len(gold.Agreement) != 2 {
		return errors.New("gold set must report oracle and evidence agreement")
	}
	views := make(map[string]struct{}, 2)
	for _, agreement := range gold.Agreement {
		if err := validateView(agreement.View); err != nil {
			return err
		}
		if _, ok := views[agreement.View]; ok {
			return fmt.Errorf("duplicate agreement view %q", agreement.View)
		}
		views[agreement.View] = struct{}{}
		if agreement.Items != len(gold.Records) || agreement.Ratings < agreement.Items*gold.MinimumAnnotatorsPerView {
			return fmt.Errorf("agreement counts for %s do not prove the annotator minimum", agreement.View)
		}
		if agreement.PairwiseAgreement < 0 || agreement.PairwiseAgreement > 1 || agreement.Kappa < -1 || agreement.Kappa > 1 {
			return fmt.Errorf("invalid agreement statistics for %s", agreement.View)
		}
	}
	return nil
}

func BuildSeal(rootDir, corpusDir, protocolPath, preregPath, goldPath, annotationsPath, adjudicationsPath, splitsPath, sealedAt string) (Seal, error) {
	rootAbs, err := filepath.Abs(rootDir)
	if err != nil {
		return Seal{}, err
	}
	rootInfo, err := os.Lstat(rootAbs)
	if err != nil {
		return Seal{}, err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return Seal{}, errors.New("study root must be a non-symlink directory")
	}
	rootAbs, err = filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return Seal{}, err
	}
	if err := validateTime("sealed_at", sealedAt); err != nil {
		return Seal{}, err
	}
	var prereg Preregistration
	if err := ReadStrictJSON(preregPath, &prereg); err != nil {
		return Seal{}, fmt.Errorf("read preregistration: %w", err)
	}
	if err := prereg.Validate(); err != nil {
		return Seal{}, err
	}
	registered, _ := time.Parse(time.RFC3339, prereg.RegisteredAt)
	sealed, _ := time.Parse(time.RFC3339, sealedAt)
	if sealed.Before(registered) {
		return Seal{}, errors.New("sealed_at precedes registered_at")
	}
	var annotations []Annotation
	if err := ReadStrictJSON(annotationsPath, &annotations); err != nil {
		return Seal{}, fmt.Errorf("read annotations: %w", err)
	}
	var adjudications []Adjudication
	if err := ReadStrictJSON(adjudicationsPath, &adjudications); err != nil {
		return Seal{}, fmt.Errorf("read adjudications: %w", err)
	}
	if err := validateAnnotationTimeline(annotations, adjudications, registered, sealed); err != nil {
		return Seal{}, err
	}
	recomputedGold, err := Adjudicate(prereg.StudyID, prereg.MinimumAnnotatorsPerView, annotations, adjudications)
	if err != nil {
		return Seal{}, fmt.Errorf("recompute gold set: %w", err)
	}
	var gold GoldSet
	if err := ReadStrictJSON(goldPath, &gold); err != nil {
		return Seal{}, fmt.Errorf("read gold set: %w", err)
	}
	if err := gold.Validate(); err != nil {
		return Seal{}, err
	}
	goldEqual, err := sameJSON(recomputedGold, gold)
	if err != nil {
		return Seal{}, err
	}
	if !goldEqual {
		return Seal{}, errors.New("gold set does not replay from annotations and adjudications")
	}
	var splits SplitManifest
	if err := ReadStrictJSON(splitsPath, &splits); err != nil {
		return Seal{}, fmt.Errorf("read split manifest: %w", err)
	}
	if err := splits.Validate(); err != nil {
		return Seal{}, err
	}
	if gold.StudyID != prereg.StudyID || splits.StudyID != prereg.StudyID {
		return Seal{}, errors.New("study_id mismatch among preregistration, gold, and splits")
	}
	if gold.MinimumAnnotatorsPerView < prereg.MinimumAnnotatorsPerView {
		return Seal{}, errors.New("gold set does not meet preregistered annotator minimum")
	}
	if err := validateScenarioSets(gold, splits, prereg.HeldOutMinimumBasisPoints); err != nil {
		return Seal{}, err
	}
	protocolDigest, err := digestRelative(rootAbs, protocolPath, "protocol")
	if err != nil {
		return Seal{}, err
	}
	if protocolDigest.SHA256 != prereg.ProtocolSHA256 {
		return Seal{}, errors.New("protocol file does not match protocol_sha256")
	}

	preregDigest, err := digestRelative(rootAbs, preregPath, "preregistration")
	if err != nil {
		return Seal{}, err
	}
	goldDigest, err := digestRelative(rootAbs, goldPath, "gold")
	if err != nil {
		return Seal{}, err
	}
	annotationsDigest, err := digestRelative(rootAbs, annotationsPath, "annotations")
	if err != nil {
		return Seal{}, err
	}
	adjudicationsDigest, err := digestRelative(rootAbs, adjudicationsPath, "adjudications")
	if err != nil {
		return Seal{}, err
	}
	splitsDigest, err := digestRelative(rootAbs, splitsPath, "splits")
	if err != nil {
		return Seal{}, err
	}
	corpus, err := digestCorpus(rootAbs, corpusDir, gold, registered, sealed)
	if err != nil {
		return Seal{}, err
	}
	seal := Seal{
		SchemaVersion: SealSchema, StudyID: prereg.StudyID, Mode: prereg.Mode,
		RegistrationAssurance: prereg.RegistrationAssurance,
		SealedAt:              sealedAt, Protocol: protocolDigest, Preregistration: preregDigest, Gold: goldDigest,
		Annotations: annotationsDigest, Adjudications: adjudicationsDigest,
		Splits: splitsDigest, Corpus: corpus,
	}
	rootHash, err := sealRootDigest(seal)
	if err != nil {
		return Seal{}, err
	}
	seal.RootSHA256 = rootHash
	return seal, nil
}

func VerifySeal(rootDir, corpusDir, protocolPath, preregPath, goldPath, annotationsPath, adjudicationsPath, splitsPath string, seal Seal) error {
	if err := validateSealEnvelope(seal); err != nil {
		return err
	}
	rebuilt, err := BuildSeal(rootDir, corpusDir, protocolPath, preregPath, goldPath, annotationsPath, adjudicationsPath, splitsPath, seal.SealedAt)
	if err != nil {
		return err
	}
	equal, err := sameJSON(rebuilt, seal)
	if err != nil {
		return err
	}
	if !equal {
		return errors.New("seal verification failed: artifact drift detected")
	}
	return nil
}

func sealRootDigest(seal Seal) (string, error) {
	seal.RootSHA256 = ""
	return ArtifactDigest(seal)
}

func SealDigest(seal Seal) (string, error) {
	if err := validateSealEnvelope(seal); err != nil {
		return "", err
	}
	return ArtifactDigest(seal)
}

func validateSealEnvelope(seal Seal) error {
	if seal.SchemaVersion != SealSchema || !validSHA256(seal.RootSHA256) {
		return errors.New("invalid seal")
	}
	if seal.Mode != ModePilot {
		return fmt.Errorf("unsupported seal mode %q", seal.Mode)
	}
	if seal.RegistrationAssurance != RegistrationAssuranceSelfAsserted {
		return fmt.Errorf("unsupported seal registration_assurance %q", seal.RegistrationAssurance)
	}
	return nil
}

func digestRelative(rootAbs, path, role string) (FileDigest, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return FileDigest{}, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return FileDigest{}, err
	}
	rel, err := filepath.Rel(rootAbs, real)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return FileDigest{}, fmt.Errorf("artifact is outside study root: %s", path)
	}
	hash, size, err := SHA256File(abs)
	if err != nil {
		return FileDigest{}, err
	}
	return FileDigest{Path: filepath.ToSlash(rel), Role: role, SHA256: hash, Bytes: size}, nil
}

func digestCorpus(rootAbs, corpusDir string, gold GoldSet, registeredAt, sealedAt time.Time) ([]FileDigest, error) {
	corpusAbs, err := filepath.Abs(corpusDir)
	if err != nil {
		return nil, err
	}
	corpusInfo, err := os.Lstat(corpusAbs)
	if err != nil {
		return nil, err
	}
	if corpusInfo.Mode()&os.ModeSymlink != 0 || !corpusInfo.IsDir() {
		return nil, errors.New("corpus root must be a non-symlink directory")
	}
	corpusAbs, err = filepath.EvalSymlinks(corpusAbs)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(rootAbs, corpusAbs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, errors.New("corpus directory is outside study root")
	}
	scenarios := make(map[string]map[string]string)
	captures := make(map[string]Capture)
	oracleArtifacts := make(map[string]OracleArtifact)
	evidenceArtifacts := make(map[string]EvidenceArtifact)
	expectedBundles := make(map[string]map[string]string, len(gold.Records))
	for _, record := range gold.Records {
		expectedBundles[record.ScenarioID] = map[string]string{
			ViewOracle:   record.OracleBundleSHA256,
			ViewEvidence: record.EvidenceBundleSHA256,
		}
	}
	var digests []FileDigest
	err = filepath.WalkDir(corpusAbs, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("corpus contains symlink: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("corpus contains non-regular file: %s", path)
		}
		if len(digests) >= maxCorpusFiles {
			return fmt.Errorf("corpus exceeds %d files", maxCorpusFiles)
		}
		role := ""
		scenarioID := ""
		switch {
		case strings.HasSuffix(path, ".capture.json"):
			var capture Capture
			if err := ReadStrictJSON(path, &capture); err != nil {
				return err
			}
			if err := capture.Validate(); err != nil {
				return err
			}
			capturedAt, _ := time.Parse(time.RFC3339, capture.CapturedAt)
			if capturedAt.Before(registeredAt) || capturedAt.After(sealedAt) {
				return fmt.Errorf("capture %q falls outside registered-to-sealed interval", capture.ScenarioID)
			}
			role, scenarioID = "capture", capture.ScenarioID
			if _, ok := captures[scenarioID]; ok {
				return fmt.Errorf("duplicate capture artifact for %q", scenarioID)
			}
			captures[scenarioID] = capture
		case strings.HasSuffix(path, ".oracle.json"):
			var artifact OracleArtifact
			if err := ReadStrictJSON(path, &artifact); err != nil {
				return err
			}
			if artifact.SchemaVersion != OracleSchema || !validSHA256(artifact.CaptureSHA256) {
				return fmt.Errorf("invalid oracle artifact: %s", path)
			}
			if err := validateObservations(artifact.Observations); err != nil {
				return err
			}
			role, scenarioID = ViewOracle, artifact.ScenarioID
			oracleArtifacts[scenarioID] = artifact
		case strings.HasSuffix(path, ".evidence.json"):
			var artifact EvidenceArtifact
			if err := ReadStrictJSON(path, &artifact); err != nil {
				return err
			}
			if artifact.SchemaVersion != EvidenceSchema || !validSHA256(artifact.CaptureSHA256) {
				return fmt.Errorf("invalid evidence artifact: %s", path)
			}
			if len(artifact.Observations) > 0 {
				if err := validateObservations(artifact.Observations); err != nil {
					return err
				}
			}
			role, scenarioID = ViewEvidence, artifact.ScenarioID
			evidenceArtifacts[scenarioID] = artifact
		default:
			return fmt.Errorf("unexpected corpus file: %s", path)
		}
		if err := validateID("scenario_id", scenarioID); err != nil {
			return err
		}
		if scenarios[scenarioID] == nil {
			scenarios[scenarioID] = make(map[string]string)
		}
		if _, ok := scenarios[scenarioID][role]; ok {
			return fmt.Errorf("duplicate %s artifact for %q", role, scenarioID)
		}
		digest, err := digestRelative(rootAbs, path, role)
		if err != nil {
			return err
		}
		scenarios[scenarioID][role] = digest.SHA256
		if role == ViewOracle || role == ViewEvidence {
			bundle, err := BuildLabelBundle(gold.StudyID, role, path)
			if err != nil {
				return err
			}
			bundleHash, err := ArtifactDigest(bundle)
			if err != nil {
				return err
			}
			if bundleHash != expectedBundles[scenarioID][role] {
				return fmt.Errorf("%s bundle for %q does not match gold provenance", role, scenarioID)
			}
		}
		digests = append(digests, digest)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(digests) == 0 {
		return nil, errors.New("empty corpus")
	}
	for _, record := range gold.Records {
		roles := scenarios[record.ScenarioID]
		if roles["capture"] == "" || roles[ViewOracle] == "" || roles[ViewEvidence] == "" {
			return nil, fmt.Errorf("scenario %q lacks capture/oracle/evidence artifacts", record.ScenarioID)
		}
		expectedOracle, expectedEvidence, err := NormalizeCapture(captures[record.ScenarioID])
		if err != nil {
			return nil, err
		}
		oracleEqual, err := sameJSON(expectedOracle, oracleArtifacts[record.ScenarioID])
		if err != nil {
			return nil, err
		}
		evidenceEqual, err := sameJSON(expectedEvidence, evidenceArtifacts[record.ScenarioID])
		if err != nil {
			return nil, err
		}
		if !oracleEqual || !evidenceEqual {
			return nil, fmt.Errorf("scenario %q normalized views do not replay from raw capture", record.ScenarioID)
		}
	}
	if len(scenarios) != len(gold.Records) {
		return nil, errors.New("corpus scenario set does not match gold set")
	}
	sort.Slice(digests, func(i, j int) bool {
		if digests[i].Path != digests[j].Path {
			return digests[i].Path < digests[j].Path
		}
		return digests[i].Role < digests[j].Role
	})
	return digests, nil
}

func validateAnnotationTimeline(annotations []Annotation, adjudications []Adjudication, registeredAt, sealedAt time.Time) error {
	for _, annotation := range annotations {
		createdAt, err := time.Parse(time.RFC3339, annotation.CreatedAt)
		if err != nil {
			return fmt.Errorf("invalid annotation created_at: %w", err)
		}
		if createdAt.Before(registeredAt) || createdAt.After(sealedAt) {
			return fmt.Errorf("annotation for %q falls outside registered-to-sealed interval", annotation.ScenarioID)
		}
	}
	for _, adjudication := range adjudications {
		createdAt, err := time.Parse(time.RFC3339, adjudication.CreatedAt)
		if err != nil {
			return fmt.Errorf("invalid adjudication created_at: %w", err)
		}
		if createdAt.Before(registeredAt) || createdAt.After(sealedAt) {
			return fmt.Errorf("adjudication for %q falls outside registered-to-sealed interval", adjudication.ScenarioID)
		}
	}
	return nil
}

func validateScenarioSets(gold GoldSet, splits SplitManifest, minimumHeldOutBasisPoints int) error {
	goldIDs := make(map[string]struct{}, len(gold.Records))
	for _, record := range gold.Records {
		goldIDs[record.ScenarioID] = struct{}{}
	}
	heldOut := 0
	for _, record := range splits.Records {
		if _, ok := goldIDs[record.ScenarioID]; !ok {
			return fmt.Errorf("split scenario %q is absent from gold set", record.ScenarioID)
		}
		if record.Split == SplitHeldOut {
			heldOut++
		}
	}
	if len(splits.Records) != len(goldIDs) {
		return errors.New("split manifest scenario set does not match gold set")
	}
	actualBasisPoints := heldOut * 10000 / len(splits.Records)
	if actualBasisPoints < minimumHeldOutBasisPoints {
		return fmt.Errorf("held-out split is %d basis points, need %d", actualBasisPoints, minimumHeldOutBasisPoints)
	}
	return nil
}
