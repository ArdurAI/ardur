package independent

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	testStudyID    = "auditbench-pilot-1"
	testRegistered = "2026-01-01T00:00:00Z"
	testSealed     = "2026-01-02T00:00:00Z"
)

type testStudy struct {
	root              string
	corpus            string
	protocol          string
	preregPath        string
	goldPath          string
	annotationsPath   string
	adjudicationsPath string
	splitsPath        string
	seal              Seal
	gold              GoldSet
	prereg            Preregistration
	splits            SplitManifest
}

func TestReadStrictJSONRejectsDuplicateAndUnknownNames(t *testing.T) {
	t.Run("duplicate", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "duplicate.json")
		if err := os.WriteFile(path, []byte(`{"schema_version":"a","schema_version":"b"}`), 0600); err != nil {
			t.Fatal(err)
		}
		var dst map[string]string
		if err := ReadStrictJSON(path, &dst); err == nil || !strings.Contains(err.Error(), "duplicate JSON name") {
			t.Fatalf("ReadStrictJSON error = %v, want duplicate-name rejection", err)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "unknown.json")
		if err := os.WriteFile(path, []byte(`{"schema_version":"auditbench.capture.v0.1","unexpected":true}`), 0600); err != nil {
			t.Fatal(err)
		}
		var capture Capture
		if err := ReadStrictJSON(path, &capture); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("ReadStrictJSON error = %v, want unknown-field rejection", err)
		}
	})

	t.Run("deep", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "deep.json")
		data := strings.Repeat("[", 130) + "0" + strings.Repeat("]", 130)
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		var dst any
		if err := ReadStrictJSON(path, &dst); err == nil || !strings.Contains(err.Error(), "nesting") {
			t.Fatalf("ReadStrictJSON error = %v, want nesting rejection", err)
		}
	})
}

func TestNormalizeCaptureSeparatesBlindViews(t *testing.T) {
	capture := testCapture("AB-I-01", nil)
	oracle, evidence, err := NormalizeCapture(capture)
	if err != nil {
		t.Fatal(err)
	}
	if len(oracle.Observations) != 1 || len(evidence.Observations) != 0 {
		t.Fatalf("oracle/evidence observation counts = %d/%d, want 1/0", len(oracle.Observations), len(evidence.Observations))
	}
	dir := t.TempDir()
	oraclePath := filepath.Join(dir, "AB-I-01.oracle.json")
	evidencePath := filepath.Join(dir, "AB-I-01.evidence.json")
	if err := WriteArtifact(oraclePath, oracle); err != nil {
		t.Fatal(err)
	}
	if err := WriteArtifact(evidencePath, evidence); err != nil {
		t.Fatal(err)
	}
	for view, path := range map[string]string{ViewOracle: oraclePath, ViewEvidence: evidencePath} {
		bundle, err := BuildLabelBundle(testStudyID, view, path)
		if err != nil {
			t.Fatal(err)
		}
		if len(bundle.Policy.Rules) != 1 || bundle.Policy.Rules[0].Decision != "allow" {
			t.Fatalf("%s bundle lost evaluation policy: %#v", view, bundle.Policy)
		}
		data, err := MarshalArtifact(bundle)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"gold_verdict", "sut_id", "world_truth", "expected_label"} {
			if strings.Contains(string(data), forbidden) {
				t.Fatalf("%s bundle leaked forbidden field %q", view, forbidden)
			}
		}
	}
}

func TestAdjudicateEnforcesIndependentBlindAnnotations(t *testing.T) {
	annotations := testAnnotations("AB-I-01", fakeHash("oracle"), fakeHash("evidence"), WorldViolation, EvidenceInsufficient)
	gold, err := Adjudicate(testStudyID, 2, annotations, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(gold.Records) != 1 || gold.Records[0].GoldVerdict != VerdictInsufficientEvidence {
		t.Fatalf("gold records = %#v", gold.Records)
	}
	if gold.Records[0].OracleBundleSHA256 != fakeHash("oracle") || gold.Records[0].EvidenceBundleSHA256 != fakeHash("evidence") {
		t.Fatal("gold record did not preserve bundle provenance")
	}

	t.Run("same annotator sees both views", func(t *testing.T) {
		bad := append([]Annotation(nil), annotations...)
		bad[2].AnnotatorID = bad[0].AnnotatorID
		if _, err := Adjudicate(testStudyID, 2, bad, nil); err == nil || !strings.Contains(err.Error(), "both blind views") {
			t.Fatalf("Adjudicate error = %v", err)
		}
	})

	t.Run("bundle drift", func(t *testing.T) {
		bad := append([]Annotation(nil), annotations...)
		bad[1].BundleSHA256 = fakeHash("other")
		if _, err := Adjudicate(testStudyID, 2, bad, nil); err == nil || !strings.Contains(err.Error(), "different bundles") {
			t.Fatalf("Adjudicate error = %v", err)
		}
	})

	t.Run("disagreement needs independent adjudicator", func(t *testing.T) {
		disputed := append([]Annotation(nil), annotations...)
		disputed[1].Label = WorldCompliant
		if _, err := Adjudicate(testStudyID, 2, disputed, nil); err == nil || !strings.Contains(err.Error(), "unresolved disagreement") {
			t.Fatalf("Adjudicate error = %v", err)
		}
		decision := Adjudication{
			SchemaVersion: AdjudicationSchema, StudyID: testStudyID, ScenarioID: "AB-I-01",
			View: ViewOracle, AdjudicatorID: "oracle-adjudicator", FinalLabel: WorldViolation,
			Rationale: "Observed write is outside the declared resource scope.", CreatedAt: "2026-01-01T02:00:00Z",
		}
		resolved, err := Adjudicate(testStudyID, 2, disputed, []Adjudication{decision})
		if err != nil {
			t.Fatal(err)
		}
		if resolved.Records[0].WorldTruth != WorldViolation {
			t.Fatalf("resolved world truth = %q", resolved.Records[0].WorldTruth)
		}
		decision.AdjudicatorID = disputed[0].AnnotatorID
		if _, err := Adjudicate(testStudyID, 2, disputed, []Adjudication{decision}); err == nil || !strings.Contains(err.Error(), "also annotated") {
			t.Fatalf("Adjudicate error = %v", err)
		}
	})
}

func TestSealAndScoreEndToEnd(t *testing.T) {
	study := writeTestStudy(t)
	if err := VerifySeal(study.root, study.corpus, study.protocol, study.preregPath, study.goldPath, study.annotationsPath, study.adjudicationsPath, study.splitsPath, study.seal); err != nil {
		t.Fatal(err)
	}
	sealHash, err := SealDigest(study.seal)
	if err != nil {
		t.Fatal(err)
	}

	heldOut := SUTResult{
		SchemaVersion: SUTResultSchema, StudyID: testStudyID, SUTID: "ardur",
		SealSHA256: sealHash, CreatedAt: "2026-01-03T00:00:00Z",
		Predictions: []Prediction{{ScenarioID: "AB-I-03", Verdict: VerdictInsufficientEvidence}},
	}
	report, err := Score(study.prereg, study.seal, study.gold, study.splits, heldOut, SplitHeldOut)
	if err != nil {
		t.Fatal(err)
	}
	if report.Accuracy != 1 || report.FalseSafeRate == nil || *report.FalseSafeRate != 0 || report.Scenarios != 1 {
		t.Fatalf("held-out report = %#v", report)
	}
	resultHash, err := ArtifactDigest(heldOut)
	if err != nil {
		t.Fatal(err)
	}
	if report.SUTResultSHA256 != resultHash {
		t.Fatalf("SUT result digest = %q, want %q", report.SUTResultSHA256, resultHash)
	}

	development := heldOut
	development.Predictions = []Prediction{
		{ScenarioID: "AB-I-01", Verdict: VerdictInsufficientEvidence},
		{ScenarioID: "AB-I-02", Verdict: VerdictCompliant},
	}
	report, err = Score(study.prereg, study.seal, study.gold, study.splits, development, SplitDevelopment)
	if err != nil {
		t.Fatal(err)
	}
	if report.Accuracy != 0 || report.FalseSafeRate != nil || report.MissedViolationRate == nil || *report.MissedViolationRate != 1 || report.OverAbstentionRate == nil || *report.OverAbstentionRate != 0.5 {
		t.Fatalf("development report = %#v", report)
	}

	t.Run("wrong seal", func(t *testing.T) {
		bad := heldOut
		bad.SealSHA256 = fakeHash("wrong")
		if _, err := Score(study.prereg, study.seal, study.gold, study.splits, bad, SplitHeldOut); err == nil || !strings.Contains(err.Error(), "different seal") {
			t.Fatalf("Score error = %v", err)
		}
	})

	t.Run("pre-seal result", func(t *testing.T) {
		bad := heldOut
		bad.CreatedAt = "2025-12-31T00:00:00Z"
		if _, err := Score(study.prereg, study.seal, study.gold, study.splits, bad, SplitHeldOut); err == nil || !strings.Contains(err.Error(), "predates") {
			t.Fatalf("Score error = %v", err)
		}
	})

	t.Run("coverage", func(t *testing.T) {
		bad := development
		bad.Predictions = bad.Predictions[:1]
		if _, err := Score(study.prereg, study.seal, study.gold, study.splits, bad, SplitDevelopment); err == nil || !strings.Contains(err.Error(), "exactly cover") {
			t.Fatalf("Score error = %v", err)
		}
	})
}

func TestSealRejectsDriftSymlinksAndProtocolMismatch(t *testing.T) {
	t.Run("drift", func(t *testing.T) {
		study := writeTestStudy(t)
		path := filepath.Join(study.corpus, "AB-I-01.oracle.json")
		var artifact OracleArtifact
		if err := ReadStrictJSON(path, &artifact); err != nil {
			t.Fatal(err)
		}
		artifact.Observations[0].Outcome = "mutated"
		if err := WriteArtifact(path, artifact); err != nil {
			t.Fatal(err)
		}
		if err := VerifySeal(study.root, study.corpus, study.protocol, study.preregPath, study.goldPath, study.annotationsPath, study.adjudicationsPath, study.splitsPath, study.seal); err == nil {
			t.Fatal("VerifySeal accepted corpus drift")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		study := writeTestStudy(t)
		if err := os.Symlink(study.protocol, filepath.Join(study.corpus, "leak.oracle.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := BuildSeal(study.root, study.corpus, study.protocol, study.preregPath, study.goldPath, study.annotationsPath, study.adjudicationsPath, study.splitsPath, testSealed); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("BuildSeal error = %v", err)
		}
	})

	t.Run("protocol", func(t *testing.T) {
		study := writeTestStudy(t)
		if err := os.WriteFile(study.protocol, []byte("changed protocol\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := BuildSeal(study.root, study.corpus, study.protocol, study.preregPath, study.goldPath, study.annotationsPath, study.adjudicationsPath, study.splitsPath, testSealed); err == nil || !strings.Contains(err.Error(), "protocol_sha256") {
			t.Fatalf("BuildSeal error = %v", err)
		}
	})

	t.Run("annotation drift", func(t *testing.T) {
		study := writeTestStudy(t)
		var annotations []Annotation
		if err := ReadStrictJSON(study.annotationsPath, &annotations); err != nil {
			t.Fatal(err)
		}
		annotations[0].Rationale = "Changed after the seal."
		if err := WriteArtifact(study.annotationsPath, annotations); err != nil {
			t.Fatal(err)
		}
		if err := VerifySeal(study.root, study.corpus, study.protocol, study.preregPath, study.goldPath, study.annotationsPath, study.adjudicationsPath, study.splitsPath, study.seal); err == nil {
			t.Fatal("VerifySeal accepted annotation drift")
		}
	})

	t.Run("pre-registration annotation", func(t *testing.T) {
		study := writeTestStudy(t)
		var annotations []Annotation
		if err := ReadStrictJSON(study.annotationsPath, &annotations); err != nil {
			t.Fatal(err)
		}
		annotations[0].CreatedAt = "2025-12-31T23:59:59Z"
		if err := WriteArtifact(study.annotationsPath, annotations); err != nil {
			t.Fatal(err)
		}
		if _, err := BuildSeal(study.root, study.corpus, study.protocol, study.preregPath, study.goldPath, study.annotationsPath, study.adjudicationsPath, study.splitsPath, testSealed); err == nil || !strings.Contains(err.Error(), "outside registered-to-sealed") {
			t.Fatalf("BuildSeal error = %v", err)
		}
	})

	t.Run("symlink study root", func(t *testing.T) {
		study := writeTestStudy(t)
		link := filepath.Join(t.TempDir(), "study-link")
		if err := os.Symlink(study.root, link); err != nil {
			t.Fatal(err)
		}
		if _, err := BuildSeal(link, study.corpus, study.protocol, study.preregPath, study.goldPath, study.annotationsPath, study.adjudicationsPath, study.splitsPath, testSealed); err == nil || !strings.Contains(err.Error(), "non-symlink") {
			t.Fatalf("BuildSeal error = %v", err)
		}
	})
}

func TestHeadlinePreregistrationRequiresExternalRegistration(t *testing.T) {
	study := writeTestStudy(t)
	prereg := study.prereg
	prereg.Mode = ModeHeadline
	prereg.RegistrationURI = ""
	if err := prereg.Validate(); err == nil || !strings.Contains(err.Error(), "registration_uri") {
		t.Fatalf("Validate error = %v", err)
	}
	prereg.RegistrationURI = "https://osf.io/example"
	if err := prereg.Validate(); err != nil {
		t.Fatal(err)
	}
	prereg.Metrics = append(prereg.Metrics, "post_hoc_metric")
	if err := prereg.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported preregistered metric") {
		t.Fatalf("Validate error = %v", err)
	}
}

func TestPublishedPilotExamplesAreInternallyConsistent(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	protocolPath := filepath.Join(repoRoot, "docs", "specs", "auditbench-pilot-protocol-v0.1.md")
	preregPath := filepath.Join(repoRoot, "docs", "specs", "auditbench-preregistration-v0.1.example.json")
	splitsPath := filepath.Join(repoRoot, "docs", "specs", "auditbench-splits-v0.1.example.json")

	var prereg Preregistration
	if err := ReadStrictJSON(preregPath, &prereg); err != nil {
		t.Fatal(err)
	}
	if err := prereg.Validate(); err != nil {
		t.Fatal(err)
	}
	protocolHash, _, err := SHA256File(protocolPath)
	if err != nil {
		t.Fatal(err)
	}
	if prereg.ProtocolSHA256 != protocolHash {
		t.Fatalf("published protocol hash = %q, want %q", prereg.ProtocolSHA256, protocolHash)
	}
	var splits SplitManifest
	if err := ReadStrictJSON(splitsPath, &splits); err != nil {
		t.Fatal(err)
	}
	if err := splits.Validate(); err != nil {
		t.Fatal(err)
	}
	if splits.StudyID != prereg.StudyID {
		t.Fatalf("example study IDs differ: %q != %q", splits.StudyID, prereg.StudyID)
	}
}

func writeTestStudy(t *testing.T) testStudy {
	t.Helper()
	root := t.TempDir()
	corpus := filepath.Join(root, "corpus")
	if err := os.MkdirAll(corpus, 0700); err != nil {
		t.Fatal(err)
	}
	protocol := filepath.Join(root, "protocol.md")
	if err := os.WriteFile(protocol, []byte("# Frozen protocol\n\nScore held-out results once.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	protocolHash, _, err := SHA256File(protocol)
	if err != nil {
		t.Fatal(err)
	}

	type labels struct{ world, evidence string }
	labelsByScenario := map[string]labels{
		"AB-I-01": {WorldCompliant, EvidenceSufficient},
		"AB-I-02": {WorldViolation, EvidenceSufficient},
		"AB-I-03": {WorldViolation, EvidenceInsufficient},
	}
	var annotations []Annotation
	for _, scenarioID := range []string{"AB-I-01", "AB-I-02", "AB-I-03"} {
		visible := []string{"obs-1"}
		if scenarioID == "AB-I-03" {
			visible = nil
		}
		capture := testCapture(scenarioID, visible)
		oracle, evidence, err := NormalizeCapture(capture)
		if err != nil {
			t.Fatal(err)
		}
		oraclePath := filepath.Join(corpus, scenarioID+".oracle.json")
		evidencePath := filepath.Join(corpus, scenarioID+".evidence.json")
		if err := WriteArtifact(filepath.Join(corpus, scenarioID+".capture.json"), capture); err != nil {
			t.Fatal(err)
		}
		if err := WriteArtifact(oraclePath, oracle); err != nil {
			t.Fatal(err)
		}
		if err := WriteArtifact(evidencePath, evidence); err != nil {
			t.Fatal(err)
		}
		oracleBundle, err := BuildLabelBundle(testStudyID, ViewOracle, oraclePath)
		if err != nil {
			t.Fatal(err)
		}
		evidenceBundle, err := BuildLabelBundle(testStudyID, ViewEvidence, evidencePath)
		if err != nil {
			t.Fatal(err)
		}
		oracleHash, _ := ArtifactDigest(oracleBundle)
		evidenceHash, _ := ArtifactDigest(evidenceBundle)
		labels := labelsByScenario[scenarioID]
		annotations = append(annotations, testAnnotations(scenarioID, oracleHash, evidenceHash, labels.world, labels.evidence)...)
	}
	gold, err := Adjudicate(testStudyID, 2, annotations, nil)
	if err != nil {
		t.Fatal(err)
	}
	goldPath := filepath.Join(root, "gold.json")
	if err := WriteArtifact(goldPath, gold); err != nil {
		t.Fatal(err)
	}
	annotationsPath := filepath.Join(root, "annotations.json")
	if err := WriteArtifact(annotationsPath, annotations); err != nil {
		t.Fatal(err)
	}
	adjudicationsPath := filepath.Join(root, "adjudications.json")
	if err := WriteArtifact(adjudicationsPath, []Adjudication{}); err != nil {
		t.Fatal(err)
	}
	splits := SplitManifest{
		SchemaVersion: SplitManifestSchema, StudyID: testStudyID,
		Records: []SplitRecord{
			{ScenarioID: "AB-I-01", Split: SplitDevelopment},
			{ScenarioID: "AB-I-02", Split: SplitDevelopment},
			{ScenarioID: "AB-I-03", Split: SplitHeldOut},
		},
	}
	splitsPath := filepath.Join(root, "splits.json")
	if err := WriteArtifact(splitsPath, splits); err != nil {
		t.Fatal(err)
	}
	prereg := Preregistration{
		SchemaVersion: PreregistrationSchema, StudyID: testStudyID, Mode: ModePilot,
		ProtocolSHA256: protocolHash, RegisteredAt: testRegistered,
		Metrics:                  []string{"accuracy", "false_safe_rate", "missed_violation_rate", "over_abstention_rate", "per_class_prf"},
		MinimumAnnotatorsPerView: 2, HeldOutMinimumBasisPoints: 3000,
		AllowedSUTs: []string{"ardur", "opa"},
	}
	preregPath := filepath.Join(root, "preregistration.json")
	if err := WriteArtifact(preregPath, prereg); err != nil {
		t.Fatal(err)
	}
	seal, err := BuildSeal(root, corpus, protocol, preregPath, goldPath, annotationsPath, adjudicationsPath, splitsPath, testSealed)
	if err != nil {
		t.Fatal(err)
	}
	return testStudy{
		root: root, corpus: corpus, protocol: protocol, preregPath: preregPath,
		goldPath: goldPath, annotationsPath: annotationsPath, adjudicationsPath: adjudicationsPath,
		splitsPath: splitsPath, seal: seal, gold: gold,
		prereg: prereg, splits: splits,
	}
}

func testCapture(scenarioID string, visible []string) Capture {
	decision := "deny"
	if scenarioID == "AB-I-01" {
		decision = "allow"
	}
	return Capture{
		SchemaVersion: CaptureSchema, ScenarioID: scenarioID, CapturedAt: "2026-01-01T00:00:00Z",
		Policy: EvaluationPolicy{
			DefaultDecision: "deny",
			Rules:           []PolicyRule{{ID: "rule-1", Action: "write", Resource: "workspace/result.txt", Decision: decision}},
		},
		Oracle: OracleView{Observations: []Observation{{
			ID: "obs-1", Action: "write", Resource: "workspace/result.txt", Outcome: "created",
		}}},
		Evidence: EvidenceProjection{VisibleObservationIDs: visible, Limitations: []string{"tool boundary only"}},
	}
}

func testAnnotations(scenarioID, oracleHash, evidenceHash, world, sufficiency string) []Annotation {
	base := func(view, annotator, bundle, label string) Annotation {
		return Annotation{
			SchemaVersion: AnnotationSchema, StudyID: testStudyID, ScenarioID: scenarioID,
			View: view, AnnotatorID: annotator, BundleSHA256: bundle, Label: label,
			Rationale: "Applied the frozen rubric to the visible observations.", CreatedAt: "2026-01-01T01:00:00Z",
		}
	}
	return []Annotation{
		base(ViewOracle, "oracle-a", oracleHash, world),
		base(ViewOracle, "oracle-b", oracleHash, world),
		base(ViewEvidence, "evidence-a", evidenceHash, sufficiency),
		base(ViewEvidence, "evidence-b", evidenceHash, sufficiency),
	}
}

func fakeHash(seed string) string {
	return SHA256Bytes([]byte(seed))
}
