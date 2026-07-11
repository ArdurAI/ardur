package independent

const (
	CaptureSchema         = "auditbench.capture.v0.1"
	OracleSchema          = "auditbench.oracle.v0.1"
	EvidenceSchema        = "auditbench.evidence.v0.1"
	LabelBundleSchema     = "auditbench.label_bundle.v0.1"
	AnnotationSchema      = "auditbench.annotation.v0.1"
	AdjudicationSchema    = "auditbench.adjudication.v0.1"
	GoldSetSchema         = "auditbench.gold_set.v0.1"
	PreregistrationSchema = "auditbench.preregistration.v0.1"
	SplitManifestSchema   = "auditbench.split_manifest.v0.1"
	SealSchema            = "auditbench.seal.v0.1"
	SUTResultSchema       = "auditbench.sut_result.v0.1"
	ScoreReportSchema     = "auditbench.score_report.v0.1"
)

const (
	ViewOracle   = "oracle"
	ViewEvidence = "evidence"

	WorldCompliant = "compliant"
	WorldViolation = "violation"
	WorldUnknown   = "unknown"

	EvidenceSufficient   = "sufficient"
	EvidenceInsufficient = "insufficient"

	VerdictCompliant            = "compliant"
	VerdictViolation            = "violation"
	VerdictInsufficientEvidence = "insufficient_evidence"

	SplitDevelopment = "development"
	SplitHeldOut     = "held_out"

	ModePilot    = "pilot"
	ModeHeadline = "headline"
)

type Observation struct {
	ID       string `json:"id"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Outcome  string `json:"outcome"`
}

type PolicyRule struct {
	ID       string `json:"id"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Decision string `json:"decision"`
}

type EvaluationPolicy struct {
	Rules           []PolicyRule `json:"rules"`
	DefaultDecision string       `json:"default_decision"`
}

type Capture struct {
	SchemaVersion string             `json:"schema_version"`
	ScenarioID    string             `json:"scenario_id"`
	CapturedAt    string             `json:"captured_at"`
	Policy        EvaluationPolicy   `json:"policy"`
	Oracle        OracleView         `json:"oracle"`
	Evidence      EvidenceProjection `json:"evidence_projection"`
}

type OracleView struct {
	Observations []Observation `json:"observations"`
	Limitations  []string      `json:"limitations,omitempty"`
}

type EvidenceProjection struct {
	VisibleObservationIDs []string `json:"visible_observation_ids"`
	Limitations           []string `json:"limitations,omitempty"`
}

type OracleArtifact struct {
	SchemaVersion string           `json:"schema_version"`
	ScenarioID    string           `json:"scenario_id"`
	CapturedAt    string           `json:"captured_at"`
	Policy        EvaluationPolicy `json:"policy"`
	Observations  []Observation    `json:"observations"`
	Limitations   []string         `json:"limitations,omitempty"`
	CaptureSHA256 string           `json:"capture_sha256"`
}

type EvidenceArtifact struct {
	SchemaVersion string           `json:"schema_version"`
	ScenarioID    string           `json:"scenario_id"`
	CapturedAt    string           `json:"captured_at"`
	Policy        EvaluationPolicy `json:"policy"`
	Observations  []Observation    `json:"observations"`
	Limitations   []string         `json:"limitations,omitempty"`
	CaptureSHA256 string           `json:"capture_sha256"`
}

type LabelBundle struct {
	SchemaVersion string           `json:"schema_version"`
	StudyID       string           `json:"study_id"`
	ScenarioID    string           `json:"scenario_id"`
	View          string           `json:"view"`
	SourceSHA256  string           `json:"source_sha256"`
	CapturedAt    string           `json:"captured_at"`
	Policy        EvaluationPolicy `json:"policy"`
	Observations  []Observation    `json:"observations"`
	Limitations   []string         `json:"limitations,omitempty"`
	Rubric        AnnotationRubric `json:"rubric"`
}

type AnnotationRubric struct {
	AllowedLabels []string `json:"allowed_labels"`
	Question      string   `json:"question"`
}

type Annotation struct {
	SchemaVersion string `json:"schema_version"`
	StudyID       string `json:"study_id"`
	ScenarioID    string `json:"scenario_id"`
	View          string `json:"view"`
	AnnotatorID   string `json:"annotator_id"`
	BundleSHA256  string `json:"bundle_sha256"`
	Label         string `json:"label"`
	Rationale     string `json:"rationale"`
	CreatedAt     string `json:"created_at"`
}

type Adjudication struct {
	SchemaVersion string `json:"schema_version"`
	StudyID       string `json:"study_id"`
	ScenarioID    string `json:"scenario_id"`
	View          string `json:"view"`
	AdjudicatorID string `json:"adjudicator_id"`
	FinalLabel    string `json:"final_label"`
	Rationale     string `json:"rationale"`
	CreatedAt     string `json:"created_at"`
}

type Agreement struct {
	View              string  `json:"view"`
	Items             int     `json:"items"`
	Ratings           int     `json:"ratings"`
	PairwiseAgreement float64 `json:"pairwise_agreement"`
	Kappa             float64 `json:"kappa"`
}

type GoldRecord struct {
	ScenarioID           string `json:"scenario_id"`
	OracleBundleSHA256   string `json:"oracle_bundle_sha256"`
	EvidenceBundleSHA256 string `json:"evidence_bundle_sha256"`
	WorldTruth           string `json:"world_truth"`
	EvidenceSufficiency  string `json:"evidence_sufficiency"`
	GoldVerdict          string `json:"gold_verdict"`
}

type GoldSet struct {
	SchemaVersion            string       `json:"schema_version"`
	StudyID                  string       `json:"study_id"`
	MinimumAnnotatorsPerView int          `json:"minimum_annotators_per_view"`
	AnnotationsSHA256        string       `json:"annotations_sha256"`
	Records                  []GoldRecord `json:"records"`
	Agreement                []Agreement  `json:"agreement"`
}

type Preregistration struct {
	SchemaVersion             string   `json:"schema_version"`
	StudyID                   string   `json:"study_id"`
	Mode                      string   `json:"mode"`
	ProtocolSHA256            string   `json:"protocol_sha256"`
	RegistrationURI           string   `json:"registration_uri,omitempty"`
	RegisteredAt              string   `json:"registered_at"`
	Metrics                   []string `json:"metrics"`
	MinimumAnnotatorsPerView  int      `json:"minimum_annotators_per_view"`
	HeldOutMinimumBasisPoints int      `json:"held_out_minimum_basis_points"`
	AllowedSUTs               []string `json:"allowed_suts"`
}

type SplitRecord struct {
	ScenarioID string `json:"scenario_id"`
	Split      string `json:"split"`
}

type SplitManifest struct {
	SchemaVersion string        `json:"schema_version"`
	StudyID       string        `json:"study_id"`
	Records       []SplitRecord `json:"records"`
}

type FileDigest struct {
	Path   string `json:"path"`
	Role   string `json:"role"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type Seal struct {
	SchemaVersion   string       `json:"schema_version"`
	StudyID         string       `json:"study_id"`
	Mode            string       `json:"mode"`
	SealedAt        string       `json:"sealed_at"`
	Protocol        FileDigest   `json:"protocol"`
	Preregistration FileDigest   `json:"preregistration"`
	Gold            FileDigest   `json:"gold"`
	Annotations     FileDigest   `json:"annotations"`
	Adjudications   FileDigest   `json:"adjudications"`
	Splits          FileDigest   `json:"splits"`
	Corpus          []FileDigest `json:"corpus"`
	RootSHA256      string       `json:"root_sha256"`
}

type Prediction struct {
	ScenarioID string `json:"scenario_id"`
	Verdict    string `json:"verdict"`
}

type SUTResult struct {
	SchemaVersion string       `json:"schema_version"`
	StudyID       string       `json:"study_id"`
	SUTID         string       `json:"sut_id"`
	SealSHA256    string       `json:"seal_sha256"`
	CreatedAt     string       `json:"created_at"`
	Predictions   []Prediction `json:"predictions"`
}

type ClassMetrics struct {
	Label     string   `json:"label"`
	Support   int      `json:"support"`
	Predicted int      `json:"predicted"`
	Precision *float64 `json:"precision"`
	Recall    *float64 `json:"recall"`
	F1        *float64 `json:"f1"`
}

type ScoreReport struct {
	SchemaVersion           string         `json:"schema_version"`
	StudyID                 string         `json:"study_id"`
	SUTID                   string         `json:"sut_id"`
	SealSHA256              string         `json:"seal_sha256"`
	SUTResultSHA256         string         `json:"sut_result_sha256"`
	Split                   string         `json:"split"`
	Scenarios               int            `json:"scenarios"`
	Correct                 int            `json:"correct"`
	Accuracy                float64        `json:"accuracy"`
	FalseSafeCount          int            `json:"false_safe_count"`
	FalseSafeEligible       int            `json:"false_safe_eligible"`
	FalseSafeRate           *float64       `json:"false_safe_rate"`
	MissedViolationCount    int            `json:"missed_violation_count"`
	MissedViolationEligible int            `json:"missed_violation_eligible"`
	MissedViolationRate     *float64       `json:"missed_violation_rate"`
	OverAbstentionCount     int            `json:"over_abstention_count"`
	OverAbstentionEligible  int            `json:"over_abstention_eligible"`
	OverAbstentionRate      *float64       `json:"over_abstention_rate"`
	Classes                 []ClassMetrics `json:"classes"`
}
