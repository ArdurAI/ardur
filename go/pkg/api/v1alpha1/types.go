// Package v1alpha1 defines the AgentPassport CRD types for the VIBAP operator.
package v1alpha1

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	GroupName = "ardur.dev"
	Version   = "v1alpha1"

	AnnotationCredential = "vibap.ardur.dev/credential" // #nosec G101 -- Kubernetes annotation key, not a secret
	AnnotationTrustTier  = "vibap.ardur.dev/trust-tier"
	AnnotationCompliance = "vibap.ardur.dev/compliance-level"

	LabelManagedBy = "vibap.ardur.dev/managed-by"
	LabelTrustTier = "vibap.ardur.dev/trust-tier"

	FinalizerName = "vibap.ardur.dev/cleanup"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ap;aps
// +kubebuilder:printcolumn:name="Compliance",type=string,JSONPath=`.status.complianceLevel`
// +kubebuilder:printcolumn:name="Trust Tier",type=string,JSONPath=`.status.trustTier`
// +kubebuilder:printcolumn:name="Score",type=number,JSONPath=`.status.compositeScore`
// +kubebuilder:printcolumn:name="Expires",type=date,JSONPath=`.status.expiresAt`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AgentPassport declares the desired security posture for an AI agent workload.
// The VIBAP operator watches these resources, issues SD-JWT-VC credentials,
// and manages the agent's lifecycle through trust tiers.
type AgentPassport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AgentPassportSpec   `json:"spec,omitempty"`
	Status AgentPassportStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AgentPassportList contains a list of AgentPassport resources.
type AgentPassportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AgentPassport `json:"items"`
}

// AgentPassportSpec defines the desired state of an agent's security posture.
type AgentPassportSpec struct {
	// Identity configures Layer 1 (SPIFFE/SPIRE workload identity).
	Identity IdentitySpec `json:"identity"`

	// Provenance configures Layer 2 (Sigstore supply chain verification).
	// +optional
	Provenance *ProvenanceSpec `json:"provenance,omitempty"`

	// Intent configures Layer 3 (Cedar policy binding).
	Intent IntentSpec `json:"intent"`

	// Baseline configures Layer 4 (Kubescape/Tetragon behavioral profiling).
	// +optional
	Baseline *BaselineSpec `json:"baseline,omitempty"`

	// Trust configures Layer 5 (dynamic trust scoring).
	Trust TrustSpec `json:"trust"`

	// Credential configures the SD-JWT-VC credential parameters.
	Credential CredentialSpec `json:"credential"`

	// Governance configures runtime mission-bound governance.
	// +optional
	Governance *GovernanceSpec `json:"governance,omitempty"`

	// Selector identifies the pods this passport applies to.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// IdentitySpec configures Layer 1 identity binding.
type IdentitySpec struct {
	// SPIFFEID is the expected SPIFFE ID for the agent workload.
	// If empty, the operator fetches it from the SPIRE agent.
	// +optional
	SPIFFEID string `json:"spiffeID,omitempty"`

	// OwnerID is SPIFFE-formatted deployer attribution. It is self-asserted;
	// UseSpire authenticates the workload SVID, not this ownership relation.
	OwnerID string `json:"ownerID"`

	// A2ACardRef is a URL to the agent's A2A Agent Card.
	// +optional
	A2ACardRef string `json:"a2aCardRef,omitempty"`

	// UseSpire enables automatic SPIFFE ID fetching from the SPIRE agent.
	// +optional
	UseSpire bool `json:"useSpire,omitempty"`
}

// ProvenanceSpec configures Layer 2 supply chain verification.
type ProvenanceSpec struct {
	// ImageRef is the OCI image reference to verify.
	// +optional
	ImageRef string `json:"imageRef,omitempty"`

	// BundlePath is the Sigstore bundle path for offline verification.
	// +optional
	BundlePath string `json:"bundlePath,omitempty"`

	// ModelHash is the expected SHA-256 hash of AI model weights.
	// +optional
	ModelHash string `json:"modelHash,omitempty"`

	// RequireSLSA requires SLSA provenance attestation.
	// +optional
	RequireSLSA bool `json:"requireSLSA,omitempty"`
}

// IntentSpec configures Layer 3 policy binding.
type IntentSpec struct {
	// PolicyRef references a ConfigMap containing Cedar policy text.
	// +optional
	PolicyRef *PolicyReference `json:"policyRef,omitempty"`

	// InlinePolicy contains Cedar policy text directly.
	// +optional
	InlinePolicy string `json:"inlinePolicy,omitempty"`

	// SystemPrompt is the agent's system prompt for checksum computation.
	// +optional
	SystemPrompt string `json:"systemPrompt,omitempty"`

	// ToolManifest is the agent's tool manifest for checksum computation.
	// +optional
	ToolManifest string `json:"toolManifest,omitempty"`

	// PermittedActions is an explicit allowlist of actions the agent may take.
	PermittedActions []string `json:"permittedActions"`
}

// PolicyReference points to a ConfigMap containing Cedar policy.
type PolicyReference struct {
	// Name of the ConfigMap.
	Name string `json:"name"`
	// Key within the ConfigMap data. Defaults to "policy.cedar".
	// +optional
	Key string `json:"key,omitempty"`
}

// BaselineSpec configures Layer 4 behavioral profiling.
type BaselineSpec struct {
	// ProfileMode controls how the behavioral profile is obtained.
	// "learn" generates a new profile; "enforce" uses the frozen baseline.
	// +kubebuilder:validation:Enum=learn;enforce
	// +kubebuilder:default=learn
	ProfileMode string `json:"profileMode,omitempty"`

	// MaxDelegationDepth limits how many hops an agent can delegate.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=3
	MaxDelegationDepth int `json:"maxDelegationDepth,omitempty"`

	// TetragonPolicy enables Tetragon eBPF enforcement.
	// +optional
	TetragonPolicy bool `json:"tetragonPolicy,omitempty"`
}

// TrustSpec configures Layer 5 trust scoring.
type TrustSpec struct {
	// StaticCapabilityScore is the declared capability score (0.0-1.0).
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1
	StaticCapabilityScore float64 `json:"staticCapabilityScore"`

	// HistoricalReputation is the initial reputation score (0.0-1.0).
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1
	HistoricalReputation float64 `json:"historicalReputation"`

	// Thresholds override the default trust tier boundaries.
	// +optional
	Thresholds *TrustThresholds `json:"thresholds,omitempty"`
}

// TrustThresholds defines the boundaries between trust tiers.
type TrustThresholds struct {
	// FullTier is the minimum composite score for full access. Default: 70.
	// +optional
	FullTier *float64 `json:"fullTier,omitempty"`
	// LimitedTier is the minimum composite score for limited access. Default: 40.
	// +optional
	LimitedTier *float64 `json:"limitedTier,omitempty"`
}

// CredentialSpec configures the SD-JWT-VC credential parameters.
type CredentialSpec struct {
	// TTL is the credential time-to-live. Default: 1h.
	// +optional
	TTL *metav1.Duration `json:"ttl,omitempty"`

	// RenewBefore is how long before expiry to renew. Default: 10m.
	// +optional
	RenewBefore *metav1.Duration `json:"renewBefore,omitempty"`

	// SelectiveDisclosure lists layer names to selectively disclose.
	// Valid values: "provenance", "baseline".
	// +optional
	SelectiveDisclosure []string `json:"selectiveDisclosure,omitempty"`

	// StatusListURI is the Token Status List endpoint.
	// +optional
	StatusListURI string `json:"statusListURI,omitempty"`
}

// GovernanceSpec configures runtime mission-bound governance.
type GovernanceSpec struct {
	// Enabled activates runtime governance for this agent.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Mode controls enforcement behavior: "monitor" logs findings,
	// "enforce" triggers containment actions.
	// +kubebuilder:validation:Enum=monitor;enforce
	// +kubebuilder:default=monitor
	Mode string `json:"mode,omitempty"`

	// DeclarationRef references a ConfigMap containing the mission declaration JSON.
	// +optional
	DeclarationRef *DeclarationReference `json:"declarationRef,omitempty"`

	// InlineDeclaration contains the mission declaration directly.
	// +optional
	InlineDeclaration *InlineDeclaration `json:"inlineDeclaration,omitempty"`

	// GovernorURL is the endpoint of the governance service.
	// +optional
	GovernorURL string `json:"governorURL,omitempty"`

	// CollectorURL is the endpoint that receives runtime events from the agent sidecar.
	// +optional
	CollectorURL string `json:"collectorURL,omitempty"`

	// SessionTTL is how long a governance session stays active. Default: 24h.
	// +optional
	SessionTTL *metav1.Duration `json:"sessionTTL,omitempty"`

	// EnforcementPolicy controls what happens on violation.
	// +optional
	EnforcementPolicy *EnforcementPolicy `json:"enforcementPolicy,omitempty"`

	// EmitRuntimeEvents controls whether the operator creates Kubernetes Events for governance findings.
	// +kubebuilder:default=true
	EmitRuntimeEvents bool `json:"emitRuntimeEvents,omitempty"`
}

// DeclarationReference points to a ConfigMap containing a mission declaration.
type DeclarationReference struct {
	Name string `json:"name"`
	// +optional
	Key string `json:"key,omitempty"`
}

// InlineDeclaration specifies what an agent is permitted to do, embedded directly in the CR.
type InlineDeclaration struct {
	AllowedActions          []string          `json:"allowedActions"`
	AllowedTools            []string          `json:"allowedTools"`
	AllowedResources        []string          `json:"allowedResources,omitempty"`
	AllowedResourceFamilies []string          `json:"allowedResourceFamilies,omitempty"`
	AllowedSideEffects      []string          `json:"allowedSideEffects,omitempty"`
	MaxDelegationDepth      int               `json:"maxDelegationDepth,omitempty"`
	MaxTotalDelegations     int               `json:"maxTotalDelegations,omitempty"`
	MaxSiblingDelegations   int               `json:"maxSiblingDelegations,omitempty"`
	Metadata                map[string]string `json:"metadata,omitempty"`
}

// EnforcementPolicy controls violation handling.
type EnforcementPolicy struct {
	// OnViolation specifies the action: "log", "alert", "quarantine", "terminate"
	// +kubebuilder:validation:Enum=log;alert;quarantine;terminate
	// +kubebuilder:default=alert
	OnViolation string `json:"onViolation,omitempty"`

	// GracePeriod is how long to wait before escalating enforcement.
	// +optional
	GracePeriod *metav1.Duration `json:"gracePeriod,omitempty"`

	// MaxViolations is the threshold before automatic escalation.
	// +kubebuilder:default=3
	MaxViolations int `json:"maxViolations,omitempty"`
}

// GovernanceStatus reports the observed governance state.
type GovernanceStatus struct {
	// SessionID is the active governance session identifier.
	SessionID string `json:"sessionID,omitempty"`

	// LastDecision is the most recent governance decision.
	LastDecision string `json:"lastDecision,omitempty"`

	// LastDecisionTime is when the last decision was made.
	LastDecisionTime *metav1.Time `json:"lastDecisionTime,omitempty"`

	// FindingCount is the total number of findings in the current session.
	FindingCount int `json:"findingCount,omitempty"`

	// ViolationCount is the total violation findings.
	ViolationCount int `json:"violationCount,omitempty"`

	// GovernancePhase tracks the session lifecycle.
	GovernancePhase string `json:"governancePhase,omitempty"`

	// RecommendedAction is the latest containment recommendation.
	RecommendedAction string `json:"recommendedAction,omitempty"`

	// LastEventID is the ID of the most recently processed event.
	LastEventID string `json:"lastEventID,omitempty"`

	// DeclarationHash is the SHA-256 of the active mission declaration.
	DeclarationHash string `json:"declarationHash,omitempty"`
}

// AgentPassportStatus is the observed state of the agent's security posture.
type AgentPassportStatus struct {
	// ComplianceLevel is the achieved compliance level: core, verified, or enforced.
	// +optional
	ComplianceLevel string `json:"complianceLevel,omitempty"`

	// TrustTier is the current trust tier: full, limited, or quarantine.
	// +optional
	TrustTier string `json:"trustTier,omitempty"`

	// CompositeScore is the current trust score (0-100).
	// +optional
	CompositeScore float64 `json:"compositeScore,omitempty"`

	// Credential is the encoded SD-JWT-VC credential string.
	// +optional
	Credential string `json:"credential,omitempty"`

	// ExpiresAt is when the current credential expires.
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`

	// IssuedAt is when the current credential was issued.
	// +optional
	IssuedAt *metav1.Time `json:"issuedAt,omitempty"`

	// LogIndex is the transparency log index of the issuance event.
	// +optional
	LogIndex *int64 `json:"logIndex,omitempty"`

	// PolicyHash is the SHA-256 hash of the compiled Cedar policy.
	// +optional
	PolicyHash string `json:"policyHash,omitempty"`

	// ProfileHash is the SHA-256 hash of the behavioral baseline.
	// +optional
	ProfileHash string `json:"profileHash,omitempty"`

	// ObservedGeneration is the .metadata.generation that was last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Governance holds the observed governance state.
	// +optional
	Governance *GovernanceStatus `json:"governance,omitempty"`

	// Conditions represent the latest available observations of the resource's state.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Condition types for AgentPassport.
const (
	ConditionReady            = "Ready"
	ConditionCredentialIssued = "CredentialIssued" // #nosec G101 -- Status condition name, not a secret
	ConditionPolicyCompiled   = "PolicyCompiled"
	ConditionBaselineReady    = "BaselineReady"
	ConditionTrustScored      = "TrustScored"
	ConditionGovernanceReady  = "GovernanceReady"
)

// Condition reasons.
const (
	ReasonReconciling        = "Reconciling"
	ReasonIssued             = "Issued"
	ReasonFailed             = "Failed"
	ReasonExpired            = "Expired"
	ReasonRenewing           = "Renewing"
	ReasonPolicyInvalid      = "PolicyInvalid"
	ReasonTierChanged        = "TierChanged"
	ReasonGovernanceEnabled  = "GovernanceEnabled"
	ReasonGovernanceDisabled = "GovernanceDisabled"
	ReasonGovernanceInvalid  = "GovernanceInvalid"
)

var allowedGovernanceSideEffects = map[string]struct{}{
	"none":           {},
	"internal_write": {},
	"external_send":  {},
	"state_change":   {},
}

// Validate checks whether the governance configuration is internally consistent.
func (g *GovernanceSpec) Validate() error {
	if g == nil || !g.Enabled {
		return nil
	}

	if g.Mode != "" && g.Mode != "monitor" && g.Mode != "enforce" {
		return fmt.Errorf("invalid governance mode %q", g.Mode)
	}

	hasInline := g.InlineDeclaration != nil
	hasRef := g.DeclarationRef != nil
	switch {
	case hasInline && hasRef:
		return fmt.Errorf("set only one of inlineDeclaration or declarationRef when governance is enabled")
	case !hasInline && !hasRef:
		return fmt.Errorf("governance.enabled requires inlineDeclaration or declarationRef")
	}

	if hasInline {
		if err := g.InlineDeclaration.Validate(); err != nil {
			return err
		}
	}
	if hasRef {
		if strings.TrimSpace(g.DeclarationRef.Name) == "" {
			return fmt.Errorf("declarationRef.name is required when governance is enabled")
		}
	}
	if g.EnforcementPolicy != nil {
		if g.EnforcementPolicy.OnViolation != "" {
			switch g.EnforcementPolicy.OnViolation {
			case "log", "alert", "quarantine", "terminate":
			default:
				return fmt.Errorf("invalid enforcementPolicy.onViolation %q", g.EnforcementPolicy.OnViolation)
			}
		}
		if g.EnforcementPolicy.MaxViolations < 0 {
			return fmt.Errorf("enforcementPolicy.maxViolations must be non-negative")
		}
	}

	return nil
}

// Validate checks whether an inline declaration is well-formed for operator use.
func (d *InlineDeclaration) Validate() error {
	if d == nil {
		return fmt.Errorf("inlineDeclaration is required")
	}
	if err := validateStringSlice("allowedActions", d.AllowedActions, true); err != nil {
		return err
	}
	if err := validateStringSlice("allowedTools", d.AllowedTools, true); err != nil {
		return err
	}
	if err := validateStringSlice("allowedResources", d.AllowedResources, false); err != nil {
		return err
	}
	if err := validateStringSlice("allowedResourceFamilies", d.AllowedResourceFamilies, false); err != nil {
		return err
	}
	if err := validateStringSlice("allowedSideEffects", d.AllowedSideEffects, false); err != nil {
		return err
	}
	for _, value := range d.AllowedSideEffects {
		if _, ok := allowedGovernanceSideEffects[strings.TrimSpace(value)]; !ok {
			return fmt.Errorf("allowedSideEffects contains unsupported value %q", value)
		}
	}
	if d.MaxDelegationDepth < 0 {
		return fmt.Errorf("maxDelegationDepth must be non-negative")
	}
	if d.MaxTotalDelegations < 0 {
		return fmt.Errorf("maxTotalDelegations must be non-negative")
	}
	if d.MaxSiblingDelegations < 0 {
		return fmt.Errorf("maxSiblingDelegations must be non-negative")
	}
	for key := range d.Metadata {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("metadata keys must be non-empty")
		}
	}
	return nil
}

func validateStringSlice(field string, values []string, required bool) error {
	if required && len(values) == 0 {
		return fmt.Errorf("%s must not be empty", field)
	}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s must not contain empty values", field)
		}
	}
	return nil
}
