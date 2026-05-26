package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sevents "k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	vibapv1alpha1 "github.com/ArdurAI/ardur/go/pkg/api/v1alpha1"
	"github.com/ArdurAI/ardur/go/pkg/credential"
	"github.com/ArdurAI/ardur/go/pkg/issuer"
	"github.com/ArdurAI/ardur/go/pkg/transparency"
	"github.com/ArdurAI/ardur/go/pkg/trust"
)

const (
	defaultTTL                      = 1 * time.Hour
	defaultRenewBefore              = 10 * time.Minute
	defaultGovernanceDeclarationKey = "declaration.json"
	maxStatusRetries                = 3
	maxStatusLogIndex               = uint64(1<<63 - 1)
)

// AgentPassportReconciler reconciles AgentPassport resources.
type AgentPassportReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Recorder  k8sevents.EventRecorder
	issuer    *issuer.Issuer
	transLog  transparency.TransparencyLog
	trustAgg  trust.ScoreAggregator
	issuerURI string
}

// NewAgentPassportReconciler creates a reconciler with the signing key and issuer pipeline.
//
// FIX-R9-6 (round-9, 2026-04-29): when ``signingKeyPath`` is empty,
// the constructor refuses to start unless ``allowEphemeralKey=true``
// is passed explicitly. Round-8 audit (LOW-NEW-6) flagged that the
// previous warn-only path silently issued credentials no consumer
// could verify across pod restarts — same shape as the Authority's
// ``--no-require-auth`` foot-gun, just with no opt-in flag making
// the choice visible. Now ephemeral behaviour requires an opt-in.
func NewAgentPassportReconciler(c client.Client, scheme *runtime.Scheme, signingKeyPath, issuerURI string, allowEphemeralKey bool) (*AgentPassportReconciler, error) {
	var signingKey *credential.SigningKey

	if signingKeyPath != "" {
		key, err := loadSigningKey(signingKeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading signing key: %w", err)
		}
		signingKey = key
	} else {
		if !allowEphemeralKey {
			return nil, fmt.Errorf(
				"operator startup refused: --signing-key is empty and " +
					"--allow-ephemeral-key was not set. Production " +
					"deployments MUST supply a persistent signing key " +
					"(credentials issued under an ephemeral key cannot " +
					"be verified across pod restarts). Pass " +
					"--allow-ephemeral-key only for explicit local-dev " +
					"or single-pod test deployments")
		}
		setupLog := ctrl.Log.WithName("setup")
		setupLog.Info("WARNING: no --signing-key provided; --allow-ephemeral-key set; generating ephemeral key. Credentials will NOT survive operator restart. DO NOT use in production.")
		_, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, fmt.Errorf("generating ephemeral key: %w", err)
		}
		signingKey = &credential.SigningKey{
			PrivateKey: priv,
			PublicKey:  priv.Public().(ed25519.PublicKey),
			KeyID:      "vibap-operator-ephemeral",
		}
	}

	tlog := transparency.NewInMemoryLog()
	trustAgg, err := trust.NewInMemoryAggregator()
	if err != nil {
		return nil, fmt.Errorf("creating trust aggregator: %w", err)
	}

	iss, err := issuer.NewIssuer(signingKey, issuerURI,
		issuer.WithTransparencyLog(tlog),
		issuer.WithTrustAggregator(trustAgg),
	)
	if err != nil {
		return nil, fmt.Errorf("creating issuer: %w", err)
	}

	return &AgentPassportReconciler{
		Client:    c,
		Scheme:    scheme,
		issuer:    iss,
		transLog:  tlog,
		trustAgg:  trustAgg,
		issuerURI: issuerURI,
	}, nil
}

// SetupWithManager wires event recording after the manager is ready.
func (r *AgentPassportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Recorder = mgr.GetEventRecorder("vibap-operator")
	return ctrl.NewControllerManagedBy(mgr).
		For(&vibapv1alpha1.AgentPassport{}).
		Complete(r)
}

// Reconcile handles a single reconciliation loop for an AgentPassport resource.
func (r *AgentPassportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var ap vibapv1alpha1.AgentPassport
	if err := r.Get(ctx, req.NamespacedName, &ap); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Handle finalizer for cleanup on deletion.
	if ap.DeletionTimestamp != nil {
		if controllerutil.ContainsFinalizer(&ap, vibapv1alpha1.FinalizerName) {
			logger.Info("running finalizer cleanup")
			// Cleanup: revoke credential in status list, remove transparency log entry, etc.
			// Currently a no-op — real revocation is Phase 6+.
			controllerutil.RemoveFinalizer(&ap, vibapv1alpha1.FinalizerName)
			if err := r.Update(ctx, &ap); err != nil {
				return ctrl.Result{}, fmt.Errorf("removing finalizer: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}

	// Ensure finalizer is present.
	if !controllerutil.ContainsFinalizer(&ap, vibapv1alpha1.FinalizerName) {
		controllerutil.AddFinalizer(&ap, vibapv1alpha1.FinalizerName)
		if err := r.Update(ctx, &ap); err != nil {
			return ctrl.Result{}, fmt.Errorf("adding finalizer: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if needsCredential(&ap) {
		return r.issueCredential(ctx, &ap)
	}

	if needsRenewal(&ap) {
		logger.Info("credential nearing expiry, renewing",
			"expiresAt", ap.Status.ExpiresAt,
		)
		r.recordEvent(&ap, corev1.EventTypeNormal, "Renewing", "Credential nearing expiry, renewing")
		return r.issueCredential(ctx, &ap)
	}

	return r.scheduleNextReconcile(&ap), nil
}

func (r *AgentPassportReconciler) issueCredential(ctx context.Context, ap *vibapv1alpha1.AgentPassport) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	setCondition(ap, vibapv1alpha1.ConditionReady, metav1.ConditionFalse,
		vibapv1alpha1.ReasonReconciling, "Issuing credential")

	policyText := ap.Spec.Intent.InlinePolicy
	if policyText == "" && ap.Spec.Intent.PolicyRef != nil {
		var err error
		policyText, err = r.loadPolicyFromConfigMap(ctx, ap.Namespace, ap.Spec.Intent.PolicyRef)
		if err != nil {
			return r.setFailed(ctx, ap, "PolicyLoad", err)
		}
	}
	if policyText == "" {
		err := fmt.Errorf("no policy provided: set spec.intent.inlinePolicy or spec.intent.policyRef")
		r.recordEvent(ap, corev1.EventTypeWarning, "PolicyMissing", err.Error())
		return r.setFailed(ctx, ap, "PolicyMissing", err)
	}

	agentID := ap.Spec.Identity.SPIFFEID
	if agentID == "" {
		agentID = fmt.Sprintf("spiffe://ardur.dev/ns/%s/agent/%s", ap.Namespace, ap.Name)
	}

	if err := r.ensureAgentRegistered(ctx, agentID, ap.Spec.Trust); err != nil {
		logger.V(1).Info("trust registration note", "detail", err.Error())
	}

	ttl := defaultTTL
	if ap.Spec.Credential.TTL != nil {
		ttl = ap.Spec.Credential.TTL.Duration
	}

	issueReq := issuer.IssueRequest{
		SPIFFEID:          agentID,
		OwnerID:           ap.Spec.Identity.OwnerID,
		A2ACardRef:        ap.Spec.Identity.A2ACardRef,
		PolicyText:        policyText,
		SystemPrompt:      ap.Spec.Intent.SystemPrompt,
		ToolManifest:      ap.Spec.Intent.ToolManifest,
		PermittedActions:  ap.Spec.Intent.PermittedActions,
		AgentID:           agentID,
		TTL:               ttl,
		SelectiveDisclose: ap.Spec.Credential.SelectiveDisclosure,
		StatusURI:         ap.Spec.Credential.StatusListURI,
	}

	if ap.Spec.Provenance != nil {
		issueReq.ImageRef = ap.Spec.Provenance.ImageRef
		issueReq.BundlePath = ap.Spec.Provenance.BundlePath
		issueReq.ModelHash = ap.Spec.Provenance.ModelHash
	}

	result, err := r.issuer.Issue(ctx, issueReq)
	if err != nil {
		r.recordEvent(ap, corev1.EventTypeWarning, "IssueFailed", "Credential issuance failed: %s", err.Error())
		return r.setFailed(ctx, ap, "IssueFailed", err)
	}

	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(ttl))

	ap.Status.Credential = result.Encoded
	ap.Status.ComplianceLevel = string(result.ComplianceLevel)
	ap.Status.IssuedAt = &now
	ap.Status.ExpiresAt = &expiresAt
	ap.Status.ObservedGeneration = ap.Generation

	if result.LogIndex != nil {
		if *result.LogIndex > maxStatusLogIndex {
			return ctrl.Result{}, fmt.Errorf("transparency log index %d exceeds int64 status field", *result.LogIndex)
		}
		idx := int64(*result.LogIndex)
		ap.Status.LogIndex = &idx
	}

	if result.Credential != nil && result.Credential.Claims.Trust != nil {
		ap.Status.TrustTier = result.Credential.Claims.Trust.AuthorizationTier
		ap.Status.CompositeScore = result.Credential.Claims.Trust.CompositeScore
	}

	governanceErr := r.reconcileGovernance(ctx, ap)

	setCondition(ap, vibapv1alpha1.ConditionCredentialIssued, metav1.ConditionTrue,
		vibapv1alpha1.ReasonIssued, fmt.Sprintf("Credential issued at compliance level %s", result.ComplianceLevel))
	if governanceErr != nil {
		setCondition(ap, vibapv1alpha1.ConditionReady, metav1.ConditionFalse,
			vibapv1alpha1.ReasonGovernanceInvalid, governanceErr.Error())
	} else {
		setCondition(ap, vibapv1alpha1.ConditionReady, metav1.ConditionTrue,
			vibapv1alpha1.ReasonIssued, "Agent passport ready")
	}

	if err := r.updateStatusWithRetry(ctx, ap); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	r.recordEvent(ap, corev1.EventTypeNormal, "Issued",
		"Credential issued: compliance=%s tier=%s score=%.1f",
		result.ComplianceLevel, ap.Status.TrustTier, ap.Status.CompositeScore)

	logger.Info("credential issued",
		"compliance", result.ComplianceLevel,
		"trustTier", ap.Status.TrustTier,
		"score", ap.Status.CompositeScore,
		"expiresAt", expiresAt.Format(time.RFC3339),
	)

	if governanceErr != nil {
		r.recordEvent(ap, corev1.EventTypeWarning, "GovernanceInvalid", governanceErr.Error())
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	return r.scheduleNextReconcile(ap), nil
}

func (r *AgentPassportReconciler) ensureAgentRegistered(ctx context.Context, agentID string, trustSpec vibapv1alpha1.TrustSpec) error {
	return r.trustAgg.RegisterAgent(ctx, agentID,
		trustSpec.StaticCapabilityScore,
		trustSpec.HistoricalReputation,
	)
}

func (r *AgentPassportReconciler) loadPolicyFromConfigMap(ctx context.Context, ns string, ref *vibapv1alpha1.PolicyReference) (string, error) {
	var cm corev1.ConfigMap
	key := client.ObjectKey{Namespace: ns, Name: ref.Name}
	if err := r.Get(ctx, key, &cm); err != nil {
		return "", fmt.Errorf("getting policy ConfigMap %s: %w", ref.Name, err)
	}

	dataKey := ref.Key
	if dataKey == "" {
		dataKey = "policy.cedar"
	}
	text, ok := cm.Data[dataKey]
	if !ok {
		return "", fmt.Errorf("key %q not found in ConfigMap %s", dataKey, ref.Name)
	}
	return text, nil
}

func (r *AgentPassportReconciler) setFailed(ctx context.Context, ap *vibapv1alpha1.AgentPassport, reason string, err error) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Error(err, "reconciliation failed", "reason", reason)

	setCondition(ap, vibapv1alpha1.ConditionReady, metav1.ConditionFalse,
		vibapv1alpha1.ReasonFailed, err.Error())
	ap.Status.ObservedGeneration = ap.Generation

	if updateErr := r.updateStatusWithRetry(ctx, ap); updateErr != nil {
		logger.Error(updateErr, "failed to update status after error")
	}

	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// updateStatusWithRetry retries status updates on conflict.
func (r *AgentPassportReconciler) updateStatusWithRetry(ctx context.Context, ap *vibapv1alpha1.AgentPassport) error {
	for attempt := 0; attempt < maxStatusRetries; attempt++ {
		err := r.Status().Update(ctx, ap)
		if err == nil {
			return nil
		}
		if !apierrors.IsConflict(err) {
			return err
		}

		// Re-fetch and re-apply status fields on conflict.
		fresh := &vibapv1alpha1.AgentPassport{}
		if getErr := r.Get(ctx, client.ObjectKeyFromObject(ap), fresh); getErr != nil {
			return getErr
		}
		fresh.Status = ap.Status
		ap = fresh
	}
	return fmt.Errorf("status update failed after %d retries", maxStatusRetries)
}

func (r *AgentPassportReconciler) scheduleNextReconcile(ap *vibapv1alpha1.AgentPassport) ctrl.Result {
	if ap.Status.ExpiresAt == nil {
		return ctrl.Result{RequeueAfter: 30 * time.Second}
	}

	renewBefore := defaultRenewBefore
	if ap.Spec.Credential.RenewBefore != nil {
		renewBefore = ap.Spec.Credential.RenewBefore.Duration
	}

	renewAt := ap.Status.ExpiresAt.Add(-renewBefore)
	delay := time.Until(renewAt)
	if delay < 0 {
		delay = 0
	}
	return ctrl.Result{RequeueAfter: delay}
}

// recordEvent emits a Kubernetes event if the recorder is available.
func (r *AgentPassportReconciler) recordEvent(ap *vibapv1alpha1.AgentPassport, eventType, reason, messageFmt string, args ...interface{}) {
	if r.Recorder != nil {
		r.Recorder.Eventf(ap, nil, eventType, reason, reason, messageFmt, args...)
	}
}

func needsCredential(ap *vibapv1alpha1.AgentPassport) bool {
	return ap.Status.Credential == "" ||
		ap.Status.ObservedGeneration != ap.Generation
}

func needsRenewal(ap *vibapv1alpha1.AgentPassport) bool {
	if ap.Status.ExpiresAt == nil {
		return false
	}

	renewBefore := defaultRenewBefore
	if ap.Spec.Credential.RenewBefore != nil {
		renewBefore = ap.Spec.Credential.RenewBefore.Duration
	}

	return time.Until(ap.Status.ExpiresAt.Time) < renewBefore
}

func setCondition(ap *vibapv1alpha1.AgentPassport, condType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	for i, c := range ap.Status.Conditions {
		if c.Type == condType {
			if c.Status != status {
				ap.Status.Conditions[i].LastTransitionTime = now
			}
			ap.Status.Conditions[i].Status = status
			ap.Status.Conditions[i].Reason = reason
			ap.Status.Conditions[i].Message = message
			ap.Status.Conditions[i].ObservedGeneration = ap.Generation
			return
		}
	}
	ap.Status.Conditions = append(ap.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: ap.Generation,
	})
}

func (r *AgentPassportReconciler) reconcileGovernance(ctx context.Context, ap *vibapv1alpha1.AgentPassport) error {
	if ap.Spec.Governance == nil || !ap.Spec.Governance.Enabled {
		ap.Status.Governance = nil
		setCondition(ap, vibapv1alpha1.ConditionGovernanceReady, metav1.ConditionFalse,
			vibapv1alpha1.ReasonGovernanceDisabled, "Governance is not enabled")
		return nil
	}

	if err := ap.Spec.Governance.Validate(); err != nil {
		ap.Status.Governance = nil
		setCondition(ap, vibapv1alpha1.ConditionGovernanceReady, metav1.ConditionFalse,
			vibapv1alpha1.ReasonGovernanceInvalid, err.Error())
		return err
	}

	declarationHash, err := r.resolveGovernanceDeclarationHash(ctx, ap.Namespace, ap.Spec.Governance)
	if err != nil {
		ap.Status.Governance = nil
		setCondition(ap, vibapv1alpha1.ConditionGovernanceReady, metav1.ConditionFalse,
			vibapv1alpha1.ReasonGovernanceInvalid, err.Error())
		return err
	}

	ap.Status.Governance = buildGovernanceStatus(declarationHash, ap.Status.Governance)

	mode := effectiveGovernanceMode(ap.Spec.Governance.Mode)

	setCondition(ap, vibapv1alpha1.ConditionGovernanceReady, metav1.ConditionTrue,
		vibapv1alpha1.ReasonGovernanceEnabled,
		fmt.Sprintf("Governance active in %s mode", mode))

	if ap.Spec.Governance.EmitRuntimeEvents {
		r.recordEvent(ap, corev1.EventTypeNormal, "GovernanceActive",
			"Governance session %s active in %s mode (declaration=%s)",
			ap.Status.Governance.SessionID, mode,
			ap.Status.Governance.DeclarationHash)
	}

	return nil
}

func buildGovernanceStatus(declarationHash string, existing *vibapv1alpha1.GovernanceStatus) *vibapv1alpha1.GovernanceStatus {
	gs := &vibapv1alpha1.GovernanceStatus{
		GovernancePhase: "initialized",
		LastDecision:    "pending",
		DeclarationHash: declarationHash,
	}

	if existing != nil && existing.DeclarationHash == declarationHash {
		gs.SessionID = existing.SessionID
		gs.FindingCount = existing.FindingCount
		gs.ViolationCount = existing.ViolationCount
		gs.LastEventID = existing.LastEventID
		gs.RecommendedAction = existing.RecommendedAction
		if existing.LastDecisionTime != nil {
			gs.LastDecisionTime = existing.LastDecisionTime.DeepCopy()
			gs.LastDecision = existing.LastDecision
		}
		if existing.GovernancePhase == "active" || existing.GovernancePhase == "closed" {
			gs.GovernancePhase = existing.GovernancePhase
		}
	}

	if gs.SessionID == "" {
		gs.SessionID = fmt.Sprintf("gs-%x", sha256.Sum256([]byte(
			gs.DeclarationHash+time.Now().UTC().Format(time.RFC3339Nano))))[:24]
	}

	return gs
}

func computeDeclarationHash(spec *vibapv1alpha1.InlineDeclaration) string {
	h := sha256.New()

	if spec != nil {
		actions := make([]string, len(spec.AllowedActions))
		copy(actions, spec.AllowedActions)
		sort.Strings(actions)

		tools := make([]string, len(spec.AllowedTools))
		copy(tools, spec.AllowedTools)
		sort.Strings(tools)

		resources := make([]string, len(spec.AllowedResources))
		copy(resources, spec.AllowedResources)
		sort.Strings(resources)

		families := make([]string, len(spec.AllowedResourceFamilies))
		copy(families, spec.AllowedResourceFamilies)
		sort.Strings(families)

		sideEffects := make([]string, len(spec.AllowedSideEffects))
		copy(sideEffects, spec.AllowedSideEffects)
		sort.Strings(sideEffects)

		metadataKeys := make([]string, 0, len(spec.Metadata))
		for key := range spec.Metadata {
			metadataKeys = append(metadataKeys, key)
		}
		sort.Strings(metadataKeys)

		fmt.Fprintf(h, "actions=%s\n", strings.Join(actions, ","))
		fmt.Fprintf(h, "tools=%s\n", strings.Join(tools, ","))
		fmt.Fprintf(h, "resources=%s\n", strings.Join(resources, ","))
		fmt.Fprintf(h, "families=%s\n", strings.Join(families, ","))
		fmt.Fprintf(h, "sideEffects=%s\n", strings.Join(sideEffects, ","))
		fmt.Fprintf(h, "maxDelegationDepth=%d\n", spec.MaxDelegationDepth)
		fmt.Fprintf(h, "maxTotalDelegations=%d\n", spec.MaxTotalDelegations)
		fmt.Fprintf(h, "maxSiblingDelegations=%d\n", spec.MaxSiblingDelegations)
		for _, key := range metadataKeys {
			fmt.Fprintf(h, "metadata.%s=%s\n", key, spec.Metadata[key])
		}
	}

	return hex.EncodeToString(h.Sum(nil))
}

func (r *AgentPassportReconciler) resolveGovernanceDeclarationHash(ctx context.Context, namespace string, spec *vibapv1alpha1.GovernanceSpec) (string, error) {
	if spec.InlineDeclaration != nil {
		return computeDeclarationHash(spec.InlineDeclaration), nil
	}

	data, err := r.loadGovernanceDeclarationFromConfigMap(ctx, namespace, spec.DeclarationRef)
	if err != nil {
		return "", err
	}
	return hashGovernanceDeclarationJSON(data)
}

func (r *AgentPassportReconciler) loadGovernanceDeclarationFromConfigMap(ctx context.Context, ns string, ref *vibapv1alpha1.DeclarationReference) (string, error) {
	var cm corev1.ConfigMap
	key := client.ObjectKey{Namespace: ns, Name: ref.Name}
	if err := r.Get(ctx, key, &cm); err != nil {
		return "", fmt.Errorf("getting governance declaration ConfigMap %s: %w", ref.Name, err)
	}

	dataKey := ref.Key
	if dataKey == "" {
		dataKey = defaultGovernanceDeclarationKey
	}
	text, ok := cm.Data[dataKey]
	if !ok {
		return "", fmt.Errorf("key %q not found in governance ConfigMap %s", dataKey, ref.Name)
	}

	return text, nil
}

func hashGovernanceDeclarationJSON(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("governance declaration is empty")
	}

	var obj map[string]any
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		return "", fmt.Errorf("governance declaration is not valid JSON: %w", err)
	}
	if len(obj) == 0 {
		return "", fmt.Errorf("governance declaration must be a non-empty JSON object")
	}
	if !hasDeclarationFields(obj) {
		return "", fmt.Errorf("governance declaration must define allowed_actions/allowed_tools or allowedActions/allowedTools")
	}

	var normalized bytes.Buffer
	if err := json.Compact(&normalized, []byte(trimmed)); err != nil {
		return "", fmt.Errorf("normalizing governance declaration JSON: %w", err)
	}

	sum := sha256.Sum256(normalized.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

func hasDeclarationFields(obj map[string]any) bool {
	_, hasSnakeActions := obj["allowed_actions"]
	_, hasSnakeTools := obj["allowed_tools"]
	_, hasCamelActions := obj["allowedActions"]
	_, hasCamelTools := obj["allowedTools"]
	return (hasSnakeActions && hasSnakeTools) || (hasCamelActions && hasCamelTools)
}

func effectiveGovernanceMode(mode string) string {
	if strings.TrimSpace(mode) == "" {
		return "monitor"
	}
	return mode
}

func loadSigningKey(path string) (*credential.SigningKey, error) {
	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath) // #nosec G304 -- operator reads an admin-configured key path
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		D   string `json:"d"`
		X   string `json:"x"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, fmt.Errorf("parsing JWK: %w", err)
	}

	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported key type: %s/%s", jwk.Kty, jwk.Crv)
	}

	seed, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("decoding private key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid key seed length: %d", len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)

	return &credential.SigningKey{
		PrivateKey: priv,
		PublicKey:  priv.Public().(ed25519.PublicKey),
		KeyID:      jwk.Kid,
	}, nil
}
