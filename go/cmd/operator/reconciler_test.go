package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vibapv1alpha1 "github.com/ArdurAI/ardur/go/pkg/api/v1alpha1"
)

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = vibapv1alpha1.AddToScheme(s)
	return s
}

func testReconciler(objects ...runtime.Object) (*AgentPassportReconciler, error) {
	s := testScheme()
	c := fake.NewClientBuilder().WithScheme(s).WithRuntimeObjects(objects...).
		WithStatusSubresource(&vibapv1alpha1.AgentPassport{}).
		Build()
	// FIX-R9-6: tests must explicitly opt in to the ephemeral-key
	// path; production startup refuses without --signing-key.
	return NewAgentPassportReconciler(c, s, "", "https://test.vibap.io", true)
}

// FIX-R10-1 (round-10, 2026-04-29): negative-path regression for the
// FIX-R9-6 ephemeral-key opt-in gate. Round-9 audit (MED-NEW-1) caught
// that all existing reconciler tests pass ``allowEphemeralKey=true``
// — a revert that removed the refusal branch (``if !allowEphemeralKey``)
// would not be caught by any test. This test pins production fail-
// closed: with no signing-key path AND no ephemeral opt-in, the
// constructor returns an error containing the operator-friendly
// "startup refused" string.
func TestNewAgentPassportReconciler_RefusesEphemeralKeyWithoutOptIn(t *testing.T) {
	s := testScheme()
	c := fake.NewClientBuilder().WithScheme(s).
		WithStatusSubresource(&vibapv1alpha1.AgentPassport{}).
		Build()

	_, err := NewAgentPassportReconciler(c, s, "", "https://test.vibap.io", false)
	if err == nil {
		t.Fatal("expected NewAgentPassportReconciler to refuse without --signing-key and without --allow-ephemeral-key")
	}
	// Operator-facing error must name the explicit opt-in flag so
	// deployments fail loudly with a clear remediation, not silently
	// degrade or panic with a generic ed25519/cluster error.
	expected := []string{"startup refused", "--allow-ephemeral-key"}
	for _, want := range expected {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message must mention %q; got: %v", want, err)
		}
	}
}

// FIX-R10-1b: complementary test — when the operator DOES pass the
// flag, construction succeeds and yields a reconciler with the
// ephemeral-key fingerprint. This confirms the opt-in path still
// works after the negative-path is locked down.
func TestNewAgentPassportReconciler_AcceptsEphemeralKeyWithOptIn(t *testing.T) {
	s := testScheme()
	c := fake.NewClientBuilder().WithScheme(s).
		WithStatusSubresource(&vibapv1alpha1.AgentPassport{}).
		Build()

	r, err := NewAgentPassportReconciler(c, s, "", "https://test.vibap.io", true)
	if err != nil {
		t.Fatalf("expected acceptance with --allow-ephemeral-key=true; got: %v", err)
	}
	if r == nil {
		t.Fatal("reconciler is nil despite no error")
	}
}


func testPassport(name, ns string) *vibapv1alpha1.AgentPassport {
	return &vibapv1alpha1.AgentPassport{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  ns,
			Generation: 1,
		},
		Spec: vibapv1alpha1.AgentPassportSpec{
			Identity: vibapv1alpha1.IdentitySpec{
				OwnerID: "spiffe://test.org/owner",
			},
			Intent: vibapv1alpha1.IntentSpec{
				InlinePolicy:     "permit(principal, action, resource);",
				PermittedActions: []string{"read"},
			},
			Trust: vibapv1alpha1.TrustSpec{
				StaticCapabilityScore: 0.8,
				HistoricalReputation:  0.9,
			},
			Credential: vibapv1alpha1.CredentialSpec{},
		},
	}
}

// reconcileUntilStable runs reconcile in a loop until there's no immediate requeue,
// simulating the controller queue. This handles the finalizer addition round-trip.
func reconcileUntilStable(t *testing.T, r *AgentPassportReconciler, nn types.NamespacedName, maxRounds int) ctrl.Result {
	t.Helper()
	ctx := context.Background()
	var result ctrl.Result
	var err error
	for i := 0; i < maxRounds; i++ {
		result, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: nn})
		if err != nil {
			t.Fatalf("reconcile round %d failed: %v", i, err)
		}
		if result.RequeueAfter > 0 || result.IsZero() {
			return result
		}
	}
	return result
}

func TestReconcile_NewPassport(t *testing.T) {
	ap := testPassport("test-agent", "default")
	r, err := testReconciler(ap)
	if err != nil {
		t.Fatalf("creating reconciler: %v", err)
	}

	nn := types.NamespacedName{Name: "test-agent", Namespace: "default"}
	result := reconcileUntilStable(t, r, nn, 5)

	if result.RequeueAfter <= 0 {
		t.Error("expected positive requeue delay for renewal scheduling")
	}

	var updated vibapv1alpha1.AgentPassport
	if err := r.Get(context.Background(), nn, &updated); err != nil {
		t.Fatalf("getting updated passport: %v", err)
	}

	if updated.Status.Credential == "" {
		t.Error("expected credential to be set in status")
	}
	if updated.Status.ComplianceLevel == "" {
		t.Error("expected compliance level to be set")
	}
	if updated.Status.TrustTier == "" {
		t.Error("expected trust tier to be set")
	}
	if updated.Status.ExpiresAt == nil {
		t.Error("expected expiresAt to be set")
	}
	if updated.Status.IssuedAt == nil {
		t.Error("expected issuedAt to be set")
	}
	if updated.Status.ObservedGeneration != 1 {
		t.Errorf("expected observedGeneration=1, got %d", updated.Status.ObservedGeneration)
	}

	// Verify finalizer was added.
	hasFinalizer := false
	for _, f := range updated.Finalizers {
		if f == vibapv1alpha1.FinalizerName {
			hasFinalizer = true
		}
	}
	if !hasFinalizer {
		t.Error("expected finalizer to be present")
	}
}

func TestReconcile_NotFound(t *testing.T) {
	r, err := testReconciler()
	if err != nil {
		t.Fatalf("creating reconciler: %v", err)
	}

	ctx := context.Background()
	result, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("reconcile should not error for missing resource: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("should not requeue for missing resource")
	}
}

func TestReconcile_AlreadyIssued(t *testing.T) {
	ap := testPassport("test-agent", "default")
	ap.Finalizers = []string{vibapv1alpha1.FinalizerName}
	now := metav1.Now()
	future := metav1.NewTime(now.Add(1 * time.Hour))
	ap.Status = vibapv1alpha1.AgentPassportStatus{
		Credential:         "eyJhbGciOiJFZERTQSJ9.test~disc1~",
		ComplianceLevel:    "core",
		TrustTier:          "limited",
		CompositeScore:     60.0,
		IssuedAt:           &now,
		ExpiresAt:          &future,
		ObservedGeneration: 1,
	}

	r, err := testReconciler(ap)
	if err != nil {
		t.Fatalf("creating reconciler: %v", err)
	}

	ctx := context.Background()
	result, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-agent", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	if result.RequeueAfter <= 0 {
		t.Error("should schedule renewal")
	}
}

func TestReconcile_NeedsRenewal(t *testing.T) {
	ap := testPassport("test-agent", "default")
	ap.Finalizers = []string{vibapv1alpha1.FinalizerName}
	now := metav1.Now()
	almostExpired := metav1.NewTime(now.Add(5 * time.Minute))
	ap.Status = vibapv1alpha1.AgentPassportStatus{
		Credential:         "eyJhbGciOiJFZERTQSJ9.old~disc~",
		ComplianceLevel:    "core",
		TrustTier:          "limited",
		IssuedAt:           &now,
		ExpiresAt:          &almostExpired,
		ObservedGeneration: 1,
	}

	r, err := testReconciler(ap)
	if err != nil {
		t.Fatalf("creating reconciler: %v", err)
	}

	ctx := context.Background()
	result, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-agent", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var updated vibapv1alpha1.AgentPassport
	if err := r.Get(ctx, types.NamespacedName{Name: "test-agent", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("getting updated passport: %v", err)
	}

	if updated.Status.Credential == "eyJhbGciOiJFZERTQSJ9.old~disc~" {
		t.Error("credential should have been renewed")
	}

	if result.RequeueAfter <= 0 {
		t.Error("should schedule next renewal")
	}
}

func TestReconcile_SpecChange(t *testing.T) {
	ap := testPassport("test-agent", "default")
	ap.Finalizers = []string{vibapv1alpha1.FinalizerName}
	now := metav1.Now()
	future := metav1.NewTime(now.Add(1 * time.Hour))
	ap.Generation = 2
	ap.Status = vibapv1alpha1.AgentPassportStatus{
		Credential:         "eyJhbGciOiJFZERTQSJ9.old~disc~",
		ComplianceLevel:    "core",
		ObservedGeneration: 1,
		IssuedAt:           &now,
		ExpiresAt:          &future,
	}

	r, err := testReconciler(ap)
	if err != nil {
		t.Fatalf("creating reconciler: %v", err)
	}

	ctx := context.Background()
	_, err = r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-agent", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var updated vibapv1alpha1.AgentPassport
	if err := r.Get(ctx, types.NamespacedName{Name: "test-agent", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("getting updated passport: %v", err)
	}

	if updated.Status.ObservedGeneration != 2 {
		t.Errorf("expected observedGeneration=2, got %d", updated.Status.ObservedGeneration)
	}
}

func TestReconcile_NoPolicy(t *testing.T) {
	ap := testPassport("test-agent", "default")
	ap.Finalizers = []string{vibapv1alpha1.FinalizerName}
	ap.Spec.Intent.InlinePolicy = ""

	r, err := testReconciler(ap)
	if err != nil {
		t.Fatalf("creating reconciler: %v", err)
	}

	ctx := context.Background()
	result, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-agent", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("reconcile should not hard-fail: %v", err)
	}

	// Should requeue after failure backoff.
	if result.RequeueAfter <= 0 {
		t.Error("expected requeue on policy missing error")
	}

	var updated vibapv1alpha1.AgentPassport
	if err := r.Get(ctx, types.NamespacedName{Name: "test-agent", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("getting updated passport: %v", err)
	}

	// Should have a Failed condition.
	found := false
	for _, c := range updated.Status.Conditions {
		if c.Type == vibapv1alpha1.ConditionReady && c.Status == metav1.ConditionFalse {
			found = true
		}
	}
	if !found {
		t.Error("expected Ready=False condition when no policy provided")
	}
}

func TestReconcile_WithCustomTTL(t *testing.T) {
	ap := testPassport("ttl-agent", "default")
	ap.Spec.Credential.TTL = &metav1.Duration{Duration: 30 * time.Minute}

	r, err := testReconciler(ap)
	if err != nil {
		t.Fatalf("creating reconciler: %v", err)
	}

	nn := types.NamespacedName{Name: "ttl-agent", Namespace: "default"}
	result := reconcileUntilStable(t, r, nn, 5)

	// With 30m TTL and 10m renewBefore, requeue should be ~20m.
	if result.RequeueAfter > 25*time.Minute || result.RequeueAfter < 15*time.Minute {
		t.Errorf("unexpected requeue delay: %v (expected ~20m)", result.RequeueAfter)
	}
}

func TestReconcile_WithProvenance(t *testing.T) {
	ap := testPassport("prov-agent", "default")
	ap.Spec.Provenance = &vibapv1alpha1.ProvenanceSpec{
		ImageRef:    "ghcr.io/test/agent:v1",
		RequireSLSA: true,
	}

	r, err := testReconciler(ap)
	if err != nil {
		t.Fatalf("creating reconciler: %v", err)
	}

	nn := types.NamespacedName{Name: "prov-agent", Namespace: "default"}
	_ = reconcileUntilStable(t, r, nn, 5)
}

func TestReconcile_GovernanceEnabledWithoutDeclaration(t *testing.T) {
	ap := testPassport("gov-missing", "default")
	ap.Spec.Governance = &vibapv1alpha1.GovernanceSpec{
		Enabled: true,
	}

	r, err := testReconciler(ap)
	if err != nil {
		t.Fatalf("creating reconciler: %v", err)
	}

	nn := types.NamespacedName{Name: "gov-missing", Namespace: "default"}
	result := reconcileUntilStable(t, r, nn, 5)
	if result.RequeueAfter <= 0 {
		t.Fatal("expected governance validation failure to requeue")
	}

	var updated vibapv1alpha1.AgentPassport
	if err := r.Get(context.Background(), nn, &updated); err != nil {
		t.Fatalf("getting updated passport: %v", err)
	}

	if updated.Status.Governance != nil {
		t.Fatal("expected governance status to remain unset when no declaration is provided")
	}
	assertConditionStatus(t, updated.Status.Conditions, vibapv1alpha1.ConditionGovernanceReady, metav1.ConditionFalse)
	assertConditionStatus(t, updated.Status.Conditions, vibapv1alpha1.ConditionReady, metav1.ConditionFalse)
}

func TestReconcile_GovernanceDeclarationRefReady(t *testing.T) {
	ap := testPassport("gov-ref", "default")
	ap.Spec.Governance = &vibapv1alpha1.GovernanceSpec{
		Enabled: true,
		Mode:    "enforce",
		DeclarationRef: &vibapv1alpha1.DeclarationReference{
			Name: "governance-declaration",
		},
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "governance-declaration",
			Namespace: "default",
		},
		Data: map[string]string{
			"default":          "unused",
			"declaration.json": `{"allowed_actions":["read"],"allowed_tools":["reader"]}`,
		},
	}

	r, err := testReconciler(ap, cm)
	if err != nil {
		t.Fatalf("creating reconciler: %v", err)
	}

	nn := types.NamespacedName{Name: "gov-ref", Namespace: "default"}
	_ = reconcileUntilStable(t, r, nn, 5)

	var updated vibapv1alpha1.AgentPassport
	if err := r.Get(context.Background(), nn, &updated); err != nil {
		t.Fatalf("getting updated passport: %v", err)
	}

	if updated.Status.Governance == nil {
		t.Fatal("expected governance status to be populated")
	}
	if updated.Status.Governance.DeclarationHash == "" {
		t.Fatal("expected declaration hash to be populated from ConfigMap content")
	}
	assertConditionStatus(t, updated.Status.Conditions, vibapv1alpha1.ConditionGovernanceReady, metav1.ConditionTrue)
	assertConditionStatus(t, updated.Status.Conditions, vibapv1alpha1.ConditionReady, metav1.ConditionTrue)
}

func TestBuildGovernanceStatusResetsOnDeclarationChange(t *testing.T) {
	existing := &vibapv1alpha1.GovernanceStatus{
		SessionID:         "gs-old",
		LastDecision:      "violation",
		FindingCount:      4,
		ViolationCount:    2,
		GovernancePhase:   "active",
		RecommendedAction: "alert",
		LastEventID:       "evt-9",
		DeclarationHash:   "old-hash",
		LastDecisionTime:  &metav1.Time{Time: time.Now().UTC()},
	}

	updated := buildGovernanceStatus("new-hash", existing)
	if updated.SessionID == existing.SessionID {
		t.Fatal("expected declaration change to create a fresh governance session")
	}
	if updated.FindingCount != 0 || updated.ViolationCount != 0 {
		t.Fatalf("expected counters reset, got findings=%d violations=%d", updated.FindingCount, updated.ViolationCount)
	}
	if updated.LastDecision != "pending" {
		t.Fatalf("expected last decision reset to pending, got %q", updated.LastDecision)
	}
	if updated.GovernancePhase != "initialized" {
		t.Fatalf("expected governance phase reset to initialized, got %q", updated.GovernancePhase)
	}
}

func TestHashGovernanceDeclarationJSON(t *testing.T) {
	first, err := hashGovernanceDeclarationJSON("{\n  \"allowed_actions\": [\"read\"],\n  \"allowed_tools\": [\"reader\"]\n}")
	if err != nil {
		t.Fatalf("hash first declaration: %v", err)
	}
	second, err := hashGovernanceDeclarationJSON("{\"allowed_actions\":[\"read\"],\"allowed_tools\":[\"reader\"]}")
	if err != nil {
		t.Fatalf("hash second declaration: %v", err)
	}
	if first != second {
		t.Fatal("expected equivalent JSON declarations to hash identically")
	}
}

func TestNeedsCredential(t *testing.T) {
	tests := []struct {
		name   string
		ap     *vibapv1alpha1.AgentPassport
		expect bool
	}{
		{
			name:   "no credential",
			ap:     &vibapv1alpha1.AgentPassport{},
			expect: true,
		},
		{
			name: "has credential, generation matches",
			ap: &vibapv1alpha1.AgentPassport{
				ObjectMeta: metav1.ObjectMeta{Generation: 1},
				Status:     vibapv1alpha1.AgentPassportStatus{Credential: "eyJ...", ObservedGeneration: 1},
			},
			expect: false,
		},
		{
			name: "has credential, generation mismatch",
			ap: &vibapv1alpha1.AgentPassport{
				ObjectMeta: metav1.ObjectMeta{Generation: 2},
				Status:     vibapv1alpha1.AgentPassportStatus{Credential: "eyJ...", ObservedGeneration: 1},
			},
			expect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := needsCredential(tt.ap); got != tt.expect {
				t.Errorf("needsCredential = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestNeedsRenewal(t *testing.T) {
	now := metav1.Now()
	farFuture := metav1.NewTime(now.Add(2 * time.Hour))
	nearFuture := metav1.NewTime(now.Add(5 * time.Minute))

	tests := []struct {
		name   string
		ap     *vibapv1alpha1.AgentPassport
		expect bool
	}{
		{
			name:   "no expiry",
			ap:     &vibapv1alpha1.AgentPassport{},
			expect: false,
		},
		{
			name: "far from expiry",
			ap: &vibapv1alpha1.AgentPassport{
				Status: vibapv1alpha1.AgentPassportStatus{ExpiresAt: &farFuture},
			},
			expect: false,
		},
		{
			name: "near expiry (within renewBefore)",
			ap: &vibapv1alpha1.AgentPassport{
				Status: vibapv1alpha1.AgentPassportStatus{ExpiresAt: &nearFuture},
			},
			expect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := needsRenewal(tt.ap); got != tt.expect {
				t.Errorf("needsRenewal = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestSetCondition_NewCondition(t *testing.T) {
	ap := &vibapv1alpha1.AgentPassport{}
	setCondition(ap, vibapv1alpha1.ConditionReady, metav1.ConditionTrue, vibapv1alpha1.ReasonIssued, "test message")

	if len(ap.Status.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(ap.Status.Conditions))
	}
	if ap.Status.Conditions[0].Type != vibapv1alpha1.ConditionReady {
		t.Errorf("expected type %q, got %q", vibapv1alpha1.ConditionReady, ap.Status.Conditions[0].Type)
	}
	if ap.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Errorf("expected status True, got %s", ap.Status.Conditions[0].Status)
	}
}

func TestSetCondition_UpdateExisting(t *testing.T) {
	ap := &vibapv1alpha1.AgentPassport{
		Status: vibapv1alpha1.AgentPassportStatus{
			Conditions: []metav1.Condition{
				{
					Type:               vibapv1alpha1.ConditionReady,
					Status:             metav1.ConditionFalse,
					Reason:             vibapv1alpha1.ReasonReconciling,
					Message:            "old message",
					LastTransitionTime: metav1.Now(),
				},
			},
		},
	}

	setCondition(ap, vibapv1alpha1.ConditionReady, metav1.ConditionTrue, vibapv1alpha1.ReasonIssued, "new message")

	if len(ap.Status.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(ap.Status.Conditions))
	}
	if ap.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Errorf("expected status True after update, got %s", ap.Status.Conditions[0].Status)
	}
	if ap.Status.Conditions[0].Message != "new message" {
		t.Errorf("expected message %q, got %q", "new message", ap.Status.Conditions[0].Message)
	}
}

func TestLoadSigningKey_InvalidPath(t *testing.T) {
	_, err := loadSigningKey("/nonexistent/key.json")
	if err == nil {
		t.Error("expected error for nonexistent key file")
	}
}

func TestLoadSigningKey_InvalidJSON(t *testing.T) {
	tmpFile := t.TempDir() + "/bad.json"
	if err := writeFile(tmpFile, []byte("not json")); err != nil {
		t.Fatal(err)
	}
	_, err := loadSigningKey(tmpFile)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadSigningKey_WrongKeyType(t *testing.T) {
	tmpFile := t.TempDir() + "/rsa.json"
	data := []byte(`{"kty":"RSA","crv":"","d":"","x":"","kid":"test"}`)
	if err := writeFile(tmpFile, data); err != nil {
		t.Fatal(err)
	}
	_, err := loadSigningKey(tmpFile)
	if err == nil {
		t.Error("expected error for non-Ed25519 key")
	}
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0600)
}

func assertConditionStatus(t *testing.T, conditions []metav1.Condition, condType string, want metav1.ConditionStatus) {
	t.Helper()
	for _, condition := range conditions {
		if condition.Type == condType {
			if condition.Status != want {
				t.Fatalf("condition %s = %s, want %s", condType, condition.Status, want)
			}
			return
		}
	}
	t.Fatalf("condition %s not found", condType)
}
