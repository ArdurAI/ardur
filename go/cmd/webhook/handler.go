package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	vibapv1alpha1 "github.com/ArdurAI/ardur/go/pkg/api/v1alpha1"
)

// PodValidator validates that agent pods have valid VIBAP credentials.
type PodValidator struct {
	Client  client.Client
	decoder admission.Decoder
}

func NewPodValidator(c client.Client, decoder admission.Decoder) *PodValidator {
	return &PodValidator{Client: c, decoder: decoder}
}

// Handle implements admission.Handler for pod validation.
func (v *PodValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	logger := log.FromContext(ctx).WithValues("pod", req.Name, "namespace", req.Namespace)

	pod := &corev1.Pod{}
	if err := v.decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("failed to decode pod"))
	}

	if !isAgentPod(pod) {
		return admission.Allowed("not a VIBAP-managed pod")
	}

	passports, err := findMatchingPassports(ctx, v.Client, pod)
	if err != nil {
		logger.Error(err, "failed to find agent passports")
		return admission.Denied("internal error looking up agent passport")
	}

	if len(passports) == 0 {
		return admission.Denied("no AgentPassport found for this pod; VIBAP-managed pods require a valid passport")
	}

	for _, ap := range passports {
		if ap.Status.Credential == "" {
			return admission.Denied(fmt.Sprintf("AgentPassport %s has no issued credential", ap.Name))
		}
		if !isReady(&ap) {
			return admission.Denied(fmt.Sprintf("AgentPassport %s is not Ready", ap.Name))
		}
		if ap.Status.TrustTier == "quarantine" {
			return admission.Denied(fmt.Sprintf("AgentPassport %s is quarantined", ap.Name))
		}
	}

	logger.V(1).Info("pod validated",
		"passports", len(passports),
		"trustTier", passports[0].Status.TrustTier,
	)

	return admission.Allowed("valid VIBAP credential found")
}

// PodMutator injects VIBAP labels and annotations into agent pods.
type PodMutator struct {
	Client  client.Client
	decoder admission.Decoder
}

func NewPodMutator(c client.Client, decoder admission.Decoder) *PodMutator {
	return &PodMutator{Client: c, decoder: decoder}
}

// Handle implements admission.Handler for pod mutation.
// Returns a JSON patch so the API server applies the mutations.
func (m *PodMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	logger := log.FromContext(ctx).WithValues("pod", req.Name, "namespace", req.Namespace)

	pod := &corev1.Pod{}
	if err := m.decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("failed to decode pod"))
	}

	if !isAgentPod(pod) {
		return admission.Allowed("not a VIBAP-managed pod")
	}

	passports, err := findMatchingPassports(ctx, m.Client, pod)
	if err != nil {
		logger.Error(err, "failed to find agent passports")
		return admission.Errored(http.StatusInternalServerError, fmt.Errorf("internal error looking up agent passport"))
	}
	if len(passports) == 0 {
		return admission.Allowed("no matching AgentPassport")
	}

	ap := passports[0]

	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}
	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}

	if ap.Status.TrustTier != "" {
		pod.Labels[vibapv1alpha1.LabelTrustTier] = ap.Status.TrustTier
	}
	pod.Labels[vibapv1alpha1.LabelManagedBy] = "vibap-operator"

	if ap.Status.ComplianceLevel != "" {
		pod.Annotations[vibapv1alpha1.AnnotationCompliance] = ap.Status.ComplianceLevel
	}

	marshaledPod, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, fmt.Errorf("failed to marshal mutated pod"))
	}

	logger.V(1).Info("mutated pod",
		"trustTier", ap.Status.TrustTier,
		"compliance", ap.Status.ComplianceLevel,
	)

	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
}

func findMatchingPassports(ctx context.Context, c client.Client, pod *corev1.Pod) ([]vibapv1alpha1.AgentPassport, error) {
	var apList vibapv1alpha1.AgentPassportList
	if err := c.List(ctx, &apList, client.InNamespace(pod.Namespace)); err != nil {
		return nil, fmt.Errorf("listing agent passports: %w", err)
	}

	var matched []vibapv1alpha1.AgentPassport
	for _, ap := range apList.Items {
		if ap.Spec.Selector == nil {
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(ap.Spec.Selector)
		if err != nil {
			continue
		}
		if selector.Matches(labels.Set(pod.Labels)) {
			matched = append(matched, ap)
		}
	}
	return matched, nil
}

func isAgentPod(pod *corev1.Pod) bool {
	if pod.Labels == nil {
		return false
	}
	_, managed := pod.Labels[vibapv1alpha1.LabelManagedBy]
	_, hasTier := pod.Labels[vibapv1alpha1.LabelTrustTier]
	if pod.Annotations != nil {
		if _, hasPassport := pod.Annotations[vibapv1alpha1.AnnotationCredential]; hasPassport {
			return true
		}
	}
	return managed || hasTier
}

func isReady(ap *vibapv1alpha1.AgentPassport) bool {
	for _, c := range ap.Status.Conditions {
		if c.Type == vibapv1alpha1.ConditionReady {
			return c.Status == metav1.ConditionTrue
		}
	}
	return false
}
