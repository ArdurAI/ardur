// Package trust — NetworkPolicy generation for per-tier egress enforcement.
//
// Each trust tier maps to a distinct egress posture (documented in scorer.go):
//
//   - Full  (≥70): all egress allowed (no EgressRule restrictions)
//   - Limited (≥40): cluster-internal egress only (port 53 for DNS, no
//     external destinations)
//   - Quarantine (<40): egress denied to everything except the Prometheus
//     scrape port (9090/TCP) within the same namespace
//
// NetworkPolicy objects are generated as in-memory Kubernetes API objects.
// Applying them to a cluster requires the K8s client (see reconciler.go).
// The generation logic itself is locally testable without a cluster.
package trust

import (
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	// NetworkPolicyNameFull is the NetworkPolicy name for full-tier agents.
	NetworkPolicyNameFull = "vibap-egress-full"
	// NetworkPolicyNameLimited is the NetworkPolicy name for limited-tier agents.
	NetworkPolicyNameLimited = "vibap-egress-limited"
	// NetworkPolicyNameQuarantine is the NetworkPolicy name for quarantine-tier agents.
	NetworkPolicyNameQuarantine = "vibap-egress-quarantine"

	// labelKeyTier is the pod label the NetworkPolicy selects on.
	labelKeyTier = "vibap.ardur.dev/trust-tier"

	// prometheusPort is the only port quarantined agents may reach.
	prometheusPort = 9090
)

// NetworkPolicyForTier returns the canonical Kubernetes NetworkPolicy that
// enforces egress for the given trust tier in namespace ns.
//
// The returned object has no ResourceVersion — callers must create or update
// it via the K8s API. The object's name is deterministic so callers can use
// server-side apply or a simple Get + Create/Update cycle.
//
// Callers targeting a real cluster:
//
//	REQUIRES_CLUSTER: applying or listing NetworkPolicy objects
func NetworkPolicyForTier(tier, namespace string) *networkingv1.NetworkPolicy {
	switch tier {
	case TierFull:
		return fullEgressPolicy(namespace)
	case TierLimited:
		return limitedEgressPolicy(namespace)
	default:
		return quarantineEgressPolicy(namespace)
	}
}

// PolicyNameForTier returns the deterministic NetworkPolicy name for a tier.
func PolicyNameForTier(tier string) string {
	switch tier {
	case TierFull:
		return NetworkPolicyNameFull
	case TierLimited:
		return NetworkPolicyNameLimited
	default:
		return NetworkPolicyNameQuarantine
	}
}

// AllTierPolicyNames returns all tier NetworkPolicy names. Useful for cleanup.
func AllTierPolicyNames() []string {
	return []string{
		NetworkPolicyNameFull,
		NetworkPolicyNameLimited,
		NetworkPolicyNameQuarantine,
	}
}

// fullEgressPolicy allows all egress — no EgressRule restrictions.
// Equivalent to "any destination, any port".
func fullEgressPolicy(namespace string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "networking.k8s.io/v1",
			Kind:       "NetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      NetworkPolicyNameFull,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "vibap-operator",
				"vibap.ardur.dev/policy-tier":  TierFull,
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					labelKeyTier: TierFull,
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
			// Single rule with no To or Ports restrictions means allow all egress.
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{},
			},
		},
	}
}

// limitedEgressPolicy allows only cluster-internal egress:
//   - UDP 53 for in-cluster DNS resolution
//   - TCP to any cluster-internal destination (no CIDR block for external IPs)
//
// This prevents reaching external endpoints while permitting in-cluster service calls.
func limitedEgressPolicy(namespace string) *networkingv1.NetworkPolicy {
	dnsPort := intstr.FromInt32(53)
	tcpProto := corev1.ProtocolTCP
	udpProto := corev1.ProtocolUDP

	return &networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "networking.k8s.io/v1",
			Kind:       "NetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      NetworkPolicyNameLimited,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "vibap-operator",
				"vibap.ardur.dev/policy-tier":  TierLimited,
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					labelKeyTier: TierLimited,
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					// DNS egress: UDP 53 to kube-dns
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &udpProto, Port: &dnsPort},
					},
				},
				{
					// Cluster-internal TCP — PodSelector with no IPBlock
					// allows any cluster pod but blocks external IP addresses.
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &tcpProto},
					},
					To: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{},
						},
					},
				},
			},
		},
	}
}

// quarantineEgressPolicy denies all egress except Prometheus scraping (TCP 9090)
// from within the same namespace. No external access permitted.
func quarantineEgressPolicy(namespace string) *networkingv1.NetworkPolicy {
	prometheusPortVal := intstr.FromInt32(prometheusPort)
	tcpProto := corev1.ProtocolTCP

	return &networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "networking.k8s.io/v1",
			Kind:       "NetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      NetworkPolicyNameQuarantine,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "vibap-operator",
				"vibap.ardur.dev/policy-tier":  TierQuarantine,
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					labelKeyTier: TierQuarantine,
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					// Only allow Prometheus scrape port within the same namespace.
					// Empty PodSelector matches all pods; absent NamespaceSelector
					// restricts to the current namespace.
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &tcpProto, Port: &prometheusPortVal},
					},
					To: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{},
						},
					},
				},
			},
		},
	}
}
