package trust

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

func TestNetworkPolicyForTier_Full(t *testing.T) {
	np := NetworkPolicyForTier(TierFull, "default")

	if np.Name != NetworkPolicyNameFull {
		t.Errorf("expected name %q, got %q", NetworkPolicyNameFull, np.Name)
	}
	if np.Namespace != "default" {
		t.Errorf("expected namespace %q, got %q", "default", np.Namespace)
	}
	if np.Labels["vibap.ardur.dev/policy-tier"] != TierFull {
		t.Errorf("expected tier label %q", TierFull)
	}

	sel := np.Spec.PodSelector.MatchLabels
	if sel[labelKeyTier] != TierFull {
		t.Errorf("pod selector must match tier=%s", TierFull)
	}

	assertPolicyType(t, np, networkingv1.PolicyTypeEgress)

	// Full tier: one egress rule with no port/To restrictions (allow-all)
	if len(np.Spec.Egress) == 0 {
		t.Fatal("full tier must have at least one egress rule")
	}
	rule := np.Spec.Egress[0]
	if len(rule.Ports) != 0 || len(rule.To) != 0 {
		t.Error("full tier egress rule must have no port or To restrictions")
	}
}

func TestNetworkPolicyForTier_Limited(t *testing.T) {
	np := NetworkPolicyForTier(TierLimited, "agents")

	if np.Name != NetworkPolicyNameLimited {
		t.Errorf("expected name %q, got %q", NetworkPolicyNameLimited, np.Name)
	}
	if np.Namespace != "agents" {
		t.Errorf("expected namespace %q, got %q", "agents", np.Namespace)
	}

	sel := np.Spec.PodSelector.MatchLabels
	if sel[labelKeyTier] != TierLimited {
		t.Errorf("pod selector must match tier=%s", TierLimited)
	}

	assertPolicyType(t, np, networkingv1.PolicyTypeEgress)

	if len(np.Spec.Egress) < 2 {
		t.Fatalf("limited tier must have at least 2 egress rules, got %d", len(np.Spec.Egress))
	}

	// Find DNS rule (UDP 53)
	dnsFound := false
	for _, rule := range np.Spec.Egress {
		for _, p := range rule.Ports {
			if p.Protocol != nil && *p.Protocol == corev1.ProtocolUDP &&
				p.Port != nil && p.Port.IntVal == 53 {
				dnsFound = true
			}
		}
	}
	if !dnsFound {
		t.Error("limited tier must include UDP 53 egress rule for DNS")
	}

	// Must not permit external IPs: at least one rule must have a To with PodSelector
	hasPodSelectorRule := false
	for _, rule := range np.Spec.Egress {
		for _, peer := range rule.To {
			if peer.PodSelector != nil && peer.IPBlock == nil {
				hasPodSelectorRule = true
			}
		}
	}
	if !hasPodSelectorRule {
		t.Error("limited tier must have a To rule with PodSelector (no IPBlock) to block external IPs")
	}
}

func TestNetworkPolicyForTier_Quarantine(t *testing.T) {
	np := NetworkPolicyForTier(TierQuarantine, "secure")

	if np.Name != NetworkPolicyNameQuarantine {
		t.Errorf("expected name %q, got %q", NetworkPolicyNameQuarantine, np.Name)
	}

	sel := np.Spec.PodSelector.MatchLabels
	if sel[labelKeyTier] != TierQuarantine {
		t.Errorf("pod selector must match tier=%s", TierQuarantine)
	}

	assertPolicyType(t, np, networkingv1.PolicyTypeEgress)

	if len(np.Spec.Egress) == 0 {
		t.Fatal("quarantine tier must have at least one egress rule for Prometheus")
	}

	// Only Prometheus port (9090/TCP) allowed
	prometheusFound := false
	for _, rule := range np.Spec.Egress {
		for _, p := range rule.Ports {
			if p.Protocol != nil && *p.Protocol == corev1.ProtocolTCP &&
				p.Port != nil && p.Port.IntVal == prometheusPort {
				prometheusFound = true
			}
		}
	}
	if !prometheusFound {
		t.Errorf("quarantine tier must permit TCP %d (Prometheus)", prometheusPort)
	}

	// No IPBlock peers allowed (no external IPs)
	for _, rule := range np.Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock != nil {
				t.Error("quarantine tier must not include IPBlock peers (no external IPs)")
			}
		}
	}
}

// TestNetworkPolicyForTier_UnknownTierFallsToQuarantine ensures unrecognized
// tier names are treated as quarantine (fail-safe).
func TestNetworkPolicyForTier_UnknownTierFallsToQuarantine(t *testing.T) {
	np := NetworkPolicyForTier("unknown-tier", "default")
	if np.Name != NetworkPolicyNameQuarantine {
		t.Errorf("unknown tier must fall to quarantine policy, got %q", np.Name)
	}
}

// TestPolicyNameForTier checks deterministic name mapping.
func TestPolicyNameForTier(t *testing.T) {
	cases := []struct {
		tier string
		want string
	}{
		{TierFull, NetworkPolicyNameFull},
		{TierLimited, NetworkPolicyNameLimited},
		{TierQuarantine, NetworkPolicyNameQuarantine},
		{"bogus", NetworkPolicyNameQuarantine},
	}
	for _, tc := range cases {
		got := PolicyNameForTier(tc.tier)
		if got != tc.want {
			t.Errorf("PolicyNameForTier(%q) = %q, want %q", tc.tier, got, tc.want)
		}
	}
}

// TestAllTierPolicyNames ensures all three tier names are returned.
func TestAllTierPolicyNames(t *testing.T) {
	names := AllTierPolicyNames()
	if len(names) != 3 {
		t.Fatalf("expected 3 tier policy names, got %d", len(names))
	}
	want := map[string]bool{
		NetworkPolicyNameFull:       true,
		NetworkPolicyNameLimited:    true,
		NetworkPolicyNameQuarantine: true,
	}
	for _, n := range names {
		if !want[n] {
			t.Errorf("unexpected policy name %q", n)
		}
	}
}

// TestNetworkPolicyForTier_Metadata checks managed-by label and type metadata.
func TestNetworkPolicyForTier_Metadata(t *testing.T) {
	for _, tier := range []string{TierFull, TierLimited, TierQuarantine} {
		np := NetworkPolicyForTier(tier, "ns")
		if np.Labels["app.kubernetes.io/managed-by"] != "vibap-operator" {
			t.Errorf("tier %s: missing managed-by label", tier)
		}
		if np.APIVersion != "networking.k8s.io/v1" {
			t.Errorf("tier %s: wrong APIVersion %q", tier, np.APIVersion)
		}
		if np.Kind != "NetworkPolicy" {
			t.Errorf("tier %s: wrong Kind %q", tier, np.Kind)
		}
	}
}

// TestNetworkPolicyForTier_NamespaceIsolation verifies namespace is propagated.
func TestNetworkPolicyForTier_NamespaceIsolation(t *testing.T) {
	for _, tier := range []string{TierFull, TierLimited, TierQuarantine} {
		np := NetworkPolicyForTier(tier, "production")
		if np.Namespace != "production" {
			t.Errorf("tier %s: expected namespace %q, got %q", tier, "production", np.Namespace)
		}
	}
}

func assertPolicyType(t *testing.T, np *networkingv1.NetworkPolicy, want networkingv1.PolicyType) {
	t.Helper()
	for _, pt := range np.Spec.PolicyTypes {
		if pt == want {
			return
		}
	}
	t.Errorf("policy %q missing PolicyType %q", np.Name, want)
}
