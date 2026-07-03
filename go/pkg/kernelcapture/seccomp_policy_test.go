package kernelcapture

// seccomp_policy_test.go — unit tests for SeccompPolicyStore
// (seccomp_policy.go), the seccomp tier's in-memory OP_NET_CONNECT policy
// store. Pure Go, no build tag, no kernel dependency.

import (
	"net"
	"testing"
)

func netConnectRequest(sessionID string, action BpfAction, mode BpfEnforceMode, netAllow ...string) DaemonApplyPolicyRequest {
	return DaemonApplyPolicyRequest{
		SessionID: sessionID,
		OpPolicies: []DaemonOpPolicy{
			{Op: BpfOpNetConnect, Action: action, EnforceMode: mode},
		},
		NetAllow: netAllow,
	}
}

func TestEvaluateSeccompConnect_NilStoreFailsOpen(t *testing.T) {
	// A nil store means the seccomp tier was never wired up on this daemon
	// build (see main.go: it's always non-nil in practice, this exercises
	// the defensive branch directly) — matching HasPolicy=false's documented
	// "this session doesn't opt into the tier" semantics, not a deny.
	d := EvaluateSeccompConnect(nil, "any-session", net.ParseIP("1.2.3.4"))
	if d.HasPolicy || !d.Allowed {
		t.Errorf("nil store: got %+v, want HasPolicy=false, Allowed=true", d)
	}
}

func TestApplySeccompPolicy_NilStoreErrors(t *testing.T) {
	err := ApplySeccompPolicy(nil, "s1", netConnectRequest("s1", BpfActionAllow, BpfEnforceModeEnforce))
	if err == nil {
		t.Error("expected an error applying a policy to a nil store, got nil")
	}
}

func TestRemoveSeccompPolicy_NilStoreIsSafeNoop(t *testing.T) {
	RemoveSeccompPolicy(nil, "s1") // must not panic
}

func TestEvaluateSeccompConnect_NoPolicyForSessionAllowsByDefault(t *testing.T) {
	store := NewSeccompPolicyStore()
	d := EvaluateSeccompConnect(store, "unknown-session", net.ParseIP("8.8.8.8"))
	if d.HasPolicy {
		t.Error("HasPolicy = true for a session with no applied policy")
	}
	if !d.Allowed {
		t.Error("Allowed = false for a session with no applied policy, want true (opted out of this tier, not denied)")
	}
}

func TestApplySeccompPolicy_AllowActionMatchesAnyIP(t *testing.T) {
	store := NewSeccompPolicyStore()
	if err := ApplySeccompPolicy(store, "s1", netConnectRequest("s1", BpfActionAllow, BpfEnforceModeEnforce)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	d := EvaluateSeccompConnect(store, "s1", net.ParseIP("203.0.113.9"))
	if !d.HasPolicy || !d.Matched || !d.Allowed {
		t.Errorf("ACT_ALLOW: got %+v, want HasPolicy=Matched=Allowed=true", d)
	}
}

func TestApplySeccompPolicy_DenyActionEnforceBlocks(t *testing.T) {
	store := NewSeccompPolicyStore()
	if err := ApplySeccompPolicy(store, "s1", netConnectRequest("s1", BpfActionDeny, BpfEnforceModeEnforce)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	d := EvaluateSeccompConnect(store, "s1", net.ParseIP("203.0.113.9"))
	if d.Matched {
		t.Error("ACT_DENY: Matched = true, want false")
	}
	if d.Allowed {
		t.Error("ACT_DENY under ENFORCE: Allowed = true, want false")
	}
}

func TestApplySeccompPolicy_DenyActionPermissiveStillAllowsButUnmatched(t *testing.T) {
	store := NewSeccompPolicyStore()
	if err := ApplySeccompPolicy(store, "s1", netConnectRequest("s1", BpfActionDeny, BpfEnforceModePermissive)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	d := EvaluateSeccompConnect(store, "s1", net.ParseIP("203.0.113.9"))
	if d.Matched {
		t.Error("ACT_DENY under PERMISSIVE: Matched = true, want false (still a would-be deny)")
	}
	if !d.Allowed {
		t.Error("ACT_DENY under PERMISSIVE: Allowed = false, want true (log, don't block)")
	}
}

func TestApplySeccompPolicy_AllowlistCIDRMatch(t *testing.T) {
	store := NewSeccompPolicyStore()
	req := netConnectRequest("s1", BpfActionAllowlist, BpfEnforceModeEnforce, "10.0.0.0/8")
	if err := ApplySeccompPolicy(store, "s1", req); err != nil {
		t.Fatalf("apply: %v", err)
	}

	inside := EvaluateSeccompConnect(store, "s1", net.ParseIP("10.1.2.3"))
	if !inside.Matched || !inside.Allowed {
		t.Errorf("10.1.2.3 in 10.0.0.0/8: got %+v, want Matched=Allowed=true", inside)
	}

	outside := EvaluateSeccompConnect(store, "s1", net.ParseIP("11.1.2.3"))
	if outside.Matched || outside.Allowed {
		t.Errorf("11.1.2.3 outside 10.0.0.0/8: got %+v, want Matched=Allowed=false", outside)
	}
}

func TestApplySeccompPolicy_AllowlistBareIPExactMatch(t *testing.T) {
	store := NewSeccompPolicyStore()
	req := netConnectRequest("s1", BpfActionAllowlist, BpfEnforceModeEnforce, "1.2.3.4")
	if err := ApplySeccompPolicy(store, "s1", req); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if d := EvaluateSeccompConnect(store, "s1", net.ParseIP("1.2.3.4")); !d.Matched {
		t.Errorf("exact bare-IP match: got %+v, want Matched=true", d)
	}
	if d := EvaluateSeccompConnect(store, "s1", net.ParseIP("1.2.3.5")); d.Matched {
		t.Errorf("adjacent IP against a bare-IP allow entry: got %+v, want Matched=false", d)
	}
}

func TestApplySeccompPolicy_AllowlistIPv6CIDRMatch(t *testing.T) {
	store := NewSeccompPolicyStore()
	req := netConnectRequest("s1", BpfActionAllowlist, BpfEnforceModeEnforce, "2001:db8::/32")
	if err := ApplySeccompPolicy(store, "s1", req); err != nil {
		t.Fatalf("apply: %v", err)
	}

	inside := EvaluateSeccompConnect(store, "s1", net.ParseIP("2001:db8::1"))
	if !inside.Matched {
		t.Errorf("2001:db8::1 in 2001:db8::/32: got %+v, want Matched=true", inside)
	}
	outside := EvaluateSeccompConnect(store, "s1", net.ParseIP("2001:db9::1"))
	if outside.Matched {
		t.Errorf("2001:db9::1 outside 2001:db8::/32: got %+v, want Matched=false", outside)
	}
}

func TestApplySeccompPolicy_InvalidNetAllowEntryErrorsAndLeavesPriorPolicyIntact(t *testing.T) {
	store := NewSeccompPolicyStore()
	// Install a good policy first...
	good := netConnectRequest("s1", BpfActionAllow, BpfEnforceModeEnforce)
	if err := ApplySeccompPolicy(store, "s1", good); err != nil {
		t.Fatalf("apply good policy: %v", err)
	}

	// ...then attempt to overwrite it with a request that has a malformed
	// net_allow entry. The CIDR list is validated in full before any store
	// write happens, so this must fail loudly without disturbing the
	// existing policy — a partial/corrupt write here would be silent
	// under-enforcement, exactly what this codebase's fail-loud convention
	// (see the package header comment) exists to avoid.
	bad := netConnectRequest("s1", BpfActionAllowlist, BpfEnforceModeEnforce, "not-a-cidr-or-ip")
	if err := ApplySeccompPolicy(store, "s1", bad); err == nil {
		t.Fatal("expected an error applying a policy with a malformed net_allow entry, got nil")
	}

	d := EvaluateSeccompConnect(store, "s1", net.ParseIP("1.2.3.4"))
	if !d.HasPolicy || !d.Matched {
		t.Errorf("after a rejected apply, prior policy should still be in effect: got %+v", d)
	}
}

func TestApplySeccompPolicy_NoNetConnectOpClearsPriorPolicy(t *testing.T) {
	store := NewSeccompPolicyStore()
	if err := ApplySeccompPolicy(store, "s1", netConnectRequest("s1", BpfActionAllow, BpfEnforceModeEnforce)); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// A later apply_policy for the same session with no OP_NET_CONNECT rule
	// at all (e.g. exec/file-only policy) must clear the seccomp tier's
	// rule, not leave the stale one in effect.
	execOnly := DaemonApplyPolicyRequest{
		SessionID:  "s1",
		OpPolicies: []DaemonOpPolicy{{Op: BpfOpExec, Action: BpfActionDeny, EnforceMode: BpfEnforceModeEnforce}},
	}
	if err := ApplySeccompPolicy(store, "s1", execOnly); err != nil {
		t.Fatalf("apply exec-only policy: %v", err)
	}

	d := EvaluateSeccompConnect(store, "s1", net.ParseIP("1.2.3.4"))
	if d.HasPolicy {
		t.Errorf("after clearing OP_NET_CONNECT, HasPolicy = true, want false: %+v", d)
	}
}

func TestRemoveSeccompPolicy_ClearsSession(t *testing.T) {
	store := NewSeccompPolicyStore()
	if err := ApplySeccompPolicy(store, "s1", netConnectRequest("s1", BpfActionAllow, BpfEnforceModeEnforce)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	RemoveSeccompPolicy(store, "s1")
	d := EvaluateSeccompConnect(store, "s1", net.ParseIP("1.2.3.4"))
	if d.HasPolicy {
		t.Errorf("after RemoveSeccompPolicy, HasPolicy = true, want false: %+v", d)
	}
}

func TestEvaluateSeccompConnect_UnknownActionFailsClosed(t *testing.T) {
	store := NewSeccompPolicyStore()
	// Bypasses daemon_protocol.go's request validation deliberately, to
	// exercise EvaluateSeccompConnect's own defensive default: an
	// unrecognised action value must never resolve to a match.
	req := netConnectRequest("s1", BpfAction(99), BpfEnforceModeEnforce)
	if err := ApplySeccompPolicy(store, "s1", req); err != nil {
		t.Fatalf("apply: %v", err)
	}
	d := EvaluateSeccompConnect(store, "s1", net.ParseIP("1.2.3.4"))
	if d.Matched || d.Allowed {
		t.Errorf("unknown action value: got %+v, want Matched=Allowed=false (fail closed)", d)
	}
}

func TestEvaluateSeccompConnect_AllowlistWithNilIPNeverMatches(t *testing.T) {
	store := NewSeccompPolicyStore()
	req := netConnectRequest("s1", BpfActionAllowlist, BpfEnforceModeEnforce, "0.0.0.0/0")
	if err := ApplySeccompPolicy(store, "s1", req); err != nil {
		t.Fatalf("apply: %v", err)
	}
	d := EvaluateSeccompConnect(store, "s1", nil)
	if d.Matched || d.Allowed {
		t.Errorf("nil target IP against an allowlist: got %+v, want Matched=Allowed=false", d)
	}
}

func TestSeccompPolicyStore_PerSessionIsolation(t *testing.T) {
	store := NewSeccompPolicyStore()
	if err := ApplySeccompPolicy(store, "allow-session", netConnectRequest("allow-session", BpfActionAllow, BpfEnforceModeEnforce)); err != nil {
		t.Fatalf("apply allow-session: %v", err)
	}
	if err := ApplySeccompPolicy(store, "deny-session", netConnectRequest("deny-session", BpfActionDeny, BpfEnforceModeEnforce)); err != nil {
		t.Fatalf("apply deny-session: %v", err)
	}

	if d := EvaluateSeccompConnect(store, "allow-session", net.ParseIP("1.2.3.4")); !d.Allowed {
		t.Errorf("allow-session: got %+v, want Allowed=true", d)
	}
	if d := EvaluateSeccompConnect(store, "deny-session", net.ParseIP("1.2.3.4")); d.Allowed {
		t.Errorf("deny-session: got %+v, want Allowed=false", d)
	}
	if d := EvaluateSeccompConnect(store, "no-such-session", net.ParseIP("1.2.3.4")); d.HasPolicy {
		t.Errorf("no-such-session: got %+v, want HasPolicy=false", d)
	}
}
