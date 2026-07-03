package kernelcapture

// seccomp_policy.go — in-memory OP_NET_CONNECT policy store for the seccomp
// user-notify enforcement tier (Epic A #63, plan E4).
//
// This is the seccomp tier's counterpart to bpf_policy_apply.go: same
// DaemonApplyPolicyRequest schema, same BpfOp/BpfAction/BpfEnforceMode
// semantics, same CIDR-or-bare-IP net_allow parsing — "the SAME policy
// tables ... as the BPF tier" the plan calls for — but stored in an
// in-process map instead of kernel BPF maps, because E4 exists specifically
// for hosts where those kernel maps are never loaded (stock distros that
// ship CONFIG_BPF_LSM=y but don't put "bpf" in the boot lsm= list). No build
// tag: this has no syscall dependency and is fully unit-testable on
// darwin/CI, matching bpf_policy_apply.go's platform-independence rationale.
//
// Scope: OP_NET_CONNECT only. The seccomp filter this tier installs traps
// connect(2) exclusively (see seccomp_notify_linux.go) — there is no
// seccomp-user-notify equivalent for exec/file-open enforcement in this
// design. A seccomp filter *can* trap execve, but by the time a
// SECCOMP_RET_USER_NOTIF notification is serviced the new program image
// hasn't loaded yet, and SECCOMP_USER_NOTIF_FLAG_CONTINUE for execve carries
// TOCTOU hazards beyond what connect's fixed-size sockaddr argument has
// (variable-length argv/envp the tracee can keep mutating). Out of scope for
// E4; BPF-LSM remains the only tier that governs exec and file ops.
//
// Claim boundary (state up front, not just in the PR description): seccomp
// user-notify is weaker than an in-kernel LSM against a racing multithreaded
// adversary. The supervisor observes syscall arguments and reads target
// memory across a window bounded by SECCOMP_IOCTL_NOTIF_ID_VALID checks (see
// seccomp_notify_linux.go), but a sufficiently fast concurrent thread in the
// target process can still rewrite the sockaddr bytes between the kernel
// capturing the syscall arguments and this store's decision being enforced,
// in ways a kernel-resident LSM hook (which runs synchronously in the
// syscalling thread's own context, with no supervisor round-trip) is not
// exposed to. This tier is a real, load-bearing enforcement mechanism for
// single-threaded or cooperative targets — which describes the overwhelming
// majority of AI-agent subprocess trees this project governs — not a
// theoretically-airtight one against an adversarial multithreaded target.

import (
	"fmt"
	"net"
	"sync"
)

// SeccompPolicyStore holds each governed session's OP_NET_CONNECT policy.
// Safe for concurrent use.
type SeccompPolicyStore struct {
	mu       sync.RWMutex
	sessions map[string]seccompSessionPolicy
}

type seccompSessionPolicy struct {
	action      BpfAction
	enforceMode BpfEnforceMode
	allow       []*net.IPNet
}

// NewSeccompPolicyStore returns an empty store.
func NewSeccompPolicyStore() *SeccompPolicyStore {
	return &SeccompPolicyStore{sessions: make(map[string]seccompSessionPolicy)}
}

// ApplySeccompPolicy installs req's OP_NET_CONNECT rule (if any) for
// sessionID. Unlike ApplyPolicyMaps, an in-memory map write cannot fail on
// "guard not loaded" — the seccomp tier's apply_policy path has no degraded
// branch to speak of, only "this request had no OP_NET_CONNECT rule," which
// is a no-op (and clears any earlier rule for the session), not an error.
func ApplySeccompPolicy(store *SeccompPolicyStore, sessionID string, req DaemonApplyPolicyRequest) error {
	if store == nil {
		return fmt.Errorf("kernelcapture: seccomp policy store is required")
	}

	var netPolicy *DaemonOpPolicy
	for i := range req.OpPolicies {
		if req.OpPolicies[i].Op == BpfOpNetConnect {
			netPolicy = &req.OpPolicies[i]
			break
		}
	}
	if netPolicy == nil {
		store.mu.Lock()
		delete(store.sessions, sessionID)
		store.mu.Unlock()
		return nil
	}

	allow := make([]*net.IPNet, 0, len(req.NetAllow))
	for _, cidr := range req.NetAllow {
		ipNet, err := parseSeccompNetAllowEntry(cidr)
		if err != nil {
			return fmt.Errorf("kernelcapture: seccomp apply_policy net_allow (%q): %w", cidr, err)
		}
		allow = append(allow, ipNet)
	}

	store.mu.Lock()
	store.sessions[sessionID] = seccompSessionPolicy{
		action:      netPolicy.Action,
		enforceMode: netPolicy.EnforceMode,
		allow:       allow,
	}
	store.mu.Unlock()
	return nil
}

// RemoveSeccompPolicy clears sessionID's policy, mirroring RemovePolicyMaps'
// session-end cleanup for the BPF tier.
func RemoveSeccompPolicy(store *SeccompPolicyStore, sessionID string) {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.sessions, sessionID)
}

// SeccompConnectDecision is the result of evaluating one connect(2) attempt.
type SeccompConnectDecision struct {
	Action      BpfAction
	EnforceMode BpfEnforceMode
	// HasPolicy is false when sessionID has no OP_NET_CONNECT rule at all.
	// Unlike the BPF tier's STRICT-cgroup fail-closed default (any *governed*
	// cgroup with no rule for an op denies it), a seccomp listener is only
	// ever attached to a session that explicitly opted into this tier — an
	// absent rule here means "this session's policy doesn't govern network
	// connects," not "deny by default," so HasPolicy=false always resolves
	// to Allowed=true.
	HasPolicy bool
	// Matched is whether the target address satisfied the policy's ALLOW/
	// ALLOWLIST condition, independent of enforce mode — this is what the
	// emitted enforce_event's ActionTaken/verdict should reflect (a
	// PERMISSIVE-mode miss is still logged as a would-be deny).
	Matched bool
	// Allowed is the final syscall-level outcome the supervisor must act on:
	// whether to let connect(2) proceed (CONTINUE) or fail it with EPERM.
	// False only when Matched is false AND EnforceMode is Enforce.
	Allowed bool
}

// EvaluateSeccompConnect decides whether ip may be connect(2)'d to for
// sessionID, using the same BpfAction semantics process_guard.bpf.c's
// decide() applies for OP_NET_CONNECT: ACT_ALLOW always matches, ACT_DENY
// never matches, ACT_ALLOWLIST matches only if ip is covered by an entry in
// the session's net_allow CIDR list. An unrecognised action value fails
// closed (Matched=false) rather than defaulting to allow — silent
// under-enforcement is worse than a loud failure, the same principle
// bpf_lower.py's ENFORCE_STRICT loud-guard and ApplyPolicyMaps'
// ErrPolicyMapsUnavailable handling already apply elsewhere in this
// codebase.
func EvaluateSeccompConnect(store *SeccompPolicyStore, sessionID string, ip net.IP) SeccompConnectDecision {
	if store == nil {
		return SeccompConnectDecision{Allowed: true, HasPolicy: false}
	}
	store.mu.RLock()
	policy, ok := store.sessions[sessionID]
	store.mu.RUnlock()
	if !ok {
		return SeccompConnectDecision{Allowed: true, HasPolicy: false}
	}

	matched := false
	switch policy.action {
	case BpfActionAllow:
		matched = true
	case BpfActionDeny:
		matched = false
	case BpfActionAllowlist:
		for _, ipNet := range policy.allow {
			if ip != nil && ipNet.Contains(ip) {
				matched = true
				break
			}
		}
	default:
		matched = false
	}

	allowed := matched || policy.enforceMode != BpfEnforceModeEnforce
	return SeccompConnectDecision{
		Action:      policy.action,
		EnforceMode: policy.enforceMode,
		HasPolicy:   true,
		Matched:     matched,
		Allowed:     allowed,
	}
}

// parseSeccompNetAllowEntry mirrors netLpmKey's CIDR-or-bare-IP acceptance in
// bpf_policy_apply.go, so the same net_allow list produces the same matching
// behavior on either tier.
func parseSeccompNetAllowEntry(cidr string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err == nil {
		return ipNet, nil
	}
	ip := net.ParseIP(cidr)
	if ip == nil {
		return nil, fmt.Errorf("invalid CIDR/IP %q: %w", cidr, err)
	}
	if ip4 := ip.To4(); ip4 != nil {
		return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}, nil
}
