package kernelcapture

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

const (
	DaemonProtocolVersion = "kernelcapture.daemon.v1"

	DaemonProtocolMethodHealth          = "health"
	DaemonProtocolMethodRegisterSession = "register_session"
	DaemonProtocolMethodRegisterReceipt = "register_receipt"
	DaemonProtocolMethodEndSession      = "end_session"
	DaemonProtocolMethodSessionStatus   = "session_status"
	DaemonProtocolMethodApplyPolicy     = "apply_policy"
	DaemonProtocolMethodSetKillSwitch   = "set_kill_switch"

	DaemonProtocolEventProcessLifecycle = "process_lifecycle"

	// EnforcementTierBPFLSM/EnforcementTierSeccomp/EnforcementTierNone are the
	// values a health response's EnforcementTier field takes. Forward-
	// compatible with future tiers — a new tier adds a new constant here, not
	// a breaking change to the field's meaning.
	EnforcementTierBPFLSM  = "bpf_lsm"
	EnforcementTierSeccomp = "seccomp"
	EnforcementTierNone    = "none"

	MaxDaemonProtocolTTLSeconds = 24 * 60 * 60
	MaxDaemonReceiptIDBytes     = 512

	// MaxDaemonPolicyGeneration is the largest generation value the daemon will
	// accept in an apply_policy request. Generation 0 is reserved to mean
	// "uninitialized" in the BPF program; callers must start at 1.
	MaxDaemonPolicyGeneration = 1<<32 - 1
)

var ErrDaemonProtocol = errors.New("kernelcapture: invalid daemon protocol message")

// DaemonProtocolRequest is the narrow launch-wrapper-to-daemon request
// contract. It is JSON-line compatible: each encoded request is one
// deterministic JSON object followed by '\n'. No socket server is implemented
// in this slice.
type DaemonProtocolRequest struct {
	ProtocolVersion string                        `json:"protocol_version"`
	Method          string                        `json:"method"`
	Health          *DaemonHealthRequest          `json:"health,omitempty"`
	RegisterSession *DaemonRegisterSessionRequest `json:"register_session,omitempty"`
	RegisterReceipt *DaemonRegisterReceiptRequest `json:"register_receipt,omitempty"`
	EndSession      *DaemonEndSessionRequest      `json:"end_session,omitempty"`
	SessionStatus   *DaemonSessionStatusRequest   `json:"session_status,omitempty"`
	ApplyPolicy     *DaemonApplyPolicyRequest     `json:"apply_policy,omitempty"`
	SetKillSwitch   *DaemonSetKillSwitchRequest   `json:"set_kill_switch,omitempty"`
}

// DaemonSetKillSwitchRequest engages or disengages the global BPF-LSM
// kill switch. Engaged=true suspends all enforcement (every op passes
// through); false re-enables enforcement per the currently applied policy.
// This is a global, not per-session, control — like health, it carries no
// session_id; peer authorization (UID/GID allowlist) is what gates who may
// call it, the same as every other method.
type DaemonSetKillSwitchRequest struct {
	Engaged bool `json:"engaged"`
}

// DaemonApplyPolicyRequest installs or replaces the BPF enforcement policy for
// one session's cgroup. The daemon writes the supplied entries to the BPF
// maps in the order: op_policies → path_allow → daemon-bounded trusted-root
// runtime state and exact control-plane endpoint → net_allow → cgroup_managed
// (generation-atomic, managed flag written last).
//
// Generation must be non-zero and strictly increasing relative to the previous
// apply for this session.  The BPF program uses the generation to detect stale
// map entries left over from a prior policy cycle.
type DaemonApplyPolicyRequest struct {
	SessionID            string                      `json:"session_id"`
	OpPolicies           []DaemonOpPolicy            `json:"op_policies"`
	PathAllow            []string                    `json:"path_allow,omitempty"`
	NetAllow             []string                    `json:"net_allow,omitempty"` // CIDR strings (IPv4 or IPv6)
	Generation           BpfPolicyGeneration         `json:"generation"`
	EnforceMode          BpfEnforceMode              `json:"enforce_mode"` // default mode for no-rule ops
	ControlPlaneEndpoint *DaemonControlPlaneEndpoint `json:"control_plane_endpoint,omitempty"`
	BootstrapReadAllow   []string                    `json:"bootstrap_read_allow,omitempty"`
	// RootPID is stamped from the daemon's active session registry after wire
	// validation. It is never accepted from JSON or trusted from the client.
	RootPID uint32 `json:"-"`
	// BootstrapFiles are exact initial executable/argument file identities
	// observed by the daemon while RootPID is stopped at exec. They are never
	// accepted from JSON, so the governed client cannot widen this set.
	BootstrapFiles []BootstrapFile `json:"-"`
}

const MaxBootstrapFileIdentities = 4

// BootstrapFile identifies one daemon-observed initial regular file. The LSM
// fills KernelDevice during a daemon-only observation handshake, avoiding
// userspace namespace translation of the backing filesystem identity.
type BootstrapFile struct {
	Path         string
	KernelDevice uint64
	Inode        uint64
}

// DaemonControlPlaneEndpoint is the exact loopback listener owned by the
// authenticated ardur-run bridge. It is deliberately separate from NetAllow:
// the seccomp supervisor may emulate a connect to this one tuple, but it must
// never turn into a mission-controlled CIDR or wildcard exception.
type DaemonControlPlaneEndpoint struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

// DaemonOpPolicy is one (op, action, enforce_mode) triple in an apply_policy
// request. It corresponds to one entry written to cgroup_op_policy BPF hash map.
type DaemonOpPolicy struct {
	Op          BpfOp          `json:"op"`
	Action      BpfAction      `json:"action"`
	EnforceMode BpfEnforceMode `json:"enforce_mode"`
}

type DaemonHealthRequest struct{}

type DaemonRegisterSessionRequest struct {
	SessionID       string         `json:"session_id"`
	MissionID       string         `json:"mission_id,omitempty"`
	TraceID         string         `json:"trace_id,omitempty"`
	RootPID         uint32         `json:"root_pid,omitempty"`
	PIDNamespaceID  uint32         `json:"pid_namespace_id,omitempty"`
	CgroupID        uint64         `json:"cgroup_id,omitempty"`
	EventClasses    []string       `json:"event_classes"`
	TTLSeconds      int64          `json:"ttl_seconds"`
	HandoffMetadata map[string]any `json:"handoff_metadata,omitempty"`
	// RootProcessStartTimeTicks is stamped from daemon-observed /proc identity
	// after cgroup/ancestry verification. It is never accepted from JSON.
	RootProcessStartTimeTicks uint64 `json:"-"`
}

// DaemonRegisterReceiptRequest reports one governance receipt to the daemon
// before the governed action is released. The daemon supplies the session's
// process identity, cgroup, and observation time from its own state; the client
// may provide only the opaque receipt identifier.
type DaemonRegisterReceiptRequest struct {
	SessionID string `json:"session_id"`
	ReceiptID string `json:"receipt_id"`
}

type DaemonEndSessionRequest struct {
	SessionID string `json:"session_id"`
	TraceID   string `json:"trace_id,omitempty"`
}

type DaemonSessionStatusRequest struct {
	SessionID string `json:"session_id"`
}

type DaemonProtocolResponse struct {
	ProtocolVersion string `json:"protocol_version"`
	OK              bool   `json:"ok"`
	Method          string `json:"method"`
	SessionID       string `json:"session_id,omitempty"`
	Status          string `json:"status,omitempty"`
	Error           string `json:"error,omitempty"`
	// Enforcement carries a session's kernel-enforcement rollup on successful
	// session_status responses. Populated by the daemon when enforce_events
	// have been processed for the session; omitted otherwise. Evidence-log
	// directories are root-0700, so this is the only channel a non-root client
	// has to learn what kernel-level enforcement happened.
	Enforcement *EnforceEventSummary `json:"enforcement,omitempty"`
	// LifecycleCapture reports daemon-global process exec/exit capture loss that
	// occurred while this session was active. It is populated on successful
	// session_status and end_session responses. Loss is summarized independently
	// for every concurrently active session because a malformed host-level record
	// cannot be attributed to whichever session produces the next valid event.
	LifecycleCapture *LifecycleCaptureSummary `json:"lifecycle_capture,omitempty"`
	// ObservabilityGap measures only the process lifecycle effects captured for
	// this session. It never represents universal file, network, or host-effect
	// coverage, and its status degrades with LifecycleCapture loss.
	ObservabilityGap *ObservabilityGapSummary `json:"observability_gap,omitempty"`
	// AgentFingerprint reports bounded asynchronous native-executable matching
	// state on authenticated health responses only. It never contains a host
	// path, computed executable digest, argv, environment, or file content.
	AgentFingerprint *AgentFingerprintHealth `json:"agent_fingerprint,omitempty"`
	// EnforcementTier carries which kernel enforcement tier is currently
	// active — EnforcementTierBPFLSM, EnforcementTierSeccomp, or
	// EnforcementTierNone — on successful health responses. The daemon
	// decides this once at startup (BPF-LSM preferred, seccomp as fallback)
	// and never changes it while running; a launcher queries it to decide
	// whether a governed process needs to be routed through ardur-exec-shim
	// (the seccomp tier's on-ramp) before spawning one, or can rely on
	// BPF-LSM's cgroup-scoped enforcement with no per-process wrapper at all.
	// session_status responses use Enforcement (per-session) instead.
	EnforcementTier string `json:"enforcement_tier,omitempty"`
	// SeccompListenerAttached is populated on successful session_status
	// responses (never on health — attachment is per-session, not
	// daemon-wide) to report whether a seccomp user-notify listener is
	// *currently* supervising this session, i.e. whether some
	// ardur-exec-shim's handoff for it actually completed.
	//
	// This exists because EnforcementTier=="seccomp" alone is not proof that
	// enforcement is live for any given session: it only says the daemon
	// *would* enforce net-connect policy via seccomp if a listener attaches.
	// apply_policy syncing the seccomp policy store (handleApplyPolicy) is
	// similarly necessary but not sufficient — the store update and the
	// shim's handoff are two independent operations that can each succeed or
	// fail on their own. A launcher that only checked the first two and
	// declared success (issue #104) would silently govern nothing: no shim
	// wraps the agent, no filter traps its connect(2) calls, and yet
	// apply_policy honestly (not falsely) reported the tier-side policy as
	// applied. This field lets a caller confirm the *third*, session-scoped
	// fact before trusting that a run is actually enforced.
	//
	// No omitempty: false is a meaningful, load-bearing answer here, and a
	// client must be able to tell "not attached" apart from "field absent
	// because this daemon predates it" — always emitting it removes that
	// ambiguity on the wire.
	SeccompListenerAttached bool `json:"seccomp_listener_attached"`
}

// CgroupFilterSequence describes daemon-side map sequencing. Enabling
// filtering is only valid after at least one non-zero allowlist entry exists.
type CgroupFilterSequence struct {
	Enable             bool
	AllowlistCgroupIDs []uint64
}

func EncodeDaemonProtocolRequest(req DaemonProtocolRequest) ([]byte, error) {
	if err := ValidateDaemonProtocolRequest(req); err != nil {
		return nil, err
	}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("%w: encode request: %v", ErrDaemonProtocol, err)
	}
	return append(data, '\n'), nil
}

func DecodeDaemonProtocolRequest(data []byte) (DaemonProtocolRequest, error) {
	if err := rejectPrivilegedDaemonProtocolFields(data); err != nil {
		return DaemonProtocolRequest{}, err
	}
	var req DaemonProtocolRequest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return DaemonProtocolRequest{}, fmt.Errorf("%w: decode request: %v", ErrDaemonProtocol, err)
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return DaemonProtocolRequest{}, fmt.Errorf("%w: multiple JSON values are not allowed", ErrDaemonProtocol)
	} else if !errors.Is(err, io.EOF) {
		return DaemonProtocolRequest{}, fmt.Errorf("%w: trailing data after request: %v", ErrDaemonProtocol, err)
	}
	if err := ValidateDaemonProtocolRequest(req); err != nil {
		return DaemonProtocolRequest{}, err
	}
	return req, nil
}

func EncodeDaemonProtocolResponse(resp DaemonProtocolResponse) ([]byte, error) {
	if resp.ProtocolVersion == "" {
		resp.ProtocolVersion = DaemonProtocolVersion
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("%w: encode response: %v", ErrDaemonProtocol, err)
	}
	return append(data, '\n'), nil
}

func DecodeDaemonProtocolResponse(data []byte) (DaemonProtocolResponse, error) {
	var resp DaemonProtocolResponse
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&resp); err != nil {
		return DaemonProtocolResponse{}, fmt.Errorf("%w: decode response: %v", ErrDaemonProtocol, err)
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return DaemonProtocolResponse{}, fmt.Errorf("%w: multiple JSON values are not allowed in response", ErrDaemonProtocol)
	} else if !errors.Is(err, io.EOF) {
		return DaemonProtocolResponse{}, fmt.Errorf("%w: trailing data after response: %v", ErrDaemonProtocol, err)
	}
	if resp.ProtocolVersion != DaemonProtocolVersion {
		return DaemonProtocolResponse{}, fmt.Errorf("%w: unsupported response protocol version %q", ErrDaemonProtocol, resp.ProtocolVersion)
	}
	switch resp.Method {
	case "", DaemonProtocolMethodHealth, DaemonProtocolMethodRegisterSession, DaemonProtocolMethodRegisterReceipt,
		DaemonProtocolMethodEndSession, DaemonProtocolMethodSessionStatus,
		DaemonProtocolMethodApplyPolicy, DaemonProtocolMethodSetKillSwitch:
	default:
		return DaemonProtocolResponse{}, fmt.Errorf("%w: unknown response method %q", ErrDaemonProtocol, resp.Method)
	}
	return resp, nil
}

func ValidateDaemonProtocolRequest(req DaemonProtocolRequest) error {
	if req.ProtocolVersion != DaemonProtocolVersion {
		return fmt.Errorf("%w: unsupported protocol version %q", ErrDaemonProtocol, req.ProtocolVersion)
	}
	switch req.Method {
	case DaemonProtocolMethodHealth:
		if req.Health == nil || req.RegisterSession != nil || req.RegisterReceipt != nil || req.EndSession != nil || req.SessionStatus != nil || req.ApplyPolicy != nil || req.SetKillSwitch != nil {
			return fmt.Errorf("%w: health request must include only health payload", ErrDaemonProtocol)
		}
	case DaemonProtocolMethodRegisterSession:
		if req.RegisterSession == nil || req.Health != nil || req.RegisterReceipt != nil || req.EndSession != nil || req.SessionStatus != nil || req.ApplyPolicy != nil || req.SetKillSwitch != nil {
			return fmt.Errorf("%w: register_session request must include only register_session payload", ErrDaemonProtocol)
		}
		return validateDaemonRegisterSession(*req.RegisterSession)
	case DaemonProtocolMethodRegisterReceipt:
		if req.RegisterReceipt == nil || req.Health != nil || req.RegisterSession != nil || req.EndSession != nil || req.SessionStatus != nil || req.ApplyPolicy != nil || req.SetKillSwitch != nil {
			return fmt.Errorf("%w: register_receipt request must include only register_receipt payload", ErrDaemonProtocol)
		}
		return validateDaemonRegisterReceipt(*req.RegisterReceipt)
	case DaemonProtocolMethodEndSession:
		if req.EndSession == nil || req.Health != nil || req.RegisterSession != nil || req.RegisterReceipt != nil || req.SessionStatus != nil || req.ApplyPolicy != nil || req.SetKillSwitch != nil {
			return fmt.Errorf("%w: end_session request must include only end_session payload", ErrDaemonProtocol)
		}
		if strings.TrimSpace(req.EndSession.SessionID) == "" {
			return fmt.Errorf("%w: end_session session_id is required", ErrDaemonProtocol)
		}
	case DaemonProtocolMethodSessionStatus:
		if req.SessionStatus == nil || req.Health != nil || req.RegisterSession != nil || req.RegisterReceipt != nil || req.EndSession != nil || req.ApplyPolicy != nil || req.SetKillSwitch != nil {
			return fmt.Errorf("%w: session_status request must include only session_status payload", ErrDaemonProtocol)
		}
		if strings.TrimSpace(req.SessionStatus.SessionID) == "" {
			return fmt.Errorf("%w: session_status session_id is required", ErrDaemonProtocol)
		}
	case DaemonProtocolMethodApplyPolicy:
		if req.ApplyPolicy == nil || req.Health != nil || req.RegisterSession != nil || req.RegisterReceipt != nil || req.EndSession != nil || req.SessionStatus != nil || req.SetKillSwitch != nil {
			return fmt.Errorf("%w: apply_policy request must include only apply_policy payload", ErrDaemonProtocol)
		}
		return validateDaemonApplyPolicy(*req.ApplyPolicy)
	case DaemonProtocolMethodSetKillSwitch:
		if req.SetKillSwitch == nil || req.Health != nil || req.RegisterSession != nil || req.RegisterReceipt != nil || req.EndSession != nil || req.SessionStatus != nil || req.ApplyPolicy != nil {
			return fmt.Errorf("%w: set_kill_switch request must include only set_kill_switch payload", ErrDaemonProtocol)
		}
	default:
		return fmt.Errorf("%w: unknown method %q", ErrDaemonProtocol, req.Method)
	}
	return nil
}

func validateDaemonRegisterReceipt(req DaemonRegisterReceiptRequest) error {
	if strings.TrimSpace(req.SessionID) == "" {
		return fmt.Errorf("%w: register_receipt session_id is required", ErrDaemonProtocol)
	}
	receiptID := strings.TrimSpace(req.ReceiptID)
	if receiptID == "" {
		return fmt.Errorf("%w: register_receipt receipt_id is required", ErrDaemonProtocol)
	}
	if receiptID != req.ReceiptID {
		return fmt.Errorf("%w: register_receipt receipt_id must not contain surrounding whitespace", ErrDaemonProtocol)
	}
	if len(receiptID) > MaxDaemonReceiptIDBytes {
		return fmt.Errorf("%w: register_receipt receipt_id exceeds %d bytes", ErrDaemonProtocol, MaxDaemonReceiptIDBytes)
	}
	for _, ch := range receiptID {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || strings.ContainsRune("._:-", ch)) {
			return fmt.Errorf("%w: register_receipt receipt_id contains unsupported characters", ErrDaemonProtocol)
		}
	}
	return nil
}

func validateDaemonApplyPolicy(req DaemonApplyPolicyRequest) error {
	if strings.TrimSpace(req.SessionID) == "" {
		return fmt.Errorf("%w: apply_policy session_id is required", ErrDaemonProtocol)
	}
	if req.Generation == 0 {
		return fmt.Errorf("%w: apply_policy generation must be non-zero (0 is reserved for uninitialized)", ErrDaemonProtocol)
	}
	seenOps := map[BpfOp]struct{}{}
	for i, p := range req.OpPolicies {
		switch p.Op {
		case BpfOpExec, BpfOpFileRead, BpfOpFileWrite, BpfOpNetConnect, BpfOpExternalSend:
		default:
			return fmt.Errorf("%w: apply_policy op_policies[%d]: unknown op %d", ErrDaemonProtocol, i, p.Op)
		}
		if _, dup := seenOps[p.Op]; dup {
			return fmt.Errorf("%w: apply_policy op_policies[%d]: duplicate op %s", ErrDaemonProtocol, i, p.Op)
		}
		seenOps[p.Op] = struct{}{}
		switch p.Action {
		case BpfActionAllow, BpfActionDeny, BpfActionAllowlist:
		default:
			return fmt.Errorf("%w: apply_policy op_policies[%d]: unknown action %d", ErrDaemonProtocol, i, p.Action)
		}
		switch p.EnforceMode {
		case BpfEnforceModePermissive, BpfEnforceModeEnforce:
		default:
			return fmt.Errorf("%w: apply_policy op_policies[%d]: unknown enforce_mode %d", ErrDaemonProtocol, i, p.EnforceMode)
		}
	}
	for i, p := range req.PathAllow {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("%w: apply_policy path_allow[%d]: path %q must be absolute", ErrDaemonProtocol, i, p)
		}
	}
	allowedBootstrap := map[string]struct{}{
		"/usr": {}, "/lib": {}, "/lib64": {}, "/etc/ld.so.cache": {}, "/etc/ssl/certs": {}, "/dev/urandom": {},
	}
	seenBootstrap := make(map[string]struct{}, len(req.BootstrapReadAllow))
	for i, p := range req.BootstrapReadAllow {
		if _, ok := allowedBootstrap[p]; !ok {
			return fmt.Errorf("%w: apply_policy bootstrap_read_allow[%d]: path %q is not a daemon-approved runtime root", ErrDaemonProtocol, i, p)
		}
		if _, duplicate := seenBootstrap[p]; duplicate {
			return fmt.Errorf("%w: apply_policy bootstrap_read_allow[%d]: duplicate path %q", ErrDaemonProtocol, i, p)
		}
		seenBootstrap[p] = struct{}{}
	}
	if req.ControlPlaneEndpoint != nil {
		if _, ok := seenOps[BpfOpNetConnect]; !ok {
			return fmt.Errorf("%w: apply_policy control_plane_endpoint requires OP_NET_CONNECT", ErrDaemonProtocol)
		}
		if _, err := parseDaemonControlPlaneEndpoint(*req.ControlPlaneEndpoint); err != nil {
			return fmt.Errorf("%w: apply_policy control_plane_endpoint: %v", ErrDaemonProtocol, err)
		}
	}
	switch req.EnforceMode {
	case BpfEnforceModePermissive, BpfEnforceModeEnforce:
	default:
		return fmt.Errorf("%w: apply_policy unknown enforce_mode %d", ErrDaemonProtocol, req.EnforceMode)
	}
	return nil
}

func parseDaemonControlPlaneEndpoint(endpoint DaemonControlPlaneEndpoint) (net.IP, error) {
	if endpoint.Port == 0 {
		return nil, fmt.Errorf("port must be non-zero")
	}
	ipText := strings.TrimSpace(endpoint.IP)
	if ipText != endpoint.IP || ipText == "" {
		return nil, fmt.Errorf("ip must be a non-empty literal without surrounding whitespace")
	}
	ip := net.ParseIP(ipText)
	if ip == nil {
		return nil, fmt.Errorf("ip %q must be a literal address", endpoint.IP)
	}
	if !ip.IsLoopback() {
		return nil, fmt.Errorf("ip %q must be loopback", endpoint.IP)
	}
	if ip4 := ip.To4(); ip4 != nil {
		return append(net.IP(nil), ip4...), nil
	}
	return append(net.IP(nil), ip.To16()...), nil
}

func validateDaemonRegisterSession(req DaemonRegisterSessionRequest) error {
	if strings.TrimSpace(req.SessionID) == "" {
		return fmt.Errorf("%w: register_session session_id is required", ErrDaemonProtocol)
	}
	if req.RootPID == 0 {
		return fmt.Errorf("%w: register_session root_pid is required", ErrDaemonProtocol)
	}
	if req.CgroupID == 0 {
		return fmt.Errorf("%w: register_session cgroup_id is required", ErrDaemonProtocol)
	}
	if req.TTLSeconds <= 0 || req.TTLSeconds > MaxDaemonProtocolTTLSeconds {
		return fmt.Errorf("%w: ttl_seconds must be between 1 and %d", ErrDaemonProtocol, MaxDaemonProtocolTTLSeconds)
	}
	if len(req.EventClasses) == 0 {
		return fmt.Errorf("%w: at least one event class is required", ErrDaemonProtocol)
	}
	seen := map[string]struct{}{}
	for _, eventClass := range req.EventClasses {
		switch eventClass {
		case DaemonProtocolEventProcessLifecycle:
			seen[eventClass] = struct{}{}
		default:
			return fmt.Errorf("%w: unknown event class %q", ErrDaemonProtocol, eventClass)
		}
	}
	if len(seen) != len(req.EventClasses) {
		return fmt.Errorf("%w: duplicate event classes are not allowed", ErrDaemonProtocol)
	}
	normalizedHandoff, err := normalizeDaemonProtocolHandoffMetadata(req.HandoffMetadata)
	if err != nil {
		return err
	}
	if containsForbiddenClientHandoffMetadataField(normalizedHandoff) {
		return fmt.Errorf("%w: register_session handoff metadata contains raw command, path, environment, secret-like, daemon-owned path, or peer identity fields", ErrDaemonProtocol)
	}
	return nil
}

func normalizeDaemonProtocolHandoffMetadata(metadata map[string]any) (map[string]any, error) {
	if len(metadata) == 0 {
		return map[string]any{}, nil
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("%w: register_session handoff metadata must be JSON-encodable: %v", ErrDaemonProtocol, err)
	}
	var normalized map[string]any
	if err := json.Unmarshal(data, &normalized); err != nil {
		return nil, fmt.Errorf("%w: register_session handoff metadata must be JSON object metadata: %v", ErrDaemonProtocol, err)
	}
	return normalized, nil
}

func ValidateCgroupFilterSequence(seq CgroupFilterSequence) error {
	if !seq.Enable {
		return nil
	}
	if len(seq.AllowlistCgroupIDs) == 0 {
		return fmt.Errorf("%w: cgroup filtering cannot be enabled before allowlist entries exist", ErrDaemonProtocol)
	}
	for _, cgroupID := range seq.AllowlistCgroupIDs {
		if cgroupID == 0 {
			return fmt.Errorf("%w: cgroup allowlist entries must be non-zero before enabling filtering", ErrDaemonProtocol)
		}
	}
	return nil
}

func rejectPrivilegedDaemonProtocolFields(data []byte) error {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("%w: decode raw request: %v", ErrDaemonProtocol, err)
	}
	if containsPrivilegedDaemonProtocolField(raw) {
		return fmt.Errorf("%w: client-supplied daemon-controlled path or peer identity fields are forbidden", ErrDaemonProtocol)
	}
	return nil
}

func containsPrivilegedDaemonProtocolField(value any) bool {
	obj, ok := value.(map[string]any)
	if !ok {
		list, ok := value.([]any)
		if !ok {
			return false
		}
		for _, item := range list {
			if containsPrivilegedDaemonProtocolField(item) {
				return true
			}
		}
		return false
	}
	for key, nested := range obj {
		if isPrivilegedDaemonProtocolMetadataKey(normalizedLaunchWrapperMetadataKey(key)) {
			return true
		}
		if containsPrivilegedDaemonProtocolField(nested) {
			return true
		}
	}
	return false
}

func isPrivilegedDaemonProtocolMetadataKey(normalizedKey string) bool {
	switch normalizedKey {
	case "configpath", "statedir", "rundir", "socketpath", "bpffsdir", "ringbufmappath", "pinnedmappath", "mappath",
		"peeruid", "peergid", "peerpid", "peercredentials", "sopeercred", "linuxsopeercred", "ucred", "credentialsource",
		"processstarttime", "processstarttimeticks", "peerprocessstarttime", "peerprocessstarttimeticks", "peerstarttime", "peerstarttimeticks":
		return true
	default:
		return false
	}
}
