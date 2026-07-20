package kernelcapture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	AgentFingerprintRegistrySchema       = "ardur.agent_fingerprint_registry.v0.2"
	agentFingerprintRegistryLegacySchema = "ardur.agent_fingerprint_registry.v0.1"
	AgentFingerprintResultSchema         = "ardur.agent_fingerprint_result.v0.1"

	AgentFingerprintMethodSHA256ProcExe        = "sha256_proc_exe"
	AgentFingerprintMethodSHA256KernelLauncher = "sha256_kernel_bound_launcher"

	AgentFingerprintObjectLinked  = "linked"
	AgentFingerprintObjectDeleted = "deleted"
	AgentFingerprintObjectUnknown = "unknown"

	AgentFingerprintOutcomeSuccess           = "success"
	AgentFingerprintOutcomeDigestMismatch    = "digest_mismatch"
	AgentFingerprintOutcomeQueueSaturated    = "queue_saturated"
	AgentFingerprintOutcomeResolutionDenied  = "resolution_denied"
	AgentFingerprintOutcomeProcessExited     = "process_exited"
	AgentFingerprintOutcomeUnsupported       = "unsupported"
	AgentFingerprintOutcomeUnsupportedKernel = "unsupported_kernel"
	AgentFingerprintOutcomeUnsupportedFS     = "unsupported_filesystem"
	AgentFingerprintOutcomeMissingIdentity   = "missing_kernel_object_identity"
	AgentFingerprintOutcomeMissingLocator    = "missing_locator"
	AgentFingerprintOutcomeLocatorMismatch   = "locator_mismatch"
	AgentFingerprintOutcomeInterpreterDenied = "interpreter_not_allowed"
	AgentFingerprintOutcomeArgumentLimit     = "argument_limit_exceeded"
	AgentFingerprintOutcomeSizeExceeded      = "size_exceeded"
	AgentFingerprintOutcomeDeadlineExceeded  = "deadline_exceeded"
	AgentFingerprintOutcomeWorkerUnavailable = "worker_unavailable"
)

const (
	MaxAgentFingerprintRegistryBytes       = 64 << 10
	maxAgentFingerprintRules               = 64
	maxAgentFingerprintDigestsPerRule      = 16
	maxAgentFingerprintInterpretersPerRule = 16

	DefaultAgentFingerprintQueueCapacity    = 64
	DefaultAgentFingerprintWorkerCount      = 2
	DefaultAgentFingerprintMaxFileBytes     = 32 << 20
	DefaultAgentFingerprintTimeout          = 500 * time.Millisecond
	DefaultAgentFingerprintMaxArgumentBytes = 16 << 10
	DefaultAgentFingerprintMaxArguments     = 64
)

var ErrAgentFingerprintWorkerClosed = errors.New("kernelcapture: agent fingerprint worker is closed")

// AgentFingerprintRule binds one recognized agent class to operator-owned
// native and/or launcher digests. Launcher digests are valid only with one of
// the exact final-interpreter profiles in the same rule. Computed digests and
// interpreter names are never published in results or health data.
type AgentFingerprintRule struct {
	RuleID                     string   `json:"rule_id"`
	AgentType                  string   `json:"agent_type"`
	ExpectedSHA256             []string `json:"expected_sha256,omitempty"`
	ExpectedLauncherSHA256     []string `json:"expected_launcher_sha256,omitempty"`
	AllowedInterpreterProfiles []string `json:"allowed_interpreter_profiles,omitempty"`
}

// AgentFingerprintRegistryDocument is the bounded on-disk JSON contract.
// File ownership and mode checks are performed by the privileged daemon before
// this parser sees bytes.
type AgentFingerprintRegistryDocument struct {
	SchemaVersion   string                 `json:"schema_version"`
	RegistryVersion string                 `json:"registry_version"`
	Rules           []AgentFingerprintRule `json:"rules"`
}

type agentFingerprintExpectedRule struct {
	ruleID              string
	nativeDigests       [][sha256.Size]byte
	launcherDigests     [][sha256.Size]byte
	interpreterProfiles map[string]struct{}
}

// AgentFingerprintRegistry is immutable after parsing and safe for concurrent
// worker access.
type AgentFingerprintRegistry struct {
	version string
	digest  string
	byType  map[string][]agentFingerprintExpectedRule
}

// ParseAgentFingerprintRegistry validates and canonicalizes one bounded JSON
// document. It reads at most the hard limit plus one sentinel byte.
func ParseAgentFingerprintRegistry(r io.Reader) (*AgentFingerprintRegistry, error) {
	if r == nil {
		return nil, fmt.Errorf("agent fingerprint registry reader is required")
	}
	raw, err := io.ReadAll(io.LimitReader(r, MaxAgentFingerprintRegistryBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read agent fingerprint registry: %w", err)
	}
	if len(raw) > MaxAgentFingerprintRegistryBytes {
		return nil, fmt.Errorf("agent fingerprint registry exceeds the maximum size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document AgentFingerprintRegistryDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode agent fingerprint registry: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("decode agent fingerprint registry: multiple JSON values are not allowed")
		}
		return nil, fmt.Errorf("decode agent fingerprint registry trailing data: %w", err)
	}
	return NewAgentFingerprintRegistry(document)
}

// NewAgentFingerprintRegistry validates, canonicalizes, and hashes a registry
// document without retaining the caller's slices.
func NewAgentFingerprintRegistry(document AgentFingerprintRegistryDocument) (*AgentFingerprintRegistry, error) {
	if document.SchemaVersion != AgentFingerprintRegistrySchema && document.SchemaVersion != agentFingerprintRegistryLegacySchema {
		return nil, fmt.Errorf("agent fingerprint registry schema must be %q or %q", AgentFingerprintRegistrySchema, agentFingerprintRegistryLegacySchema)
	}
	document.RegistryVersion = strings.TrimSpace(document.RegistryVersion)
	if !agentRecognitionIdentifier.MatchString(document.RegistryVersion) {
		return nil, fmt.Errorf("agent fingerprint registry version is invalid")
	}
	if len(document.Rules) == 0 || len(document.Rules) > maxAgentFingerprintRules {
		return nil, fmt.Errorf("agent fingerprint registry must contain 1..%d rules", maxAgentFingerprintRules)
	}

	canonical := make([]AgentFingerprintRule, 0, len(document.Rules))
	knownRuleIDs := make(map[string]struct{}, len(document.Rules))
	digestOwners := make(map[[sha256.Size]byte]string)
	byType := make(map[string][]agentFingerprintExpectedRule)
	for index, input := range document.Rules {
		ruleID := strings.TrimSpace(input.RuleID)
		agentType := strings.TrimSpace(input.AgentType)
		if !agentRecognitionIdentifier.MatchString(ruleID) || !agentRecognitionIdentifier.MatchString(agentType) {
			return nil, fmt.Errorf("agent fingerprint rule %d has an invalid id or agent type", index)
		}
		if _, duplicate := knownRuleIDs[ruleID]; duplicate {
			return nil, fmt.Errorf("agent fingerprint rule id %q is duplicated", ruleID)
		}
		knownRuleIDs[ruleID] = struct{}{}
		if document.SchemaVersion == agentFingerprintRegistryLegacySchema && (len(input.ExpectedLauncherSHA256) > 0 || len(input.AllowedInterpreterProfiles) > 0) {
			return nil, fmt.Errorf("agent fingerprint rule %q requires schema %q for launcher fields", ruleID, AgentFingerprintRegistrySchema)
		}
		if len(input.ExpectedSHA256) > maxAgentFingerprintDigestsPerRule || len(input.ExpectedLauncherSHA256) > maxAgentFingerprintDigestsPerRule {
			return nil, fmt.Errorf("agent fingerprint rule %q exceeds the %d-digest limit", ruleID, maxAgentFingerprintDigestsPerRule)
		}
		if len(input.ExpectedSHA256) == 0 && len(input.ExpectedLauncherSHA256) == 0 {
			return nil, fmt.Errorf("agent fingerprint rule %q must contain native or launcher SHA-256 digests", ruleID)
		}

		parseDigests := func(rawValues []string, kind string) ([]string, [][sha256.Size]byte, error) {
			canonicalDigests := make([]string, 0, len(rawValues))
			parsedDigests := make([][sha256.Size]byte, 0, len(rawValues))
			seen := make(map[[sha256.Size]byte]struct{}, len(rawValues))
			for _, raw := range rawValues {
				digest, canonicalDigest, err := parseAgentFingerprintSHA256(raw)
				if err != nil {
					return nil, nil, fmt.Errorf("agent fingerprint rule %q %s digest: %w", ruleID, kind, err)
				}
				if _, duplicate := seen[digest]; duplicate {
					continue
				}
				if owner, exists := digestOwners[digest]; exists && owner != agentType {
					return nil, nil, fmt.Errorf("agent fingerprint digest is shared by agent types %q and %q", owner, agentType)
				}
				digestOwners[digest] = agentType
				seen[digest] = struct{}{}
				canonicalDigests = append(canonicalDigests, canonicalDigest)
				parsedDigests = append(parsedDigests, digest)
			}
			sort.Strings(canonicalDigests)
			sort.Slice(parsedDigests, func(i, j int) bool {
				return strings.Compare(hex.EncodeToString(parsedDigests[i][:]), hex.EncodeToString(parsedDigests[j][:])) < 0
			})
			return canonicalDigests, parsedDigests, nil
		}
		canonicalNative, parsedNative, err := parseDigests(input.ExpectedSHA256, "native")
		if err != nil {
			return nil, err
		}
		canonicalLauncher, parsedLauncher, err := parseDigests(input.ExpectedLauncherSHA256, "launcher")
		if err != nil {
			return nil, err
		}

		if len(parsedLauncher) == 0 && len(input.AllowedInterpreterProfiles) != 0 {
			return nil, fmt.Errorf("agent fingerprint rule %q has interpreter profiles without launcher digests", ruleID)
		}
		if len(parsedLauncher) > 0 && (len(input.AllowedInterpreterProfiles) == 0 || len(input.AllowedInterpreterProfiles) > maxAgentFingerprintInterpretersPerRule) {
			return nil, fmt.Errorf("agent fingerprint rule %q must contain 1..%d allowed interpreter profiles", ruleID, maxAgentFingerprintInterpretersPerRule)
		}
		canonicalInterpreters := make([]string, 0, len(input.AllowedInterpreterProfiles))
		interpreterProfiles := make(map[string]struct{}, len(input.AllowedInterpreterProfiles))
		for _, raw := range input.AllowedInterpreterProfiles {
			profile, ok := normalizeAgentExecutableBasename(raw)
			if !ok {
				return nil, fmt.Errorf("agent fingerprint rule %q has an invalid interpreter profile", ruleID)
			}
			if _, duplicate := interpreterProfiles[profile]; duplicate {
				continue
			}
			interpreterProfiles[profile] = struct{}{}
			canonicalInterpreters = append(canonicalInterpreters, profile)
		}
		sort.Strings(canonicalInterpreters)
		canonical = append(canonical, AgentFingerprintRule{
			RuleID:                     ruleID,
			AgentType:                  agentType,
			ExpectedSHA256:             canonicalNative,
			ExpectedLauncherSHA256:     canonicalLauncher,
			AllowedInterpreterProfiles: canonicalInterpreters,
		})
		byType[agentType] = append(byType[agentType], agentFingerprintExpectedRule{
			ruleID:              ruleID,
			nativeDigests:       parsedNative,
			launcherDigests:     parsedLauncher,
			interpreterProfiles: interpreterProfiles,
		})
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].RuleID < canonical[j].RuleID })
	for agentType := range byType {
		sort.Slice(byType[agentType], func(i, j int) bool {
			return byType[agentType][i].ruleID < byType[agentType][j].ruleID
		})
	}
	canonicalBytes, err := json.Marshal(AgentFingerprintRegistryDocument{
		SchemaVersion:   document.SchemaVersion,
		RegistryVersion: document.RegistryVersion,
		Rules:           canonical,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal canonical agent fingerprint registry: %w", err)
	}
	digest := sha256.Sum256(canonicalBytes)
	return &AgentFingerprintRegistry{
		version: document.RegistryVersion,
		digest:  hex.EncodeToString(digest[:]),
		byType:  byType,
	}, nil
}

func parseAgentFingerprintSHA256(raw string) ([sha256.Size]byte, string, error) {
	var result [sha256.Size]byte
	canonical := strings.ToLower(strings.TrimSpace(raw))
	if len(canonical) != sha256.Size*2 {
		return result, "", fmt.Errorf("expected SHA-256 digest must contain exactly %d hexadecimal characters", sha256.Size*2)
	}
	decoded, err := hex.DecodeString(canonical)
	if err != nil {
		return result, "", fmt.Errorf("expected SHA-256 digest is invalid")
	}
	copy(result[:], decoded)
	return result, canonical, nil
}

func (r *AgentFingerprintRegistry) hasAgentType(agentType string) bool {
	if r == nil {
		return false
	}
	return len(r.byType[agentType]) > 0
}

func (r *AgentFingerprintRegistry) hasNativeAgentType(agentType string) bool {
	for _, rule := range r.byType[agentType] {
		if len(rule.nativeDigests) > 0 {
			return true
		}
	}
	return false
}

func (r *AgentFingerprintRegistry) hasLauncherAgentType(agentType string) bool {
	for _, rule := range r.byType[agentType] {
		if len(rule.launcherDigests) > 0 {
			return true
		}
	}
	return false
}

// HasLauncherRules reports whether startup must attempt the optional BPF-LSM
// observer. It exposes no rule contents.
func (r *AgentFingerprintRegistry) HasLauncherRules() bool {
	if r == nil {
		return false
	}
	for agentType := range r.byType {
		if r.hasLauncherAgentType(agentType) {
			return true
		}
	}
	return false
}

func (r *AgentFingerprintRegistry) allowsLauncherInterpreter(agentType, interpreter string) bool {
	profile, ok := normalizeAgentExecutableBasename(interpreter)
	if !ok {
		return false
	}
	for _, rule := range r.byType[agentType] {
		if len(rule.launcherDigests) == 0 {
			continue
		}
		if _, allowed := rule.interpreterProfiles[profile]; allowed {
			return true
		}
	}
	return false
}

// ValidateAgentTypes rejects registry rules that cannot be reached by the
// active name recognizer. This catches operator typos at startup instead of
// presenting a loaded but ineffective trust registry.
func (r *AgentFingerprintRegistry) ValidateAgentTypes(allowedAgentTypes []string) error {
	if r == nil {
		return fmt.Errorf("agent fingerprint registry is required")
	}
	allowed := make(map[string]struct{}, len(allowedAgentTypes))
	for _, agentType := range allowedAgentTypes {
		allowed[agentType] = struct{}{}
	}
	for agentType := range r.byType {
		if _, ok := allowed[agentType]; !ok {
			return fmt.Errorf("agent fingerprint registry contains unknown agent type %q", agentType)
		}
	}
	return nil
}

func (r *AgentFingerprintRegistry) matchNative(agentType string, digest [sha256.Size]byte) []string {
	if r == nil {
		return nil
	}
	var matched []string
	for _, rule := range r.byType[agentType] {
		for _, expected := range rule.nativeDigests {
			if expected == digest {
				matched = append(matched, rule.ruleID)
				break
			}
		}
	}
	return matched
}

func (r *AgentFingerprintRegistry) matchLauncher(agentType string, digest [sha256.Size]byte, interpreter string) []string {
	if r == nil {
		return nil
	}
	profile, ok := normalizeAgentExecutableBasename(interpreter)
	if !ok {
		return nil
	}
	var matched []string
	for _, rule := range r.byType[agentType] {
		if _, allowed := rule.interpreterProfiles[profile]; !allowed {
			continue
		}
		for _, expected := range rule.launcherDigests {
			if expected == digest {
				matched = append(matched, rule.ruleID)
				break
			}
		}
	}
	return matched
}

// AgentFingerprintObservation is the public-safe result of one attempt. It
// intentionally has no path, argv, environment, file content, or digest field.
type AgentFingerprintObservation struct {
	SchemaVersion              string   `json:"schema_version"`
	Outcome                    string   `json:"outcome"`
	Method                     string   `json:"method,omitempty"`
	ObjectState                string   `json:"object_state,omitempty"`
	AgentType                  string   `json:"agent_type"`
	Confidence                 string   `json:"confidence"`
	IdentityAssurance          string   `json:"identity_assurance"`
	GovernanceAction           string   `json:"governance_action"`
	MatchedRuleIDs             []string `json:"matched_rule_ids,omitempty"`
	FingerprintRegistryVersion string   `json:"fingerprint_registry_version"`
	FingerprintRegistrySHA256  string   `json:"fingerprint_registry_sha256"`
}

// AgentFingerprintCounters are monotonic daemon-lifetime attempt outcomes.
type AgentFingerprintCounters struct {
	QueueSaturated    uint64 `json:"queue_saturated"`
	ResolutionDenied  uint64 `json:"resolution_denied"`
	ProcessExited     uint64 `json:"process_exited"`
	Unsupported       uint64 `json:"unsupported"`
	UnsupportedKernel uint64 `json:"unsupported_kernel"`
	UnsupportedFS     uint64 `json:"unsupported_filesystem"`
	MissingIdentity   uint64 `json:"missing_kernel_object_identity"`
	MissingLocator    uint64 `json:"missing_locator"`
	LocatorMismatch   uint64 `json:"locator_mismatch"`
	InterpreterDenied uint64 `json:"interpreter_not_allowed"`
	ArgumentLimit     uint64 `json:"argument_limit_exceeded"`
	SizeExceeded      uint64 `json:"size_exceeded"`
	DeadlineExceeded  uint64 `json:"deadline_exceeded"`
	DigestMismatch    uint64 `json:"digest_mismatch"`
	Success           uint64 `json:"success"`
	// WorkerUnavailable counts attempts the worker refused or abandoned
	// because it was closing, already closed, or because processing
	// panicked and was contained.
	WorkerUnavailable uint64 `json:"worker_unavailable"`
}

// AgentFingerprintHealth is exposed only through the authenticated local
// daemon health response.
type AgentFingerprintHealth struct {
	Enabled                   bool                     `json:"enabled"`
	RegistryVersion           string                   `json:"registry_version,omitempty"`
	RegistrySHA256            string                   `json:"registry_sha256,omitempty"`
	QueueCapacity             int                      `json:"queue_capacity"`
	QueueDepth                int                      `json:"queue_depth"`
	WorkerCount               int                      `json:"worker_count"`
	TimeoutMS                 int64                    `json:"timeout_ms"`
	MaxFileBytes              int64                    `json:"max_file_bytes"`
	MaxArgumentBytes          int64                    `json:"max_argument_bytes"`
	MaxArguments              int                      `json:"max_arguments"`
	LauncherIdentityAvailable bool                     `json:"launcher_identity_available"`
	Counters                  AgentFingerprintCounters `json:"counters"`
}

type agentFingerprintTarget interface {
	Close() error
}

type agentFingerprintDigest struct {
	digest      [sha256.Size]byte
	method      string
	objectState string
}

type agentFingerprintResolveLimits struct {
	maxFileBytes     int64
	maxArgumentBytes int64
	maxArguments     int
}

// agentFingerprintResolver keeps the PID binding and file acquisition behind
// a testable seam. Bind must be cheap and non-blocking; Resolve owns all file
// I/O and runs only in bounded workers.
type agentFingerprintResolver interface {
	Bind(ProcessEvent) (agentFingerprintTarget, string)
	Resolve(context.Context, agentFingerprintTarget, agentFingerprintResolveLimits) (agentFingerprintDigest, string)
}

// AgentFingerprintWorkerOptions controls fixed safety bounds. Zero values use
// the documented defaults.
type AgentFingerprintWorkerOptions struct {
	QueueCapacity    int
	WorkerCount      int
	Timeout          time.Duration
	MaxFileBytes     int64
	MaxArgumentBytes int64
	MaxArguments     int
	Observer         func(ProcessEvent, AgentRecognitionResult, AgentFingerprintObservation)
}

type agentFingerprintJob struct {
	event     ProcessEvent
	candidate AgentRecognitionResult
	target    agentFingerprintTarget
}

type agentFingerprintAtomicCounters struct {
	queueSaturated    atomic.Uint64
	resolutionDenied  atomic.Uint64
	processExited     atomic.Uint64
	unsupported       atomic.Uint64
	unsupportedKernel atomic.Uint64
	unsupportedFS     atomic.Uint64
	missingIdentity   atomic.Uint64
	missingLocator    atomic.Uint64
	locatorMismatch   atomic.Uint64
	interpreterDenied atomic.Uint64
	argumentLimit     atomic.Uint64
	sizeExceeded      atomic.Uint64
	deadlineExceeded  atomic.Uint64
	digestMismatch    atomic.Uint64
	success           atomic.Uint64
	workerUnavailable atomic.Uint64
}

// AgentFingerprintWorker owns a fixed queue and fixed worker set. Submit never
// waits for capacity. Close cancels in-flight work and releases queued targets.
type AgentFingerprintWorker struct {
	registry                  *AgentFingerprintRegistry
	resolver                  agentFingerprintResolver
	opts                      AgentFingerprintWorkerOptions
	jobs                      chan agentFingerprintJob
	ctx                       context.Context
	cancel                    context.CancelFunc
	done                      chan struct{}
	closed                    atomic.Bool
	launcherIdentityAvailable atomic.Bool
	submitMu                  sync.RWMutex
	wg                        sync.WaitGroup
	counters                  agentFingerprintAtomicCounters
}

// NewAgentFingerprintWorker returns the platform resolver backed by a bounded
// queue. On unsupported platforms, submissions return the explicit
// "unsupported" outcome rather than weakening the name-only classifier.
func NewAgentFingerprintWorker(registry *AgentFingerprintRegistry, opts AgentFingerprintWorkerOptions) (*AgentFingerprintWorker, error) {
	return newAgentFingerprintWorker(registry, newPlatformAgentFingerprintResolver(), opts)
}

func newAgentFingerprintWorker(registry *AgentFingerprintRegistry, resolver agentFingerprintResolver, opts AgentFingerprintWorkerOptions) (*AgentFingerprintWorker, error) {
	if registry == nil {
		return nil, fmt.Errorf("agent fingerprint registry is required")
	}
	if resolver == nil {
		return nil, fmt.Errorf("agent fingerprint resolver is required")
	}
	if opts.QueueCapacity <= 0 {
		opts.QueueCapacity = DefaultAgentFingerprintQueueCapacity
	}
	if opts.WorkerCount <= 0 {
		opts.WorkerCount = DefaultAgentFingerprintWorkerCount
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultAgentFingerprintTimeout
	}
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = DefaultAgentFingerprintMaxFileBytes
	}
	if opts.MaxArgumentBytes <= 0 {
		opts.MaxArgumentBytes = DefaultAgentFingerprintMaxArgumentBytes
	}
	if opts.MaxArguments <= 0 {
		opts.MaxArguments = DefaultAgentFingerprintMaxArguments
	}
	if opts.QueueCapacity > 4096 || opts.WorkerCount > 32 || opts.Timeout > time.Minute || opts.MaxFileBytes > 1<<30 || opts.MaxArgumentBytes > 1<<20 || opts.MaxArguments > 1024 {
		return nil, fmt.Errorf("agent fingerprint worker bounds exceed hard safety limits")
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &AgentFingerprintWorker{
		registry: registry,
		resolver: resolver,
		opts:     opts,
		jobs:     make(chan agentFingerprintJob, opts.QueueCapacity),
		ctx:      ctx,
		cancel:   cancel,
		done:     make(chan struct{}),
	}
	for range opts.WorkerCount {
		w.wg.Add(1)
		go w.run()
	}
	go w.finish()
	return w, nil
}

// Submit binds one recognized PID and queues it without waiting. The returned
// observation is non-nil only for an immediate explicit failure.
func (w *AgentFingerprintWorker) Submit(event ProcessEvent, candidate AgentRecognitionResult) *AgentFingerprintObservation {
	if w == nil || candidate.Status != AgentRecognitionStatusRecognized || !w.registry.hasAgentType(candidate.AgentType) {
		return nil
	}
	w.submitMu.RLock()
	defer w.submitMu.RUnlock()
	if w.closed.Load() {
		w.recordOutcome(AgentFingerprintOutcomeWorkerUnavailable)
		observation := w.observation(candidate, AgentFingerprintOutcomeWorkerUnavailable, "", AgentFingerprintObjectUnknown, nil)
		return &observation
	}
	method := ""
	objectState := AgentFingerprintObjectUnknown
	if event.InterpreterBacked || event.LauncherScript {
		if !w.registry.hasLauncherAgentType(candidate.AgentType) {
			return nil
		}
		method = AgentFingerprintMethodSHA256KernelLauncher
		objectState = launcherFingerprintObjectState(event.LauncherIdentity)
		if !w.launcherIdentityAvailable.Load() {
			return w.immediateObservation(candidate, AgentFingerprintOutcomeUnsupportedKernel, method, objectState)
		}
		if !event.LauncherScript || !event.LauncherIdentity.Present {
			return w.immediateObservation(candidate, AgentFingerprintOutcomeMissingIdentity, method, objectState)
		}
		if !w.registry.allowsLauncherInterpreter(candidate.AgentType, event.LauncherInterpreter) {
			return w.immediateObservation(candidate, AgentFingerprintOutcomeInterpreterDenied, method, objectState)
		}
	} else if !w.registry.hasNativeAgentType(candidate.AgentType) {
		return nil
	}
	target, outcome := w.resolver.Bind(event)
	if outcome != "" {
		return w.immediateObservation(candidate, outcome, method, objectState)
	}
	job := agentFingerprintJob{event: event, candidate: candidate, target: target}
	select {
	case w.jobs <- job:
		return nil
	default:
		_ = target.Close()
		w.recordOutcome(AgentFingerprintOutcomeQueueSaturated)
		observation := w.observation(candidate, AgentFingerprintOutcomeQueueSaturated, "", AgentFingerprintObjectUnknown, nil)
		return &observation
	}
}

func (w *AgentFingerprintWorker) immediateObservation(candidate AgentRecognitionResult, outcome, method, objectState string) *AgentFingerprintObservation {
	w.recordOutcome(outcome)
	observation := w.observation(candidate, outcome, method, objectState, nil)
	return &observation
}

func launcherFingerprintObjectState(identity LauncherObjectIdentity) string {
	if !identity.Present {
		return AgentFingerprintObjectUnknown
	}
	if identity.LinkCount == 0 {
		return AgentFingerprintObjectDeleted
	}
	return AgentFingerprintObjectLinked
}

// SetLauncherIdentityAvailable records whether the optional BPF-LSM observer
// attached successfully. A false value yields explicit unsupported_kernel
// observations for launcher rules while native fingerprinting continues.
func (w *AgentFingerprintWorker) SetLauncherIdentityAvailable(available bool) {
	if w != nil {
		w.launcherIdentityAvailable.Store(available)
	}
}

// HasLauncherRules reports whether this worker needs the optional kernel
// launcher observer. It exposes no registry rule contents.
func (w *AgentFingerprintWorker) HasLauncherRules() bool {
	return w != nil && w.registry.HasLauncherRules()
}

func (w *AgentFingerprintWorker) run() {
	defer w.wg.Done()
	for {
		select {
		case <-w.ctx.Done():
			return
		case job := <-w.jobs:
			w.process(job)
		}
	}
}

func (w *AgentFingerprintWorker) process(job agentFingerprintJob) {
	defer job.target.Close()
	// This lane is advisory and observe-only, but it shares a process with
	// lifecycle capture and enforcement. An unrecovered panic here unwinds
	// out of run() and takes the whole daemon down, so a bug in the least
	// privileged component would disable the most critical one: the guard
	// is pinned, so the kernel keeps enforcing while apply_policy, the
	// kill switch, and the tamper-audit chain all become unreachable.
	// Contain it and account for it in the counters instead. Same backstop
	// as the per-connection recover in daemon_socket_server.go; as there,
	// the real fix for any given panic is to make the code fail cleanly.
	// This handler deliberately does NOT publish: the observer callback is
	// itself a panic source, so re-entering it from here would repanic and
	// defeat the backstop.
	defer func() {
		if r := recover(); r != nil {
			w.recordOutcome(AgentFingerprintOutcomeWorkerUnavailable)
		}
	}()
	ctx, cancel := context.WithTimeout(w.ctx, w.opts.Timeout)
	defer cancel()
	digest, outcome := w.resolver.Resolve(ctx, job.target, agentFingerprintResolveLimits{
		maxFileBytes: w.opts.MaxFileBytes, maxArgumentBytes: w.opts.MaxArgumentBytes, maxArguments: w.opts.MaxArguments,
	})
	if outcome == "" {
		matched := w.registry.matchNative(job.candidate.AgentType, digest.digest)
		if digest.method == AgentFingerprintMethodSHA256KernelLauncher {
			matched = w.registry.matchLauncher(job.candidate.AgentType, digest.digest, job.event.LauncherInterpreter)
		}
		if len(matched) == 0 {
			outcome = AgentFingerprintOutcomeDigestMismatch
		} else {
			outcome = AgentFingerprintOutcomeSuccess
		}
		observation := w.observation(job.candidate, outcome, digest.method, digest.objectState, matched)
		w.publish(job, observation)
		w.recordOutcome(outcome)
		return
	}
	observation := w.observation(job.candidate, outcome, digest.method, digest.objectState, nil)
	w.publish(job, observation)
	w.recordOutcome(outcome)
}

func (w *AgentFingerprintWorker) publish(job agentFingerprintJob, observation AgentFingerprintObservation) {
	if w.opts.Observer != nil {
		w.opts.Observer(job.event, job.candidate, observation)
	}
}

func (w *AgentFingerprintWorker) observation(candidate AgentRecognitionResult, outcome, method, objectState string, matched []string) AgentFingerprintObservation {
	return agentFingerprintObservation(w.registry, candidate, outcome, method, objectState, matched)
}

func agentFingerprintObservation(registry *AgentFingerprintRegistry, candidate AgentRecognitionResult, outcome, method, objectState string, matched []string) AgentFingerprintObservation {
	confidence := candidate.Confidence
	assurance := candidate.IdentityAssurance
	if outcome == AgentFingerprintOutcomeSuccess {
		confidence = AgentRecognitionConfidenceMedium
		assurance = "heuristic_executable_content"
		if method == AgentFingerprintMethodSHA256KernelLauncher {
			assurance = "heuristic_kernel_bound_launcher_content"
		}
	}
	return AgentFingerprintObservation{
		SchemaVersion:              AgentFingerprintResultSchema,
		Outcome:                    outcome,
		Method:                     method,
		ObjectState:                objectState,
		AgentType:                  candidate.AgentType,
		Confidence:                 confidence,
		IdentityAssurance:          assurance,
		GovernanceAction:           "observe_only",
		MatchedRuleIDs:             append([]string(nil), matched...),
		FingerprintRegistryVersion: registry.version,
		FingerprintRegistrySHA256:  registry.digest,
	}
}

func (w *AgentFingerprintWorker) recordOutcome(outcome string) {
	switch outcome {
	case AgentFingerprintOutcomeQueueSaturated:
		w.counters.queueSaturated.Add(1)
	case AgentFingerprintOutcomeResolutionDenied:
		w.counters.resolutionDenied.Add(1)
	case AgentFingerprintOutcomeProcessExited:
		w.counters.processExited.Add(1)
	case AgentFingerprintOutcomeUnsupported:
		w.counters.unsupported.Add(1)
	case AgentFingerprintOutcomeUnsupportedKernel:
		w.counters.unsupportedKernel.Add(1)
	case AgentFingerprintOutcomeUnsupportedFS:
		w.counters.unsupportedFS.Add(1)
	case AgentFingerprintOutcomeMissingIdentity:
		w.counters.missingIdentity.Add(1)
	case AgentFingerprintOutcomeMissingLocator:
		w.counters.missingLocator.Add(1)
	case AgentFingerprintOutcomeLocatorMismatch:
		w.counters.locatorMismatch.Add(1)
	case AgentFingerprintOutcomeInterpreterDenied:
		w.counters.interpreterDenied.Add(1)
	case AgentFingerprintOutcomeArgumentLimit:
		w.counters.argumentLimit.Add(1)
	case AgentFingerprintOutcomeSizeExceeded:
		w.counters.sizeExceeded.Add(1)
	case AgentFingerprintOutcomeDeadlineExceeded:
		w.counters.deadlineExceeded.Add(1)
	case AgentFingerprintOutcomeDigestMismatch:
		w.counters.digestMismatch.Add(1)
	case AgentFingerprintOutcomeSuccess:
		w.counters.success.Add(1)
	case AgentFingerprintOutcomeWorkerUnavailable:
		w.counters.workerUnavailable.Add(1)
	}
}

func (w *AgentFingerprintWorker) Health() AgentFingerprintHealth {
	if w == nil {
		return AgentFingerprintHealth{}
	}
	return AgentFingerprintHealth{
		Enabled:                   !w.closed.Load(),
		RegistryVersion:           w.registry.version,
		RegistrySHA256:            w.registry.digest,
		QueueCapacity:             cap(w.jobs),
		QueueDepth:                len(w.jobs),
		WorkerCount:               w.opts.WorkerCount,
		TimeoutMS:                 w.opts.Timeout.Milliseconds(),
		MaxFileBytes:              w.opts.MaxFileBytes,
		MaxArgumentBytes:          w.opts.MaxArgumentBytes,
		MaxArguments:              w.opts.MaxArguments,
		LauncherIdentityAvailable: w.launcherIdentityAvailable.Load(),
		Counters: AgentFingerprintCounters{
			QueueSaturated:    w.counters.queueSaturated.Load(),
			ResolutionDenied:  w.counters.resolutionDenied.Load(),
			ProcessExited:     w.counters.processExited.Load(),
			Unsupported:       w.counters.unsupported.Load(),
			UnsupportedKernel: w.counters.unsupportedKernel.Load(),
			UnsupportedFS:     w.counters.unsupportedFS.Load(),
			MissingIdentity:   w.counters.missingIdentity.Load(),
			MissingLocator:    w.counters.missingLocator.Load(),
			LocatorMismatch:   w.counters.locatorMismatch.Load(),
			InterpreterDenied: w.counters.interpreterDenied.Load(),
			ArgumentLimit:     w.counters.argumentLimit.Load(),
			SizeExceeded:      w.counters.sizeExceeded.Load(),
			DeadlineExceeded:  w.counters.deadlineExceeded.Load(),
			DigestMismatch:    w.counters.digestMismatch.Load(),
			Success:           w.counters.success.Load(),
			WorkerUnavailable: w.counters.workerUnavailable.Load(),
		},
	}
}

func (w *AgentFingerprintWorker) Close(ctx context.Context) error {
	if w == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	w.submitMu.Lock()
	if w.closed.CompareAndSwap(false, true) {
		w.cancel()
	}
	w.submitMu.Unlock()
	select {
	case <-w.done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%w: %v", ErrAgentFingerprintWorkerClosed, ctx.Err())
	}
}

func (w *AgentFingerprintWorker) finish() {
	w.wg.Wait()
	for {
		select {
		case job := <-w.jobs:
			_ = job.target.Close()
		default:
			close(w.done)
			return
		}
	}
}
