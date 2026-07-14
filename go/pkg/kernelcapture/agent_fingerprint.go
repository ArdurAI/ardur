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
	AgentFingerprintRegistrySchema = "ardur.agent_fingerprint_registry.v0.1"
	AgentFingerprintResultSchema   = "ardur.agent_fingerprint_result.v0.1"

	AgentFingerprintMethodSHA256ProcExe = "sha256_proc_exe"

	AgentFingerprintObjectLinked  = "linked"
	AgentFingerprintObjectDeleted = "deleted"
	AgentFingerprintObjectUnknown = "unknown"

	AgentFingerprintOutcomeSuccess           = "success"
	AgentFingerprintOutcomeDigestMismatch    = "digest_mismatch"
	AgentFingerprintOutcomeQueueSaturated    = "queue_saturated"
	AgentFingerprintOutcomeResolutionDenied  = "resolution_denied"
	AgentFingerprintOutcomeProcessExited     = "process_exited"
	AgentFingerprintOutcomeUnsupported       = "unsupported"
	AgentFingerprintOutcomeSizeExceeded      = "size_exceeded"
	AgentFingerprintOutcomeDeadlineExceeded  = "deadline_exceeded"
	AgentFingerprintOutcomeWorkerUnavailable = "worker_unavailable"
)

const (
	MaxAgentFingerprintRegistryBytes  = 64 << 10
	maxAgentFingerprintRules          = 64
	maxAgentFingerprintDigestsPerRule = 16

	DefaultAgentFingerprintQueueCapacity = 64
	DefaultAgentFingerprintWorkerCount   = 2
	DefaultAgentFingerprintMaxFileBytes  = 32 << 20
	DefaultAgentFingerprintTimeout       = 500 * time.Millisecond
)

var ErrAgentFingerprintWorkerClosed = errors.New("kernelcapture: agent fingerprint worker is closed")

// AgentFingerprintRule binds one recognized agent class to operator-owned
// expected native executable digests. The digests are used for matching only;
// computed executable digests are never published in results or health data.
type AgentFingerprintRule struct {
	RuleID         string   `json:"rule_id"`
	AgentType      string   `json:"agent_type"`
	ExpectedSHA256 []string `json:"expected_sha256"`
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
	ruleID  string
	digests [][sha256.Size]byte
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
	if document.SchemaVersion != AgentFingerprintRegistrySchema {
		return nil, fmt.Errorf("agent fingerprint registry schema must be %q", AgentFingerprintRegistrySchema)
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
		if len(input.ExpectedSHA256) == 0 || len(input.ExpectedSHA256) > maxAgentFingerprintDigestsPerRule {
			return nil, fmt.Errorf("agent fingerprint rule %q must contain 1..%d SHA-256 digests", ruleID, maxAgentFingerprintDigestsPerRule)
		}

		canonicalDigests := make([]string, 0, len(input.ExpectedSHA256))
		parsedDigests := make([][sha256.Size]byte, 0, len(input.ExpectedSHA256))
		seen := make(map[[sha256.Size]byte]struct{}, len(input.ExpectedSHA256))
		for _, raw := range input.ExpectedSHA256 {
			digest, canonicalDigest, err := parseAgentFingerprintSHA256(raw)
			if err != nil {
				return nil, fmt.Errorf("agent fingerprint rule %q: %w", ruleID, err)
			}
			if _, duplicate := seen[digest]; duplicate {
				continue
			}
			if owner, exists := digestOwners[digest]; exists && owner != agentType {
				return nil, fmt.Errorf("agent fingerprint digest is shared by agent types %q and %q", owner, agentType)
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
		canonical = append(canonical, AgentFingerprintRule{
			RuleID:         ruleID,
			AgentType:      agentType,
			ExpectedSHA256: canonicalDigests,
		})
		byType[agentType] = append(byType[agentType], agentFingerprintExpectedRule{
			ruleID:  ruleID,
			digests: parsedDigests,
		})
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].RuleID < canonical[j].RuleID })
	for agentType := range byType {
		sort.Slice(byType[agentType], func(i, j int) bool {
			return byType[agentType][i].ruleID < byType[agentType][j].ruleID
		})
	}
	canonicalBytes, err := json.Marshal(AgentFingerprintRegistryDocument{
		SchemaVersion:   AgentFingerprintRegistrySchema,
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

func (r *AgentFingerprintRegistry) match(agentType string, digest [sha256.Size]byte) []string {
	if r == nil {
		return nil
	}
	var matched []string
	for _, rule := range r.byType[agentType] {
		for _, expected := range rule.digests {
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
	QueueSaturated   uint64 `json:"queue_saturated"`
	ResolutionDenied uint64 `json:"resolution_denied"`
	ProcessExited    uint64 `json:"process_exited"`
	Unsupported      uint64 `json:"unsupported"`
	SizeExceeded     uint64 `json:"size_exceeded"`
	DeadlineExceeded uint64 `json:"deadline_exceeded"`
	DigestMismatch   uint64 `json:"digest_mismatch"`
	Success          uint64 `json:"success"`
}

// AgentFingerprintHealth is exposed only through the authenticated local
// daemon health response.
type AgentFingerprintHealth struct {
	Enabled         bool                     `json:"enabled"`
	RegistryVersion string                   `json:"registry_version,omitempty"`
	RegistrySHA256  string                   `json:"registry_sha256,omitempty"`
	QueueCapacity   int                      `json:"queue_capacity"`
	QueueDepth      int                      `json:"queue_depth"`
	WorkerCount     int                      `json:"worker_count"`
	TimeoutMS       int64                    `json:"timeout_ms"`
	MaxFileBytes    int64                    `json:"max_file_bytes"`
	Counters        AgentFingerprintCounters `json:"counters"`
}

type agentFingerprintTarget interface {
	Close() error
}

type agentFingerprintDigest struct {
	digest      [sha256.Size]byte
	method      string
	objectState string
}

// agentFingerprintResolver keeps the PID binding and file acquisition behind
// a testable seam. Bind must be cheap and non-blocking; Resolve owns all file
// I/O and runs only in bounded workers.
type agentFingerprintResolver interface {
	Bind(pid uint32) (agentFingerprintTarget, string)
	Resolve(context.Context, agentFingerprintTarget, int64) (agentFingerprintDigest, string)
}

// AgentFingerprintWorkerOptions controls fixed safety bounds. Zero values use
// the documented defaults.
type AgentFingerprintWorkerOptions struct {
	QueueCapacity int
	WorkerCount   int
	Timeout       time.Duration
	MaxFileBytes  int64
	Observer      func(ProcessEvent, AgentRecognitionResult, AgentFingerprintObservation)
}

type agentFingerprintJob struct {
	event     ProcessEvent
	candidate AgentRecognitionResult
	target    agentFingerprintTarget
}

type agentFingerprintAtomicCounters struct {
	queueSaturated   atomic.Uint64
	resolutionDenied atomic.Uint64
	processExited    atomic.Uint64
	unsupported      atomic.Uint64
	sizeExceeded     atomic.Uint64
	deadlineExceeded atomic.Uint64
	digestMismatch   atomic.Uint64
	success          atomic.Uint64
}

// AgentFingerprintWorker owns a fixed queue and fixed worker set. Submit never
// waits for capacity. Close cancels in-flight work and releases queued targets.
type AgentFingerprintWorker struct {
	registry *AgentFingerprintRegistry
	resolver agentFingerprintResolver
	opts     AgentFingerprintWorkerOptions
	jobs     chan agentFingerprintJob
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	closed   atomic.Bool
	submitMu sync.RWMutex
	wg       sync.WaitGroup
	counters agentFingerprintAtomicCounters
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
	if opts.QueueCapacity > 4096 || opts.WorkerCount > 32 || opts.Timeout > time.Minute || opts.MaxFileBytes > 1<<30 {
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
		observation := w.observation(candidate, AgentFingerprintOutcomeWorkerUnavailable, "", AgentFingerprintObjectUnknown, nil)
		return &observation
	}
	target, outcome := w.resolver.Bind(event.PID)
	if outcome != "" {
		w.recordOutcome(outcome)
		observation := w.observation(candidate, outcome, "", AgentFingerprintObjectUnknown, nil)
		return &observation
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
	ctx, cancel := context.WithTimeout(w.ctx, w.opts.Timeout)
	defer cancel()
	digest, outcome := w.resolver.Resolve(ctx, job.target, w.opts.MaxFileBytes)
	if outcome == "" {
		matched := w.registry.match(job.candidate.AgentType, digest.digest)
		if len(matched) == 0 {
			outcome = AgentFingerprintOutcomeDigestMismatch
		} else {
			outcome = AgentFingerprintOutcomeSuccess
		}
		observation := w.observation(job.candidate, outcome, digest.method, digest.objectState, matched)
		w.recordOutcome(outcome)
		w.publish(job, observation)
		return
	}
	observation := w.observation(job.candidate, outcome, digest.method, digest.objectState, nil)
	w.recordOutcome(outcome)
	w.publish(job, observation)
}

func (w *AgentFingerprintWorker) publish(job agentFingerprintJob, observation AgentFingerprintObservation) {
	if w.opts.Observer != nil {
		w.opts.Observer(job.event, job.candidate, observation)
	}
}

func (w *AgentFingerprintWorker) observation(candidate AgentRecognitionResult, outcome, method, objectState string, matched []string) AgentFingerprintObservation {
	confidence := candidate.Confidence
	assurance := candidate.IdentityAssurance
	if outcome == AgentFingerprintOutcomeSuccess {
		confidence = AgentRecognitionConfidenceMedium
		assurance = "heuristic_executable_content"
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
		FingerprintRegistryVersion: w.registry.version,
		FingerprintRegistrySHA256:  w.registry.digest,
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
	case AgentFingerprintOutcomeSizeExceeded:
		w.counters.sizeExceeded.Add(1)
	case AgentFingerprintOutcomeDeadlineExceeded:
		w.counters.deadlineExceeded.Add(1)
	case AgentFingerprintOutcomeDigestMismatch:
		w.counters.digestMismatch.Add(1)
	case AgentFingerprintOutcomeSuccess:
		w.counters.success.Add(1)
	}
}

func (w *AgentFingerprintWorker) Health() AgentFingerprintHealth {
	if w == nil {
		return AgentFingerprintHealth{}
	}
	return AgentFingerprintHealth{
		Enabled:         !w.closed.Load(),
		RegistryVersion: w.registry.version,
		RegistrySHA256:  w.registry.digest,
		QueueCapacity:   cap(w.jobs),
		QueueDepth:      len(w.jobs),
		WorkerCount:     w.opts.WorkerCount,
		TimeoutMS:       w.opts.Timeout.Milliseconds(),
		MaxFileBytes:    w.opts.MaxFileBytes,
		Counters: AgentFingerprintCounters{
			QueueSaturated:   w.counters.queueSaturated.Load(),
			ResolutionDenied: w.counters.resolutionDenied.Load(),
			ProcessExited:    w.counters.processExited.Load(),
			Unsupported:      w.counters.unsupported.Load(),
			SizeExceeded:     w.counters.sizeExceeded.Load(),
			DeadlineExceeded: w.counters.deadlineExceeded.Load(),
			DigestMismatch:   w.counters.digestMismatch.Load(),
			Success:          w.counters.success.Load(),
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
