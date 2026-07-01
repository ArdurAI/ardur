// Package trust implements the posture aggregator for VIBAP Layer 5 (Trust Score).
//
// It defines a ScoreAggregator interface that consumes telemetry signals from
// Tetragon, Kubescape, and credential verifiers, then computes a composite
// trust score (0–100) that determines an agent's authorization tier:
//   - Full (≥70): all egress allowed to authorized services
//   - Limited (≥40, <70): observation-only, no external access
//   - Quarantine (<40): all egress denied, only Prometheus scraping allowed
//
// The scoring formula is a weighted combination:
//
//	composite = w_static * static_capability + w_historical * historical_reputation + w_runtime * runtime_compliance
//
// where runtime_compliance is computed from recent telemetry signals
// (behavioral drift, policy violations, failed verifications).
package trust

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"sync"
	"time"
)

// Sentinel errors for the trust package.
var (
	ErrAgentNotFound          = errors.New("agent not found in score store")
	ErrAgentAlreadyRegistered = errors.New("agent already registered")
	ErrInvalidSignal          = errors.New("invalid telemetry signal")
	ErrAggregatorClosed       = errors.New("score aggregator is closed")
	ErrScoreOutOfRange        = errors.New("score out of valid range")
)

// Authorization tiers matching credential types.go constants.
const (
	TierFull       = "full"
	TierLimited    = "limited"
	TierQuarantine = "quarantine"
)

// Default scoring weights.
const (
	DefaultWeightStatic     = 0.3
	DefaultWeightHistorical = 0.3
	DefaultWeightRuntime    = 0.4
)

// Default scoring parameters.
const (
	DefaultDecayRate           = 0.05 // Runtime score decays 5% per violation
	DefaultRecoveryRate        = 0.01 // Runtime score recovers 1% per clean interval
	DefaultCleanInterval       = 5 * time.Minute
	DefaultMaxSignalAge        = 1 * time.Hour
	DefaultMaxSignalsPerMinute = 10
)

// SignalType categorizes telemetry signals.
type SignalType string

const (
	SignalBehavioralDrift   SignalType = "behavioral_drift"
	SignalPolicyViolation   SignalType = "policy_violation"
	SignalVerificationFail  SignalType = "verification_failure"
	SignalSyscallAnomaly    SignalType = "syscall_anomaly"
	SignalNetworkAnomaly    SignalType = "network_anomaly"
	SignalFileAccessAnomaly SignalType = "file_access_anomaly"
	SignalProcessAnomaly    SignalType = "process_anomaly"
	SignalCleanInterval     SignalType = "clean_interval"
)

// SignalSeverity indicates the impact of a signal on the trust score.
type SignalSeverity string

const (
	SeverityCritical SignalSeverity = "critical" // -20 to composite
	SeverityHigh     SignalSeverity = "high"     // -10 to composite
	SeverityMedium   SignalSeverity = "medium"   // -5 to composite
	SeverityLow      SignalSeverity = "low"      // -2 to composite
	SeverityInfo     SignalSeverity = "info"     // no impact
)

// TelemetrySignal represents a single observation from the monitoring stack.
type TelemetrySignal struct {
	AgentID   string         `json:"agent_id"`
	Type      SignalType     `json:"type"`
	Severity  SignalSeverity `json:"severity"`
	Timestamp time.Time      `json:"timestamp"`
	Source    string         `json:"source"`  // e.g., "tetragon", "kubescape", "verifier"
	Details   string         `json:"details"` // Human-readable description
}

// TrustScore represents the computed trust posture for an agent.
type TrustScore struct {
	AgentID              string    `json:"agent_id"`
	StaticCapability     float64   `json:"static_capability_score"`
	HistoricalReputation float64   `json:"historical_reputation"`
	RuntimeCompliance    float64   `json:"runtime_compliance"`
	CompositeScore       float64   `json:"composite_score"`
	AuthorizationTier    string    `json:"authorization_tier"`
	LastUpdated          time.Time `json:"last_updated"`
	SignalCount          int       `json:"signal_count"`
	ViolationCount       int       `json:"violation_count"`
}

// ScoreWeights configures the relative importance of each scoring component.
type ScoreWeights struct {
	Static     float64 `json:"static"`
	Historical float64 `json:"historical"`
	Runtime    float64 `json:"runtime"`
}

// Validate checks that weights are finite, non-negative, and sum to 1.0 (within tolerance).
func (w ScoreWeights) Validate() error {
	if math.IsNaN(w.Static) || math.IsInf(w.Static, 0) ||
		math.IsNaN(w.Historical) || math.IsInf(w.Historical, 0) ||
		math.IsNaN(w.Runtime) || math.IsInf(w.Runtime, 0) {
		return fmt.Errorf("weights must be finite: static=%.2f, historical=%.2f, runtime=%.2f",
			w.Static, w.Historical, w.Runtime)
	}
	if w.Static < 0 || w.Historical < 0 || w.Runtime < 0 {
		return fmt.Errorf("weights must be non-negative: static=%.2f, historical=%.2f, runtime=%.2f",
			w.Static, w.Historical, w.Runtime)
	}
	sum := w.Static + w.Historical + w.Runtime
	if math.Abs(sum-1.0) > 0.001 {
		return fmt.Errorf("weights must sum to 1.0 (got %.4f)", sum)
	}
	return nil
}

// SeverityPenalty returns the score penalty for a given severity level.
func SeverityPenalty(s SignalSeverity) float64 {
	switch s {
	case SeverityCritical:
		return 20.0
	case SeverityHigh:
		return 10.0
	case SeverityMedium:
		return 5.0
	case SeverityLow:
		return 2.0
	case SeverityInfo:
		return 0.0
	default:
		return 5.0 // unknown severity treated as medium
	}
}

// TierFromScore determines the authorization tier from a composite trust score.
func TierFromScore(score float64) string {
	switch {
	case score >= 70:
		return TierFull
	case score >= 40:
		return TierLimited
	default:
		return TierQuarantine
	}
}

// ScoreAggregator computes and manages trust scores for VIBAP agents.
type ScoreAggregator interface {
	// RegisterAgent initializes scoring for a new agent with static and historical scores.
	RegisterAgent(ctx context.Context, agentID string, staticCapability, historicalReputation float64) error

	// IngestSignal processes a telemetry signal and updates the agent's trust score.
	IngestSignal(ctx context.Context, signal TelemetrySignal) (*TrustScore, error)

	// GetScore retrieves the current trust score for an agent.
	GetScore(ctx context.Context, agentID string) (*TrustScore, error)

	// ListScores returns trust scores for all registered agents.
	ListScores(ctx context.Context) ([]*TrustScore, error)

	// Close releases resources held by the aggregator.
	Close() error
}

// ScoreChangeCallback is invoked whenever an agent's authorization tier changes.
type ScoreChangeCallback func(agentID string, oldTier, newTier string, score *TrustScore)

// --- In-memory implementation ---

// agentState tracks the mutable scoring state for a single agent.
type agentState struct {
	staticCapability     float64
	historicalReputation float64
	runtimeCompliance    float64 // starts at 1.0, decays with violations
	signalCount          int
	violationCount       int
	lastUpdated          time.Time
	signalWindow         []time.Time // timestamps of recent penalty signals
	maxSignalsPerMin     int         // max penalty signals per minute (default 10)
}

// InMemoryAggregator implements ScoreAggregator with in-memory state.
// Suitable for single-node deployments and testing.
type InMemoryAggregator struct {
	mu         sync.RWMutex
	closed     bool
	agents     map[string]*agentState
	weights    ScoreWeights
	onChange   ScoreChangeCallback
	callbackCh chan func()
	callbackWg sync.WaitGroup
}

// InMemoryOption configures an InMemoryAggregator.
type InMemoryOption func(*InMemoryAggregator)

// WithWeights sets custom scoring weights.
func WithWeights(w ScoreWeights) InMemoryOption {
	return func(a *InMemoryAggregator) { a.weights = w }
}

// WithOnChange sets a callback for tier changes.
func WithOnChange(cb ScoreChangeCallback) InMemoryOption {
	return func(a *InMemoryAggregator) { a.onChange = cb }
}

// NewInMemoryAggregator creates a new in-memory trust score aggregator.
func NewInMemoryAggregator(opts ...InMemoryOption) (*InMemoryAggregator, error) {
	a := &InMemoryAggregator{
		agents: make(map[string]*agentState),
		weights: ScoreWeights{
			Static:     DefaultWeightStatic,
			Historical: DefaultWeightHistorical,
			Runtime:    DefaultWeightRuntime,
		},
	}
	for _, opt := range opts {
		opt(a)
	}
	if err := a.weights.Validate(); err != nil {
		return nil, fmt.Errorf("invalid weights: %w", err)
	}

	a.callbackCh = make(chan func(), 64)
	a.callbackWg.Add(1)
	go func() {
		defer a.callbackWg.Done()
		for fn := range a.callbackCh {
			fn()
		}
	}()

	return a, nil
}

var _ ScoreAggregator = (*InMemoryAggregator)(nil)

// RegisterAgent initializes scoring state for a new agent.
func (a *InMemoryAggregator) RegisterAgent(_ context.Context, agentID string, staticCapability, historicalReputation float64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrAggregatorClosed
	}

	if agentID == "" {
		return fmt.Errorf("%w: empty agent ID", ErrInvalidSignal)
	}
	if _, exists := a.agents[agentID]; exists {
		return fmt.Errorf("%w: %s", ErrAgentAlreadyRegistered, agentID)
	}
	if staticCapability < 0 || staticCapability > 1.0 {
		return fmt.Errorf("%w: static_capability %.2f not in [0, 1]", ErrScoreOutOfRange, staticCapability)
	}
	if historicalReputation < 0 || historicalReputation > 1.0 {
		return fmt.Errorf("%w: historical_reputation %.2f not in [0, 1]", ErrScoreOutOfRange, historicalReputation)
	}

	a.agents[agentID] = &agentState{
		staticCapability:     staticCapability,
		historicalReputation: historicalReputation,
		runtimeCompliance:    1.0, // starts fully compliant
		lastUpdated:          time.Now(),
		maxSignalsPerMin:     DefaultMaxSignalsPerMinute,
	}
	return nil
}

// IngestSignal processes a telemetry signal and recomputes the agent's trust score.
func (a *InMemoryAggregator) IngestSignal(_ context.Context, signal TelemetrySignal) (*TrustScore, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, ErrAggregatorClosed
	}

	if signal.AgentID == "" {
		return nil, fmt.Errorf("%w: empty agent ID", ErrInvalidSignal)
	}

	state, ok := a.agents[signal.AgentID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrAgentNotFound, signal.AgentID)
	}

	// Snapshot tier BEFORE mutation for change detection
	oldTier := TierFromScore(a.computeScore(signal.AgentID, state).CompositeScore)

	state.signalCount++
	now := time.Now()

	if signal.Type == SignalCleanInterval {
		if signal.Severity != SeverityInfo {
			return nil, fmt.Errorf("%w: clean_interval signal must have info severity, got %s", ErrInvalidSignal, signal.Severity)
		}
		state.runtimeCompliance = math.Min(1.0, state.runtimeCompliance+DefaultRecoveryRate)
	} else if signal.Severity != SeverityInfo {
		cutoff := now.Add(-1 * time.Minute)
		pruned := state.signalWindow[:0]
		for _, ts := range state.signalWindow {
			if ts.After(cutoff) {
				pruned = append(pruned, ts)
			}
		}
		state.signalWindow = pruned

		if len(state.signalWindow) >= state.maxSignalsPerMin {
			log.Printf("trust: rate limit exceeded for registered agent (%d penalty signals in last minute), skipping penalty",
				len(state.signalWindow))
		} else {
			penalty := SeverityPenalty(signal.Severity) / 100.0
			state.runtimeCompliance = math.Max(0, state.runtimeCompliance-penalty)
			state.violationCount++
			state.signalWindow = append(state.signalWindow, now)
		}
	}

	state.lastUpdated = now

	score := a.computeScore(signal.AgentID, state)
	newTier := score.AuthorizationTier

	if a.onChange != nil && oldTier != newTier {
		cb := a.onChange
		agentID := signal.AgentID
		scoreCopy := *score
		select {
		case a.callbackCh <- func() { cb(agentID, oldTier, newTier, &scoreCopy) }:
		default:
		}
	}

	return score, nil
}

// GetScore retrieves the current trust score for an agent.
func (a *InMemoryAggregator) GetScore(_ context.Context, agentID string) (*TrustScore, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return nil, ErrAggregatorClosed
	}

	state, ok := a.agents[agentID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrAgentNotFound, agentID)
	}

	return a.computeScore(agentID, state), nil
}

// ListScores returns trust scores for all registered agents.
func (a *InMemoryAggregator) ListScores(_ context.Context) ([]*TrustScore, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return nil, ErrAggregatorClosed
	}

	scores := make([]*TrustScore, 0, len(a.agents))
	for id, state := range a.agents {
		scores = append(scores, a.computeScore(id, state))
	}
	return scores, nil
}

// Close releases resources and waits for pending callbacks to complete.
func (a *InMemoryAggregator) Close() error {
	a.mu.Lock()
	a.closed = true
	a.agents = nil
	a.mu.Unlock()

	close(a.callbackCh)
	a.callbackWg.Wait()
	return nil
}

// computeScore calculates the composite trust score from agent state.
// Must be called with at least a read lock held.
func (a *InMemoryAggregator) computeScore(agentID string, state *agentState) *TrustScore {
	// Scale component scores to 0-100 range before weighting
	staticScaled := state.staticCapability * 100.0
	historicalScaled := state.historicalReputation * 100.0
	runtimeScaled := state.runtimeCompliance * 100.0

	composite := a.weights.Static*staticScaled +
		a.weights.Historical*historicalScaled +
		a.weights.Runtime*runtimeScaled

	// Clamp to [0, 100]
	composite = math.Max(0, math.Min(100, composite))

	return &TrustScore{
		AgentID:              agentID,
		StaticCapability:     state.staticCapability,
		HistoricalReputation: state.historicalReputation,
		RuntimeCompliance:    state.runtimeCompliance,
		CompositeScore:       math.Round(composite*100) / 100,
		AuthorizationTier:    TierFromScore(composite),
		LastUpdated:          state.lastUpdated,
		SignalCount:          state.signalCount,
		ViolationCount:       state.violationCount,
	}
}
