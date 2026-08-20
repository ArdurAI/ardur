// Package trusttest provides test doubles for the trust scoring (Layer 5)
// aggregation layer.
//
// It lives in its own package, separate from pkg/trust, so that a fake
// aggregator cannot be linked into a production binary. That matters because
// pkg/issuer treats "a ScoreAggregator is configured and GetScore returned no
// error" as the trustScored input to computeActualCompliance, one of the five
// conditions that raise a credential to LevelEnforced. A mock reachable from
// cmd/ would let a hand-set composite score and authorization tier — derived
// from no telemetry at all — earn that treatment.
//
// go/internal/linkgraph enforces the separation: its architecture test fails
// if this package, or any exported Mock/Fake/Stub/Dummy symbol in a non-test
// file, becomes reachable from a binary under cmd/.
package trusttest

import (
	"context"
	"fmt"
	"sync"

	"github.com/ArdurAI/ardur/go/pkg/trust"
)

// MockAggregator implements trust.ScoreAggregator for testing.
type MockAggregator struct {
	mu          sync.Mutex
	closed      bool
	scores      map[string]*trust.TrustScore
	ingestErr   error
	ingestCount int
	signals     []trust.TelemetrySignal
}

// NewMockAggregator creates a mock trust score aggregator.
func NewMockAggregator() *MockAggregator {
	return &MockAggregator{
		scores: make(map[string]*trust.TrustScore),
	}
}

var _ trust.ScoreAggregator = (*MockAggregator)(nil)

// SetScore pre-loads a score for testing.
func (m *MockAggregator) SetScore(score *trust.TrustScore) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scores[score.AgentID] = score
}

// SetIngestError configures an error returned by IngestSignal.
func (m *MockAggregator) SetIngestError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ingestErr = err
}

// IngestCount returns the number of IngestSignal calls.
func (m *MockAggregator) IngestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ingestCount
}

// Signals returns all ingested signals.
func (m *MockAggregator) Signals() []trust.TelemetrySignal {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]trust.TelemetrySignal(nil), m.signals...)
}

func (m *MockAggregator) RegisterAgent(_ context.Context, agentID string, staticCapability, historicalReputation float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return trust.ErrAggregatorClosed
	}
	m.scores[agentID] = &trust.TrustScore{
		AgentID:              agentID,
		StaticCapability:     staticCapability,
		HistoricalReputation: historicalReputation,
		RuntimeCompliance:    1.0,
		CompositeScore:       100.0,
		AuthorizationTier:    trust.TierFull,
	}
	return nil
}

func (m *MockAggregator) IngestSignal(_ context.Context, signal trust.TelemetrySignal) (*trust.TrustScore, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ingestCount++
	m.signals = append(m.signals, signal)

	if m.closed {
		return nil, trust.ErrAggregatorClosed
	}
	if m.ingestErr != nil {
		return nil, m.ingestErr
	}

	score, ok := m.scores[signal.AgentID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", trust.ErrAgentNotFound, signal.AgentID)
	}
	return score, nil
}

func (m *MockAggregator) GetScore(_ context.Context, agentID string) (*trust.TrustScore, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, trust.ErrAggregatorClosed
	}
	score, ok := m.scores[agentID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", trust.ErrAgentNotFound, agentID)
	}
	return score, nil
}

func (m *MockAggregator) ListScores(_ context.Context) ([]*trust.TrustScore, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, trust.ErrAggregatorClosed
	}
	scores := make([]*trust.TrustScore, 0, len(m.scores))
	for _, s := range m.scores {
		scores = append(scores, s)
	}
	return scores, nil
}

func (m *MockAggregator) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}
