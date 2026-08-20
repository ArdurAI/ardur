package trusttest

import (
	"context"
	"errors"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/trust"
)

func TestMockAggregator_NewMockAggregator(t *testing.T) {
	m := NewMockAggregator()
	if m == nil {
		t.Fatal("NewMockAggregator returned nil")
	}
	if m.scores == nil {
		t.Error("scores map should be initialized")
	}
	if m.closed {
		t.Error("new mock should not be closed")
	}
}

func TestMockAggregator_SetScore(t *testing.T) {
	m := NewMockAggregator()
	score := &trust.TrustScore{AgentID: "agent-1", CompositeScore: 85.0}
	m.SetScore(score)
	got, err := m.GetScore(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if got.CompositeScore != 85.0 {
		t.Errorf("composite = %.2f, want 85.00", got.CompositeScore)
	}
}

func TestMockAggregator_SetIngestError(t *testing.T) {
	m := NewMockAggregator()
	m.RegisterAgent(context.Background(), "agent-1", 0.8, 0.9)
	m.SetIngestError(errors.New("injected error"))
	_, err := m.IngestSignal(context.Background(), trust.TelemetrySignal{AgentID: "agent-1"})
	if err == nil {
		t.Error("expected error from SetIngestError")
	}
	if err.Error() != "injected error" {
		t.Errorf("err = %v, want injected error", err)
	}
}

func TestMockAggregator_IngestCount(t *testing.T) {
	m := NewMockAggregator()
	m.RegisterAgent(context.Background(), "agent-1", 0.8, 0.9)
	if c := m.IngestCount(); c != 0 {
		t.Errorf("IngestCount() = %d, want 0", c)
	}
	m.IngestSignal(context.Background(), trust.TelemetrySignal{AgentID: "agent-1"})
	m.IngestSignal(context.Background(), trust.TelemetrySignal{AgentID: "agent-1"})
	if c := m.IngestCount(); c != 2 {
		t.Errorf("IngestCount() = %d, want 2", c)
	}
}

func TestMockAggregator_Signals(t *testing.T) {
	m := NewMockAggregator()
	m.RegisterAgent(context.Background(), "agent-1", 0.8, 0.9)
	sig1 := trust.TelemetrySignal{AgentID: "agent-1", Type: trust.SignalBehavioralDrift}
	sig2 := trust.TelemetrySignal{AgentID: "agent-1", Type: trust.SignalPolicyViolation}
	m.IngestSignal(context.Background(), sig1)
	m.IngestSignal(context.Background(), sig2)
	signals := m.Signals()
	if len(signals) != 2 {
		t.Fatalf("Signals() len = %d, want 2", len(signals))
	}
	if signals[0].Type != trust.SignalBehavioralDrift {
		t.Errorf("first signal type = %s, want behavioral_drift", signals[0].Type)
	}
	if signals[1].Type != trust.SignalPolicyViolation {
		t.Errorf("second signal type = %s, want policy_violation", signals[1].Type)
	}
}

func TestMockAggregator_RegisterAgent(t *testing.T) {
	m := NewMockAggregator()
	ctx := context.Background()
	err := m.RegisterAgent(ctx, "agent-1", 0.8, 0.9)
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	score, err := m.GetScore(ctx, "agent-1")
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if score.StaticCapability != 0.8 || score.HistoricalReputation != 0.9 {
		t.Errorf("score = %+v", score)
	}
}

func TestMockAggregator_IngestSignal_Success(t *testing.T) {
	m := NewMockAggregator()
	m.RegisterAgent(context.Background(), "agent-1", 0.8, 0.9)
	score, err := m.IngestSignal(context.Background(), trust.TelemetrySignal{
		AgentID: "agent-1", Type: trust.SignalBehavioralDrift, Source: "test",
	})
	if err != nil {
		t.Fatalf("IngestSignal: %v", err)
	}
	if score == nil {
		t.Fatal("expected non-nil score")
	}
	if score.AgentID != "agent-1" {
		t.Errorf("agentID = %s, want agent-1", score.AgentID)
	}
}

func TestMockAggregator_IngestSignal_Error(t *testing.T) {
	m := NewMockAggregator()
	m.RegisterAgent(context.Background(), "agent-1", 0.8, 0.9)
	m.SetIngestError(errors.New("mock ingest error"))
	_, err := m.IngestSignal(context.Background(), trust.TelemetrySignal{AgentID: "agent-1"})
	if err == nil {
		t.Error("expected error")
	}
}

func TestMockAggregator_GetScore_Found(t *testing.T) {
	m := NewMockAggregator()
	m.SetScore(&trust.TrustScore{AgentID: "agent-1", CompositeScore: 75.0})
	score, err := m.GetScore(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if score.CompositeScore != 75.0 {
		t.Errorf("composite = %.2f, want 75.00", score.CompositeScore)
	}
}

func TestMockAggregator_GetScore_NotFound(t *testing.T) {
	m := NewMockAggregator()
	_, err := m.GetScore(context.Background(), "nonexistent")
	if !errors.Is(err, trust.ErrAgentNotFound) {
		t.Errorf("err = %v, want ErrAgentNotFound", err)
	}
}

func TestMockAggregator_ListScores(t *testing.T) {
	m := NewMockAggregator()
	m.SetScore(&trust.TrustScore{AgentID: "a1", CompositeScore: 80})
	m.SetScore(&trust.TrustScore{AgentID: "a2", CompositeScore: 90})
	scores, err := m.ListScores(context.Background())
	if err != nil {
		t.Fatalf("ListScores: %v", err)
	}
	if len(scores) != 2 {
		t.Errorf("len = %d, want 2", len(scores))
	}
}

func TestMockAggregator_Close(t *testing.T) {
	m := NewMockAggregator()
	if err := m.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if !m.closed {
		t.Error("closed should be true after Close")
	}
	_, err := m.GetScore(context.Background(), "any")
	if !errors.Is(err, trust.ErrAggregatorClosed) {
		t.Errorf("GetScore after close: %v", err)
	}
}

func TestMockAggregator_RegisterAgentClosed(t *testing.T) {
	m := NewMockAggregator()
	m.Close()
	err := m.RegisterAgent(context.Background(), "agent-1", 0.5, 0.5)
	if !errors.Is(err, trust.ErrAggregatorClosed) {
		t.Errorf("RegisterAgent after close: %v", err)
	}
}
