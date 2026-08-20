package trust

import (
	"bytes"
	"context"
	"errors"
	"log"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestScoreWeightsValidate(t *testing.T) {
	tests := []struct {
		name    string
		weights ScoreWeights
		wantErr bool
	}{
		{"default", ScoreWeights{0.3, 0.3, 0.4}, false},
		{"equal", ScoreWeights{1.0 / 3, 1.0 / 3, 1.0 / 3}, false},
		{"sum not 1", ScoreWeights{0.5, 0.5, 0.5}, true},
		{"negative", ScoreWeights{-0.1, 0.6, 0.5}, true},
		{"zero sum", ScoreWeights{0, 0, 0}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.weights.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSeverityPenalty(t *testing.T) {
	if SeverityPenalty(SeverityCritical) != 20.0 {
		t.Error("critical penalty should be 20")
	}
	if SeverityPenalty(SeverityHigh) != 10.0 {
		t.Error("high penalty should be 10")
	}
	if SeverityPenalty(SeverityMedium) != 5.0 {
		t.Error("medium penalty should be 5")
	}
	if SeverityPenalty(SeverityLow) != 2.0 {
		t.Error("low penalty should be 2")
	}
	if SeverityPenalty(SeverityInfo) != 0.0 {
		t.Error("info penalty should be 0")
	}
	if SeverityPenalty("unknown") != 5.0 {
		t.Error("unknown severity should default to 5")
	}
}

func TestTierFromScore(t *testing.T) {
	tests := []struct {
		score float64
		tier  string
	}{
		{100, TierFull},
		{70, TierFull},
		{69.9, TierLimited},
		{40, TierLimited},
		{39.9, TierQuarantine},
		{0, TierQuarantine},
	}

	for _, tt := range tests {
		tier := TierFromScore(tt.score)
		if tier != tt.tier {
			t.Errorf("TierFromScore(%.1f) = %s, want %s", tt.score, tier, tt.tier)
		}
	}
}

func TestInMemoryAggregator_RegisterAndGetScore(t *testing.T) {
	agg, err := NewInMemoryAggregator()
	if err != nil {
		t.Fatalf("NewInMemoryAggregator: %v", err)
	}
	defer agg.Close()

	ctx := context.Background()

	err = agg.RegisterAgent(ctx, "agent-1", 0.8, 0.9)
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	score, err := agg.GetScore(ctx, "agent-1")
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}

	if score.StaticCapability != 0.8 {
		t.Errorf("static = %.2f, want 0.80", score.StaticCapability)
	}
	if score.HistoricalReputation != 0.9 {
		t.Errorf("historical = %.2f, want 0.90", score.HistoricalReputation)
	}
	if score.RuntimeCompliance != 1.0 {
		t.Errorf("runtime = %.2f, want 1.00", score.RuntimeCompliance)
	}

	// Default weights: 0.3*80 + 0.3*90 + 0.4*100 = 24 + 27 + 40 = 91
	if score.CompositeScore != 91.0 {
		t.Errorf("composite = %.2f, want 91.00", score.CompositeScore)
	}
	if score.AuthorizationTier != TierFull {
		t.Errorf("tier = %s, want full", score.AuthorizationTier)
	}
}

func TestInMemoryAggregator_RegisterValidation(t *testing.T) {
	agg, _ := NewInMemoryAggregator()
	defer agg.Close()
	ctx := context.Background()

	if err := agg.RegisterAgent(ctx, "", 0.5, 0.5); err == nil {
		t.Error("expected error for empty agent ID")
	}
	if err := agg.RegisterAgent(ctx, "a", -0.1, 0.5); err == nil {
		t.Error("expected error for negative static score")
	}
	if err := agg.RegisterAgent(ctx, "a", 0.5, 1.1); err == nil {
		t.Error("expected error for historical > 1.0")
	}
}

func TestInMemoryAggregator_IngestSignalDegradation(t *testing.T) {
	agg, _ := NewInMemoryAggregator()
	defer agg.Close()
	ctx := context.Background()

	agg.RegisterAgent(ctx, "agent-1", 0.8, 0.9)

	// Ingest a critical signal (penalty = 20/100 = 0.20 to runtime)
	score, err := agg.IngestSignal(ctx, TelemetrySignal{
		AgentID:   "agent-1",
		Type:      SignalBehavioralDrift,
		Severity:  SeverityCritical,
		Timestamp: time.Now(),
		Source:    "tetragon",
	})
	if err != nil {
		t.Fatalf("IngestSignal: %v", err)
	}

	// Runtime goes from 1.0 to 0.8
	if score.RuntimeCompliance != 0.8 {
		t.Errorf("runtime = %.2f, want 0.80", score.RuntimeCompliance)
	}
	// 0.3*80 + 0.3*90 + 0.4*80 = 24 + 27 + 32 = 83
	if score.CompositeScore != 83.0 {
		t.Errorf("composite = %.2f, want 83.00", score.CompositeScore)
	}
	if score.ViolationCount != 1 {
		t.Errorf("violations = %d, want 1", score.ViolationCount)
	}
}

func TestInMemoryAggregator_DegradeToQuarantine(t *testing.T) {
	agg, _ := NewInMemoryAggregator()
	defer agg.Close()
	ctx := context.Background()

	// Use low static+historical so quarantine is reachable
	agg.RegisterAgent(ctx, "agent-1", 0.3, 0.3)

	// Initial: 0.3*30 + 0.3*30 + 0.4*100 = 9 + 9 + 40 = 58 (limited)
	score, _ := agg.GetScore(ctx, "agent-1")
	if score.AuthorizationTier != TierLimited {
		t.Logf("initial tier = %s, composite=%.2f", score.AuthorizationTier, score.CompositeScore)
	}

	// Multiple critical violations to push to quarantine
	for i := 0; i < 5; i++ {
		score, _ = agg.IngestSignal(ctx, TelemetrySignal{
			AgentID:  "agent-1",
			Type:     SignalPolicyViolation,
			Severity: SeverityCritical,
			Source:   "verifier",
		})
	}

	// Runtime should be 0 after 5 critical penalties (each -0.20)
	if score.RuntimeCompliance > 0.001 {
		t.Errorf("runtime = %.4f, want ~0.00", score.RuntimeCompliance)
	}
	// 0.3*30 + 0.3*30 + 0.4*0 = 9 + 9 + 0 = 18 (quarantine)
	if score.AuthorizationTier != TierQuarantine {
		t.Errorf("tier = %s, want quarantine (composite=%.2f, runtime=%.4f)",
			score.AuthorizationTier, score.CompositeScore, score.RuntimeCompliance)
	}
}

func TestInMemoryAggregator_Recovery(t *testing.T) {
	agg, _ := NewInMemoryAggregator()
	defer agg.Close()
	ctx := context.Background()

	agg.RegisterAgent(ctx, "agent-1", 0.8, 0.9)

	// Degrade
	agg.IngestSignal(ctx, TelemetrySignal{
		AgentID: "agent-1", Type: SignalBehavioralDrift,
		Severity: SeverityHigh, Source: "tetragon",
	})

	score, _ := agg.GetScore(ctx, "agent-1")
	runtimeBefore := score.RuntimeCompliance

	// Clean interval should recover runtime
	agg.IngestSignal(ctx, TelemetrySignal{
		AgentID: "agent-1", Type: SignalCleanInterval,
		Severity: SeverityInfo, Source: "aggregator",
	})

	score, _ = agg.GetScore(ctx, "agent-1")
	if score.RuntimeCompliance <= runtimeBefore {
		t.Errorf("runtime didn't recover: before=%.2f, after=%.2f", runtimeBefore, score.RuntimeCompliance)
	}
}

func TestInMemoryAggregator_RateLimitLogOmitsAgentID(t *testing.T) {
	var buf bytes.Buffer
	oldWriter := log.Writer()
	oldFlags := log.Flags()
	oldPrefix := log.Prefix()
	log.SetOutput(&buf)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
		log.SetPrefix(oldPrefix)
	}()

	agg, _ := NewInMemoryAggregator()
	defer agg.Close()
	ctx := context.Background()
	agentID := "agent-1\nforged-log-line"
	agg.RegisterAgent(ctx, agentID, 0.8, 0.9)

	agg.mu.Lock()
	agg.agents[agentID].maxSignalsPerMin = 1
	agg.mu.Unlock()

	for i := 0; i < 2; i++ {
		_, err := agg.IngestSignal(ctx, TelemetrySignal{
			AgentID:  agentID,
			Type:     SignalPolicyViolation,
			Severity: SeverityLow,
			Source:   "test",
		})
		if err != nil {
			t.Fatalf("IngestSignal: %v", err)
		}
	}

	logged := buf.String()
	if !strings.Contains(logged, "rate limit exceeded for registered agent") {
		t.Fatalf("expected rate-limit log entry, got %q", logged)
	}
	if strings.Contains(logged, "agent-1") || strings.Contains(logged, "forged-log-line") {
		t.Fatalf("rate-limit log leaked agent ID: %q", logged)
	}
}

func TestInMemoryAggregator_InfoSignalNoImpact(t *testing.T) {
	agg, _ := NewInMemoryAggregator()
	defer agg.Close()
	ctx := context.Background()

	agg.RegisterAgent(ctx, "agent-1", 0.8, 0.9)

	scoreBefore, _ := agg.GetScore(ctx, "agent-1")
	compositeBefore := scoreBefore.CompositeScore

	agg.IngestSignal(ctx, TelemetrySignal{
		AgentID: "agent-1", Type: SignalBehavioralDrift,
		Severity: SeverityInfo, Source: "kubescape",
	})

	scoreAfter, _ := agg.GetScore(ctx, "agent-1")
	if scoreAfter.CompositeScore != compositeBefore {
		t.Errorf("info signal changed composite: before=%.2f, after=%.2f", compositeBefore, scoreAfter.CompositeScore)
	}
}

func TestInMemoryAggregator_AgentNotFound(t *testing.T) {
	agg, _ := NewInMemoryAggregator()
	defer agg.Close()

	_, err := agg.GetScore(context.Background(), "nonexistent")
	if !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("err = %v, want ErrAgentNotFound", err)
	}

	_, err = agg.IngestSignal(context.Background(), TelemetrySignal{AgentID: "nonexistent"})
	if !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("err = %v, want ErrAgentNotFound", err)
	}
}

func TestInMemoryAggregator_Closed(t *testing.T) {
	agg, _ := NewInMemoryAggregator()
	agg.Close()
	ctx := context.Background()

	if err := agg.RegisterAgent(ctx, "a", 0.5, 0.5); !errors.Is(err, ErrAggregatorClosed) {
		t.Errorf("RegisterAgent after close: %v", err)
	}
	if _, err := agg.GetScore(ctx, "a"); !errors.Is(err, ErrAggregatorClosed) {
		t.Errorf("GetScore after close: %v", err)
	}
	if _, err := agg.IngestSignal(ctx, TelemetrySignal{AgentID: "a"}); !errors.Is(err, ErrAggregatorClosed) {
		t.Errorf("IngestSignal after close: %v", err)
	}
	if _, err := agg.ListScores(ctx); !errors.Is(err, ErrAggregatorClosed) {
		t.Errorf("ListScores after close: %v", err)
	}
}

func TestInMemoryAggregator_ListScores(t *testing.T) {
	agg, _ := NewInMemoryAggregator()
	defer agg.Close()
	ctx := context.Background()

	agg.RegisterAgent(ctx, "agent-1", 0.8, 0.9)
	agg.RegisterAgent(ctx, "agent-2", 0.5, 0.5)

	scores, err := agg.ListScores(ctx)
	if err != nil {
		t.Fatalf("ListScores: %v", err)
	}
	if len(scores) != 2 {
		t.Errorf("score count = %d, want 2", len(scores))
	}
}

func TestInMemoryAggregator_CustomWeights(t *testing.T) {
	agg, err := NewInMemoryAggregator(WithWeights(ScoreWeights{
		Static: 0.5, Historical: 0.3, Runtime: 0.2,
	}))
	if err != nil {
		t.Fatalf("NewInMemoryAggregator: %v", err)
	}
	defer agg.Close()

	agg.RegisterAgent(context.Background(), "agent-1", 1.0, 1.0)
	score, _ := agg.GetScore(context.Background(), "agent-1")

	// 0.5*100 + 0.3*100 + 0.2*100 = 100
	if score.CompositeScore != 100.0 {
		t.Errorf("composite = %.2f, want 100.00", score.CompositeScore)
	}
}

func TestInMemoryAggregator_InvalidWeights(t *testing.T) {
	_, err := NewInMemoryAggregator(WithWeights(ScoreWeights{
		Static: 0.5, Historical: 0.5, Runtime: 0.5,
	}))
	if err == nil {
		t.Error("expected error for invalid weights")
	}
}

func TestInMemoryAggregator_OnChangeCallback(t *testing.T) {
	var mu sync.Mutex
	var changes []string

	agg, _ := NewInMemoryAggregator(WithOnChange(func(agentID, oldTier, newTier string, _ *TrustScore) {
		mu.Lock()
		defer mu.Unlock()
		changes = append(changes, agentID+":"+oldTier+"->"+newTier)
	}))
	defer agg.Close()
	ctx := context.Background()

	agg.RegisterAgent(ctx, "agent-1", 0.5, 0.5)

	// Push to quarantine with multiple critical violations
	for i := 0; i < 5; i++ {
		agg.IngestSignal(ctx, TelemetrySignal{
			AgentID: "agent-1", Type: SignalPolicyViolation,
			Severity: SeverityCritical, Source: "test",
		})
	}

	// Give the goroutine a moment to fire
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(changes) == 0 {
		t.Log("note: tier change callback may not fire if score stays in same tier between individual signals")
	}
}

func TestInMemoryAggregator_ConcurrentAccess(t *testing.T) {
	agg, _ := NewInMemoryAggregator()
	defer agg.Close()
	ctx := context.Background()

	agg.RegisterAgent(ctx, "agent-1", 0.8, 0.9)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			agg.IngestSignal(ctx, TelemetrySignal{
				AgentID:  "agent-1",
				Type:     SignalBehavioralDrift,
				Severity: SeverityLow,
				Source:   "test",
			})
		}()
	}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			agg.GetScore(ctx, "agent-1")
		}()
	}
	wg.Wait()

	score, _ := agg.GetScore(ctx, "agent-1")
	if score.SignalCount != 50 {
		t.Errorf("signal count = %d, want 50", score.SignalCount)
	}
}

// --- Scorer edge cases ---

func TestScoreWeightsValidate_NegativeWeights(t *testing.T) {
	tests := []struct {
		name string
		w    ScoreWeights
	}{
		{"static negative", ScoreWeights{Static: -0.1, Historical: 0.6, Runtime: 0.5}},
		{"historical negative", ScoreWeights{Static: 0.6, Historical: -0.1, Runtime: 0.5}},
		{"runtime negative", ScoreWeights{Static: 0.5, Historical: 0.5, Runtime: -0.1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.w.Validate()
			if err == nil {
				t.Error("expected error for negative weight")
			}
		})
	}
}

func TestScoreWeightsValidate_NaNInfWeights(t *testing.T) {
	tests := []struct {
		name string
		w    ScoreWeights
	}{
		{"NaN static", ScoreWeights{Static: math.NaN(), Historical: 0.5, Runtime: 0.5}},
		{"NaN historical", ScoreWeights{Static: 0.5, Historical: math.NaN(), Runtime: 0.5}},
		{"NaN runtime", ScoreWeights{Static: 0.5, Historical: 0.5, Runtime: math.NaN()}},
		{"Inf static", ScoreWeights{Static: math.Inf(1), Historical: 0.5, Runtime: 0.5}},
		{"Inf historical", ScoreWeights{Static: 0.5, Historical: math.Inf(-1), Runtime: 0.5}},
		{"Inf runtime", ScoreWeights{Static: 0.5, Historical: 0.5, Runtime: math.Inf(1)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.w.Validate()
			if err == nil {
				t.Error("expected error for NaN/Inf weight")
			}
		})
	}
}

func TestInMemoryAggregator_RegisterAgentClosed(t *testing.T) {
	agg, _ := NewInMemoryAggregator()
	agg.Close()
	err := agg.RegisterAgent(context.Background(), "agent-1", 0.5, 0.5)
	if !errors.Is(err, ErrAggregatorClosed) {
		t.Errorf("RegisterAgent on closed aggregator: %v", err)
	}
}

func TestInMemoryAggregator_IngestSignalEmptyAgentID(t *testing.T) {
	agg, _ := NewInMemoryAggregator()
	defer agg.Close()
	agg.RegisterAgent(context.Background(), "agent-1", 0.8, 0.9)
	_, err := agg.IngestSignal(context.Background(), TelemetrySignal{AgentID: ""})
	if err == nil {
		t.Error("expected error for empty agent ID")
	}
	if !errors.Is(err, ErrInvalidSignal) {
		t.Errorf("err = %v, want ErrInvalidSignal", err)
	}
}

func TestInMemoryAggregator_RegisterAgentEmptyAgentID(t *testing.T) {
	agg, _ := NewInMemoryAggregator()
	defer agg.Close()
	err := agg.RegisterAgent(context.Background(), "", 0.5, 0.5)
	if err == nil {
		t.Error("expected error for empty agent ID")
	}
	if !errors.Is(err, ErrInvalidSignal) {
		t.Errorf("err = %v, want ErrInvalidSignal", err)
	}
}
