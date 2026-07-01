package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/trust"
)

// newTestIngestor builds an ingestor backed by a fresh in-memory aggregator
// with "test-agent" pre-registered at scores that place it in the full tier.
func newTestIngestor(t *testing.T) (*TelemetryIngestor, trust.ScoreAggregator) {
	t.Helper()
	agg, err := trust.NewInMemoryAggregator()
	if err != nil {
		t.Fatalf("creating aggregator: %v", err)
	}
	if err := agg.RegisterAgent(context.Background(), "test-agent", 0.8, 0.8); err != nil {
		t.Fatalf("registering agent: %v", err)
	}
	return NewTelemetryIngestor(agg, nil), agg
}

func postSignal(t *testing.T, h http.Handler, body telemetryRequest) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshaling request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/telemetry/signal", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestTelemetryIngestor_CleanInterval(t *testing.T) {
	h, _ := newTestIngestor(t)
	w := postSignal(t, h, telemetryRequest{
		AgentID:  "test-agent",
		Type:     string(trust.SignalCleanInterval),
		Severity: string(trust.SeverityInfo),
		Source:   "verifier",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var score trust.TrustScore
	if err := json.NewDecoder(w.Body).Decode(&score); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if score.AgentID != "test-agent" {
		t.Errorf("expected agent_id test-agent, got %q", score.AgentID)
	}
	if score.CompositeScore <= 0 {
		t.Error("expected positive composite score after clean interval")
	}
}

func TestTelemetryIngestor_PolicyViolationDegrades(t *testing.T) {
	h, agg := newTestIngestor(t)

	baseScore, err := agg.GetScore(context.Background(), "test-agent")
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	w := postSignal(t, h, telemetryRequest{
		AgentID:  "test-agent",
		Type:     string(trust.SignalPolicyViolation),
		Severity: string(trust.SeverityHigh),
		Source:   "kubescape",
		Details:  "privileged container detected",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var score trust.TrustScore
	if err := json.NewDecoder(w.Body).Decode(&score); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if score.CompositeScore >= baseScore.CompositeScore {
		t.Errorf("score should degrade after high violation: before=%.2f after=%.2f",
			baseScore.CompositeScore, score.CompositeScore)
	}
}

func TestTelemetryIngestor_UnknownAgent404(t *testing.T) {
	h, _ := newTestIngestor(t)
	w := postSignal(t, h, telemetryRequest{
		AgentID:  "ghost-agent",
		Type:     string(trust.SignalCleanInterval),
		Severity: string(trust.SeverityInfo),
		Source:   "verifier",
	})
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown agent, got %d", w.Code)
	}
}

func TestTelemetryIngestor_MissingAgentID400(t *testing.T) {
	h, _ := newTestIngestor(t)
	w := postSignal(t, h, telemetryRequest{
		Type:     string(trust.SignalCleanInterval),
		Severity: string(trust.SeverityInfo),
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing agent_id, got %d", w.Code)
	}
}

func TestTelemetryIngestor_InvalidJSON400(t *testing.T) {
	h, _ := newTestIngestor(t)
	req := httptest.NewRequest(http.MethodPost, "/telemetry/signal", bytes.NewBufferString("{invalid"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestTelemetryIngestor_WrongMethod405(t *testing.T) {
	h, _ := newTestIngestor(t)
	req := httptest.NewRequest(http.MethodGet, "/telemetry/signal", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", w.Code)
	}
}

func TestTelemetryIngestor_TimestampOverride(t *testing.T) {
	h, _ := newTestIngestor(t)
	ts := time.Now().Add(-5 * time.Minute)
	w := postSignal(t, h, telemetryRequest{
		AgentID:   "test-agent",
		Type:      string(trust.SignalCleanInterval),
		Severity:  string(trust.SeverityInfo),
		Source:    "verifier",
		Timestamp: &ts,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with explicit timestamp, got %d: %s", w.Code, w.Body.String())
	}
}

// TestTelemetryIngestor_ApplyPolicyCalledOnTierChange verifies the applyPolicy
// callback fires when a signal causes a tier transition.
func TestTelemetryIngestor_ApplyPolicyCalledOnTierChange(t *testing.T) {
	agg, err := trust.NewInMemoryAggregator()
	if err != nil {
		t.Fatal(err)
	}
	// Register near the quarantine boundary
	if err := agg.RegisterAgent(context.Background(), "fringe-agent", 0.4, 0.4); err != nil {
		t.Fatal(err)
	}

	var capturedTier string
	applyFn := func(_ context.Context, _ string, tier string) error {
		capturedTier = tier
		return nil
	}

	h := NewTelemetryIngestor(agg, applyFn)

	// Apply critical signals to push into quarantine
	for range 5 {
		w := postSignal(t, h, telemetryRequest{
			AgentID:   "fringe-agent",
			Type:      string(trust.SignalPolicyViolation),
			Severity:  string(trust.SeverityCritical),
			Source:    "tetragon",
			Namespace: "agents",
		})
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	}

	score, err := agg.GetScore(context.Background(), "fringe-agent")
	if err != nil {
		t.Fatal(err)
	}
	// After heavy degradation agent should be in quarantine and callback should have fired
	if score.AuthorizationTier == trust.TierQuarantine && capturedTier == "" {
		t.Error("applyPolicy callback was not called despite tier change to quarantine")
	}
}

// TestBearerAuthMiddleware_NoAuth_Returns401 verifies unauthenticated requests
// are rejected with 401, preventing any pod from forging telemetry signals.
func TestBearerAuthMiddleware_NoAuth_Returns401(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := BearerAuthMiddleware("secret-token", inner)
	req := httptest.NewRequest(http.MethodPost, "/telemetry/signal", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing auth header, got %d", w.Code)
	}
}

func TestBearerAuthMiddleware_WrongToken_Returns401(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := BearerAuthMiddleware("secret-token", inner)
	req := httptest.NewRequest(http.MethodPost, "/telemetry/signal", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong token, got %d", w.Code)
	}
}

func TestBearerAuthMiddleware_CorrectToken_PassesThrough(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := BearerAuthMiddleware("secret-token", inner)
	req := httptest.NewRequest(http.MethodPost, "/telemetry/signal", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}

func TestBearerAuthMiddleware_EmptyToken_RejectsAll(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := BearerAuthMiddleware("", inner)
	req := httptest.NewRequest(http.MethodPost, "/telemetry/signal", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for empty token (fail-closed), got %d", w.Code)
	}
}

// TestTelemetryIngestor_ResponseContainsAuthorizationTier checks the JSON
// response includes the authorization_tier field.
func TestTelemetryIngestor_ResponseContainsAuthorizationTier(t *testing.T) {
	h, _ := newTestIngestor(t)
	w := postSignal(t, h, telemetryRequest{
		AgentID:  "test-agent",
		Type:     string(trust.SignalCleanInterval),
		Severity: string(trust.SeverityInfo),
		Source:   "verifier",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var m map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["authorization_tier"]; !ok {
		t.Error("response must contain authorization_tier field")
	}
}
