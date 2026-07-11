package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/trust"
)

// TelemetryIngestor exposes an HTTP endpoint that accepts TelemetrySignal
// objects from monitoring sources (Tetragon, Kubescape, verifiers) and feeds
// them into the trust ScoreAggregator.
//
// POST /telemetry/signal
//
//	Body: JSON-encoded TelemetrySignal
//	Response 200: updated TrustScore JSON
//	Response 400: malformed request
//	Response 404: agent not registered
//	Response 500: internal error
//
// REQUIRES_CLUSTER: after ingestion, if the tier changes the reconciler applies
// a NetworkPolicy. The NetworkPolicy application step is skipped when
// applyPolicy is nil (e.g. unit tests without a K8s client).
type TelemetryIngestor struct {
	agg         trust.ScoreAggregator
	applyPolicy func(ctx context.Context, namespace, tier string) error
	authorize   telemetryRequestAuthorizer
}

type telemetryRequestAuthorizer func(r *http.Request, req telemetryRequest) error

// newTelemetryIngestor creates a handler wired to an explicit request
// authorizer. Production passes telemetrySourceBindings.authorize; tests may
// use a test-only authorizer. There is deliberately no unauthenticated
// constructor for this trust-changing endpoint.
func newTelemetryIngestor(
	agg trust.ScoreAggregator,
	applyPolicy func(ctx context.Context, namespace, tier string) error,
	authorize telemetryRequestAuthorizer,
) *TelemetryIngestor {
	if authorize == nil {
		panic("telemetry request authorizer is required")
	}
	return &TelemetryIngestor{
		agg:         agg,
		applyPolicy: applyPolicy,
		authorize:   authorize,
	}
}

// telemetryRequest is the wire format for inbound signals.
// Timestamp is optional; defaults to now if omitted.
type telemetryRequest struct {
	AgentID   string     `json:"agent_id"`
	Type      string     `json:"type"`
	Severity  string     `json:"severity"`
	Source    string     `json:"source"`
	Details   string     `json:"details"`
	Namespace string     `json:"namespace"` // needed for NetworkPolicy application
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

// ServeHTTP handles POST /telemetry/signal.
func (h *TelemetryIngestor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req telemetryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	if req.AgentID == "" {
		http.Error(w, "agent_id is required", http.StatusBadRequest)
		return
	}
	if req.Source == "" {
		http.Error(w, "source is required", http.StatusBadRequest)
		return
	}
	if err := h.authorize(r, req); err != nil {
		status := http.StatusForbidden
		if errors.Is(err, errTelemetryUnauthenticated) {
			status = http.StatusUnauthorized
		}
		http.Error(w, http.StatusText(status), status)
		return
	}

	ts := time.Now()
	if req.Timestamp != nil {
		ts = *req.Timestamp
	}

	signal := trust.TelemetrySignal{
		AgentID:   req.AgentID,
		Type:      trust.SignalType(req.Type),
		Severity:  trust.SignalSeverity(req.Severity),
		Timestamp: ts,
		Source:    req.Source,
		Details:   req.Details,
	}

	ctx := r.Context()

	// Capture old tier before ingestion to detect tier changes.
	oldScore, _ := h.agg.GetScore(ctx, req.AgentID)
	oldTier := ""
	if oldScore != nil {
		oldTier = oldScore.AuthorizationTier
	}

	score, err := h.agg.IngestSignal(ctx, signal)
	if err != nil {
		if isNotFound(err) {
			http.Error(w, fmt.Sprintf("agent %q not registered", req.AgentID), http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("ingestion error: %v", err), http.StatusInternalServerError)
		return
	}

	// Apply NetworkPolicy if tier changed and a namespace was provided.
	// Failure is non-fatal: the score update already succeeded; the next
	// reconcile loop will retry the NetworkPolicy application.
	if h.applyPolicy != nil && req.Namespace != "" && score.AuthorizationTier != oldTier {
		_ = h.applyPolicy(ctx, req.Namespace, score.AuthorizationTier)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(score)
}

func isNotFound(err error) bool {
	return err != nil && (err == trust.ErrAgentNotFound ||
		containsError(err, trust.ErrAgentNotFound))
}

func containsError(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		if u, ok := err.(unwrapper); ok {
			err = u.Unwrap()
		} else {
			return false
		}
	}
	return false
}
