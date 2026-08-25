// Package policytest provides test doubles for the policy (Layer 3) engine.
//
// It lives in its own package, separate from pkg/policy, so that a fake policy
// engine cannot be linked into a production binary. That matters because
// pkg/issuer treats "a PolicyEngine is configured and Compile returned no
// error" as the policyCompiled input to computeActualCompliance, one of the
// three conditions that raise a credential to LevelVerified. A mock reachable
// from cmd/ would let policy text that was never parsed — and an authorization
// decision no real engine produced — earn that treatment.
//
// go/internal/linkgraph enforces the separation: its architecture test fails
// if this package, or any exported Mock/Fake/Stub/Dummy symbol in a non-test
// file, becomes reachable from a binary under cmd/.
package policytest

import (
	"context"
	"sync"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/policy"
)

// MockPolicyEngine implements policy.PolicyEngine for testing.
// Configurable decision, errors, and call tracking.
type MockPolicyEngine struct {
	mu           sync.Mutex
	closed       bool
	decision     policy.Decision
	compileErr   error
	evalErr      error
	evalReasons  []string
	compileCount int
	evalCount    int
	entities     []policy.Entity
	lastRequest  *policy.AuthzRequest
	name         string
}

// MockPolicyEngineOption configures a MockPolicyEngine.
type MockPolicyEngineOption func(*MockPolicyEngine)

// WithMockDecision sets the decision returned by Evaluate.
func WithMockDecision(d policy.Decision) MockPolicyEngineOption {
	return func(m *MockPolicyEngine) { m.decision = d }
}

// WithMockCompileError sets the error returned by Compile.
func WithMockCompileError(err error) MockPolicyEngineOption {
	return func(m *MockPolicyEngine) { m.compileErr = err }
}

// WithMockEvalError sets the error returned by Evaluate.
func WithMockEvalError(err error) MockPolicyEngineOption {
	return func(m *MockPolicyEngine) { m.evalErr = err }
}

// WithMockEngineName sets the engine name.
func WithMockEngineName(name string) MockPolicyEngineOption {
	return func(m *MockPolicyEngine) { m.name = name }
}

// NewMockPolicyEngine creates a new mock policy engine.
func NewMockPolicyEngine(opts ...MockPolicyEngineOption) *MockPolicyEngine {
	m := &MockPolicyEngine{
		decision: policy.DecisionAllow,
		name:     "mock",
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

var _ policy.PolicyEngine = (*MockPolicyEngine)(nil)

func (m *MockPolicyEngine) Compile(_ context.Context, policyText string) (*policy.CompiledPolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.compileCount++

	if m.closed {
		return nil, policy.ErrEngineClosed
	}
	if m.compileErr != nil {
		return nil, m.compileErr
	}

	hash := policy.ComputePolicyHash(policyText)
	return &policy.CompiledPolicy{
		PolicyText:  policyText,
		Hash:        hash,
		PolicyCount: 1,
		PolicyIDs:   []string{"mock-policy-0"},
	}, nil
}

func (m *MockPolicyEngine) Evaluate(_ context.Context, _ *policy.CompiledPolicy, _ []policy.Entity, request policy.AuthzRequest) (*policy.AuthzResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evalCount++
	m.lastRequest = &request

	if m.closed {
		return nil, policy.ErrEngineClosed
	}
	if m.evalErr != nil {
		return nil, m.evalErr
	}

	return &policy.AuthzResult{
		Decision: m.decision,
		Reasons:  m.evalReasons,
		EvalTime: 100 * time.Microsecond,
	}, nil
}

func (m *MockPolicyEngine) SetEntities(entities []policy.Entity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return policy.ErrEngineClosed
	}
	m.entities = entities
	return nil
}

func (m *MockPolicyEngine) EngineName() string { return m.name }

func (m *MockPolicyEngine) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// SetDecision changes the mock decision (thread-safe).
func (m *MockPolicyEngine) SetDecision(d policy.Decision) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decision = d
}

// CompileCount returns the number of Compile calls.
func (m *MockPolicyEngine) CompileCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.compileCount
}

// EvalCount returns the number of Evaluate calls.
func (m *MockPolicyEngine) EvalCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.evalCount
}

// LastRequest returns the last AuthzRequest passed to Evaluate.
func (m *MockPolicyEngine) LastRequest() *policy.AuthzRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastRequest
}
