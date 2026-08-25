package policytest

import (
	"context"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/policy"
)

func TestMockPolicyEngine(t *testing.T) {
	t.Run("default allow", func(t *testing.T) {
		m := NewMockPolicyEngine()
		defer m.Close()

		compiled, err := m.Compile(context.Background(), "permit(principal, action, resource);")
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if compiled.Hash == "" {
			t.Error("compiled hash is empty")
		}

		result, err := m.Evaluate(context.Background(), compiled, nil, policy.AuthzRequest{
			Principal: policy.EntityRef{Type: "VIBAP::Agent", ID: "bot"},
			Action:    policy.EntityRef{Type: "Action", ID: "read"},
			Resource:  policy.EntityRef{Type: "VIBAP::Resource", ID: "db"},
		})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if result.Decision != policy.DecisionAllow {
			t.Errorf("decision = %s, want allow", result.Decision)
		}
		if m.EvalCount() != 1 {
			t.Errorf("eval count = %d, want 1", m.EvalCount())
		}
	})

	t.Run("configured deny", func(t *testing.T) {
		m := NewMockPolicyEngine(WithMockDecision(policy.DecisionDeny))
		defer m.Close()

		compiled, _ := m.Compile(context.Background(), "forbid(principal, action, resource);")
		result, err := m.Evaluate(context.Background(), compiled, nil, policy.AuthzRequest{})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if result.Decision != policy.DecisionDeny {
			t.Errorf("decision = %s, want deny", result.Decision)
		}
	})

	t.Run("closed engine", func(t *testing.T) {
		m := NewMockPolicyEngine()
		m.Close()

		_, err := m.Compile(context.Background(), "permit(principal, action, resource);")
		if err != policy.ErrEngineClosed {
			t.Errorf("Compile after close: err = %v, want ErrEngineClosed", err)
		}
	})

	t.Run("compile error", func(t *testing.T) {
		m := NewMockPolicyEngine(WithMockCompileError(policy.ErrPolicyParse))
		defer m.Close()

		_, err := m.Compile(context.Background(), "bad policy")
		if err != policy.ErrPolicyParse {
			t.Errorf("err = %v, want ErrPolicyParse", err)
		}
	})

	t.Run("tracks last request", func(t *testing.T) {
		m := NewMockPolicyEngine()
		defer m.Close()

		compiled, _ := m.Compile(context.Background(), "permit(principal, action, resource);")
		req := policy.AuthzRequest{
			Principal: policy.EntityRef{Type: "VIBAP::Agent", ID: "test-agent"},
			Action:    policy.EntityRef{Type: "Action", ID: "write"},
			Resource:  policy.EntityRef{Type: "VIBAP::Resource", ID: "log"},
		}
		m.Evaluate(context.Background(), compiled, nil, req)

		last := m.LastRequest()
		if last == nil {
			t.Fatal("LastRequest is nil")
		}
		if last.Principal.ID != "test-agent" {
			t.Errorf("principal = %s, want test-agent", last.Principal.ID)
		}
	})
}

func TestMockHelperFunctions(t *testing.T) {
	t.Run("WithMockEvalError", func(t *testing.T) {
		m := NewMockPolicyEngine(WithMockEvalError(policy.ErrEvaluation))
		defer m.Close()

		compiled, _ := m.Compile(context.Background(), "permit(principal, action, resource);")
		_, err := m.Evaluate(context.Background(), compiled, nil, policy.AuthzRequest{})
		if err != policy.ErrEvaluation {
			t.Errorf("Evaluate err = %v, want ErrEvaluation", err)
		}
	})

	t.Run("WithMockEngineName and EngineName", func(t *testing.T) {
		m := NewMockPolicyEngine(WithMockEngineName("custom-engine"))
		defer m.Close()

		if got := m.EngineName(); got != "custom-engine" {
			t.Errorf("EngineName() = %q, want custom-engine", got)
		}
	})

	t.Run("SetDecision", func(t *testing.T) {
		m := NewMockPolicyEngine()
		defer m.Close()

		m.SetDecision(policy.DecisionDeny)
		compiled, _ := m.Compile(context.Background(), "permit(principal, action, resource);")
		result, err := m.Evaluate(context.Background(), compiled, nil, policy.AuthzRequest{})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if result.Decision != policy.DecisionDeny {
			t.Errorf("decision = %s, want deny", result.Decision)
		}
	})

	t.Run("CompileCount", func(t *testing.T) {
		m := NewMockPolicyEngine()
		defer m.Close()

		m.Compile(context.Background(), "permit(principal, action, resource);")
		m.Compile(context.Background(), "forbid(principal, action, resource);")
		m.Compile(context.Background(), "permit(principal, action, resource);")
		if got := m.CompileCount(); got != 3 {
			t.Errorf("CompileCount() = %d, want 3", got)
		}
	})

	t.Run("SetEntities", func(t *testing.T) {
		m := NewMockPolicyEngine()
		defer m.Close()

		entities := []policy.Entity{
			{UID: policy.EntityRef{Type: "VIBAP::Agent", ID: "bot-1"}},
		}
		if err := m.SetEntities(entities); err != nil {
			t.Errorf("SetEntities: %v", err)
		}
	})

	t.Run("EngineName default", func(t *testing.T) {
		m := NewMockPolicyEngine()
		defer m.Close()

		if got := m.EngineName(); got != "mock" {
			t.Errorf("EngineName() = %q, want mock", got)
		}
	})
}

func TestMockEvaluateErrorPath(t *testing.T) {
	m := NewMockPolicyEngine(WithMockEvalError(policy.ErrEvaluation))
	defer m.Close()

	compiled, _ := m.Compile(context.Background(), "permit(principal, action, resource);")
	_, err := m.Evaluate(context.Background(), compiled, nil, policy.AuthzRequest{})
	if err != policy.ErrEvaluation {
		t.Errorf("Evaluate err = %v, want ErrEvaluation", err)
	}
}

func TestMockEvaluateOnClosedEngine(t *testing.T) {
	m := NewMockPolicyEngine()
	compiled, _ := m.Compile(context.Background(), "permit(principal, action, resource);")
	m.Close()

	_, err := m.Evaluate(context.Background(), compiled, nil, policy.AuthzRequest{})
	if err != policy.ErrEngineClosed {
		t.Errorf("Evaluate on closed engine: err = %v, want ErrEngineClosed", err)
	}
}
