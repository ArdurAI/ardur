package kernelcapture

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
)

func TestEmbeddedAgentRecognizerCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata/agent_recognition_corpus.json")
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var corpus []struct {
		Name              string `json:"name"`
		Comm              string `json:"comm"`
		ExpectedStatus    string `json:"expected_status"`
		ExpectedAgentType string `json:"expected_agent_type"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("decode corpus: %v", err)
	}
	recognizer, err := NewEmbeddedAgentRecognizer(AgentRecognizerOptions{})
	if err != nil {
		t.Fatalf("new embedded recognizer: %v", err)
	}
	for _, item := range corpus {
		t.Run(item.Name, func(t *testing.T) {
			result := recognizer.Classify(AgentRecognitionInput{Comm: item.Comm})
			if result.Status != item.ExpectedStatus || result.AgentType != item.ExpectedAgentType {
				t.Fatalf("classify(%q) = status %q type %q, want %q %q", item.Comm, result.Status, result.AgentType, item.ExpectedStatus, item.ExpectedAgentType)
			}
			if result.GovernanceAction != "observe_only" || result.IdentityAssurance != "heuristic_process_metadata" {
				t.Fatalf("unsafe recognition boundary: %+v", result)
			}
		})
	}
}

func TestAgentRecognizerConfidenceRequiresAgreeingSignals(t *testing.T) {
	recognizer, err := NewEmbeddedAgentRecognizer(AgentRecognizerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	low := recognizer.Classify(AgentRecognitionInput{Comm: "claude"})
	if low.Confidence != AgentRecognitionConfidenceLow {
		t.Fatalf("comm-only confidence = %q, want low", low.Confidence)
	}
	medium := recognizer.Classify(AgentRecognitionInput{Comm: "claude", ExecutableBasename: "claude"})
	if medium.Confidence != AgentRecognitionConfidenceMedium || !reflect.DeepEqual(medium.MatchedSignalKinds, []string{"comm", "executable_basename"}) {
		t.Fatalf("agreeing signal result = %+v", medium)
	}
	ambiguous := recognizer.Classify(AgentRecognitionInput{Comm: "claude", ExecutableBasename: "codex"})
	if ambiguous.Status != AgentRecognitionStatusAmbiguous || ambiguous.AgentType != "" || len(ambiguous.MatchedRuleIDs) != 2 {
		t.Fatalf("conflicting signal result = %+v", ambiguous)
	}
}

func TestAgentRecognizerAggregatesMultipleRulesForOneAgentType(t *testing.T) {
	recognizer, err := NewAgentRecognizer("registry.v1", []AgentRecognitionRule{
		{RuleID: "rule.claude.comm", AgentType: "claude_code", ExactComms: []string{"claude"}},
		{RuleID: "rule.claude.alias", AgentType: "claude_code", ExactComms: []string{"claude-code"}},
	}, AgentRecognizerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	result := recognizer.Classify(AgentRecognitionInput{Comm: "claude", ExecutableBasename: "claude-code"})
	if result.Status != AgentRecognitionStatusRecognized || result.AgentType != "claude_code" {
		t.Fatalf("same-class rules produced conflicting result: %+v", result)
	}
	if result.Confidence != AgentRecognitionConfidenceMedium || !reflect.DeepEqual(result.MatchedRuleIDs, []string{"rule.claude.alias", "rule.claude.comm"}) {
		t.Fatalf("same-class evidence was not aggregated: %+v", result)
	}
}

func TestAgentRecognizerOverridesApplyBeforePrefilter(t *testing.T) {
	recognizer, err := NewEmbeddedAgentRecognizer(AgentRecognizerOptions{
		AllowAgentTypes: []string{"claude_code", "codex_cli"},
		DenyAgentTypes:  []string{"codex_cli"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := recognizer.PrefilterComms(), []string{"claude"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("prefilter comms = %v, want %v", got, want)
	}
	if got := recognizer.Classify(AgentRecognitionInput{Comm: "codex"}); got.Status != AgentRecognitionStatusUnknown {
		t.Fatalf("denied class result = %+v, want unknown", got)
	}
}

func TestAgentRegistryDigestIsOrderIndependent(t *testing.T) {
	rulesA := []AgentRecognitionRule{
		{RuleID: "rule.b", AgentType: "type_b", ExactComms: []string{"beta", "b"}},
		{RuleID: "rule.a", AgentType: "type_a", ExactComms: []string{"alpha"}},
	}
	rulesB := []AgentRecognitionRule{
		{RuleID: "rule.a", AgentType: "type_a", ExactComms: []string{"alpha"}},
		{RuleID: "rule.b", AgentType: "type_b", ExactComms: []string{"b", "beta"}},
	}
	a, err := NewAgentRecognizer("registry.v1", rulesA, AgentRecognizerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAgentRecognizer("registry.v1", rulesB, AgentRecognizerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if a.digest != b.digest || len(a.digest) != 64 {
		t.Fatalf("registry digests differ: %q != %q", a.digest, b.digest)
	}
}

func TestAgentRecognizerRejectsCollidingOrOversizedComms(t *testing.T) {
	tests := []struct {
		name  string
		rules []AgentRecognitionRule
	}{
		{
			name: "collision",
			rules: []AgentRecognitionRule{
				{RuleID: "rule.a", AgentType: "type_a", ExactComms: []string{"same"}},
				{RuleID: "rule.b", AgentType: "type_b", ExactComms: []string{"same"}},
			},
		},
		{name: "oversized", rules: []AgentRecognitionRule{{RuleID: "rule.a", AgentType: "type_a", ExactComms: []string{"sixteen-byte-name"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewAgentRecognizer("registry.v1", tt.rules, AgentRecognizerOptions{}); err == nil {
				t.Fatal("invalid registry unexpectedly accepted")
			}
		})
	}
}

func TestAgentRecognizerUsesCaseSensitiveKernelCommSemantics(t *testing.T) {
	recognizer, err := NewEmbeddedAgentRecognizer(AgentRecognizerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := recognizer.Classify(AgentRecognitionInput{Comm: "Codex"}); got.Status != AgentRecognitionStatusUnknown {
		t.Fatalf("case-mismatched comm result = %+v, want unknown", got)
	}
}

func TestAgentRecognizerRejectsRegistryLargerThanKernelPrefilter(t *testing.T) {
	rules := make([]AgentRecognitionRule, 0, 5)
	for index := 0; index < 5; index++ {
		comms := make([]string, 0, 13)
		for commIndex := 0; commIndex < 13; commIndex++ {
			comms = append(comms, fmt.Sprintf("agent-%02d-%02d", index, commIndex))
		}
		rules = append(rules, AgentRecognitionRule{
			RuleID:     fmt.Sprintf("rule.%d", index),
			AgentType:  fmt.Sprintf("type_%d", index),
			ExactComms: comms,
		})
	}
	if _, err := NewAgentRecognizer("registry.v1", rules, AgentRecognizerOptions{}); err == nil {
		t.Fatal("oversized prefilter registry unexpectedly accepted")
	}
}
