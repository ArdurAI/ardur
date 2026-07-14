package kernelcapture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	AgentRecognitionSchema           = "ardur.agent_recognition.v0.1"
	EmbeddedAgentRegistryVersion     = "ardur.embedded-agent-registry.2026-07-11.v2"
	AgentRecognitionStatusRecognized = "recognized"
	AgentRecognitionStatusUnknown    = "unknown"
	AgentRecognitionStatusAmbiguous  = "ambiguous"
	AgentRecognitionConfidenceLow    = "low"
	AgentRecognitionConfidenceMedium = "medium"
	AgentRecognitionConfidenceNone   = "none"
)

const (
	maxAgentRecognitionCommBytes               = 15
	maxAgentRecognitionExecutableBasenameBytes = 62
	maxAgentRecognitionRules                   = 64
	maxAgentRecognitionComms                   = 64
	maxAgentRecognitionExecutableBasenames     = 64
)

var agentRecognitionIdentifier = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// AgentRecognitionRule is one release-bound executable-name fingerprint.
// ExactComms are Linux task comm values and therefore must fit in 15 bytes.
type AgentRecognitionRule struct {
	RuleID                   string   `json:"rule_id"`
	AgentType                string   `json:"agent_type"`
	ExactComms               []string `json:"exact_comms,omitempty"`
	ExactExecutableBasenames []string `json:"exact_executable_basenames,omitempty"`
}

// AgentRecognizerOptions applies root/operator-owned class overrides before
// the in-kernel prefilter is populated. Deny takes precedence over allow.
type AgentRecognizerOptions struct {
	AllowAgentTypes []string
	DenyAgentTypes  []string
}

// AgentRecognitionInput contains bounded process metadata. No argv,
// environment, full path, or file content is accepted by this profile.
type AgentRecognitionInput struct {
	Comm               string
	ExecutableBasename string
}

// AgentRecognitionResult is heuristic candidate evidence, not binary identity
// and not authorization to attest or govern the observed process.
type AgentRecognitionResult struct {
	SchemaVersion      string   `json:"schema_version"`
	Status             string   `json:"status"`
	AgentType          string   `json:"agent_type,omitempty"`
	Confidence         string   `json:"confidence"`
	MatchedRuleIDs     []string `json:"matched_rule_ids,omitempty"`
	MatchedSignalKinds []string `json:"matched_signal_kinds,omitempty"`
	RegistryVersion    string   `json:"registry_version"`
	RegistrySHA256     string   `json:"registry_sha256"`
	IdentityAssurance  string   `json:"identity_assurance"`
	GovernanceAction   string   `json:"governance_action"`
}

// AgentRecognizer is immutable after construction and safe for concurrent use.
type AgentRecognizer struct {
	version                      string
	digest                       string
	rules                        []AgentRecognitionRule
	commIndex                    map[string]int
	executableBasenameIndex      map[string]int
	prefilterComms               []string
	prefilterExecutableBasenames []string
}

type agentRecognitionCandidate struct {
	ruleIDs     map[string]struct{}
	signalKinds map[string]struct{}
}

// NewEmbeddedAgentRecognizer returns the bounded registry shipped in the
// reviewed binary. The digest is integrity metadata, not an independent
// signature or software-provenance claim.
func NewEmbeddedAgentRecognizer(opts AgentRecognizerOptions) (*AgentRecognizer, error) {
	return NewAgentRecognizer(EmbeddedAgentRegistryVersion, []AgentRecognitionRule{
		{RuleID: "agent.claude_code.exact_name", AgentType: "claude_code", ExactComms: []string{"claude"}, ExactExecutableBasenames: []string{"claude"}},
		{RuleID: "agent.codex_cli.exact_name", AgentType: "codex_cli", ExactComms: []string{"codex"}, ExactExecutableBasenames: []string{"codex"}},
		{RuleID: "agent.gemini_cli.exact_name", AgentType: "gemini_cli", ExactComms: []string{"gemini"}, ExactExecutableBasenames: []string{"gemini"}},
		{RuleID: "agent.kimi_cli.exact_name", AgentType: "kimi_cli", ExactComms: []string{"kimi"}, ExactExecutableBasenames: []string{"kimi"}},
	}, opts)
}

// NewAgentRecognizer validates, canonicalizes, and hashes one registry.
func NewAgentRecognizer(version string, rules []AgentRecognitionRule, opts AgentRecognizerOptions) (*AgentRecognizer, error) {
	version = strings.TrimSpace(version)
	if !agentRecognitionIdentifier.MatchString(version) {
		return nil, fmt.Errorf("agent recognition registry version is invalid")
	}
	if len(rules) == 0 || len(rules) > maxAgentRecognitionRules {
		return nil, fmt.Errorf("agent recognition registry must contain 1..%d rules", maxAgentRecognitionRules)
	}

	allow, err := normalizedAgentTypeSet(opts.AllowAgentTypes)
	if err != nil {
		return nil, fmt.Errorf("agent recognition allow override: %w", err)
	}
	deny, err := normalizedAgentTypeSet(opts.DenyAgentTypes)
	if err != nil {
		return nil, fmt.Errorf("agent recognition deny override: %w", err)
	}

	canonical := make([]AgentRecognitionRule, len(rules))
	knownTypes := make(map[string]struct{}, len(rules))
	knownRuleIDs := make(map[string]struct{}, len(rules))
	allComms := make(map[string]string)
	allExecutableBasenames := make(map[string]string)
	for i, rule := range rules {
		rule.RuleID = strings.TrimSpace(rule.RuleID)
		rule.AgentType = strings.TrimSpace(rule.AgentType)
		if !agentRecognitionIdentifier.MatchString(rule.RuleID) || !agentRecognitionIdentifier.MatchString(rule.AgentType) {
			return nil, fmt.Errorf("agent recognition rule %d has an invalid id or agent type", i)
		}
		if _, exists := knownRuleIDs[rule.RuleID]; exists {
			return nil, fmt.Errorf("agent recognition rule id %q is duplicated", rule.RuleID)
		}
		knownRuleIDs[rule.RuleID] = struct{}{}
		knownTypes[rule.AgentType] = struct{}{}
		if len(rule.ExactComms) > 16 || len(rule.ExactExecutableBasenames) > 16 {
			return nil, fmt.Errorf("agent recognition rule %q exceeds 16 names for one signal", rule.RuleID)
		}
		if len(rule.ExactComms) == 0 && len(rule.ExactExecutableBasenames) == 0 {
			return nil, fmt.Errorf("agent recognition rule %q must contain at least one exact name", rule.RuleID)
		}
		comms := make([]string, 0, len(rule.ExactComms))
		seen := make(map[string]struct{}, len(rule.ExactComms))
		for _, raw := range rule.ExactComms {
			comm, ok := normalizeAgentComm(raw)
			if !ok {
				return nil, fmt.Errorf("agent recognition rule %q contains an invalid comm", rule.RuleID)
			}
			if _, exists := seen[comm]; exists {
				continue
			}
			if owner, exists := allComms[comm]; exists {
				return nil, fmt.Errorf("agent recognition comm %q is shared by rules %q and %q", comm, owner, rule.RuleID)
			}
			seen[comm] = struct{}{}
			allComms[comm] = rule.RuleID
			comms = append(comms, comm)
		}
		sort.Strings(comms)
		rule.ExactComms = comms

		basenames := make([]string, 0, len(rule.ExactExecutableBasenames))
		seenBasenames := make(map[string]struct{}, len(rule.ExactExecutableBasenames))
		for _, raw := range rule.ExactExecutableBasenames {
			basename, ok := normalizeAgentExecutableBasename(raw)
			if !ok {
				return nil, fmt.Errorf("agent recognition rule %q contains an invalid executable basename", rule.RuleID)
			}
			if _, exists := seenBasenames[basename]; exists {
				continue
			}
			if owner, exists := allExecutableBasenames[basename]; exists {
				return nil, fmt.Errorf("agent recognition executable basename %q is shared by rules %q and %q", basename, owner, rule.RuleID)
			}
			seenBasenames[basename] = struct{}{}
			allExecutableBasenames[basename] = rule.RuleID
			basenames = append(basenames, basename)
		}
		sort.Strings(basenames)
		rule.ExactExecutableBasenames = basenames
		canonical[i] = rule
	}
	if len(allComms) > maxAgentRecognitionComms {
		return nil, fmt.Errorf("agent recognition registry contains %d exact comms, maximum is %d", len(allComms), maxAgentRecognitionComms)
	}
	if len(allExecutableBasenames) > maxAgentRecognitionExecutableBasenames {
		return nil, fmt.Errorf("agent recognition registry contains %d exact executable basenames, maximum is %d", len(allExecutableBasenames), maxAgentRecognitionExecutableBasenames)
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].RuleID < canonical[j].RuleID })

	for agentType := range allow {
		if _, ok := knownTypes[agentType]; !ok {
			return nil, fmt.Errorf("unknown allowed agent type %q", agentType)
		}
	}
	for agentType := range deny {
		if _, ok := knownTypes[agentType]; !ok {
			return nil, fmt.Errorf("unknown denied agent type %q", agentType)
		}
	}

	digestInput, err := json.Marshal(struct {
		Version string                 `json:"version"`
		Rules   []AgentRecognitionRule `json:"rules"`
	}{Version: version, Rules: canonical})
	if err != nil {
		return nil, fmt.Errorf("marshal canonical agent recognition registry: %w", err)
	}
	digestBytes := sha256.Sum256(digestInput)

	activeRules := make([]AgentRecognitionRule, 0, len(canonical))
	commIndex := make(map[string]int)
	executableBasenameIndex := make(map[string]int)
	prefilterComms := make([]string, 0, len(allComms))
	prefilterExecutableBasenames := make([]string, 0, len(allExecutableBasenames))
	for _, rule := range canonical {
		if _, denied := deny[rule.AgentType]; denied {
			continue
		}
		if len(allow) > 0 {
			if _, allowed := allow[rule.AgentType]; !allowed {
				continue
			}
		}
		index := len(activeRules)
		activeRules = append(activeRules, rule)
		for _, comm := range rule.ExactComms {
			commIndex[comm] = index
			prefilterComms = append(prefilterComms, comm)
		}
		for _, basename := range rule.ExactExecutableBasenames {
			executableBasenameIndex[basename] = index
			prefilterExecutableBasenames = append(prefilterExecutableBasenames, basename)
		}
	}
	sort.Strings(prefilterComms)
	sort.Strings(prefilterExecutableBasenames)
	return &AgentRecognizer{
		version:                      version,
		digest:                       hex.EncodeToString(digestBytes[:]),
		rules:                        activeRules,
		commIndex:                    commIndex,
		executableBasenameIndex:      executableBasenameIndex,
		prefilterComms:               prefilterComms,
		prefilterExecutableBasenames: prefilterExecutableBasenames,
	}, nil
}

// PrefilterExecutableBasenames returns a defensive copy suitable for the
// bounded Linux successful-exec filename map.
func (r *AgentRecognizer) PrefilterExecutableBasenames() []string {
	if r == nil {
		return nil
	}
	return append([]string(nil), r.prefilterExecutableBasenames...)
}

// PrefilterComms returns a defensive copy suitable for the Linux BPF map.
func (r *AgentRecognizer) PrefilterComms() []string {
	if r == nil {
		return nil
	}
	return append([]string(nil), r.prefilterComms...)
}

// AgentTypes returns the active agent classes after allow/deny overrides.
// The defensive copy is sorted so startup validation and diagnostics are
// deterministic.
func (r *AgentRecognizer) AgentTypes() []string {
	if r == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(r.rules))
	for _, rule := range r.rules {
		seen[rule.AgentType] = struct{}{}
	}
	types := make([]string, 0, len(seen))
	for agentType := range seen {
		types = append(types, agentType)
	}
	sort.Strings(types)
	return types
}

// Classify matches bounded names. Exact process names remain low-confidence
// even when both fields agree because one executable can control both values.
func (r *AgentRecognizer) Classify(input AgentRecognitionInput) AgentRecognitionResult {
	result := AgentRecognitionResult{
		SchemaVersion:     AgentRecognitionSchema,
		Status:            AgentRecognitionStatusUnknown,
		Confidence:        AgentRecognitionConfidenceNone,
		IdentityAssurance: "heuristic_process_metadata",
		GovernanceAction:  "observe_only",
	}
	if r == nil {
		result.RegistryVersion = "unavailable"
		return result
	}
	result.RegistryVersion = r.version
	result.RegistrySHA256 = r.digest

	candidates := make(map[string]*agentRecognitionCandidate)
	r.matchSignal(candidates, r.commIndex, normalizeAgentComm, "comm", input.Comm)
	r.matchSignal(candidates, r.executableBasenameIndex, normalizeAgentExecutableBasename, "executable_basename", input.ExecutableBasename)
	if len(candidates) == 0 {
		return result
	}

	agentTypes := make([]string, 0, len(candidates))
	for agentType, candidate := range candidates {
		agentTypes = append(agentTypes, agentType)
		for ruleID := range candidate.ruleIDs {
			result.MatchedRuleIDs = append(result.MatchedRuleIDs, ruleID)
		}
	}
	sort.Strings(agentTypes)
	sort.Strings(result.MatchedRuleIDs)
	if len(agentTypes) != 1 {
		result.Status = AgentRecognitionStatusAmbiguous
		result.Confidence = AgentRecognitionConfidenceNone
		return result
	}

	candidate := candidates[agentTypes[0]]
	result.Status = AgentRecognitionStatusRecognized
	result.AgentType = agentTypes[0]
	for kind := range candidate.signalKinds {
		result.MatchedSignalKinds = append(result.MatchedSignalKinds, kind)
	}
	sort.Strings(result.MatchedSignalKinds)
	result.Confidence = AgentRecognitionConfidenceLow
	return result
}

func (r *AgentRecognizer) matchSignal(candidates map[string]*agentRecognitionCandidate, indexByName map[string]int, normalize func(string) (string, bool), kind, raw string) {
	name, ok := normalize(raw)
	if !ok {
		return
	}
	index, ok := indexByName[name]
	if !ok {
		return
	}
	rule := r.rules[index]
	candidate := candidates[rule.AgentType]
	if candidate == nil {
		candidate = &agentRecognitionCandidate{
			ruleIDs:     make(map[string]struct{}),
			signalKinds: make(map[string]struct{}),
		}
		candidates[rule.AgentType] = candidate
	}
	candidate.ruleIDs[rule.RuleID] = struct{}{}
	candidate.signalKinds[kind] = struct{}{}
}

func normalizeAgentComm(raw string) (string, bool) {
	return normalizeAgentExecutableName(raw, maxAgentRecognitionCommBytes)
}

func normalizeAgentExecutableBasename(raw string) (string, bool) {
	return normalizeAgentExecutableName(raw, maxAgentRecognitionExecutableBasenameBytes)
}

func normalizeAgentExecutableName(raw string, maxBytes int) (string, bool) {
	name := strings.TrimSpace(raw)
	if name == "" || len(name) > maxBytes || strings.ContainsAny(name, "/\\\x00") {
		return "", false
	}
	for _, ch := range name {
		if ch < 0x21 || ch > 0x7e {
			return "", false
		}
	}
	return name, true
}

func normalizedAgentTypeSet(values []string) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !agentRecognitionIdentifier.MatchString(value) {
			return nil, fmt.Errorf("invalid agent type %q", value)
		}
		result[value] = struct{}{}
	}
	return result, nil
}
