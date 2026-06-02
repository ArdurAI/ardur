package policy

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
)

// CedarEngine implements PolicyEngine using the cedar-go SDK.
// It parses Cedar policy text, builds entity stores, and evaluates
// authorization requests per the Cedar language specification.
type CedarEngine struct {
	mu          sync.RWMutex
	closed      bool
	entities    cedar.EntityMap
	policyCache sync.Map // map[string]*cedar.PolicySet, keyed by policy hash
}

// NewCedarEngine creates a new Cedar policy engine instance.
func NewCedarEngine() *CedarEngine {
	return &CedarEngine{
		entities: make(cedar.EntityMap),
	}
}

// compile-time interface check
var _ PolicyEngine = (*CedarEngine)(nil)

// Compile parses Cedar policy text and returns a compiled policy with
// a deterministic hash suitable for credential binding.
func (e *CedarEngine) Compile(_ context.Context, policyText string) (*CompiledPolicy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		return nil, ErrEngineClosed
	}

	if policyText == "" {
		return nil, fmt.Errorf("%w: empty policy text", ErrPolicyParse)
	}

	ps, err := cedar.NewPolicySetFromBytes("vibap-policy.cedar", []byte(policyText))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPolicyParse, err)
	}

	// Extract policy IDs
	var ids []string
	for id := range ps.All() {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)

	// Generate canonical (deterministic) text for hashing
	canonical := string(ps.MarshalCedar())
	hash := ComputePolicyHash(canonical)

	cp := &CompiledPolicy{
		PolicyText:  canonical,
		Hash:        hash,
		PolicyCount: len(ids),
		PolicyIDs:   ids,
	}

	e.policyCache.Store(hash, ps)
	return cp, nil
}

// Evaluate runs an authorization request against a compiled policy set.
func (e *CedarEngine) Evaluate(_ context.Context, compiled *CompiledPolicy, entities []Entity, request AuthzRequest) (*AuthzResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		return nil, ErrEngineClosed
	}

	if compiled == nil {
		return nil, fmt.Errorf("%w: compiled policy is nil", ErrInvalidRequest)
	}

	start := time.Now()

	ps, err := e.getCachedPolicySet(compiled)
	if err != nil {
		return nil, fmt.Errorf("%w: loading compiled policy: %v", ErrEvaluation, err)
	}

	entityMap := e.buildEntityMap(entities)

	// Merge with pre-loaded entities (lock already held from top of function)
	for uid, ent := range e.entities {
		if _, exists := entityMap[uid]; !exists {
			entityMap[uid] = ent
		}
	}

	req := cedar.Request{
		Principal: cedar.NewEntityUID(cedar.EntityType(request.Principal.Type), cedar.String(request.Principal.ID)),
		Action:    cedar.NewEntityUID(cedar.EntityType(request.Action.Type), cedar.String(request.Action.ID)),
		Resource:  cedar.NewEntityUID(cedar.EntityType(request.Resource.Type), cedar.String(request.Resource.ID)),
		Context:   buildCedarRecord(request.Context),
	}

	decision, diag := cedar.Authorize(ps, entityMap, req)

	result := &AuthzResult{
		EvalTime: time.Since(start),
	}

	if decision {
		result.Decision = DecisionAllow
	} else {
		result.Decision = DecisionDeny
	}

	for _, reason := range diag.Reasons {
		result.Reasons = append(result.Reasons, string(reason.PolicyID))
	}
	for _, diagErr := range diag.Errors {
		result.Errors = append(result.Errors, fmt.Sprintf("policy %s: %s", diagErr.PolicyID, diagErr.Message))
	}

	return result, nil
}

// SetEntities loads entities into the engine's persistent entity store.
// These entities are available for all subsequent evaluations.
func (e *CedarEngine) SetEntities(entities []Entity) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrEngineClosed
	}

	e.entities = e.buildEntityMap(entities)
	return nil
}

// EngineName returns "cedar".
func (e *CedarEngine) EngineName() string {
	return "cedar"
}

// Close releases resources held by the engine.
func (e *CedarEngine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	e.entities = nil
	e.policyCache = sync.Map{}
	return nil
}

// getCachedPolicySet returns a cached PolicySet or parses a new one.
// Uses sync.Map for lock-free reads, avoiding re-parsing on every Evaluate call.
func (e *CedarEngine) getCachedPolicySet(compiled *CompiledPolicy) (*cedar.PolicySet, error) {
	if cached, ok := e.policyCache.Load(compiled.Hash); ok {
		return cached.(*cedar.PolicySet), nil
	}

	ps, err := cedar.NewPolicySetFromBytes("eval.cedar", []byte(compiled.PolicyText))
	if err != nil {
		return nil, err
	}
	e.policyCache.Store(compiled.Hash, ps)
	return ps, nil
}

// buildEntityMap converts VIBAP Entity types to Cedar EntityMap.
func (e *CedarEngine) buildEntityMap(entities []Entity) cedar.EntityMap {
	em := make(cedar.EntityMap, len(entities))
	for _, ent := range entities {
		uid := cedar.NewEntityUID(cedar.EntityType(ent.UID.Type), cedar.String(ent.UID.ID))

		var parents cedar.EntityUIDSet
		if len(ent.Parents) > 0 {
			parentUIDs := make([]cedar.EntityUID, len(ent.Parents))
			for i, p := range ent.Parents {
				parentUIDs[i] = cedar.NewEntityUID(cedar.EntityType(p.Type), cedar.String(p.ID))
			}
			parents = cedar.NewEntityUIDSet(parentUIDs...)
		} else {
			parents = cedar.NewEntityUIDSet()
		}

		em[uid] = cedar.Entity{
			UID:        uid,
			Parents:    parents,
			Attributes: buildCedarRecord(ent.Attributes),
		}
	}
	return em
}

// buildCedarRecord converts a Go map to a Cedar Record.
func buildCedarRecord(attrs map[string]any) cedar.Record {
	if len(attrs) == 0 {
		return cedar.NewRecord(cedar.RecordMap{})
	}

	rm := make(cedar.RecordMap, len(attrs))
	for k, v := range attrs {
		rm[cedar.String(k)] = toCedarValue(v)
	}
	return cedar.NewRecord(rm)
}

// toCedarValue converts a Go value to a Cedar Value.
func toCedarValue(v any) cedar.Value {
	switch val := v.(type) {
	case string:
		return cedar.String(val)
	case int:
		return cedar.Long(int64(val))
	case int64:
		return cedar.Long(val)
	case bool:
		return cedar.Boolean(val)
	case []string:
		vals := make([]cedar.Value, len(val))
		for i, s := range val {
			vals[i] = cedar.String(s)
		}
		return cedar.NewSet(vals...)
	case []any:
		vals := make([]cedar.Value, len(val))
		for i, item := range val {
			vals[i] = toCedarValue(item)
		}
		return cedar.NewSet(vals...)
	case map[string]any:
		return buildCedarRecord(val)
	default:
		return cedar.String(fmt.Sprintf("%v", v))
	}
}
