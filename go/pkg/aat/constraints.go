package aat

import (
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
)

// ConstraintHandler defines the extension point required by AAT §3.5.
type ConstraintHandler interface {
	Type() ConstraintType
	Check(value any, constraint *Constraint) error
	Subsumes(parent, child *Constraint) (bool, error)
}

// ConstraintRegistry is the minimal interface needed for core and extension
// constraint registration.
type ConstraintRegistry interface {
	Register(handler ConstraintHandler) error
	Lookup(constraintType ConstraintType) (ConstraintHandler, bool)
}

// Registry is the default in-memory registry implementation.
type Registry struct {
	handlers map[ConstraintType]ConstraintHandler
}

func NewRegistry() *Registry {
	return &Registry{handlers: make(map[ConstraintType]ConstraintHandler)}
}

func (r *Registry) Register(handler ConstraintHandler) error {
	if r == nil {
		return ErrNilConstraintHandler
	}
	if handler == nil {
		return ErrNilConstraintHandler
	}
	if _, exists := r.handlers[handler.Type()]; exists {
		return ErrDuplicateConstraintType
	}
	r.handlers[handler.Type()] = handler
	return nil
}

func (r *Registry) Lookup(constraintType ConstraintType) (ConstraintHandler, bool) {
	if r == nil {
		return nil, false
	}
	handler, ok := r.handlers[constraintType]
	return handler, ok
}

type coreConstraintHandler struct {
	typ      ConstraintType
	check    func(value any, constraint *Constraint) error
	subsumes func(parent, child *Constraint) (bool, error)
}

func (h coreConstraintHandler) Type() ConstraintType { return h.typ }

func (h coreConstraintHandler) Check(value any, constraint *Constraint) error {
	return h.check(value, constraint)
}

func (h coreConstraintHandler) Subsumes(parent, child *Constraint) (bool, error) {
	return h.subsumes(parent, child)
}

var DefaultConstraintRegistry *Registry

func newCoreConstraintRegistry() *Registry {
	registry := NewRegistry()
	handlers := []ConstraintHandler{
		coreConstraintHandler{typ: ConstraintTypeExact, check: CheckExact, subsumes: SubsumesExact},
		coreConstraintHandler{typ: ConstraintTypePattern, check: CheckPattern, subsumes: SubsumesPattern},
		coreConstraintHandler{typ: ConstraintTypeRange, check: CheckRange, subsumes: SubsumesRange},
		coreConstraintHandler{typ: ConstraintTypeOneOf, check: CheckOneOf, subsumes: SubsumesOneOf},
		coreConstraintHandler{typ: ConstraintTypeNotOneOf, check: CheckNotOneOf, subsumes: SubsumesNotOneOf},
		coreConstraintHandler{typ: ConstraintTypeContains, check: CheckContains, subsumes: SubsumesContains},
		coreConstraintHandler{typ: ConstraintTypeSubset, check: CheckSubset, subsumes: SubsumesSubset},
		coreConstraintHandler{typ: ConstraintTypeRegex, check: CheckRegex, subsumes: SubsumesRegex},
		coreConstraintHandler{typ: ConstraintTypeCEL, check: CheckCEL, subsumes: SubsumesCEL},
		coreConstraintHandler{typ: ConstraintTypeWildcard, check: CheckWildcard, subsumes: SubsumesWildcard},
		coreConstraintHandler{typ: ConstraintTypeAll, check: CheckAll, subsumes: SubsumesAll},
		coreConstraintHandler{typ: ConstraintTypeAny, check: CheckAny, subsumes: SubsumesAny},
		coreConstraintHandler{typ: ConstraintTypeNot, check: CheckNot, subsumes: SubsumesNot},
	}
	for _, handler := range handlers {
		if err := registry.Register(handler); err != nil {
			panic(err)
		}
	}
	return registry
}

func CheckConstraint(value any, constraint *Constraint) error {
	return _checkConstraint(value, constraint)
}

func SubsumesConstraint(parent, child *Constraint) (bool, error) {
	return _subsumesConstraint(parent, child)
}

var _checkConstraint func(value any, constraint *Constraint) error
var _subsumesConstraint func(parent, child *Constraint) (bool, error)

func init() {
	DefaultConstraintRegistry = newCoreConstraintRegistry()
	_checkConstraint = func(value any, constraint *Constraint) error {
		if constraint == nil {
			return ErrNilConstraint
		}
		handler, ok := DefaultConstraintRegistry.Lookup(constraint.ConstraintType)
		if !ok {
			return ErrUnknownConstraintType
		}
		return handler.Check(value, constraint)
	}
	_subsumesConstraint = func(parent, child *Constraint) (bool, error) {
		if parent == nil || child == nil {
			return false, ErrNilConstraint
		}
		handler, ok := DefaultConstraintRegistry.Lookup(child.ConstraintType)
		if !ok {
			return false, ErrUnknownConstraintType
		}
		return handler.Subsumes(parent, child)
	}
}

// ---------------------------------------------------------------------------
// Check predicates (AAT §3.4)
// ---------------------------------------------------------------------------

func CheckExact(value any, constraint *Constraint) error {
	if reflect.DeepEqual(value, constraint.Value) {
		return nil
	}
	return fmt.Errorf("exact constraint: %v != %v", value, constraint.Value)
}

func SubsumesExact(parent, child *Constraint) (bool, error) {
	switch parent.ConstraintType {
	case ConstraintTypeExact:
		return reflect.DeepEqual(parent.Value, child.Value), nil
	case ConstraintTypeWildcard:
		return true, nil
	case ConstraintTypeOneOf:
		return sliceContains(parent.Values, child.Value), nil
	default:
		return false, nil
	}
}

func CheckPattern(value any, constraint *Constraint) error {
	pattern, ok := constraint.Value.(string)
	if !ok {
		return fmt.Errorf("pattern constraint value must be a string, got %T", constraint.Value)
	}
	actual, ok := value.(string)
	if !ok {
		return fmt.Errorf("pattern constraint requires string value, got %T", value)
	}
	matched, err := filepath.Match(pattern, actual)
	if err != nil {
		return fmt.Errorf("pattern match error: %w", err)
	}
	if !matched {
		return fmt.Errorf("pattern constraint: %q does not match %q", actual, pattern)
	}
	return nil
}

func SubsumesPattern(parent, child *Constraint) (bool, error) {
	switch parent.ConstraintType {
	case ConstraintTypeWildcard:
		return true, nil
	case ConstraintTypePattern:
		// Parent pattern must match all strings child pattern matches.
		// Conservative: only allow identical patterns or prefix narrowing.
		pPat := parent.Value.(string)
		cPat := child.Value.(string)
		if pPat == cPat {
			return true, nil
		}
		if strings.HasSuffix(pPat, "*") && strings.HasPrefix(cPat, strings.TrimSuffix(pPat, "*")) {
			return true, nil
		}
		return false, nil
	case ConstraintTypeExact:
		pVal := parent.Value.(string)
		cPat := child.Value.(string)
		matched, _ := filepath.Match(cPat, pVal)
		return matched, nil
	default:
		return false, nil
	}
}

func CheckRange(value any, constraint *Constraint) error {
	n, err := toFloat64(value)
	if err != nil {
		return fmt.Errorf("range constraint: %w", err)
	}
	if constraint.Min != nil {
		if constraint.MinInclusive != nil && !*constraint.MinInclusive {
			if n <= *constraint.Min {
				return fmt.Errorf("range: %v <= min %v (exclusive)", n, *constraint.Min)
			}
		} else {
			if n < *constraint.Min {
				return fmt.Errorf("range: %v < min %v", n, *constraint.Min)
			}
		}
	}
	if constraint.Max != nil {
		if constraint.MaxInclusive != nil && !*constraint.MaxInclusive {
			if n >= *constraint.Max {
				return fmt.Errorf("range: %v >= max %v (exclusive)", n, *constraint.Max)
			}
		} else {
			if n > *constraint.Max {
				return fmt.Errorf("range: %v > max %v", n, *constraint.Max)
			}
		}
	}
	return nil
}

func SubsumesRange(parent, child *Constraint) (bool, error) {
	switch parent.ConstraintType {
	case ConstraintTypeWildcard:
		return true, nil
	case ConstraintTypeRange:
		return rangeNarrowerOrEqual(parent, child), nil
	case ConstraintTypeExact:
		n, err := toFloat64(parent.Value)
		if err != nil {
			return false, nil
		}
		if child.Min != nil && n < *child.Min {
			return false, nil
		}
		if child.Max != nil && n > *child.Max {
			return false, nil
		}
		return true, nil
	default:
		return false, nil
	}
}

func rangeNarrowerOrEqual(parent, child *Constraint) bool {
	minOK := true
	if parent.Min != nil {
		if child.Min == nil {
			return false
		}
		if *child.Min < *parent.Min {
			return false
		}
		if *child.Min == *parent.Min {
			if parent.MinInclusive != nil && *parent.MinInclusive {
				if child.MinInclusive == nil || *child.MinInclusive {
					// ok
				} else {
					minOK = false
				}
			}
		}
	}
	maxOK := true
	if parent.Max != nil {
		if child.Max == nil {
			return false
		}
		if *child.Max > *parent.Max {
			return false
		}
		if *child.Max == *parent.Max {
			if parent.MaxInclusive != nil && *parent.MaxInclusive {
				if child.MaxInclusive == nil || *child.MaxInclusive {
					// ok
				} else {
					maxOK = false
				}
			}
		}
	}
	return minOK && maxOK
}

func CheckOneOf(value any, constraint *Constraint) error {
	if sliceContains(constraint.Values, value) {
		return nil
	}
	return fmt.Errorf("one_of: %v not in %v", value, constraint.Values)
}

func SubsumesOneOf(parent, child *Constraint) (bool, error) {
	switch parent.ConstraintType {
	case ConstraintTypeWildcard:
		return true, nil
	case ConstraintTypeOneOf:
		return isSubsetAny(child.Values, parent.Values), nil
	case ConstraintTypeExact:
		return sliceContains(child.Values, parent.Value), nil
	default:
		return false, nil
	}
}

func CheckNotOneOf(value any, constraint *Constraint) error {
	if sliceContains(constraint.Excluded, value) {
		return fmt.Errorf("not_one_of: %v is excluded", value)
	}
	return nil
}

func SubsumesNotOneOf(parent, child *Constraint) (bool, error) {
	return isSupersetAny(child.Excluded, parent.Excluded), nil
}

func CheckContains(value any, constraint *Constraint) error {
	arr, ok := toSlice(value)
	if !ok {
		return fmt.Errorf("contains requires array, got %T", value)
	}
	for _, req := range constraint.Required {
		if !sliceContains(arr, req) {
			return fmt.Errorf("contains: missing required value %v", req)
		}
	}
	return nil
}

func SubsumesContains(parent, child *Constraint) (bool, error) {
	return isSupersetAny(child.Required, parent.Required), nil
}

func CheckSubset(value any, constraint *Constraint) error {
	arr, ok := toSlice(value)
	if !ok {
		return fmt.Errorf("subset requires array, got %T", value)
	}
	for _, elem := range arr {
		if !sliceContains(constraint.Allowed, elem) {
			return fmt.Errorf("subset: value %v not in allowed set", elem)
		}
	}
	return nil
}

func SubsumesSubset(parent, child *Constraint) (bool, error) {
	return isSubsetAny(child.Allowed, parent.Allowed), nil
}

var _regexCache = make(map[string]*regexp.Regexp)

func getCachedRegex(pattern string) (*regexp.Regexp, error) {
	if re, ok := _regexCache[pattern]; ok {
		return re, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	_regexCache[pattern] = re
	return re, nil
}

func CheckRegex(value any, constraint *Constraint) error {
	actual, ok := value.(string)
	if !ok {
		return fmt.Errorf("regex constraint requires string value, got %T", value)
	}
	re, err := getCachedRegex(constraint.Pattern)
	if err != nil {
		return fmt.Errorf("regex compile: %w", err)
	}
	if !re.MatchString(actual) {
		return fmt.Errorf("regex: %q does not match %q", actual, constraint.Pattern)
	}
	return nil
}

func SubsumesRegex(parent, child *Constraint) (bool, error) {
	switch parent.ConstraintType {
	case ConstraintTypeWildcard:
		return true, nil
	case ConstraintTypeRegex:
		return parent.Pattern == child.Pattern, nil
	case ConstraintTypeExact:
		actual, ok := parent.Value.(string)
		if !ok {
			return false, nil
		}
		re, err := getCachedRegex(child.Pattern)
		if err != nil {
			return false, nil
		}
		return re.MatchString(actual), nil
	default:
		return false, nil
	}
}

func CheckCEL(value any, constraint *Constraint) error {
	// CEL runtime integration deferred — stub returns not-implemented.
	return ErrConstraintCheckNotImplemented
}

func SubsumesCEL(parent, child *Constraint) (bool, error) {
	return false, ErrConstraintSubsumptionNotImplemented
}

func CheckWildcard(value any, constraint *Constraint) error {
	return nil
}

func SubsumesWildcard(parent, child *Constraint) (bool, error) {
	return parent.ConstraintType == ConstraintTypeWildcard, nil
}

func CheckAll(value any, constraint *Constraint) error {
	for _, child := range constraint.Children {
		if err := CheckConstraint(value, child); err != nil {
			return fmt.Errorf("all: %w", err)
		}
	}
	return nil
}

func SubsumesAll(parent, child *Constraint) (bool, error) {
	switch parent.ConstraintType {
	case ConstraintTypeWildcard:
		return true, nil
	case ConstraintTypeAll:
		// Each child clause must be subsumed by some parent clause.
		for _, cClause := range child.Children {
			found := false
			for _, pClause := range parent.Children {
				ok, err := SubsumesConstraint(pClause, cClause)
				if err != nil {
					return false, err
				}
				if ok {
					found = true
					break
				}
			}
			if !found {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, nil
	}
}

func CheckAny(value any, constraint *Constraint) error {
	for _, child := range constraint.Children {
		if err := CheckConstraint(value, child); err == nil {
			return nil
		}
	}
	return fmt.Errorf("any: no clause matched")
}

func SubsumesAny(parent, child *Constraint) (bool, error) {
	switch parent.ConstraintType {
	case ConstraintTypeWildcard:
		return true, nil
	case ConstraintTypeAny:
		if len(child.Children) == 0 {
			return false, nil
		}
		// Every derived clause must be subsumed by at least one parent clause.
		for _, cClause := range child.Children {
			found := false
			for _, pClause := range parent.Children {
				ok, err := SubsumesConstraint(pClause, cClause)
				if err != nil {
					return false, err
				}
				if ok {
					found = true
					break
				}
			}
			if !found {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, nil
	}
}

func CheckNot(value any, constraint *Constraint) error {
	if constraint.Inner == nil {
		return fmt.Errorf("not constraint requires inner clause")
	}
	if err := CheckConstraint(value, constraint.Inner); err != nil {
		return nil // negation succeeds when inner fails
	}
	return fmt.Errorf("not: inner constraint matched")
}

func SubsumesNot(parent, child *Constraint) (bool, error) {
	if parent.ConstraintType != ConstraintTypeNot || child.ConstraintType != ConstraintTypeNot {
		return false, nil
	}
	return SubsumesConstraint(parent.Inner, child.Inner)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func toFloat64(value any) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int32:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case json.Number:
		f, err := v.Float64()
		if err != nil {
			// Try int fallback
			i, ierr := v.Int64()
			if ierr != nil {
				return 0, err
			}
			return float64(i), nil
		}
		return f, nil
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", value)
	}
}

func toSlice(value any) ([]any, bool) {
	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return nil, false
	}
	result := make([]any, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		result[i] = rv.Index(i).Interface()
	}
	return result, true
}

func sliceContains(slice []any, value any) bool {
	for _, item := range slice {
		if reflect.DeepEqual(item, value) {
			return true
		}
	}
	return false
}

func isSubsetAny(child, parent []any) bool {
	for _, item := range child {
		if !sliceContains(parent, item) {
			return false
		}
	}
	return true
}

func isSupersetAny(child, parent []any) bool {
	for _, item := range parent {
		if !sliceContains(child, item) {
			return false
		}
	}
	return true
}

func floatPtr(v float64) *float64       { return &v }
func boolPtr(v bool) *bool              { return &v }
func intPtr(v int) *int                 { return &v }
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

const (
	MAX_TOKEN_SIZE       = 64 * 1024
	MAX_STACK_SIZE       = 128
	MAX_CONSTRAINT_DEPTH = 32
	MAX_DELEGATION_DEPTH = 10
	MAX_IAT_SKEW_S       = 300
	MAX_TOKEN_LIFETIME_S = 86400
)

var mathInf = math.Inf(1)
