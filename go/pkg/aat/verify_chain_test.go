package aat

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

func publicKeyToJWK(pub ed25519.PublicKey) jose.JSONWebKey {
	return jose.JSONWebKey{Key: pub, Algorithm: "EdDSA"}
}

func privateKeyToJWK(priv ed25519.PrivateKey) jose.JSONWebKey {
	return jose.JSONWebKey{Key: priv, Algorithm: "EdDSA"}
}

func simpleAuthorization(tools ToolMap) []AuthorizationDetail {
	return []AuthorizationDetail{
		{Type: AuthorizationDetailType, Tools: tools},
	}
}

func wildcardToolMap(toolName string) ToolMap {
	return ToolMap{toolName: ArgumentConstraintMap{}}
}

// ---------------------------------------------------------------------------
// Constraint Check Tests
// ---------------------------------------------------------------------------

func TestCheckExact(t *testing.T) {
	c := &Constraint{ConstraintType: ConstraintTypeExact}
	c.Value = "hello"
	if err := CheckExact("hello", c); err != nil {
		t.Fatalf("CheckExact failed: %v", err)
	}
	if err := CheckExact("world", c); err == nil {
		t.Fatal("CheckExact should fail for mismatched value")
	}
}

func TestCheckWildcard(t *testing.T) {
	if err := CheckWildcard("anything", &Constraint{ConstraintType: ConstraintTypeWildcard}); err != nil {
		t.Fatalf("CheckWildcard should always pass: %v", err)
	}
}

func TestCheckOneOf(t *testing.T) {
	c := &Constraint{ConstraintType: ConstraintTypeOneOf, Values: []any{"a", "b", "c"}}
	if err := CheckOneOf("b", c); err != nil {
		t.Fatalf("CheckOneOf failed: %v", err)
	}
	if err := CheckOneOf("z", c); err == nil {
		t.Fatal("CheckOneOf should fail for value not in set")
	}
}

func TestCheckNotOneOf(t *testing.T) {
	c := &Constraint{ConstraintType: ConstraintTypeNotOneOf, Excluded: []any{"x", "y"}}
	if err := CheckNotOneOf("a", c); err != nil {
		t.Fatalf("CheckNotOneOf failed: %v", err)
	}
	if err := CheckNotOneOf("x", c); err == nil {
		t.Fatal("CheckNotOneOf should fail for excluded value")
	}
}

func TestCheckPattern(t *testing.T) {
	c := &Constraint{ConstraintType: ConstraintTypePattern, Value: "*.go"}
	if err := CheckPattern("main.go", c); err != nil {
		t.Fatalf("CheckPattern failed: %v", err)
	}
	if err := CheckPattern("main.py", c); err == nil {
		t.Fatal("CheckPattern should fail for non-matching pattern")
	}
}

func TestCheckRange(t *testing.T) {
	min := 10.0
	max := 100.0
	c := &Constraint{ConstraintType: ConstraintTypeRange, Min: &min, Max: &max}
	if err := CheckRange(float64(50), c); err != nil {
		t.Fatalf("CheckRange failed: %v", err)
	}
	if err := CheckRange(float64(5), c); err == nil {
		t.Fatal("CheckRange should fail for value below min")
	}
	if err := CheckRange(float64(200), c); err == nil {
		t.Fatal("CheckRange should fail for value above max")
	}
}

func TestCheckRangeExclusive(t *testing.T) {
	min := 10.0
	f := false
	c := &Constraint{ConstraintType: ConstraintTypeRange, Min: &min, MinInclusive: &f}
	if err := CheckRange(float64(10), c); err == nil {
		t.Fatal("CheckRange should reject exact min when exclusive")
	}
	if err := CheckRange(float64(11), c); err != nil {
		t.Fatalf("CheckRange should accept value above exclusive min: %v", err)
	}
}

func TestCheckContains(t *testing.T) {
	c := &Constraint{ConstraintType: ConstraintTypeContains, Required: []any{"a", "b"}}
	if err := CheckContains([]any{"a", "b", "c"}, c); err != nil {
		t.Fatalf("CheckContains failed: %v", err)
	}
	if err := CheckContains([]any{"a", "c"}, c); err == nil {
		t.Fatal("CheckContains should fail when missing required element")
	}
}

func TestCheckSubset(t *testing.T) {
	c := &Constraint{ConstraintType: ConstraintTypeSubset, Allowed: []any{"a", "b", "c"}}
	if err := CheckSubset([]any{"a", "b"}, c); err != nil {
		t.Fatalf("CheckSubset failed: %v", err)
	}
	if err := CheckSubset([]any{"a", "z"}, c); err == nil {
		t.Fatal("CheckSubset should fail when element not in allowed set")
	}
}

func TestCheckRegex(t *testing.T) {
	c := &Constraint{ConstraintType: ConstraintTypeRegex, Pattern: `^\d{3}-\d{2}-\d{4}$`}
	if err := CheckRegex("123-45-6789", c); err != nil {
		t.Fatalf("CheckRegex failed: %v", err)
	}
	if err := CheckRegex("abc", c); err == nil {
		t.Fatal("CheckRegex should fail for non-matching string")
	}
}

func TestCheckAll(t *testing.T) {
	c := &Constraint{
		ConstraintType: ConstraintTypeAll,
		Children: []*Constraint{
			{ConstraintType: ConstraintTypeExact, Value: "hello"},
		},
	}
	if err := CheckAll("hello", c); err != nil {
		t.Fatalf("CheckAll failed: %v", err)
	}
}

func TestCheckAny(t *testing.T) {
	c := &Constraint{
		ConstraintType: ConstraintTypeAny,
		Children: []*Constraint{
			{ConstraintType: ConstraintTypeExact, Value: "a"},
			{ConstraintType: ConstraintTypeExact, Value: "b"},
		},
	}
	if err := CheckAny("b", c); err != nil {
		t.Fatalf("CheckAny failed: %v", err)
	}
	if err := CheckAny("z", c); err == nil {
		t.Fatal("CheckAny should fail when no clause matches")
	}
}

func TestCheckNot(t *testing.T) {
	c := &Constraint{
		ConstraintType: ConstraintTypeNot,
		Inner:          &Constraint{ConstraintType: ConstraintTypeExact, Value: "forbidden"},
	}
	if err := CheckNot("allowed", c); err != nil {
		t.Fatalf("CheckNot failed: %v", err)
	}
	if err := CheckNot("forbidden", c); err == nil {
		t.Fatal("CheckNot should fail when inner matches")
	}
}

func TestCheckCELStub(t *testing.T) {
	c := &Constraint{ConstraintType: ConstraintTypeCEL, Expression: "true"}
	if err := CheckCEL("any", c); !errors.Is(err, ErrConstraintCheckNotImplemented) {
		t.Fatalf("CheckCEL error = %v, want ErrConstraintCheckNotImplemented", err)
	}
}

// ---------------------------------------------------------------------------
// Constraint Subsumption Tests
// ---------------------------------------------------------------------------

func TestSubsumesWildcard(t *testing.T) {
	parent := &Constraint{ConstraintType: ConstraintTypeWildcard}
	child := &Constraint{ConstraintType: ConstraintTypeExact, Value: "x"}
	ok, err := SubsumesWildcard(parent, child)
	if err != nil || !ok {
		t.Fatalf("Wildcard should subsume any child constraint")
	}
}

func TestSubsumesExactToExact(t *testing.T) {
	parent := &Constraint{ConstraintType: ConstraintTypeExact, Value: "x"}
	child := &Constraint{ConstraintType: ConstraintTypeExact, Value: "x"}
	ok, err := SubsumesExact(parent, child)
	if err != nil || !ok {
		t.Fatalf("Identical exact constraints should subsume")
	}
	child2 := &Constraint{ConstraintType: ConstraintTypeExact, Value: "y"}
	ok, err = SubsumesExact(parent, child2)
	if err != nil || ok {
		t.Fatal("Different exact constraints should not subsume")
	}
}

func TestSubsumesOneOf(t *testing.T) {
	parent := &Constraint{ConstraintType: ConstraintTypeOneOf, Values: []any{"a", "b", "c"}}
	child := &Constraint{ConstraintType: ConstraintTypeOneOf, Values: []any{"a", "b"}}
	ok, err := SubsumesOneOf(parent, child)
	if err != nil || !ok {
		t.Fatalf("Parent one_of should subsume subset child")
	}
	child2 := &Constraint{ConstraintType: ConstraintTypeOneOf, Values: []any{"a", "z"}}
	ok, err = SubsumesOneOf(parent, child2)
	if err != nil || ok {
		t.Fatal("Parent one_of should not subsume child with extra value")
	}
}

func TestSubsumesRange(t *testing.T) {
	min10 := 10.0
	max100 := 100.0
	min20 := 20.0
	max50 := 50.0
	parent := &Constraint{ConstraintType: ConstraintTypeRange, Min: &min10, Max: &max100}
	child := &Constraint{ConstraintType: ConstraintTypeRange, Min: &min20, Max: &max50}
	ok, err := SubsumesRange(parent, child)
	if err != nil || !ok {
		t.Fatalf("Parent range should subsume narrower child")
	}

	min0 := 0.0
	child2 := &Constraint{ConstraintType: ConstraintTypeRange, Min: &min0, Max: &max50}
	ok, err = SubsumesRange(parent, child2)
	if err != nil || ok {
		t.Fatal("Parent range should not subsume child with lower min")
	}
}

func TestSubsumesNotOneOf(t *testing.T) {
	parent := &Constraint{ConstraintType: ConstraintTypeNotOneOf, Excluded: []any{"a"}}
	child := &Constraint{ConstraintType: ConstraintTypeNotOneOf, Excluded: []any{"a", "b"}}
	ok, err := SubsumesNotOneOf(parent, child)
	if err != nil || !ok {
		t.Fatalf("Child with more exclusions should be subsumed by parent with fewer")
	}
	child2 := &Constraint{ConstraintType: ConstraintTypeNotOneOf, Excluded: []any{}}
	ok, err = SubsumesNotOneOf(parent, child2)
	if err != nil || ok {
		t.Fatal("Child with fewer exclusions should not be subsumed")
	}
}

// ---------------------------------------------------------------------------
// CanonicalizeHTA Tests
// ---------------------------------------------------------------------------

func TestCanonicalizeHTADeterministic(t *testing.T) {
	hta := map[string]interface{}{
		"tool": "read_file",
		"args": map[string]interface{}{"path": "/tmp/test.txt"},
	}
	first, err := CanonicalizeHTA(hta)
	if err != nil {
		t.Fatalf("CanonicalizeHTA failed: %v", err)
	}
	second, err := CanonicalizeHTA(hta)
	if err != nil {
		t.Fatalf("second CanonicalizeHTA failed: %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("CanonicalizeHTA is not deterministic")
	}
}

func TestCanonicalizeHTAKeyOrder(t *testing.T) {
	hta := map[string]interface{}{
		"args": map[string]interface{}{"path": "/tmp/test.txt"},
		"tool": "read_file",
	}
	result, err := CanonicalizeHTA(hta)
	if err != nil {
		t.Fatalf("CanonicalizeHTA failed: %v", err)
	}
	// Keys should be sorted: "args" before "tool"
	if !strings.Contains(string(result), `"args"`) || !strings.Contains(string(result), `"tool"`) {
		t.Fatalf("CanonicalizeHTA missing expected keys: %s", result)
	}
	argsIdx := strings.Index(string(result), `"args"`)
	toolIdx := strings.Index(string(result), `"tool"`)
	if argsIdx > toolIdx {
		t.Fatal("CanonicalizeHTA keys not sorted alphabetically")
	}
}

// ---------------------------------------------------------------------------
// IssueRoot / DeriveChild Tests
// ---------------------------------------------------------------------------

func TestIssueRootSuccess(t *testing.T) {
	pub, priv := newKeyPair()
	now := time.Now()
	token, err := IssueRoot(IssueRootOpts{
		JWTID:         "root-jti-1",
		Issuer:        "https://as.example.com",
		Now:           now,
		ExpiresAt:     now.Add(1 * time.Hour),
		TokenType:     AATTypeDelegation,
		MaxDelegationDepth: 3,
		HolderJWK:     publicKeyToJWK(pub),
		Authorization: simpleAuthorization(wildcardToolMap("read_file")),
		Signer:        priv,
	})
	if err != nil {
		t.Fatalf("IssueRoot failed: %v", err)
	}
	if !token.IsRoot() {
		t.Fatal("Token should be root")
	}
	if token.DelegationDepth != 0 {
		t.Fatalf("Root depth = %d, want 0", token.DelegationDepth)
	}
	if token.TokenType != AATTypeDelegation {
		t.Fatalf("TokenType = %q, want delegation", token.TokenType)
	}
	if token.Compact == "" {
		t.Fatal("Compact JWT is empty")
	}
}

func TestIssueRootValidationErrors(t *testing.T) {
	pub, priv := newKeyPair()
	now := time.Now()

	tests := []struct {
		name string
		opts IssueRootOpts
	}{
		{"missing JWTID", IssueRootOpts{Issuer: "iss", ExpiresAt: now.Add(time.Hour), TokenType: AATTypeDelegation, HolderJWK: publicKeyToJWK(pub), Authorization: simpleAuthorization(wildcardToolMap("t")), Signer: priv}},
		{"missing Issuer", IssueRootOpts{JWTID: "jti", ExpiresAt: now.Add(time.Hour), TokenType: AATTypeDelegation, HolderJWK: publicKeyToJWK(pub), Authorization: simpleAuthorization(wildcardToolMap("t")), Signer: priv}},
		{"missing ExpiresAt", IssueRootOpts{JWTID: "jti", Issuer: "iss", TokenType: AATTypeDelegation, HolderJWK: publicKeyToJWK(pub), Authorization: simpleAuthorization(wildcardToolMap("t")), Signer: priv}},
		{"invalid TokenType", IssueRootOpts{JWTID: "jti", Issuer: "iss", ExpiresAt: now.Add(time.Hour), TokenType: "bad", HolderJWK: publicKeyToJWK(pub), Authorization: simpleAuthorization(wildcardToolMap("t")), Signer: priv}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, err := IssueRoot(tt.opts)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tok != nil {
				t.Fatal("expected nil token on error")
			}
		})
	}
}

func TestDeriveChildSuccess(t *testing.T) {
	rootPub, rootPriv := newKeyPair()
	childPub, childPriv := newKeyPair()
	now := time.Now()

	root, err := IssueRoot(IssueRootOpts{
		JWTID:         "root-jti-2",
		Issuer:        "https://as.example.com",
		Now:           now,
		ExpiresAt:     now.Add(2 * time.Hour),
		TokenType:     AATTypeDelegation,
		MaxDelegationDepth: 3,
		HolderJWK:     publicKeyToJWK(rootPub),
		Authorization: simpleAuthorization(wildcardToolMap("read_file")),
		Signer:        rootPriv,
	})
	if err != nil {
		t.Fatalf("IssueRoot failed: %v", err)
	}

	// Child signed by root's holder key, so iss = root.cnf.jwk thumbprint
	rootJWK := publicKeyToJWK(rootPub)
	rootThumb, _ := rootJWK.Thumbprint(crypto.SHA256)
	childIssuer := fmt.Sprintf("urn:ietf:params:oauth:jwk-thumbprint:sha-256:%s", base64.RawURLEncoding.EncodeToString(rootThumb))

	child, err := DeriveChild(root, DeriveOpts{
		JWTID:              "child-jti-1",
		Issuer:             childIssuer,
		Now:                now.Add(1 * time.Minute),
		ExpiresAt:          now.Add(1 * time.Hour),
		TokenType:          AATTypeDelegation,
		MaxDelegationDepth: 2,
		HolderJWK:          publicKeyToJWK(childPub),
		Authorization:      simpleAuthorization(wildcardToolMap("read_file")),
		Signer:             childPriv,
	})
	if err != nil {
		t.Fatalf("DeriveChild failed: %v", err)
	}
	if child.DelegationDepth != 1 {
		t.Fatalf("Child depth = %d, want 1", child.DelegationDepth)
	}
	if child.ParentHash == "" {
		t.Fatal("Child par_hash is empty")
	}
}

func TestDeriveChildDepthExceedsParentMax(t *testing.T) {
	rootPub, rootPriv := newKeyPair()
	childPub, childPriv := newKeyPair()
	now := time.Now()

	root, err := IssueRoot(IssueRootOpts{
		JWTID:         "root-jti-3",
		Issuer:        "https://as.example.com",
		Now:           now,
		ExpiresAt:     now.Add(2 * time.Hour),
		TokenType:     AATTypeDelegation,
		MaxDelegationDepth: 0, // no further delegation allowed
		HolderJWK:     publicKeyToJWK(rootPub),
		Authorization: simpleAuthorization(wildcardToolMap("read_file")),
		Signer:        rootPriv,
	})
	if err != nil {
		t.Fatalf("IssueRoot failed: %v", err)
	}

	_, err = DeriveChild(root, DeriveOpts{
		JWTID:              "child-jti-2",
		Now:                now.Add(1 * time.Minute),
		ExpiresAt:          now.Add(1 * time.Hour),
		TokenType:          AATTypeDelegation,
		MaxDelegationDepth: 0,
		HolderJWK:          publicKeyToJWK(childPub),
		Authorization:      simpleAuthorization(wildcardToolMap("read_file")),
		Signer:             childPriv,
	})
	if err == nil {
		t.Fatal("DeriveChild should fail when depth exceeds parent max")
	}
}

// ---------------------------------------------------------------------------
// PoP JWT Tests
// ---------------------------------------------------------------------------

func TestBuildAndVerifyPoPJWT(t *testing.T) {
	leafPub, leafPriv := newKeyPair()
	now := time.Now()

	leaf := &Token{
		JWTID:        "leaf-jti-1",
		TokenType:    AATTypeExecution,
		Confirmation: &ConfirmationKey{JWK: publicKeyToJWK(leafPub)},
		Authorization: simpleAuthorization(wildcardToolMap("read_file")),
	}

	popJWT, err := BuildPoPJWT(BuildPoPOpts{
		JWTID:  "pop-jti-1",
		Now:    now,
		Leaf:   leaf,
		Tool:   "read_file",
		Args:   map[string]interface{}{"path": "/tmp/test.txt"},
		Signer: leafPriv,
	})
	if err != nil {
		t.Fatalf("BuildPoPJWT failed: %v", err)
	}
	if popJWT == "" {
		t.Fatal("BuildPoPJWT returned empty string")
	}

	verified, err := VerifyPoPJWT(leaf, "read_file", map[string]interface{}{"path": "/tmp/test.txt"}, popJWT, VerifyPoPOpts{Now: now})
	if err != nil {
		t.Fatalf("VerifyPoPJWT failed: %v", err)
	}
	if verified.AATID != leaf.JWTID {
		t.Fatalf("AATID = %q, want %q", verified.AATID, leaf.JWTID)
	}
	if verified.AATTool != "read_file" {
		t.Fatalf("AATTool = %q, want read_file", verified.AATTool)
	}
}

func TestVerifyPoPJWTWrongKey(t *testing.T) {
	leafPub, _ := newKeyPair()
	_, otherPriv := newKeyPair()
	now := time.Now()

	leaf := &Token{
		JWTID:        "leaf-jti-2",
		Confirmation: &ConfirmationKey{JWK: publicKeyToJWK(leafPub)},
		Authorization: simpleAuthorization(wildcardToolMap("read_file")),
	}

	// Sign with wrong key
	popJWT, err := BuildPoPJWT(BuildPoPOpts{
		JWTID:  "pop-jti-2",
		Now:    now,
		Leaf:   leaf,
		Tool:   "read_file",
		Args:   map[string]interface{}{"path": "/tmp/test.txt"},
		Signer: otherPriv, // wrong key!
	})
	if err != nil {
		t.Fatalf("BuildPoPJWT failed: %v", err)
	}

	_, err = VerifyPoPJWT(leaf, "read_file", map[string]interface{}{"path": "/tmp/test.txt"}, popJWT, VerifyPoPOpts{Now: now})
	if err == nil {
		t.Fatal("VerifyPoPJWT should fail when signed with wrong key")
	}
	if !errors.Is(err, ErrDenyStep7APoPSignature) {
		t.Fatalf("VerifyPoPJWT error = %v, want ErrDenyStep7APoPSignature", err)
	}
}

func TestVerifyPoPJWTHTAMismatch(t *testing.T) {
	leafPub, leafPriv := newKeyPair()
	now := time.Now()

	leaf := &Token{
		JWTID:        "leaf-jti-3",
		Confirmation: &ConfirmationKey{JWK: publicKeyToJWK(leafPub)},
		Authorization: simpleAuthorization(wildcardToolMap("read_file")),
	}

	popJWT, err := BuildPoPJWT(BuildPoPOpts{
		JWTID:  "pop-jti-3",
		Now:    now,
		Leaf:   leaf,
		Tool:   "read_file",
		Args:   map[string]interface{}{"path": "/tmp/good.txt"},
		Signer: leafPriv,
	})
	if err != nil {
		t.Fatalf("BuildPoPJWT failed: %v", err)
	}

	// Try to verify with different args
	_, err = VerifyPoPJWT(leaf, "read_file", map[string]interface{}{"path": "/tmp/evil.txt"}, popJWT, VerifyPoPOpts{Now: now})
	if err == nil {
		t.Fatal("VerifyPoPJWT should fail when HTA doesn't match")
	}
}

// ---------------------------------------------------------------------------
// VerifyChain Tests
// ---------------------------------------------------------------------------

func TestVerifyChainEmptyChain(t *testing.T) {
	_, err := VerifyChain(nil, nil, "tool", nil, "pop")
	if !errors.Is(err, ErrDenyStep1EmptyChain) {
		t.Fatalf("error = %v, want ErrDenyStep1EmptyChain", err)
	}
}

func TestVerifyChainDuplicateJTI(t *testing.T) {
	tok := &Token{JWTID: "same-jti", Compact: "h.p.s"}
	_, err := VerifyChain([]*Token{tok, tok}, nil, "tool", nil, "pop")
	if !errors.Is(err, ErrDenyStep2CDuplicateJTI) {
		t.Fatalf("error = %v, want ErrDenyStep2CDuplicateJTI", err)
	}
}

func TestVerifyChainFullFlow(t *testing.T) {
	// AS keypair (trust anchor)
	asPub, asPriv := newKeyPair()
	// Holder 1 (receives root delegation)
	h1Pub, h1Priv := newKeyPair()
	// Holder 2 (receives child delegation)
	h2Pub, h2Priv := newKeyPair()
	// Holder 3 (leaf execution holder)
	h3Pub, h3Priv := newKeyPair()

	now := time.Now()

	// Step 1: AS issues root delegation token to H1
	root, err := IssueRoot(IssueRootOpts{
		JWTID:         "root-jti-chain",
		Issuer:        "https://as.example.com",
		Now:           now,
		ExpiresAt:     now.Add(4 * time.Hour),
		TokenType:     AATTypeDelegation,
		MaxDelegationDepth: 2,
		HolderJWK:     publicKeyToJWK(h1Pub),
		Authorization: simpleAuthorization(wildcardToolMap("read_file")),
		Signer:        asPriv,
	})
	if err != nil {
		t.Fatalf("IssueRoot failed: %v", err)
	}

	// Step 2: H1 derives child for H2. Child signed by H1, so iss = H1's
	// (parent.cnf.jwk = root.cnf.jwk) thumbprint URI.
	h1JWK := publicKeyToJWK(h1Pub)
	h1Thumb, _ := h1JWK.Thumbprint(crypto.SHA256)
	h1Issuer := "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + base64.RawURLEncoding.EncodeToString(h1Thumb)

	child, err := DeriveChild(root, DeriveOpts{
		JWTID:              "child-jti-chain",
		Issuer:             h1Issuer,
		Now:                now.Add(1 * time.Minute),
		ExpiresAt:          now.Add(3 * time.Hour),
		TokenType:          AATTypeDelegation,
		MaxDelegationDepth: 2,
		HolderJWK:          publicKeyToJWK(h2Pub),
		Authorization:      simpleAuthorization(wildcardToolMap("read_file")),
		Signer:             h1Priv,
	})
	if err != nil {
		t.Fatalf("DeriveChild (H1→H2) failed: %v", err)
	}

	// Step 3: H2 derives execution leaf for H3. Child signed by H2, so iss = H2's
	// (parent.cnf.jwk = child-token.cnf.jwk = h2Pub) thumbprint URI.
	h2JWK := publicKeyToJWK(h2Pub)
	h2Thumb, _ := h2JWK.Thumbprint(crypto.SHA256)
	h2Issuer := "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + base64.RawURLEncoding.EncodeToString(h2Thumb)

	leaf, err := DeriveChild(child, DeriveOpts{
		JWTID:              "leaf-jti-chain",
		Issuer:             h2Issuer,
		Now:                now.Add(2 * time.Minute),
		ExpiresAt:          now.Add(2 * time.Hour),
		TokenType:          AATTypeExecution,
		MaxDelegationDepth: 2,
		HolderJWK:          publicKeyToJWK(h3Pub),
		Authorization:      simpleAuthorization(wildcardToolMap("read_file")),
		Signer:             h2Priv,
	})
	if err != nil {
		t.Fatalf("DeriveChild (H2→H3) failed: %v", err)
	}

	// Step 4: Build PoP JWT for the invocation
	args := map[string]interface{}{"path": "/tmp/test.txt"}
	popJWT, err := BuildPoPJWT(BuildPoPOpts{
		JWTID:  "pop-jti-chain",
		Now:    now.Add(3 * time.Minute),
		Leaf:   leaf,
		Tool:   "read_file",
		Args:   args,
		Signer: h3Priv,
	})
	if err != nil {
		t.Fatalf("BuildPoPJWT failed: %v", err)
	}

	// Step 5: Verify the chain
	chain := []*Token{root, child, leaf}
	result, err := VerifyChain(chain, [][]byte{asPub}, "read_file", args, popJWT)
	if err != nil {
		t.Fatalf("VerifyChain failed: %v\nFailed step: %s", err, result.FailedStep)
	}
	if result.Verdict != VerdictPermit {
		t.Fatalf("Verdict = %q, want permit. Failed step: %s, Cause: %v", result.Verdict, result.FailedStep, result.Cause)
	}
	if len(result.Links) != 2 {
		t.Fatalf("Links count = %d, want 2", len(result.Links))
	}
	if result.Leaf != leaf {
		t.Fatal("Leaf token mismatch")
	}
	if result.PoP == nil {
		t.Fatal("PoP result is nil")
	}
}

func TestVerifyChainUnauthorizedTool(t *testing.T) {
	pub, priv := newKeyPair()
	now := time.Now()

	root, err := IssueRoot(IssueRootOpts{
		JWTID:         "root-jti-unauth",
		Issuer:        "https://as.example.com",
		Now:           now,
		ExpiresAt:     now.Add(1 * time.Hour),
		TokenType:     AATTypeExecution,
		MaxDelegationDepth: 0,
		HolderJWK:     publicKeyToJWK(pub),
		Authorization: simpleAuthorization(wildcardToolMap("read_file")),
		Signer:        priv,
	})
	if err != nil {
		t.Fatalf("IssueRoot failed: %v", err)
	}

	args := map[string]interface{}{"path": "/tmp/test.txt"}
	popJWT, _ := BuildPoPJWT(BuildPoPOpts{
		JWTID:  "pop-jti-unauth", Now: now,
		Leaf: root, Tool: "delete_file", Args: args, Signer: priv,
	})

	result, err := VerifyChain([]*Token{root}, [][]byte{pub}, "delete_file", args, popJWT)
	if err == nil {
		t.Fatal("VerifyChain should fail for unauthorized tool")
	}
	if !errors.Is(err, ErrDenyStep6BLeafToolUnauthorized) {
		t.Fatalf("error = %v, want ErrDenyStep6BLeafToolUnauthorized. FailedStep=%s", err, result.FailedStep)
	}
}

// ---------------------------------------------------------------------------
// Registry Tests
// ---------------------------------------------------------------------------

type fakeConstraintHandler struct {
	typ         ConstraintType
	checkErr    error
	subsumesOK  bool
	subsumesErr error
}

func (h *fakeConstraintHandler) Type() ConstraintType           { return h.typ }
func (h *fakeConstraintHandler) Check(any, *Constraint) error          { return h.checkErr }
func (h *fakeConstraintHandler) Subsumes(p, c *Constraint) (bool, error) { return h.subsumesOK, h.subsumesErr }

func TestRegistryRegisterAndLookup(t *testing.T) {
	var nilReg *Registry
	if err := nilReg.Register(&fakeConstraintHandler{typ: ConstraintTypeExact}); !errors.Is(err, ErrNilConstraintHandler) {
		t.Fatalf("nil registry Register() = %v, want ErrNilConstraintHandler", err)
	}

	reg := NewRegistry()
	if err := reg.Register(nil); !errors.Is(err, ErrNilConstraintHandler) {
		t.Fatalf("nil handler Register() = %v, want ErrNilConstraintHandler", err)
	}

	h := &fakeConstraintHandler{typ: ConstraintTypeExact}
	if err := reg.Register(h); err != nil {
		t.Fatalf("Register() unexpected error: %v", err)
	}
	if err := reg.Register(&fakeConstraintHandler{typ: ConstraintTypeExact}); !errors.Is(err, ErrDuplicateConstraintType) {
		t.Fatalf("duplicate Register() = %v, want ErrDuplicateConstraintType", err)
	}

	got, ok := reg.Lookup(ConstraintTypeExact)
	if !ok || got != h {
		t.Fatalf("Lookup() = (%v, %v), want registered handler", got, ok)
	}
	if got, ok := reg.Lookup(ConstraintTypeRange); ok || got != nil {
		t.Fatalf("missing Lookup() = (%v, %v), want nil,false", got, ok)
	}

	if got, ok := nilReg.Lookup(ConstraintTypeExact); ok || got != nil {
		t.Fatalf("nil Lookup() = (%v, %v), want nil,false", got, ok)
	}
}

func TestTokenIsRoot(t *testing.T) {
	tests := []struct {
		name string
		tok  *Token
		want bool
	}{
		{"nil", nil, false},
		{"root", &Token{DelegationDepth: 0}, true},
		{"child depth", &Token{DelegationDepth: 1}, false},
		{"parent hash", &Token{DelegationDepth: 0, ParentHash: "p"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tok.IsRoot(); got != tt.want {
				t.Fatalf("IsRoot() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Constraint Dispatch Tests
// ---------------------------------------------------------------------------

func TestCheckConstraintNilConstraint(t *testing.T) {
	if err := CheckConstraint("x", nil); !errors.Is(err, ErrNilConstraint) {
		t.Fatalf("CheckConstraint(nil) = %v, want ErrNilConstraint", err)
	}
}

func TestCheckConstraintUnknownType(t *testing.T) {
	if err := CheckConstraint("x", &Constraint{ConstraintType: "unknown"}); !errors.Is(err, ErrUnknownConstraintType) {
		t.Fatalf("CheckConstraint(unknown) = %v, want ErrUnknownConstraintType", err)
	}
}

func TestCheckConstraintDispatches(t *testing.T) {
	c := &Constraint{ConstraintType: ConstraintTypeExact, Value: "hello"}
	if err := CheckConstraint("hello", c); err != nil {
		t.Fatalf("CheckConstraint failed: %v", err)
	}
}

func TestSubsumesConstraintNilInputs(t *testing.T) {
	c := &Constraint{ConstraintType: ConstraintTypeExact, Value: "x"}
	for _, tc := range []struct{ name string; p, c *Constraint }{
		{"nil parent", nil, c},
		{"nil child", c, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := SubsumesConstraint(tc.p, tc.c)
			if ok || !errors.Is(err, ErrNilConstraint) {
				t.Fatalf("SubsumesConstraint() = (%v, %v), want false, ErrNilConstraint", ok, err)
			}
		})
	}
}

func TestSubsumesConstraintWildcardToExact(t *testing.T) {
	parent := &Constraint{ConstraintType: ConstraintTypeWildcard}
	child := &Constraint{ConstraintType: ConstraintTypeExact, Value: "x"}
	ok, err := SubsumesConstraint(parent, child)
	if err != nil || !ok {
		t.Fatalf("SubsumesConstraint(wildcard, exact) = (%v, %v), want true, nil", ok, err)
	}
}

// ---------------------------------------------------------------------------
// JSON Serialization Tests
// ---------------------------------------------------------------------------

func TestConstraintJSONRoundTrip(t *testing.T) {
	original := &Constraint{
		ConstraintType: ConstraintTypeExact,
		Value:          "hello",
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var parsed Constraint
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if parsed.ConstraintType != ConstraintTypeExact {
		t.Fatalf("ConstraintType = %q, want exact", parsed.ConstraintType)
	}
	if parsed.Value != "hello" {
		t.Fatalf("Value = %v, want hello", parsed.Value)
	}
}

func TestTokenJSONRoundTrip(t *testing.T) {
	original := &Token{
		JWTID:         "jti-1",
		Issuer:        "iss",
		IssuedAt:      1000,
		ExpiresAt:     2000,
		TokenType:     AATTypeDelegation,
		DelegationDepth: 0,
		DelegationMaxDepth: 3,
		Authorization: []AuthorizationDetail{
			{Type: AuthorizationDetailType, Tools: ToolMap{
				"read_file": ArgumentConstraintMap{
					"path": &Constraint{ConstraintType: ConstraintTypePattern, Value: "/tmp/*"},
				},
			}},
		},
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var parsed Token
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if parsed.JWTID != "jti-1" {
		t.Fatalf("JWTID = %q, want jti-1", parsed.JWTID)
	}
	if len(parsed.Authorization) != 1 {
		t.Fatalf("Authorization count = %d, want 1", len(parsed.Authorization))
	}
}
