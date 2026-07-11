package aat

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func draft01Authorization(constraint *Constraint) []AuthorizationDetail {
	return simpleAuthorization(ToolMap{
		"https://tools.example/read_file": {
			"path": constraint,
		},
	})
}

func issueDraft01Chain(t *testing.T) ([]*Token, []byte, []byte, ed25519.PrivateKey, time.Time) {
	t.Helper()
	rootPub, rootPriv := newKeyPair()
	plannerPub, plannerPriv := newKeyPair()
	workerPub, workerPriv := newKeyPair()
	leafPub, leafPriv := newKeyPair()
	receiptPub, _ := newKeyPair()
	now := time.Now().UTC().Truncate(time.Second)
	missionRef := map[string]any{
		"uri":            "https://issuer.example/missions/aat-draft01",
		"mission_id":     "urn:ardur:mission:aat:draft01",
		"mission_digest": "sha-256:1111111111111111111111111111111111111111111111111111111111111111",
	}

	root, err := IssueRoot(IssueRootOpts{
		JWTID:              "019a0000-0000-7000-8000-000000000001",
		Issuer:             "https://issuer.example",
		Now:                now,
		ExpiresAt:          now.Add(time.Hour),
		MaxDelegationDepth: 2,
		HolderJWK:          publicKeyToJWK(plannerPub),
		Authorization: draft01Authorization(&Constraint{
			ConstraintType: ConstraintTypeWildcard,
		}),
		Signer:           rootPriv,
		Profile:          DGProfileV02,
		MissionRef:       missionRef,
		ApprovalRefs:     []string{"approval:human-owner"},
		ReceiptSignerJWK: publicKeyToJWK(receiptPub),
	})
	if err != nil {
		t.Fatalf("IssueRoot draft-01: %v", err)
	}

	child, err := DeriveChild(root, DeriveOpts{
		JWTID:              "019a0000-0000-7000-8000-000000000002",
		Issuer:             thumbprintIssuer(t, plannerPub),
		Now:                now,
		ExpiresAt:          now.Add(45 * time.Minute),
		MaxDelegationDepth: 2,
		HolderJWK:          publicKeyToJWK(workerPub),
		Authorization: draft01Authorization(&Constraint{
			ConstraintType: ConstraintTypeOneOf,
			Values:         []any{"/data/a.txt", "/data/b.txt"},
		}),
		Signer:           plannerPriv,
		Profile:          DGProfileV02,
		ApprovalRefs:     []string{"approval:human-owner", "approval:security"},
		ReceiptSignerJWK: publicKeyToJWK(receiptPub),
	})
	if err != nil {
		t.Fatalf("DeriveChild draft-01: %v", err)
	}

	leaf, err := DeriveChild(child, DeriveOpts{
		JWTID:              "019a0000-0000-7000-8000-000000000003",
		Issuer:             thumbprintIssuer(t, workerPub),
		Now:                now,
		ExpiresAt:          now.Add(30 * time.Minute),
		MaxDelegationDepth: 2,
		HolderJWK:          publicKeyToJWK(leafPub),
		Authorization: draft01Authorization(&Constraint{
			ConstraintType: ConstraintTypeExact,
			Value:          "/data/a.txt",
		}),
		Signer:           workerPriv,
		Profile:          DGProfileV02,
		ApprovalRefs:     []string{"approval:human-owner", "approval:security"},
		ReceiptSignerJWK: publicKeyToJWK(receiptPub),
	})
	if err != nil {
		t.Fatalf("DeriveChild leaf draft-01: %v", err)
	}
	return []*Token{root, child, leaf}, rootPub, receiptPub, leafPriv, now
}

func TestDGProfileV02OrganicChainAndAudienceBoundPoP(t *testing.T) {
	chain, rootPub, receiptPub, leafPriv, now := issueDraft01Chain(t)
	receiptJWK := publicKeyToJWK(receiptPub)
	args := map[string]interface{}{"path": "/data/a.txt"}
	pop, err := BuildPoPJWT(BuildPoPOpts{
		JWTID: "019a0000-0000-7000-8000-000000000011", Now: now,
		Leaf: chain[len(chain)-1], Tool: "https://tools.example/read_file", Args: args,
		Signer: leafPriv, Audience: "https://enforcer.example",
	})
	if err != nil {
		t.Fatalf("BuildPoPJWT draft-01: %v", err)
	}
	result, err := VerifyChainWithOpts(
		chain, [][]byte{rootPub}, "https://tools.example/read_file", args, pop,
		VerifyChainOpts{
			Now: now, Audience: "https://enforcer.example", ReceiptSignerJWK: receiptJWK,
			SatisfiedApprovalRefs: map[string]struct{}{
				"approval:human-owner": {},
				"approval:security":    {},
			},
		},
	)
	if err != nil {
		t.Fatalf("VerifyChainWithOpts draft-01: %v", err)
	}
	if result.Verdict != VerdictPermit || result.PoP.AATAudience != "https://enforcer.example" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestDGProfileV02SecurityBoundaries(t *testing.T) {
	chain, rootPub, receiptPub, _, now := issueDraft01Chain(t)
	leaf := chain[len(chain)-1]
	if leaf.Profile != DGProfileV02 || leaf.TokenType != "" {
		t.Fatalf("leaf profile/type = %q/%q", leaf.Profile, leaf.TokenType)
	}
	claims, err := parseClaims(leaf.Compact)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := claims["aat_type"]; present {
		t.Fatal("DG v0.2 token contains draft-00 aat_type")
	}
	if claims["ardur_dg_profile"] != DGProfileV02 {
		t.Fatalf("profile discriminator = %v", claims["ardur_dg_profile"])
	}

	for index := 1; index < len(chain); index++ {
		if jwkThumbprintsEqual(chain[index-1].Confirmation.JWK, chain[index].Confirmation.JWK) {
			t.Fatalf("holder key reused at link %d", index-1)
		}
	}
	if err := validateReceiptSignerSeparation(chain, publicKeyToJWK(receiptPub)); err != nil {
		t.Fatalf("receipt signer separation: %v", err)
	}

	_, err = VerifyChainWithOpts(chain, [][]byte{rootPub}, "https://tools.example/read_file", map[string]interface{}{"path": "/data/a.txt"}, "invalid", VerifyChainOpts{Now: now, Audience: "https://enforcer.example", ReceiptSignerJWK: publicKeyToJWK(receiptPub)})
	if err == nil {
		t.Fatal("invalid PoP unexpectedly passed")
	}
}

func TestDGProfileV02RejectsRemovedConstraintsAndMixedWire(t *testing.T) {
	_, issuerPriv := newKeyPair()
	holderPub, _ := newKeyPair()
	receiptPub, _ := newKeyPair()
	now := time.Now().UTC().Truncate(time.Second)
	for _, constraintType := range []ConstraintType{
		ConstraintTypePattern, ConstraintTypeRegex, ConstraintTypeCEL, ConstraintTypeNot,
	} {
		_, err := IssueRoot(IssueRootOpts{
			JWTID: "019a0000-0000-7000-8000-000000000020", Issuer: "https://issuer.example",
			Now: now, ExpiresAt: now.Add(time.Hour), MaxDelegationDepth: 0,
			HolderJWK:     publicKeyToJWK(holderPub),
			Authorization: draft01Authorization(&Constraint{ConstraintType: constraintType, Value: "x"}),
			Signer:        issuerPriv, Profile: DGProfileV02,
			MissionRef:       map[string]any{"uri": "https://issuer.example/missions/removed"},
			ReceiptSignerJWK: publicKeyToJWK(receiptPub),
		})
		if !errors.Is(err, ErrDraft01Constraint) {
			t.Fatalf("constraint %q error = %v", constraintType, err)
		}
	}
	_, err := IssueRoot(IssueRootOpts{
		JWTID: "019a0000-0000-7000-8000-000000000021", Issuer: "https://issuer.example",
		Now: now, ExpiresAt: now.Add(time.Hour), TokenType: AATTypeExecution,
		MaxDelegationDepth: 0, HolderJWK: publicKeyToJWK(holderPub),
		Authorization: draft01Authorization(&Constraint{ConstraintType: ConstraintTypeWildcard}),
		Signer:        issuerPriv, Profile: DGProfileV02,
		MissionRef:       map[string]any{"uri": "https://issuer.example/missions/mixed"},
		ReceiptSignerJWK: publicKeyToJWK(receiptPub),
	})
	if !errors.Is(err, ErrMixedDraftWire) {
		t.Fatalf("mixed wire error = %v", err)
	}
}

func TestDGProfileV02RejectsEmptyLogicalConstraints(t *testing.T) {
	_, issuerPriv := newKeyPair()
	holderPub, _ := newKeyPair()
	receiptPub, _ := newKeyPair()
	now := time.Now().UTC().Truncate(time.Second)
	for _, constraintType := range []ConstraintType{ConstraintTypeAll, ConstraintTypeAny} {
		_, err := IssueRoot(IssueRootOpts{
			JWTID: "019a0000-0000-7000-8000-000000000022", Issuer: "https://issuer.example",
			Now: now, ExpiresAt: now.Add(time.Hour), MaxDelegationDepth: 0,
			HolderJWK:     publicKeyToJWK(holderPub),
			Authorization: draft01Authorization(&Constraint{ConstraintType: constraintType}),
			Signer:        issuerPriv, Profile: DGProfileV02,
			MissionRef:       map[string]any{"uri": "https://issuer.example/missions/empty-logical"},
			ReceiptSignerJWK: publicKeyToJWK(receiptPub),
		})
		if !errors.Is(err, ErrDraft01Constraint) {
			t.Fatalf("empty %q error = %v", constraintType, err)
		}
	}
}

func TestDGProfileV02RejectsReceiptSignerReuse(t *testing.T) {
	issuerPub, issuerPriv := newKeyPair()
	now := time.Now().UTC().Truncate(time.Second)
	_, err := IssueRoot(IssueRootOpts{
		JWTID: "019a0000-0000-7000-8000-000000000030", Issuer: "https://issuer.example",
		Now: now, ExpiresAt: now.Add(time.Hour), MaxDelegationDepth: 0,
		HolderJWK:     publicKeyToJWK(issuerPub),
		Authorization: draft01Authorization(&Constraint{ConstraintType: ConstraintTypeWildcard}),
		Signer:        issuerPriv, Profile: DGProfileV02,
		MissionRef:       map[string]any{"uri": "https://issuer.example/missions/key-reuse"},
		ReceiptSignerJWK: publicKeyToJWK(issuerPub),
	})
	if !errors.Is(err, ErrReceiptSignerKeyReuse) {
		t.Fatalf("receipt key reuse error = %v", err)
	}
}

func TestDGProfileV02RejectsMissingOrWrongAudienceAndApprovals(t *testing.T) {
	chain, rootPub, receiptPub, leafPriv, now := issueDraft01Chain(t)
	args := map[string]interface{}{"path": "/data/a.txt"}
	leaf := chain[len(chain)-1]
	if _, err := BuildPoPJWT(BuildPoPOpts{
		JWTID: "019a0000-0000-7000-8000-000000000040", Now: now,
		Leaf: leaf, Tool: "https://tools.example/read_file", Args: args, Signer: leafPriv,
	}); !errors.Is(err, ErrPoPAudienceRequired) {
		t.Fatalf("missing PoP audience error = %v", err)
	}
	pop, err := BuildPoPJWT(BuildPoPOpts{
		JWTID: "019a0000-0000-7000-8000-000000000041", Now: now,
		Leaf: leaf, Tool: "https://tools.example/read_file", Args: args,
		Signer: leafPriv, Audience: "https://enforcer.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	baseOpts := VerifyChainOpts{
		Now: now, Audience: "https://enforcer.example",
		ReceiptSignerJWK: publicKeyToJWK(receiptPub),
		SatisfiedApprovalRefs: map[string]struct{}{
			"approval:human-owner": {},
			"approval:security":    {},
		},
	}
	wrongAudience := baseOpts
	wrongAudience.Audience = "https://other-enforcer.example"
	if _, err := VerifyChainWithOpts(
		chain, [][]byte{rootPub}, "https://tools.example/read_file", args, pop, wrongAudience,
	); !errors.Is(err, ErrPoPAudienceMismatch) {
		t.Fatalf("wrong audience error = %v", err)
	}
	missingApproval := baseOpts
	missingApproval.SatisfiedApprovalRefs = map[string]struct{}{
		"approval:human-owner": {},
	}
	if _, err := VerifyChainWithOpts(
		chain, [][]byte{rootPub}, "https://tools.example/read_file", args, pop, missingApproval,
	); !errors.Is(err, ErrApprovalUnsatisfied) {
		t.Fatalf("missing approval error = %v", err)
	}
}

func TestDGProfileV02RejectsHolderReuseAndDroppedApproval(t *testing.T) {
	rootPub, rootPriv := newKeyPair()
	holderPub, holderPriv := newKeyPair()
	receiptPub, _ := newKeyPair()
	now := time.Now().UTC().Truncate(time.Second)
	receiptJWK := publicKeyToJWK(receiptPub)
	root, err := IssueRoot(IssueRootOpts{
		JWTID: "019a0000-0000-7000-8000-000000000050", Issuer: "https://issuer.example",
		Now: now, ExpiresAt: now.Add(time.Hour), MaxDelegationDepth: 1,
		HolderJWK:     publicKeyToJWK(holderPub),
		Authorization: draft01Authorization(&Constraint{ConstraintType: ConstraintTypeWildcard}),
		Signer:        rootPriv, Profile: DGProfileV02,
		MissionRef:   map[string]any{"uri": "https://issuer.example/missions/derivation"},
		ApprovalRefs: []string{"approval:root"}, ReceiptSignerJWK: receiptJWK,
	})
	if err != nil {
		t.Fatal(err)
	}
	base := DeriveOpts{
		JWTID:  "019a0000-0000-7000-8000-000000000051",
		Issuer: thumbprintIssuer(t, holderPub), Now: now,
		ExpiresAt: now.Add(30 * time.Minute), MaxDelegationDepth: 1,
		Authorization: draft01Authorization(&Constraint{ConstraintType: ConstraintTypeWildcard}),
		Signer:        holderPriv, Profile: DGProfileV02,
		ApprovalRefs: []string{"approval:root"}, ReceiptSignerJWK: receiptJWK,
	}
	reuse := base
	reuse.HolderJWK = publicKeyToJWK(holderPub)
	if _, err := DeriveChild(root, reuse); !errors.Is(err, ErrDraft01HolderKeyReuse) {
		t.Fatalf("holder reuse error = %v", err)
	}
	childPub, _ := newKeyPair()
	dropped := base
	dropped.HolderJWK = publicKeyToJWK(childPub)
	dropped.ApprovalRefs = nil
	if _, err := DeriveChild(root, dropped); !errors.Is(err, ErrApprovalRefDropped) {
		t.Fatalf("dropped approval error = %v", err)
	}
	_ = rootPub
}

func TestDGProfileV02RejectsCrossVersionDerivation(t *testing.T) {
	rootPub, rootPriv := newKeyPair()
	holderPub, holderPriv := newKeyPair()
	childPub, _ := newKeyPair()
	receiptPub, _ := newKeyPair()
	now := time.Now().UTC().Truncate(time.Second)
	root, err := IssueRoot(IssueRootOpts{
		JWTID: "019a0000-0000-7000-8000-000000000060", Issuer: "https://issuer.example",
		Now: now, ExpiresAt: now.Add(time.Hour), TokenType: AATTypeDelegation,
		MaxDelegationDepth: 1, HolderJWK: publicKeyToJWK(holderPub),
		Authorization: simpleAuthorization(wildcardToolMap("read")), Signer: rootPriv,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = DeriveChild(root, DeriveOpts{
		JWTID:  "019a0000-0000-7000-8000-000000000061",
		Issuer: thumbprintIssuer(t, holderPub), Now: now,
		ExpiresAt: now.Add(30 * time.Minute), MaxDelegationDepth: 1,
		HolderJWK:     publicKeyToJWK(childPub),
		Authorization: draft01Authorization(&Constraint{ConstraintType: ConstraintTypeWildcard}),
		Signer:        holderPriv, Profile: DGProfileV02,
		ReceiptSignerJWK: publicKeyToJWK(rootPub),
	})
	if !errors.Is(err, ErrProfileMismatch) {
		t.Fatalf("cross-version derivation error = %v", err)
	}

	draft01Root, err := IssueRoot(IssueRootOpts{
		JWTID: "019a0000-0000-7000-8000-000000000062", Issuer: "https://issuer.example",
		Now: now, ExpiresAt: now.Add(time.Hour), MaxDelegationDepth: 1,
		HolderJWK:     publicKeyToJWK(holderPub),
		Authorization: draft01Authorization(&Constraint{ConstraintType: ConstraintTypeWildcard}),
		Signer:        rootPriv, Profile: DGProfileV02,
		MissionRef:       map[string]any{"uri": "https://issuer.example/missions/cross-version"},
		ReceiptSignerJWK: publicKeyToJWK(receiptPub),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = DeriveChild(draft01Root, DeriveOpts{
		JWTID:  "019a0000-0000-7000-8000-000000000063",
		Issuer: thumbprintIssuer(t, holderPub), Now: now,
		ExpiresAt: now.Add(30 * time.Minute), TokenType: AATTypeExecution,
		MaxDelegationDepth: 1, HolderJWK: publicKeyToJWK(childPub),
		Authorization: simpleAuthorization(wildcardToolMap("read")), Signer: holderPriv,
	})
	if !errors.Is(err, ErrProfileMismatch) {
		t.Fatalf("reverse cross-version derivation error = %v", err)
	}
}

func TestDraft00RejectsUnsignedProfileOnlyInputs(t *testing.T) {
	_, issuerPriv := newKeyPair()
	holderPub, _ := newKeyPair()
	receiptPub, _ := newKeyPair()
	now := time.Now().UTC().Truncate(time.Second)
	_, err := IssueRoot(IssueRootOpts{
		JWTID: "draft00-profile-input", Issuer: "https://issuer.example",
		Now: now, ExpiresAt: now.Add(time.Hour), TokenType: AATTypeExecution,
		MaxDelegationDepth: 0, HolderJWK: publicKeyToJWK(holderPub),
		Authorization: simpleAuthorization(wildcardToolMap("read")), Signer: issuerPriv,
		ApprovalRefs: []string{"approval:not-signed"}, ReceiptSignerJWK: publicKeyToJWK(receiptPub),
	})
	if !errors.Is(err, ErrMixedDraftWire) {
		t.Fatalf("draft-00 profile-only input error = %v", err)
	}
}
