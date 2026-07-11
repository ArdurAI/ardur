package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/aat"
	jose "github.com/go-jose/go-jose/v4"
)

const draft01SHA256 = "4e5fdd2f42cd3ff4570b711a0be5ff710236618e1f6926ef34030f82c3d04df5"

type fixture struct {
	SchemaVersion               string                     `json:"schema_version"`
	ClaimBoundary               string                     `json:"claim_boundary"`
	DraftRevision               string                     `json:"draft_revision"`
	DraftTextSHA256             string                     `json:"draft_text_sha256"`
	DGProfile                   string                     `json:"dg_profile"`
	IndependentFixtureAvailable bool                       `json:"independent_fixture_available"`
	ReferenceImplementationNote string                     `json:"reference_implementation_note"`
	VerificationTime            string                     `json:"verification_time"`
	Audience                    string                     `json:"audience"`
	Tool                        string                     `json:"tool"`
	Arguments                   map[string]any             `json:"arguments"`
	ApprovalRefs                []string                   `json:"approval_refs"`
	PublicKeys                  map[string]jose.JSONWebKey `json:"public_keys"`
	Chain                       []string                   `json:"chain"`
	PoPJWT                      string                     `json:"pop_jwt"`
	Expected                    map[string]any             `json:"expected"`
}

func key(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func publicJWK(publicKey ed25519.PublicKey) jose.JSONWebKey {
	return jose.JSONWebKey{Key: publicKey, Algorithm: string(jose.EdDSA), Use: "sig"}
}

func issuerFor(publicKey ed25519.PublicKey) string {
	key := publicJWK(publicKey)
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		panic(err)
	}
	return "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + base64.RawURLEncoding.EncodeToString(thumbprint)
}

func authorization(constraint *aat.Constraint) []aat.AuthorizationDetail {
	return []aat.AuthorizationDetail{{
		Type: aat.AuthorizationDetailType,
		Tools: aat.ToolMap{
			"https://tools.example/read_file": {"path": constraint},
		},
	}}
}

func generateFixture() (fixture, error) {
	rootPublic, rootPrivate := key(0x11)
	plannerPublic, plannerPrivate := key(0x22)
	workerPublic, workerPrivate := key(0x33)
	leafPublic, leafPrivate := key(0x44)
	receiptPublic, _ := key(0x55)
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	missionRef := map[string]any{
		"uri":            "https://issuer.example/missions/aat-draft01-fixture",
		"mission_id":     "urn:ardur:mission:aat:draft01:fixture",
		"mission_digest": "sha-256:1111111111111111111111111111111111111111111111111111111111111111",
	}
	receiptJWK := publicJWK(receiptPublic)

	root, err := aat.IssueRoot(aat.IssueRootOpts{
		JWTID: "019a0000-0000-7000-8000-000000000101", Issuer: "https://issuer.example",
		Now: now, ExpiresAt: now.Add(time.Hour), MaxDelegationDepth: 2,
		HolderJWK:     publicJWK(plannerPublic),
		Authorization: authorization(&aat.Constraint{ConstraintType: aat.ConstraintTypeWildcard}),
		Signer:        rootPrivate, Profile: aat.DGProfileV02, MissionRef: missionRef,
		ApprovalRefs: []string{"approval:human-owner"}, ReceiptSignerJWK: receiptJWK,
	})
	if err != nil {
		return fixture{}, err
	}
	child, err := aat.DeriveChild(root, aat.DeriveOpts{
		JWTID: "019a0000-0000-7000-8000-000000000102", Issuer: issuerFor(plannerPublic),
		Now: now, ExpiresAt: now.Add(45 * time.Minute), MaxDelegationDepth: 2,
		HolderJWK: publicJWK(workerPublic),
		Authorization: authorization(&aat.Constraint{
			ConstraintType: aat.ConstraintTypeOneOf,
			Values:         []any{"/data/a.txt", "/data/b.txt"},
		}),
		Signer: plannerPrivate, Profile: aat.DGProfileV02,
		ApprovalRefs:     []string{"approval:human-owner", "approval:security"},
		ReceiptSignerJWK: receiptJWK,
	})
	if err != nil {
		return fixture{}, err
	}
	leaf, err := aat.DeriveChild(child, aat.DeriveOpts{
		JWTID: "019a0000-0000-7000-8000-000000000103", Issuer: issuerFor(workerPublic),
		Now: now, ExpiresAt: now.Add(30 * time.Minute), MaxDelegationDepth: 2,
		HolderJWK: publicJWK(leafPublic),
		Authorization: authorization(&aat.Constraint{
			ConstraintType: aat.ConstraintTypeExact,
			Value:          "/data/a.txt",
		}),
		Signer: workerPrivate, Profile: aat.DGProfileV02,
		ApprovalRefs:     []string{"approval:human-owner", "approval:security"},
		ReceiptSignerJWK: receiptJWK,
	})
	if err != nil {
		return fixture{}, err
	}
	args := map[string]any{"path": "/data/a.txt"}
	popJWT, err := aat.BuildPoPJWT(aat.BuildPoPOpts{
		JWTID: "019a0000-0000-7000-8000-000000000104", Now: now,
		Leaf: leaf, Tool: "https://tools.example/read_file", Args: args,
		Signer: leafPrivate, Audience: "https://enforcer.example",
	})
	if err != nil {
		return fixture{}, err
	}
	chain := []*aat.Token{root, child, leaf}
	result, err := aat.VerifyChainWithOpts(
		chain, [][]byte{rootPublic}, "https://tools.example/read_file", args, popJWT,
		aat.VerifyChainOpts{
			Now: now, Audience: "https://enforcer.example", ReceiptSignerJWK: receiptJWK,
			SatisfiedApprovalRefs: map[string]struct{}{
				"approval:human-owner": {},
				"approval:security":    {},
			},
		},
	)
	if err != nil || result.Verdict != aat.VerdictPermit {
		return fixture{}, fmt.Errorf("self-verification failed: %w", err)
	}

	return fixture{
		SchemaVersion: "ardur.aat_draft01_fixture.v0.2",
		ClaimBoundary: "Ardur-generated deterministic self-test; not independent interoperability evidence",
		DraftRevision: aat.Draft01Revision, DraftTextSHA256: draft01SHA256,
		DGProfile: aat.DGProfileV02, IndependentFixtureAvailable: false,
		ReferenceImplementationNote: "The draft-author Tenuo repository exposes a different CBOR warrant fixture, not a draft-01 JWT interoperability fixture.",
		VerificationTime:            now.Format(time.RFC3339), Audience: "https://enforcer.example",
		Tool: "https://tools.example/read_file", Arguments: args,
		ApprovalRefs: []string{"approval:human-owner", "approval:security"},
		PublicKeys: map[string]jose.JSONWebKey{
			"root_trust_anchor": publicJWK(rootPublic), "planner_holder": publicJWK(plannerPublic),
			"worker_holder": publicJWK(workerPublic), "leaf_holder": publicJWK(leafPublic),
			"drp_receipt_signer": receiptJWK,
		},
		Chain: []string{root.Compact, child.Compact, leaf.Compact}, PoPJWT: popJWT,
		Expected: map[string]any{
			"verdict": "permit", "chain_length": 3, "leaf_jti": leaf.JWTID,
			"fresh_holder_key_each_hop": true, "receipt_signer_separate": true,
		},
	}, nil
}

func encodeFixture(document fixture) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func main() {
	document, err := generateFixture()
	if err != nil {
		panic(err)
	}
	output, err := encodeFixture(document)
	if err != nil {
		panic(err)
	}
	if _, err := os.Stdout.Write(output); err != nil {
		panic(err)
	}
}
