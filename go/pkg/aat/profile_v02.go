package aat

import (
	"bytes"
	"crypto"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	jose "github.com/go-jose/go-jose/v4"
)

const maxApprovalRefs = 64

func detectTokenProfile(claims map[string]interface{}) (string, AATType, error) {
	profileRaw, hasProfile := claims["ardur_dg_profile"]
	_, hasType := claims["aat_type"]
	if !hasProfile {
		if !hasType {
			return "", "", ErrUnsupportedDraftRevision
		}
		tokenType, err := draft00TokenType(claims)
		return "", tokenType, err
	}
	profile, ok := profileRaw.(string)
	if !ok || profile != DGProfileV02 {
		return "", "", ErrUnknownDGProfile
	}
	if hasType {
		return "", "", ErrMixedDraftWire
	}
	return profile, "", nil
}

func validateIssueProfile(profile string, tokenType AATType) error {
	switch profile {
	case "":
		if tokenType != AATTypeDelegation && tokenType != AATTypeExecution {
			return fmt.Errorf("invalid aat_type %q", tokenType)
		}
	case DGProfileV02:
		if tokenType != "" {
			return ErrMixedDraftWire
		}
	default:
		return ErrUnknownDGProfile
	}
	return nil
}

func validateProfileOnlyInputs(profile string, missionRef any, approvalRefs []string, receiptSigner jose.JSONWebKey) error {
	if profile == DGProfileV02 {
		return nil
	}
	if missionRef != nil || len(approvalRefs) != 0 || receiptSigner.Key != nil {
		return ErrMixedDraftWire
	}
	return nil
}

func validateMissionRef(value any) error {
	switch typed := value.(type) {
	case string:
		return validateMissionRefURI(typed)
	case map[string]any:
		rawURI, ok := typed["uri"].(string)
		if !ok || validateMissionRefURI(rawURI) != nil {
			return ErrMissionRefInvalid
		}
		if digest, present := typed["mission_digest"]; present {
			text, ok := digest.(string)
			if !ok || len(text) != len("sha-256:")+64 || !strings.HasPrefix(text, "sha-256:") {
				return ErrMissionRefInvalid
			}
			for _, char := range text[len("sha-256:"):] {
				if !strings.ContainsRune("0123456789abcdef", char) {
					return ErrMissionRefInvalid
				}
			}
		}
		if missionID, present := typed["mission_id"]; present {
			text, ok := missionID.(string)
			if !ok || text == "" || strings.TrimSpace(text) != text {
				return ErrMissionRefInvalid
			}
		}
		return nil
	default:
		return ErrMissionRefInvalid
	}
}

func validateMissionRefURI(raw string) error {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return ErrMissionRefInvalid
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" {
		return ErrMissionRefInvalid
	}
	return nil
}

func missionRefsEqual(parent, child any) bool {
	parentBytes, parentErr := canonicalizeJSON(parent)
	childBytes, childErr := canonicalizeJSON(child)
	return parentErr == nil && childErr == nil && bytes.Equal(parentBytes, childBytes)
}

func normalizeApprovalRefs(refs []string) ([]string, error) {
	if len(refs) > maxApprovalRefs {
		return nil, ErrApprovalRefInvalid
	}
	normalized := append([]string(nil), refs...)
	for _, ref := range normalized {
		if ref == "" || len(ref) > 256 || !utf8.ValidString(ref) || strings.TrimSpace(ref) != ref {
			return nil, ErrApprovalRefInvalid
		}
		for _, char := range ref {
			if unicode.IsControl(char) {
				return nil, ErrApprovalRefInvalid
			}
		}
	}
	sort.Strings(normalized)
	for index := 1; index < len(normalized); index++ {
		if normalized[index] == normalized[index-1] {
			return nil, ErrApprovalRefInvalid
		}
	}
	return normalized, nil
}

func approvalRefsFromClaims(claims map[string]interface{}) ([]string, error) {
	raw, present := claims["ardur_approval_refs"]
	if !present {
		return []string{}, nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil, ErrApprovalRefInvalid
	}
	refs := make([]string, len(items))
	for index, item := range items {
		ref, ok := item.(string)
		if !ok {
			return nil, ErrApprovalRefInvalid
		}
		refs[index] = ref
	}
	normalized, err := normalizeApprovalRefs(refs)
	if err != nil {
		return nil, err
	}
	for index := range refs {
		if refs[index] != normalized[index] {
			return nil, ErrApprovalRefInvalid
		}
	}
	return normalized, nil
}

func approvalRefsPreserved(parent, child []string) bool {
	childSet := make(map[string]struct{}, len(child))
	for _, ref := range child {
		childSet[ref] = struct{}{}
	}
	for _, ref := range parent {
		if _, ok := childSet[ref]; !ok {
			return false
		}
	}
	return true
}

func validateSatisfiedApprovals(required []string, satisfied map[string]struct{}) error {
	for _, ref := range required {
		if _, ok := satisfied[ref]; !ok {
			return fmt.Errorf("%w: %s", ErrApprovalUnsatisfied, ref)
		}
	}
	return nil
}

func validateDraft01Authorization(details []AuthorizationDetail) error {
	for _, detail := range details {
		for _, arguments := range detail.Tools {
			for _, constraint := range arguments {
				if err := validateDraft01Constraint(constraint); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateDraft01Constraint(constraint *Constraint) error {
	if constraint == nil {
		return ErrDraft01Constraint
	}
	switch constraint.ConstraintType {
	case ConstraintTypeExact, ConstraintTypeRange, ConstraintTypeOneOf,
		ConstraintTypeNotOneOf, ConstraintTypeContains, ConstraintTypeSubset,
		ConstraintTypeWildcard:
		return nil
	case ConstraintTypeAll, ConstraintTypeAny:
		if len(constraint.Children) == 0 {
			return fmt.Errorf("%w: %s requires at least one child", ErrDraft01Constraint, constraint.ConstraintType)
		}
		for _, child := range constraint.Children {
			if err := validateDraft01Constraint(child); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrDraft01Constraint, constraint.ConstraintType)
	}
}

func jwkThumbprintsEqual(left, right jose.JSONWebKey) bool {
	leftThumbprint, leftErr := left.Thumbprint(crypto.SHA256)
	rightThumbprint, rightErr := right.Thumbprint(crypto.SHA256)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftThumbprint, rightThumbprint)
}

func validateReceiptSignerSeparation(chain []*Token, receiptSigner jose.JSONWebKey) error {
	if receiptSigner.Key == nil || !receiptSigner.Valid() || !receiptSigner.IsPublic() {
		return fmt.Errorf("%w: configured receipt signer key is invalid", ErrReceiptSignerKeyReuse)
	}
	for _, token := range chain {
		if token.Confirmation != nil && jwkThumbprintsEqual(token.Confirmation.JWK, receiptSigner) {
			return ErrReceiptSignerKeyReuse
		}
	}
	return nil
}
