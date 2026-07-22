package main

import (
	"strings"
	"testing"
)

// validPaths returns studyPaths populated with placeholder values so that
// only the field under test can be set to whitespace.
func validPaths() studyPaths {
	return studyPaths{
		root:          "placeholder-root",
		corpus:        "placeholder-corpus",
		protocol:      "placeholder-protocol",
		prereg:        "placeholder-prereg",
		gold:          "placeholder-gold",
		annotations:   "placeholder-annotations",
		adjudications: "placeholder-adjudications",
		splits:        "placeholder-splits",
	}
}

func TestValidateRejectsWhitespaceOnlyPaths(t *testing.T) {
	cases := []struct {
		name  string
		field string
	}{
		{"root", "root"},
		{"corpus", "corpus"},
		{"protocol", "protocol"},
		{"prereg", "prereg"},
		{"gold", "gold"},
		{"annotations", "annotations"},
		{"adjudications", "adjudications"},
		{"splits", "splits"},
	}
	for _, whitespace := range []string{"   ", "\t", "\n"} {
		for _, tc := range cases {
			t.Run(tc.name+"="+strings.TrimSpace(whitespace)+"empty", func(t *testing.T) {
				p := validPaths()
				setField(&p, tc.field, whitespace)
				if err := p.validate(); err == nil {
					t.Fatalf("validate() with whitespace-only %s = nil, want error", tc.name)
				}
			})
		}
	}
}

func TestValidateAcceptsPopulatedPaths(t *testing.T) {
	if err := validPaths().validate(); err != nil {
		t.Fatalf("validate() with all populated = %v, want nil", err)
	}
}

func TestRunSealRejectsWhitespaceSealAndSealedAt(t *testing.T) {
	base := []string{
		"-root", "placeholder-root",
		"-corpus", "placeholder-corpus",
		"-protocol", "placeholder-protocol",
		"-prereg", "placeholder-prereg",
		"-gold", "placeholder-gold",
		"-annotations", "placeholder-annotations",
		"-adjudications", "placeholder-adjudications",
		"-splits", "placeholder-splits",
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"whitespace-seal", append(append([]string{}, base...), "-sealed-at", "2026-01-01T00:00:00Z", "-seal", "   ")},
		{"whitespace-sealed-at", append(append([]string{}, base...), "-sealed-at", "   ", "-seal", "placeholder-seal.json")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := runSeal(tc.args); err == nil {
				t.Fatalf("runSeal() = nil, want error for %s", tc.name)
			}
		})
	}
}

func TestRunScoreRejectsWhitespaceRequiredFlags(t *testing.T) {
	base := []string{
		"-root", "placeholder-root",
		"-corpus", "placeholder-corpus",
		"-protocol", "placeholder-protocol",
		"-prereg", "placeholder-prereg",
		"-gold", "placeholder-gold",
		"-annotations", "placeholder-annotations",
		"-adjudications", "placeholder-adjudications",
		"-splits", "placeholder-splits",
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"whitespace-seal", append(append([]string{}, base...), "-result", "placeholder-result.json", "-out", "placeholder-out.json", "-seal", "   ")},
		{"whitespace-result", append(append([]string{}, base...), "-result", "   ", "-out", "placeholder-out.json", "-seal", "placeholder-seal.json")},
		{"whitespace-out", append(append([]string{}, base...), "-result", "placeholder-result.json", "-out", "   ", "-seal", "placeholder-seal.json")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := runScore(tc.args); err == nil {
				t.Fatalf("runScore() = nil, want error for %s", tc.name)
			}
		})
	}
}

func TestRunVerifyRejectsWhitespaceSeal(t *testing.T) {
	base := []string{
		"-root", "placeholder-root",
		"-corpus", "placeholder-corpus",
		"-protocol", "placeholder-protocol",
		"-prereg", "placeholder-prereg",
		"-gold", "placeholder-gold",
		"-annotations", "placeholder-annotations",
		"-adjudications", "placeholder-adjudications",
		"-splits", "placeholder-splits",
	}
	args := append(append([]string{}, base...), "-seal", "   ")
	if err := runVerify(args); err == nil {
		t.Fatalf("runVerify() with whitespace seal = nil, want error")
	}
}

// setField assigns a value to a studyPaths field by name. It panics for
// unknown fields so table-driven tests fail loudly if the struct changes.
func setField(p *studyPaths, name, value string) {
	switch name {
	case "root":
		p.root = value
	case "corpus":
		p.corpus = value
	case "protocol":
		p.protocol = value
	case "prereg":
		p.prereg = value
	case "gold":
		p.gold = value
	case "annotations":
		p.annotations = value
	case "adjudications":
		p.adjudications = value
	case "splits":
		p.splits = value
	default:
		panic("unknown studyPaths field: " + name)
	}
}
