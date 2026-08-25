// Package linkgraph holds architecture tests over the module's production
// dependency graph. It contains no production code and is imported by nothing.
//
// The rule it enforces: no test double may be reachable from a shipped binary.
//
// This matters because pkg/issuer.computeActualCompliance raises a credential's
// ComplianceLevel to verified/enforced from five booleans, and each of those
// booleans is set by nothing stronger than "a provider was configured and
// FetchIdentity/Verify/Compile returned no error" (issuer.go:211/246/263/287/302).
// The five provider packages — spiffe, provenance, policy, profiling, trust —
// map one-to-one onto the five booleans. A fake linked into a binary can
// therefore mint a credential at LevelVerified over a fabricated SPIFFE ID and
// fabricated provenance, and the signed artifact will say it was verified.
//
// Keeping the fakes out of the link graph is the structural form of that rule.
// A comment asking people not to wire a mock in is not.
//
// This lives as a Go test rather than a CI step so that it runs everywhere
// `go test ./...` runs — CI, `make test-go`, and a developer's checkout — with
// no workflow wiring to keep in sync.
package linkgraph

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// testDoubleDecl matches an exported declaration whose name marks it as a test
// double. Deliberately anchored to a top-level declaration so that a local
// variable named e.g. mockResponse does not trip it.
var testDoubleDecl = regexp.MustCompile(`(?m)^(func|type|var|const) (Mock|Fake|Stub|Dummy)[A-Z]\w*`)

// testPackageDir matches a package directory name reserved for test doubles,
// following the httptest/spiffetest convention.
var testPackageDir = regexp.MustCompile(`^[a-z0-9_]*test$`)

func goList(t *testing.T, dir string, args ...string) []string {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list"}, args...)...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("go list %s: %v\nstderr:\n%s", strings.Join(args, " "), err, ee.Stderr)
		}
		t.Fatalf("go list %s: %v", strings.Join(args, " "), err)
	}
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func moduleRoot(t *testing.T) (dir, importPath string) {
	t.Helper()
	got := goList(t, ".", "-m", "-f", "{{.Dir}}|{{.Path}}")
	if len(got) != 1 {
		t.Fatalf("resolving module: want 1 line, got %d: %v", len(got), got)
	}
	parts := strings.SplitN(got[0], "|", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		t.Fatalf("resolving module: unparseable %q", got[0])
	}
	return parts[0], parts[1]
}

// TestNoTestDoubleReachableFromProductionBinary asserts that neither a
// test-double package nor a test-double symbol is reachable from any main
// package in this module.
func TestNoTestDoubleReachableFromProductionBinary(t *testing.T) {
	root, module := moduleRoot(t)

	binaries := goList(t, root, "-f", `{{if eq .Name "main"}}{{.ImportPath}}{{end}}`, "./...")
	if len(binaries) == 0 {
		t.Fatal("found no main packages — refusing to pass vacuously")
	}
	t.Logf("checking %d production binaries in %s", len(binaries), module)

	// One query for the union of every binary's dependencies. Attribution to a
	// specific binary is deferred to the failure path, where it is worth the
	// extra process.
	args := append([]string{"-deps", "-f", `{{.ImportPath}}|{{.Dir}}|{{join .GoFiles ","}}`}, binaries...)
	var reachable []string
	for _, line := range goList(t, root, args...) {
		if strings.HasPrefix(line, module+"/") {
			reachable = append(reachable, line)
		}
	}
	if len(reachable) == 0 {
		t.Fatal("resolved no module-local dependencies — refusing to pass vacuously")
	}
	t.Logf("%d module-local packages are reachable from production binaries", len(reachable))

	for _, line := range reachable {
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			t.Fatalf("unparseable go list output: %q", line)
		}
		importPath, dir, goFiles := parts[0], parts[1], parts[2]

		// Rule 1 — the package itself is reserved for test doubles.
		if testPackageDir.MatchString(path.Base(importPath)) {
			t.Errorf("test-double package %s is reachable from a production binary\n%s",
				importPath, remedy)
		}

		// Rule 2 — the package declares a test double in a production file.
		// GoFiles excludes _test.go, which is exactly right: a _test.go file is
		// never linked into a binary, so a double defined there is safe.
		if goFiles == "" {
			continue
		}
		for _, f := range strings.Split(goFiles, ",") {
			src, err := os.ReadFile(filepath.Join(dir, f))
			if err != nil {
				t.Fatalf("reading %s: %v", filepath.Join(dir, f), err)
			}
			for _, m := range testDoubleDecl.FindAllString(string(src), -1) {
				t.Errorf("%s declares a test double in production file %s: %q\n%s",
					importPath, f, m, remedy)
			}
		}
	}
}

const remedy = `
	A test double is reachable from a production binary. pkg/issuer raises a
	credential's ComplianceLevel on the mere presence of a working provider, so a
	fake in the link graph can produce a "verified" credential over fabricated
	inputs.

	Move the double into a sibling *test package that no cmd/ binary imports
	(see pkg/spiffe/spiffetest), or into a _test.go file in the package under test.`
