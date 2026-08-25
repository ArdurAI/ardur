//go:build darwin

package kernelcapture

import (
	"context"
	"errors"
	"testing"
)

func TestNewESClient_AlwaysUnavailable(t *testing.T) {
	t.Parallel()
	client, err := NewESClient()
	if client != nil {
		t.Fatalf("expected nil client, got %#v", client)
	}
	if !errors.Is(err, ErrEndpointSecurityUnavailable) {
		t.Fatalf("err = %v, want ErrEndpointSecurityUnavailable", err)
	}
}

// TestESClient_InterfaceShapeMatchesProcessSource is a compile-time-flavored
// check that ESClient's Next signature mirrors RingbufProcessSource.Next
// closely enough that a future consumption loop can treat both uniformly
// (modulo the SessionScope filtering parameter, which is ES-inapplicable —
// ES event delivery is already scoped by subscription, not a post-hoc filter).
func TestESClient_InterfaceShapeMatchesProcessSource(t *testing.T) {
	t.Parallel()
	var _ ESClient = (*fakeESClient)(nil)
}

type fakeESClient struct{}

func (fakeESClient) Next(_ context.Context) (ProcessEvent, bool, error) {
	return ProcessEvent{}, false, nil
}
func (fakeESClient) Close() error { return nil }

func TestInspectEndpointSecurityPreflight_ReportsAFinding(t *testing.T) {
	t.Parallel()
	report := InspectEndpointSecurityPreflight()
	if len(report.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(report.Findings), report.Findings)
	}
	f := report.Findings[0]
	if f.CheckName != "es_client_entitlement" {
		t.Fatalf("CheckName = %q, want es_client_entitlement", f.CheckName)
	}
	if f.Path == "" {
		t.Fatal("expected Path to be set to the running executable")
	}
	switch f.Verdict {
	case DaemonPreflightVerdictPass, DaemonPreflightVerdictFail, DaemonPreflightVerdictWarn:
		// any of these is a legitimate outcome depending on how the test
		// binary itself is signed in this environment.
	default:
		t.Fatalf("unexpected verdict %q", f.Verdict)
	}
	if f.Details == "" {
		t.Fatal("expected Details to be populated")
	}
	// go test binaries are not code-signed with the ES entitlement in any CI
	// or local dev environment, so this must not report CanContinue=true via
	// a false-positive Pass.
	if f.Verdict == DaemonPreflightVerdictPass {
		t.Fatalf("unexpected Pass verdict for an unentitled go test binary: %+v", f)
	}
}

func TestBinaryHasEndpointSecurityEntitlement_UnsignedTestBinaryIsFalse(t *testing.T) {
	t.Parallel()
	entitled, err := binaryHasEndpointSecurityEntitlement(t.TempDir() + "/does-not-exist")
	if err == nil && entitled {
		t.Fatal("expected a nonexistent path to never report entitled=true")
	}
}
