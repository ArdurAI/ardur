//go:build darwin

package kernelcapture

// es_client_darwin.go — Endpoint Security client scaffold (Epic A #63,
// Slice 2 remainder).
//
// macOS has no eBPF. The kernel-level visibility the Linux daemon gets from
// process_exec.bpf.c / process_guard.bpf.c (exec/exit tracepoints, BPF-LSM
// enforcement hooks) has one macOS equivalent: the Endpoint Security
// framework (ES), consumed via a System Extension — see
// packaging/macos/systemextension/ for the extension bundle skeleton.
//
// Claim boundary — what THIS FILE does:
//   - Defines ESClient, the Go-side interface a real ES-backed event source
//     would satisfy, shaped to match ProcessSource's pull-based Next
//     (ringbuf_source_linux.go) so the daemon's consumption loop
//     (runEBPFConsumer's shape) does not need a macOS-specific branch once
//     this is wired for real.
//   - InspectEndpointSecurityPreflight: a genuine, read-only check of whether
//     this binary's code signature currently carries
//     EndpointSecurityEntitlement (shells out to `codesign`, no cgo).
//
// What this file does NOT do (out of scope for this slice, and the reason
// NewESClient always fails):
//   - Call es_new_client() / es_subscribe() (EndpointSecurity.framework).
//     Doing so requires cgo linkage against Security.framework/
//     EndpointSecurity.framework and, per Apple's design, es_new_client()
//     itself refuses to run without EndpointSecurityEntitlement — so a real
//     binding here would be dead code until the entitlement is granted, with
//     no way to test it in this environment either way. NewESClient's single
//     call site (runEBPFConsumer, daemon_darwin.go) is where the real
//     binding plugs in once that happens.
//   - Activate or manage the System Extension bundle. That is an
//     OS-level installation step (systemextensionsctl / SMAppService),
//     entirely separate from this Go process.
//
// Tracking: requesting EndpointSecurityEntitlement from Apple for the
// ardur-kernelcaptured code-signing identity is filed as a tracking issue
// referenced from the PR that introduced this file — see EndpointSecurityEntitlement's
// doc comment for what to request.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// EndpointSecurityEntitlement is the code-signing entitlement Apple must
// grant before es_new_client() will succeed for this binary. Request it via
// https://developer.apple.com/contact/request/system-extension/ (Endpoint
// Security extension request form) for the ardur-kernelcaptured code-signing
// identity; see Apple's TN3138 for background on the approval process.
const EndpointSecurityEntitlement = "com.apple.developer.endpoint-security.client"

// ErrEndpointSecurityUnavailable is returned by NewESClient until the running
// binary's code signature carries EndpointSecurityEntitlement.
var ErrEndpointSecurityUnavailable = errors.New("kernelcapture: endpoint security client unavailable (entitlement not granted)")

// ESClient streams process-lifecycle events observed via Endpoint Security,
// projected into the same ProcessEvent shape the Linux eBPF exec/exit
// tracepoint consumer produces (types.go), so the daemon's correlation and
// evidence-writing code needs no macOS-specific branch once this is wired for
// real.
type ESClient interface {
	// Next blocks until the next process event is available, ctx is done, or
	// the client is closed.
	Next(ctx context.Context) (ProcessEvent, bool, error)
	Close() error
}

// NewESClient always returns ErrEndpointSecurityUnavailable today — see this
// file's header comment for why a real es_new_client() binding is deferred
// rather than half-implemented here.
func NewESClient() (ESClient, error) {
	return nil, ErrEndpointSecurityUnavailable
}

// InspectEndpointSecurityPreflight checks whether this binary's code
// signature carries EndpointSecurityEntitlement, using the same
// DaemonPreflightFinding shape InspectBPFLSMPreflight (Linux) uses so callers
// can render both uniformly. Read-only: never loads the ES framework,
// subscribes to any event, or touches kernel/EndpointSecurity state.
//
// Detection shells out to `codesign -d --entitlements :-` against the
// currently running executable rather than linking Security.framework via
// cgo — that keeps this package cgo-free (no Xcode toolchain requirement to
// build/test it) at the cost of requiring `codesign` on PATH, which ships
// with every macOS install.
func InspectEndpointSecurityPreflight() DaemonPreflightReport {
	report := DaemonPreflightReport{
		Mode: "endpoint_security_capability_check",
		WorksNow: []string{
			"read-only code-signing entitlement inspection",
		},
		NotClaimed: []string{
			"Endpoint Security client creation or event subscription",
			"System Extension activation",
		},
	}

	finding := DaemonPreflightFinding{CheckName: "es_client_entitlement"}
	exe, err := os.Executable()
	if err != nil {
		finding.Verdict = DaemonPreflightVerdictFail
		finding.Details = fmt.Sprintf("resolve running executable: %v", err)
		finding.Remediation = "unexpected: os.Executable() failed"
		report.Findings = append(report.Findings, finding)
		report.CanContinue = false
		return report
	}
	finding.Path = exe

	entitled, checkErr := binaryHasEndpointSecurityEntitlement(exe)
	switch {
	case checkErr != nil:
		finding.Verdict = DaemonPreflightVerdictWarn
		finding.Details = fmt.Sprintf("entitlement check failed: %v", checkErr)
		finding.Remediation = "ensure `codesign` is on PATH and the binary is code-signed"
	case entitled:
		finding.Verdict = DaemonPreflightVerdictPass
		finding.Details = EndpointSecurityEntitlement + " is present in the code signature"
	default:
		finding.Verdict = DaemonPreflightVerdictFail
		finding.Details = EndpointSecurityEntitlement + " is not present in the code signature"
		finding.Remediation = "request the entitlement from Apple (see EndpointSecurityEntitlement doc comment); until granted, ardur-kernelcaptured runs control-plane-only on macOS"
	}
	report.Findings = append(report.Findings, finding)

	report.CanContinue = true
	for _, f := range report.Findings {
		if f.Verdict == DaemonPreflightVerdictFail {
			report.CanContinue = false
		}
	}
	return report
}

// binaryHasEndpointSecurityEntitlement shells out to codesign to read back
// the entitlements embedded in path's code signature. An unsigned or
// ad-hoc-signed binary (the common local-dev case) makes codesign exit
// non-zero — that is reported as "not entitled" (false, nil), not an error;
// only a codesign invocation failure (missing binary, not on PATH) is an
// error.
func binaryHasEndpointSecurityEntitlement(path string) (bool, error) {
	cmd := exec.Command("codesign", "-d", "--entitlements", ":-", path)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return false, nil
		}
		return false, fmt.Errorf("run codesign: %w", err)
	}
	return strings.Contains(string(out), EndpointSecurityEntitlement), nil
}
