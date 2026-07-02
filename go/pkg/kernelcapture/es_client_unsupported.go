//go:build !darwin

package kernelcapture

// es_client_unsupported.go lets InspectEndpointSecurityPreflight be called
// unconditionally from cross-platform callers (ardur-sensor preflight) the
// same way CheckKernelCapabilities and InspectBPFLSMPreflight already are.
// Endpoint Security itself (ESClient/NewESClient, es_client_darwin.go) has no
// non-Darwin callers, so no stub is needed for those.

// InspectEndpointSecurityPreflight reports "not applicable" on non-Darwin
// platforms — Endpoint Security is a macOS-only capability, unlike the
// BPF-LSM check (InspectBPFLSMPreflight) which fails informatively on any
// platform lacking BTF/BPF-LSM. Reporting Pass here (rather than Fail) is
// deliberate: a Linux host not having an ES entitlement is not a
// misconfiguration to flag, it is simply the wrong framework for that OS.
func InspectEndpointSecurityPreflight() DaemonPreflightReport {
	return DaemonPreflightReport{
		Mode: "endpoint_security_capability_check",
		Findings: []DaemonPreflightFinding{
			{
				CheckName: "es_client_entitlement",
				Verdict:   DaemonPreflightVerdictPass,
				Details:   "not applicable on this platform (Endpoint Security is macOS-only)",
			},
		},
		CanContinue: true,
	}
}
