//go:build !linux

package kernelcapture

import "context"

type unsupportedAgentFingerprintResolver struct{}

type unsupportedAgentFingerprintTarget struct{}

func newPlatformAgentFingerprintResolver() agentFingerprintResolver {
	return unsupportedAgentFingerprintResolver{}
}

func (unsupportedAgentFingerprintResolver) Bind(ProcessEvent) (agentFingerprintTarget, string) {
	return nil, AgentFingerprintOutcomeUnsupported
}

func (unsupportedAgentFingerprintResolver) Resolve(context.Context, agentFingerprintTarget, agentFingerprintResolveLimits) (agentFingerprintDigest, string) {
	return agentFingerprintDigest{}, AgentFingerprintOutcomeUnsupported
}

func (unsupportedAgentFingerprintTarget) Close() error { return nil }
