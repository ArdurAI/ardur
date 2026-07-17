//go:build !linux

package kernelcapture

import "context"

type unsupportedAgentFingerprintResolver struct{}

type unsupportedAgentFingerprintTarget struct{}

func newPlatformAgentFingerprintResolver() agentFingerprintResolver {
	return unsupportedAgentFingerprintResolver{}
}

func (unsupportedAgentFingerprintResolver) Bind(uint32) (agentFingerprintTarget, string) {
	return nil, AgentFingerprintOutcomeUnsupported
}

func (unsupportedAgentFingerprintResolver) Resolve(context.Context, agentFingerprintTarget, int64) (agentFingerprintDigest, string) {
	return agentFingerprintDigest{}, AgentFingerprintOutcomeUnsupported
}

func (unsupportedAgentFingerprintTarget) Close() error { return nil }
