//go:build !linux

package main

import (
	"fmt"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

func loadAgentFingerprintRegistry(string, uint32) (*kernelcapture.AgentFingerprintRegistry, error) {
	return nil, fmt.Errorf("agent fingerprint registries are supported only on Linux")
}
