//go:build !linux

package main

import (
	"fmt"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

func observeRootBootstrapFiles(rootPID uint32) ([]kernelcapture.BootstrapFile, error) {
	return nil, fmt.Errorf("process bootstrap observation is unavailable for pid %d on this platform", rootPID)
}
