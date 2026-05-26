//go:build !linux

package kernelcapture

import (
	"errors"
	"testing"
)

func TestObserveLinuxUnixPeerCredentialsUnsupportedPlatformsFailClosed(t *testing.T) {
	t.Parallel()

	_, err := ObserveLinuxUnixPeerCredentials(nil, "/run/ardur/kernelcapture/control.sock")
	if err == nil {
		t.Fatalf("expected unsupported-platform error")
	}
	if !errors.Is(err, ErrDaemonPeerCredentialRetrieval) {
		t.Fatalf("expected ErrDaemonPeerCredentialRetrieval, got %v", err)
	}
}
