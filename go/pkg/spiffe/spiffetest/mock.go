// Package spiffetest provides test doubles for the SPIFFE identity layer.
//
// It lives in its own package, separate from pkg/spiffe, so that a fake
// identity provider cannot be linked into a production binary. That matters
// because pkg/issuer treats "an IdentityProvider is configured and returned no
// error" as proof that a workload identity came from SPIRE, and raises the
// credential's compliance level accordingly. A mock reachable from cmd/ would
// let a fabricated SPIFFE ID earn that treatment.
//
// go/internal/linkgraph enforces the separation: its architecture test fails
// if this package, or any exported Mock/Fake/Stub/Dummy symbol in a non-test
// file, becomes reachable from a binary under cmd/.
package spiffetest

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/spiffe"
)

// MockIdentityProvider implements spiffe.IdentityProvider for testing.
// It returns preconfigured identities and simulates SVID rotation.
type MockIdentityProvider struct {
	mu       sync.RWMutex
	identity *spiffe.AgentIdentity
	closed   bool
	rotateC  chan struct{}
}

// MockIdentityProviderOptions configures a MockIdentityProvider.
type MockIdentityProviderOptions struct {
	SPIFFEID string
	// OwnerID is self-asserted attribution, matching SPIREClient behavior.
	OwnerID     string
	TrustDomain string
	ExpiresAt   time.Time
	A2ACardRef  string
}

// NewMockIdentityProvider creates a mock identity provider for testing.
func NewMockIdentityProvider(opts MockIdentityProviderOptions) *MockIdentityProvider {
	if opts.ExpiresAt.IsZero() {
		opts.ExpiresAt = time.Now().Add(1 * time.Hour)
	}
	if opts.TrustDomain == "" {
		opts.TrustDomain = "ardur.dev"
	}
	if opts.SPIFFEID == "" {
		opts.SPIFFEID = fmt.Sprintf("spiffe://%s/agent/test/instance-mock", opts.TrustDomain)
	}

	return &MockIdentityProvider{
		identity: &spiffe.AgentIdentity{
			SPIFFEID:    opts.SPIFFEID,
			OwnerID:     spiffe.UnverifiedOwnerID(opts.OwnerID),
			TrustDomain: opts.TrustDomain,
			ExpiresAt:   opts.ExpiresAt,
			A2ACardRef:  opts.A2ACardRef,
		},
		rotateC: make(chan struct{}, 1),
	}
}

// FetchIdentity returns the preconfigured mock identity.
func (m *MockIdentityProvider) FetchIdentity(_ context.Context) (*spiffe.AgentIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("mock provider is closed")
	}

	id := *m.identity
	return &id, nil
}

// WatchRotation blocks until SimulateRotation is called or the context is canceled.
func (m *MockIdentityProvider) WatchRotation(ctx context.Context, callback spiffe.RotationCallback) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.rotateC:
			m.mu.RLock()
			id := *m.identity
			m.mu.RUnlock()
			callback(&id)
		}
	}
}

// SimulateRotation triggers a rotation event with a new identity.
func (m *MockIdentityProvider) SimulateRotation(newIdentity *spiffe.AgentIdentity) {
	m.mu.Lock()
	m.identity = newIdentity
	m.mu.Unlock()

	select {
	case m.rotateC <- struct{}{}:
	default:
	}
}

// Close marks the mock provider as closed.
func (m *MockIdentityProvider) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// compile-time interface check
var _ spiffe.IdentityProvider = (*MockIdentityProvider)(nil)
