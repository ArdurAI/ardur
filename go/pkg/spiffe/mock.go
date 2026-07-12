package spiffe

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MockIdentityProvider implements IdentityProvider for testing.
// It returns preconfigured identities and simulates SVID rotation.
type MockIdentityProvider struct {
	mu       sync.RWMutex
	identity *AgentIdentity
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
		identity: &AgentIdentity{
			SPIFFEID:    opts.SPIFFEID,
			OwnerID:     UnverifiedOwnerID(opts.OwnerID),
			TrustDomain: opts.TrustDomain,
			ExpiresAt:   opts.ExpiresAt,
			A2ACardRef:  opts.A2ACardRef,
		},
		rotateC: make(chan struct{}, 1),
	}
}

// FetchIdentity returns the preconfigured mock identity.
func (m *MockIdentityProvider) FetchIdentity(_ context.Context) (*AgentIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("mock provider is closed")
	}

	id := *m.identity
	return &id, nil
}

// WatchRotation blocks until SimulateRotation is called or the context is canceled.
func (m *MockIdentityProvider) WatchRotation(ctx context.Context, callback RotationCallback) error {
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
func (m *MockIdentityProvider) SimulateRotation(newIdentity *AgentIdentity) {
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
var _ IdentityProvider = (*MockIdentityProvider)(nil)
