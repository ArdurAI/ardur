package spiffetest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/spiffe"
)

func TestMockIdentityProvider_FetchIdentity(t *testing.T) {
	mock := NewMockIdentityProvider(MockIdentityProviderOptions{
		SPIFFEID:    "spiffe://ardur.dev/agent/test/instance-001",
		OwnerID:     "spiffe://ardur.dev/user/deployer",
		TrustDomain: "ardur.dev",
	})
	defer mock.Close()

	ctx := context.Background()
	identity, err := mock.FetchIdentity(ctx)
	if err != nil {
		t.Fatalf("FetchIdentity() error = %v", err)
	}

	if identity.SPIFFEID != "spiffe://ardur.dev/agent/test/instance-001" {
		t.Errorf("SPIFFEID = %q, want %q", identity.SPIFFEID, "spiffe://ardur.dev/agent/test/instance-001")
	}
	if identity.OwnerID != "spiffe://ardur.dev/user/deployer" {
		t.Errorf("OwnerID = %q, want %q", identity.OwnerID, "spiffe://ardur.dev/user/deployer")
	}
	if identity.TrustDomain != "ardur.dev" {
		t.Errorf("TrustDomain = %q, want %q", identity.TrustDomain, "ardur.dev")
	}
}

func TestMockIdentityProvider_FetchAfterClose(t *testing.T) {
	mock := NewMockIdentityProvider(MockIdentityProviderOptions{})
	mock.Close()

	_, err := mock.FetchIdentity(context.Background())
	if err == nil {
		t.Fatal("FetchIdentity() after Close() should return error")
	}
}

func TestMockIdentityProvider_WatchRotation(t *testing.T) {
	mock := NewMockIdentityProvider(MockIdentityProviderOptions{
		SPIFFEID: "spiffe://ardur.dev/agent/v1",
	})
	defer mock.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var received *spiffe.AgentIdentity
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		_ = mock.WatchRotation(ctx, func(newIdentity *spiffe.AgentIdentity) {
			received = newIdentity
			wg.Done()
			cancel()
		})
	}()

	time.Sleep(50 * time.Millisecond)

	mock.SimulateRotation(&spiffe.AgentIdentity{
		SPIFFEID:    "spiffe://ardur.dev/agent/v2",
		TrustDomain: "ardur.dev",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})

	wg.Wait()

	if received == nil {
		t.Fatal("callback was never invoked")
	}
	if received.SPIFFEID != "spiffe://ardur.dev/agent/v2" {
		t.Errorf("rotated SPIFFEID = %q, want v2", received.SPIFFEID)
	}
}

func TestMockIdentityProvider_DefaultValues(t *testing.T) {
	mock := NewMockIdentityProvider(MockIdentityProviderOptions{})
	defer mock.Close()

	identity, err := mock.FetchIdentity(context.Background())
	if err != nil {
		t.Fatalf("FetchIdentity() error = %v", err)
	}

	if identity.TrustDomain != "ardur.dev" {
		t.Errorf("default TrustDomain = %q, want ardur.dev", identity.TrustDomain)
	}
	if identity.SPIFFEID == "" {
		t.Error("default SPIFFEID should not be empty")
	}
	if identity.ExpiresAt.IsZero() {
		t.Error("default ExpiresAt should not be zero")
	}
}

func TestMockIdentityProvider_SimulateRotationThenFetchIdentity(t *testing.T) {
	mock := NewMockIdentityProvider(MockIdentityProviderOptions{
		SPIFFEID: "spiffe://ardur.dev/agent/v1",
	})
	defer mock.Close()

	// Initial FetchIdentity returns v1
	ctx := context.Background()
	id1, err := mock.FetchIdentity(ctx)
	if err != nil {
		t.Fatalf("FetchIdentity() error = %v", err)
	}
	if id1.SPIFFEID != "spiffe://ardur.dev/agent/v1" {
		t.Errorf("initial SPIFFEID = %q, want v1", id1.SPIFFEID)
	}

	// Simulate rotation to v2
	newID := &spiffe.AgentIdentity{
		SPIFFEID:    "spiffe://ardur.dev/agent/v2",
		TrustDomain: "ardur.dev",
		ExpiresAt:   time.Now().Add(2 * time.Hour),
	}
	mock.SimulateRotation(newID)

	// FetchIdentity now returns v2
	id2, err := mock.FetchIdentity(ctx)
	if err != nil {
		t.Fatalf("FetchIdentity() after rotation error = %v", err)
	}
	if id2.SPIFFEID != "spiffe://ardur.dev/agent/v2" {
		t.Errorf("after rotation SPIFFEID = %q, want v2", id2.SPIFFEID)
	}
	if id2.ExpiresAt != newID.ExpiresAt {
		t.Errorf("ExpiresAt = %v, want %v", id2.ExpiresAt, newID.ExpiresAt)
	}
}

func TestMockIdentityProvider_CustomExpiresAtAndA2ACardRef(t *testing.T) {
	expiresAt := time.Now().Add(30 * time.Minute)
	a2aRef := "https://agentgateway.example.com/cards/weather-bot"
	mock := NewMockIdentityProvider(MockIdentityProviderOptions{
		SPIFFEID:    "spiffe://ardur.dev/agent/custom",
		TrustDomain: "ardur.dev",
		ExpiresAt:   expiresAt,
		A2ACardRef:  a2aRef,
	})
	defer mock.Close()

	identity, err := mock.FetchIdentity(context.Background())
	if err != nil {
		t.Fatalf("FetchIdentity() error = %v", err)
	}
	if !identity.ExpiresAt.Equal(expiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", identity.ExpiresAt, expiresAt)
	}
	if identity.A2ACardRef != a2aRef {
		t.Errorf("A2ACardRef = %q, want %q", identity.A2ACardRef, a2aRef)
	}
}
