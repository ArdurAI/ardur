// Package spiffe provides SPIFFE/SPIRE integration for VIBAP Layer 1 (Identity).
//
// It defines an IdentityProvider interface abstraction over the SPIRE Workload
// API, enabling testability and future pluggability (e.g., cert-manager SPIFFE
// issuer). The primary implementation connects to a SPIRE agent via the
// go-spiffe/v2 SDK and fetches X.509-SVIDs with automatic rotation.
package spiffe

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// UnverifiedOwnerID is a deployer attribution supplied by configuration.
//
// A SPIFFE Workload API response authenticates the workload SPIFFE ID in its
// SVID. It does not authenticate a second owner/deployer relationship. Keeping
// the owner in a named type forces callers to make that weaker assurance
// explicit instead of treating it as another SPIRE-verified identity.
type UnverifiedOwnerID string

// String returns the configured attribution without upgrading its assurance.
func (id UnverifiedOwnerID) String() string {
	return string(id)
}

// AgentIdentity holds the resolved identity information for a VIBAP agent.
// This is the output of IdentityProvider.FetchIdentity and feeds directly
// into the IdentityClaims of a VIBAP credential (Layer 1).
type AgentIdentity struct {
	// SPIFFE ID of this agent instance (e.g., spiffe://ardur.dev/agent/weather-bot/instance-abc)
	SPIFFEID string

	// Self-asserted SPIFFE-formatted deployer attribution. The Workload API does
	// not prove that this identity owns or approved the workload.
	OwnerID UnverifiedOwnerID

	// Trust domain the agent belongs to (e.g., "ardur.dev")
	TrustDomain string

	// Expiration time of the current SVID
	ExpiresAt time.Time

	// Optional A2A Agent Card URL for inter-agent discovery
	A2ACardRef string
}

// RotationCallback is invoked when the agent's SVID is rotated by SPIRE.
type RotationCallback func(newIdentity *AgentIdentity)

// IdentityProvider abstracts the workload identity source for VIBAP.
// The primary implementation uses SPIRE via go-spiffe/v2, but the interface
// enables mock providers for testing and alternative SPIFFE implementations.
type IdentityProvider interface {
	// FetchIdentity retrieves the current agent identity from the identity source.
	// Returns the SPIFFE ID, trust domain, SVID expiration, and any error.
	FetchIdentity(ctx context.Context) (*AgentIdentity, error)

	// WatchRotation starts watching for SVID rotation events.
	// The callback is invoked each time the SVID is rotated.
	// This method blocks until the context is canceled.
	WatchRotation(ctx context.Context, callback RotationCallback) error

	// Close releases resources held by the identity provider.
	Close() error
}

// ValidateSPIFFEID checks that a string is a well-formed SPIFFE ID per the
// SPIFFE specification (RFC-style: spiffe://<trust-domain>/<path>).
// Returns the trust domain and path, or an error if malformed.
func ValidateSPIFFEID(id string) (trustDomain, path string, err error) {
	if id == "" {
		return "", "", fmt.Errorf("SPIFFE ID is empty")
	}

	// SPIFFE spec mandates max 2048 bytes
	if len(id) > 2048 {
		return "", "", fmt.Errorf("SPIFFE ID exceeds 2048-byte maximum length (%d bytes)", len(id))
	}

	u, err := url.Parse(id)
	if err != nil {
		return "", "", fmt.Errorf("invalid SPIFFE ID URL: %w", err)
	}

	if u.Scheme != "spiffe" {
		return "", "", fmt.Errorf("SPIFFE ID scheme must be 'spiffe', got %q", u.Scheme)
	}

	if u.Host == "" {
		return "", "", fmt.Errorf("SPIFFE ID must have a trust domain (host)")
	}

	if u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("SPIFFE ID must not contain query or fragment")
	}

	if u.User != nil {
		return "", "", fmt.Errorf("SPIFFE ID must not contain userinfo")
	}

	td := u.Host
	if strings.Contains(td, ":") {
		return "", "", fmt.Errorf("SPIFFE ID trust domain must not contain port")
	}

	p := u.Path
	if p == "" {
		p = "/"
	}

	if strings.Contains(p, "//") {
		return "", "", fmt.Errorf("SPIFFE ID path must not contain empty segments (double slashes)")
	}

	return td, p, nil
}
