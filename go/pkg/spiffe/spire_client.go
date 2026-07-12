package spiffe

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Sentinel errors for the spiffe package.
var (
	ErrClosed        = errors.New("identity provider is closed")
	ErrInvalidSPIFFE = errors.New("invalid SPIFFE ID")
	ErrNoOwnerID     = errors.New("owner_id is required as self-asserted attribution")
)

// SPIREClient implements IdentityProvider using the SPIRE Workload API.
// It connects to a SPIRE agent via Unix socket and fetches X.509-SVIDs
// with automatic rotation support.
type SPIREClient struct {
	source *workloadapi.X509Source
	mu     sync.RWMutex
	closed bool

	// ownerID is self-asserted deployer attribution passed at construction.
	// SPIRE authenticates the workload SVID, not this ownership relation.
	ownerID UnverifiedOwnerID

	// a2aCardRef is the optional A2A Agent Card URL.
	a2aCardRef string
}

// SPIREClientOptions configures a SPIREClient.
type SPIREClientOptions struct {
	// AgentSocketPath is the path to the SPIRE agent Unix socket.
	// If empty, the SPIFFE_ENDPOINT_SOCKET env var is used.
	AgentSocketPath string

	// OwnerID is required SPIFFE-formatted deployer attribution. It is
	// self-asserted and is not verified by the SPIRE Workload API.
	OwnerID string

	// A2ACardRef is the optional A2A Agent Card URL.
	A2ACardRef string
}

// NewSPIREClient creates a new SPIRE-backed identity provider.
// It connects to the SPIRE agent and blocks until the first SVID is received.
// Pass a context with timeout to avoid blocking indefinitely if the agent is down.
func NewSPIREClient(ctx context.Context, opts SPIREClientOptions) (*SPIREClient, error) {
	if opts.OwnerID == "" {
		return nil, ErrNoOwnerID
	}
	if _, _, err := ValidateSPIFFEID(opts.OwnerID); err != nil {
		return nil, fmt.Errorf("invalid owner_id: %w", err)
	}

	var clientOpts []workloadapi.X509SourceOption
	if opts.AgentSocketPath != "" {
		clientOpts = append(clientOpts,
			workloadapi.WithClientOptions(
				workloadapi.WithAddr("unix://"+opts.AgentSocketPath),
			),
		)
	}

	source, err := workloadapi.NewX509Source(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create X509Source: %w", err)
	}

	return &SPIREClient{
		source:     source,
		ownerID:    UnverifiedOwnerID(opts.OwnerID),
		a2aCardRef: opts.A2ACardRef,
	}, nil
}

// FetchIdentity retrieves the current agent identity from SPIRE.
func (c *SPIREClient) FetchIdentity(ctx context.Context) (*AgentIdentity, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, fmt.Errorf("SPIRE client is closed")
	}

	svid, err := c.source.GetX509SVID()
	if err != nil {
		return nil, fmt.Errorf("failed to get X509-SVID: %w", err)
	}

	return c.svidToIdentity(svid)
}

// WatchRotation starts watching for SVID rotation events.
// Blocks until the context is canceled or the client is closed.
func (c *SPIREClient) WatchRotation(ctx context.Context, callback RotationCallback) error {
	for {
		c.mu.RLock()
		closed := c.closed
		c.mu.RUnlock()
		if closed {
			return ErrClosed
		}

		err := c.source.WaitUntilUpdated(ctx)
		if err != nil {
			return err
		}

		c.mu.RLock()
		if c.closed {
			c.mu.RUnlock()
			return ErrClosed
		}
		svid, err := c.source.GetX509SVID()
		c.mu.RUnlock()
		if err != nil {
			continue
		}

		identity, err := c.svidToIdentity(svid)
		if err != nil {
			continue
		}

		callback(identity)
	}
}

// Close releases the SPIRE connection and resources.
func (c *SPIREClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true
	return c.source.Close()
}

func (c *SPIREClient) svidToIdentity(svid *x509svid.SVID) (*AgentIdentity, error) {
	if len(svid.Certificates) == 0 {
		return nil, fmt.Errorf("SVID has no certificates")
	}

	id := svid.ID
	leaf := svid.Certificates[0]

	return &AgentIdentity{
		SPIFFEID:    id.String(),
		OwnerID:     c.ownerID,
		TrustDomain: id.TrustDomain().Name(),
		ExpiresAt:   leaf.NotAfter,
		A2ACardRef:  c.a2aCardRef,
	}, nil
}
