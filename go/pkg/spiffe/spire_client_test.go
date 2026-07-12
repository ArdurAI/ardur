package spiffe

import (
	"context"
	"crypto/x509"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func TestNewSPIREClientRejectsMissingOwner(t *testing.T) {
	_, err := NewSPIREClient(context.Background(), SPIREClientOptions{})
	if err == nil {
		t.Fatal("NewSPIREClient() should reject a missing owner ID before dialing SPIRE")
	}
	if !strings.Contains(err.Error(), "owner_id is required") {
		t.Fatalf("NewSPIREClient() error = %q", err.Error())
	}
}

func TestNewSPIREClientRejectsInvalidOwner(t *testing.T) {
	_, err := NewSPIREClient(
		context.Background(),
		SPIREClientOptions{OwnerID: "https://example.org/not-spiffe"},
	)
	if err == nil {
		t.Fatal("NewSPIREClient() should reject an invalid owner ID before dialing SPIRE")
	}
	if !strings.Contains(err.Error(), "invalid owner_id") {
		t.Fatalf("NewSPIREClient() error = %q", err.Error())
	}
}

func TestSPIREClientSVIDToIdentityRejectsEmptyCertificateChain(t *testing.T) {
	id := spiffeid.RequireFromString("spiffe://example.org/ns/default/sa/agent")
	client := &SPIREClient{ownerID: "spiffe://example.org/owner/alice"}

	_, err := client.svidToIdentity(&x509svid.SVID{ID: id})
	if err == nil {
		t.Fatal("svidToIdentity() should reject an empty certificate chain")
	}
	if !strings.Contains(err.Error(), "no certificates") {
		t.Fatalf("svidToIdentity() error = %q", err.Error())
	}
}

func TestSPIREClientSVIDToIdentityMapsCertificateMetadata(t *testing.T) {
	id := spiffeid.RequireFromString("spiffe://example.org/ns/default/sa/agent")
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	client := &SPIREClient{
		ownerID:    "spiffe://example.org/owner/alice",
		a2aCardRef: "https://agents.example.org/cards/agent.json",
	}

	identity, err := client.svidToIdentity(&x509svid.SVID{
		ID:           id,
		Certificates: []*x509.Certificate{{NotAfter: expires}},
	})
	if err != nil {
		t.Fatalf("svidToIdentity() error = %v", err)
	}
	if identity.SPIFFEID != id.String() {
		t.Fatalf("SPIFFEID = %q, want %q", identity.SPIFFEID, id.String())
	}
	if identity.OwnerID != client.ownerID {
		t.Fatalf("OwnerID = %q, want %q", identity.OwnerID, client.ownerID)
	}
	if got := reflect.TypeOf(identity.OwnerID).Name(); got != "UnverifiedOwnerID" {
		t.Fatalf("OwnerID type = %q, want UnverifiedOwnerID", got)
	}
	if identity.TrustDomain != "example.org" {
		t.Fatalf("TrustDomain = %q, want example.org", identity.TrustDomain)
	}
	if !identity.ExpiresAt.Equal(expires) {
		t.Fatalf("ExpiresAt = %s, want %s", identity.ExpiresAt, expires)
	}
	if identity.A2ACardRef != client.a2aCardRef {
		t.Fatalf("A2ACardRef = %q, want %q", identity.A2ACardRef, client.a2aCardRef)
	}
}
