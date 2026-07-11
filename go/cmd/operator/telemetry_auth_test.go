package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ArdurAI/ardur/go/pkg/trust"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func TestTelemetrySourceBindings(t *testing.T) {
	var bindings telemetrySourceBindings
	if err := bindings.Set("verifier=spiffe://ardur.dev/ns/ardur/sa/verifier"); err != nil {
		t.Fatal(err)
	}
	if err := bindings.Set("tetragon=spiffe://ardur.dev/ns/kube-system/sa/tetragon"); err != nil {
		t.Fatal(err)
	}
	if got, want := bindings.String(), "tetragon=spiffe://ardur.dev/ns/kube-system/sa/tetragon,verifier=spiffe://ardur.dev/ns/ardur/sa/verifier"; got != want {
		t.Fatalf("bindings.String() = %q, want %q", got, want)
	}
	ids := bindings.spiffeIDs()
	if len(ids) != 2 || ids[0].String() != "spiffe://ardur.dev/ns/kube-system/sa/tetragon" {
		t.Fatalf("spiffeIDs() = %v, want deterministic source order", ids)
	}
}

func TestTelemetrySourceBindingsRejectInvalidAndDuplicateEntries(t *testing.T) {
	tests := []struct {
		name   string
		values []string
	}{
		{name: "missing separator", values: []string{"verifier"}},
		{name: "invalid source", values: []string{"bad source=spiffe://ardur.dev/verifier"}},
		{name: "confusable source", values: []string{"verifi\u0435r=spiffe://ardur.dev/verifier"}},
		{name: "invalid ID", values: []string{"verifier=https://ardur.dev/verifier"}},
		{name: "duplicate source", values: []string{"verifier=spiffe://ardur.dev/a", "verifier=spiffe://ardur.dev/b"}},
		{name: "duplicate identity", values: []string{"verifier=spiffe://ardur.dev/a", "tetragon=spiffe://ardur.dev/a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bindings telemetrySourceBindings
			var err error
			for _, value := range tt.values {
				if err = bindings.Set(value); err != nil {
					break
				}
			}
			if err == nil {
				t.Fatalf("Set(%v) succeeded, want error", tt.values)
			}
		})
	}
}

func TestTelemetrySourceAuthorization(t *testing.T) {
	ca, caKey := newTestCA(t)
	verifierID := spiffeid.RequireFromString("spiffe://ardur.dev/ns/ardur/sa/verifier")
	tetragonID := spiffeid.RequireFromString("spiffe://ardur.dev/ns/kube-system/sa/tetragon")
	verifier := newTestSVID(t, verifierID, ca, caKey, 2)
	tetragon := newTestSVID(t, tetragonID, ca, caKey, 3)
	malformed := *verifier
	malformedCert := *verifier.Certificates[0]
	malformedCert.URIs = nil
	malformed.Certificates = []*x509.Certificate{&malformedCert}
	bindings := telemetrySourceBindings{"verifier": verifierID}

	tests := []struct {
		name   string
		tls    *tlsState
		source string
		want   error
	}{
		{name: "no TLS", source: "verifier", want: errTelemetryUnauthenticated},
		{name: "certificate without SPIFFE URI", tls: peerTLS(&malformed), source: "verifier", want: errTelemetryUnauthenticated},
		{name: "matching identity and source", tls: peerTLS(verifier), source: "verifier"},
		{name: "configured identity wrong source", tls: peerTLS(verifier), source: "tetragon", want: errTelemetryUnauthorized},
		{name: "unknown identity", tls: peerTLS(tetragon), source: "verifier", want: errTelemetryUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/telemetry/signal", nil)
			if tt.tls != nil {
				req.TLS = tt.tls.state
			}
			err := bindings.authorize(req, telemetryRequest{Source: tt.source})
			if tt.want == nil && err != nil {
				t.Fatalf("authorize() error = %v", err)
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("authorize() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestAuthenticatedTelemetryIngestorStatusBoundaries(t *testing.T) {
	ca, caKey := newTestCA(t)
	verifierID := spiffeid.RequireFromString("spiffe://ardur.dev/ns/ardur/sa/verifier")
	verifier := newTestSVID(t, verifierID, ca, caKey, 4)
	bindings := telemetrySourceBindings{"verifier": verifierID}

	agg, err := trust.NewInMemoryAggregator()
	if err != nil {
		t.Fatal(err)
	}
	defer agg.Close()
	if err := agg.RegisterAgent(context.Background(), "test-agent", 0.8, 0.8); err != nil {
		t.Fatal(err)
	}
	h := newTelemetryIngestor(agg, nil, bindings.authorize)

	body := telemetryRequest{
		AgentID:  "test-agent",
		Type:     string(trust.SignalCleanInterval),
		Severity: string(trust.SeverityInfo),
		Source:   "verifier",
	}
	if got := postAuthenticatedSignal(t, h, body, nil).Code; got != http.StatusUnauthorized {
		t.Fatalf("request without X509-SVID = %d, want 401", got)
	}
	body.Source = "tetragon"
	if got := postAuthenticatedSignal(t, h, body, verifier).Code; got != http.StatusForbidden {
		t.Fatalf("cross-source request = %d, want 403", got)
	}
	body.Source = "verifier"
	if got := postAuthenticatedSignal(t, h, body, verifier).Code; got != http.StatusOK {
		t.Fatalf("authorized request = %d, want 200", got)
	}
}

func TestTelemetryMTLSHandshakeAndSourceBinding(t *testing.T) {
	ca, caKey := newTestCA(t)
	td := spiffeid.RequireTrustDomainFromString("ardur.dev")
	serverID := spiffeid.RequireFromString("spiffe://ardur.dev/ns/ardur/sa/operator")
	verifierID := spiffeid.RequireFromString("spiffe://ardur.dev/ns/ardur/sa/verifier")
	unknownID := spiffeid.RequireFromString("spiffe://ardur.dev/ns/default/sa/unknown")
	bundle := x509bundle.FromX509Authorities(td, []*x509.Certificate{ca})
	serverSource := staticX509Source{svid: newTestSVID(t, serverID, ca, caKey, 10), bundle: bundle}
	verifierSource := staticX509Source{svid: newTestSVID(t, verifierID, ca, caKey, 11), bundle: bundle}
	unknownSource := staticX509Source{svid: newTestSVID(t, unknownID, ca, caKey, 12), bundle: bundle}
	bindings := telemetrySourceBindings{"verifier": verifierID}

	serverTLS, err := telemetryMTLSConfig(serverSource, bindings)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS.Certificates = []tls.Certificate{tlsCertificateForTest(serverSource.svid)}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := bindings.authorize(r, telemetryRequest{Source: r.Header.Get("X-Test-Source")}); err != nil {
			status := http.StatusForbidden
			if errors.Is(err, errTelemetryUnauthenticated) {
				status = http.StatusUnauthorized
			}
			http.Error(w, http.StatusText(status), status)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()

	verifierClient := server.Client()
	verifierClient.Transport.(*http.Transport).TLSClientConfig = tlsconfig.MTLSClientConfig(
		verifierSource, verifierSource, tlsconfig.AuthorizeID(serverID),
	)
	req, _ := http.NewRequest(http.MethodPost, server.URL, nil)
	req.Header.Set("X-Test-Source", "verifier")
	resp, err := verifierClient.Do(req)
	if err != nil {
		t.Fatalf("authorized mTLS request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("authorized mTLS status = %d, want 204", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodPost, server.URL, nil)
	req.Header.Set("X-Test-Source", "tetragon")
	resp, err = verifierClient.Do(req)
	if err != nil {
		t.Fatalf("cross-source mTLS request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-source mTLS status = %d, want 403", resp.StatusCode)
	}

	unknownClient := server.Client()
	unknownClient.Transport = verifierClient.Transport.(*http.Transport).Clone()
	unknownClient.Transport.(*http.Transport).TLSClientConfig = tlsconfig.MTLSClientConfig(
		unknownSource, unknownSource, tlsconfig.AuthorizeID(serverID),
	)
	if _, err := unknownClient.Post(server.URL, "application/json", nil); err == nil {
		t.Fatal("unknown SPIFFE identity completed mTLS handshake, want rejection")
	}
}

func TestTelemetryMTLSConfigRequiresBindings(t *testing.T) {
	ca, caKey := newTestCA(t)
	td := spiffeid.RequireTrustDomainFromString("ardur.dev")
	serverID := spiffeid.RequireFromString("spiffe://ardur.dev/operator")
	source := staticX509Source{
		svid:   newTestSVID(t, serverID, ca, caKey, 20),
		bundle: x509bundle.FromX509Authorities(td, []*x509.Certificate{ca}),
	}
	if _, err := telemetryMTLSConfig(source, nil); err == nil {
		t.Fatal("telemetryMTLSConfig without bindings succeeded")
	}
}

type staticX509Source struct {
	svid   *x509svid.SVID
	bundle *x509bundle.Bundle
}

func (s staticX509Source) GetX509SVID() (*x509svid.SVID, error) {
	return s.svid, nil
}

func (s staticX509Source) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if s.bundle.TrustDomain() != td {
		return nil, fmt.Errorf("bundle for %s not found", td)
	}
	return s.bundle, nil
}

type tlsState struct {
	state *tls.ConnectionState
}

func peerTLS(svid *x509svid.SVID) *tlsState {
	return &tlsState{state: &tls.ConnectionState{PeerCertificates: svid.Certificates}}
}

func postAuthenticatedSignal(t *testing.T, h http.Handler, body telemetryRequest, peer *x509svid.SVID) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/telemetry/signal", bytes.NewReader(b))
	if peer != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: peer.Certificates}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func newTestCA(t *testing.T) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Ardur test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func newTestSVID(t *testing.T, id spiffeid.ID, ca *x509.Certificate, caKey ed25519.PrivateKey, serial int64) *x509svid.SVID {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(id.String())
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: id.String()},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{uri},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &x509svid.SVID{ID: id, Certificates: []*x509.Certificate{cert}, PrivateKey: key}
}

func tlsCertificateForTest(svid *x509svid.SVID) tls.Certificate {
	chain := make([][]byte, 0, len(svid.Certificates))
	for _, cert := range svid.Certificates {
		chain = append(chain, cert.Raw)
	}
	return tls.Certificate{
		Certificate: chain,
		PrivateKey:  svid.PrivateKey,
		Leaf:        svid.Certificates[0],
	}
}
