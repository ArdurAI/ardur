package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

var (
	errTelemetryUnauthenticated = errors.New("telemetry caller is not authenticated")
	errTelemetryUnauthorized    = errors.New("telemetry caller is not authorized for source")
)

// telemetrySourceBindings maps a payload source name to the only SPIFFE
// workload identity authorized to assert that source. A producer may report on
// multiple target agents, but it cannot impersonate another telemetry source.
type telemetrySourceBindings map[string]spiffeid.ID

func (b *telemetrySourceBindings) Set(value string) error {
	source, rawID, ok := strings.Cut(value, "=")
	if !ok {
		return fmt.Errorf("telemetry SPIFFE source must use source=spiffe://... format")
	}
	source = strings.TrimSpace(source)
	rawID = strings.TrimSpace(rawID)
	if !validTelemetrySource(source) {
		return fmt.Errorf("invalid telemetry source %q: use 1-64 letters, digits, '.', '_' or '-'", source)
	}
	id, err := spiffeid.FromString(rawID)
	if err != nil {
		return fmt.Errorf("invalid SPIFFE ID for telemetry source %q: %w", source, err)
	}
	if *b == nil {
		*b = make(telemetrySourceBindings)
	}
	if _, exists := (*b)[source]; exists {
		return fmt.Errorf("telemetry source %q is configured more than once", source)
	}
	for configuredSource, configuredID := range *b {
		if configuredID == id {
			return fmt.Errorf("SPIFFE ID %q is already bound to telemetry source %q", id, configuredSource)
		}
	}
	(*b)[source] = id
	return nil
}

func (b telemetrySourceBindings) String() string {
	entries := make([]string, 0, len(b))
	for source, id := range b {
		entries = append(entries, source+"="+id.String())
	}
	sort.Strings(entries)
	return strings.Join(entries, ",")
}

func (b telemetrySourceBindings) spiffeIDs() []spiffeid.ID {
	sources := make([]string, 0, len(b))
	for source := range b {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	ids := make([]spiffeid.ID, 0, len(sources))
	for _, source := range sources {
		ids = append(ids, b[source])
	}
	return ids
}

func (b telemetrySourceBindings) authorize(r *http.Request, req telemetryRequest) error {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return errTelemetryUnauthenticated
	}
	peerID, err := x509svid.IDFromCert(r.TLS.PeerCertificates[0])
	if err != nil {
		return fmt.Errorf("%w: invalid peer X509-SVID: %v", errTelemetryUnauthenticated, err)
	}
	expectedID, ok := b[req.Source]
	if !ok || expectedID != peerID {
		return fmt.Errorf("%w: SPIFFE ID %q cannot assert source %q", errTelemetryUnauthorized, peerID, req.Source)
	}
	return nil
}

func validTelemetrySource(source string) bool {
	if source == "" || len(source) > 64 {
		return false
	}
	for _, r := range source {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

type telemetryX509Source interface {
	x509svid.Source
	x509bundle.Source
}

func telemetryMTLSConfig(source telemetryX509Source, bindings telemetrySourceBindings) (*tls.Config, error) {
	ids := bindings.spiffeIDs()
	if len(ids) == 0 {
		return nil, fmt.Errorf("at least one telemetry SPIFFE source binding is required")
	}
	config := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeOneOf(ids...))
	config.MinVersion = tls.VersionTLS13
	return config, nil
}
