package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	telemetryStartupTimeout  = 10 * time.Second
	telemetryShutdownTimeout = 5 * time.Second
	telemetryReadTimeout     = 10 * time.Second
	telemetryWriteTimeout    = 10 * time.Second
	telemetryIdleTimeout     = 30 * time.Second
	telemetryMaxHeaderBytes  = 16 << 10
)

type telemetryServer struct {
	server   *http.Server
	listener net.Listener
	source   io.Closer
	close    sync.Once
}

func newTelemetryServer(
	ctx context.Context,
	addr string,
	workloadAPIAddr string,
	bindings telemetrySourceBindings,
	handler http.Handler,
) (*telemetryServer, error) {
	if handler == nil {
		return nil, fmt.Errorf("telemetry handler is required")
	}
	if len(bindings) == 0 {
		return nil, fmt.Errorf("at least one telemetry SPIFFE source binding is required")
	}
	startupCtx, cancel := context.WithTimeout(ctx, telemetryStartupTimeout)
	defer cancel()

	var sourceOptions []workloadapi.X509SourceOption
	if workloadAPIAddr != "" {
		if strings.HasPrefix(workloadAPIAddr, "/") {
			workloadAPIAddr = "unix://" + workloadAPIAddr
		}
		sourceOptions = append(sourceOptions,
			workloadapi.WithClientOptions(workloadapi.WithAddr(workloadAPIAddr)),
		)
	}
	source, err := workloadapi.NewX509Source(startupCtx, sourceOptions...)
	if err != nil {
		return nil, fmt.Errorf("initialize telemetry SPIFFE X509 source: %w", err)
	}

	tlsConfig, err := telemetryMTLSConfig(source, bindings)
	if err != nil {
		return nil, errors.Join(err, source.Close())
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("listen for telemetry on %q: %w", addr, err),
			source.Close(),
		)
	}

	return &telemetryServer{
		server: &http.Server{
			Addr:           addr,
			Handler:        handler,
			TLSConfig:      tlsConfig,
			ReadTimeout:    telemetryReadTimeout,
			WriteTimeout:   telemetryWriteTimeout,
			IdleTimeout:    telemetryIdleTimeout,
			MaxHeaderBytes: telemetryMaxHeaderBytes,
		},
		listener: listener,
		source:   source,
	}, nil
}

func (s *telemetryServer) Start(ctx context.Context) (retErr error) {
	defer func() {
		retErr = errors.Join(retErr, s.Close())
	}()
	if ctx.Err() != nil {
		return nil
	}
	stopShutdown := context.AfterFunc(ctx, func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), telemetryShutdownTimeout)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
		_ = s.listener.Close()
	})
	defer stopShutdown()

	err := s.server.Serve(tls.NewListener(s.listener, s.server.TLSConfig))
	if ctx.Err() != nil && (errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed)) {
		return nil
	}
	return err
}

func (s *telemetryServer) NeedLeaderElection() bool {
	return false
}

func (s *telemetryServer) Close() error {
	var errs []error
	s.close.Do(func() {
		errs = append(errs, s.server.Close(), s.source.Close())
	})
	return errors.Join(errs...)
}
