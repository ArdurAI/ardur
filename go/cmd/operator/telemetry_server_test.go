package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type countingCloser struct {
	count atomic.Int32
	err   error
}

func (c *countingCloser) Close() error {
	c.count.Add(1)
	return c.err
}

func TestTelemetryServerPreCanceledContextClosesResources(t *testing.T) {
	srv, closer := newLifecycleTestTelemetryServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() = %v, want nil", err)
	}
	if got := closer.count.Load(); got != 1 {
		t.Fatalf("source close count = %d, want 1", got)
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if got := closer.count.Load(); got != 1 {
		t.Fatalf("idempotent source close count = %d, want 1", got)
	}
}

func TestTelemetryServerReportsSourceCloseError(t *testing.T) {
	srv, closer := newLifecycleTestTelemetryServer(t)
	want := errors.New("close SPIFFE source")
	closer.err = want
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := srv.Start(ctx); !errors.Is(err, want) {
		t.Fatalf("Start() = %v, want close error", err)
	}
}

func TestTelemetryServerStopsOnContextCancellation(t *testing.T) {
	srv, closer := newLifecycleTestTelemetryServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()

	deadline := time.Now().Add(time.Second)
	for {
		conn, err := net.DialTimeout("tcp", srv.listener.Addr().String(), 20*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("telemetry listener did not become reachable: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start() after cancellation = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("telemetry server did not stop after cancellation")
	}
	if got := closer.count.Load(); got != 1 {
		t.Fatalf("source close count = %d, want 1", got)
	}
}

func TestTelemetryServerDoesNotNeedLeaderElection(t *testing.T) {
	srv, _ := newLifecycleTestTelemetryServer(t)
	defer srv.Close()
	if srv.NeedLeaderElection() {
		t.Fatal("telemetry server unexpectedly requires leader election")
	}
}

func TestNewTelemetryServerRejectsEmptyBindingsBeforeWorkloadAPI(t *testing.T) {
	_, err := newTelemetryServer(
		context.Background(),
		"127.0.0.1:0",
		"unix:///definitely/missing/spire.sock",
		nil,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	)
	if err == nil || err.Error() != "at least one telemetry SPIFFE source binding is required" {
		t.Fatalf("newTelemetryServer() error = %v, want binding error", err)
	}
}

func newLifecycleTestTelemetryServer(t *testing.T) (*telemetryServer, *countingCloser) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closer := &countingCloser{}
	return &telemetryServer{
		server: &http.Server{
			Handler:   http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
		},
		listener: listener,
		source:   closer,
	}, closer
}
