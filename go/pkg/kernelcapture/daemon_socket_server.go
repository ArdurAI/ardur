package kernelcapture

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultDaemonUnixSocketMode        fs.FileMode = 0o660
	DefaultDaemonServerShutdownTimeout             = 5 * time.Second
	MaxDaemonServerShutdownTimeout                 = time.Minute
)

var ErrDaemonSocketServer = errors.New("kernelcapture: daemon socket server failed")
var ErrDaemonSocketServerShutdownTimeout = fmt.Errorf("%w: handler drain timed out", ErrDaemonSocketServer)

type DaemonPeerCredentialObserver func(*net.UnixConn, string) (DaemonSocketPeerObservation, error)

type DaemonAuthorizedProtocolHandler func(context.Context, DaemonProtocolRequest, DaemonProtocolPeerHandshake) DaemonProtocolResponse

// DaemonUnixSocketServerConfig configures the local Unix-domain daemon control
// socket. It is deliberately Unix-socket-only: no TCP/network listener is
// accepted here. The custody plan remains the source of daemon-owned path and
// peer-observation context; the server does not install or start a system
// service, create directories, pin BPF maps, or load eBPF programs.
type DaemonUnixSocketServerConfig struct {
	CustodyPlan             DaemonCustodyPlan
	PeerAuthorizationPolicy DaemonPeerAuthorizationPolicy

	SocketMode               fs.FileMode
	MaxRequestBytes          int64
	ReadTimeout              time.Duration
	MaxConcurrentConnections int
	ShutdownTimeout          time.Duration

	ObservePeerCredentials  DaemonPeerCredentialObserver
	HandleAuthorizedRequest DaemonAuthorizedProtocolHandler

	// bindSocketPath is an internal test-harness escape hatch so unit tests can
	// bind under t.TempDir without weakening the exported custody-plan defaults.
	// Production callers leave this empty and bind CustodyPlan.SocketPath.
	bindSocketPath string
}

// DaemonUnixSocketServer is a bound Unix-domain control socket plus a bounded
// accept loop. Callers own process/service lifecycle outside this type.
type DaemonUnixSocketServer struct {
	cfg        DaemonUnixSocketServerConfig
	listener   *net.UnixListener
	socketPath string
	semaphore  chan struct{}
	handlerWG  sync.WaitGroup
	handlersMu sync.Mutex
	handlers   map[*net.UnixConn]struct{}

	handlersDrained chan struct{}
	serveDone       chan struct{}
	drainOnce       sync.Once
	serveDoneOnce   sync.Once
	serveStarted    atomic.Bool

	closed    atomic.Bool
	closeMu   sync.Mutex
	closeErr  error
	closeOnce sync.Once
}

func DefaultDaemonUnixSocketServerConfig(plan DaemonCustodyPlan, policy DaemonPeerAuthorizationPolicy) DaemonUnixSocketServerConfig {
	return DaemonUnixSocketServerConfig{
		CustodyPlan:              plan,
		PeerAuthorizationPolicy:  policy,
		SocketMode:               DefaultDaemonUnixSocketMode,
		MaxRequestBytes:          DefaultDaemonAcceptLoopMaxRequestBytes,
		ReadTimeout:              DefaultDaemonAcceptLoopReadTimeout,
		MaxConcurrentConnections: DefaultDaemonAcceptLoopMaxConcurrentConnections,
		ShutdownTimeout:          DefaultDaemonServerShutdownTimeout,
		ObservePeerCredentials:   ObserveLinuxUnixPeerCredentials,
		HandleAuthorizedRequest:  defaultDaemonAuthorizedProtocolHandler,
	}
}

func ListenDaemonUnixSocketServer(cfg DaemonUnixSocketServerConfig) (*DaemonUnixSocketServer, error) {
	cfg = normalizeDaemonUnixSocketServerConfig(cfg)
	if err := validateDaemonUnixSocketServerConfig(cfg); err != nil {
		return nil, err
	}

	bindPath := daemonUnixSocketServerBindPath(cfg)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: bindPath, Net: "unix"})
	if err != nil {
		return nil, daemonSocketServerError("bind unix socket: %v", err)
	}
	if err := os.Chmod(bindPath, cfg.SocketMode); err != nil {
		_ = listener.Close()
		_ = os.Remove(bindPath)
		return nil, daemonSocketServerError("set unix socket mode: %v", err)
	}

	return &DaemonUnixSocketServer{
		cfg:             cfg,
		listener:        listener,
		socketPath:      bindPath,
		semaphore:       make(chan struct{}, cfg.MaxConcurrentConnections),
		handlers:        make(map[*net.UnixConn]struct{}),
		handlersDrained: make(chan struct{}),
		serveDone:       make(chan struct{}),
	}, nil
}

func (s *DaemonUnixSocketServer) SocketPath() string {
	if s == nil {
		return ""
	}
	return s.socketPath
}

// HandlersDrained closes only after Serve has stopped accepting and every
// accepted connection handler has returned. It remains open when the bounded
// drain deadline expires before handlers finish.
func (s *DaemonUnixSocketServer) HandlersDrained() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.handlersDrained
}

// ServeDone closes when Serve returns, including after a bounded drain timeout.
func (s *DaemonUnixSocketServer) ServeDone() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.serveDone
}

func (s *DaemonUnixSocketServer) Serve(ctx context.Context) error {
	if s == nil || s.listener == nil {
		return daemonSocketServerError("server is not listening")
	}
	if !s.serveStarted.CompareAndSwap(false, true) {
		return daemonSocketServerError("Serve may be called only once")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	defer s.serveDoneOnce.Do(func() { close(s.serveDone) })

	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-stop:
		}
	}()
	defer close(stop)

	var acceptErr error
acceptLoop:
	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				acceptErr = ctx.Err()
				break acceptLoop
			}
			if s.closed.Load() || isDaemonSocketServerClosedError(err) {
				break acceptLoop
			}
			acceptErr = daemonSocketServerError("accept unix connection: %v", err)
			break acceptLoop
		}

		select {
		case s.semaphore <- struct{}{}:
			s.handlersMu.Lock()
			s.handlers[conn] = struct{}{}
			s.handlerWG.Add(1)
			s.handlersMu.Unlock()
			go s.handleAcceptedConnection(ctx, conn)
		default:
			_ = writeDaemonProtocolResponse(conn, DaemonProtocolResponse{
				ProtocolVersion: DaemonProtocolVersion,
				OK:              false,
				Error:           daemonSocketServerError("too many concurrent daemon unix socket connections").Error(),
			})
			_ = conn.Close()
		}
	}

	if ctx.Err() != nil {
		// Closing accepted connections is the documented way to unblock pending
		// net.Conn reads/writes. Handlers already inside business logic receive the
		// canceled ctx and are covered by the bounded WaitGroup drain below.
		s.closeAcceptedConnections()
	}
	return errors.Join(acceptErr, s.drainAcceptedConnections())
}

func (s *DaemonUnixSocketServer) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		var joined error
		if s.listener != nil {
			if err := s.listener.Close(); err != nil && !isDaemonSocketServerClosedError(err) {
				joined = errors.Join(joined, daemonSocketServerError("close listener: %v", err))
			}
		}
		if s.socketPath != "" {
			if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
				joined = errors.Join(joined, daemonSocketServerError("remove unix socket: %v", err))
			}
		}
		s.closeMu.Lock()
		s.closeErr = joined
		s.closeMu.Unlock()
	})
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closeErr
}

func defaultDaemonAuthorizedProtocolHandler(_ context.Context, req DaemonProtocolRequest, handshake DaemonProtocolPeerHandshake) DaemonProtocolResponse {
	return DefaultDaemonAuthorizedProtocolResponse(req, handshake)
}

func DefaultDaemonAuthorizedProtocolResponse(req DaemonProtocolRequest, handshake DaemonProtocolPeerHandshake) DaemonProtocolResponse {
	return DaemonProtocolResponse{
		ProtocolVersion: DaemonProtocolVersion,
		OK:              true,
		Method:          req.Method,
		SessionID:       handshake.SessionID,
		Status:          "authorized",
	}
}

func (s *DaemonUnixSocketServer) handleAcceptedConnection(ctx context.Context, conn *net.UnixConn) {
	defer func() {
		_ = conn.Close()
		s.handlersMu.Lock()
		delete(s.handlers, conn)
		s.handlersMu.Unlock()
		<-s.semaphore
		s.handlerWG.Done()
	}()
	// One misbehaving request (e.g. a handler bug reachable only in a
	// specific degraded state, such as BPF-LSM maps not being loaded) must
	// not take the whole daemon down — each connection runs in its own
	// goroutine, and an unrecovered panic there crashes the process. This is
	// a backstop; the real fix for any given panic is to make the handler
	// fail cleanly instead of panicking.
	defer func() {
		if r := recover(); r != nil {
			_ = writeDaemonProtocolResponse(conn, DaemonProtocolResponse{
				ProtocolVersion: DaemonProtocolVersion,
				OK:              false,
				Error:           fmt.Sprintf("internal server error: %v", r),
			})
		}
	}()

	if ctx.Err() != nil {
		return
	}
	req, handshake, err := s.authorizeAcceptedConnection(conn)
	if err != nil {
		_ = writeDaemonProtocolResponse(conn, daemonProtocolErrorResponse(req, err))
		return
	}
	if ctx.Err() != nil {
		return
	}
	resp := s.cfg.HandleAuthorizedRequest(ctx, req, handshake)
	if ctx.Err() != nil {
		return
	}
	resp = normalizeDaemonProtocolResponse(resp, req, handshake)
	if err := writeDaemonProtocolResponse(conn, resp); err != nil {
		return
	}
}

func (s *DaemonUnixSocketServer) drainAcceptedConnections() error {
	s.drainOnce.Do(func() {
		go func() {
			s.handlerWG.Wait()
			close(s.handlersDrained)
		}()
	})
	timer := time.NewTimer(s.cfg.ShutdownTimeout)
	defer timer.Stop()
	select {
	case <-s.handlersDrained:
		return nil
	case <-timer.C:
		s.closeAcceptedConnections()
		select {
		case <-s.handlersDrained:
			return nil
		default:
			return fmt.Errorf("%w after %s", ErrDaemonSocketServerShutdownTimeout, s.cfg.ShutdownTimeout)
		}
	}
}

func (s *DaemonUnixSocketServer) closeAcceptedConnections() {
	s.handlersMu.Lock()
	connections := make([]*net.UnixConn, 0, len(s.handlers))
	for conn := range s.handlers {
		connections = append(connections, conn)
	}
	s.handlersMu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func (s *DaemonUnixSocketServer) authorizeAcceptedConnection(conn *net.UnixConn) (DaemonProtocolRequest, DaemonProtocolPeerHandshake, error) {
	req, err := readDaemonProtocolRequestFromAcceptedUnixConnectionWithLimits(conn, s.cfg.MaxRequestBytes, s.cfg.ReadTimeout)
	if err != nil {
		return DaemonProtocolRequest{}, DaemonProtocolPeerHandshake{}, err
	}
	observation, err := s.cfg.ObservePeerCredentials(conn, s.cfg.CustodyPlan.SocketPath)
	if err != nil {
		return req, DaemonProtocolPeerHandshake{}, fmt.Errorf("%w: peer credential retrieval failed: %v", ErrDaemonSocketPeerObservation, err)
	}
	handshake, err := AuthorizeDaemonProtocolPeer(req, observation, s.cfg.PeerAuthorizationPolicy, s.cfg.CustodyPlan)
	if err != nil {
		return req, DaemonProtocolPeerHandshake{}, err
	}
	return req, handshake, nil
}

func normalizeDaemonProtocolResponse(resp DaemonProtocolResponse, req DaemonProtocolRequest, handshake DaemonProtocolPeerHandshake) DaemonProtocolResponse {
	if resp.ProtocolVersion == "" {
		resp.ProtocolVersion = DaemonProtocolVersion
	}
	if resp.Method == "" {
		resp.Method = req.Method
	}
	if resp.SessionID == "" {
		resp.SessionID = handshake.SessionID
	}
	return resp
}

func daemonProtocolErrorResponse(req DaemonProtocolRequest, err error) DaemonProtocolResponse {
	return DaemonProtocolResponse{
		ProtocolVersion: DaemonProtocolVersion,
		OK:              false,
		Method:          req.Method,
		SessionID:       daemonProtocolRequestSessionID(req),
		Error:           err.Error(),
	}
}

func writeDaemonProtocolResponse(conn *net.UnixConn, resp DaemonProtocolResponse) error {
	if conn == nil {
		return daemonSocketServerError("unix connection is required")
	}
	if err := conn.SetWriteDeadline(time.Now().Add(daemonUnixSocketReadDeadline)); err != nil {
		return daemonSocketServerError("set write deadline: %v", err)
	}
	encoded, err := EncodeDaemonProtocolResponse(resp)
	if err != nil {
		return err
	}
	if _, err := conn.Write(encoded); err != nil {
		return daemonSocketServerError("write response: %v", err)
	}
	return nil
}

func normalizeDaemonUnixSocketServerConfig(cfg DaemonUnixSocketServerConfig) DaemonUnixSocketServerConfig {
	if cfg.SocketMode == 0 {
		cfg.SocketMode = DefaultDaemonUnixSocketMode
	}
	if cfg.MaxRequestBytes == 0 {
		cfg.MaxRequestBytes = DefaultDaemonAcceptLoopMaxRequestBytes
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = DefaultDaemonAcceptLoopReadTimeout
	}
	if cfg.MaxConcurrentConnections == 0 {
		cfg.MaxConcurrentConnections = DefaultDaemonAcceptLoopMaxConcurrentConnections
	}
	if cfg.ShutdownTimeout == 0 {
		cfg.ShutdownTimeout = DefaultDaemonServerShutdownTimeout
	}
	if cfg.ObservePeerCredentials == nil {
		cfg.ObservePeerCredentials = ObserveLinuxUnixPeerCredentials
	}
	if cfg.HandleAuthorizedRequest == nil {
		cfg.HandleAuthorizedRequest = defaultDaemonAuthorizedProtocolHandler
	}
	cfg.bindSocketPath = cleanPath(cfg.bindSocketPath)
	return cfg
}

func validateDaemonUnixSocketServerConfig(cfg DaemonUnixSocketServerConfig) error {
	if err := validateDaemonAcceptLoopConfig(DaemonAcceptLoopConfig{
		CustodyPlan:              cfg.CustodyPlan,
		PeerAuthorizationPolicy:  cfg.PeerAuthorizationPolicy,
		MaxRequestBytes:          cfg.MaxRequestBytes,
		ReadTimeout:              cfg.ReadTimeout,
		MaxConcurrentConnections: cfg.MaxConcurrentConnections,
	}); err != nil {
		return daemonSocketServerError("accept loop config is invalid: %v", err)
	}
	if cfg.SocketMode&^fs.ModePerm != 0 {
		return daemonSocketServerError("socket mode must contain permission bits only")
	}
	if cfg.SocketMode != 0o600 && cfg.SocketMode != 0o660 {
		return daemonSocketServerError("socket mode must be 0600 or 0660")
	}
	bindPath := daemonUnixSocketServerBindPath(cfg)
	if strings.TrimSpace(bindPath) == "" {
		return daemonSocketServerError("socket path is required")
	}
	if !filepath.IsAbs(bindPath) {
		return daemonSocketServerError("socket path must be absolute")
	}
	if cfg.ObservePeerCredentials == nil {
		return daemonSocketServerError("peer credential observer is required")
	}
	if cfg.HandleAuthorizedRequest == nil {
		return daemonSocketServerError("authorized protocol handler is required")
	}
	if cfg.ShutdownTimeout <= 0 || cfg.ShutdownTimeout > MaxDaemonServerShutdownTimeout {
		return daemonSocketServerError("shutdown timeout must be between 1ns and %s", MaxDaemonServerShutdownTimeout)
	}
	return nil
}

func daemonUnixSocketServerBindPath(cfg DaemonUnixSocketServerConfig) string {
	if cfg.bindSocketPath != "" {
		return cfg.bindSocketPath
	}
	return cleanPath(cfg.CustodyPlan.SocketPath)
}

func daemonSocketServerError(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrDaemonSocketServer}, args...)...)
}

func isDaemonSocketServerClosedError(err error) bool {
	return err != nil && (errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "closed network connection"))
}
