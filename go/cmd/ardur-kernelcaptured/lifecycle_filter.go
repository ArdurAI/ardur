package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// lifecycleCgroupFilter is the daemon's narrow write surface for the two
// process-exec producer-filter maps. ProcessExecEBPFHandles implements it on
// Linux; tests use an in-memory implementation.
type lifecycleCgroupFilter interface {
	SetLifecycleCgroupFilterEnabled(bool) error
	AllowLifecycleCgroup(uint64) error
	RemoveLifecycleCgroup(uint64) error
	ClearLifecycleCgroups() error
}

// lifecycleFilterManager serializes producer-filter state independently of
// routing and policy-map locks. Registration waits until lifecycle consumer
// startup resolves, adds its cgroup before the registry can return success,
// and removes it only after route retirement has completed.
type lifecycleFilterManager struct {
	mu sync.Mutex

	startup     chan struct{}
	startupOnce sync.Once
	startupErr  error
	unsafeErr   error

	controller lifecycleCgroupFilter
	sessions   map[string]uint64
	owners     map[uint64]string
}

func newLifecycleFilterManager() *lifecycleFilterManager {
	return &lifecycleFilterManager{
		startup:  make(chan struct{}),
		sessions: make(map[string]uint64),
		owners:   make(map[uint64]string),
	}
}

// install reconciles a fresh or reopened pinned generation. Filtering is first
// made permissive so a partial reconciliation cannot omit governed events. The
// allowlist is then rebuilt and filtering enabled. With no sessions, enabled +
// empty means the producer emits no host lifecycle events.
func (m *lifecycleFilterManager) install(controller lifecycleCgroupFilter) error {
	if m == nil || controller == nil {
		return fmt.Errorf("lifecycle cgroup filter controller is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := controller.SetLifecycleCgroupFilterEnabled(false); err != nil {
		return m.resolveInstallFailureLocked(controller, fmt.Errorf("disable lifecycle cgroup filter before reconciliation: %w", err))
	}
	if err := controller.ClearLifecycleCgroups(); err != nil {
		return m.resolveInstallFailureLocked(controller, fmt.Errorf("clear lifecycle cgroup filter before reconciliation: %w", err))
	}
	for sessionID, cgroupID := range m.sessions {
		if err := controller.AllowLifecycleCgroup(cgroupID); err != nil {
			return m.resolveInstallFailureLocked(controller, fmt.Errorf("restore lifecycle cgroup %d for session %q: %w", cgroupID, sessionID, err))
		}
	}
	if err := controller.SetLifecycleCgroupFilterEnabled(true); err != nil {
		return m.resolveInstallFailureLocked(controller, fmt.Errorf("enable lifecycle cgroup filter after reconciliation: %w", err))
	}

	m.controller = controller
	m.startupErr = nil
	m.unsafeErr = nil
	m.startupOnce.Do(func() { close(m.startup) })
	return nil
}

func (m *lifecycleFilterManager) resolveInstallFailureLocked(controller lifecycleCgroupFilter, cause error) error {
	disableErr := controller.SetLifecycleCgroupFilterEnabled(false)
	m.controller = nil
	m.startupErr = cause
	m.unsafeErr = nil
	if disableErr != nil {
		m.unsafeErr = errors.Join(cause, fmt.Errorf("cannot establish permissive lifecycle capture fallback: %w", disableErr))
	}
	m.startupOnce.Do(func() { close(m.startup) })
	return errors.Join(cause, disableErr)
}

// markUnavailable preserves the daemon's existing control-plane-only fallback:
// registrations continue without producer filtering when lifecycle loading was
// deliberately disabled or failed before a controller became available.
func (m *lifecycleFilterManager) markUnavailable(cause error) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.controller != nil {
		return
	}
	m.startupErr = cause
	m.startupOnce.Do(func() { close(m.startup) })
}

// prepare waits for producer startup and reserves one cgroup before the session
// registry commits. added reports whether rollback is required if registry
// admission later fails.
func (m *lifecycleFilterManager) prepare(ctx context.Context, sessionID string, cgroupID uint64) (added bool, err error) {
	if m == nil || sessionID == "" || cgroupID == 0 {
		return false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-m.startup:
	case <-ctx.Done():
		return false, fmt.Errorf("wait for lifecycle cgroup filter startup: %w", ctx.Err())
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.unsafeErr != nil {
		return false, m.unsafeErr
	}
	if existing, ok := m.sessions[sessionID]; ok {
		if existing != cgroupID {
			return false, fmt.Errorf("session %q is already bound to lifecycle cgroup %d", sessionID, existing)
		}
		return false, nil
	}
	if owner, ok := m.owners[cgroupID]; ok && owner != sessionID {
		return false, fmt.Errorf("lifecycle cgroup %d is already bound to session %q", cgroupID, owner)
	}
	if m.controller != nil {
		if err := m.controller.AllowLifecycleCgroup(cgroupID); err != nil {
			return false, fmt.Errorf("allow lifecycle cgroup %d for session %q: %w", cgroupID, sessionID, err)
		}
	}
	m.sessions[sessionID] = cgroupID
	m.owners[cgroupID] = sessionID
	return true, nil
}

func (m *lifecycleFilterManager) remove(sessionID string) error {
	if m == nil || sessionID == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cgroupID, ok := m.sessions[sessionID]
	if !ok {
		return nil
	}
	delete(m.sessions, sessionID)
	delete(m.owners, cgroupID)
	if m.controller == nil {
		return nil
	}
	if err := m.controller.RemoveLifecycleCgroup(cgroupID); err != nil {
		return fmt.Errorf("remove lifecycle cgroup %d for session %q: %w", cgroupID, sessionID, err)
	}
	return nil
}

// detach leaves pinned programs in a quiet fail-closed producer state: enabled
// filtering with an empty allowlist. This avoids host-wide ringbuf pressure
// while no daemon consumer is attached.
func (m *lifecycleFilterManager) detach(controller lifecycleCgroupFilter) error {
	if m == nil || controller == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.controller != controller {
		return nil
	}
	disableErr := controller.SetLifecycleCgroupFilterEnabled(false)
	clearErr := controller.ClearLifecycleCgroups()
	enableErr := controller.SetLifecycleCgroupFilterEnabled(true)
	m.controller = nil
	return errors.Join(disableErr, clearErr, enableErr)
}
