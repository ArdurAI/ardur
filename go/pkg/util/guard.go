// Package util provides shared Go utilities for the Ardur codebase.
package util

import "sync"

// CloseGuard wraps a sync.RWMutex and a closed boolean flag for safe
// concurrent close semantics. Types that embed or hold a CloseGuard can
// call CheckClosed() at the top of every exported method under a read
// lock, and MarkClosed() inside Close() under a write lock.
type CloseGuard struct {
	mu     sync.RWMutex
	closed bool
}

// CheckClosed returns true if the guard has been marked closed.
func (g *CloseGuard) CheckClosed() bool {
	return g.closed
}

// MarkClosed sets the closed flag to true. Callers must hold the write
// lock before calling.
func (g *CloseGuard) MarkClosed() {
	g.closed = true
}

// Lock acquires the write lock.
func (g *CloseGuard) Lock() {
	g.mu.Lock()
}

// Unlock releases the write lock.
func (g *CloseGuard) Unlock() {
	g.mu.Unlock()
}

// RLock acquires the read lock.
func (g *CloseGuard) RLock() {
	g.mu.RLock()
}

// RUnlock releases the read lock.
func (g *CloseGuard) RUnlock() {
	g.mu.RUnlock()
}
