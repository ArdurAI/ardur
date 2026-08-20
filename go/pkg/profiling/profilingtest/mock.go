// Package profilingtest provides test doubles for the behavioral baseline
// (Layer 4) profiling layer.
//
// It lives in its own package, separate from pkg/profiling, so that a fake
// profile provider cannot be linked into a production binary. That matters
// because pkg/issuer treats "a ProfileProvider is configured and GetProfile
// returned no error" as the profileRetrieved input to
// computeActualCompliance, one of the five conditions that raise a credential
// to LevelEnforced. A mock reachable from cmd/ would let a hand-written
// baseline — one no runtime profiler ever observed — earn that treatment.
//
// go/internal/linkgraph enforces the separation: its architecture test fails
// if this package, or any exported Mock/Fake/Stub/Dummy symbol in a non-test
// file, becomes reachable from a binary under cmd/.
package profilingtest

import (
	"context"
	"fmt"
	"sync"

	"github.com/ArdurAI/ardur/go/pkg/profiling"
)

// MockProfileProvider implements profiling.ProfileProvider for testing.
// Pre-loaded profiles are returned by GetProfile; comparison uses
// profiling.DiffProfiles.
type MockProfileProvider struct {
	mu       sync.Mutex
	closed   bool
	profiles map[string]*profiling.ApplicationProfile // key: "namespace/pod/container"
	getErr   error
	getCount int
}

// NewMockProfileProvider creates a mock profile provider.
func NewMockProfileProvider() *MockProfileProvider {
	return &MockProfileProvider{
		profiles: make(map[string]*profiling.ApplicationProfile),
	}
}

var _ profiling.ProfileProvider = (*MockProfileProvider)(nil)

// AddProfile registers a profile that GetProfile will return.
func (m *MockProfileProvider) AddProfile(profile *profiling.ApplicationProfile) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s/%s/%s", profile.Namespace, profile.Name, profile.Container)
	m.profiles[key] = profile
}

// SetGetError configures an error returned by GetProfile.
func (m *MockProfileProvider) SetGetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getErr = err
}

// GetCount returns the number of GetProfile calls.
func (m *MockProfileProvider) GetCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getCount
}

func (m *MockProfileProvider) GetProfile(_ context.Context, namespace, podName, container string) (*profiling.ApplicationProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getCount++

	if m.closed {
		return nil, profiling.ErrProviderClosed
	}
	if m.getErr != nil {
		return nil, m.getErr
	}

	key := fmt.Sprintf("%s/%s/%s", namespace, podName, container)
	profile, ok := m.profiles[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", profiling.ErrProfileNotFound, key)
	}
	return profile, nil
}

func (m *MockProfileProvider) CompareProfiles(baseline, current *profiling.ApplicationProfile) (*profiling.ProfileDiff, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, profiling.ErrProviderClosed
	}
	return profiling.DiffProfiles(baseline, current), nil
}

func (m *MockProfileProvider) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}
