package kernelcapture

import (
	"errors"
	"testing"
)

func TestAuthorizeObservedDaemonPeerAllowsExplicitUIDOrGID(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		creds       DaemonObservedPeerCredentials
		policy      DaemonPeerAuthorizationPolicy
		wantMatched string
	}{
		{
			name:        "uid allowlist",
			creds:       DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 1234},
			policy:      DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
			wantMatched: "uid",
		},
		{
			name:        "gid allowlist",
			creds:       DaemonObservedPeerCredentials{UID: 502, GID: 991, PID: 1235},
			policy:      DaemonPeerAuthorizationPolicy{AllowedGIDs: []uint32{991}},
			wantMatched: "gid",
		},
		{
			name:        "root must still be explicit",
			creds:       DaemonObservedPeerCredentials{UID: 0, GID: 0, PID: 1236},
			policy:      DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{0}},
			wantMatched: "uid",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			decision, err := AuthorizeObservedDaemonPeer(tc.creds, tc.policy)
			if err != nil {
				t.Fatalf("AuthorizeObservedDaemonPeer returned error: %v", err)
			}
			if decision.Verdict != DaemonPeerAuthorizationVerdictAllow {
				t.Fatalf("verdict = %q, want allow", decision.Verdict)
			}
			if decision.Matched != tc.wantMatched {
				t.Fatalf("matched = %q, want %q", decision.Matched, tc.wantMatched)
			}
			if decision.PID != tc.creds.PID || decision.UID != tc.creds.UID || decision.GID != tc.creds.GID {
				t.Fatalf("decision did not preserve observed credentials: got %+v want %+v", decision, tc.creds)
			}
		})
	}
}

func TestAuthorizeObservedDaemonPeerFailsClosed(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		creds  DaemonObservedPeerCredentials
		policy DaemonPeerAuthorizationPolicy
	}{
		{
			name:   "missing observed pid",
			creds:  DaemonObservedPeerCredentials{UID: 501, GID: 20},
			policy: DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}},
		},
		{
			name:   "empty policy",
			creds:  DaemonObservedPeerCredentials{UID: 501, GID: 20, PID: 1234},
			policy: DaemonPeerAuthorizationPolicy{},
		},
		{
			name:   "unmatched observed peer",
			creds:  DaemonObservedPeerCredentials{UID: 502, GID: 21, PID: 1234},
			policy: DaemonPeerAuthorizationPolicy{AllowedUIDs: []uint32{501}, AllowedGIDs: []uint32{20}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			decision, err := AuthorizeObservedDaemonPeer(tc.creds, tc.policy)
			if err == nil {
				t.Fatalf("expected authorization error")
			}
			if !errors.Is(err, ErrDaemonPeerAuthorization) {
				t.Fatalf("expected ErrDaemonPeerAuthorization, got %v", err)
			}
			if decision.Verdict != DaemonPeerAuthorizationVerdictDeny {
				t.Fatalf("verdict = %q, want deny", decision.Verdict)
			}
		})
	}
}
