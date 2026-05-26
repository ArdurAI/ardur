package kernelcapture

import (
	"errors"
	"fmt"
)

const (
	DaemonPeerAuthorizationVerdictAllow = "allow"
	DaemonPeerAuthorizationVerdictDeny  = "deny"
)

var ErrDaemonPeerAuthorization = errors.New("kernelcapture: unauthorized daemon peer")

// DaemonObservedPeerCredentials is the daemon-observed local socket peer
// identity. A future Unix socket server must populate this from the operating
// system (for example SO_PEERCRED on Linux), not from client JSON.
type DaemonObservedPeerCredentials struct {
	UID uint32
	GID uint32
	PID uint32
}

// DaemonPeerAuthorizationPolicy is deliberately fail-closed. A daemon that has
// not loaded an explicit local client allowlist must not accept registration
// traffic just because a process can connect to the socket.
type DaemonPeerAuthorizationPolicy struct {
	AllowedUIDs []uint32
	AllowedGIDs []uint32
}

// DaemonPeerAuthorization records the deterministic authorization decision for
// a daemon-observed peer. It is safe to include in debug reports because it does
// not contain secrets or protocol payloads.
type DaemonPeerAuthorization struct {
	Verdict string
	Reason  string
	UID     uint32
	GID     uint32
	PID     uint32
	Matched string
}

// AuthorizeObservedDaemonPeer validates a local client identity before a future
// daemon accepts launch-wrapper protocol traffic. This function is contract
// validation only: it does not open sockets, read SO_PEERCRED, start a daemon,
// or inspect process trees.
func AuthorizeObservedDaemonPeer(creds DaemonObservedPeerCredentials, policy DaemonPeerAuthorizationPolicy) (DaemonPeerAuthorization, error) {
	decision := DaemonPeerAuthorization{
		Verdict: DaemonPeerAuthorizationVerdictDeny,
		UID:     creds.UID,
		GID:     creds.GID,
		PID:     creds.PID,
	}
	if creds.PID == 0 {
		decision.Reason = "missing observed peer pid"
		return decision, fmt.Errorf("%w: %s", ErrDaemonPeerAuthorization, decision.Reason)
	}
	if len(policy.AllowedUIDs) == 0 && len(policy.AllowedGIDs) == 0 {
		decision.Reason = "no allowed peer uid or gid entries configured"
		return decision, fmt.Errorf("%w: %s", ErrDaemonPeerAuthorization, decision.Reason)
	}
	for _, uid := range policy.AllowedUIDs {
		if creds.UID == uid {
			decision.Verdict = DaemonPeerAuthorizationVerdictAllow
			decision.Reason = "observed peer uid is explicitly allowed"
			decision.Matched = "uid"
			return decision, nil
		}
	}
	for _, gid := range policy.AllowedGIDs {
		if creds.GID == gid {
			decision.Verdict = DaemonPeerAuthorizationVerdictAllow
			decision.Reason = "observed peer gid is explicitly allowed"
			decision.Matched = "gid"
			return decision, nil
		}
	}
	decision.Reason = "observed peer uid/gid did not match daemon policy"
	return decision, fmt.Errorf("%w: %s", ErrDaemonPeerAuthorization, decision.Reason)
}
