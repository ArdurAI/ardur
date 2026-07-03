//go:build linux

package main

import (
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func hsWithPID(pid uint32) kernelcapture.DaemonProtocolPeerHandshake {
	return kernelcapture.DaemonProtocolPeerHandshake{
		Authorization: kernelcapture.DaemonPeerAuthorization{PID: pid},
	}
}

func regReq(rootPID uint32, cgroupID uint64) *kernelcapture.DaemonRegisterSessionRequest {
	return &kernelcapture.DaemonRegisterSessionRequest{SessionID: "s", RootPID: rootPID, CgroupID: cgroupID}
}

func TestProcParentPID_Self(t *testing.T) {
	got, err := procParentPID(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("procParentPID(self): %v", err)
	}
	if want := uint32(os.Getppid()); got != want {
		t.Fatalf("procParentPID(self) = %d, want %d", got, want)
	}
}

func TestVerifyRegisterSessionCgroup_SelfIsOwned(t *testing.T) {
	self := uint32(os.Getpid())
	// peer registering its own process: trivially owned.
	if err := verifyRegisterSessionCgroup(hsWithPID(self), regReq(self, 12345), quietLogger()); err != nil {
		t.Fatalf("self-registration should be owned, got: %v", err)
	}
}

func TestVerifyRegisterSessionCgroup_NonDescendantRejected(t *testing.T) {
	self := uint32(os.Getpid())
	// pid 1 (init) exists but is not a descendant of the test process — a peer
	// naming a process it did not spawn must be rejected.
	if err := verifyRegisterSessionCgroup(hsWithPID(self), regReq(1, 12345), quietLogger()); err == nil {
		t.Fatal("registering pid 1 (not a descendant of the peer) should be rejected")
	}
}

func TestVerifyRegisterSessionCgroup_BogusRootRejected(t *testing.T) {
	self := uint32(os.Getpid())
	// A pid that is not a live process cannot be verified — reject.
	if err := verifyRegisterSessionCgroup(hsWithPID(self), regReq(1<<30, 12345), quietLogger()); err == nil {
		t.Fatal("registering a non-existent root_pid should be rejected")
	}
}

func TestVerifyRegisterSessionCgroup_PeerNotVisibleSkips(t *testing.T) {
	// If the peer itself is not visible in /proc (cross-PID-namespace daemon),
	// ancestry can't be established either way — skip rather than break.
	if err := verifyRegisterSessionCgroup(hsWithPID(1<<30), regReq(1, 12345), quietLogger()); err != nil {
		t.Fatalf("unresolvable peer should skip the check, got: %v", err)
	}
}
