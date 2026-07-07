package main

// daemon_guard_degrade_test.go — tests for issue #121: the daemon must never
// keep advertising the bpf_lsm enforcement tier once the guard consumer that
// was actually feeding enforce_events has exited. Exercises degradeGuardTier
// directly (the pure state-transition logic) and end-to-end through the
// health protocol response, without needing a real kernel/BPF-LSM.

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

func TestDegradeGuardTier_MovesBPFLSMToNone(t *testing.T) {
	d := newTestDaemon(t)
	d.setActiveTier(daemonTierBPFLSM)

	d.degradeGuardTier(errors.New("ringbuf read: i/o error"), d.log)

	if got := d.getActiveTier(); got != daemonTierNone {
		t.Fatalf("activeTier after degrade = %q, want %q", got, daemonTierNone)
	}
}

// TestDegradeGuardTier_CleanEOFAlsoDegrades covers the "err == nil" cause: a
// clean io.EOF from consumeEnforceEvents (e.g. the guard was force-detached
// externally, closing the ringbuf for a reason other than this daemon's own
// ctx-cancellation watcher) must degrade the tier exactly like a real error
// does -- the guard is equally gone either way.
func TestDegradeGuardTier_CleanEOFAlsoDegrades(t *testing.T) {
	d := newTestDaemon(t)
	d.setActiveTier(daemonTierBPFLSM)

	d.degradeGuardTier(nil, d.log)

	if got := d.getActiveTier(); got != daemonTierNone {
		t.Fatalf("activeTier after clean-EOF degrade = %q, want %q", got, daemonTierNone)
	}
}

// TestDegradeGuardTier_NoOpWhenBPFLSMNeverActive covers the startup-load-
// failure path: runGuardConsumer can return before main()'s ready-channel
// select has ever set activeTier to bpf_lsm (preflight or load failed
// immediately). degradeGuardTier must not manufacture a spurious transition
// or tamper-audit entry in that case.
func TestDegradeGuardTier_NoOpWhenBPFLSMNeverActive(t *testing.T) {
	d := newTestDaemon(t)
	// activeTier is daemonTierNone from newTestDaemon; simulate the seccomp
	// fallback having already won, too.
	d.setActiveTier(daemonTierSeccomp)

	d.degradeGuardTier(errors.New("preflight failed"), d.log)

	if got := d.getActiveTier(); got != daemonTierSeccomp {
		t.Fatalf("activeTier changed to %q, want unchanged %q", got, daemonTierSeccomp)
	}
	if n := d.tamperChain.Len(); n != 0 {
		t.Fatalf("tamperChain.Len() = %d, want 0 (no-op must not record an entry)", n)
	}
}

// TestDegradeGuardTier_RecordsAuditableTamperEntry proves the degradation is
// not just a log line: it is hash-chained and appended to the same evidence
// trail RunTamperAudit ticks use, so an operator who is already watching
// tamper_audit.jsonl for drift sees this event too.
func TestDegradeGuardTier_RecordsAuditableTamperEntry(t *testing.T) {
	d := newTestDaemon(t)
	stub := newStubFS()
	d.fs = stub
	d.setActiveTier(daemonTierBPFLSM)

	cause := errors.New("enforce_events ringbuf read: link detached")
	d.degradeGuardTier(cause, d.log)

	if n := d.tamperChain.Len(); n != 1 {
		t.Fatalf("tamperChain.Len() = %d, want 1", n)
	}

	path := filepath.Join(d.evidenceDir, "_tamper", "tamper_audit.jsonl")
	stub.mu.Lock()
	data := stub.appends[path]
	stub.mu.Unlock()
	if len(data) == 0 {
		t.Fatalf("no tamper_audit.jsonl entry written to %s", path)
	}

	var entry kernelcapture.TamperReceiptEntry
	if err := json.Unmarshal(data[:len(data)-1], &entry); err != nil {
		t.Fatalf("unmarshal tamper receipt: %v\n%s", err, data)
	}
	if !entry.Result.Drift {
		t.Fatal("recorded tamper entry Drift = false, want true")
	}
	found := false
	for _, c := range entry.Result.Checks {
		if c.Name == "guard_consumer" {
			found = true
			if c.OK {
				t.Error("guard_consumer check OK = true, want false")
			}
			if c.Detail == "" || !strings.Contains(c.Detail, "guard consumer exited") || !strings.Contains(c.Detail, cause.Error()) {
				t.Errorf("guard_consumer detail = %q, want it to explain the cause and the transition", c.Detail)
			}
		}
	}
	if !found {
		t.Fatal("no guard_consumer check in the recorded tamper entry")
	}
}

// TestHealthReflectsTrueTier_AfterGuardConsumerDeath is the end-to-end proof
// the issue asks for: a client calling health after the guard consumer has
// died must see EnforcementTierNone, never a stale EnforcementTierBPFLSM --
// even though nothing here touches a real kernel or BPF-LSM.
func TestHealthReflectsTrueTier_AfterGuardConsumerDeath(t *testing.T) {
	d := newTestDaemon(t)
	d.fs = newStubFS()

	// Simulate a successful guard load: policyMaps populated, tier live.
	d.policyMaps = kernelcapture.PolicyMaps{
		CgroupOpPolicy:  &fakeHealthPolicyMap{},
		CgroupPathAllow: &fakeHealthPolicyMap{},
		CgroupFileAllow: &fakeHealthPolicyMap{},
		CgroupNetAllow:  &fakeHealthPolicyMap{},
		CgroupManaged:   &fakeHealthPolicyMap{},
		KillSwitch:      &fakeHealthPolicyMap{},
	}
	d.setActiveTier(daemonTierBPFLSM)

	before := d.handleAuthorizedRequest(context.Background(), healthReq(), validHealthHandshake())
	if before.EnforcementTier != kernelcapture.EnforcementTierBPFLSM {
		t.Fatalf("precondition: EnforcementTier = %q, want %q", before.EnforcementTier, kernelcapture.EnforcementTierBPFLSM)
	}

	// The guard consumer dies mid-run: its defer clears policyMaps (mirrors
	// runGuardConsumer's defer in daemon_guard_linux.go), and the goroutine
	// that awaited it calls degradeGuardTier -- exactly what main() now does.
	d.policyMaps = kernelcapture.PolicyMaps{}
	d.degradeGuardTier(errors.New("guard died"), d.log)

	after := d.handleAuthorizedRequest(context.Background(), healthReq(), validHealthHandshake())
	if !after.OK {
		t.Fatalf("health response = %+v, want OK", after)
	}
	if after.EnforcementTier != kernelcapture.EnforcementTierNone {
		t.Fatalf("EnforcementTier after guard death = %q, want %q (must never keep advertising a detached tier)",
			after.EnforcementTier, kernelcapture.EnforcementTierNone)
	}
}

// TestActiveTier_ConcurrentReadWriteIsRaceFree exercises getActiveTier /
// setActiveTier / enforcementTier concurrently -- activeTier is written from
// the guard goroutine and read from every socket-handling goroutine in
// production; this is meaningful under `go test -race` (see kernel-enforce.yml).
func TestActiveTier_ConcurrentReadWriteIsRaceFree(t *testing.T) {
	d := newTestDaemon(t)
	d.fs = newStubFS()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			d.setActiveTier(daemonTierBPFLSM)
			d.degradeGuardTier(errors.New("flap"), d.log)
		}
	}()

	for i := 0; i < 200; i++ {
		_ = d.enforcementTier()
		_ = d.handleAuthorizedRequest(context.Background(), healthReq(), validHealthHandshake())
	}
	<-done
}
