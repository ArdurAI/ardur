package kernelcapture

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestBuildDaemonSessionStatusEvidenceLogEntryReturnsDetachedJSONL(t *testing.T) {
	t.Parallel()

	cfg := daemonSessionStatusEvidenceLogConfigForTest(t, "entry-session")
	cfg.Snapshot.AsOf = cfg.Snapshot.AsOf.Add(123456789 * time.Nanosecond)
	plan, err := BuildDaemonSessionStatusEvidenceLogPlan(cfg)
	if err != nil {
		t.Fatalf("BuildDaemonSessionStatusEvidenceLogPlan returned error: %v", err)
	}

	entryBytes, err := BuildDaemonSessionStatusEvidenceLogEntry(plan, cfg.Snapshot)
	if err != nil {
		t.Fatalf("BuildDaemonSessionStatusEvidenceLogEntry returned error: %v", err)
	}
	if !strings.HasSuffix(string(entryBytes), "\n") {
		t.Fatalf("entry is not newline-terminated JSONL: %q", string(entryBytes))
	}
	if strings.Count(string(entryBytes), "\n") != 1 {
		t.Fatalf("entry must be exactly one JSONL record, got %q", string(entryBytes))
	}
	if int64(len(entryBytes)) > plan.MaxEntryBytes {
		t.Fatalf("entry length %d exceeded max entry bytes %d", len(entryBytes), plan.MaxEntryBytes)
	}

	var entry DaemonSessionStatusEvidenceLogEntry
	if err := json.Unmarshal([]byte(strings.TrimSuffix(string(entryBytes), "\n")), &entry); err != nil {
		t.Fatalf("entry JSON did not parse: %v", err)
	}
	if entry.SchemaVersion != DaemonSessionStatusEvidenceLogSchemaVersion {
		t.Fatalf("schema version = %q", entry.SchemaVersion)
	}
	if entry.EntryKind != DaemonSessionStatusEvidenceLogEntryKind {
		t.Fatalf("entry kind = %q", entry.EntryKind)
	}
	if entry.SessionID != plan.SessionID || entry.SessionID != cfg.Snapshot.Session.SessionID {
		t.Fatalf("session id = %q, want plan/snapshot session", entry.SessionID)
	}
	if entry.EvidenceLogPath != plan.EvidenceLogPath {
		t.Fatalf("evidence log path = %q, want %q", entry.EvidenceLogPath, plan.EvidenceLogPath)
	}
	if entry.EntryDigest != plan.EntryDigest {
		t.Fatalf("entry digest = %q, want plan digest %q", entry.EntryDigest, plan.EntryDigest)
	}
	if !entry.SnapshotAsOf.Equal(cfg.Snapshot.AsOf) {
		t.Fatalf("snapshot_as_of = %s, want %s", entry.SnapshotAsOf, cfg.Snapshot.AsOf)
	}
	if entry.Snapshot.ProtocolResponse.SessionID != cfg.Snapshot.ProtocolResponse.SessionID {
		t.Fatalf("snapshot response session id = %q", entry.Snapshot.ProtocolResponse.SessionID)
	}
	if !containsText(entry.ClaimBoundary, "performs no filesystem writes") {
		t.Fatalf("entry claim boundary does not preserve no-write boundary: %#v", entry.ClaimBoundary)
	}
	if !containsText(entry.NotClaimed, "evidence-log append") {
		t.Fatalf("entry not-claimed list missing append boundary: %#v", entry.NotClaimed)
	}

	again, err := BuildDaemonSessionStatusEvidenceLogEntry(plan, cfg.Snapshot)
	if err != nil {
		t.Fatalf("second BuildDaemonSessionStatusEvidenceLogEntry returned error: %v", err)
	}
	if string(again) != string(entryBytes) {
		t.Fatalf("entry bytes not deterministic:\nfirst:  %q\nsecond: %q", string(entryBytes), string(again))
	}

	entryBytes[0] = '{' + 1
	fresh, err := BuildDaemonSessionStatusEvidenceLogEntry(plan, cfg.Snapshot)
	if err != nil {
		t.Fatalf("fresh BuildDaemonSessionStatusEvidenceLogEntry returned error: %v", err)
	}
	if string(fresh) != string(again) {
		t.Fatalf("caller byte-slice mutation leaked into fresh entry: %q != %q", string(fresh), string(again))
	}
}

func TestBuildDaemonSessionStatusEvidenceLogEntryFailsClosed(t *testing.T) {
	t.Parallel()

	cfg := daemonSessionStatusEvidenceLogConfigForTest(t, "entry-fail-session")
	validPlan, err := BuildDaemonSessionStatusEvidenceLogPlan(cfg)
	if err != nil {
		t.Fatalf("BuildDaemonSessionStatusEvidenceLogPlan returned error: %v", err)
	}

	for _, tc := range []struct {
		name string
		mut  func(*DaemonSessionStatusEvidenceLogPlan, *DaemonSessionStatusSnapshot)
		want string
	}{
		{name: "zero plan", mut: func(plan *DaemonSessionStatusEvidenceLogPlan, snapshot *DaemonSessionStatusSnapshot) {
			*plan = DaemonSessionStatusEvidenceLogPlan{}
		}, want: "mode"},
		{name: "wrong schema", mut: func(plan *DaemonSessionStatusEvidenceLogPlan, snapshot *DaemonSessionStatusSnapshot) {
			plan.SchemaVersion = "ardur.daemon.evidence-log.v99"
		}, want: "schema"},
		{name: "wrong kind", mut: func(plan *DaemonSessionStatusEvidenceLogPlan, snapshot *DaemonSessionStatusSnapshot) {
			plan.EntryKind = "other"
		}, want: "kind"},
		{name: "empty evidence path", mut: func(plan *DaemonSessionStatusEvidenceLogPlan, snapshot *DaemonSessionStatusSnapshot) {
			plan.EvidenceLogPath = ""
		}, want: "path"},
		{name: "executed plan step", mut: func(plan *DaemonSessionStatusEvidenceLogPlan, snapshot *DaemonSessionStatusSnapshot) {
			plan.Steps[0].Executed = true
		}, want: "executed"},
		{name: "digest mismatch", mut: func(plan *DaemonSessionStatusEvidenceLogPlan, snapshot *DaemonSessionStatusSnapshot) {
			plan.EntryDigest = strings.Repeat("0", 64)
		}, want: "digest"},
		{name: "snapshot mutated after planning", mut: func(plan *DaemonSessionStatusEvidenceLogPlan, snapshot *DaemonSessionStatusSnapshot) {
			snapshot.Session.HandoffMetadata["handoff_source"] = "mutated-after-plan"
		}, want: "digest"},
		{name: "snapshot session mismatch", mut: func(plan *DaemonSessionStatusEvidenceLogPlan, snapshot *DaemonSessionStatusSnapshot) {
			snapshot.Session.SessionID = "other-session"
		}, want: "session"},
		{name: "zero snapshot AsOf", mut: func(plan *DaemonSessionStatusEvidenceLogPlan, snapshot *DaemonSessionStatusSnapshot) {
			snapshot.AsOf = time.Time{}
		}, want: "AsOf"},
		{name: "entry exceeds max entry bytes", mut: func(plan *DaemonSessionStatusEvidenceLogPlan, snapshot *DaemonSessionStatusSnapshot) {
			plan.MaxEntryBytes = 128
		}, want: "max entry"},
		{name: "max log smaller than max entry", mut: func(plan *DaemonSessionStatusEvidenceLogPlan, snapshot *DaemonSessionStatusSnapshot) {
			plan.MaxLogBytes = plan.MaxEntryBytes - 1
		}, want: "max log"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			plan := validPlan
			plan.Steps = append([]DaemonSessionStatusEvidenceLogStep(nil), validPlan.Steps...)
			plan.ClaimBoundary = append([]string(nil), validPlan.ClaimBoundary...)
			plan.NotClaimed = append([]string(nil), validPlan.NotClaimed...)
			snapshot := copyDaemonSessionStatusSnapshot(cfg.Snapshot)
			tc.mut(&plan, &snapshot)

			_, err := BuildDaemonSessionStatusEvidenceLogEntry(plan, snapshot)
			if err == nil {
				t.Fatalf("expected evidence-log entry failure")
			}
			if !errors.Is(err, ErrDaemonSessionStatusEvidenceLogEntry) {
				t.Fatalf("expected ErrDaemonSessionStatusEvidenceLogEntry, got %v", err)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}
