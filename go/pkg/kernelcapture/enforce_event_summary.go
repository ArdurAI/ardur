package kernelcapture

// enforce_event_summary.go — enforcement-event accounting exposed over the
// daemon status protocol (Epic A #63, plan E3).
//
// EnforceEventSummary is the accumulator behind the "enforcement" block on a
// session_status response. It exists so a client (the run bridge, an
// operator) can learn what kernel-level enforcement happened for a session
// without reading the evidence-log JSONL directly — evidence directories are
// root-0700, so the daemon socket is the only channel a non-root client has.
import "sync"

// EnforceEventSummary is a point-in-time rollup of enforcement events for one
// session (or the shared orphan scope). It is safe to copy by value once
// read; use EnforceEventSummaryAccumulator to build one under concurrent
// writes.
type EnforceEventSummary struct {
	// TotalEvents is every enforce_event processed for this scope, including
	// ones that could not be matched to a session (only present on the orphan
	// scope's summary).
	TotalEvents uint64 `json:"total_events"`
	// VerdictCounts keys are SyntheticKernelReceipt-style verdict strings
	// ("denied", "blocked", "compliant", "insufficient_evidence", "unknown").
	VerdictCounts map[string]uint64 `json:"verdict_counts,omitempty"`
	// TierCoverage keys identify the enforcement tier + mode that produced an
	// event, e.g. "bpf_lsm:enforce" or "bpf_lsm:permissive". Forward-compatible
	// with future tiers (seccomp unotify, plan E4).
	TierCoverage map[string]uint64 `json:"tier_coverage,omitempty"`
	// OrphanCount is enforce_events observed for this session's cgroup before
	// (or after) it was known to the routing index, or otherwise unattributed.
	// Zero on the orphan scope's own summary (its events are the orphans).
	OrphanCount uint64 `json:"orphan_count"`
	// LostSamples is the cumulative ringbuf LostSamples count observed while
	// consuming enforce_events, regardless of session attribution.
	LostSamples uint64 `json:"lost_samples"`
	// LastSeq is the highest Seq appended to this scope's receipt chain.
	LastSeq uint64 `json:"last_seq"`
	// ChainDigest is the hash of the most recently appended receipt: the
	// chain head. A verifier who trusts this digest (e.g. because it was
	// attested) can validate the full evidence log against it.
	ChainDigest string `json:"chain_digest,omitempty"`
	// TamperChainStartSeq is the first global tamper-chain sequence that could
	// have occurred during this session. TamperChainLastSeq/TamperChainDigest
	// identify the coherent chain head captured by session_status and therefore
	// by the signed kernel_enforcement attestation claim.
	TamperChainStartSeq uint64 `json:"tamper_chain_start_seq,omitempty"`
	TamperChainLastSeq  uint64 `json:"tamper_chain_last_seq,omitempty"`
	TamperChainDigest   string `json:"tamper_chain_digest,omitempty"`
	// KillSwitchChangeCount counts committed global kill-switch transitions
	// while this session was active. EngagedDuringSession remains true after a
	// later disengage so an engage->disengage interval cannot disappear from the
	// final signed snapshot.
	KillSwitchChangeCount          uint64 `json:"kill_switch_change_count"`
	KillSwitchEngagedDuringSession bool   `json:"kill_switch_engaged_during_session"`
	// KillSwitchEvidenceGap is set on any receipt-persistence failure, even when
	// the compensating kernel-state rollback succeeds, because partial I/O can
	// leave the evidence file uncertain. It prevents that uncertainty from being
	// represented as a fully evidenced session.
	KillSwitchEvidenceGap bool `json:"kill_switch_evidence_gap"`
}

// EnforceEventSummaryAccumulator accumulates EnforceEventSummary counters as
// events are processed. Safe for concurrent use.
type EnforceEventSummaryAccumulator struct {
	mu      sync.Mutex
	summary EnforceEventSummary
}

// NewEnforceEventSummaryAccumulator returns an empty accumulator.
func NewEnforceEventSummaryAccumulator() *EnforceEventSummaryAccumulator {
	return &EnforceEventSummaryAccumulator{
		summary: EnforceEventSummary{
			VerdictCounts: make(map[string]uint64),
			TierCoverage:  make(map[string]uint64),
		},
	}
}

// RecordReceipt folds one finalized EnforceReceiptEntry into the running
// summary. tier identifies the enforcement backend + mode (e.g.
// "bpf_lsm:enforce"); pass "" if unknown.
func (a *EnforceEventSummaryAccumulator) RecordReceipt(entry EnforceReceiptEntry, tier string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.summary.TotalEvents++
	if entry.Verdict != "" {
		a.summary.VerdictCounts[entry.Verdict]++
	}
	if tier != "" {
		a.summary.TierCoverage[tier]++
	}
	if entry.Orphan {
		a.summary.OrphanCount++
	}
	if entry.Seq > a.summary.LastSeq {
		a.summary.LastSeq = entry.Seq
	}
	a.summary.ChainDigest = entry.Hash
}

// RecordLostSamples adds n to the cumulative lost-sample counter. It is
// called regardless of whether the lost samples could have been attributed to
// any particular session, since the ringbuf reports loss globally.
func (a *EnforceEventSummaryAccumulator) RecordLostSamples(n uint64) {
	if n == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.summary.LostSamples += n
}

// InitializeTamperWindow records the first global tamper sequence that may
// overlap this session and whether enforcement was already suspended when the
// session was registered.
func (a *EnforceEventSummaryAccumulator) InitializeTamperWindow(startSeq uint64, killSwitchEngaged bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.summary.TamperChainStartSeq = startSeq
	a.summary.KillSwitchEngagedDuringSession = killSwitchEngaged
}

// RecordKillSwitchChange records one committed transition affecting this
// active session. Once engaged, the during-session flag stays true even after
// a later disengage.
func (a *EnforceEventSummaryAccumulator) RecordKillSwitchChange(engaged bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.summary.KillSwitchChangeCount++
	if engaged {
		a.summary.KillSwitchEngagedDuringSession = true
	}
}

// RecordKillSwitchEvidenceGap marks that the kernel state may have changed
// without a committed receipt because both persistence and rollback failed.
func (a *EnforceEventSummaryAccumulator) RecordKillSwitchEvidenceGap(engaged bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.summary.KillSwitchEvidenceGap = true
	if engaged {
		a.summary.KillSwitchEngagedDuringSession = true
	}
}

// Snapshot returns a detached copy of the current summary.
func (a *EnforceEventSummaryAccumulator) Snapshot() EnforceEventSummary {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := EnforceEventSummary{
		TotalEvents:                    a.summary.TotalEvents,
		OrphanCount:                    a.summary.OrphanCount,
		LostSamples:                    a.summary.LostSamples,
		LastSeq:                        a.summary.LastSeq,
		ChainDigest:                    a.summary.ChainDigest,
		TamperChainStartSeq:            a.summary.TamperChainStartSeq,
		TamperChainLastSeq:             a.summary.TamperChainLastSeq,
		TamperChainDigest:              a.summary.TamperChainDigest,
		KillSwitchChangeCount:          a.summary.KillSwitchChangeCount,
		KillSwitchEngagedDuringSession: a.summary.KillSwitchEngagedDuringSession,
		KillSwitchEvidenceGap:          a.summary.KillSwitchEvidenceGap,
	}
	if len(a.summary.VerdictCounts) > 0 {
		out.VerdictCounts = make(map[string]uint64, len(a.summary.VerdictCounts))
		for k, v := range a.summary.VerdictCounts {
			out.VerdictCounts[k] = v
		}
	}
	if len(a.summary.TierCoverage) > 0 {
		out.TierCoverage = make(map[string]uint64, len(a.summary.TierCoverage))
		for k, v := range a.summary.TierCoverage {
			out.TierCoverage[k] = v
		}
	}
	return out
}
