package kernelcapture

import "time"

// ProcessEventType represents normalized process lifecycle classes.
type ProcessEventType string

const (
	ProcessEventExec ProcessEventType = "exec"
	ProcessEventExit ProcessEventType = "exit"
)

// ProcessEvent captures one kernel-observed process lifecycle observation.
//
// ObservedAt and ObservedMonotonicNS intentionally use separate bases:
//   - ObservedAt: daemon-owned wall-clock timestamp when available.
//   - ObservedMonotonicNS: kernel monotonic timestamp from producer samples.
//
// Correlation and restart-gap logic must not treat these as interchangeable.
type ProcessEvent struct {
	EventID                 string
	SessionID               string
	Type                    ProcessEventType
	PID                     uint32
	PPID                    uint32
	TID                     uint32
	PIDNamespaceID          uint64
	ProcessStartMonotonicNS uint64
	CgroupID                uint64
	Comm                    string
	ExitCode                int32
	ObservedAt              time.Time
	ObservedMonotonicNS     uint64
}

// ToolReceipt is the synthetic tool-call receipt we correlate kernel events to.
//
// PID alone is not sufficient for high-confidence attribution. Receipt windows
// and additional process identity (namespace/start-time/cgroup) are used to
// avoid stale or reused-PID matches.
type ToolReceipt struct {
	ReceiptID               string
	SessionID               string
	PID                     uint32
	PIDNamespaceID          uint64
	ProcessStartMonotonicNS uint64
	CgroupID                uint64
	SpanStart               time.Time
	SpanEnd                 time.Time
	ObservedAt              time.Time
}

// CaptureLoss carries loss counters for the capture pipeline.
type CaptureLoss struct {
	RingbufDropped     uint64
	DaemonQueueDropped uint64
}

// EventContext carries userspace pipeline health at event-processing time.
type EventContext struct {
	CaptureLoss CaptureLoss
	ConsumerLag bool
}

// SessionScope filters event streams to one monitored session boundary.
type SessionScope struct {
	SessionID string
	CgroupID  uint64
	PIDs      map[uint32]struct{}
}

func (s SessionScope) matches(evt ProcessEvent) bool {
	if s.SessionID != "" && evt.SessionID != s.SessionID {
		return false
	}
	if s.CgroupID != 0 && evt.CgroupID != s.CgroupID {
		return false
	}
	if len(s.PIDs) > 0 {
		if _, ok := s.PIDs[evt.PID]; !ok {
			return false
		}
	}
	return true
}

// ProcessTreeScope tracks a launched process tree after the root process is
// known. It is a userspace session filter used by the Phase 2 MVP harness; it
// does not claim kernel-map enforcement or production daemon custody.
type ProcessTreeScope struct {
	SessionID           string
	RootPID             uint32
	CgroupID            uint64
	PIDs                map[uint32]struct{}
	PIDStartMonotonicNS map[uint32]uint64
}

// NewProcessTreeScope returns a cgroup-guarded process-tree scope rooted at
// rootPID. A zero cgroup leaves the cgroup guard disabled for tests/replay.
func NewProcessTreeScope(rootPID uint32, cgroupID uint64) ProcessTreeScope {
	s := ProcessTreeScope{
		RootPID:             rootPID,
		CgroupID:            cgroupID,
		PIDs:                make(map[uint32]struct{}),
		PIDStartMonotonicNS: make(map[uint32]uint64),
	}
	if rootPID != 0 {
		s.PIDs[rootPID] = struct{}{}
	}
	return s
}

// MatchesAndTrack reports whether evt belongs to the current process tree. When
// evt is a direct child of a known PID, the child PID is added to the scope so
// grandchildren can be attributed by later events. Exit events retire PIDs from
// the live scope, which limits reused-PID false positives when the producer has
// not yet supplied ProcessStartMonotonicNS for every platform path.
func (s *ProcessTreeScope) MatchesAndTrack(evt ProcessEvent) bool {
	if evt.PID == 0 {
		return false
	}
	if s.SessionID != "" && evt.SessionID != "" && evt.SessionID != s.SessionID {
		return false
	}
	if s.CgroupID != 0 && evt.CgroupID != s.CgroupID {
		return false
	}
	s.ensureProcessTreeMaps()
	if s.RootPID != 0 {
		s.PIDs[s.RootPID] = struct{}{}
	}

	if _, ok := s.PIDs[evt.PID]; ok {
		if !s.pidIdentityMatches(evt) {
			delete(s.PIDs, evt.PID)
			delete(s.PIDStartMonotonicNS, evt.PID)
		} else {
			s.rememberPIDIdentity(evt)
			s.retirePIDOnExit(evt)
			return true
		}
	}
	if evt.PPID != 0 {
		if _, ok := s.PIDs[evt.PPID]; ok {
			s.PIDs[evt.PID] = struct{}{}
			s.rememberPIDIdentity(evt)
			s.retirePIDOnExit(evt)
			return true
		}
	}
	return false
}

func (s *ProcessTreeScope) ensureProcessTreeMaps() {
	if s.PIDs == nil {
		s.PIDs = make(map[uint32]struct{})
	}
	if s.PIDStartMonotonicNS == nil {
		s.PIDStartMonotonicNS = make(map[uint32]uint64)
	}
}

func (s *ProcessTreeScope) pidIdentityMatches(evt ProcessEvent) bool {
	knownStart := s.PIDStartMonotonicNS[evt.PID]
	return knownStart == 0 || evt.ProcessStartMonotonicNS == 0 || knownStart == evt.ProcessStartMonotonicNS
}

func (s *ProcessTreeScope) rememberPIDIdentity(evt ProcessEvent) {
	if evt.ProcessStartMonotonicNS != 0 {
		s.PIDStartMonotonicNS[evt.PID] = evt.ProcessStartMonotonicNS
	}
}

func (s *ProcessTreeScope) retirePIDOnExit(evt ProcessEvent) {
	if evt.Type == ProcessEventExit {
		delete(s.PIDs, evt.PID)
		delete(s.PIDStartMonotonicNS, evt.PID)
	}
}

// CorrelatorOptions configures correlation and health-window behavior.
type CorrelatorOptions struct {
	Platform         string
	CaptureBackend   string
	RestartGrace     time.Duration
	CorrelationGrace time.Duration
}

// SyntheticKernelReceipt is the kernel-effect synthetic receipt projection.
type SyntheticKernelReceipt struct {
	EventID               string      `json:"event_id"`
	EventClass            string      `json:"event_class"`
	CaptureBackend        string      `json:"capture_backend"`
	Platform              string      `json:"platform"`
	KernelEventType       string      `json:"kernel_event_type"`
	CoverageStatus        string      `json:"coverage_status"`
	CorrelationMethod     string      `json:"correlation_method"`
	CorrelationConfidence string      `json:"correlation_confidence"`
	CausedByReceiptID     string      `json:"caused_by_receipt_id"`
	CaptureLoss           CaptureLoss `json:"capture_loss"`
	Verdict               string      `json:"verdict"`
	PublicDenialReason    string      `json:"public_denial_reason,omitempty"`
	InternalDenialCode    string      `json:"internal_denial_code,omitempty"`
}
