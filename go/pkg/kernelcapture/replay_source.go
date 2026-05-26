package kernelcapture

// ReplayEventSource is a deterministic in-memory source used by tests and demos.
type ReplayEventSource struct {
	events []ProcessEvent
	next   int
}

// NewReplayEventSource returns a replay source over a defensive copy of events.
func NewReplayEventSource(events []ProcessEvent) *ReplayEventSource {
	cp := make([]ProcessEvent, len(events))
	copy(cp, events)
	return &ReplayEventSource{events: cp}
}

// Next returns the next event that matches scope, if any.
func (s *ReplayEventSource) Next(scope SessionScope) (ProcessEvent, bool) {
	for s.next < len(s.events) {
		evt := s.events[s.next]
		s.next++
		if scope.matches(evt) {
			return evt, true
		}
	}
	return ProcessEvent{}, false
}
