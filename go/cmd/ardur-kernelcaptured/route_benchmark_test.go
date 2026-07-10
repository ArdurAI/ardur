package main

import (
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

var benchmarkRouteSessionCounts = []int{1, 8, 64, 256}

func BenchmarkRouteEventFastPathParallel(b *testing.B) {
	for _, sessionCount := range benchmarkRouteSessionCounts {
		b.Run(fmt.Sprintf("sessions-%d", sessionCount), func(b *testing.B) {
			d := newBenchmarkRouteDaemon(sessionCount)
			assertBenchmarkRouteMatch(b, d, 0)
			var next atomic.Uint64
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					index := int(next.Add(1)-1) % sessionCount
					evt := benchmarkRouteEvent(index)
					d.routeEvent(&evt)
				}
			})
		})
	}
}

func BenchmarkRouteEventUnownedParallel(b *testing.B) {
	for _, sessionCount := range benchmarkRouteSessionCounts {
		b.Run(fmt.Sprintf("sessions-%d", sessionCount), func(b *testing.B) {
			d := newBenchmarkRouteDaemon(sessionCount)
			evt := kernelcapture.ProcessEvent{PID: 1, CgroupID: ^uint64(0), Type: kernelcapture.ProcessEventExec}
			if sid, correlator := d.routeEvent(&evt); sid != "" || correlator != nil {
				b.Fatalf("unowned probe routed to session %q", sid)
			}
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					probe := evt
					d.routeEvent(&probe)
				}
			})
		})
	}
}

func BenchmarkRouteEventFallbackParallel(b *testing.B) {
	for _, sessionCount := range benchmarkRouteSessionCounts {
		b.Run(fmt.Sprintf("sessions-%d", sessionCount), func(b *testing.B) {
			d := newBenchmarkFallbackRouteDaemon(sessionCount)
			var next atomic.Uint64
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					index := int(next.Add(1)-1) % sessionCount
					evt := benchmarkFallbackRouteEvent(index)
					d.routeEvent(&evt)
				}
			})
		})
	}
}

func newBenchmarkRouteDaemon(sessionCount int) *daemon {
	d := &daemon{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		cgroupIndex: make(map[uint64]string, sessionCount),
		treeScopes:  make(map[string]*kernelcapture.ProcessTreeScope, sessionCount),
		correlators: make(map[string]*kernelcapture.Correlator, sessionCount),
		routeIndex:  make(map[string]*sessionRoute, sessionCount),
	}
	for index := 0; index < sessionCount; index++ {
		sessionID := benchmarkRouteSessionID(index)
		evt := benchmarkRouteEvent(index)
		scope := kernelcapture.NewProcessTreeScope(evt.PID, evt.CgroupID)
		scope.SessionID = sessionID
		d.cgroupIndex[evt.CgroupID] = sessionID
		d.treeScopes[sessionID] = &scope
		correlator := kernelcapture.NewCorrelator(kernelcapture.CorrelatorOptions{})
		d.correlators[sessionID] = correlator
		d.publishSessionRouteLocked(newSessionRoute(sessionID, &scope, correlator))
	}
	return d
}

func newBenchmarkFallbackRouteDaemon(sessionCount int) *daemon {
	d := newBenchmarkRouteDaemon(0)
	for index := 0; index < sessionCount; index++ {
		sessionID := benchmarkRouteSessionID(index)
		evt := benchmarkFallbackRouteEvent(index)
		scope := kernelcapture.NewProcessTreeScope(evt.PID, 0)
		scope.SessionID = sessionID
		d.treeScopes[sessionID] = &scope
		correlator := kernelcapture.NewCorrelator(kernelcapture.CorrelatorOptions{})
		d.correlators[sessionID] = correlator
		d.publishSessionRouteLocked(newSessionRoute(sessionID, &scope, correlator))
	}
	return d
}

func assertBenchmarkRouteMatch(b *testing.B, d *daemon, index int) {
	b.Helper()
	evt := benchmarkRouteEvent(index)
	want := benchmarkRouteSessionID(index)
	if sid, correlator := d.routeEvent(&evt); sid != want || correlator == nil {
		b.Fatalf("fast-path probe = (%q, %v), want (%q, non-nil)", sid, correlator, want)
	}
}

func benchmarkRouteEvent(index int) kernelcapture.ProcessEvent {
	return kernelcapture.ProcessEvent{
		PID:      uint32(1_000 + index),
		CgroupID: uint64(10_000 + index),
		Type:     kernelcapture.ProcessEventExec,
	}
}

func benchmarkFallbackRouteEvent(index int) kernelcapture.ProcessEvent {
	return kernelcapture.ProcessEvent{
		PID:  uint32(1_000 + index),
		Type: kernelcapture.ProcessEventExec,
	}
}

func benchmarkRouteSessionID(index int) string {
	return fmt.Sprintf("benchmark-session-%d", index)
}
