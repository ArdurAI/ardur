package kernelcapture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAgentFingerprintRegistryCanonicalizesAndRejectsCrossClassDigestReuse(t *testing.T) {
	digestA := sha256.Sum256([]byte("agent-a"))
	digestB := sha256.Sum256([]byte("agent-b"))
	documentA := AgentFingerprintRegistryDocument{
		SchemaVersion:   AgentFingerprintRegistrySchema,
		RegistryVersion: "operator.registry.v1",
		Rules: []AgentFingerprintRule{
			{RuleID: "native.b", AgentType: "type_b", ExpectedSHA256: []string{hex.EncodeToString(digestB[:])}},
			{RuleID: "native.a", AgentType: "type_a", ExpectedSHA256: []string{stringsToUpperHex(digestA[:]), hex.EncodeToString(digestA[:])}},
		},
	}
	documentB := AgentFingerprintRegistryDocument{
		SchemaVersion:   AgentFingerprintRegistrySchema,
		RegistryVersion: "operator.registry.v1",
		Rules: []AgentFingerprintRule{
			{RuleID: "native.a", AgentType: "type_a", ExpectedSHA256: []string{hex.EncodeToString(digestA[:])}},
			{RuleID: "native.b", AgentType: "type_b", ExpectedSHA256: []string{hex.EncodeToString(digestB[:])}},
		},
	}
	a, err := NewAgentFingerprintRegistry(documentA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAgentFingerprintRegistry(documentB)
	if err != nil {
		t.Fatal(err)
	}
	if a.digest != b.digest || len(a.digest) != sha256.Size*2 {
		t.Fatalf("canonical registry digests differ: %q != %q", a.digest, b.digest)
	}
	if got := a.match("type_a", digestA); !reflect.DeepEqual(got, []string{"native.a"}) {
		t.Fatalf("matched rules = %v, want native.a", got)
	}

	documentB.Rules[1].ExpectedSHA256 = []string{hex.EncodeToString(digestA[:])}
	if _, err := NewAgentFingerprintRegistry(documentB); err == nil {
		t.Fatal("cross-agent digest reuse was accepted")
	}
}

func TestParseAgentFingerprintRegistryRejectsUnknownOrTrailingData(t *testing.T) {
	digest := sha256.Sum256([]byte("trusted"))
	valid := fmt.Sprintf(`{"schema_version":%q,"registry_version":"operator.v1","rules":[{"rule_id":"native.a","agent_type":"type_a","expected_sha256":[%q]}]}`,
		AgentFingerprintRegistrySchema, hex.EncodeToString(digest[:]))
	for _, raw := range []string{
		valid[:len(valid)-1] + `,"unknown":true}`,
		valid + `{}`,
		valid + strings.Repeat(" ", MaxAgentFingerprintRegistryBytes),
	} {
		if _, err := ParseAgentFingerprintRegistry(bytes.NewBufferString(raw)); err == nil {
			t.Fatalf("invalid registry was accepted: %s", raw)
		}
	}
}

func TestAgentFingerprintRegistryValidatesActiveRecognizerAgentTypes(t *testing.T) {
	digest := sha256.Sum256([]byte("trusted"))
	registry := mustAgentFingerprintRegistry(t, "codex_cli", digest)
	if err := registry.ValidateAgentTypes([]string{"codex_cli"}); err != nil {
		t.Fatalf("active agent type rejected: %v", err)
	}
	if err := registry.ValidateAgentTypes([]string{"claude_code"}); err == nil {
		t.Fatal("unknown registry agent type was accepted")
	}
}

func TestAgentFingerprintWorkerMatchAndMismatchNeverExposeComputedDigest(t *testing.T) {
	trusted := sha256.Sum256([]byte("trusted executable"))
	untrusted := sha256.Sum256([]byte("masquerading executable"))
	registry := mustAgentFingerprintRegistry(t, "codex_cli", trusted)
	for _, test := range []struct {
		name           string
		digest         [sha256.Size]byte
		wantOutcome    string
		wantConfidence string
	}{
		{name: "match", digest: trusted, wantOutcome: AgentFingerprintOutcomeSuccess, wantConfidence: AgentRecognitionConfidenceMedium},
		{name: "mismatch", digest: untrusted, wantOutcome: AgentFingerprintOutcomeDigestMismatch, wantConfidence: AgentRecognitionConfidenceLow},
	} {
		t.Run(test.name, func(t *testing.T) {
			observed := make(chan AgentFingerprintObservation, 1)
			resolver := &fakeAgentFingerprintResolver{digest: agentFingerprintDigest{
				digest: test.digest, method: AgentFingerprintMethodSHA256ProcExe, objectState: AgentFingerprintObjectLinked,
			}}
			worker, err := newAgentFingerprintWorker(registry, resolver, AgentFingerprintWorkerOptions{
				QueueCapacity: 1,
				WorkerCount:   1,
				Timeout:       time.Second,
				MaxFileBytes:  1024,
				Observer: func(_ ProcessEvent, _ AgentRecognitionResult, observation AgentFingerprintObservation) {
					observed <- observation
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeAgentFingerprintWorker(t, worker) })

			candidate := recognizedAgentCandidate("codex_cli")
			if immediate := worker.Submit(ProcessEvent{PID: 42, Type: ProcessEventExec}, candidate); immediate != nil {
				t.Fatalf("unexpected immediate result: %+v", immediate)
			}
			observation := receiveFingerprintObservation(t, observed)
			if observation.Outcome != test.wantOutcome || observation.Confidence != test.wantConfidence {
				t.Fatalf("observation = %+v, want outcome=%q confidence=%q", observation, test.wantOutcome, test.wantConfidence)
			}
			if observation.GovernanceAction != "observe_only" {
				t.Fatalf("fingerprint widened governance: %+v", observation)
			}
			encoded, err := json.Marshal(observation)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{hex.EncodeToString(test.digest[:]), "/private/agent", "--secret"} {
				if bytes.Contains(encoded, []byte(secret)) {
					t.Fatalf("observation exposed private fingerprint input %q: %s", secret, encoded)
				}
			}
		})
	}
}

func TestAgentFingerprintWorkerReportsBindFailuresAndCounters(t *testing.T) {
	trusted := sha256.Sum256([]byte("trusted"))
	registry := mustAgentFingerprintRegistry(t, "codex_cli", trusted)
	for _, outcome := range []string{
		AgentFingerprintOutcomeProcessExited,
		AgentFingerprintOutcomeResolutionDenied,
		AgentFingerprintOutcomeUnsupported,
	} {
		t.Run(outcome, func(t *testing.T) {
			worker, err := newAgentFingerprintWorker(registry, &fakeAgentFingerprintResolver{bindOutcome: outcome}, AgentFingerprintWorkerOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeAgentFingerprintWorker(t, worker) })
			observation := worker.Submit(ProcessEvent{PID: 42, Type: ProcessEventExec}, recognizedAgentCandidate("codex_cli"))
			if observation == nil || observation.Outcome != outcome || observation.Confidence != AgentRecognitionConfidenceLow {
				t.Fatalf("immediate observation = %+v, want %q low-confidence", observation, outcome)
			}
			health := worker.Health()
			switch outcome {
			case AgentFingerprintOutcomeProcessExited:
				if health.Counters.ProcessExited != 1 {
					t.Fatalf("counters = %+v", health.Counters)
				}
			case AgentFingerprintOutcomeResolutionDenied:
				if health.Counters.ResolutionDenied != 1 {
					t.Fatalf("counters = %+v", health.Counters)
				}
			case AgentFingerprintOutcomeUnsupported:
				if health.Counters.Unsupported != 1 {
					t.Fatalf("counters = %+v", health.Counters)
				}
			}
		})
	}
}

func TestAgentFingerprintWorkerQueueSaturationIsImmediateAndBounded(t *testing.T) {
	trusted := sha256.Sum256([]byte("trusted"))
	registry := mustAgentFingerprintRegistry(t, "codex_cli", trusted)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	resolver := &fakeAgentFingerprintResolver{
		digest:  agentFingerprintDigest{digest: trusted, method: AgentFingerprintMethodSHA256ProcExe, objectState: AgentFingerprintObjectLinked},
		started: started,
		release: release,
	}
	observed := make(chan AgentFingerprintObservation, 2)
	worker, err := newAgentFingerprintWorker(registry, resolver, AgentFingerprintWorkerOptions{
		QueueCapacity: 1,
		WorkerCount:   1,
		Timeout:       time.Second,
		MaxFileBytes:  1024,
		Observer: func(_ ProcessEvent, _ AgentRecognitionResult, observation AgentFingerprintObservation) {
			select {
			case observed <- observation:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeAgentFingerprintWorker(t, worker) })
	candidate := recognizedAgentCandidate("codex_cli")
	if got := worker.Submit(ProcessEvent{PID: 1, Type: ProcessEventExec}, candidate); got != nil {
		t.Fatalf("first submit = %+v", got)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first job did not start")
	}
	if got := worker.Submit(ProcessEvent{PID: 2, Type: ProcessEventExec}, candidate); got != nil {
		t.Fatalf("queued submit = %+v", got)
	}
	start := time.Now()
	saturated := worker.Submit(ProcessEvent{PID: 3, Type: ProcessEventExec}, candidate)
	if saturated == nil || saturated.Outcome != AgentFingerprintOutcomeQueueSaturated {
		t.Fatalf("saturated submit = %+v", saturated)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("saturated submit blocked for %s", elapsed)
	}
	if health := worker.Health(); health.QueueDepth != 1 || health.Counters.QueueSaturated != 1 {
		t.Fatalf("health = %+v", health)
	}
	close(release)
	for range 2 {
		if got := receiveFingerprintObservation(t, observed); got.Outcome != AgentFingerprintOutcomeSuccess {
			t.Fatalf("queued observation = %+v", got)
		}
	}
	if got := resolver.maxTargetCloseCount(); got > 1 {
		t.Fatalf("target closed %d times", got)
	}
}

func TestAgentFingerprintWorkerDeadlineAndConcurrentClose(t *testing.T) {
	trusted := sha256.Sum256([]byte("trusted"))
	registry := mustAgentFingerprintRegistry(t, "codex_cli", trusted)
	observed := make(chan AgentFingerprintObservation, 1)
	resolver := &fakeAgentFingerprintResolver{waitForContext: true}
	worker, err := newAgentFingerprintWorker(registry, resolver, AgentFingerprintWorkerOptions{
		QueueCapacity: 8,
		WorkerCount:   2,
		Timeout:       10 * time.Millisecond,
		MaxFileBytes:  1024,
		Observer: func(_ ProcessEvent, _ AgentRecognitionResult, observation AgentFingerprintObservation) {
			select {
			case observed <- observation:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate := recognizedAgentCandidate("codex_cli")
	if got := worker.Submit(ProcessEvent{PID: 1, Type: ProcessEventExec}, candidate); got != nil {
		t.Fatalf("submit = %+v", got)
	}
	if got := receiveFingerprintObservation(t, observed); got.Outcome != AgentFingerprintOutcomeDeadlineExceeded {
		t.Fatalf("deadline observation = %+v", got)
	}
	if worker.Health().Counters.DeadlineExceeded != 1 {
		t.Fatalf("health = %+v", worker.Health())
	}

	var submitters sync.WaitGroup
	for index := 0; index < 32; index++ {
		submitters.Add(1)
		go func(pid uint32) {
			defer submitters.Done()
			_ = worker.Submit(ProcessEvent{PID: pid + 10, Type: ProcessEventExec}, candidate)
		}(uint32(index))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := worker.Close(ctx); err != nil {
		t.Fatal(err)
	}
	submitters.Wait()
	if got := worker.Submit(ProcessEvent{PID: 99, Type: ProcessEventExec}, candidate); got == nil || got.Outcome != AgentFingerprintOutcomeWorkerUnavailable {
		t.Fatalf("submit after close = %+v", got)
	}
}

type fakeAgentFingerprintTarget struct {
	closeCount atomic.Int32
}

func (t *fakeAgentFingerprintTarget) Close() error {
	if t.closeCount.Add(1) > 1 {
		return errors.New("target closed more than once")
	}
	return nil
}

type fakeAgentFingerprintResolver struct {
	bindOutcome    string
	digest         agentFingerprintDigest
	resolveOutcome string
	started        chan struct{}
	release        chan struct{}
	waitForContext bool
	mu             sync.Mutex
	targets        []*fakeAgentFingerprintTarget
}

func (r *fakeAgentFingerprintResolver) Bind(uint32) (agentFingerprintTarget, string) {
	if r.bindOutcome != "" {
		return nil, r.bindOutcome
	}
	target := &fakeAgentFingerprintTarget{}
	r.mu.Lock()
	r.targets = append(r.targets, target)
	r.mu.Unlock()
	return target, ""
}

func (r *fakeAgentFingerprintResolver) Resolve(ctx context.Context, _ agentFingerprintTarget, _ int64) (agentFingerprintDigest, string) {
	if r.started != nil {
		select {
		case r.started <- struct{}{}:
		default:
		}
	}
	if r.waitForContext {
		<-ctx.Done()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return agentFingerprintDigest{}, AgentFingerprintOutcomeDeadlineExceeded
		}
		return agentFingerprintDigest{}, AgentFingerprintOutcomeWorkerUnavailable
	}
	if r.release != nil {
		select {
		case <-r.release:
		case <-ctx.Done():
			return agentFingerprintDigest{}, AgentFingerprintOutcomeDeadlineExceeded
		}
	}
	return r.digest, r.resolveOutcome
}

func (r *fakeAgentFingerprintResolver) maxTargetCloseCount() int32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	var max int32
	for _, target := range r.targets {
		if count := target.closeCount.Load(); count > max {
			max = count
		}
	}
	return max
}

func mustAgentFingerprintRegistry(t *testing.T, agentType string, digest [sha256.Size]byte) *AgentFingerprintRegistry {
	t.Helper()
	registry, err := NewAgentFingerprintRegistry(AgentFingerprintRegistryDocument{
		SchemaVersion:   AgentFingerprintRegistrySchema,
		RegistryVersion: "operator.registry.v1",
		Rules: []AgentFingerprintRule{{
			RuleID: "native." + agentType, AgentType: agentType, ExpectedSHA256: []string{hex.EncodeToString(digest[:])},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func recognizedAgentCandidate(agentType string) AgentRecognitionResult {
	return AgentRecognitionResult{
		Status:            AgentRecognitionStatusRecognized,
		AgentType:         agentType,
		Confidence:        AgentRecognitionConfidenceLow,
		IdentityAssurance: "heuristic_process_metadata",
		GovernanceAction:  "observe_only",
	}
}

func receiveFingerprintObservation(t *testing.T, ch <-chan AgentFingerprintObservation) AgentFingerprintObservation {
	t.Helper()
	select {
	case observation := <-ch:
		return observation
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for fingerprint observation")
		return AgentFingerprintObservation{}
	}
}

func closeAgentFingerprintWorker(t *testing.T, worker *AgentFingerprintWorker) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := worker.Close(ctx); err != nil {
		t.Errorf("close worker: %v", err)
	}
}

func stringsToUpperHex(value []byte) string {
	encoded := hex.EncodeToString(value)
	result := make([]byte, len(encoded))
	for index, ch := range []byte(encoded) {
		if ch >= 'a' && ch <= 'f' {
			ch -= 'a' - 'A'
		}
		result[index] = ch
	}
	return string(result)
}
