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
	if got := a.matchNative("type_a", digestA); !reflect.DeepEqual(got, []string{"native.a"}) {
		t.Fatalf("matched rules = %v, want native.a", got)
	}

	documentB.Rules[1].ExpectedSHA256 = []string{hex.EncodeToString(digestA[:])}
	if _, err := NewAgentFingerprintRegistry(documentB); err == nil {
		t.Fatal("cross-agent digest reuse was accepted")
	}
}

func TestAgentFingerprintRegistryLauncherRulesAreVersionedAndInterpreterBound(t *testing.T) {
	t.Parallel()
	launcher := sha256.Sum256([]byte("trusted launcher"))
	native := sha256.Sum256([]byte("trusted native"))
	document := AgentFingerprintRegistryDocument{
		SchemaVersion:   AgentFingerprintRegistrySchema,
		RegistryVersion: "operator.launchers.v1",
		Rules: []AgentFingerprintRule{{
			RuleID:                     "launcher.codex",
			AgentType:                  "codex_cli",
			ExpectedSHA256:             []string{hex.EncodeToString(native[:])},
			ExpectedLauncherSHA256:     []string{stringsToUpperHex(launcher[:]), hex.EncodeToString(launcher[:])},
			AllowedInterpreterProfiles: []string{"python3", "sh", "python3"},
		}},
	}
	registry, err := NewAgentFingerprintRegistry(document)
	if err != nil {
		t.Fatal(err)
	}
	if !registry.HasLauncherRules() || !registry.hasNativeAgentType("codex_cli") || !registry.hasLauncherAgentType("codex_cli") {
		t.Fatalf("registry domains were not retained")
	}
	if got := registry.matchLauncher("codex_cli", launcher, "python3"); !reflect.DeepEqual(got, []string{"launcher.codex"}) {
		t.Fatalf("launcher match = %v", got)
	}
	if got := registry.matchLauncher("codex_cli", launcher, "ruby"); len(got) != 0 {
		t.Fatalf("disallowed interpreter matched launcher: %v", got)
	}
	if got := registry.matchNative("codex_cli", launcher); len(got) != 0 {
		t.Fatalf("launcher digest crossed into native domain: %v", got)
	}

	legacy, err := NewAgentFingerprintRegistry(AgentFingerprintRegistryDocument{
		SchemaVersion:   agentFingerprintRegistryLegacySchema,
		RegistryVersion: "operator.legacy.v1",
		Rules:           []AgentFingerprintRule{{RuleID: "native.codex", AgentType: "codex_cli", ExpectedSHA256: []string{hex.EncodeToString(native[:])}}},
	})
	if err != nil || legacy.HasLauncherRules() {
		t.Fatalf("legacy native registry compatibility failed: registry=%v err=%v", legacy, err)
	}

	invalid := document
	invalid.SchemaVersion = agentFingerprintRegistryLegacySchema
	if _, err := NewAgentFingerprintRegistry(invalid); err == nil {
		t.Fatal("legacy schema accepted launcher fields")
	}
	invalid = document
	invalid.Rules = append([]AgentFingerprintRule(nil), document.Rules...)
	invalid.Rules[0].AllowedInterpreterProfiles = nil
	if _, err := NewAgentFingerprintRegistry(invalid); err == nil {
		t.Fatal("launcher digest without interpreter profile was accepted")
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

func TestAgentFingerprintWorkerLauncherCapabilityIdentityAndInterpreterFailLow(t *testing.T) {
	t.Parallel()
	launcher := sha256.Sum256([]byte("trusted launcher"))
	registry, err := NewAgentFingerprintRegistry(AgentFingerprintRegistryDocument{
		SchemaVersion:   AgentFingerprintRegistrySchema,
		RegistryVersion: "operator.launchers.v1",
		Rules: []AgentFingerprintRule{{
			RuleID:                     "launcher.codex",
			AgentType:                  "codex_cli",
			ExpectedLauncherSHA256:     []string{hex.EncodeToString(launcher[:])},
			AllowedInterpreterProfiles: []string{"python3"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate := recognizedAgentCandidate("codex_cli")
	baseEvent := ProcessEvent{
		PID:                 42,
		Type:                ProcessEventExec,
		InterpreterBacked:   true,
		LauncherScript:      true,
		LauncherInterpreter: "python3",
		LauncherIdentity: LauncherObjectIdentity{
			Present: true, DeviceMajor: 8, DeviceMinor: 1, Inode: 99, MountID: 7, LinkCount: 1,
		},
	}

	worker, err := newAgentFingerprintWorker(registry, &fakeAgentFingerprintResolver{}, AgentFingerprintWorkerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	unsupported := worker.Submit(baseEvent, candidate)
	if unsupported == nil || unsupported.Outcome != AgentFingerprintOutcomeUnsupportedKernel {
		t.Fatalf("unavailable observer outcome = %+v", unsupported)
	}
	closeAgentFingerprintWorker(t, worker)

	worker, err = newAgentFingerprintWorker(registry, &fakeAgentFingerprintResolver{}, AgentFingerprintWorkerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	worker.SetLauncherIdentityAvailable(true)
	unsupportedShape := baseEvent
	unsupportedShape.LauncherScript = false
	unsupportedShape.LauncherIdentity = LauncherObjectIdentity{}
	unsupportedShapeObservation := worker.Submit(unsupportedShape, candidate)
	if unsupportedShapeObservation == nil || unsupportedShapeObservation.Outcome != AgentFingerprintOutcomeMissingIdentity {
		t.Fatalf("unsupported interpreter-backed shape outcome = %+v", unsupportedShapeObservation)
	}
	missingEvent := baseEvent
	missingEvent.LauncherIdentity = LauncherObjectIdentity{}
	missing := worker.Submit(missingEvent, candidate)
	if missing == nil || missing.Outcome != AgentFingerprintOutcomeMissingIdentity {
		t.Fatalf("missing identity outcome = %+v", missing)
	}
	deniedEvent := baseEvent
	deniedEvent.LauncherInterpreter = "ruby"
	denied := worker.Submit(deniedEvent, candidate)
	if denied == nil || denied.Outcome != AgentFingerprintOutcomeInterpreterDenied {
		t.Fatalf("interpreter outcome = %+v", denied)
	}
	closeAgentFingerprintWorker(t, worker)
}

func TestAgentFingerprintWorkerKernelBoundLauncherMatchIsPrivateAndObserveOnly(t *testing.T) {
	t.Parallel()
	launcher := sha256.Sum256([]byte("trusted launcher"))
	registry, err := NewAgentFingerprintRegistry(AgentFingerprintRegistryDocument{
		SchemaVersion:   AgentFingerprintRegistrySchema,
		RegistryVersion: "operator.launchers.v1",
		Rules: []AgentFingerprintRule{{
			RuleID:                     "launcher.codex",
			AgentType:                  "codex_cli",
			ExpectedLauncherSHA256:     []string{hex.EncodeToString(launcher[:])},
			AllowedInterpreterProfiles: []string{"python3"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan AgentFingerprintObservation, 1)
	resolver := &fakeAgentFingerprintResolver{digest: agentFingerprintDigest{
		digest: launcher, method: AgentFingerprintMethodSHA256KernelLauncher, objectState: AgentFingerprintObjectLinked,
	}}
	worker, err := newAgentFingerprintWorker(registry, resolver, AgentFingerprintWorkerOptions{
		Observer: func(_ ProcessEvent, _ AgentRecognitionResult, observation AgentFingerprintObservation) {
			observed <- observation
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	worker.SetLauncherIdentityAvailable(true)
	t.Cleanup(func() { closeAgentFingerprintWorker(t, worker) })
	event := ProcessEvent{
		PID: 42, Type: ProcessEventExec, LauncherScript: true, LauncherInterpreter: "python3",
		LauncherIdentity: LauncherObjectIdentity{Present: true, DeviceMajor: 8, DeviceMinor: 1, Inode: 99, MountID: 7, LinkCount: 1},
	}
	if immediate := worker.Submit(event, recognizedAgentCandidate("codex_cli")); immediate != nil {
		t.Fatalf("unexpected immediate result: %+v", immediate)
	}
	observation := receiveFingerprintObservation(t, observed)
	if observation.Outcome != AgentFingerprintOutcomeSuccess || observation.Method != AgentFingerprintMethodSHA256KernelLauncher || observation.IdentityAssurance != "heuristic_kernel_bound_launcher_content" || observation.GovernanceAction != "observe_only" {
		t.Fatalf("launcher observation = %+v", observation)
	}
	encoded, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"python3", "/trusted/launcher", hex.EncodeToString(launcher[:])} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("launcher observation exposed private input %q: %s", secret, encoded)
		}
	}
}

func TestAgentFingerprintWorkerDoesNotHashScriptAsNative(t *testing.T) {
	t.Parallel()
	native := sha256.Sum256([]byte("native"))
	registry := mustAgentFingerprintRegistry(t, "codex_cli", native)
	resolver := &fakeAgentFingerprintResolver{}
	worker, err := newAgentFingerprintWorker(registry, resolver, AgentFingerprintWorkerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeAgentFingerprintWorker(t, worker) })
	event := ProcessEvent{PID: 42, Type: ProcessEventExec, InterpreterBacked: true, LauncherScript: false, LauncherInterpreter: "sh"}
	if got := worker.Submit(event, recognizedAgentCandidate("codex_cli")); got != nil {
		t.Fatalf("script with native-only registry produced observation: %+v", got)
	}
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if len(resolver.targets) != 0 {
		t.Fatalf("script was bound to native resolver")
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
	panicOnResolve bool
	mu             sync.Mutex
	targets        []*fakeAgentFingerprintTarget
}

func (r *fakeAgentFingerprintResolver) Bind(ProcessEvent) (agentFingerprintTarget, string) {
	if r.bindOutcome != "" {
		return nil, r.bindOutcome
	}
	target := &fakeAgentFingerprintTarget{}
	r.mu.Lock()
	r.targets = append(r.targets, target)
	r.mu.Unlock()
	return target, ""
}

func (r *fakeAgentFingerprintResolver) Resolve(ctx context.Context, _ agentFingerprintTarget, _ agentFingerprintResolveLimits) (agentFingerprintDigest, string) {
	if r.panicOnResolve {
		panic("resolver blew up")
	}
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

// A panic in this observe-only lane must not unwind out of the worker
// goroutine and kill the capture daemon: the guard is pinned, so the kernel
// would keep enforcing while the kill switch and tamper chain became
// unreachable.
func TestAgentFingerprintWorkerContainsResolverPanic(t *testing.T) {
	digest := sha256.Sum256([]byte("trusted"))
	registry := mustAgentFingerprintRegistry(t, "codex_cli", digest)
	resolver := &fakeAgentFingerprintResolver{panicOnResolve: true}
	observed := make(chan AgentFingerprintObservation, 1)
	worker, err := newAgentFingerprintWorker(registry, resolver, AgentFingerprintWorkerOptions{
		QueueCapacity: 2,
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
	candidate := recognizedAgentCandidate("codex_cli")
	if got := worker.Submit(ProcessEvent{PID: 1, Type: ProcessEventExec}, candidate); got != nil {
		t.Fatalf("submit = %+v, want queued", got)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if worker.Health().Counters.WorkerUnavailable == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := worker.Health().Counters.WorkerUnavailable; got != 1 {
		t.Fatalf("worker_unavailable = %d, want 1 (panic not contained or not counted)", got)
	}

	// The pool must keep draining after a contained panic, not wedge.
	resolver.panicOnResolve = false
	if got := worker.Submit(ProcessEvent{PID: 2, Type: ProcessEventExec}, candidate); got != nil {
		t.Fatalf("submit after panic = %+v, want queued", got)
	}
	if got := receiveFingerprintObservation(t, observed); got.Outcome != AgentFingerprintOutcomeDigestMismatch {
		t.Fatalf("post-panic observation = %+v, want digest_mismatch", got)
	}
	closeAgentFingerprintWorker(t, worker)
}

// The Observer is caller-supplied, so it is itself a panic source. A recover
// handler that republished the observation would re-enter it and repanic, so
// this asserts containment without that re-entry.
func TestAgentFingerprintWorkerContainsObserverPanic(t *testing.T) {
	digest := sha256.Sum256([]byte("trusted"))
	registry := mustAgentFingerprintRegistry(t, "codex_cli", digest)
	resolver := &fakeAgentFingerprintResolver{digest: agentFingerprintDigest{
		digest: digest, method: AgentFingerprintMethodSHA256ProcExe, objectState: AgentFingerprintObjectLinked,
	}}
	observed := make(chan AgentFingerprintObservation, 1)
	var calls atomic.Uint32
	worker, err := newAgentFingerprintWorker(registry, resolver, AgentFingerprintWorkerOptions{
		QueueCapacity: 2,
		WorkerCount:   1,
		Timeout:       time.Second,
		MaxFileBytes:  1024,
		Observer: func(_ ProcessEvent, _ AgentRecognitionResult, observation AgentFingerprintObservation) {
			if calls.Add(1) == 1 {
				panic("observer blew up")
			}
			observed <- observation
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := worker.Submit(ProcessEvent{PID: 1, Type: ProcessEventExec}, recognizedAgentCandidate("codex_cli")); got != nil {
		t.Fatalf("submit = %+v, want queued", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if worker.Health().Counters.WorkerUnavailable == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := worker.Health().Counters.WorkerUnavailable; got != 1 {
		t.Fatalf("worker_unavailable = %d, want 1 after observer panic", got)
	}
	if got := worker.Health().Counters.Success; got != 0 {
		t.Fatalf("success = %d, want 0 after unpublished observer panic", got)
	}
	if got := worker.Submit(ProcessEvent{PID: 2, Type: ProcessEventExec}, recognizedAgentCandidate("codex_cli")); got != nil {
		t.Fatalf("submit after observer panic = %+v, want queued", got)
	}
	if got := receiveFingerprintObservation(t, observed); got.Outcome != AgentFingerprintOutcomeSuccess {
		t.Fatalf("post-observer-panic observation = %+v, want success", got)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("observer calls = %d, want 2", got)
	}
	closeAgentFingerprintWorker(t, worker)
	health := worker.Health().Counters
	if health.Success != 1 || health.WorkerUnavailable != 1 {
		t.Fatalf("terminal counters = %+v, want one success and one worker_unavailable", health)
	}
}

func TestAgentFingerprintWorkerCountsSubmitAfterClose(t *testing.T) {
	digest := sha256.Sum256([]byte("trusted"))
	registry := mustAgentFingerprintRegistry(t, "codex_cli", digest)
	worker, err := newAgentFingerprintWorker(registry, &fakeAgentFingerprintResolver{}, AgentFingerprintWorkerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	closeAgentFingerprintWorker(t, worker)
	got := worker.Submit(ProcessEvent{PID: 1, Type: ProcessEventExec}, recognizedAgentCandidate("codex_cli"))
	if got == nil || got.Outcome != AgentFingerprintOutcomeWorkerUnavailable {
		t.Fatalf("submit after close = %+v", got)
	}
	if counted := worker.Health().Counters.WorkerUnavailable; counted != 1 {
		t.Fatalf("worker_unavailable = %d, want 1", counted)
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
