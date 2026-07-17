package main

import (
	"testing"
	"time"
)

func TestWorkloadIsBoundedAndStrict(t *testing.T) {
	started := time.Now()
	if code := run([]string{"--workload-hold-milliseconds", "1"}); code != 0 {
		t.Fatalf("valid workload exit = %d", code)
	}
	if time.Since(started) > time.Second {
		t.Fatal("bounded workload slept unexpectedly long")
	}
	for _, args := range [][]string{
		nil,
		{"--workload-hold-milliseconds"},
		{"--workload-hold-milliseconds", "0"},
		{"--workload-hold-milliseconds", "10001"},
		{"--workload-hold-milliseconds", "not-a-number"},
		{"--unknown", "1"},
	} {
		if code := run(args); code != 2 {
			t.Fatalf("run(%v) exit = %d, want 2", args, code)
		}
	}
}
