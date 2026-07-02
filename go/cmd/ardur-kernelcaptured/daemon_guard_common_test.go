package main

// daemon_guard_common_test.go — tests for the platform-independent BPF-LSM
// guard event handling (daemon_guard_common.go). Runs on darwin and Linux
// alike: decodeEnforceEvent, processEnforceEvent, and enforceEventVerdict do
// not touch BPF maps or kernel state.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

// encodeTestEnforceEvent builds a raw 304-byte buffer matching
// struct ardur_enforce_event in process_guard.bpf.c, in native-endian layout.
func encodeTestEnforceEvent(t *testing.T, cgroupID uint64, pid, op, action, mode uint32, observedNS uint64, comm, path string) []byte {
	t.Helper()
	var buf bytes.Buffer
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("encode enforce event: %v", err)
		}
	}
	must(binary.Write(&buf, binary.NativeEndian, cgroupID))
	must(binary.Write(&buf, binary.NativeEndian, pid))
	must(binary.Write(&buf, binary.NativeEndian, op))
	must(binary.Write(&buf, binary.NativeEndian, action))
	must(binary.Write(&buf, binary.NativeEndian, mode))
	must(binary.Write(&buf, binary.NativeEndian, observedNS))

	var comm16 [16]byte
	copy(comm16[:], comm)
	must(binary.Write(&buf, binary.NativeEndian, comm16))

	var path256 [256]byte
	copy(path256[:], path)
	must(binary.Write(&buf, binary.NativeEndian, path256))

	return buf.Bytes()
}

func TestDecodeEnforceEvent_RoundTrip(t *testing.T) {
	t.Parallel()
	raw := encodeTestEnforceEvent(t, 0xdeadbeef, 4242, uint32(kernelcapture.BpfOpExec),
		uint32(kernelcapture.BpfActionDeny), uint32(kernelcapture.BpfEnforceModeEnforce),
		123456789, "python3", "/usr/bin/python3")

	ev, err := decodeEnforceEvent(raw)
	if err != nil {
		t.Fatalf("decodeEnforceEvent: unexpected error: %v", err)
	}
	if ev.CgroupID != 0xdeadbeef {
		t.Errorf("CgroupID = %#x, want 0xdeadbeef", ev.CgroupID)
	}
	if ev.PID != 4242 {
		t.Errorf("PID = %d, want 4242", ev.PID)
	}
	if ev.Op != kernelcapture.BpfOpExec {
		t.Errorf("Op = %v, want OP_EXEC", ev.Op)
	}
	if ev.ActionTaken != kernelcapture.BpfActionDeny {
		t.Errorf("ActionTaken = %v, want ACT_DENY", ev.ActionTaken)
	}
	if ev.EnforceMode != kernelcapture.BpfEnforceModeEnforce {
		t.Errorf("EnforceMode = %v, want ENFORCE", ev.EnforceMode)
	}
	if ev.ObservedNS != 123456789 {
		t.Errorf("ObservedNS = %d, want 123456789", ev.ObservedNS)
	}
	if ev.Comm != "python3" {
		t.Errorf("Comm = %q, want %q", ev.Comm, "python3")
	}
	if ev.Path != "/usr/bin/python3" {
		t.Errorf("Path = %q, want %q", ev.Path, "/usr/bin/python3")
	}
}

func TestDecodeEnforceEvent_FullLengthPathNotTruncated(t *testing.T) {
	t.Parallel()
	// A path that fills the entire 256-byte buffer (no trailing NUL) must
	// decode in full — this is the userspace-side analogue of the BPF
	// path_is_allowed copy_len&255 bug: a full-length path must not come
	// back empty or truncated.
	fullPath := strings.Repeat("a", 256)
	raw := encodeTestEnforceEvent(t, 1, 1, uint32(kernelcapture.BpfOpFileRead),
		uint32(kernelcapture.BpfActionAllow), uint32(kernelcapture.BpfEnforceModePermissive),
		1, "cat", fullPath)

	ev, err := decodeEnforceEvent(raw)
	if err != nil {
		t.Fatalf("decodeEnforceEvent: unexpected error: %v", err)
	}
	if ev.Path != fullPath {
		t.Errorf("Path length = %d, want %d (full buffer must decode intact)", len(ev.Path), len(fullPath))
	}
}

func TestDecodeEnforceEvent_TooShortErrors(t *testing.T) {
	t.Parallel()
	if _, err := decodeEnforceEvent(make([]byte, 10)); err == nil {
		t.Error("decodeEnforceEvent on a 10-byte buffer: expected error, got nil")
	}
}

func TestEnforceEventVerdict(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ev   kernelcapture.BpfEnforceEvent
		want string
	}{
		{
			name: "deny+enforce is denied",
			ev:   kernelcapture.BpfEnforceEvent{ActionTaken: kernelcapture.BpfActionDeny, EnforceMode: kernelcapture.BpfEnforceModeEnforce},
			want: kernelcapture.SyntheticKernelReceiptVerdictDenied,
		},
		{
			name: "deny+permissive is blocked (logged only)",
			ev:   kernelcapture.BpfEnforceEvent{ActionTaken: kernelcapture.BpfActionDeny, EnforceMode: kernelcapture.BpfEnforceModePermissive},
			want: kernelcapture.SyntheticKernelReceiptVerdictBlocked,
		},
		{
			name: "allowlist miss is blocked",
			ev:   kernelcapture.BpfEnforceEvent{ActionTaken: kernelcapture.BpfActionAllowlist},
			want: kernelcapture.SyntheticKernelReceiptVerdictBlocked,
		},
		{
			name: "allow is compliant",
			ev:   kernelcapture.BpfEnforceEvent{ActionTaken: kernelcapture.BpfActionAllow},
			want: kernelcapture.SyntheticKernelReceiptVerdictCompliant,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := enforceEventVerdict(c.ev); got != c.want {
				t.Errorf("enforceEventVerdict(%+v) = %q, want %q", c.ev, got, c.want)
			}
		})
	}
}

func TestProcessEnforceEvent_AppendsReceiptForRegisteredCgroup(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	stub := newStubFS()
	d.fs = stub
	d.cgroupIndex[555] = "ses-guard-001"

	ev := kernelcapture.BpfEnforceEvent{
		CgroupID:    555,
		PID:         99,
		Op:          kernelcapture.BpfOpExec,
		ActionTaken: kernelcapture.BpfActionDeny,
		EnforceMode: kernelcapture.BpfEnforceModeEnforce,
		Comm:        "sh",
		Path:        "/bin/sh",
	}
	d.processEnforceEvent(ev, testLogger(t))

	found := false
	for path, data := range stub.appends {
		if !strings.HasSuffix(path, "enforce_events.jsonl") {
			continue
		}
		var entry EnforceReceiptEntry
		if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
			t.Fatalf("unmarshal receipt entry: %v", err)
		}
		if entry.SessionID != "ses-guard-001" {
			t.Errorf("SessionID = %q, want ses-guard-001", entry.SessionID)
		}
		if entry.Verdict != kernelcapture.SyntheticKernelReceiptVerdictDenied {
			t.Errorf("Verdict = %q, want denied", entry.Verdict)
		}
		found = true
	}
	if !found {
		t.Error("no enforce_events.jsonl append recorded")
	}
}

func TestProcessEnforceEvent_IgnoresUnregisteredCgroup(t *testing.T) {
	t.Parallel()
	d := newTestDaemon(t)
	stub := newStubFS()
	d.fs = stub
	// cgroupIndex intentionally left empty.

	d.processEnforceEvent(kernelcapture.BpfEnforceEvent{CgroupID: 999}, testLogger(t))

	if len(stub.appends) != 0 {
		t.Errorf("expected no evidence writes for an unregistered cgroup, got %d", len(stub.appends))
	}
}
