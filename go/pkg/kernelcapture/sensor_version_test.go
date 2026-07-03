package kernelcapture

import (
	"errors"
	"testing"
)

func TestExtractSensorVersion(t *testing.T) {
	t.Parallel()
	config := []byte("# comment\n[daemon]\nversion      = \"1.2.3\"\nsocket_path = \"/x\"\n")
	v, ok := ExtractSensorVersion(config)
	if !ok || v != "1.2.3" {
		t.Fatalf("ExtractSensorVersion() = (%q, %v), want (\"1.2.3\", true)", v, ok)
	}
}

func TestExtractSensorVersion_MissingLine(t *testing.T) {
	t.Parallel()
	_, ok := ExtractSensorVersion([]byte("[daemon]\nsocket_path = \"/x\"\n"))
	if ok {
		t.Fatal("expected ok=false for config with no version line")
	}
}

func TestParseSensorVersion(t *testing.T) {
	t.Parallel()
	maj, min, patch, err := ParseSensorVersion("1.2.3")
	if err != nil {
		t.Fatalf("ParseSensorVersion: %v", err)
	}
	if maj != 1 || min != 2 || patch != 3 {
		t.Fatalf("ParseSensorVersion(\"1.2.3\") = (%d,%d,%d), want (1,2,3)", maj, min, patch)
	}
}

func TestParseSensorVersion_RejectsMalformed(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"1.2", "1.2.3.4", "a.b.c", "1.2.-3", "", "1.2.3-rc1"} {
		if _, _, _, err := ParseSensorVersion(bad); err == nil {
			t.Errorf("ParseSensorVersion(%q) accepted, want error", bad)
		}
	}
}

func TestCompareSensorVersions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"1.1.0", "1.0.9", 1},
		{"2.0.0", "1.9.9", 1},
		{"0.2.0", "0.10.0", -1}, // proves integer compare, not string compare
	}
	for _, c := range cases {
		got, err := CompareSensorVersions(c.a, c.b)
		if err != nil {
			t.Fatalf("CompareSensorVersions(%q, %q): %v", c.a, c.b, err)
		}
		if got != c.want {
			t.Errorf("CompareSensorVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCheckSensorVersionDowngrade_RefusesOlderCandidate(t *testing.T) {
	t.Parallel()
	existing := []byte(`version = "2.0.0"` + "\n")
	err := checkSensorVersionDowngrade("1.5.0", existing, false)
	if err == nil {
		t.Fatal("expected downgrade refusal, got nil")
	}
	if !errors.Is(err, ErrSensorVersionDowngradeRefused) {
		t.Fatalf("error = %v, want wrapping ErrSensorVersionDowngradeRefused", err)
	}
}

func TestCheckSensorVersionDowngrade_AllowsOlderCandidateWithOverride(t *testing.T) {
	t.Parallel()
	existing := []byte(`version = "2.0.0"` + "\n")
	if err := checkSensorVersionDowngrade("1.5.0", existing, true); err != nil {
		t.Fatalf("expected allow-downgrade override to permit install, got %v", err)
	}
}

func TestCheckSensorVersionDowngrade_AllowsUpgrade(t *testing.T) {
	t.Parallel()
	existing := []byte(`version = "1.0.0"` + "\n")
	if err := checkSensorVersionDowngrade("2.0.0", existing, false); err != nil {
		t.Fatalf("expected upgrade to proceed without override, got %v", err)
	}
}

func TestCheckSensorVersionDowngrade_AllowsSameVersion(t *testing.T) {
	t.Parallel()
	existing := []byte(`version = "1.0.0"` + "\n")
	if err := checkSensorVersionDowngrade("1.0.0", existing, false); err != nil {
		t.Fatalf("expected reinstall of same version to proceed, got %v", err)
	}
}

func TestCheckSensorVersionDowngrade_ProceedsWithoutVersionLine(t *testing.T) {
	t.Parallel()
	// A config written before version stamping existed must not permanently
	// block installs.
	existing := []byte("[daemon]\nsocket_path = \"/x\"\n")
	if err := checkSensorVersionDowngrade("1.0.0", existing, false); err != nil {
		t.Fatalf("expected install to proceed over unversioned config, got %v", err)
	}
}

func TestCheckSensorVersionDowngrade_ProceedsWithoutExistingConfig(t *testing.T) {
	t.Parallel()
	if err := checkSensorVersionDowngrade("1.0.0", nil, false); err != nil {
		t.Fatalf("expected fresh install (no existing config) to proceed, got %v", err)
	}
}

func TestSensorVersion_IsWellFormed(t *testing.T) {
	t.Parallel()
	if _, _, _, err := ParseSensorVersion(SensorVersion); err != nil {
		t.Fatalf("SensorVersion constant %q does not parse: %v", SensorVersion, err)
	}
}
