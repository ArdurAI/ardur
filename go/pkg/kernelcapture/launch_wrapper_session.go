package kernelcapture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrLaunchWrapperSessionProof = errors.New("kernelcapture: invalid launch-wrapper session proof")

// LaunchWrapperSessionMetadata is the local, no-privilege handoff a generic
// CLI launch wrapper can record after starting a command. It deliberately keeps
// daemon-owned paths and OS-observed peer credentials out of the client record.
type LaunchWrapperSessionMetadata struct {
	SessionID               string
	MissionID               string
	TraceID                 string
	Command                 []string
	WorkingDirectory        string
	RootPID                 uint32
	PIDNamespaceID          uint32
	ProcessStartMonotonicNS uint64
	CgroupID                uint64
	StartedAt               time.Time
	TTLSeconds              int64
	HandoffMetadata         map[string]any
}

// LaunchWrapperSessionProof is reviewable bridge data for the future
// ardur-run/launch-wrapper to daemon boundary. It does not execute commands or
// communicate with a daemon.
type LaunchWrapperSessionProof struct {
	RegisterSessionRequest DaemonProtocolRequest
	CorrelatorSeed         ToolReceipt
	ClaimBoundary          []string
	NotClaimed             []string
}

// BuildLaunchWrapperSessionProof converts launch-wrapper session metadata into
// the existing daemon register_session protocol request and a correlator seed
// receipt for the launched root process.
//
// This is a local contract seam only. It validates and redacts handoff metadata
// but does not run a subprocess, open/bind/listen on a socket, retrieve
// SO_PEERCRED, install/start a daemon, mutate cgroup maps, or capture
// subprocess/file/network side effects.
func BuildLaunchWrapperSessionProof(meta LaunchWrapperSessionMetadata) (LaunchWrapperSessionProof, error) {
	normalized, err := normalizeLaunchWrapperSessionMetadata(meta)
	if err != nil {
		return LaunchWrapperSessionProof{}, err
	}
	handoff, err := buildLaunchWrapperHandoffMetadata(normalized)
	if err != nil {
		return LaunchWrapperSessionProof{}, err
	}
	req := DaemonProtocolRequest{
		ProtocolVersion: DaemonProtocolVersion,
		Method:          DaemonProtocolMethodRegisterSession,
		RegisterSession: &DaemonRegisterSessionRequest{
			SessionID:       normalized.SessionID,
			MissionID:       normalized.MissionID,
			TraceID:         normalized.TraceID,
			RootPID:         normalized.RootPID,
			PIDNamespaceID:  normalized.PIDNamespaceID,
			CgroupID:        normalized.CgroupID,
			EventClasses:    []string{DaemonProtocolEventProcessLifecycle},
			TTLSeconds:      normalized.TTLSeconds,
			HandoffMetadata: handoff,
		},
	}
	if err := ValidateDaemonProtocolRequest(req); err != nil {
		return LaunchWrapperSessionProof{}, fmt.Errorf("%w: daemon register_session request: %v", ErrLaunchWrapperSessionProof, err)
	}

	return LaunchWrapperSessionProof{
		RegisterSessionRequest: req,
		CorrelatorSeed: ToolReceipt{
			ReceiptID:               launchWrapperReceiptID(normalized),
			SessionID:               normalized.SessionID,
			PID:                     normalized.RootPID,
			PIDNamespaceID:          uint64(normalized.PIDNamespaceID),
			ProcessStartMonotonicNS: normalized.ProcessStartMonotonicNS,
			CgroupID:                normalized.CgroupID,
			SpanStart:               normalized.StartedAt,
			ObservedAt:              normalized.StartedAt,
		},
		ClaimBoundary: []string{
			"launch-wrapper session identity is converted into a daemon register_session request",
			"root process identity can seed userspace correlation for later kernel lifecycle observations",
			"handoff metadata is redacted and rejects daemon-owned paths or peer credential fields",
		},
		NotClaimed: []string{
			"universal CLI capture",
			"production eBPF or daemon readiness",
			"subprocess/file/network side-effect capture",
			"daemon install/start, socket listener, SO_PEERCRED retrieval, or privileged cgroup/map mutation",
		},
	}, nil
}

func normalizeLaunchWrapperSessionMetadata(meta LaunchWrapperSessionMetadata) (LaunchWrapperSessionMetadata, error) {
	meta.SessionID = strings.TrimSpace(meta.SessionID)
	meta.MissionID = strings.TrimSpace(meta.MissionID)
	meta.TraceID = strings.TrimSpace(meta.TraceID)
	if meta.SessionID == "" {
		return LaunchWrapperSessionMetadata{}, fmt.Errorf("%w: session_id is required", ErrLaunchWrapperSessionProof)
	}
	if len(meta.Command) == 0 {
		return LaunchWrapperSessionMetadata{}, fmt.Errorf("%w: command argv is required", ErrLaunchWrapperSessionProof)
	}
	if strings.TrimSpace(meta.Command[0]) == "" {
		return LaunchWrapperSessionMetadata{}, fmt.Errorf("%w: command path is required", ErrLaunchWrapperSessionProof)
	}
	if meta.RootPID == 0 {
		return LaunchWrapperSessionMetadata{}, fmt.Errorf("%w: root_pid is required", ErrLaunchWrapperSessionProof)
	}
	if meta.StartedAt.IsZero() {
		return LaunchWrapperSessionMetadata{}, fmt.Errorf("%w: started_at is required", ErrLaunchWrapperSessionProof)
	}
	if meta.TTLSeconds <= 0 || meta.TTLSeconds > MaxDaemonProtocolTTLSeconds {
		return LaunchWrapperSessionMetadata{}, fmt.Errorf("%w: ttl_seconds must be between 1 and %d", ErrLaunchWrapperSessionProof, MaxDaemonProtocolTTLSeconds)
	}
	if containsForbiddenClientHandoffMetadataField(meta.HandoffMetadata) {
		return LaunchWrapperSessionMetadata{}, fmt.Errorf("%w: handoff metadata contains raw command, path, environment, secret-like, daemon-owned path, or peer identity fields", ErrLaunchWrapperSessionProof)
	}
	return meta, nil
}

func buildLaunchWrapperHandoffMetadata(meta LaunchWrapperSessionMetadata) (map[string]any, error) {
	handoff, err := sanitizeLaunchWrapperHandoffMetadata(meta.HandoffMetadata)
	if err != nil {
		return nil, err
	}
	handoff["handoff_source"] = "launch_wrapper"
	handoff["command_argc"] = len(meta.Command)
	handoff["command_argv_sha256"] = commandArgvSHA256(meta.Command)
	if strings.TrimSpace(meta.WorkingDirectory) != "" {
		handoff["working_directory_sha256"] = sha256Hex([]byte(meta.WorkingDirectory))
	}
	return handoff, nil
}

func sanitizeLaunchWrapperHandoffMetadata(metadata map[string]any) (map[string]any, error) {
	if len(metadata) == 0 {
		return map[string]any{}, nil
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("%w: handoff metadata must be JSON-encodable: %v", ErrLaunchWrapperSessionProof, err)
	}
	var sanitized map[string]any
	if err := json.Unmarshal(data, &sanitized); err != nil {
		return nil, fmt.Errorf("%w: handoff metadata must be JSON object metadata: %v", ErrLaunchWrapperSessionProof, err)
	}
	if containsForbiddenClientHandoffMetadataField(sanitized) {
		return nil, fmt.Errorf("%w: handoff metadata contains raw command, working directory, executable path, environment, or secret-like fields", ErrLaunchWrapperSessionProof)
	}
	return sanitized, nil
}

func containsForbiddenClientHandoffMetadataField(value any) bool {
	obj, ok := value.(map[string]any)
	if !ok {
		list, ok := value.([]any)
		if !ok {
			return false
		}
		for _, item := range list {
			if containsForbiddenClientHandoffMetadataField(item) {
				return true
			}
		}
		return false
	}
	for key, nested := range obj {
		normalizedKey := normalizedLaunchWrapperMetadataKey(key)
		if isRawLaunchWrapperMetadataKey(normalizedKey) || isSecretLikeLaunchWrapperMetadataKey(normalizedKey) || isPrivilegedDaemonProtocolMetadataKey(normalizedKey) {
			return true
		}
		if containsForbiddenClientHandoffMetadataField(nested) {
			return true
		}
	}
	return false
}

func isRawLaunchWrapperMetadataKey(normalizedKey string) bool {
	switch normalizedKey {
	case "args", "argv", "command", "commandargs", "commandargv", "commandline", "cwd", "environment", "env", "executable", "executablepath", "path", "rawargs", "rawargv", "rawcommand", "rawcommandline", "workingdir", "workingdirectory", "workdir":
		return true
	default:
		return false
	}
}

func isSecretLikeLaunchWrapperMetadataKey(normalizedKey string) bool {
	if normalizedKey == "" {
		return false
	}
	switch normalizedKey {
	case "authorization", "authheader", "bearer", "jwt", "key":
		return true
	}
	for _, marker := range []string{
		"accesstoken",
		"apikey",
		"authtoken",
		"bearertoken",
		"clientsecret",
		"credential",
		"credentials",
		"password",
		"passwd",
		"privatekey",
		"privkey",
		"refreshtoken",
		"secret",
		"secretkey",
		"sessiontoken",
		"token",
	} {
		if strings.Contains(normalizedKey, marker) {
			return true
		}
	}
	return false
}

func normalizedLaunchWrapperMetadataKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.ReplaceAll(key, "-", "")
	key = strings.ReplaceAll(key, "_", "")
	key = strings.ReplaceAll(key, " ", "")
	return key
}

func commandArgvSHA256(command []string) string {
	data, err := json.Marshal(command)
	if err != nil {
		return sha256Hex([]byte(strings.Join(command, "\x00")))
	}
	return sha256Hex(data)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func launchWrapperReceiptID(meta LaunchWrapperSessionMetadata) string {
	if meta.TraceID != "" {
		return "launch-wrapper:" + meta.SessionID + ":" + meta.TraceID
	}
	return "launch-wrapper:" + meta.SessionID
}
