package kernelcapture

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	DaemonProtocolVersion = "kernelcapture.daemon.v1"

	DaemonProtocolMethodHealth          = "health"
	DaemonProtocolMethodRegisterSession = "register_session"
	DaemonProtocolMethodEndSession      = "end_session"
	DaemonProtocolMethodSessionStatus   = "session_status"

	DaemonProtocolEventProcessLifecycle = "process_lifecycle"

	MaxDaemonProtocolTTLSeconds = 24 * 60 * 60
)

var ErrDaemonProtocol = errors.New("kernelcapture: invalid daemon protocol message")

// DaemonProtocolRequest is the narrow launch-wrapper-to-daemon request
// contract. It is JSON-line compatible: each encoded request is one
// deterministic JSON object followed by '\n'. No socket server is implemented
// in this slice.
type DaemonProtocolRequest struct {
	ProtocolVersion string                        `json:"protocol_version"`
	Method          string                        `json:"method"`
	Health          *DaemonHealthRequest          `json:"health,omitempty"`
	RegisterSession *DaemonRegisterSessionRequest `json:"register_session,omitempty"`
	EndSession      *DaemonEndSessionRequest      `json:"end_session,omitempty"`
	SessionStatus   *DaemonSessionStatusRequest   `json:"session_status,omitempty"`
}

type DaemonHealthRequest struct{}

type DaemonRegisterSessionRequest struct {
	SessionID       string         `json:"session_id"`
	MissionID       string         `json:"mission_id,omitempty"`
	TraceID         string         `json:"trace_id,omitempty"`
	RootPID         uint32         `json:"root_pid,omitempty"`
	PIDNamespaceID  uint32         `json:"pid_namespace_id,omitempty"`
	CgroupID        uint64         `json:"cgroup_id,omitempty"`
	EventClasses    []string       `json:"event_classes"`
	TTLSeconds      int64          `json:"ttl_seconds"`
	HandoffMetadata map[string]any `json:"handoff_metadata,omitempty"`
}

type DaemonEndSessionRequest struct {
	SessionID string `json:"session_id"`
	TraceID   string `json:"trace_id,omitempty"`
}

type DaemonSessionStatusRequest struct {
	SessionID string `json:"session_id"`
}

type DaemonProtocolResponse struct {
	ProtocolVersion string `json:"protocol_version"`
	OK              bool   `json:"ok"`
	Method          string `json:"method"`
	SessionID       string `json:"session_id,omitempty"`
	Status          string `json:"status,omitempty"`
	Error           string `json:"error,omitempty"`
}

// CgroupFilterSequence describes daemon-side map sequencing. Enabling
// filtering is only valid after at least one non-zero allowlist entry exists.
type CgroupFilterSequence struct {
	Enable             bool
	AllowlistCgroupIDs []uint64
}

func EncodeDaemonProtocolRequest(req DaemonProtocolRequest) ([]byte, error) {
	if err := ValidateDaemonProtocolRequest(req); err != nil {
		return nil, err
	}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("%w: encode request: %v", ErrDaemonProtocol, err)
	}
	return append(data, '\n'), nil
}

func DecodeDaemonProtocolRequest(data []byte) (DaemonProtocolRequest, error) {
	if err := rejectPrivilegedDaemonProtocolFields(data); err != nil {
		return DaemonProtocolRequest{}, err
	}
	var req DaemonProtocolRequest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return DaemonProtocolRequest{}, fmt.Errorf("%w: decode request: %v", ErrDaemonProtocol, err)
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return DaemonProtocolRequest{}, fmt.Errorf("%w: multiple JSON values are not allowed", ErrDaemonProtocol)
	} else if !errors.Is(err, io.EOF) {
		return DaemonProtocolRequest{}, fmt.Errorf("%w: trailing data after request: %v", ErrDaemonProtocol, err)
	}
	if err := ValidateDaemonProtocolRequest(req); err != nil {
		return DaemonProtocolRequest{}, err
	}
	return req, nil
}

func EncodeDaemonProtocolResponse(resp DaemonProtocolResponse) ([]byte, error) {
	if resp.ProtocolVersion == "" {
		resp.ProtocolVersion = DaemonProtocolVersion
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("%w: encode response: %v", ErrDaemonProtocol, err)
	}
	return append(data, '\n'), nil
}

func ValidateDaemonProtocolRequest(req DaemonProtocolRequest) error {
	if req.ProtocolVersion != DaemonProtocolVersion {
		return fmt.Errorf("%w: unsupported protocol version %q", ErrDaemonProtocol, req.ProtocolVersion)
	}
	switch req.Method {
	case DaemonProtocolMethodHealth:
		if req.Health == nil || req.RegisterSession != nil || req.EndSession != nil || req.SessionStatus != nil {
			return fmt.Errorf("%w: health request must include only health payload", ErrDaemonProtocol)
		}
	case DaemonProtocolMethodRegisterSession:
		if req.RegisterSession == nil || req.Health != nil || req.EndSession != nil || req.SessionStatus != nil {
			return fmt.Errorf("%w: register_session request must include only register_session payload", ErrDaemonProtocol)
		}
		return validateDaemonRegisterSession(*req.RegisterSession)
	case DaemonProtocolMethodEndSession:
		if req.EndSession == nil || req.Health != nil || req.RegisterSession != nil || req.SessionStatus != nil {
			return fmt.Errorf("%w: end_session request must include only end_session payload", ErrDaemonProtocol)
		}
		if strings.TrimSpace(req.EndSession.SessionID) == "" {
			return fmt.Errorf("%w: end_session session_id is required", ErrDaemonProtocol)
		}
	case DaemonProtocolMethodSessionStatus:
		if req.SessionStatus == nil || req.Health != nil || req.RegisterSession != nil || req.EndSession != nil {
			return fmt.Errorf("%w: session_status request must include only session_status payload", ErrDaemonProtocol)
		}
		if strings.TrimSpace(req.SessionStatus.SessionID) == "" {
			return fmt.Errorf("%w: session_status session_id is required", ErrDaemonProtocol)
		}
	default:
		return fmt.Errorf("%w: unknown method %q", ErrDaemonProtocol, req.Method)
	}
	return nil
}

func validateDaemonRegisterSession(req DaemonRegisterSessionRequest) error {
	if strings.TrimSpace(req.SessionID) == "" {
		return fmt.Errorf("%w: register_session session_id is required", ErrDaemonProtocol)
	}
	if req.RootPID == 0 {
		return fmt.Errorf("%w: register_session root_pid is required", ErrDaemonProtocol)
	}
	if req.TTLSeconds <= 0 || req.TTLSeconds > MaxDaemonProtocolTTLSeconds {
		return fmt.Errorf("%w: ttl_seconds must be between 1 and %d", ErrDaemonProtocol, MaxDaemonProtocolTTLSeconds)
	}
	if len(req.EventClasses) == 0 {
		return fmt.Errorf("%w: at least one event class is required", ErrDaemonProtocol)
	}
	seen := map[string]struct{}{}
	for _, eventClass := range req.EventClasses {
		switch eventClass {
		case DaemonProtocolEventProcessLifecycle:
			seen[eventClass] = struct{}{}
		default:
			return fmt.Errorf("%w: unknown event class %q", ErrDaemonProtocol, eventClass)
		}
	}
	if len(seen) != len(req.EventClasses) {
		return fmt.Errorf("%w: duplicate event classes are not allowed", ErrDaemonProtocol)
	}
	normalizedHandoff, err := normalizeDaemonProtocolHandoffMetadata(req.HandoffMetadata)
	if err != nil {
		return err
	}
	if containsForbiddenClientHandoffMetadataField(normalizedHandoff) {
		return fmt.Errorf("%w: register_session handoff metadata contains raw command, path, environment, secret-like, daemon-owned path, or peer identity fields", ErrDaemonProtocol)
	}
	return nil
}

func normalizeDaemonProtocolHandoffMetadata(metadata map[string]any) (map[string]any, error) {
	if len(metadata) == 0 {
		return map[string]any{}, nil
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("%w: register_session handoff metadata must be JSON-encodable: %v", ErrDaemonProtocol, err)
	}
	var normalized map[string]any
	if err := json.Unmarshal(data, &normalized); err != nil {
		return nil, fmt.Errorf("%w: register_session handoff metadata must be JSON object metadata: %v", ErrDaemonProtocol, err)
	}
	return normalized, nil
}

func ValidateCgroupFilterSequence(seq CgroupFilterSequence) error {
	if !seq.Enable {
		return nil
	}
	if len(seq.AllowlistCgroupIDs) == 0 {
		return fmt.Errorf("%w: cgroup filtering cannot be enabled before allowlist entries exist", ErrDaemonProtocol)
	}
	for _, cgroupID := range seq.AllowlistCgroupIDs {
		if cgroupID == 0 {
			return fmt.Errorf("%w: cgroup allowlist entries must be non-zero before enabling filtering", ErrDaemonProtocol)
		}
	}
	return nil
}

func rejectPrivilegedDaemonProtocolFields(data []byte) error {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("%w: decode raw request: %v", ErrDaemonProtocol, err)
	}
	if containsPrivilegedDaemonProtocolField(raw) {
		return fmt.Errorf("%w: client-supplied daemon-controlled path or peer identity fields are forbidden", ErrDaemonProtocol)
	}
	return nil
}

func containsPrivilegedDaemonProtocolField(value any) bool {
	obj, ok := value.(map[string]any)
	if !ok {
		list, ok := value.([]any)
		if !ok {
			return false
		}
		for _, item := range list {
			if containsPrivilegedDaemonProtocolField(item) {
				return true
			}
		}
		return false
	}
	for key, nested := range obj {
		if isPrivilegedDaemonProtocolMetadataKey(normalizedLaunchWrapperMetadataKey(key)) {
			return true
		}
		if containsPrivilegedDaemonProtocolField(nested) {
			return true
		}
	}
	return false
}

func isPrivilegedDaemonProtocolMetadataKey(normalizedKey string) bool {
	switch normalizedKey {
	case "configpath", "statedir", "rundir", "socketpath", "bpffsdir", "ringbufmappath", "pinnedmappath", "mappath",
		"peeruid", "peergid", "peerpid", "peercredentials", "sopeercred", "linuxsopeercred", "ucred", "credentialsource":
		return true
	default:
		return false
	}
}
