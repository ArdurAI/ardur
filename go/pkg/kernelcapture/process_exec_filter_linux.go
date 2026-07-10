//go:build linux

package kernelcapture

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

const (
	processExecFilterControlKey = uint32(0)
	processExecFilterDisabled   = uint8(0)
	processExecFilterEnabled    = uint8(1)
	processExecAllowedMarker    = uint8(1)
)

func (h *ProcessExecEBPFHandles) SetLifecycleCgroupFilterEnabled(enabled bool) error {
	if h == nil {
		return fmt.Errorf("process-exec handles are not loaded")
	}
	return setProcessExecCgroupFilterMap(h.filterControl(), enabled)
}

func (h *ProcessExecEBPFHandles) AllowLifecycleCgroup(cgroupID uint64) error {
	if h == nil {
		return fmt.Errorf("process-exec handles are not loaded")
	}
	return allowProcessExecCgroupMap(h.allowedCgroups(), cgroupID)
}

func (h *ProcessExecEBPFHandles) RemoveLifecycleCgroup(cgroupID uint64) error {
	if h == nil {
		return fmt.Errorf("process-exec handles are not loaded")
	}
	return disallowProcessExecCgroupMap(h.allowedCgroups(), cgroupID)
}

// ClearLifecycleCgroups snapshots keys before deleting them. Deleting the
// current key while iterating a BPF hash map can restart get-next-key traversal.
func (h *ProcessExecEBPFHandles) ClearLifecycleCgroups() error {
	if h == nil {
		return fmt.Errorf("process-exec handles are not loaded")
	}
	allowed := h.allowedCgroups()
	if allowed == nil {
		return fmt.Errorf("process-exec cgroup allowlist map is not loaded")
	}
	keys := make([]uint64, 0, allowed.MaxEntries())
	iterator := allowed.Iterate()
	var key uint64
	var value uint8
	for iterator.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iterator.Err(); err != nil {
		return fmt.Errorf("iterate process-exec cgroup allowlist map: %w", err)
	}
	var errs []error
	for _, cgroupID := range keys {
		if err := disallowProcessExecCgroupMap(allowed, cgroupID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (h *ProcessExecEBPFHandles) filterControl() *ebpf.Map {
	if h.filterControlMap != nil {
		return h.filterControlMap
	}
	return h.objs.FilterControl
}

func (h *ProcessExecEBPFHandles) allowedCgroups() *ebpf.Map {
	if h.allowedCgroupsMap != nil {
		return h.allowedCgroupsMap
	}
	return h.objs.AllowedCgroups
}

func enableProcessExecCgroupFilter(objs *processExecObjects) error {
	return setProcessExecCgroupFilter(objs, true)
}

func disableProcessExecCgroupFilter(objs *processExecObjects) error {
	return setProcessExecCgroupFilter(objs, false)
}

func setProcessExecCgroupFilter(objs *processExecObjects, enabled bool) error {
	if objs == nil {
		return fmt.Errorf("process-exec objects are not loaded")
	}
	return setProcessExecCgroupFilterMap(objs.FilterControl, enabled)
}

func setProcessExecCgroupFilterMap(control *ebpf.Map, enabled bool) error {
	if control == nil {
		return fmt.Errorf("process-exec filter control map is not loaded")
	}
	value := processExecFilterDisabled
	if enabled {
		value = processExecFilterEnabled
	}
	if err := control.Update(processExecFilterControlKey, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update process-exec filter control map: %w", err)
	}
	return nil
}

func allowProcessExecCgroup(objs *processExecObjects, cgroupID uint64) error {
	if objs == nil {
		return fmt.Errorf("process-exec objects are not loaded")
	}
	return allowProcessExecCgroupMap(objs.AllowedCgroups, cgroupID)
}

func allowProcessExecCgroupMap(allowed *ebpf.Map, cgroupID uint64) error {
	if allowed == nil {
		return fmt.Errorf("process-exec cgroup allowlist map is not loaded")
	}
	if cgroupID == 0 {
		return fmt.Errorf("cgroup id must be non-zero")
	}
	if err := allowed.Update(cgroupID, processExecAllowedMarker, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update process-exec cgroup allowlist map for cgroup %d: %w", cgroupID, err)
	}
	return nil
}

func disallowProcessExecCgroup(objs *processExecObjects, cgroupID uint64) error {
	if objs == nil {
		return fmt.Errorf("process-exec objects are not loaded")
	}
	return disallowProcessExecCgroupMap(objs.AllowedCgroups, cgroupID)
}

func disallowProcessExecCgroupMap(allowed *ebpf.Map, cgroupID uint64) error {
	if allowed == nil {
		return fmt.Errorf("process-exec cgroup allowlist map is not loaded")
	}
	if cgroupID == 0 {
		return nil
	}
	if err := allowed.Delete(cgroupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete process-exec cgroup allowlist map entry for cgroup %d: %w", cgroupID, err)
	}
	return nil
}
