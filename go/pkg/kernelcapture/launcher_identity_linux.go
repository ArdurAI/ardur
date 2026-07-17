//go:build linux

package kernelcapture

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type launcherIdentityObserver struct {
	objs launcherIdentityObjects
	link link.Link
}

func (o *launcherIdentityObserver) Close() {
	if o == nil {
		return
	}
	if o.link != nil {
		_ = o.link.Close()
	}
	_ = o.objs.Close()
}

// AttachLauncherIdentityObserver loads the optional non-enforcing BPF-LSM
// object and replaces its map with the lifecycle producer's exact map. Hosts
// without an active BPF LSM return an error without disturbing exec/exit
// capture; callers convert that capability gap to a bounded fail-low outcome.
func (h *ProcessExecEBPFHandles) AttachLauncherIdentityObserver() error {
	if h == nil {
		return fmt.Errorf("process-exec handles are not loaded")
	}
	if h.launcherIdentity != nil {
		return fmt.Errorf("launcher identity observer is already attached")
	}
	state := h.launcherExecState()
	if state == nil {
		return fmt.Errorf("launcher exec state map is not loaded")
	}

	observer := &launcherIdentityObserver{}
	if err := loadLauncherIdentityObjects(&observer.objs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			launcherIdentityMapLauncherExecState: state,
		},
	}); err != nil {
		return fmt.Errorf("load launcher identity BPF-LSM object: %w", err)
	}

	var err error
	observer.link, err = link.AttachLSM(link.LSMOptions{Program: observer.objs.ObserveLauncherIdentity})
	if err != nil {
		observer.Close()
		return fmt.Errorf("attach lsm/bprm_check_security launcher observer: %w", err)
	}
	h.launcherIdentity = observer
	return nil
}

func (h *ProcessExecEBPFHandles) launcherExecState() *ebpf.Map {
	if h.launcherExecStateMap != nil {
		return h.launcherExecStateMap
	}
	return h.objs.LauncherExecState
}
