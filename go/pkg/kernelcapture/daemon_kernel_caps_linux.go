//go:build linux

package kernelcapture

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// KernelCapReport holds the result of all preflight kernel capability checks
// required before installing ardur-kernelcaptured as a system service.
// CanInstall is false if any required check did not pass.
type KernelCapReport struct {
	Findings   []KernelCapFinding
	CanInstall bool
}

// KernelCapFinding is the result of one preflight check.
type KernelCapFinding struct {
	Check  string
	OK     bool
	Detail string
}

// CheckKernelCapabilities runs the full set of host capability checks.
//
// Checks performed:
//   - Kernel version ≥ 5.8 (CO-RE eBPF requires 5.8+)
//   - BTF available at /sys/kernel/btf/vmlinux (CONFIG_DEBUG_INFO_BTF)
//   - bpffs mounted at /sys/fs/bpf (BPF_FS_MAGIC)
//   - cgroup v2 at /sys/fs/cgroup (CGROUP2_SUPER_MAGIC)
//   - BPF LSM enabled (bpf present in /sys/kernel/security/lsm)
//   - CAP_BPF and CAP_SYS_ADMIN effective capabilities
func CheckKernelCapabilities() KernelCapReport {
	type namedCheck struct {
		name string
		fn   func() (bool, string)
	}
	checks := []namedCheck{
		{"kernel_version_ge_5_8", kernelCapCheckVersion},
		{"btf_available", kernelCapCheckBTF},
		{"bpffs_mounted", kernelCapCheckBPFFS},
		{"cgroup_v2", kernelCapCheckCgroupV2},
		{"bpf_lsm", kernelCapCheckBPFLSM},
		{"cap_bpf_and_sys_admin", kernelCapCheckCapabilities},
	}

	r := KernelCapReport{CanInstall: true}
	for _, c := range checks {
		ok, detail := c.fn()
		r.Findings = append(r.Findings, KernelCapFinding{Check: c.name, OK: ok, Detail: detail})
		if !ok {
			r.CanInstall = false
		}
	}
	return r
}

func kernelCapCheckVersion() (bool, string) {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false, fmt.Sprintf("read /proc/sys/kernel/osrelease: %v", err)
	}
	release := strings.TrimSpace(string(b))
	major, minor, err := parseKernelVersionString(release)
	if err != nil {
		return false, fmt.Sprintf("parse kernel version %q: %v", release, err)
	}
	if major > 5 || (major == 5 && minor >= 8) {
		return true, fmt.Sprintf("kernel %d.%d (%q) satisfies ≥5.8", major, minor, release)
	}
	return false, fmt.Sprintf("kernel %d.%d (%q) is below required 5.8", major, minor, release)
}

func parseKernelVersionString(release string) (major, minor int, err error) {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("not enough version components in %q", release)
	}
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("major component: %w", err)
	}
	minorStr := parts[1]
	// Strip any suffix after '-', '+', or '_' (e.g. "15-generic" → "15").
	if i := strings.IndexAny(minorStr, "-+_"); i >= 0 {
		minorStr = minorStr[:i]
	}
	minor, err = strconv.Atoi(minorStr)
	if err != nil {
		return 0, 0, fmt.Errorf("minor component: %w", err)
	}
	return major, minor, nil
}

func kernelCapCheckBTF() (bool, string) {
	const p = "/sys/kernel/btf/vmlinux"
	if _, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			return false, p + " missing (kernel needs CONFIG_DEBUG_INFO_BTF=y)"
		}
		return false, fmt.Sprintf("stat %s: %v", p, err)
	}
	return true, "BTF available at " + p
}

func kernelCapCheckBPFFS() (bool, string) {
	const p = "/sys/fs/bpf"
	var st unix.Statfs_t
	if err := unix.Statfs(p, &st); err != nil {
		return false, fmt.Sprintf("statfs %s: %v", p, err)
	}
	if st.Type != unix.BPF_FS_MAGIC {
		return false, fmt.Sprintf("%s type=0x%x, want BPF_FS_MAGIC=0x%x (mount bpffs)", p, st.Type, unix.BPF_FS_MAGIC)
	}
	return true, p + " is a bpf filesystem"
}

func kernelCapCheckCgroupV2() (bool, string) {
	const p = "/sys/fs/cgroup"
	var st unix.Statfs_t
	if err := unix.Statfs(p, &st); err != nil {
		return false, fmt.Sprintf("statfs %s: %v", p, err)
	}
	if st.Type != unix.CGROUP2_SUPER_MAGIC {
		return false, fmt.Sprintf("%s type=0x%x, want CGROUP2_SUPER_MAGIC=0x%x (need unified cgroup v2)", p, st.Type, unix.CGROUP2_SUPER_MAGIC)
	}
	return true, p + " is cgroup v2"
}

func kernelCapCheckBPFLSM() (bool, string) {
	const p = "/sys/kernel/security/lsm"
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return false, p + " not available (securityfs not mounted or CONFIG_SECURITY not set)"
		}
		return false, fmt.Sprintf("read %s: %v", p, err)
	}
	list := strings.TrimSpace(string(b))
	for _, lsm := range strings.Split(list, ",") {
		if strings.TrimSpace(lsm) == "bpf" {
			return true, fmt.Sprintf("BPF LSM active (lsm=%q)", list)
		}
	}
	return false, fmt.Sprintf("BPF LSM not enabled (lsm=%q); boot with lsm=...,bpf", list)
}

func kernelCapCheckCapabilities() (bool, string) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false, fmt.Sprintf("capget: %v", err)
	}

	hasCap := func(cap uint) bool {
		if cap < 32 {
			return data[0].Effective&(1<<cap) != 0
		}
		return data[1].Effective&(1<<(cap-32)) != 0
	}

	hasBPF := hasCap(unix.CAP_BPF)
	hasSysAdmin := hasCap(unix.CAP_SYS_ADMIN)

	if hasBPF && hasSysAdmin {
		return true, "CAP_BPF and CAP_SYS_ADMIN are effective"
	}
	var missing []string
	if !hasBPF {
		missing = append(missing, "CAP_BPF")
	}
	if !hasSysAdmin {
		missing = append(missing, "CAP_SYS_ADMIN")
	}
	return false, fmt.Sprintf("missing: %s (run as root or grant via setcap)", strings.Join(missing, ", "))
}
