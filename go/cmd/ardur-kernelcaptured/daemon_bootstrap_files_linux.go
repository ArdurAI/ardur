//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

func observeRootBootstrapFiles(rootPID uint32) ([]kernelcapture.BootstrapFile, error) {
	procRoot := fmt.Sprintf("/proc/%d", rootPID)
	executable, err := os.Readlink(filepath.Join(procRoot, "exe"))
	if err != nil {
		return nil, fmt.Errorf("read executable: %w", err)
	}
	cwd, err := os.Readlink(filepath.Join(procRoot, "cwd"))
	if err != nil {
		return nil, fmt.Errorf("read cwd: %w", err)
	}
	rawCmdline, err := os.ReadFile(filepath.Join(procRoot, "cmdline"))
	if err != nil {
		return nil, fmt.Errorf("read cmdline: %w", err)
	}
	rawArgs := bytes.Split(bytes.TrimSuffix(rawCmdline, []byte{0}), []byte{0})
	args := make([]string, 0, len(rawArgs))
	for _, raw := range rawArgs {
		args = append(args, string(raw))
	}
	return collectBootstrapFileIdentities(executable, cwd, args), nil
}

func collectBootstrapFileIdentities(executable, cwd string, argv []string) []kernelcapture.BootstrapFile {
	candidates := []string{executable}
	for _, arg := range argv[1:] {
		if arg == "" {
			continue
		}
		if !filepath.IsAbs(arg) {
			arg = filepath.Join(cwd, arg)
		}
		candidates = append(candidates, filepath.Clean(arg))
	}

	identities := make([]kernelcapture.BootstrapFile, 0, kernelcapture.MaxBootstrapFileIdentities)
	seen := make(map[string]struct{}, kernelcapture.MaxBootstrapFileIdentities)
	for _, candidate := range candidates {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Ino == 0 {
			continue
		}
		identity := kernelcapture.BootstrapFile{Path: resolved, Inode: stat.Ino}
		if _, duplicate := seen[identity.Path]; duplicate {
			continue
		}
		seen[identity.Path] = struct{}{}
		identities = append(identities, identity)
		if len(identities) == kernelcapture.MaxBootstrapFileIdentities {
			break
		}
	}
	return identities
}
