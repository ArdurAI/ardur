// Package main is the entry point for ardur-sensor, the Ardur host-sensor
// management CLI. It implements the 'ardur sensor' subcommand surface:
//
//	ardur-sensor preflight   — run kernel capability checks and custody preflight
//	ardur-sensor install     — install daemon custody paths and systemd unit
//	ardur-sensor uninstall   — remove daemon custody paths
//	ardur-sensor status      — inspect on-disk custody state
//
// Part of Epic A (#63) — Slice 2 (privileged installer + systemd service).
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"text/tabwriter"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

const unitInstallPath = "/etc/systemd/system/ardur-kernelcaptured.service"

func main() {
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
		os.Exit(2)
	}

	cmd := flag.Arg(0)
	remaining := flag.Args()[1:]

	var err error
	switch cmd {
	case "preflight":
		err = cmdPreflight(remaining)
	case "install":
		err = cmdInstall(remaining)
	case "uninstall":
		err = cmdUninstall(remaining)
	case "status":
		err = cmdStatus(remaining)
	default:
		fmt.Fprintf(os.Stderr, "ardur-sensor: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "ardur-sensor %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `ardur-sensor — Ardur host-sensor management

USAGE
  ardur-sensor <command> [flags]

COMMANDS
  preflight    Check kernel capabilities and host prerequisites
  install      Install daemon custody paths and systemd service unit
  uninstall    Remove daemon config and service unit
  status       Inspect on-disk daemon custody state

Run 'ardur-sensor <command> --help' for command-specific flags.`)
}

// ── preflight ──────────────────────────────────────────────────────────────

func cmdPreflight(args []string) error {
	fs_ := flag.NewFlagSet("preflight", flag.ExitOnError)
	jsonOut := fs_.Bool("json", false, "Output JSON instead of human-readable table")
	_ = fs_.Parse(args)

	caps := kernelcapture.CheckKernelCapabilities()
	cfg := kernelcapture.DefaultDaemonCustodyConfig()
	preflight, err := kernelcapture.InspectDaemonCustodyPreflight(cfg)
	if err != nil {
		return fmt.Errorf("custody preflight: %w", err)
	}
	// Both enforcement-tier capability checks are cross-platform-safe to call
	// unconditionally: each reports "not applicable"/informative-fail on a
	// host that can't use it rather than requiring a build-tag branch here.
	bpfLSM := kernelcapture.InspectBPFLSMPreflight()
	endpointSecurity := kernelcapture.InspectEndpointSecurityPreflight()

	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"kernel_caps":       caps,
			"custody":           preflight,
			"bpf_lsm":           bpfLSM,
			"endpoint_security": endpointSecurity,
		})
	}

	// Human-readable output.
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "KERNEL CAPABILITY CHECKS")
	fmt.Fprintln(tw, "CHECK\tOK\tDETAIL")
	for _, f := range caps.Findings {
		ok := "✓"
		if !f.OK {
			ok = "✗"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", f.Check, ok, f.Detail)
	}
	_ = tw.Flush()

	fmt.Println()
	fmt.Fprintln(tw, "DAEMON CUSTODY PREFLIGHT")
	fmt.Fprintln(tw, "CHECK\tVERDICT\tPATH\tDETAIL")
	for _, f := range preflight.Findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.CheckName, f.Verdict, f.Path, f.Details)
	}
	_ = tw.Flush()

	fmt.Println()
	fmt.Fprintln(tw, "ENFORCEMENT TIER CAPABILITY (which tier could be live)")
	fmt.Fprintln(tw, "CHECK\tVERDICT\tDETAIL")
	for _, f := range append(append([]kernelcapture.DaemonPreflightFinding{}, bpfLSM.Findings...), endpointSecurity.Findings...) {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", f.CheckName, f.Verdict, f.Details)
	}
	_ = tw.Flush()

	if !caps.CanInstall {
		fmt.Fprintln(os.Stderr, "\npreflight: host does not meet requirements for installation")
		os.Exit(1)
	}
	fmt.Println("\npreflight: all kernel capability checks passed")
	return nil
}

// ── install ────────────────────────────────────────────────────────────────

func cmdInstall(args []string) error {
	fs_ := flag.NewFlagSet("install", flag.ExitOnError)
	unitSrc := fs_.String("unit-src", "", "Path to ardur-kernelcaptured.service to install (default: bundled)")
	noEnable := fs_.Bool("no-enable", false, "Do not enable and start the systemd unit after install")
	dryRun := fs_.Bool("dry-run", false, "Print what would be done without making changes")
	allowDowngrade := fs_.Bool("allow-downgrade", false,
		"Allow installing this binary's version over a newer version already installed (default: refuse)")
	_ = fs_.Parse(args)

	cfg := kernelcapture.DefaultDaemonCustodyConfig()

	if *dryRun {
		plan, err := kernelcapture.BuildDaemonCustodyPlan(cfg)
		if err != nil {
			return fmt.Errorf("build plan: %w", err)
		}
		fmt.Println("DRY RUN — no changes will be made")
		for _, step := range plan.Steps {
			priv := ""
			if step.Privileged {
				priv = " [privileged]"
			}
			fmt.Printf("  %s: %s (mode %04o)%s\n", step.Name, step.Path, step.Mode, priv)
		}
		return nil
	}

	// Kernel capability check before touching the filesystem.
	caps := kernelcapture.CheckKernelCapabilities()
	if !caps.CanInstall {
		fmt.Fprintln(os.Stderr, "install: kernel capability checks failed:")
		for _, f := range caps.Findings {
			if !f.OK {
				fmt.Fprintf(os.Stderr, "  ✗ %s: %s\n", f.Check, f.Detail)
			}
		}
		fmt.Fprintln(os.Stderr, "\nRun 'ardur-sensor preflight' for the full report.")
		return fmt.Errorf("host does not meet requirements")
	}

	// Install daemon custody paths. Refuses to downgrade an already-installed
	// newer version unless --allow-downgrade is passed (upgrade-in-place safety).
	result, err := kernelcapture.InstallDaemonCustody(cfg, kernelcapture.WithAllowDowngrade(*allowDowngrade))
	if err != nil {
		if errors.Is(err, kernelcapture.ErrSensorVersionDowngradeRefused) {
			fmt.Fprintf(os.Stderr, "install: %v\n", err)
			fmt.Fprintln(os.Stderr, "Rerun with --allow-downgrade if this is intentional.")
		}
		return fmt.Errorf("custody install: %w", err)
	}
	for _, p := range result.PathsCreated {
		fmt.Printf("  created: %s\n", p)
	}

	// Install systemd unit.
	if err := installSystemdUnit(*unitSrc); err != nil {
		return fmt.Errorf("systemd unit: %w", err)
	}
	fmt.Printf("  installed unit: %s\n", unitInstallPath)

	if !*noEnable {
		if err := systemctlRun("daemon-reload"); err != nil {
			return fmt.Errorf("systemctl daemon-reload: %w", err)
		}
		if err := systemctlRun("enable", "--now", "ardur-kernelcaptured.service"); err != nil {
			return fmt.Errorf("systemctl enable --now: %w", err)
		}
		fmt.Println("  service enabled and started")
	}

	fmt.Println("\ninstall: complete. Run 'ardur-sensor status' to verify.")
	return nil
}

// installSystemdUnit copies the service unit to the systemd system directory.
// If unitSrc is empty it falls back to a path co-located with the binary.
func installSystemdUnit(unitSrc string) error {
	if unitSrc == "" {
		// Look for the unit relative to the binary location.
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("resolve binary path: %w", err)
		}
		candidates := []string{
			filepath.Join(filepath.Dir(exe), "..", "lib", "systemd", "system", "ardur-kernelcaptured.service"),
			filepath.Join(filepath.Dir(exe), "ardur-kernelcaptured.service"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				unitSrc = c
				break
			}
		}
		if unitSrc == "" {
			return fmt.Errorf("ardur-kernelcaptured.service not found alongside binary; use --unit-src to specify its location")
		}
	}

	data, err := os.ReadFile(unitSrc)
	if err != nil {
		return fmt.Errorf("read unit %s: %w", unitSrc, err)
	}

	if err := os.MkdirAll(filepath.Dir(unitInstallPath), 0o755); err != nil {
		return fmt.Errorf("create systemd dir: %w", err)
	}
	if err := os.WriteFile(unitInstallPath, data, fs.FileMode(0o644)); err != nil {
		return fmt.Errorf("write unit %s: %w", unitInstallPath, err)
	}
	return nil
}

func systemctlRun(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ── uninstall ──────────────────────────────────────────────────────────────

func cmdUninstall(args []string) error {
	fs_ := flag.NewFlagSet("uninstall", flag.ExitOnError)
	noStop := fs_.Bool("no-stop", false, "Do not stop/disable the systemd unit before uninstall")
	purge := fs_.Bool("purge", false,
		"Also remove the state/evidence directory tree (default: preserve it for operator review)")
	_ = fs_.Parse(args)

	cfg := kernelcapture.DefaultDaemonCustodyConfig()

	if !*noStop {
		_ = systemctlRun("disable", "--now", "ardur-kernelcaptured.service")
	}

	if err := kernelcapture.UninstallDaemonCustody(cfg, *purge); err != nil {
		return err
	}
	fmt.Printf("  removed: %s\n", cfg.ConfigPath)
	if *purge {
		fmt.Printf("  purged: %s (state + evidence)\n", cfg.StateDir)
	} else {
		fmt.Printf("  preserved: %s (state + evidence; rerun with --purge to remove)\n", cfg.StateDir)
	}

	if err := os.Remove(unitInstallPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit %s: %w", unitInstallPath, err)
	}
	fmt.Printf("  removed unit: %s\n", unitInstallPath)

	_ = systemctlRun("daemon-reload")

	fmt.Println("\nuninstall: complete")
	return nil
}

// ── status ─────────────────────────────────────────────────────────────────

func cmdStatus(args []string) error {
	fs_ := flag.NewFlagSet("status", flag.ExitOnError)
	jsonOut := fs_.Bool("json", false, "Output JSON")
	_ = fs_.Parse(args)

	cfg := kernelcapture.DefaultDaemonCustodyConfig()
	report, err := kernelcapture.InspectDaemonCustodyPreflight(cfg)
	if err != nil {
		return err
	}
	live := queryLiveDaemonStatus(cfg.SocketPath)

	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"custody": report,
			"live":    live,
		})
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CHECK\tVERDICT\tPATH\tDETAIL")
	for _, f := range report.Findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.CheckName, f.Verdict, f.Path, f.Details)
	}
	_ = tw.Flush()

	fmt.Println()
	if live.Reachable {
		fmt.Printf("daemon: running, enforcement tier = %s\n", live.EnforcementTier)
	} else {
		fmt.Printf("daemon: not reachable (%s)\n", live.Error)
	}

	if report.CanContinue {
		fmt.Println("\nstatus: daemon custody paths look healthy")
	} else {
		fmt.Fprintln(os.Stderr, "\nstatus: one or more custody paths are missing or misconfigured")
		fmt.Fprintln(os.Stderr, "Run 'ardur-sensor install' to set up.")
		os.Exit(1)
	}
	return nil
}

// sensorLiveStatus is the live-daemon half of `ardur-sensor status`: whether
// the control socket is currently reachable and, if so, which enforcement
// tier (kernelcapture.EnforcementTierBPFLSM / EnforcementTierNone) the
// running daemon reports. An unreachable daemon (not started, or still being
// set up) is a normal, expected state — queryLiveDaemonStatus never returns
// an error; status must report it clearly, not fail the whole command.
type sensorLiveStatus struct {
	Reachable       bool   `json:"reachable"`
	EnforcementTier string `json:"enforcement_tier,omitempty"`
	Error           string `json:"error,omitempty"`
}

func queryLiveDaemonStatus(socketPath string) sensorLiveStatus {
	resp, err := kernelcapture.SendDaemonHealthRequest(socketPath)
	if err != nil {
		return sensorLiveStatus{Reachable: false, Error: err.Error()}
	}
	return sensorLiveStatus{Reachable: true, EnforcementTier: resp.EnforcementTier}
}
