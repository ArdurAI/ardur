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

	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"kernel_caps": caps,
			"custody":     preflight,
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

	// Install daemon custody paths.
	result, err := kernelcapture.InstallDaemonCustody(cfg)
	if err != nil {
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
	_ = fs_.Parse(args)

	cfg := kernelcapture.DefaultDaemonCustodyConfig()

	if !*noStop {
		_ = systemctlRun("disable", "--now", "ardur-kernelcaptured.service")
	}

	if err := kernelcapture.UninstallDaemonCustody(cfg); err != nil {
		return err
	}
	fmt.Printf("  removed: %s\n", cfg.ConfigPath)

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

	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(report)
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CHECK\tVERDICT\tPATH\tDETAIL")
	for _, f := range report.Findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.CheckName, f.Verdict, f.Path, f.Details)
	}
	_ = tw.Flush()

	if report.CanContinue {
		fmt.Println("\nstatus: daemon custody paths look healthy")
	} else {
		fmt.Fprintln(os.Stderr, "\nstatus: one or more custody paths are missing or misconfigured")
		fmt.Fprintln(os.Stderr, "Run 'ardur-sensor install' to set up.")
		os.Exit(1)
	}
	return nil
}
