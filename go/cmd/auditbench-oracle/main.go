// auditbench-oracle converts a strict raw capture into separate oracle and
// projected-evidence artifacts. It never accepts labels or SUT output.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ArdurAI/ardur/go/benchmark/independent"
)

const (
	exitOK       = 0
	exitRuntime  = 1
	exitInvalid  = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("auditbench-oracle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	input := fs.String("in", "", "raw capture JSON")
	output := fs.String("out", "", "output directory")
	if err := fs.Parse(args); err != nil {
		return exitInvalid
	}
	if strings.TrimSpace(*input) == "" || strings.TrimSpace(*output) == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: auditbench-oracle -in capture.json -out corpus/")
		return exitInvalid
	}
	oracle, evidence, err := independent.NormalizeCaptureFile(*input, *output)
	if err != nil {
		fmt.Fprintf(stderr, "auditbench-oracle: %v\n", err)
		return exitRuntime
	}
	fmt.Fprintf(stdout, "normalized scenario %s: oracle=%d evidence=%d\n", oracle.ScenarioID, len(oracle.Observations), len(evidence.Observations))
	return exitOK
}
