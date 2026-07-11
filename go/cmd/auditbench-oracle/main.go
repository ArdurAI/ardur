// auditbench-oracle converts a strict raw capture into separate oracle and
// projected-evidence artifacts. It never accepts labels or SUT output.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ArdurAI/ardur/go/benchmark/independent"
)

func main() {
	input := flag.String("in", "", "raw capture JSON")
	output := flag.String("out", "", "output directory")
	flag.Parse()
	if *input == "" || *output == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: auditbench-oracle -in capture.json -out corpus/")
		os.Exit(2)
	}
	oracle, evidence, err := independent.NormalizeCaptureFile(*input, *output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "auditbench-oracle: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("normalized scenario %s: oracle=%d evidence=%d\n", oracle.ScenarioID, len(oracle.Observations), len(evidence.Observations))
}
