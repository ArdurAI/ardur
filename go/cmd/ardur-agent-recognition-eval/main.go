// ardur-agent-recognition-eval evaluates the maintained, sanitized process-name
// recognition corpus against the embedded Ardur recognition registry.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ArdurAI/ardur/go/pkg/kernelcapture"
)

const (
	exitPassed     = 0
	exitGateFailed = 1
	exitInvalid    = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ardur-agent-recognition-eval", flag.ContinueOnError)
	fs.SetOutput(stderr)
	corpusPath := fs.String("corpus", "", "optional versioned corpus JSON; defaults to the embedded corpus")
	thresholdsPath := fs.String("thresholds", "", "optional versioned threshold JSON; defaults to the embedded thresholds")
	if err := fs.Parse(args); err != nil {
		return exitInvalid
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "ardur-agent-recognition-eval: positional arguments are not supported")
		return exitInvalid
	}

	corpus, corpusSHA256, err := loadCorpus(*corpusPath)
	if err != nil {
		fmt.Fprintf(stderr, "ardur-agent-recognition-eval: %v\n", err)
		return exitInvalid
	}
	thresholds, err := loadThresholds(*thresholdsPath)
	if err != nil {
		fmt.Fprintf(stderr, "ardur-agent-recognition-eval: %v\n", err)
		return exitInvalid
	}
	recognizer, err := kernelcapture.NewEmbeddedAgentRecognizer(kernelcapture.AgentRecognizerOptions{})
	if err != nil {
		fmt.Fprintln(stderr, "ardur-agent-recognition-eval: initialize embedded recognition registry")
		return exitInvalid
	}
	report, err := kernelcapture.EvaluateAgentRecognitionCorpus(recognizer, corpus, corpusSHA256, thresholds)
	if err != nil {
		fmt.Fprintf(stderr, "ardur-agent-recognition-eval: %v\n", err)
		return exitInvalid
	}
	encoded, err := kernelcapture.MarshalAgentRecognitionEvaluationReport(report)
	if err != nil {
		fmt.Fprintln(stderr, "ardur-agent-recognition-eval: serialize evaluation report")
		return exitInvalid
	}
	if _, err := stdout.Write(encoded); err != nil {
		fmt.Fprintln(stderr, "ardur-agent-recognition-eval: write evaluation report")
		return exitInvalid
	}
	if !report.Gate.Passed {
		return exitGateFailed
	}
	return exitPassed
}

func loadCorpus(path string) (*kernelcapture.AgentRecognitionCorpus, string, error) {
	if path == "" {
		return kernelcapture.EmbeddedAgentRecognitionCorpus()
	}
	input, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("open corpus input")
	}
	defer input.Close()
	return kernelcapture.ParseAgentRecognitionCorpus(input)
}

func loadThresholds(path string) (*kernelcapture.AgentRecognitionThresholds, error) {
	if path == "" {
		return kernelcapture.EmbeddedAgentRecognitionThresholds()
	}
	input, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open threshold input")
	}
	defer input.Close()
	return kernelcapture.ParseAgentRecognitionThresholds(input)
}
