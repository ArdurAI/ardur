//go:build !linux

package kernelcapture

import (
	"context"
	"fmt"
)

func RunAgentRecognitionBenchmark(context.Context, AgentRecognitionBenchmarkOptions) (*AgentRecognitionBenchmarkReport, error) {
	return nil, fmt.Errorf("%w: real agent-recognition benchmarking is supported only on Linux", ErrAgentRecognitionBenchmark)
}
