// ardur-agent-recognition-workload is the intentionally small native process
// corpus used by the recognition overhead benchmark.
package main

import (
	"os"
	"strconv"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) != 2 || args[0] != "--workload-hold-milliseconds" {
		return 2
	}
	milliseconds, err := strconv.Atoi(args[1])
	if err != nil || milliseconds < 1 || milliseconds > 10_000 {
		return 2
	}
	time.Sleep(time.Duration(milliseconds) * time.Millisecond)
	return 0
}
