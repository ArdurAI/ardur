//go:build !linux

package main

import "fmt"

func writeBenchmarkReportFile(outputDirectory string, raw []byte) error {
	return fmt.Errorf("secure benchmark report publication is unsupported outside Linux")
}
