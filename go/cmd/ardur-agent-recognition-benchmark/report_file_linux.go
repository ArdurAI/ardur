//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const benchmarkReportTemporaryFilename = ".agent-recognition-benchmark.tmp"

func writeBenchmarkReportFile(outputDirectory string, raw []byte) error {
	directory, err := openBenchmarkReportDirectory(outputDirectory)
	if err != nil {
		return err
	}
	defer directory.Close()
	directoryFD := int(directory.Fd())
	if err := unix.Fchmod(directoryFD, 0o700); err != nil {
		return fmt.Errorf("secure output directory")
	}
	if err := unix.Unlinkat(directoryFD, benchmarkReportTemporaryFilename, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove stale report temporary file")
	}

	temporaryFD, err := unix.Openat(
		directoryFD,
		benchmarkReportTemporaryFilename,
		unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("create report temporary file")
	}
	if err := unix.Fchmod(temporaryFD, 0o600); err != nil {
		_ = unix.Close(temporaryFD)
		_ = unix.Unlinkat(directoryFD, benchmarkReportTemporaryFilename, 0)
		return fmt.Errorf("secure report temporary file")
	}
	temporary := os.NewFile(uintptr(temporaryFD), benchmarkReportTemporaryFilename)
	if temporary == nil {
		_ = unix.Close(temporaryFD)
		_ = unix.Unlinkat(directoryFD, benchmarkReportTemporaryFilename, 0)
		return fmt.Errorf("open report temporary file")
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = unix.Unlinkat(directoryFD, benchmarkReportTemporaryFilename, 0)
		}
	}()
	written, writeErr := temporary.Write(raw)
	if writeErr != nil {
		_ = temporary.Close()
		return fmt.Errorf("write report: %w", writeErr)
	}
	if written != len(raw) {
		_ = temporary.Close()
		return fmt.Errorf("write report: %w", io.ErrShortWrite)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync report")
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close report")
	}
	if err := unix.Renameat2(directoryFD, benchmarkReportTemporaryFilename, directoryFD, reportFilename, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("publish report")
	}
	removeTemporary = false
	if err := unix.Fsync(directoryFD); err != nil {
		return fmt.Errorf("sync output directory")
	}
	return nil
}

func openBenchmarkReportDirectory(outputDirectory string) (*os.File, error) {
	clean := filepath.Clean(outputDirectory)
	if !filepath.IsAbs(outputDirectory) || clean != outputDirectory || clean == string(filepath.Separator) {
		return nil, fmt.Errorf("output directory must be a clean absolute path")
	}
	components := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	currentFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open output directory root")
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			_ = unix.Close(currentFD)
			return nil, fmt.Errorf("output directory component is invalid")
		}
		nextFD, openErr := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) {
			if mkdirErr := unix.Mkdirat(currentFD, component, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = unix.Close(currentFD)
				return nil, fmt.Errorf("create output directory")
			}
			nextFD, openErr = unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		_ = unix.Close(currentFD)
		if openErr != nil {
			return nil, fmt.Errorf("output directory contains an unavailable or symlinked component")
		}
		currentFD = nextFD
	}
	directory := os.NewFile(uintptr(currentFD), "benchmark-report-directory")
	if directory == nil {
		_ = unix.Close(currentFD)
		return nil, fmt.Errorf("open benchmark report directory")
	}
	return directory, nil
}
