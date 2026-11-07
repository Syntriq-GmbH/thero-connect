//go:build !windows

package main

import (
	"context"
	"errors"
	"io"
	"os"
)

var errWindowsOnly = errors.New("thero-connect reads shares only on Windows")

func newSource() (source, error) {
	return nil, errWindowsOnly
}

func protect(data []byte) ([]byte, error) {
	return data, nil
}

func unprotect(data []byte) ([]byte, error) {
	return data, nil
}

func isService() bool {
	return false
}

func runService(run func(ctx context.Context) error) error {
	return errWindowsOnly
}

func secureDir(dir, account string) error {
	return nil
}

func install(dir, account string) error {
	return errWindowsOnly
}

func uninstall() error {
	return errWindowsOnly
}

func logOutput(service bool) io.Writer {
	return os.Stderr
}
