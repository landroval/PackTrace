//go:build !linux

package main

import (
	"errors"
	"packtrace/internal/execution"
)

func validLifetimeFD(int) bool   { return false }
func prepareLifetimeFD(int) bool { return false }
func closeLifetimeFD(int)        {}
func emitLifetime(int, execution.ScanReceipt, int) error {
	return errors.New("private receipt unsupported")
}
