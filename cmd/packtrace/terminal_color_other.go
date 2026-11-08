//go:build !linux && !windows

package main

import "os"

// Unsupported terminal capability checks stay plain rather than guessing.
func terminalSupportsANSI(_ *os.File) bool { return false }
