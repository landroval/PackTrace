//go:build !linux

package main

import "os"

// Native concurrent output is not qualified by cross-compilation.
func terminalProgressWidth(*os.File) bool { return false }
