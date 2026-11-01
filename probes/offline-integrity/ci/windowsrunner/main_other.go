//go:build !windows || !amd64

package main

import "os"

// Only the stream/capture checks run on the development host. This refusal is
// not a Windows emulator or a qualification result.
func main() { os.Exit(2) }
