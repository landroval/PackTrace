//go:build (linux && (amd64 || arm64)) || (windows && amd64)

package nativeresource

import (
	"io"
	"os"
	"runtime"
	"testing"
)

// Same inert owned child on Linux and Windows; no target program is executed.
func TestOwnedResidentChildEntry(t *testing.T) {
	if os.Getenv("PACKTRACE_TEST_RSS_CHILD") != "1" {
		return
	}
	var command [1]byte
	_, _ = os.Stdout.Write([]byte("R"))
	if _, e := io.ReadFull(os.Stdin, command[:]); e != nil {
		os.Exit(3)
	}
	pages := make([]byte, 32<<20)
	for i := 0; i < len(pages); i += os.Getpagesize() {
		pages[i] = 1
	}
	_, _ = os.Stdout.Write([]byte("A"))
	_, _ = io.ReadFull(os.Stdin, command[:])
	runtime.KeepAlive(pages)
	os.Exit(0)
}
