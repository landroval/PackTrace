//go:build !darwin || !arm64

package main

import (
	"os"
	"runtime"
	"runtime/debug"
)

func actualEnvironment() Environment {
	e := Environment{OS: runtime.GOOS, Arch: runtime.GOARCH, Go: runtime.Version(), UID: os.Getuid(), API: "clonefileat", Flags: 10}
	if b, ok := debug.ReadBuildInfo(); ok {
		for _, s := range b.Settings {
			if s.Key == "CGO_ENABLED" {
				e.CGO = s.Value
			}
		}
	}
	return e
}
func observer() int { return 2 }
func nativeRun(_ string, r *Receipt) int {
	r.Environment.Reason = "unsupported-profile"
	return finish(r, false)
}
