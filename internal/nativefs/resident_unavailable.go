//go:build (darwin && (!cgo || (!amd64 && !arm64))) || (linux && !amd64 && !arm64) || (!darwin && !linux && !windows)

package nativefs

func OwnResidentBytes() (uint64, error) { return 0, ErrUnavailable }
