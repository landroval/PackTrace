//go:build !(linux && (amd64 || arm64)) && !(windows && amd64)

package nativefs

import "os"

func ownedMove(*nativeRoot, *os.File, string, string, bool, bool) error { return ErrUnavailable }
