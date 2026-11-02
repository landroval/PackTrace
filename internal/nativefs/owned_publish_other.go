//go:build !(linux && (amd64 || arm64)) && !(windows && amd64)

package nativefs

import "os"

func ownedRename(*nativeRoot, *os.File, string, string, bool) error { return ErrUnavailable }
