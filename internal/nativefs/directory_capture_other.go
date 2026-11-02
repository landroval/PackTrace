//go:build !(linux && (amd64 || arm64)) && !(windows && amd64)

package nativefs

import "os"

func readDirectoryCaptured(*nativeRoot, *object) (*os.File, error) { return nil, ErrUnavailable }
