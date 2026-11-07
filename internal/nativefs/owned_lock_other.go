//go:build !(linux && (amd64 || arm64)) && !(windows && amd64)

package nativefs

import "os"

func ownedLockFile(*nativeRoot, string, bool) (*os.File, error) { return nil, ErrUnavailable }
func ownedUnlock(*os.File) error                                { return ErrUnavailable }
