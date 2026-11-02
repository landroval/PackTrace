//go:build !(linux && (amd64 || arm64)) && !(windows && amd64)

package nativefs

import "os"

func ownedRetireCheck(*nativeRoot, *os.File, stamp) error              { return ErrUnavailable }
func ownedRetireHandle(*nativeRoot, *os.File, stamp) (*os.File, error) { return nil, ErrUnavailable }
func ownedRetireUnlink(*nativeRoot, *os.File, string, stamp) error     { return ErrUnavailable }
