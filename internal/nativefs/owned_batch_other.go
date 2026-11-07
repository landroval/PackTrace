//go:build !(linux && (amd64 || arm64)) && !(windows && amd64)

package nativefs

import "os"

func batchPrivate(*os.File, bool) error                     { return ErrUnavailable }
func batchDuplicate(*os.File) (*os.File, error)             { return nil, ErrUnavailable }
func batchDirectory(*nativeRoot, *object) (*os.File, error) { return nil, ErrUnavailable }
