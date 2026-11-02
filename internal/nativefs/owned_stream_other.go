//go:build !(linux && (amd64 || arm64)) && !(windows && amd64)

package nativefs

import "os"

func ownedCreatePath(*nativeRoot, string, bool) (*os.File, error) { return nil, ErrUnavailable }
func (*ownedNative) refresh(*nativeRoot) error                    { return ErrUnavailable }
