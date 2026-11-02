//go:build !(linux && (amd64 || arm64)) && !(windows && amd64)

package nativefs

import "os"

func ownedControlMetadata(*nativeRoot, string) (*os.File, stamp, error) {
	return nil, stamp{}, ErrUnavailable
}

type ownedNative struct{}

func openOwnedDirectory(string, bool) (*OwnedDirectory, error)      { return nil, ErrUnavailable }
func ownedIdentity(*nativeRoot) ([32]byte, error)                   { return [32]byte{}, ErrUnavailable }
func (*ownedNative) guard(*nativeRoot) error                        { return ErrUnavailable }
func (*ownedNative) writeControl(*nativeRoot, string, []byte) error { return ErrUnavailable }
func (*ownedNative) close() error                                   { return ErrUnavailable }
