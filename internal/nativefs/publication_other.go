//go:build !(linux && (amd64 || arm64)) && !(windows && amd64)

package nativefs

import "os"

func publicationRefreshForbidden(*nativeRoot, *Root) error { return ErrUnavailable }
func publicationMetadata(*nativeRoot, string) (*os.File, stamp, error) {
	return nil, stamp{}, ErrUnavailable
}
func publicationRefresh(*nativeRoot) error { return ErrUnavailable }
