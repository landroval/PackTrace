//go:build !(linux && (amd64 || arm64)) && !(windows && amd64)

package nativefs

func publicationSameParent(*nativeRoot, *nativeRoot) error { return ErrUnavailable }
