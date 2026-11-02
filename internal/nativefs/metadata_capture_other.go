//go:build !(linux && (amd64 || arm64)) && !(windows && amd64)

package nativefs

// The inventory profile is currently Linux amd64/arm64 and Windows amd64.
// A compiled fallback is not qualification of deferred platforms.
func (r *nativeRoot) captureMetadata(name string) (*object, error) { return nil, ErrUnavailable }
