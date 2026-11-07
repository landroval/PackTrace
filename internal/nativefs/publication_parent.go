//go:build (linux && (amd64 || arm64)) || (windows && amd64)

package nativefs

// Comparing two retained native handle observations does not resolve a name or
// substitute a hash/lexical comparison for native separation authority.
func publicationSameParent(first, second *nativeRoot) error {
	a, e := statNative(first.root)
	if e != nil {
		return e
	}
	b, e := statNative(second.root)
	if e != nil {
		return e
	}
	if a != b {
		return ErrUnstable
	}
	return nil
}
