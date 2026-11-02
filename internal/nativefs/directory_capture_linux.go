//go:build linux && (amd64 || arm64)

package nativefs

import "os"

func readDirectoryCaptured(n *nativeRoot, selected *object) (*os.File, error) {
	if selected == nil || selected.initial.kind() != KindDirectory {
		return nil, ErrType
	}
	return n.readCaptured(selected.handle, selected.initial)
}
