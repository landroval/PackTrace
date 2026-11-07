//go:build windows && amd64

package nativefs

import "os"

func readDirectoryCaptured(n *nativeRoot, selected *object) (*os.File, error) {
	if selected == nil || selected.initial.kind() != KindDirectory {
		return nil, ErrType
	}
	if n.guard() != nil {
		return nil, ErrUnstable
	}
	f, err := winOpen(selected.handle, "", 1, winDirectory, true)
	if err != nil {
		return nil, err
	}
	current, err := statNative(f)
	if err != nil || current != selected.initial {
		f.Close()
		return nil, ErrUnstable
	}
	return f, nil
}
