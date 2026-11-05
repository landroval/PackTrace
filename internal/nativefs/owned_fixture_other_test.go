//go:build !windows

package nativefs

import "os"

func openOwnedFixture(path string, write bool) (*os.File, error) {
	flags := os.O_RDONLY
	if write {
		flags = os.O_RDWR
	}
	return os.OpenFile(path, flags, 0)
}
