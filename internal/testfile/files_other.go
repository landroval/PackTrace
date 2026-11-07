//go:build !windows

package testfile

import "os"

func OpenExisting(path string, write bool) (*os.File, error) {
	flags := os.O_RDONLY
	if write {
		flags = os.O_RDWR
	}
	return os.OpenFile(path, flags, 0)
}
