//go:build windows

package nativefs

import (
	"os"
	"syscall"
)

// Authored owned test files only. Ordinary os.Open/WriteFile omit SHARE_DELETE
// and cannot coexist with the original DELETE-capable publication handles.
func openOwnedFixture(path string, write bool) (*os.File, error) {
	name, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	access := uint32(syscall.GENERIC_READ)
	if write {
		access |= syscall.GENERIC_WRITE
	}
	h, e := syscall.CreateFile(name, access, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(h), path), nil
}
