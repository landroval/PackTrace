//go:build windows

package main

import (
	"os"
	"syscall"
)

func openStorageDirectory(name string) (*os.File, error) {
	p, e := syscall.UTF16PtrFromString(name)
	if e != nil {
		return nil, e
	}
	// Go's ordinary Open omits FILE_SHARE_DELETE, conflicting with a concurrent
	// owned DELETE-access handle. Sharing deletion does not grant this observer
	// DELETE access. Keep metadata/list-only access and pin any reparse object.
	h, e := syscall.CreateFile(p, 0x81, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(h), name), nil
}
