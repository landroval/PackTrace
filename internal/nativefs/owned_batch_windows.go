//go:build windows && amd64

package nativefs

import (
	"os"
	"syscall"
)

func batchDuplicate(file *os.File) (*os.File, error) {
	process, e := syscall.GetCurrentProcess()
	if e != nil {
		return nil, ErrUnavailable
	}
	var handle syscall.Handle
	if syscall.DuplicateHandle(process, syscall.Handle(file.Fd()), process, &handle, 0, false, syscall.DUPLICATE_SAME_ACCESS) != nil {
		return nil, ErrUnavailable
	}
	return os.NewFile(uintptr(handle), "owned-durability"), nil
}
func batchPrivate(file *os.File, directory bool) error { _, e := ownedCheckSecurity(file); return e }
func batchDirectory(_ *nativeRoot, selected *object) (*os.File, error) {
	return winOpen(selected.handle, "", 0x40000000|0x20000, winDirectory, true)
}
