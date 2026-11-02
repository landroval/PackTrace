//go:build linux && (amd64 || arm64)

package nativefs

import (
	"os"
	"syscall"
)

func batchDuplicate(file *os.File) (*os.File, error) {
	fd, _, e := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), 1030, 0)
	if e != 0 {
		return nil, ErrUnavailable
	}
	return os.NewFile(fd, "owned-durability"), nil
}
func batchPrivate(file *os.File, directory bool) error {
	var raw syscall.Stat_t
	if syscall.Fstat(int(file.Fd()), &raw) != nil {
		return ErrUnstable
	}
	mode, kind := uint32(0600), uint32(syscall.S_IFREG)
	if directory {
		mode, kind = 0700, syscall.S_IFDIR
	}
	if raw.Uid != uint32(os.Geteuid()) || raw.Mode&07777 != mode || raw.Mode&syscall.S_IFMT != kind || !directory && raw.Nlink != 1 {
		return ErrUnstable
	}
	return nil
}
func batchDirectory(n *nativeRoot, selected *object) (*os.File, error) {
	return n.readCaptured(selected.handle, selected.initial)
}
