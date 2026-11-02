//go:build linux && (amd64 || arm64)

package nativefs

import (
	"os"
	"strings"
	"syscall"
)

func ownedRetireCheck(_ *nativeRoot, f *os.File, initial stamp) error {
	var st syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &st) != nil || st.Uid != uint32(os.Getuid()) || initial.mode&0777 != 0600 {
		return ErrPath
	}
	now, e := statNative(f)
	if e != nil || now != initial || now.links != 1 || now.kind() != KindRegular {
		return ErrUnstable
	}
	return nil
}
func ownedRetireHandle(n *nativeRoot, f *os.File, initial stamp) (*os.File, error) {
	if e := ownedRetireCheck(n, f, initial); e != nil {
		return nil, e
	}
	fd, _, e := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), 1030, 0)
	if e != 0 {
		return nil, ErrUnavailable
	}
	return os.NewFile(fd, ""), nil
}
func ownedRetireUnlink(n *nativeRoot, f *os.File, name string, initial stamp) error {
	parentName, leaf := ".", name
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		parentName, leaf = name[:i], name[i+1:]
	}
	parent, e := n.captureMetadata(parentName)
	if e != nil {
		return e
	}
	defer parent.close()
	if parent.initial.kind() != KindDirectory {
		return ErrType
	}
	dir, e := n.readCaptured(parent.handle, parent.initial)
	if e != nil {
		return e
	}
	defer dir.Close()
	bound, e := n.captureMetadata(name)
	if e != nil {
		return e
	}
	same := bound.initial == initial
	bound.close()
	if !same {
		return ErrUnstable
	}
	if e := syscall.Unlinkat(int(dir.Fd()), leaf); e != nil {
		return ErrWrite
	}
	after, e := statNative(f)
	if e != nil || after.dev != initial.dev || after.ino != initial.ino || after.links != 0 {
		return ErrUnstable
	}
	if dir.Sync() != nil {
		return ErrWrite
	}
	return nil
}
