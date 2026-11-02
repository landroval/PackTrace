//go:build linux && (amd64 || arm64)

package nativefs

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

func ownedRename(n *nativeRoot, original *os.File, source, dest string, replace bool) (failure error) {
	// Capture both directory I/O handles before rename changes their stamps.
	dirs := make([]*os.File, 0, 2)
	defer func() {
		for _, f := range dirs {
			if f.Close() != nil {
				failure = errors.Join(failure, ErrWrite)
			}
		}
	}()
	for _, name := range []string{source, dest} {
		parent := "."
		if i := strings.LastIndexByte(name, '/'); i >= 0 {
			parent = name[:i]
		}
		m, e := n.captureMetadata(parent)
		if e != nil {
			return e
		}
		if m.initial.kind() != KindDirectory {
			m.close()
			return ErrType
		}
		f, e := n.readCaptured(m.handle, m.initial)
		m.close()
		if e != nil {
			return e
		}
		dirs = append(dirs, f)
	}
	a, e := syscall.BytePtrFromString(source)
	if e != nil {
		return ErrPath
	}
	b, e := syscall.BytePtrFromString(dest)
	if e != nil {
		return ErrPath
	}
	trap := uintptr(316)
	if runtime.GOARCH == "arm64" {
		trap = 276
	}
	flags := uintptr(1)
	if replace {
		flags = 0
	}
	_, _, errno := syscall.Syscall6(trap, n.root.Fd(), uintptr(unsafe.Pointer(a)), n.root.Fd(), uintptr(unsafe.Pointer(b)), flags, 0)
	runtime.KeepAlive(n.root)
	runtime.KeepAlive(a)
	runtime.KeepAlive(b)
	runtime.KeepAlive(original)
	if errno == syscall.EEXIST {
		return ErrExists
	}
	if errno != 0 {
		return ErrWrite
	}
	for _, f := range dirs {
		if f.Sync() != nil {
			return ErrWrite
		}
	}
	return nil
}
