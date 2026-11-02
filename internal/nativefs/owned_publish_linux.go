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

func ownedMove(n *nativeRoot, original *os.File, source, dest string, replace, flush bool) error {
	return ownedMoveMode(n, original, source, dest, replace, flush, true)
}
func ownedMoveMode(n *nativeRoot, original *os.File, source, dest string, replace, flush, flushDirectories bool) (failure error) {
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
	sourceLeaf := source
	if i := strings.LastIndexByte(sourceLeaf, '/'); i >= 0 {
		sourceLeaf = sourceLeaf[i+1:]
	}
	destLeaf := dest
	if i := strings.LastIndexByte(destLeaf, '/'); i >= 0 {
		destLeaf = destLeaf[i+1:]
	}
	a, e := syscall.BytePtrFromString(sourceLeaf)
	if e != nil {
		return ErrPath
	}
	b, e := syscall.BytePtrFromString(destLeaf)
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
	_, _, errno := syscall.Syscall6(trap, dirs[0].Fd(), uintptr(unsafe.Pointer(a)), dirs[1].Fd(), uintptr(unsafe.Pointer(b)), flags, 0)
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
		if flushDirectories && f.Sync() != nil {
			return ErrWrite
		}
	}
	return nil
}
