//go:build windows && amd64

package nativefs

import (
	"encoding/binary"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

var ownedSetInfo = winNT.NewProc("NtSetInformationFile")

func ownedMove(n *nativeRoot, f *os.File, source, dest string, replace, flush bool) error {
	return ownedMoveMode(n, f, source, dest, replace, flush, true)
}
func ownedMoveMode(n *nativeRoot, f *os.File, source, dest string, replace, flush, flushDirectories bool) error {
	if ownedSetInfo.Find() != nil {
		return ErrUnavailable
	}
	parentName, leaf := ".", dest
	if i := strings.LastIndexByte(dest, '/'); i >= 0 {
		parentName, leaf = dest[:i], dest[i+1:]
	}
	parent, e := n.captureMetadata(parentName)
	if e != nil {
		return e
	}
	defer parent.close()
	if parent.initial.kind() != KindDirectory {
		return ErrType
	}
	// Resolve the admitted destination parent once; the rename name is a
	// single component relative to that original handle, never a rewalk.
	units, e := syscall.UTF16FromString(leaf)
	if e != nil {
		return ErrPath
	}
	units = units[:len(units)-1]
	// FILE_RENAME_INFORMATION: BOOLEAN/union at0, HANDLE at8, length at16,
	// UTF16 name at20 for the admitted Windows amd64 ABI. No absolute name.
	b := make([]byte, 20+len(units)*2)
	if replace {
		b[0] = 1
	}
	binary.LittleEndian.PutUint64(b[8:16], uint64(parent.handle.Fd()))
	binary.LittleEndian.PutUint32(b[16:20], uint32(len(units)*2))
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[20+2*i:], u)
	}
	ios := new(winIOStatus)
	status, _, _ := ownedSetInfo.Call(f.Fd(), uintptr(unsafe.Pointer(ios)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 10)
	ok := winFinish(status, syscall.Handle(f.Fd()), ios)
	runtime.KeepAlive(f)
	runtime.KeepAlive(n.root)
	runtime.KeepAlive(parent.handle)
	runtime.KeepAlive(b)
	runtime.KeepAlive(ios)
	if !ok {
		if uint32(status) == 0xc0000035 || uint32(ios.status) == 0xc0000035 {
			return ErrExists
		}
		return ErrWrite
	}
	if flush && f.Sync() != nil {
		return ErrWrite
	}
	return nil
}
