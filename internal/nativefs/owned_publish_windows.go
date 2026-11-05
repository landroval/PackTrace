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
	// Both admitted amd64 layouts place flags/BOOLEAN at0, HANDLE at8,
	// length at16 and UTF16 name at20. No absolute name or parent rewalk.
	b := make([]byte, 20+len(units)*2)
	class := uintptr(10) // FileRenameInformation; no-clobber remains unchanged.
	if replace {
		// Like the pinned SDK's Renameat, NTFS POSIX replacement preserves an
		// already-open destination's original handle instead of closing it.
		// No legacy fallback: an unsupported operation remains a failure.
		class = 65                                // FileRenameInformationEx
		binary.LittleEndian.PutUint32(b[:4], 1|2) // REPLACE_IF_EXISTS | POSIX_SEMANTICS
	}
	binary.LittleEndian.PutUint64(b[8:16], uint64(parent.handle.Fd()))
	binary.LittleEndian.PutUint32(b[16:20], uint32(len(units)*2))
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[20+2*i:], u)
	}
	ios := new(winIOStatus)
	status, _, _ := ownedSetInfo.Call(f.Fd(), uintptr(unsafe.Pointer(ios)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), class)
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
