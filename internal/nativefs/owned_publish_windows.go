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

func ownedRename(n *nativeRoot, f *os.File, source, dest string, replace bool) error {
	if ownedSetInfo.Find() != nil {
		return ErrUnavailable
	}
	units, e := syscall.UTF16FromString(strings.ReplaceAll(dest, "/", `\`))
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
	binary.LittleEndian.PutUint64(b[8:16], uint64(n.root.Fd()))
	binary.LittleEndian.PutUint32(b[16:20], uint32(len(units)*2))
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[20+2*i:], u)
	}
	ios := new(winIOStatus)
	status, _, _ := ownedSetInfo.Call(f.Fd(), uintptr(unsafe.Pointer(ios)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 10)
	ok := winFinish(status, syscall.Handle(f.Fd()), ios)
	runtime.KeepAlive(f)
	runtime.KeepAlive(n.root)
	runtime.KeepAlive(b)
	runtime.KeepAlive(ios)
	if !ok {
		if uint32(status) == 0xc0000035 || uint32(ios.status) == 0xc0000035 {
			return ErrExists
		}
		return ErrWrite
	}
	if f.Sync() != nil {
		return ErrWrite
	}
	return nil
}
