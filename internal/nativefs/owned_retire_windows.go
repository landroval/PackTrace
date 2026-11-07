//go:build windows && amd64

package nativefs

import (
	"encoding/binary"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

func ownedRetireCheck(_ *nativeRoot, f *os.File, initial stamp) error {
	handle, e := winOpen(f, "", 0x20000, winNonDirectory, true)
	if e != nil {
		return e
	}
	defer handle.Close()
	now, e := statNative(handle)
	if e != nil || now != initial || now.links != 1 || now.kind() != KindRegular {
		return ErrUnstable
	}
	_, e = ownedCheckSecurity(handle)
	return e
}
func ownedRetireHandle(n *nativeRoot, f *os.File, initial stamp) (*os.File, error) {
	if e := ownedRetireCheck(n, f, initial); e != nil {
		return nil, e
	}
	// Empty-name reopen refers to the already admitted original NTFS object;
	// DELETE/READ_CONTROL do not grant FILE_READ_DATA or FILE_WRITE_DATA.
	handle, e := winOpen(f, "", 0x10000|0x20000, winNonDirectory, true)
	if e != nil {
		return nil, e
	}
	if _, e := ownedCheckSecurity(handle); e != nil {
		handle.Close()
		return nil, e
	}
	now, e := statNative(handle)
	if e != nil || now != initial {
		handle.Close()
		return nil, ErrUnstable
	}
	return handle, nil
}
func ownedRetireUnlink(n *nativeRoot, f *os.File, _ string, initial stamp) error {
	handle, e := ownedRetireHandle(n, f, initial)
	if e != nil {
		return e
	}
	var flags [4]byte
	binary.LittleEndian.PutUint32(flags[:], 3)
	ios := new(winIOStatus)
	status, _, _ := ownedSetInfo.Call(handle.Fd(), uintptr(unsafe.Pointer(ios)), uintptr(unsafe.Pointer(&flags[0])), uintptr(len(flags)), 64)
	ok := winFinish(status, syscall.Handle(handle.Fd()), ios)
	runtime.KeepAlive(handle)
	runtime.KeepAlive(flags)
	runtime.KeepAlive(ios)
	closeErr := handle.Close()
	if !ok || closeErr != nil {
		return ErrWrite
	}
	// Zero retained-original link count is positive removal evidence. General
	// statNative deliberately rejects deleted objects, so do not weaken it.
	var info syscall.ByHandleFileInformation
	var standard [24]byte
	if syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &info) != nil || winQuery(f, false, 5, standard[:], 24) != nil {
		return ErrUnstable
	}
	if uint64(info.VolumeSerialNumber) != initial.dev || uint64(info.FileIndexHigh)<<32|uint64(info.FileIndexLow) != initial.ino || binary.LittleEndian.Uint32(standard[16:]) != 0 {
		return ErrUnstable
	}
	return nil
}
