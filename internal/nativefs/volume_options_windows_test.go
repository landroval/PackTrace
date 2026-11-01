//go:build windows && amd64

package nativefs

import (
	"encoding/binary"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

// Diagnostic only: all calls select the fixed trusted kernel-volume DIRECTORY,
// never a target component, file, raw device, reparse point or content stream.
// The directory/synchronous/access requirements never change. Vary only the
// three candidate flags, in a frozen complete matrix, with immediate close.
// Success here is NOT admission by the product or scanner qualification.
func TestWindowsVolumeBootstrapPairedOptions(t *testing.T) {
	drive, _, e := winRootPath(t.TempDir())
	if e != nil {
		t.Fatal("owned-fixture-syntax", e)
	}
	if e = prepareNative(); e != nil {
		t.Fatal("native-api", e)
	}
	volume, e := winVolumeName(drive)
	if e != nil {
		t.Fatal("trusted-volume-name", e)
	}
	units, e := syscall.UTF16FromString(volume + `\`)
	if e != nil {
		t.Fatal("trusted-volume-unicode", e)
	}
	u := winUnicode{length: uint16((len(units) - 1) * 2), maximum: uint16(len(units) * 2), buffer: &units[0]}
	t.Logf("go-abi-layout: unicode=%d object-attributes=%d io-status=%d unicode-buffer-offset=%d object-root-offset=%d object-name-offset=%d", unsafe.Sizeof(u), unsafe.Sizeof(winAttributes{}), unsafe.Sizeof(winIOStatus{}), unsafe.Offsetof(u.buffer), unsafe.Offsetof(winAttributes{}.root), unsafe.Offsetof(winAttributes{}.name))
	var original syscall.ByHandleFileInformation
	haveIdentity := false
	for _, api := range []string{"create", "open"} {
		for _, guarded := range []bool{true, false} {
			for _, reparse := range []bool{true, false} {
				for _, recall := range []bool{true, false} {
					a := winAttributes{name: &u}
					a.length = uint32(unsafe.Sizeof(a))
					if guarded {
						a.attributes = winDontReparse
					}
					options := uint32(winDirectory | winSynchronous)
					if reparse {
						options |= winOpenReparse
					}
					if recall {
						options |= winNoRecall
					}
					var h syscall.Handle
					io := new(winIOStatus)
					var status uintptr
					if api == "create" {
						status, _, _ = winCreate.Call(uintptr(unsafe.Pointer(&h)), winReadAttrs|winSync, uintptr(unsafe.Pointer(&a)), uintptr(unsafe.Pointer(io)), 0, 0, 7, 1, uintptr(options), 0, 0)
					} else {
						status, _, _ = winReopen.Call(uintptr(unsafe.Pointer(&h)), winReadAttrs|winSync, uintptr(unsafe.Pointer(&a)), uintptr(unsafe.Pointer(io)), 7, uintptr(options))
					}
					ok := winFinish(status, h, io)
					runtime.KeepAlive(units)
					runtime.KeepAlive(u)
					runtime.KeepAlive(a)
					runtime.KeepAlive(io)
					t.Logf("volume-option-pair: api=%s dont-reparse=%t open-reparse=%t no-recall=%t options=%08x status=%08x ios=%08x information=%d valid=%t", api, guarded, reparse, recall, options, uint32(status), uint32(io.status), io.information, ok)
					if h == 0 || h == syscall.InvalidHandle {
						if ok {
							t.Fatal("success-without-owned-handle")
						}
						continue
					}
					var factsErr error
					if ok {
						var info syscall.ByHandleFileInformation
						factsErr = syscall.GetFileInformationByHandle(h, &info)
						isDirectory := info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0
						same := !haveIdentity || info.VolumeSerialNumber == original.VolumeSerialNumber && info.FileIndexHigh == original.FileIndexHigh && info.FileIndexLow == original.FileIndexLow
						t.Logf("volume-option-identity: query-valid=%t directory=%t file-id-nonzero=%t same-trusted-object=%t", factsErr == nil, isDirectory, info.FileIndexHigh != 0 || info.FileIndexLow != 0, same)
						if factsErr == nil && (!isDirectory || !same) {
							factsErr = ErrUnstable
						}
						if factsErr == nil && !haveIdentity {
							original = info
							haveIdentity = true
						}
						// Only fixed volume metadata; never enumerate entries/read bytes.
						var b [128]byte
						q := new(winIOStatus)
						s, _, _ := winQueryVolume.Call(uintptr(h), uintptr(unsafe.Pointer(q)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 5)
						valid := winFinish(s, h, q)
						runtime.KeepAlive(q)
						runtime.KeepAlive(b)
						t.Logf("volume-option-filesystem: status=%08x information=%d ntfs=%t", uint32(s), q.information, valid && q.information >= 20 && binary.LittleEndian.Uint32(b[8:]) == 8 && string(b[12:20]) == "N\x00T\x00F\x00S\x00")
					}
					closeErr := syscall.CloseHandle(h)
					if factsErr != nil || closeErr != nil {
						t.Fatal("owned-volume-query-or-close", factsErr, closeErr)
					}
				}
			}
		}
	}
}
