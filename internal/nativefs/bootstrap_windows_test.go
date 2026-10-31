//go:build windows && amd64

package nativefs

import (
	"encoding/binary"
	"os"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

// Keep fixed numeric bootstrap facts when an owned native fixture is refused.
// This is a diagnostic contract, not an alternate opener or an admission bypass.
// It never opens a target file/device: only the same trusted volume DIRECTORY
// used by openNativeRoot, with identical access, flags and noninheritance.
func TestWindowsVolumeBootstrapFacts(t *testing.T) {
	path := t.TempDir()
	drive, _, e := winRootPath(path)
	if e != nil {
		t.Fatal("fixture-syntax", e)
	}
	if e = prepareNative(); e != nil {
		t.Fatal("api-lookup", e)
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
	a := winAttributes{name: &u, attributes: winDontReparse}
	a.length = uint32(unsafe.Sizeof(a))
	var h syscall.Handle
	io := new(winIOStatus)
	status, _, _ := winCreate.Call(uintptr(unsafe.Pointer(&h)), winReadAttrs|winSync,
		uintptr(unsafe.Pointer(&a)), uintptr(unsafe.Pointer(io)), 0, 0, 7, 1,
		winDirectory|winSynchronous|winOpenReparse|winNoRecall, 0, 0)
	ok := winFinish(status, h, io)
	runtime.KeepAlive(units)
	runtime.KeepAlive(u)
	runtime.KeepAlive(a)
	runtime.KeepAlive(io)
	t.Logf("volume-directory-open: status=%08x ios=%08x information=%d valid=%t", uint32(status), uint32(io.status), io.information, ok)
	if !ok {
		if h != 0 && h != syscall.InvalidHandle {
			syscall.CloseHandle(h)
		}
		t.Fatal("volume-directory-open")
	}
	f := os.NewFile(uintptr(h), "owned-volume-diagnostic")
	if f == nil {
		syscall.CloseHandle(h)
		t.Fatal("owned-volume-wrapper")
	}
	defer f.Close()
	query := func(label string, volume bool, class uint32, n int) []byte {
		b := make([]byte, n)
		io := new(winIOStatus)
		proc := winQueryFile
		if volume {
			proc = winQueryVolume
		}
		status, _, _ := proc.Call(f.Fd(), uintptr(unsafe.Pointer(io)), uintptr(unsafe.Pointer(&b[0])), uintptr(n), uintptr(class))
		ok := winFinish(status, syscall.Handle(f.Fd()), io)
		runtime.KeepAlive(f)
		runtime.KeepAlive(b)
		runtime.KeepAlive(io)
		t.Logf("%s: status=%08x ios=%08x information=%d valid=%t", label, uint32(status), uint32(io.status), io.information, ok)
		return b
	}
	device := query("volume-device", true, 4, 8)
	t.Logf("volume-device: type=%08x characteristics=%08x", binary.LittleEndian.Uint32(device), binary.LittleEndian.Uint32(device[4:]))
	attrs := query("volume-attributes", true, 5, 128)
	t.Logf("volume-attributes: flags=%08x maximum-component=%d name-bytes=%d ntfs=%t", binary.LittleEndian.Uint32(attrs), binary.LittleEndian.Uint32(attrs[4:]), binary.LittleEndian.Uint32(attrs[8:]), string(attrs[12:20]) == "N\x00T\x00F\x00S\x00")
	var info syscall.ByHandleFileInformation
	e = syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &info)
	t.Logf("volume-identity: query-valid=%t id-nonzero=%t links=%d attributes=%08x", e == nil, info.FileIndexHigh != 0 || info.FileIndexLow != 0, info.NumberOfLinks, info.FileAttributes)
	basic := query("file-basic", false, 4, 40)
	t.Logf("file-basic: attributes=%08x", binary.LittleEndian.Uint32(basic[32:]))
	standard := query("file-standard", false, 5, 24)
	t.Logf("file-standard: links=%d delete-pending=%d directory=%d", binary.LittleEndian.Uint32(standard[16:]), standard[20], standard[21])
	cs := query("directory-case", false, 71, 4)
	t.Logf("directory-case: flags=%08x", binary.LittleEndian.Uint32(cs))
	if e := winQualifyVolume(f); e != nil {
		t.Fatal("volume-admission", e)
	}
	if _, e := statNative(f); e != nil {
		t.Fatal("volume-stat-admission", e)
	}
	r, e := OpenRoot(t.Context(), path)
	if e != nil {
		t.Fatal("fixture-root-admission", e)
	}
	defer r.Close()
}
