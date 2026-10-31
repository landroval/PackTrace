//go:build windows

package nativefs

import (
	"syscall"
	"unsafe"
)

// PROCESS_MEMORY_COUNTERS from the Windows SDK/psapi.h. WorkingSetSize is
// resident working-set bytes, not PagefileUsage (commit) or PeakWorkingSetSize.
// Pointer-sized fields preserve the documented Win64 layout without cgo.
type processMemoryCounters struct {
	cb, pageFaultCount                                 uint32
	peakWorkingSetSize, workingSetSize                 uintptr
	quotaPeakPagedPoolUsage, quotaPagedPoolUsage       uintptr
	quotaPeakNonPagedPoolUsage, quotaNonPagedPoolUsage uintptr
	pagefileUsage, peakPagefileUsage                   uintptr
}

var ownMemoryInfo = syscall.NewLazyDLL("kernel32.dll").NewProc("K32GetProcessMemoryInfo")

func OwnResidentBytes() (uint64, error) {
	if ownMemoryInfo.Find() != nil {
		return 0, ErrUnavailable
	}
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, ErrUnavailable
	}
	var c processMemoryCounters
	c.cb = uint32(unsafe.Sizeof(c))
	ok, _, _ := ownMemoryInfo.Call(uintptr(process), uintptr(unsafe.Pointer(&c)), uintptr(c.cb))
	if ok == 0 || c.workingSetSize == 0 {
		return 0, ErrUnavailable
	}
	return uint64(c.workingSetSize), nil
}
