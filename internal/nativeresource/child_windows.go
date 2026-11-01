//go:build windows && amd64

package nativeresource

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"packtrace/internal/nativefs"
)

var ErrUnavailable = errors.New("scan: retained-resident-query-unavailable")
var queryProcessBasic = syscall.NewLazyDLL("ntdll.dll").NewProc("NtQueryInformationProcess")

// Child owns a noninheritable duplicate of the actual os.Process handle,
// captured via WithHandle BEFORE any Wait. The additional handle survives
// Wait and never opens or reopens a numeric PID. Exit
// indication is separate from the caller's confirmed Wait/reap receipt.
type Child struct {
	handle  syscall.Handle
	created uint64
}

func creationTime(h syscall.Handle) (uint64, error) {
	var created, exited, kernel, user syscall.Filetime
	if e := syscall.GetProcessTimes(h, &created, &exited, &kernel, &user); e != nil {
		return 0, queryFailure("process-times", e, 0)
	}
	n := uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	if n == 0 {
		return 0, queryFailure("process-creation", nil, 0)
	}
	return n, nil
}
func PinProcess(process *os.Process) (*Child, error) {
	if process == nil || process.Pid <= 0 || uint64(process.Pid) > 0xffffffff || queryProcessBasic.Find() != nil {
		return nil, queryFailure("pin-process", nil, 0)
	}
	owner, e := syscall.GetCurrentProcess()
	if e != nil {
		return nil, queryFailure("pin-process-owner", e, 0)
	}
	var h syscall.Handle
	var duplicateErr error
	e = process.WithHandle(func(original uintptr) {
		duplicateErr = syscall.DuplicateHandle(owner, syscall.Handle(original), owner, &h, 0, false, syscall.DUPLICATE_SAME_ACCESS)
	})
	if e != nil || duplicateErr != nil {
		if h != 0 {
			_ = syscall.CloseHandle(h)
		}
		if e == nil {
			e = duplicateErr
		}
		return nil, queryFailure("pin-process-duplicate", e, 0)
	}
	c := &Child{handle: h}
	// PROCESS_BASIC_INFORMATION's Win64 ABI is six pointer-sized slots;
	// UniqueProcessId and InheritedFromUniqueProcessId are the last two.
	var basic [6]uintptr
	var returned uint32
	status, _, _ := queryProcessBasic.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&basic[0])), unsafe.Sizeof(basic), uintptr(unsafe.Pointer(&returned)))
	runtime.KeepAlive(basic)
	if uint32(status) != 0 || returned != uint32(unsafe.Sizeof(basic)) || basic[4] != uintptr(process.Pid) || basic[5] != uintptr(os.Getpid()) {
		c.Close()
		return nil, queryFailure("pin-process-identity", nil, 0)
	}
	c.created, e = creationTime(h)
	if e != nil {
		c.Close()
		return nil, e
	}
	return c, nil
}
func (c *Child) exited() (bool, error) {
	if c == nil || c.handle == 0 {
		return false, queryFailure("capability", nil, 0)
	}
	state, e := syscall.WaitForSingleObject(c.handle, 0)
	if e != nil {
		return false, queryFailure("process-wait", e, 0)
	}
	switch state {
	case syscall.WAIT_OBJECT_0:
		return true, nil
	case syscall.WAIT_TIMEOUT:
		return false, nil
	default:
		return false, queryFailure("process-wait-state", nil, 0)
	}
}
func (c *Child) Sample() (rss uint64, live bool, failure error) {
	ended, e := c.exited()
	if e != nil || ended {
		return 0, !ended, e
	}
	defer func() {
		if failure != nil {
			if ended, e := c.exited(); e == nil && ended {
				rss, live, failure = 0, false, nil
			}
		}
	}()
	created, e := creationTime(c.handle)
	if e != nil {
		return 0, true, e
	}
	if created != c.created {
		return 0, true, queryFailure("process-identity", nil, 0)
	}
	n, e := nativefs.ResidentBytesForProcess(c.handle)
	if e != nil || n == 0 {
		return 0, true, queryFailure("process-resident", e, 0)
	}
	return n, true, nil
}
func (c *Child) Close() error {
	if c == nil || c.handle == 0 {
		return nil
	}
	h := c.handle
	c.handle = 0
	return syscall.CloseHandle(h)
}
