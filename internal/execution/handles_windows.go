//go:build windows

package execution

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// Only owned inheritable duplicates enter Go's explicit HANDLE_LIST. Standard
// control handles are separately whitelisted by os/exec. Never change, close,
// cancel or try to make the caller's synchronous handle pollable in the parent.
func inheritFiles(cmd *exec.Cmd, files ...*os.File) ([]string, func(), error) {
	process, e := syscall.GetCurrentProcess()
	if e != nil {
		return nil, nil, errProtocol
	}
	var owned []syscall.Handle
	closeOwned := func() {
		for _, h := range owned {
			_ = syscall.CloseHandle(h)
		}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	var ids []string
	for _, f := range files {
		raw, e := f.SyscallConn()
		if e != nil {
			closeOwned()
			return nil, nil, errProtocol
		}
		var h syscall.Handle
		var inner error
		e = raw.Control(func(source uintptr) {
			inner = syscall.DuplicateHandle(process, syscall.Handle(source), process, &h, 0, true, syscall.DUPLICATE_SAME_ACCESS)
		})
		if e != nil || inner != nil {
			closeOwned()
			return nil, nil, errProtocol
		}
		owned = append(owned, h)
		cmd.SysProcAttr.AdditionalInheritedHandles = append(cmd.SysProcAttr.AdditionalInheritedHandles, h)
		ids = append(ids, strconv.FormatUint(uint64(h), 10))
	}
	return ids, closeOwned, nil
}

func validLaunchHandles(ids []uintptr) bool {
	for _, id := range ids {
		if id == 0 || id == ^uintptr(0) {
			return false
		}
	}
	return len(ids) < 2 || ids[0] != ids[1]
}
