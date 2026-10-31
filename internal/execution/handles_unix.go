//go:build linux || darwin

package execution

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// NewFile preserves an already nonblocking descriptor's flags (unlike passing
// the caller's os.Pipe File through Fd). No parent read or mode change occurs.
func inheritFiles(cmd *exec.Cmd, files ...*os.File) ([]string, func(), error) {
	var owned []*os.File
	closeOwned := func() {
		for _, f := range owned {
			_ = f.Close()
		}
	}
	var ids []string
	for _, f := range files {
		raw, e := f.SyscallConn()
		if e != nil {
			closeOwned()
			return nil, nil, errProtocol
		}
		fd := -1
		var inner error
		e = raw.Control(func(source uintptr) {
			fd, inner = syscall.Dup(int(source))
			if inner == nil {
				syscall.CloseOnExec(fd)
			}
		})
		if e != nil || inner != nil {
			closeOwned()
			return nil, nil, errProtocol
		}
		dup := os.NewFile(uintptr(fd), "inspect-batch-inherited")
		owned = append(owned, dup)
		ids = append(ids, strconv.Itoa(3+len(cmd.ExtraFiles)))
		cmd.ExtraFiles = append(cmd.ExtraFiles, dup)
	}
	return ids, closeOwned, nil
}

func validLaunchHandles(ids []uintptr) bool {
	for i, id := range ids {
		if id != uintptr(3+i) {
			return false
		}
	}
	return true
}
