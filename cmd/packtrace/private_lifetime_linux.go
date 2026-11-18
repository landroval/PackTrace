package main

import (
	"errors"
	"syscall"

	"packtrace/internal/execution"
)

// Accept only an already nonblocking write-only anonymous pipe on pipefs.
// S_IFIFO alone also admits named FIFOs: the PIPEFS_MAGIC check excludes them.
// No opening, /proc lookup, flag mutation of the shared open description, or
// path/file writes. The caller must exclusively own this dedicated endpoint.
func validLifetimeFD(fd int) bool {
	if fd < 3 || fd > 1<<20 {
		return false
	}
	var s syscall.Stat_t
	var fs syscall.Statfs_t
	if syscall.Fstat(fd, &s) != nil || s.Mode&syscall.S_IFMT != syscall.S_IFIFO || syscall.Fstatfs(fd, &fs) != nil || fs.Type != 0x50495045 {
		return false
	}
	flags, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0)
	if e != 0 || flags&syscall.O_ACCMODE != syscall.O_WRONLY || flags&syscall.O_NONBLOCK == 0 {
		return false
	}
	for i := 0; i < 3; i++ {
		var std syscall.Stat_t
		if syscall.Fstat(i, &std) == nil && std.Dev == s.Dev && std.Ino == s.Ino {
			return false
		}
	}
	return true
}
func prepareLifetimeFD(fd int) bool {
	_, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, syscall.FD_CLOEXEC)
	return e == 0
}
func closeLifetimeFD(fd int) { _ = syscall.Close(fd) }
func emitLifetime(fd int, r execution.ScanReceipt, exit int) error {
	b, e := lifetimeBytes(r, exit)
	if e != nil {
		return e
	}
	// No retry, goroutine, deadline extension, partial record, or blocking fallback.
	n, e := syscall.Write(fd, b)
	if e != nil {
		return e
	}
	if n != len(b) {
		return errors.New("private receipt short write")
	}
	return nil
}
