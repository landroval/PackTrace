//go:build linux

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// A short single-line spinner must not wrap on narrow terminals.
func terminalProgressWidth(file *os.File) bool {
	conn, e := file.SyscallConn()
	if e != nil {
		return false
	}
	wide := false
	e = conn.Control(func(fd uintptr) {
		var size struct{ Rows, Cols, X, Y uint16 }
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&size)))
		wide = errno == 0 && size.Cols >= 64
	})
	return e == nil && wide
}
func terminalSupportsANSI(file *os.File) bool {
	if os.Getenv("TERM") == "" {
		return false
	}
	conn, err := file.SyscallConn()
	if err != nil {
		return false
	}
	terminal := false
	err = conn.Control(func(fd uintptr) {
		var settings syscall.Termios
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&settings)))
		terminal = errno == 0
	})
	return err == nil && terminal
}
