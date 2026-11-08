//go:build linux

package main

import (
	"os"
	"syscall"
	"unsafe"
)

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
