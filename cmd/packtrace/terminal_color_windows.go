//go:build windows

package main

import (
	"os"
	"syscall"
)

func terminalSupportsANSI(file *os.File) bool {
	conn, err := file.SyscallConn()
	if err != nil {
		return false
	}
	terminal := false
	err = conn.Control(func(fd uintptr) {
		var mode uint32
		// Read-only capability check: never change the user's console mode.
		terminal = syscall.GetConsoleMode(syscall.Handle(fd), &mode) == nil && mode&0x4 != 0
	})
	return err == nil && terminal
}
