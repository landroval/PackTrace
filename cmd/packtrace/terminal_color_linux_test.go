//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"testing"
	"unsafe"
)

func ownedColorPTY(t *testing.T) *os.File {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal("owned PTY unavailable", err)
	}
	t.Cleanup(func() { master.Close() })
	var unlock, number uint32
	conn, err := master.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var errno syscall.Errno
	err = conn.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock)))
		if errno == 0 {
			_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCGPTN, uintptr(unsafe.Pointer(&number)))
		}
	})
	if err != nil || errno != 0 {
		t.Fatal("PTY setup", err, errno)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	return slave
}

func TestScanTerminalColorSelection(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "restore-original-after-test")
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatal(err)
	}
	tty := ownedColorPTY(t)
	if got := scanTerminalFormat("terminal", "-", tty); got != "terminal-color" {
		t.Fatal("real terminal not styled", got)
	}
	for _, format := range []string{"json", "sarif", "terminal-verbose"} {
		if got := scanTerminalFormat(format, "-", tty); got != format {
			t.Fatal("color contaminated another format", got)
		}
	}
	if got := scanTerminalFormat("terminal", "report.txt", tty); got != "terminal" {
		t.Fatal("file output styled")
	}
	var buffer bytes.Buffer
	if scanTerminalFormat("terminal", "-", &buffer) != "terminal" {
		t.Fatal("arbitrary writer styled")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if scanTerminalFormat("terminal", "-", w) != "terminal" {
		t.Fatal("pipe styled")
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	if scanTerminalFormat("terminal", "-", devNull) != "terminal" {
		t.Fatal("character device was mistaken for a terminal")
	}
	t.Setenv("NO_COLOR", "")
	if scanTerminalFormat("terminal", "-", tty) != "terminal" {
		t.Fatal("empty NO_COLOR did not opt out")
	}
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TERM", "dumb")
	if scanTerminalFormat("terminal", "-", tty) != "terminal" {
		t.Fatal("dumb terminal styled")
	}
}
