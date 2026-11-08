//go:build linux

package main

import (
	"bytes"
	"os"
	"syscall"
	"testing"
	"unsafe"

	"packtrace/internal/cli"
)

func TestIntelProgressOnlyForSupportedTerminalOperations(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "restore")
	os.Unsetenv("NO_COLOR")
	tty := ownedColorPTY(t)
	width := func(cols uint16) {
		t.Helper()
		c, e := tty.SyscallConn()
		if e != nil {
			t.Fatal(e)
		}
		var errno syscall.Errno
		e = c.Control(func(fd uintptr) {
			size := struct{ Rows, Cols, X, Y uint16 }{24, cols, 0, 0}
			_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(&size)))
		})
		if e != nil || errno != 0 {
			t.Fatal(e, errno)
		}
	}
	width(80)
	req := cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelSync, Format: "terminal"}
	for _, action := range []cli.ArgumentAction{cli.ArgumentActionIntelSync, cli.ArgumentActionIntelImport, cli.ArgumentActionIntelExport} {
		req.Action = action
		if intelProgressOutput(req, tty) != tty {
			t.Fatal("missing automatic spinner", action)
		}
	}
	req.Action = cli.ArgumentActionIntelStatus
	if intelProgressOutput(req, tty) != nil {
		t.Fatal("unnecessary status spinner")
	}
	req.Action = cli.ArgumentActionIntelSync
	req.Format = "json"
	if intelProgressOutput(req, tty) != nil {
		t.Fatal("machine spinner")
	}
	req.Format = "terminal"
	var b bytes.Buffer
	if intelProgressOutput(req, &b) != nil {
		t.Fatal("buffer spinner")
	}
	width(40)
	if intelProgressOutput(req, tty) != nil {
		t.Fatal("narrow spinner")
	}
	width(80)
	t.Setenv("NO_COLOR", "")
	if intelProgressOutput(req, tty) != nil {
		t.Fatal("empty NO_COLOR ignored")
	}
	os.Unsetenv("NO_COLOR")
	t.Setenv("TERM", "dumb")
	if intelProgressOutput(req, tty) != nil {
		t.Fatal("dumb spinner")
	}
	for _, args := range [][]string{{"scan", "--interactive", "owned"}, {"intel", "sync", "--interactive"}} {
		if _, e := cli.ParseArgs(args); e == nil {
			t.Fatal("rejected interactive mode remains", args)
		}
	}
}
