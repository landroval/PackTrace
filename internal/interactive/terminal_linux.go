package interactive

import (
	"errors"
	"github.com/charmbracelet/x/term"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"syscall"
)

func Available(in *os.File, out io.Writer) bool {
	f, ok := out.(*os.File)
	if !ok || in == nil || f == nil || os.Getenv("TERM") == "dumb" {
		return false
	}
	w, h, e := term.GetSize(f.Fd())
	if e != nil || w < 40 || h < 12 {
		return false
	}
	if foreground, e := unix.IoctlGetInt(int(in.Fd()), unix.TIOCGPGRP); e == nil && foreground != syscall.Getpgrp() {
		return false
	}
	var a, b syscall.Stat_t
	return syscall.Fstat(int(in.Fd()), &a) == nil && syscall.Fstat(int(f.Fd()), &b) == nil && a.Rdev == b.Rdev && a.Ino == b.Ino && term.IsTerminal(in.Fd()) && term.IsTerminal(f.Fd())
}

func Capture(in, out *os.File) (int, int, func() error, error) {
	if !Available(in, out) {
		return 0, 0, nil, errors.New("interactive terminal unavailable")
	}
	state, e := term.GetState(in.Fd())
	if e != nil {
		return 0, 0, nil, e
	}
	w, h, e := term.GetSize(out.Fd())
	if e != nil || w < 40 || h < 12 {
		return 0, 0, nil, errors.New("terminal too small")
	}
	return min(w, 180), min(h, 60), func() error { return term.Restore(in.Fd(), state) }, nil
}
