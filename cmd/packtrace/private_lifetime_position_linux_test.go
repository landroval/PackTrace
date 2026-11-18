package main

import (
	"bytes"
	"fmt"
	"syscall"
	"testing"
)

func TestPrivateLifetimeNonOptionLeavesPipeUntouched(t *testing.T) {
	for _, name := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"} {
		t.Setenv(name, t.TempDir())
	}
	for _, position := range []string{"literal", "option-value", "attached-value", "after-operand", "later-option"} {
		t.Run(position, func(t *testing.T) {
			r, w := privatePipe(t)
			fd := int(w.Fd())
			literal := fmt.Sprintf("--private-lifetime-fd=%d", fd)
			args := map[string][]string{
				"literal":        {"scan", "--", literal},
				"option-value":   {"scan", "--policy", literal},
				"attached-value": {"scan", "--policy=" + literal},
				"after-operand":  {"scan", "operand", literal},
				"later-option":   {"scan", "--verbose", literal},
			}[position]
			flags := func() uintptr {
				t.Helper()
				n, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
				if e != 0 {
					t.Fatal(e)
				}
				return n
			}
			before := flags()
			var wantOut, wantDiag, out, diag bytes.Buffer
			want := runMainObserved(args, forbiddenReader{}, &wantOut, &wantDiag, nil)
			got := runMain(args, forbiddenReader{}, &out, &diag)
			if got != want || !bytes.Equal(out.Bytes(), wantOut.Bytes()) || !bytes.Equal(diag.Bytes(), wantDiag.Bytes()) {
				t.Fatalf("changed ordinary parsing: exit %d/%d out %q/%q diagnostic %q/%q", got, want, out.Bytes(), wantOut.Bytes(), diag.Bytes(), wantDiag.Bytes())
			}
			if flags() != before || !validLifetimeFD(fd) {
				t.Fatal("changed unowned descriptor")
			}
			rfd := int(r.Fd())
			if e := syscall.SetNonblock(rfd, true); e != nil {
				t.Fatal(e)
			}
			var b [1]byte
			if n, e := syscall.Read(rfd, b[:]); n != -1 || e != syscall.EAGAIN {
				t.Fatalf("wrote to unowned pipe: %d %v", n, e)
			}
			if n, e := syscall.Write(fd, []byte{'x'}); n != 1 || e != nil {
				t.Fatalf("closed unowned pipe: %d %v", n, e)
			}
		})
	}
}

func TestPrivateLifetimeFirstOptionOwnership(t *testing.T) {
	for _, valid := range []bool{false, true} {
		t.Run(fmt.Sprint(valid), func(t *testing.T) {
			_, w := privatePipe(t)
			fd := int(w.Fd())
			if !valid {
				if e := syscall.SetNonblock(fd, false); e != nil {
					t.Fatal(e)
				}
			}
			var out, diag bytes.Buffer
			if code := runMain([]string{"scan", fmt.Sprintf("--private-lifetime-fd=%d", fd)}, forbiddenReader{}, &out, &diag); code != 2 {
				t.Fatal(code)
			}
			_, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
			if valid && e != syscall.EBADF {
				t.Fatalf("owned endpoint not closed: %v", e)
			}
			if !valid && e != 0 {
				t.Fatalf("unowned endpoint closed: %v", e)
			}
		})
	}
}
