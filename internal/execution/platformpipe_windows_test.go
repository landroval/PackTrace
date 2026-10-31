//go:build windows

package execution

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// Native-only assertions below are COMPILED, NOT EXECUTED on Linux.
func TestWindowsPrivatePipeSecurityAndOwnership(t *testing.T) {
	r, w, err := privatePipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	kernel, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		t.Fatal(err)
	}
	defer kernel.Release()
	getFlags, err := kernel.FindProc("GetHandleInformation")
	if err != nil {
		t.Fatal(err)
	}
	security, err := syscall.LoadDLL("advapi32.dll")
	if err != nil {
		t.Fatal(err)
	}
	defer security.Release()
	getSecurity, err := security.FindProc("GetSecurityInfo")
	if err != nil {
		t.Fatal(err)
	}
	getControl, err := security.FindProc("GetSecurityDescriptorControl")
	if err != nil {
		t.Fatal(err)
	}
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	wantSID, err := user.User.Sid.String()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []*os.File{r, w} {
		raw, err := f.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var handle syscall.Handle
		var flags uint32
		var ok uintptr
		var inner error
		if err := raw.Control(func(h uintptr) {
			handle = syscall.Handle(h)
			ok, _, inner = getFlags.Call(h, uintptr(unsafe.Pointer(&flags)))
		}); err != nil || ok == 0 || flags&1 != 0 {
			t.Fatal("private handle is inheritable or unavailable", err, inner, flags)
		}
		if f == r {
			// READ_CONTROL is present on the server handle. GetSecurityInfo's
			// descriptor owns both returned SID/ACL pointers until LocalFree.
			var owner *syscall.SID
			var dacl, descriptor unsafe.Pointer
			status, _, _ := getSecurity.Call(uintptr(handle), 1, 5, uintptr(unsafe.Pointer(&owner)), 0, uintptr(unsafe.Pointer(&dacl)), 0, uintptr(unsafe.Pointer(&descriptor)))
			if status != 0 {
				t.Fatal("cannot inspect new pipe owner/DACL", status)
			}
			func() {
				defer syscall.LocalFree(syscall.Handle(uintptr(descriptor)))
				if owner == nil || dacl == nil {
					t.Fatal("missing explicit owner/DACL")
				}
				gotSID, err := owner.String()
				if err != nil || gotSID != wantSID {
					t.Fatal("pipe owner is not process user", gotSID, err)
				}
				var control uint16
				var revision uint32
				ok, _, inner := getControl.Call(uintptr(descriptor), uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&revision)))
				if ok == 0 || control&0x1004 != 0x1004 { // DACL_PRESENT | DACL_PROTECTED
					t.Fatal("DACL missing/unprotected", control, inner)
				}
				acl := (*struct {
					Revision, Reserved byte
					Size, Count, Pad   uint16
				})(dacl)
				if acl.Count != 1 || acl.Size < 16 {
					t.Fatal("expected exactly one explicit user ACE", acl.Count, acl.Size)
				}
				ace := unsafe.Add(dacl, 8)
				if *(*byte)(ace) != 0 || *(*byte)(unsafe.Add(ace, 1)) != 0 {
					t.Fatal("expected noninheriting ACCESS_ALLOWED_ACE")
				}
				aceSize := *(*uint16)(unsafe.Add(ace, 2))
				if aceSize < 16 || uint32(aceSize)+8 > uint32(acl.Size) {
					t.Fatal("invalid user ACE size", aceSize)
				}
				gotSID, err = (*syscall.SID)(unsafe.Add(ace, 8)).String()
				if err != nil || gotSID != wantSID {
					t.Fatal("DACL grants a different principal", gotSID, err)
				}
			}()
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := syscall.GetFileType(handle); !errors.Is(err, syscall.Errno(6)) { // ERROR_INVALID_HANDLE
			t.Fatal("os.File did not close its owned native handle", err)
		}
	}
}

func TestWindowsChildControlRejectsClosedOrSynchronousHandle(t *testing.T) {
	for _, closed := range []bool{false, true} {
		r, w, err := os.Pipe() // Windows stdlib CreatePipe is synchronous.
		if err != nil {
			t.Fatal(err)
		}
		if closed {
			r.Close()
		}
		prepared, release, err := platformControlInput(r)
		if release != nil {
			release()
		}
		if err == nil || prepared != nil {
			t.Error("unusable private control input accepted", closed)
		}
		if !closed {
			if _, err := r.Stat(); err != nil {
				t.Error("caller handle closed", err)
			}
		}
		r.Close()
		w.Close()
	}
}

// This catches constructor/stdlib incompatibility at the actual inherited
// stdin/stdout boundary, not just successful privatePipe deadline setup.
func TestWindowsPrivatePipeInheritedStdio(t *testing.T) {
	if os.Getenv("PACKTRACE_PIPE_CONTRACT_CHILD") == "1" {
		control, release, err := platformControlInput(os.Stdin)
		if err != nil {
			os.Exit(80)
		}
		// Exercise the production adapter's fresh handle, not a replacement
		// blocking wrapper which recreates the exact-stdin exception.
		var same bool
		raw, err := control.(*os.File).SyscallConn()
		if err != nil || raw.Control(func(h uintptr) { same = syscall.Handle(h) == syscall.Stdin }) != nil || same {
			os.Exit(83)
		}
		var b [1]byte
		if _, err := io.ReadFull(control, b[:]); err != nil {
			os.Exit(81)
		}
		release()
		if _, err := os.Stdin.Stat(); err != nil {
			os.Exit(84)
		}
		if _, err := os.Stdout.Write(b[:]); err != nil {
			os.Exit(82)
		}
		os.Exit(0)
	}
	childIn, parentIn, err := privatePipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { childIn.Close(); parentIn.Close() })
	parentOut, childOut, err := privatePipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { parentOut.Close(); childOut.Close() })
	cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsPrivatePipeInheritedStdio$")
	cmd.Env = append(os.Environ(), "PACKTRACE_PIPE_CONTRACT_CHILD=1")
	cmd.Stdin, cmd.Stdout = childIn, childOut
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	childIn.Close()
	childOut.Close()
	// Bound/join even a child that cannot read its inherited overlapped stdin.
	watchdog := time.AfterFunc(5*time.Second, func() { cmd.Process.Kill() })
	defer watchdog.Stop()
	writeErr := parentIn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	readErr := parentOut.SetReadDeadline(time.Now().Add(5 * time.Second))
	if writeErr != nil || readErr != nil {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatal("inherited parent deadlines unavailable", writeErr, readErr)
	}
	time.Sleep(50 * time.Millisecond)
	_, writeErr = parentIn.Write([]byte{42})
	parentIn.Close()
	var b [1]byte
	_, readErr = io.ReadFull(parentOut, b[:])
	waitErr := cmd.Wait()
	if writeErr != nil || readErr != nil || waitErr != nil || b[0] != 42 {
		t.Fatalf("inherited private stdio: write=%v read=%v wait=%v byte=%d stderr=%q", writeErr, readErr, waitErr, b[0], stderr.String())
	}
}
