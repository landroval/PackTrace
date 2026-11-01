//go:build windows && amd64

package nativeresource

import (
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// Native Windows contracts. Cross-compilation is not execution of this test.
func TestWindowsRetainedChildIdentityMemoryExitAndFailure(t *testing.T) {
	in, feed, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer in.Close()
	defer feed.Close()
	read, out, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer read.Close()
	defer out.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestOwnedResidentChildEntry$")
	cmd.Env = append(os.Environ(), "PACKTRACE_TEST_RSS_CHILD=1")
	cmd.Stdin, cmd.Stdout = in, out
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	child, e := PinProcess(cmd.Process)
	if e != nil {
		t.Fatal(e)
	}
	defer child.Close()
	_ = read.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ready [1]byte
	if _, e = io.ReadFull(read, ready[:]); e != nil || ready[0] != 'R' {
		t.Fatal(e, ready)
	}
	before, live, e := child.Sample()
	if e != nil || !live || before == 0 {
		t.Fatal(before, live, e)
	}
	if _, e = feed.Write([]byte{'A'}); e != nil {
		t.Fatal(e)
	}
	if _, e = io.ReadFull(read, ready[:]); e != nil || ready[0] != 'A' {
		t.Fatal(e, ready)
	}
	after, live, e := child.Sample()
	if e != nil || !live || after < before+24<<20 {
		t.Fatal("resident growth", before, after, live, e)
	}
	self, e := os.FindProcess(os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	defer self.Release()
	if other, e := PinProcess(self); e == nil {
		other.Close()
		t.Fatal("non-child admitted")
	}
	_ = feed.Close()
	if e = cmd.Wait(); e != nil {
		t.Fatal(e)
	}
	waited = true
	if other, e := PinProcess(cmd.Process); e == nil {
		other.Close()
		t.Fatal("new capture after Wait admitted")
	}
	if n, live, e := child.Sample(); e != nil || live || n != 0 {
		t.Fatal("retained handle after reap", n, live, e)
	}
	child.Close()
	if n, _, e := child.Sample(); e == nil || n != 0 {
		t.Fatal("closed capability admitted", n, e)
	}
}

func TestWindowsRetainedChildRejectsClosedLiveHandle(t *testing.T) {
	in, feed, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer in.Close()
	defer feed.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestOwnedResidentChildEntry$")
	cmd.Env = append(os.Environ(), "PACKTRACE_TEST_RSS_CHILD=1")
	cmd.Stdin = in
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	child, e := PinProcess(cmd.Process)
	if e != nil {
		t.Fatal(e)
	}
	// Destroy only this observer's handle; the actual child remains alive and
	// held by os.Process. The unavailable observation must not become zero RSS.
	if e = syscall.CloseHandle(child.handle); e != nil {
		t.Fatal(e)
	}
	if n, _, e := child.Sample(); e == nil || n != 0 {
		t.Fatal("lost live capability became success", n, e)
	}
	child.handle = 0
}
