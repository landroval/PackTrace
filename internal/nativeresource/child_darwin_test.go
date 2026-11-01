//go:build darwin && cgo && (amd64 || arm64)

package nativeresource

import (
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestDarwinRetainedChildMemoryIdentityExitAndQueryFailure(t *testing.T) {
	input, feed, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer input.Close()
	defer feed.Close()
	read, output, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer read.Close()
	defer output.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestOwnedResidentChildEntry$")
	cmd.Env = append(os.Environ(), "PACKTRACE_TEST_RSS_CHILD=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = input, output, os.Stderr
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	waited := false
	defer func() {
		if !waited {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	c, e := PinChild(cmd.Process.Pid)
	if e != nil {
		t.Fatalf("native retained child: %#v", e)
	}
	defer c.Close()
	read.SetReadDeadline(time.Now().Add(5 * time.Second))
	var b [1]byte
	if _, e := io.ReadFull(read, b[:]); e != nil || b[0] != 'R' {
		t.Fatal(e, b)
	}
	before, live, e := c.Sample()
	if e != nil || !live || before == 0 {
		t.Fatalf("native sample: n=%d live=%t err=%#v", before, live, e)
	}
	if _, e := feed.Write([]byte("A")); e != nil {
		t.Fatal(e)
	}
	if _, e := io.ReadFull(read, b[:]); e != nil || b[0] != 'A' {
		t.Fatal(e, b)
	}
	after, live, e := c.Sample()
	if e != nil || !live || after < before+24<<20 {
		t.Fatalf("resident growth: before=%d after=%d live=%t err=%#v", before, after, live, e)
	}
	original := c.port
	c.port = 0
	n, live, queryErr := c.Sample()
	c.port = original
	if queryErr == nil || !live || n != 0 {
		t.Fatal("live failed Mach query became success", n, live, queryErr)
	}
	if other, e := PinChild(os.Getpid()); e == nil {
		other.Close()
		t.Fatal("non-child admitted")
	}
	feed.Close()
	if e := cmd.Wait(); e != nil {
		t.Fatal(e)
	}
	waited = true
	if n, live, e := c.Sample(); e != nil || live || n != 0 {
		t.Fatalf("retained exit: n=%d live=%t err=%#v", n, live, e)
	}
	if c.createdSec == 0 || c.pid != cmd.Process.Pid {
		t.Fatal("missing original identity")
	}
}
