//go:build linux && (amd64 || arm64)

package nativeresource

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRetainedChildActualRSSIdentityExitAndQueryFailure(t *testing.T) {
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
	cmd.Stdin, cmd.Stdout = input, output
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	// Pin before any Wait. No user-chosen process or target path is queried.
	c, e := PinChild(cmd.Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = read.SetReadDeadline(time.Now().Add(3 * time.Second))
	var ready [1]byte
	if _, e = io.ReadFull(read, ready[:]); e != nil || ready[0] != 'R' {
		t.Fatal(e, ready)
	}
	fdName := strconv.FormatUint(uint64(c.pidfd.Fd()), 10)
	fdKind, e := os.Readlink("/proc/self/fd/" + fdName)
	info, infoErr := os.ReadFile("/proc/self/fdinfo/" + fdName)
	if e != nil || infoErr != nil || fdKind != "anon_inode:[pidfd]" || !strings.Contains(string(info), "Pid:\t"+strconv.Itoa(cmd.Process.Pid)+"\n") {
		t.Fatal("retained descriptor not bound to actual child", fdKind, string(info), e, infoErr)
	}
	t.Logf("actual retained kernel descriptor kind=%s fdinfo=%q", fdKind, info)
	before, live, e := c.Sample()
	if e != nil || !live || before == 0 {
		t.Fatal(before, live, e)
	}
	_, _ = feed.Write([]byte("A"))
	if _, e = io.ReadFull(read, ready[:]); e != nil || ready[0] != 'A' {
		t.Fatal(e, ready)
	}
	after, live, e := c.Sample()
	if e != nil || !live || after < before+24<<20 {
		t.Fatalf("actual resident growth absent: before=%d after=%d live=%v err=%v", before, after, live, e)
	}
	start := c.start
	c.start = "wrong-creation-identity"
	if n, live, e := c.Sample(); e == nil || n != 0 || !live {
		t.Fatal("identity mismatch became RSS success", n, live, e)
	}
	c.start = start
	if e := c.proc.Close(); e != nil {
		t.Fatal(e)
	}
	if n, live, e := c.Sample(); e == nil || n != 0 || !live {
		t.Fatal("live query failure became zero success", n, live, e)
	} else {
		var failure *QueryFailure
		if !errors.Is(e, ErrUnavailable) || !errors.As(e, &failure) || failure.Stage != "stat-open" || failure.Errno != int(syscall.EBADF) || e.Error() != ErrUnavailable.Error() {
			t.Fatalf("closed owned descriptor lost bounded kernel diagnosis: %#v %v", failure, e)
		}
	}
	// Release only the original child and confirm its exit/reap. A retained
	// pidfd is still attributable even when its proc descriptor cannot be read.
	_ = feed.Close()
	if e := cmd.Wait(); e != nil {
		t.Fatal(e)
	}
	waited = true
	if n, live, e := c.Sample(); e != nil || live || n != 0 {
		t.Fatal("confirmed exit misreported as live RSS", n, live, e)
	}
	if other, e := PinChild(os.Getpid()); e == nil {
		other.Close()
		t.Fatal("non-child process admitted")
	}
	t.Logf("actual child pid=%d creation=%s resident-before=%d resident-after=%d exit=%v", cmd.Process.Pid, start, before, after, cmd.ProcessState)
}
