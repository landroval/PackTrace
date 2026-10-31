//go:build windows

package execution

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// This is a native CONTRACT test. Cross-builds compile it but do not execute
// the Windows constructor, qualify its security, or establish native timing.
func TestWindowsPrivatePipeCancelableContract(t *testing.T) {
	r, w, e := privatePipe()
	if e != nil {
		t.Fatal("required cancelable private pipe unavailable", e)
	}
	defer r.Close()
	defer w.Close()
	if e = r.SetReadDeadline(time.Now().Add(time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	var b [1]byte
	if _, e = r.Read(b[:]); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal("private read deadline not enforced", e)
	}
}
func TestWindowsOwnedDuplicateWhitelist(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "inherited")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	cmd := exec.CommandContext(context.Background(), os.Args[0], WorkerArgument)
	ids, release, e := inheritFiles(cmd, f)
	if e != nil {
		t.Fatal(e)
	}
	if len(ids) != 1 || cmd.SysProcAttr == nil || len(cmd.SysProcAttr.AdditionalInheritedHandles) != 1 {
		release()
		t.Fatal("missing explicit whitelist")
	}
	owned := cmd.SysProcAttr.AdditionalInheritedHandles[0]
	if owned == syscall.Handle(f.Fd()) {
		release()
		t.Fatal("caller handle inherited rather than owned duplicate")
	}
	release()
	if _, e = f.Stat(); e != nil {
		t.Fatal("caller closed by duplicate release", e)
	}
}
