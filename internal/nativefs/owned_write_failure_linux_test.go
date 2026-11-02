//go:build linux && (amd64 || arm64)

package nativefs

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestOwnedWriteFailureProcess(t *testing.T) {
	path := os.Getenv("PACKTRACE_TEST_WRITE_FAILURE_ROOT")
	if path == "" {
		t.Skip("private resource-bound writer")
	}
	d, e := OpenOwnedDirectory(context.Background(), path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	var limit syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_FSIZE, &limit) != nil {
		t.Fatal("own file-size bound unavailable")
	}
	limit.Cur = 1024
	signal.Ignore(syscall.SIGXFSZ)
	if syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit) != nil {
		t.Fatal("own child file-size bound failed")
	}
	f, e := d.CopyExclusive(context.Background(), "partial", bytes.NewReader(make([]byte, 4096)), 4096)
	if f == nil || !errors.Is(e, ErrWrite) || f.Size() <= 0 || f.Size() > 1024 {
		t.Fatal("native write failure lost partial bytes or became success", e)
	}
	if f.Stable() == nil {
		t.Fatal("failed write became sealed")
	}
	if e := f.Close(); e != nil {
		t.Fatal(e)
	}
}
func TestOwnedNativeWriteFailureKeepsPartialBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOwnedWriteFailureProcess$")
	cmd.Env = append(os.Environ(), "PACKTRACE_TEST_WRITE_FAILURE_ROOT="+filepath.Join(t.TempDir(), "state"))
	if out, e := cmd.CombinedOutput(); e != nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 0 {
		t.Fatal("bounded native write-failure/reap", e, string(out))
	}
}
