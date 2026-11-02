package nativefs

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestOwnedLeaseProcessHelper(t *testing.T) {
	path := os.Getenv("PACKTRACE_TEST_OWNED_LOCK_PATH")
	if path == "" {
		t.Skip("private owned lease process")
	}
	ctx := context.Background()
	d, err := OpenOwnedDirectory(ctx, path, false)
	if err != nil {
		t.Fatal("child original-root open failed", err)
	}
	defer d.Close()
	lease, err := d.ReadRoot().TryOwnedLock(ctx, "writer.lock", true)
	if os.Getenv("PACKTRACE_TEST_OWNED_LOCK_EXPECT_BUSY") == "1" {
		if !errors.Is(err, ErrBusy) || lease != nil {
			t.Fatal("child did not observe live kernel owner", err)
		}
		return
	}
	if err != nil || lease == nil {
		t.Fatal("child could not acquire released lease", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedWriterLockExcludesActualChildAndReleases(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned Linux/Windows lease")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state")
	d, err := OpenOwnedDirectory(ctx, path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.WriteControl(ctx, "writer.lock", nil); err != nil {
		t.Fatal(err)
	}
	lease, err := d.ReadRoot().TryOwnedLock(ctx, "writer.lock", true)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	for _, busy := range []bool{true, false} {
		if !busy {
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		}
		childCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		cmd := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestOwnedLeaseProcessHelper$")
		want := "0"
		if busy {
			want = "1"
		}
		cmd.Env = append(os.Environ(), "PACKTRACE_TEST_OWNED_LOCK_PATH="+path, "PACKTRACE_TEST_OWNED_LOCK_EXPECT_BUSY="+want)
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil || cmd.ProcessState == nil || !cmd.ProcessState.Exited() || cmd.ProcessState.ExitCode() != 0 {
			t.Fatal("actual child lease/reap check failed", err, string(out))
		}
	}
}
