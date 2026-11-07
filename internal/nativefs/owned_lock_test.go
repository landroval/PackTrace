package nativefs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOwnedWriterLockExcludesIndependentOpener(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned Linux/Windows lease")
	}
	ctx := context.Background()
	d, err := OpenOwnedDirectory(ctx, filepath.Join(t.TempDir(), "state"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.WriteControl(ctx, "writer.lock", nil); err != nil {
		t.Fatal(err)
	}
	first, err := d.ReadRoot().TryOwnedLock(ctx, "writer.lock", true)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := first.Stable(ctx); err != nil {
		t.Fatal("live original lease unstable", err)
	}
	if other, err := d.ReadRoot().TryOwnedLock(ctx, "writer.lock", true); !errors.Is(err, ErrBusy) || other != nil {
		t.Fatal("second writer admitted", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Stable(ctx); !errors.Is(err, ErrClosed) {
		t.Fatal("closed lease still qualified", err)
	}
	next, err := d.ReadRoot().TryOwnedLock(ctx, "writer.lock", true)
	if err != nil {
		t.Fatal("released lease stayed busy", err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedSharedLeasesBlockExclusiveAndNeverCreate(t *testing.T) {
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
	if lease, err := d.ReadRoot().TryOwnedLock(ctx, "missing.lock", false); err == nil || lease != nil {
		t.Fatal("missing lease admitted")
	}
	if _, err := os.Lstat(filepath.Join(path, "missing.lock")); !os.IsNotExist(err) {
		t.Fatal("readonly lease initialized a file")
	}
	if err := d.WriteControl(ctx, "reader.lock", nil); err != nil {
		t.Fatal(err)
	}
	a, err := d.ReadRoot().TryOwnedLock(ctx, "reader.lock", false)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := d.ReadRoot().TryOwnedLock(ctx, "reader.lock", false)
	if err != nil {
		t.Fatal("independent shared reader refused", err)
	}
	defer b.Close()
	if x, err := d.ReadRoot().TryOwnedLock(ctx, "reader.lock", true); !errors.Is(err, ErrBusy) || x != nil {
		t.Fatal("exclusive lease ignored readers", err)
	}
}
