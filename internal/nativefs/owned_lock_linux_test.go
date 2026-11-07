//go:build linux && (amd64 || arm64)

package nativefs

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestOwnedLeaseCloseUnlocksInheritedOpenDescription(t *testing.T) {
	ctx := context.Background()
	d, err := OpenOwnedDirectory(ctx, filepath.Join(t.TempDir(), "state"), true)
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
	fd, err := syscall.Dup(int(lease.file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	inherited := os.NewFile(uintptr(fd), "test-inherited-lease")
	defer inherited.Close()
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := d.ReadRoot().TryOwnedLock(ctx, "writer.lock", true)
	if err != nil {
		t.Fatal("original close left transient inherited OFD holding lock", err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
}
