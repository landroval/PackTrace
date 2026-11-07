//go:build linux && (amd64 || arm64)

package nativefs

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestDurabilityDirectoryFlushFailureCannotFence(t *testing.T) {
	ctx := context.Background()
	owner, e := OpenOwnedDirectory(ctx, filepath.Join(t.TempDir(), "owned"), true)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	if e := owner.WriteControl(ctx, "writer.lock", nil); e != nil {
		t.Fatal(e)
	}
	writer, e := owner.ReadRoot().TryOwnedLock(ctx, "writer.lock", true)
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	b, e := owner.BeginDurabilityBatch(ctx, writer)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	f, e := b.CopyExclusive(ctx, "original", bytes.NewReader([]byte("actual")), 6)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	// Retain the SAME actual directory as an O_PATH observation. Identity, owner,
	// mode and binding still pass, but fsync must positively fail with EBADF. This
	// tests the namespace barrier itself, not a pre-flush stat rejection.
	n, unlock, e := owner.root.lockNative()
	if e != nil {
		t.Fatal(e)
	}
	selected, e := n.captureMetadata(".")
	unlock()
	if e != nil {
		t.Fatal(e)
	}
	b.dirs["."].file.Close()
	b.dirs["."].file = selected.handle
	if e := b.Fence(ctx); !errors.Is(e, ErrWrite) {
		t.Fatal("directory persistence failure was not fatal", e)
	}
	if e := b.Fence(ctx); !errors.Is(e, ErrWrite) {
		t.Fatal("directory failure not sticky", e)
	}
}
