package nativefs

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// These tests fail if owned creation follows a link, adopts an existing root,
// changes a caller file, or mistakes copied marker bytes for native identity.
func TestOwnedDirectoryExclusiveRootAndControl(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned Linux/Windows capability")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "owned")
	d, err := OpenOwnedDirectory(ctx, path, true)
	if err != nil {
		t.Fatal("create owned directory", err)
	}
	defer d.Close()
	if _, err := OpenOwnedDirectory(ctx, path, true); err == nil {
		t.Fatal("exclusive constructor adopted existing directory")
	}
	id, err := d.ReadRoot().OwnedIdentity(ctx)
	if err != nil || id == ([32]byte{}) {
		t.Fatal("native owned identity unavailable", err)
	}
	if err := d.WriteControl(ctx, "marker.json", []byte("owned")); err != nil {
		t.Fatal("write bounded control", err)
	}
	if err := d.WriteControl(ctx, "marker.json", []byte("changed")); err == nil {
		t.Fatal("control writer overwrote existing bytes")
	}
	f, err := d.ReadRoot().OpenInput(ctx, "marker.json", 4096)
	if err != nil {
		t.Fatal("open original control", err)
	}
	data, err := io.ReadAll(f)
	closeErr := f.Close()
	if err != nil || closeErr != nil || string(data) != "owned" {
		t.Fatal("control bytes or stable close", err, closeErr)
	}
	after, err := d.ReadRoot().OwnedIdentity(ctx)
	if err != nil || after != id {
		t.Fatal("own control creation changed root identity", err)
	}
}

func TestOwnedDirectoryRefusesTraversalAndClosedRoot(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned Linux/Windows capability")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "owned")
	d, err := OpenOwnedDirectory(ctx, path, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../outside", "a/b", "a\\b", ".", "", "CON"} {
		if err := d.WriteControl(ctx, name, []byte("bad")); err == nil {
			t.Fatal("unsafe control name admitted")
		}
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.WriteControl(ctx, "after-close", []byte("bad")); !errors.Is(err, ErrClosed) {
		t.Fatal("closed writer admitted", err)
	}
	if _, err := d.ReadRoot().OwnedIdentity(ctx); err == nil {
		t.Fatal("closed root admitted identity")
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatal("refused writes changed directory")
	}
}
