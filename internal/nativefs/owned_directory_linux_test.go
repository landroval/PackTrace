//go:build linux && (amd64 || arm64)

package nativefs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOwnedDirectoryRejectsLinkComponentsBeforeMutation(t *testing.T) {
	ctx := context.Background()
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	alias := filepath.Join(parent, "alias")
	inner := filepath.Join(real, "inner")
	if os.Mkdir(real, 0700) != nil || os.Mkdir(inner, 0700) != nil || os.Symlink(real, alias) != nil {
		t.Fatal("owned alias fixture")
	}
	// The link is an INTERMEDIATE component. The ordinary read constructor's
	// final-component O_NOFOLLOW alone must not make this test pass.
	if d, err := OpenOwnedDirectory(ctx, filepath.Join(alias, "inner", "new"), true); err == nil || d != nil {
		if d != nil {
			d.Close()
		}
		t.Fatal("writable constructor followed ancestor link")
	}
	entries, err := os.ReadDir(inner)
	if err != nil || len(entries) != 0 {
		t.Fatal("rejected alias created state")
	}
	d, err := OpenOwnedDirectory(ctx, filepath.Join(inner, "new"), true)
	if err != nil {
		t.Fatal("equivalent literal path failed", err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedDirectoryRejectsPermissionsAndMoveReturn(t *testing.T) {
	ctx := context.Background()
	parent := t.TempDir()
	root := filepath.Join(parent, "state")
	d, err := OpenOwnedDirectory(ctx, root, true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := os.Rename(root, filepath.Join(parent, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(parent, "moved"), root); err != nil {
		t.Fatal(err)
	}
	if err := d.WriteControl(ctx, "late.json", []byte("bad")); err == nil {
		t.Fatal("move-and-return refreshed original authority")
	}
	if _, err := os.Stat(filepath.Join(root, "late.json")); !os.IsNotExist(err) {
		t.Fatal("invalidated writer created content")
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if d, err := OpenOwnedDirectory(ctx, root, false); err == nil || d != nil {
		t.Fatal("shared root admitted as private owned state")
	}
}

func TestOwnedDirectoryRejectsAncestorMoveReturn(t *testing.T) {
	ctx := context.Background()
	grand := t.TempDir()
	parent := filepath.Join(grand, "parent")
	if os.Mkdir(parent, 0700) != nil {
		t.Fatal("owned parent fixture")
	}
	d, err := OpenOwnedDirectory(ctx, filepath.Join(parent, "state"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	moved := filepath.Join(grand, "moved")
	if os.Rename(parent, moved) != nil || os.Rename(moved, parent) != nil {
		t.Fatal("owned ancestor move fixture")
	}
	if _, err := d.ReadRoot().OwnedIdentity(ctx); err == nil {
		t.Fatal("borrowed readonly view ignored invalidated ancestry")
	}
	if err := d.WriteControl(ctx, "late.json", []byte("bad")); err == nil {
		t.Fatal("ancestor move-and-return refreshed original authority")
	}
	if _, err := os.Stat(filepath.Join(parent, "state", "late.json")); !os.IsNotExist(err) {
		t.Fatal("invalidated ancestor admitted write")
	}
}

func TestOwnedDirectoryIdentityBindsOriginalRoot(t *testing.T) {
	ctx := context.Background()
	parent := t.TempDir()
	var ids [2][32]byte
	for i, name := range []string{"one", "two"} {
		d, err := OpenOwnedDirectory(ctx, filepath.Join(parent, name), true)
		if err != nil {
			t.Fatal(err)
		}
		ids[i], err = d.ReadRoot().OwnedIdentity(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if ids[0] == ids[1] || ids[0] == ([32]byte{}) || ids[1] == ([32]byte{}) {
		t.Fatal("distinct owned roots merged by selector")
	}
}
