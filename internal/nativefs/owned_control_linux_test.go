//go:build linux && (amd64 || arm64)

package nativefs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOwnedControlBindingRejectsSameBytesReplacement(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state")
	d, err := OpenOwnedDirectory(ctx, path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.WriteControl(ctx, "control.json", []byte("owned")); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(path, "control.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := ownedControlBinding(d.root.native, f, "control.json", 5); err != nil {
		t.Fatal("original binding unavailable", err)
	}
	if os.Rename(filepath.Join(path, "control.json"), filepath.Join(path, "old.json")) != nil || os.WriteFile(filepath.Join(path, "control.json"), []byte("owned"), 0600) != nil {
		t.Fatal("owned replacement fixture")
	}
	if err := ownedControlBinding(d.root.native, f, "control.json", 5); err == nil {
		t.Fatal("same bytes substituted for original created object")
	}
}
