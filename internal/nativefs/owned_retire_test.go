package nativefs

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOwnedQuarantineRetainsOriginalBeforeVerifiedRemoval(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native owned removal")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "owned")
	owner, e := OpenOwnedDirectory(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	if e := owner.Mkdir(ctx, "trash"); e != nil {
		t.Fatal(e)
	}
	f, e := owner.CopyExclusive(ctx, "item", bytes.NewReader([]byte("owned-data")), 10)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	lease, e := owner.ReadRoot().OpenMetadata(ctx, "item")
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Close()
	retired, e := owner.Quarantine(ctx, lease, "trash/item")
	if e != nil {
		t.Fatal(e)
	}
	defer retired.Close()
	if _, e := os.Lstat(filepath.Join(path, "item")); !os.IsNotExist(e) {
		t.Fatal("source slot not retired", e)
	}
	data, e := os.ReadFile(filepath.Join(path, "trash/item"))
	if e != nil || string(data) != "owned-data" {
		t.Fatal("original bytes not retained", e)
	}
	if e := retired.Remove(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Lstat(filepath.Join(path, "trash/item")); !os.IsNotExist(e) {
		t.Fatal("removal not actually observed", e)
	}
}
func TestQuarantinedChangedObjectIsPreserved(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native owned removal")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "owned")
	owner, e := OpenOwnedDirectory(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	owner.Mkdir(ctx, "trash")
	f, e := owner.CopyExclusive(ctx, "item", bytes.NewReader([]byte("original")), 8)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	lease, e := owner.ReadRoot().OpenMetadata(ctx, "item")
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Close()
	retired, e := owner.Quarantine(ctx, lease, "trash/item")
	if e != nil {
		t.Fatal(e)
	}
	defer retired.Close()
	target := filepath.Join(path, "trash/item")
	if e := os.WriteFile(target, []byte("changed!"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := retired.Remove(ctx); e == nil {
		t.Fatal("changed original authorized unlink")
	}
	got, e := os.ReadFile(target)
	if e != nil || string(got) != "changed!" {
		t.Fatal("changed bytes lost", e)
	}
}
