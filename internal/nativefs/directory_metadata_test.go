package nativefs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDirectoryMetadataBatchesWithoutContent(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned Linux/Windows directory")
	}
	ctx := context.Background()
	path := t.TempDir()
	for i := 0; i < 130; i++ {
		if os.WriteFile(filepath.Join(path, fmt.Sprintf("file-%03d", i)), []byte("private"), 0600) != nil {
			t.Fatal("owned metadata fixture")
		}
	}
	r, err := OpenRoot(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	d, err := r.OpenDirectoryMetadata(ctx, ".")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	seen := map[string]bool{}
	for {
		batch, err := d.Next()
		if len(batch) > 64 {
			t.Fatal("unbounded directory batch")
		}
		for _, e := range batch {
			if seen[e.Name] || e.Kind != KindRegular || e.Size != 7 || e.SHA256 != ([32]byte{}) || e.Status != StatusComplete {
				t.Fatal("invalid metadata observation")
			}
			seen[e.Name] = true
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 130 {
		t.Fatal("directory truncated", len(seen))
	}
}

func TestDirectoryMetadataRefusesMutationAndClosedRoot(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned Linux/Windows directory")
	}
	ctx := context.Background()
	path := t.TempDir()
	r, err := OpenRoot(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	d, err := r.OpenDirectoryMetadata(ctx, ".")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if os.WriteFile(filepath.Join(path, "late"), []byte("new"), 0600) != nil {
		t.Fatal("mutation fixture")
	}
	if _, err := d.Next(); err == nil || err == io.EOF {
		t.Fatal("changed directory declared complete")
	}
	d2, err := r.OpenDirectoryMetadata(ctx, ".")
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := d2.Next(); err == nil || err == io.EOF {
		t.Fatal("closed root retained enumeration authority")
	}
}
