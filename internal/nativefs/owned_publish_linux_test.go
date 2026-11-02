//go:build linux && (amd64 || arm64)

package nativefs

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOwnedPublishMissingParentClosesRetainedDirectories(t *testing.T) {
	ctx := context.Background()
	d, e := OpenOwnedDirectory(ctx, filepath.Join(t.TempDir(), "state"), true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	f, e := d.CopyExclusive(ctx, "source", bytes.NewBufferString("data"), 4)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	before, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 32; i++ {
		if e := d.Publish(ctx, f, "missing/dest", false); e == nil {
			t.Fatal("missing parent admitted")
		}
	}
	after, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	if len(after) > len(before)+4 {
		t.Fatal("failed publications leaked retained directory handles", len(before), len(after))
	}
	if e := f.Stable(); e != nil {
		t.Fatal("failed publication damaged original", e)
	}
}
