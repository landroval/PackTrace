package nativefs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDurabilityBatchRetains128OriginalsThenFencesBefore129(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native durability")
	}
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
	batch, e := owner.BeginDurabilityBatch(ctx, writer)
	if e != nil {
		t.Fatal(e)
	}
	defer batch.Close()
	var first *batchOriginal
	for i := 0; i < 129; i++ {
		file, e := batch.CopyExclusive(ctx, fmt.Sprintf("item-%03d", i), bytes.NewReader([]byte("actual")), 6)
		if e != nil {
			t.Fatal(e)
		}
		if i == 0 {
			first = batch.files[file]
		}
		if e := file.Close(); e != nil {
			t.Fatal(e)
		}
		want := i + 1
		if i == 128 {
			want = 1
		}
		if len(batch.files) != want || len(batch.dirs) > 272 {
			t.Fatalf("original %d: retained %d files/%d directories; want %d files, <=272 directories", i+1, len(batch.files), len(batch.dirs), want)
		}
		_, originalErr := first.file.Stat()
		if i < 128 && originalErr != nil {
			t.Fatal("caller close lost pending original", originalErr)
		}
		if i == 128 {
			// Windows Stat can report ERROR_INVALID_HANDLE after Close rather
			// than os.ErrClosed. Require unusability AND an already-closed file.
			if originalErr == nil || !errors.Is(first.file.Close(), os.ErrClosed) {
				t.Fatal("rollover did not close the successfully fenced original", originalErr)
			}
		}
	}
	if e := batch.Fence(ctx); e != nil {
		t.Fatal(e)
	}
	if len(batch.files) != 0 || len(batch.dirs) != 0 {
		t.Fatal("positive fence retained pending capabilities")
	}
}
