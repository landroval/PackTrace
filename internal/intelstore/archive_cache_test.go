package intelstore

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"runtime"
	"testing"

	"packtrace/internal/nativefs"
	"packtrace/internal/testfile"
)

func TestArchiveCacheRetainsCapturedBytesButCannotHideChangedOriginalFence(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("original source capability")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "owned")
	owner, e := nativefs.OpenOwnedDirectory(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	data := bytes.Repeat([]byte("0123456789abcdef"), 2<<17)
	original, e := owner.CopyExclusive(ctx, "archive", bytes.NewReader(data), uint64(len(data)))
	if e != nil {
		t.Fatal(e)
	}
	defer original.Close()
	cache, e := newArchiveCache(ctx, original)
	if e != nil {
		t.Fatal(e)
	}
	if len(cache.buffer) > 1<<20 {
		t.Fatal("unbounded archive retention")
	}
	var out [32]byte
	if n, e := cache.ReadAt(out[:], 17); e != nil || n != 32 || !bytes.Equal(out[:], data[17:49]) {
		t.Fatal("captured bytes differ", n, e)
	}
	charged := cache.captured
	if n, e := cache.ReadAt(out[:], 33); e != nil || n != 32 || !bytes.Equal(out[:], data[33:65]) || cache.captured != charged {
		t.Fatal("cached native capture was reread/recharged", n, e)
	}
	if n, e := cache.ReadAt(out[:], (1<<20)-8); e != nil || n != 32 || !bytes.Equal(out[:], data[(1<<20)-8:(1<<20)+24]) {
		t.Fatal("cross-window capture", n, e)
	}
	if n, e := cache.ReadAt(out[:], int64(len(data))-4); n != 4 || e != io.EOF {
		t.Fatal("ReaderAt EOF lost", n, e)
	}
	if _, e := cache.ReadAt(out[:], -1); e == nil {
		t.Fatal("negative offset admitted")
	}
	before := cache.captured
	for i := 0; i < 20; i++ {
		for _, at := range []int64{17, int64(len(data)) - 32} {
			if _, e := cache.ReadAt(out[:], at); e != nil {
				t.Fatal(e)
			}
		}
	}
	if cache.captured-before > 2<<20 {
		t.Fatal("alternating ZIP central/local observations thrash the bounded capture", cache.captured-before)
	}
	file, e := testfile.OpenExisting(filepath.Join(path, "archive"), true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := file.WriteAt([]byte("changed"), 0); e != nil {
		t.Fatal(e)
	}
	if e := file.Sync(); e != nil {
		file.Close()
		t.Fatal("fixture mutation did not flush", e)
	}
	if e := file.Close(); e != nil {
		t.Fatal("fixture mutation did not close successfully", e)
	}
	if e := cache.Stable(); e == nil {
		t.Fatal("cached bytes replaced mandatory ORIGINAL source fence")
	}
}
