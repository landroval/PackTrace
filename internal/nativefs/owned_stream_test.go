package nativefs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOwnedStreamNestedOriginalAndNoOverwrite(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned native stream")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state")
	d, e := OpenOwnedDirectory(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	for _, name := range []string{"staging", "staging/one"} {
		if e := d.Mkdir(ctx, name); e != nil {
			t.Fatal(e)
		}
	}
	data := bytes.Repeat([]byte("abc"), 30000)
	f, e := d.CopyExclusive(ctx, "staging/one/data", bytes.NewReader(data), uint64(len(data)))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if f.Size() != int64(len(data)) || f.Stable() != nil {
		t.Fatal("stream not sealed")
	}
	var got [7]byte
	n, e := f.ReadAt(got[:], 65534)
	if n != 7 || e != nil || !bytes.Equal(got[:], data[65534:65541]) {
		t.Fatal("original random read", n, e)
	}
	if other, e := d.CopyExclusive(ctx, "staging/one/data", bytes.NewReader([]byte("bad")), 3); e == nil || other != nil {
		t.Fatal("existing slot overwritten")
	}
	if e := f.Stable(); e != nil {
		t.Fatal(e)
	}
}

type ownedFailReader struct{ once bool }

func (r *ownedFailReader) Read(p []byte) (int, error) {
	if r.once {
		return 0, io.ErrUnexpectedEOF
	}
	r.once = true
	return copy(p, "partial"), io.ErrUnexpectedEOF
}

func TestOwnedStreamRetainsFailedBytesAndRefusesEscape(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned native stream")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state")
	d, e := OpenOwnedDirectory(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	for _, name := range []string{"../outside", "a/../b", "/absolute", "a\\b"} {
		if e := d.Mkdir(ctx, name); e == nil {
			t.Fatal("unsafe directory admitted")
		}
	}
	f, e := d.CopyExclusive(ctx, "partial", &ownedFailReader{}, 16)
	if e == nil || f == nil || f.Size() != 7 {
		t.Fatal("lost failed native bytes", e)
	}
	defer f.Close()
	if e := f.Stable(); e == nil {
		t.Fatal("failed stream became valid")
	}
	raw, e := readOwnedFixture(filepath.Join(path, "partial"))
	if e != nil || string(raw) != "partial" {
		t.Fatal("partial bytes discarded")
	}
	over, e := d.CopyExclusive(ctx, "over", bytes.NewReader([]byte("12345")), 4)
	if !errors.Is(e, ErrLimit) || over == nil || over.Size() > 4 {
		t.Fatal("bound bypass", e)
	}
	defer over.Close()
}
