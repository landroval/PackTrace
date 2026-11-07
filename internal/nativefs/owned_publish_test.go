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

func TestOwnedPublicationKeepsOriginalAndRefusesClobber(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned native publication")
	}
	ctx := context.Background()
	d, e := OpenOwnedDirectory(ctx, filepath.Join(t.TempDir(), "state"), true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	for _, name := range []string{"staging", "objects"} {
		if e := d.Mkdir(ctx, name); e != nil {
			t.Fatal(e)
		}
	}
	a, e := d.CopyExclusive(ctx, "staging/a", bytes.NewBufferString("first"), 5)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	if e := d.Publish(ctx, a, "objects/one", false); e != nil {
		t.Fatal(e)
	}
	if e := a.Stable(); e != nil {
		t.Fatal("original file lost after publication", e)
	}
	b, e := d.CopyExclusive(ctx, "staging/b", bytes.NewBufferString("other"), 5)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	if e := d.Publish(ctx, b, "objects/one", false); !errors.Is(e, ErrExists) {
		t.Fatal("clobber allowed", e)
	}
	if e := b.Stable(); e != nil {
		t.Fatal("failed clobber lost staging", e)
	}
	f, e := d.ReadRoot().OpenInput(ctx, "objects/one", 5)
	if e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(f)
	stable := f.Stable()
	closeErr := f.Close()
	if e != nil || stable != nil || closeErr != nil || string(got) != "first" {
		t.Fatal("published original changed")
	}
	if e := d.Publish(ctx, b, "objects/one", true); e != nil {
		t.Fatal("explicit replacement failed", e)
	}
	if e := a.Stable(); e == nil {
		t.Fatal("replaced old slot remained bound")
	}
	// Replacement must not obtain success by closing the old capability.
	// Its slot is no longer bound, but its original bytes remain readable.
	original := make([]byte, 5)
	if n, e := a.file.ReadAt(original, 0); e != nil || n != len(original) || string(original) != "first" {
		t.Fatal("replacement discarded the retained original", n, e)
	}
	if e := b.Stable(); e != nil {
		t.Fatal(e)
	}
}
