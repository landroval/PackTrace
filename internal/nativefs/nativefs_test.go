package nativefs

import (
	"context"
	"errors"
	"io"
	"testing"
)

// Removing validation, EOF/error retention, or lower-only bounds must fail these
// tests. Fixture acquisition tests are separate from platform qualification.
func TestFixedAPIAndPrivateZeroCapabilities(t *testing.T) {
	var r Root
	if f, err := r.OpenRegular(context.Background(), "a", 1); err == nil || f != nil {
		t.Fatal("zero root granted capability")
	}
	if s, err := r.Snapshot(context.Background(), Limits{}); err == nil || s.Complete {
		t.Fatal("zero root completed")
	}
	var f File
	if _, err := f.Read(make([]byte, 1)); err == nil {
		t.Fatal("zero file readable")
	}
	if err := f.Stable(); err == nil {
		t.Fatal("zero file stable")
	}
	if err := r.Close(); err == nil {
		t.Fatal("zero root close succeeded")
	}
	if err := f.Close(); err == nil {
		t.Fatal("zero file close succeeded")
	}
}

func TestLimitNormalization(t *testing.T) {
	got, err := normalizeLimits(Limits{})
	if err != nil || got != (Limits{256 << 20, 16 << 30, 100000, 128}) {
		t.Fatalf("defaults: %+v %v", got, err)
	}
	for _, l := range []Limits{{FileBytes: -1}, {TotalBytes: -1}, {Entries: -1}, {Depth: -1}, {FileBytes: 256<<20 + 1}, {TotalBytes: 16<<30 + 1}, {Entries: 100001}, {Depth: 129}} {
		if _, err := normalizeLimits(l); !errors.Is(err, ErrLimit) {
			t.Fatalf("accepted %+v: %v", l, err)
		}
	}
	if got, err = normalizeLimits(Limits{1, 2, 3, 4}); err != nil || got != (Limits{1, 2, 3, 4}) {
		t.Fatal(got, err)
	}
}

func TestRelativeNameBoundary(t *testing.T) {
	for _, s := range []string{"", "/x", "../x", "a/../x", "a//b", "a/./b", "a/", "a\x00b", "a\\b"} {
		if validRelative(s) == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	for _, s := range []string{"a", "a/b", ".hidden"} {
		if err := validRelative(s); err != nil {
			t.Fatal(s, err)
		}
	}
}

var _ io.ReadCloser = (*File)(nil)
var _ func(context.Context, string) (*Root, error) = OpenRoot
var _ func() error = PrepareProcess
var _ func() (uint64, error) = OwnResidentBytes
