//go:build linux && (amd64 || arm64)

package nativefs

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) (*Root, string) {
	t.Helper()
	d := t.TempDir()
	if err := os.Mkdir(filepath.Join(d, "dir"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "dir", "a"), []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("dir", filepath.Join(d, "alias")); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRoot(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r, d
}
func TestLinuxRegularPositiveAndStable(t *testing.T) {
	r, _ := fixture(t)
	for _, name := range []string{"dir/a", "alias/a"} {
		f, err := r.OpenRegular(context.Background(), name, 3)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(f)
		if err != nil || string(b) != "abc" {
			t.Fatal(string(b), err)
		}
		if err = f.Stable(); err != nil {
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
		if err = f.Stable(); err == nil {
			t.Fatal("closed stable")
		}
	}
}
func TestLinuxFailedLeaseNeverStable(t *testing.T) {
	r, d := fixture(t)
	if f, err := r.OpenRegular(context.Background(), "dir/a", 2); err == nil || f != nil {
		t.Fatal("oversize admitted")
	}
	f, err := r.OpenRegular(context.Background(), "dir/a", 3)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = f.Stable(); err == nil {
		t.Fatal("unread content certified")
	}
	if _, err = io.ReadAll(f); err == nil {
		t.Fatal("failed lease recovered")
	}
	g, err := r.OpenRegular(context.Background(), "dir/a", 3)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if err = os.WriteFile(filepath.Join(d, "dir", "a"), []byte("abcd"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadAll(g); !errors.Is(err, ErrLimit) {
		t.Fatalf("grow: %v", err)
	}
	if err = g.Stable(); err == nil {
		t.Fatal("growth certified")
	}
}
func TestLinuxReplacementInvalidatesOriginalLease(t *testing.T) {
	r, d := fixture(t)
	f, err := r.OpenRegular(context.Background(), "dir/a", 3)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = os.Rename(filepath.Join(d, "dir", "a"), filepath.Join(d, "dir", "old")); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(d, "dir", "a"), []byte("xyz"), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	if err != nil || string(b) != "abc" {
		t.Fatalf("lost original binding: %q %v", b, err)
	}
	if err = f.Stable(); err == nil {
		t.Fatal("replacement certified")
	}
}
func TestLinuxBoundaryLinksAndCancellation(t *testing.T) {
	r, d := fixture(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "canary"), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	for n, v := range map[string]string{"escape": filepath.Join(outside, "canary"), "cycle": "cycle", "parent": "../outside"} {
		if err := os.Symlink(v, filepath.Join(d, n)); err != nil {
			t.Fatal(err)
		}
		if f, err := r.OpenRegular(context.Background(), n, 20); err == nil || f != nil {
			t.Fatalf("followed %s", n)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if f, err := r.OpenRegular(ctx, "dir/a", 3); !errors.Is(err, context.Canceled) || f != nil {
		t.Fatal(err)
	}
	if s, err := r.Snapshot(ctx, Limits{}); !errors.Is(err, context.Canceled) || s.Complete {
		t.Fatal(s, err)
	}
}
func TestLinuxSnapshotPositiveAndBounds(t *testing.T) {
	r, _ := fixture(t)
	s, err := r.Snapshot(context.Background(), Limits{})
	if err != nil || !s.Complete {
		t.Fatalf("snapshot %+v %v", s, err)
	}
	found := false
	link := false
	for _, e := range s.Entries {
		if e.Name == "dir/a" {
			found = e.Kind == KindRegular && e.Status == StatusComplete && e.Size == 3 && e.SHA256 == sha256.Sum256([]byte("abc"))
		}
		if e.Name == "alias" {
			link = e.Kind == KindLink && e.LinkTarget == "dir" && e.Status == StatusComplete
		}
	}
	if !found || !link {
		t.Fatal(s)
	}
	for _, limits := range []Limits{{FileBytes: 2}, {TotalBytes: 2}, {Entries: 1}, {Depth: 1}} {
		s, err = r.Snapshot(context.Background(), limits)
		if err == nil || s.Complete || len(s.Reasons) == 0 {
			t.Fatalf("bounds %+v %+v %v", limits, s, err)
		}
	}
}
func TestLinuxResidentIsRealAndNonzero(t *testing.T) {
	if err := PrepareProcess(); err != nil {
		t.Fatal(err)
	}
	n, err := OwnResidentBytes()
	if err != nil || n == 0 {
		t.Fatal(n, err)
	}
	// The parser must not substitute an absent query with zero or an unchecked unit.
	for _, s := range []string{"", "Rss: 4 MB\n", "Rss: -1 kB\n", "Rss: 2 kB\nRss: 2 kB\n", "Rss: 18446744073709551615 kB\n"} {
		if n, err := parseRSS(strings.NewReader(s)); err == nil || n != 0 {
			t.Fatal(s, n, err)
		}
	}
}
