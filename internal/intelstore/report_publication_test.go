package intelstore

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"packtrace/internal/nativefs"
)

// Authored capability test only: no store marker/generation or live state is
// opened. Generation admission remains the existing caller's responsibility.
func TestReportPublicationIsOnlyTargetBound(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("Linux publication-only external binding")
	}
	ctx := context.Background()
	base := t.TempDir()
	for _, name := range []string{"target", "state", "references", "output", "other"} {
		if e := os.Mkdir(filepath.Join(base, name), 0700); e != nil {
			t.Fatal(e)
		}
	}
	target, e := nativefs.OpenRoot(ctx, filepath.Join(base, "target"))
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	state, e := target.OpenExternalRoot(ctx, filepath.Join(base, "state"))
	if e != nil {
		t.Fatal(e)
	}
	store := &Store{root: state, mode: ReadOnly}
	defer store.Close()
	references, e := target.OpenExternalRoot(ctx, filepath.Join(base, "references"))
	if e != nil {
		t.Fatal(e)
	}
	defer references.Close()
	other, e := nativefs.OpenRoot(ctx, filepath.Join(base, "other"))
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	for _, path := range []string{"target", "state", "references"} {
		pub, e := store.OpenReportPublication(ctx, target, []*nativefs.Root{references}, filepath.Join(base, path, "forbidden"))
		if e == nil {
			pub.Close()
			t.Fatal("admitted forbidden publication", path)
		}
	}
	if pub, e := store.OpenReportPublication(ctx, other, nil, filepath.Join(base, "output", "wrong-target")); e == nil {
		pub.Close()
		t.Fatal("foreign target admitted")
	}
	pub, e := store.OpenReportPublication(ctx, target, []*nativefs.Root{references}, filepath.Join(base, "output", "report"))
	if e != nil {
		t.Fatal(e)
	}
	defer pub.Close()
	if _, e := pub.Write([]byte("approved")); e != nil {
		t.Fatal(e)
	}
	if e := pub.Commit(); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(base, "output", "report"))
	if e != nil || string(raw) != "approved" {
		t.Fatal("wrong artifact", e)
	}
}
