//go:build windows && amd64

package nativefs

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"unsafe"
)

// Compile-time amd64 public ABI layout checks; these are NOT NT runtime tests.
var (
	_ [48]byte = [unsafe.Sizeof(winAttributes{})]byte{}
	_ [16]byte = [unsafe.Sizeof(winUnicode{})]byte{}
	_ [16]byte = [unsafe.Sizeof(winIOStatus{})]byte{}
	_ [8]byte  = [unsafe.Offsetof(winAttributes{}.root)]byte{}
	_ [16]byte = [unsafe.Offsetof(winAttributes{}.name)]byte{}
	_ [24]byte = [unsafe.Offsetof(winAttributes{}.attributes)]byte{}
	_ [8]byte  = [unsafe.Offsetof(winUnicode{}.buffer)]byte{}
	_ [8]byte  = [unsafe.Offsetof(winIOStatus{}.information)]byte{}
)

// Native contracts: compile-only until a separately authorized Windows run.
// No environment-based success/skip: an unsupported fixture filesystem fails.
func TestWindowsOwnResidentAcceptsCurrentProcessPseudoHandle(t *testing.T) {
	// GetCurrentProcess is the valid pseudo-handle -1, not an OpenProcess
	// failure. Losing self observation must fail this native contract.
	n, e := OwnResidentBytes()
	if e != nil || n == 0 {
		t.Fatal(n, e)
	}
}

func winFixture(t *testing.T) (string, *Root) {
	t.Helper()
	p := t.TempDir()
	r, e := OpenRoot(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close() })
	return p, r
}
func winRead(t *testing.T, r *Root, n, want string) {
	t.Helper()
	f, e := r.OpenRegular(context.Background(), n, 1024)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	b, e := io.ReadAll(f)
	if e != nil || string(b) != want {
		t.Fatal(string(b), e)
	}
	if e = f.Stable(); e != nil {
		t.Fatal(e)
	}
}
func TestWindowsOrdinaryAndSelectedPurpose(t *testing.T) {
	p, r := winFixture(t)
	ctx := context.Background()
	if e := os.Mkdir(filepath.Join(p, "pkg"), 0700); e != nil {
		t.Fatal(e)
	}
	for n, s := range map[string]string{"pkg/file": "ok", "secret": "outside"} {
		if e := os.WriteFile(filepath.Join(p, n), []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
	}
	winRead(t, r, "pkg/file", "ok")
	meta, e := r.Metadata(ctx, Limits{})
	if e != nil || !meta.Complete || meta.ReadBytes != 0 {
		t.Fatal(meta, e)
	}
	sub, e := r.OpenSubroot(ctx, "pkg")
	if e != nil {
		t.Fatal(e)
	}
	defer sub.Close()
	snap, e := sub.SnapshotPruned(ctx, Limits{}, nil)
	if e != nil || !snap.Complete || snap.ReadBytes != 2 || len(snap.Entries) != 1 {
		t.Fatal(snap, e)
	}
	if e := os.WriteFile(filepath.Join(p, "pkg", "added"), []byte("new"), 0600); e != nil {
		t.Fatal(e)
	}
	sub.Close()
	sub, e = r.OpenSubroot(ctx, "pkg")
	if e != nil {
		t.Fatal(e)
	}
	defer sub.Close()
	snap, e = sub.SnapshotPruned(ctx, Limits{}, nil)
	if e != nil || len(snap.Entries) != 2 || snap.ReadBytes != 5 {
		t.Fatal(snap, e)
	}
}
func TestWindowsNestedSlotRegularFileStillHasContent(t *testing.T) {
	p, r := winFixture(t)
	if e := os.Mkdir(filepath.Join(p, "pkg"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(p, "pkg", "nested"), []byte("added"), 0600); e != nil {
		t.Fatal(e)
	}
	sub, e := r.OpenSubroot(context.Background(), "pkg")
	if e != nil {
		t.Fatal(e)
	}
	defer sub.Close()
	snap, e := sub.SnapshotPruned(context.Background(), Limits{}, func(e Entry) bool { return e.Name == "nested" && e.Kind == KindDirectory })
	if e != nil || !snap.Complete || snap.ReadBytes != 5 || len(snap.Entries) != 1 || snap.Entries[0].Kind != KindRegular {
		t.Fatal(snap, e)
	}
}

func TestWindowsExternalAuthority(t *testing.T) {
	p, r := winFixture(t)
	ctx := context.Background()
	extPath := t.TempDir()
	if e := os.WriteFile(filepath.Join(extPath, "policy"), []byte("trusted"), 0600); e != nil {
		t.Fatal(e)
	}
	ext, e := r.OpenExternalRoot(ctx, extPath)
	if e != nil {
		t.Fatal(e)
	}
	defer ext.Close()
	winRead(t, ext, "policy", "trusted")
	f, e := ext.OpenInput(ctx, "policy", 1024)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = os.Link(filepath.Join(extPath, "policy"), filepath.Join(p, "alias")); e != nil {
		t.Fatal(e)
	}
	var b [1]byte
	if n, e := f.Read(b[:]); n != 0 || e == nil {
		t.Fatal("new hardlink permitted content", n, e)
	}
	if f, e := ext.OpenInput(ctx, "policy", 1024); e == nil {
		f.Close()
		t.Fatal("hardlink admitted")
	}
	if x, e := r.OpenExternalRoot(ctx, p); e == nil {
		x.Close()
		t.Fatal("self admitted")
	}
	if x, e := r.OpenExternalRoot(ctx, filepath.Dir(p)); e == nil {
		x.Close()
		t.Fatal("ancestor admitted")
	}
}
func TestWindowsSwapAndClosedAnchor(t *testing.T) {
	p, r := winFixture(t)
	ctx := context.Background()
	file := filepath.Join(p, "file")
	if e := os.WriteFile(file, []byte("old"), 0600); e != nil {
		t.Fatal(e)
	}
	f, e := r.OpenRegular(ctx, "file", 10)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = os.Rename(file, filepath.Join(p, "retained")); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(file, []byte("new"), 0600); e != nil {
		t.Fatal(e)
	}
	io.ReadAll(f)
	if f.Stable() == nil {
		t.Fatal("replacement binding accepted")
	}
	if e = os.Mkdir(filepath.Join(p, "pkg"), 0700); e != nil {
		t.Fatal(e)
	}
	sub, e := r.OpenSubroot(ctx, "pkg")
	if e != nil {
		t.Fatal(e)
	}
	defer sub.Close()
	r.Close()
	if _, e = sub.Metadata(ctx, Limits{}); e == nil {
		t.Fatal("closed anchor accepted")
	}
}
func TestWindowsPruneHardlinkAndSharedBudget(t *testing.T) {
	p, r := winFixture(t)
	ctx := context.Background()
	if e := os.MkdirAll(filepath.Join(p, "pkg", "nested"), 0700); e != nil {
		t.Fatal(e)
	}
	for n, s := range map[string]string{"pkg/file": "ok", "pkg/nested/secret": "never selected", "outside": "alias"} {
		if e := os.WriteFile(filepath.Join(p, n), []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Link(filepath.Join(p, "outside"), filepath.Join(p, "pkg", "alias")); e != nil {
		t.Fatal(e)
	}
	sub, e := r.OpenSubroot(ctx, "pkg")
	if e != nil {
		t.Fatal(e)
	}
	defer sub.Close()
	if f, e := sub.OpenRegular(ctx, "alias", 100); e == nil {
		f.Close()
		t.Fatal("selected hardlink content admitted")
	}
	snap, _ := sub.SnapshotPruned(ctx, Limits{}, func(e Entry) bool { return e.Name == "nested" && e.Kind == KindDirectory || e.Name == "alias" })
	if !snap.Complete || snap.ReadBytes != 2 || len(snap.Entries) != 3 {
		t.Fatal(snap)
	}
	r.mu.Lock()
	r.consumed = maxTotal - 2
	r.mu.Unlock()
	f, e := sub.OpenRegular(ctx, "file", 10)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	b := make([]byte, 2)
	if n, e := f.Read(b); n != 2 || e != nil {
		t.Fatal(n, e)
	}
	next, e := sub.OpenRegular(ctx, "file", 10)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	if n, e := next.Read(b); n != 0 || e != ErrLimit {
		t.Fatal("subroot reset shared budget", n, e)
	}
}

func TestWindowsExternalAncestorRelocation(t *testing.T) {
	_, r := winFixture(t)
	ctx := context.Background()
	base := t.TempDir()
	controller := filepath.Join(base, "controller")
	if e := os.Mkdir(controller, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(controller, "policy"), []byte("trusted"), 0600); e != nil {
		t.Fatal(e)
	}
	ext, e := r.OpenExternalRoot(ctx, controller)
	if e != nil {
		t.Fatal(e)
	}
	defer ext.Close()
	f, e := ext.OpenInput(ctx, "policy", 100)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	moved := filepath.Join(base, "moved")
	if e = os.Rename(controller, moved); e != nil {
		t.Fatal(e)
	}
	var b [1]byte
	if n, e := f.Read(b[:]); n != 0 || e == nil {
		t.Fatal("moved authority admitted content", n, e)
	}
	if e = os.Rename(moved, controller); e != nil {
		t.Fatal(e)
	}
	if f, e := ext.OpenInput(ctx, "policy", 100); e == nil {
		f.Close()
		t.Fatal("observable move-return admitted authority")
	}
}

func TestWindowsRejectNamespaceBeforeLookup(t *testing.T) {
	_, r := winFixture(t)
	for _, n := range []string{"NUL", "CON", "file:secret", `\Device\NamedPipe\x`, "a/../b", "trailing."} {
		if f, e := r.OpenRegular(context.Background(), n, 10); e == nil {
			f.Close()
			t.Fatal(n)
		}
	}
}
