//go:build linux && (amd64 || arm64)

package nativefs

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func externalFixture(t *testing.T) (*Root, *Root, string, string) {
	t.Helper()
	base := t.TempDir()
	target := filepath.Join(base, "target")
	prepared := filepath.Join(base, "parent/prepared")
	for _, d := range []string{target, prepared} {
		if e := os.MkdirAll(d, 0700); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(filepath.Join(prepared, "policy"), []byte("external inert"), 0600); e != nil {
		t.Fatal(e)
	}
	r, e := OpenRoot(context.Background(), target)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close() })
	ext, e := r.OpenExternalRoot(context.Background(), prepared)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ext.Close() })
	return r, ext, target, prepared
}
func TestExternalLeaseRefusesNewHardlinkBeforeRead(t *testing.T) {
	_, ext, target, prepared := externalFixture(t)
	f, e := ext.OpenRegular(context.Background(), "policy", 100)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = os.Link(filepath.Join(prepared, "policy"), filepath.Join(target, "mutable")); e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(f)
	if e == nil || len(b) != 0 {
		t.Fatalf("new alias content read: %q %v", b, e)
	}
	if f.Stable() == nil {
		t.Fatal("aliased lease certified")
	}
}
func TestExternalLeaseRefusesAncestorMoveAndReturn(t *testing.T) {
	_, ext, target, prepared := externalFixture(t)
	f, e := ext.OpenRegular(context.Background(), "policy", 100)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	parent := filepath.Dir(prepared)
	moved := filepath.Join(target, "moved")
	if e = os.Rename(parent, moved); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(moved, parent); e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(f)
	if e == nil || len(b) != 0 {
		t.Fatalf("relocated ancestry content read: %q %v", b, e)
	}
	if f.Stable() == nil {
		t.Fatal("moved ancestry certified")
	}
}

// A real concurrent alias churn runs after selection. The first observed
// mutation invalidates the retained lease even when the link count returns to
// one; a later read must not recover into success. All actors are joined.
func TestExternalLeaseConcurrentAliasChurn(t *testing.T) {
	_, ext, target, prepared := externalFixture(t)
	f, e := ext.OpenRegular(context.Background(), "policy", 100)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	started := make(chan error, 1)
	done := make(chan error, 1)
	go func() {
		alias := filepath.Join(target, "alias")
		for i := 0; i < 64; i++ {
			if e := os.Link(filepath.Join(prepared, "policy"), alias); e != nil {
				if i == 0 {
					started <- e
				}
				done <- e
				return
			}
			if i == 0 {
				started <- nil
			}
			if e := os.Remove(alias); e != nil {
				done <- e
				return
			}
		}
		done <- nil
	}()
	startErr := <-started
	b, readErr := io.ReadAll(f)
	joinErr := <-done
	if startErr != nil || joinErr != nil {
		t.Fatalf("owned actor: %v %v", startErr, joinErr)
	}
	if readErr == nil || len(b) != 0 || f.Stable() == nil {
		t.Fatalf("alias race admitted content: %q %v", b, readErr)
	}
}

func TestExternalRootPositiveAndClosedAnchor(t *testing.T) {
	r, ext, _, _ := externalFixture(t)
	f, e := ext.OpenRegular(context.Background(), "policy", 100)
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(f)
	if e != nil || string(b) != "external inert" || f.Stable() != nil {
		t.Fatalf("external positive %q %v", b, e)
	}
	f.Close()
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if f, e = ext.OpenRegular(context.Background(), "policy", 100); e == nil || f != nil {
		t.Fatal("closed anchor admitted")
	}
}
func TestSubrootPurposeAndSharedBudget(t *testing.T) {
	r, d := fixture(t)
	secret := filepath.Join(d, "unrelated")
	if e := os.WriteFile(secret, []byte("outside purpose"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("../unrelated", filepath.Join(d, "dir/symlink")); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(secret, filepath.Join(d, "dir/hardlink")); e != nil {
		t.Fatal(e)
	}
	sub, e := r.OpenSubroot(context.Background(), "dir")
	if e != nil {
		t.Fatal(e)
	}
	defer sub.Close()
	for _, name := range []string{"symlink", "hardlink", "../unrelated"} {
		if f, e := sub.OpenRegular(context.Background(), name, 100); e == nil || f != nil {
			t.Fatal("scope expanded", name)
		}
	}
	if s, e := r.OpenSubroot(context.Background(), "alias"); e == nil || s != nil {
		t.Fatal("symlink minted physical owner")
	}
	r.consumed = maxTotal - 2
	f, e := sub.OpenRegular(context.Background(), "a", 3)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = io.ReadAll(f); !errors.Is(e, ErrLimit) {
		t.Fatal("subroot bypassed original read budget", e)
	}
}
func TestSnapshotEnumerationAndContentAreSeparate(t *testing.T) {
	r, d := fixture(t)
	if e := os.Symlink("../../absent", filepath.Join(d, "dir/bad")); e != nil {
		t.Fatal(e)
	}
	sub, e := r.OpenSubroot(context.Background(), "dir")
	if e != nil {
		t.Fatal(e)
	}
	defer sub.Close()
	snap, e := sub.Snapshot(context.Background(), Limits{})
	if e == nil || snap.Complete || !snap.Enumerated || snap.ReadBytes != 3 {
		t.Fatalf("namespace/content receipt wrong: %+v %v", snap, e)
	}
	snap, e = sub.Snapshot(context.Background(), Limits{Entries: 1})
	if e == nil || snap.Complete || snap.Enumerated {
		t.Fatalf("entry limit granted enumeration: %+v %v", snap, e)
	}
}
