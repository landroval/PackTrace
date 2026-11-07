//go:build linux && (amd64 || arm64)

package nativefs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSeparatedPlanTargetOnlyPrivateAncestry(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	for _, dir := range []string{"branch", "branch/target", "output"} {
		if e := os.Mkdir(filepath.Join(base, dir), 0700); e != nil {
			t.Fatal(e)
		}
	}
	target, e := OpenRoot(ctx, filepath.Join(base, "branch", "target"))
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	dest := filepath.Join(base, "output", "report")
	p, e := OpenPublicationPlan(ctx, target, nil, dest)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	old, e := p.Binding()
	if e != nil {
		t.Fatal(e)
	}
	initial, e := statNative(target.native.root)
	if e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(filepath.Join(base, "branch"), filepath.Join(base, "moved")); e != nil {
		t.Fatal(e)
	}
	now, e := statNative(target.native.root)
	if e != nil || now != initial {
		t.Fatal("fixture changed target leaf, not just ancestry", e)
	}
	if e := p.Check(); e == nil {
		t.Fatal("unchanged root with changed ancestry accepted")
	}
	if e := p.CheckSources(); e == nil {
		t.Fatal("source ancestry dropped")
	}
	other, e := OpenRoot(ctx, filepath.Join(base, "moved", "target"))
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	q, e := OpenPublicationPlan(ctx, other, nil, dest)
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	token, e := q.Binding()
	if e != nil || token == old {
		t.Fatal("receipt ignored private ancestry", e)
	}
	pub, e := q.Begin()
	if e != nil {
		t.Fatal(e)
	}
	if e := q.Close(); e == nil {
		t.Fatal("released live publication proofs")
	}
	if _, e := pub.Write([]byte("same original")); e != nil {
		t.Fatal(e)
	}
	if e := pub.Commit(); e != nil {
		t.Fatal(e)
	}
	pub.Close()
	if e := q.Fulfill(); e != nil {
		t.Fatal(e)
	}
	if e := q.CheckSources(); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(base, "moved", "target", "changed"), []byte("x"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := q.CheckSources(); e == nil {
		t.Fatal("fulfilled target guard dropped")
	}
}
