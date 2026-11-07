package intelstore

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"packtrace/internal/nativefs"
)

// Capability fixture only: no marker, generation, key or MAC inspection.
func TestReportPlanOriginalPrivateStore(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("Linux plan mechanism")
	}
	ctx := context.Background()
	base := t.TempDir()
	for _, n := range []string{"target", "state", "reference", "output", "foreign"} {
		if e := os.Mkdir(filepath.Join(base, n), 0700); e != nil {
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
	ref, e := target.OpenExternalRoot(ctx, filepath.Join(base, "reference"))
	if e != nil {
		t.Fatal(e)
	}
	defer ref.Close()
	dest := filepath.Join(base, "output", "report")
	p, e := store.OpenReportPlan(ctx, target, []*nativefs.Root{ref}, dest)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	entries, e := os.ReadDir(filepath.Dir(dest))
	if e != nil || len(entries) != 0 {
		t.Fatal("capture wrote", e)
	}
	foreign, e := nativefs.OpenRoot(ctx, filepath.Join(base, "foreign"))
	if e != nil {
		t.Fatal(e)
	}
	defer foreign.Close()
	if q, e := store.OpenReportPlan(ctx, foreign, nil, dest); e == nil {
		q.Close()
		t.Fatal("foreign target")
	}
	if q, e := store.OpenReportPlan(ctx, target, make([]*nativefs.Root, 8), dest); e == nil {
		q.Close()
		t.Fatal("unbounded refs")
	}
	wrong := &Store{root: state, mode: CreateOwned}
	if q, e := wrong.OpenReportPlan(ctx, target, nil, dest); e == nil {
		q.Close()
		t.Fatal("wrong mode")
	}
	pub, e := p.Begin()
	if e != nil {
		t.Fatal(e)
	}
	if _, e := pub.Write([]byte("report plan")); e != nil {
		t.Fatal(e)
	}
	if e := pub.Commit(); e != nil {
		t.Fatal(e)
	}
	if e := pub.Close(); e != nil {
		t.Fatal(e)
	}
	if e := p.Fulfill(); e != nil {
		t.Fatal(e)
	}
	if e := p.CheckSources(); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(dest)
	if e != nil || string(raw) != "report plan" {
		t.Fatal("artifact", e)
	}
	// Source-only checks still reject changed source after fulfillment.
	if e := os.WriteFile(filepath.Join(base, "state", "changed"), []byte("x"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := p.CheckSources(); e == nil {
		t.Fatal("changed store accepted after fulfillment")
	}
	store.Close()
	if q, e := store.OpenReportPlan(ctx, target, nil, dest); e == nil {
		q.Close()
		t.Fatal("closed store")
	}
}
