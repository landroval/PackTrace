//go:build linux && (amd64 || arm64)

package nativefs

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type planFixture struct {
	base                     string
	target, state, reference *Root
}

func newPlanFixture(t *testing.T) *planFixture {
	t.Helper()
	base := t.TempDir()
	for _, s := range []string{"target", "state", "reference", "output"} {
		if e := os.Mkdir(filepath.Join(base, s), 0700); e != nil {
			t.Fatal(e)
		}
	}
	return openPlanFixture(t, base)
}
func openPlanFixture(t *testing.T, base string) *planFixture {
	t.Helper()
	ctx := context.Background()
	target, e := OpenRoot(ctx, filepath.Join(base, "target"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { target.Close() })
	state, e := target.OpenExternalRoot(ctx, filepath.Join(base, "state"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { state.Close() })
	ref, e := target.OpenExternalRoot(ctx, filepath.Join(base, "reference"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ref.Close() })
	return &planFixture{base, target, state, ref}
}
func (f *planFixture) plan(t *testing.T, dest string) *PublicationPlan {
	t.Helper()
	p, e := OpenPublicationPlan(context.Background(), f.target, []*Root{f.state, f.reference}, dest)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := p.Close(); e != nil {
			t.Error(e)
		}
	})
	return p
}
func TestSeparatedPlanCaptureAndChildPublication(t *testing.T) {
	if os.Getenv("PACKTRACE_PLAN_TEST_CHILD") == "1" {
		f := openPlanFixture(t, os.Getenv("PACKTRACE_PLAN_TEST_BASE"))
		p := f.plan(t, filepath.Join(f.base, "output", "report"))
		token, e := p.Binding()
		if e != nil || token != os.Getenv("PACKTRACE_PLAN_TEST_BINDING") {
			t.Fatal("cross-process binding mismatch", e)
		}
		pub, e := p.Begin()
		if e != nil {
			t.Fatal(e)
		}
		defer pub.Close()
		if _, e := pub.Write([]byte("approved child bytes")); e != nil {
			t.Fatal(e)
		}
		if e := pub.Commit(); e != nil {
			t.Fatal(e)
		}
		if e := pub.Close(); e != nil {
			t.Fatal(e)
		}
		if e := p.CheckSources(); e != nil {
			t.Fatal(e)
		}
		return
	}
	f := newPlanFixture(t)
	dest := filepath.Join(f.base, "output", "report")
	before, e := os.Stat(filepath.Dir(dest))
	if e != nil {
		t.Fatal(e)
	}
	p := f.plan(t, dest)
	token, e := p.Binding()
	if e != nil {
		t.Fatal(e)
	}
	other := openPlanFixture(t, f.base)
	q := other.plan(t, dest)
	token2, e := q.Binding()
	if e != nil || token != token2 {
		t.Fatal("independent binding", e)
	}
	after, e := os.Stat(filepath.Dir(dest))
	if e != nil || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("capture mutated parent", e)
	}
	entries, e := os.ReadDir(filepath.Dir(dest))
	if e != nil || len(entries) != 0 {
		t.Fatal("capture created output", e)
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(exe, "-test.run=^TestSeparatedPlanCaptureAndChildPublication$", "-test.count=1")
	cmd.Env = append(os.Environ(), "PACKTRACE_PLAN_TEST_CHILD=1", "PACKTRACE_PLAN_TEST_BASE="+f.base, "PACKTRACE_PLAN_TEST_BINDING="+token)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("child: %s %v", out, e)
	}
	if e := p.Check(); e == nil {
		t.Fatal("stale output epoch accepted")
	}
	if e := p.Fulfill(); e != nil {
		t.Fatal(e)
	}
	if e := p.CheckSources(); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Begin(); e == nil {
		t.Fatal("fulfilled plan reopened")
	}
	raw, e := os.ReadFile(dest)
	if e != nil || string(raw) != "approved child bytes" {
		t.Fatal("artifact", e)
	}
	// Fresh plans preserve historical no-clobber and retain uncertain temp bytes.
	r := f.plan(t, dest)
	pub, e := r.Begin()
	if e != nil {
		t.Fatal(e)
	}
	if _, e := pub.Write([]byte("must not replace")); e != nil {
		t.Fatal(e)
	}
	if e := pub.Commit(); e == nil {
		t.Fatal("clobber")
	}
	pub.Close()
	raw, e = os.ReadFile(dest)
	if e != nil || string(raw) != "approved child bytes" {
		t.Fatal("clobbered", e)
	}
	if e := p.CheckSources(); e != nil {
		t.Fatal(e)
	}
}
func TestSeparatedPlanChangedOriginals(t *testing.T) {
	for _, name := range []string{"target", "state", "reference", "output", "source-epoch", "branch-epoch"} {
		t.Run(name, func(t *testing.T) {
			f := newPlanFixture(t)
			// Add a private output ancestor so branch-epoch is not a shared ancestor.
			if e := os.Mkdir(filepath.Join(f.base, "output", "private"), 0700); e != nil {
				t.Fatal(e)
			}
			dest := filepath.Join(f.base, "output", "private", "report")
			p := f.plan(t, dest)
			old, e := p.Binding()
			if e != nil {
				t.Fatal(e)
			}
			switch name {
			case "source-epoch":
				if e := os.WriteFile(filepath.Join(f.base, "target", "added"), []byte("x"), 0600); e != nil {
					t.Fatal(e)
				}
			case "branch-epoch":
				if e := os.WriteFile(filepath.Join(f.base, "output", "sibling"), []byte("x"), 0600); e != nil {
					t.Fatal(e)
				}
			default:
				path := filepath.Join(f.base, name)
				if e := os.Rename(path, path+"-moved"); e != nil {
					t.Fatal(e)
				}
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
				if name == "output" {
					if e := os.Mkdir(filepath.Join(path, "private"), 0700); e != nil {
						t.Fatal(e)
					}
				}
			}
			if e := p.Check(); e == nil {
				t.Fatal("changed original admitted")
			}
			if _, e := p.Begin(); e == nil {
				t.Fatal("changed original began")
			}
			// A recreated plan cannot reproduce the pre-acquisition native receipt.
			fresh := openPlanFixture(t, f.base)
			q := fresh.plan(t, dest)
			now, e := q.Binding()
			if e != nil || now == old {
				t.Fatal("changed native receipt not distinguished", e)
			}
			if name == "target" || name == "state" || name == "reference" || name == "source-epoch" {
				if e := p.CheckSources(); e == nil {
					t.Fatal("source-only guard dropped")
				}
			}
		})
	}
}
func TestSeparatedPlanAdmissionAndClose(t *testing.T) {
	f := newPlanFixture(t)
	ctx := context.Background()
	for _, dir := range []string{f.base, filepath.Join(f.base, "target"), filepath.Join(f.base, "state"), filepath.Join(f.base, "reference")} {
		if p, e := OpenPublicationPlan(ctx, f.target, []*Root{f.state, f.reference}, filepath.Join(dir, "report")); e == nil {
			p.Close()
			t.Fatal("ancestor/common-parent admitted")
		}
	}
	foreign, e := OpenRoot(ctx, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer foreign.Close()
	if p, e := OpenPublicationPlan(ctx, foreign, []*Root{f.state}, filepath.Join(f.base, "output", "report")); e == nil {
		p.Close()
		t.Fatal("foreign target")
	}
	p := f.plan(t, filepath.Join(f.base, "output", "report"))
	if e := p.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Binding(); e == nil {
		t.Fatal("closed binding")
	}
	if e := p.CheckSources(); e == nil {
		t.Fatal("closed sources")
	}
	q := f.plan(t, filepath.Join(f.base, "output", "report"))
	f.reference.Close()
	if _, e := q.Begin(); e == nil {
		t.Fatal("closed original")
	}
}
