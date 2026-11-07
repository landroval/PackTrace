//go:build linux && (amd64 || arm64)

package nativefs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPublicationMultipleOriginalExclusions(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	var paths []string
	for _, name := range []string{"target", "state", "reference", "output"} {
		path := filepath.Join(base, name)
		if e := os.Mkdir(path, 0700); e != nil {
			t.Fatal(e)
		}
		paths = append(paths, path)
	}
	target, e := OpenRoot(ctx, paths[0])
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	state, e := target.OpenExternalRoot(ctx, paths[1])
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	reference, e := target.OpenExternalRoot(ctx, paths[2])
	if e != nil {
		t.Fatal(e)
	}
	defer reference.Close()
	extra := []*Root{state, reference}
	if nested, e := state.OpenExternalRoot(ctx, paths[3]); e == nil {
		nested.Close()
		t.Fatal("publication allowance relaxed ordinary external-root admission")
	}
	for _, path := range paths[:3] {
		pub, e := OpenPublicationExcluding(ctx, target, extra, filepath.Join(path, "forbidden"))
		if e == nil {
			pub.Close()
			t.Fatal("publication entered original exclusion", path)
		}
		if _, e := os.Lstat(filepath.Join(path, "forbidden")); !os.IsNotExist(e) {
			t.Fatal("excluded output created", e)
		}
	}
	destination := filepath.Join(paths[3], "report")
	pub, e := OpenPublicationExcluding(ctx, target, extra, destination)
	if e != nil {
		t.Fatal(e)
	}
	defer pub.Close()
	for _, text := range []string{"complete ", "approved bytes"} {
		if _, e := pub.Write([]byte(text)); e != nil {
			t.Fatal(e)
		}
	}
	if e := pub.Commit(); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(destination)
	if e != nil || string(raw) != "complete approved bytes" {
		t.Fatal("wrong native artifact", string(raw), e)
	}
	// Existing external guards remain installed, live, and bound to the target.
	if state.native.external == nil || reference.native.external == nil {
		t.Fatal("source guard stripped")
	}
	if state.native.external.target != target.native || reference.native.external.target != target.native {
		t.Fatal("source anchor changed")
	}
	// An output parent can safely be a common ancestor; its own mutations must
	// refresh ALL independent proofs without dropping either source exclusion.
	ancestor, e := OpenPublicationExcluding(ctx, target, extra, filepath.Join(base, "ancestor-report"))
	if e != nil {
		t.Fatal(e)
	}
	defer ancestor.Close()
	if _, e := ancestor.Write([]byte("ancestor")); e != nil {
		t.Fatal(e)
	}
	if e := ancestor.Commit(); e != nil {
		t.Fatal(e)
	}
	if e := state.native.guard(); e != nil {
		t.Fatal("state guard invalidated", e)
	}
	if e := reference.native.guard(); e != nil {
		t.Fatal("reference guard invalidated", e)
	}
}

func TestPublicationMultipleExclusionsReplacementAndNoClobber(t *testing.T) {
	for _, moved := range []string{"target", "state", "reference", "output", "late-existing"} {
		t.Run(moved, func(t *testing.T) {
			ctx := context.Background()
			base := t.TempDir()
			paths := map[string]string{}
			for _, name := range []string{"target", "state", "reference", "output"} {
				paths[name] = filepath.Join(base, name)
				if e := os.Mkdir(paths[name], 0700); e != nil {
					t.Fatal(e)
				}
			}
			target, e := OpenRoot(ctx, paths["target"])
			if e != nil {
				t.Fatal(e)
			}
			defer target.Close()
			state, e := target.OpenExternalRoot(ctx, paths["state"])
			if e != nil {
				t.Fatal(e)
			}
			defer state.Close()
			reference, e := target.OpenExternalRoot(ctx, paths["reference"])
			if e != nil {
				t.Fatal(e)
			}
			defer reference.Close()
			destination := filepath.Join(paths["output"], "report")
			pub, e := OpenPublicationExcluding(ctx, target, []*Root{state, reference}, destination)
			if e != nil {
				t.Fatal(e)
			}
			defer pub.Close()
			if _, e := pub.Write([]byte("new")); e != nil {
				t.Fatal(e)
			}
			if moved == "late-existing" {
				if e := os.WriteFile(destination, []byte("canary"), 0600); e != nil {
					t.Fatal(e)
				}
			} else {
				path := paths[moved]
				if e := os.Rename(path, path+"-original"); e != nil {
					t.Fatal(e)
				}
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
			}
			if e := pub.Commit(); e == nil {
				t.Fatal("changed original/clobber accepted")
			}
			if moved == "late-existing" {
				raw, e := os.ReadFile(destination)
				if e != nil || string(raw) != "canary" {
					t.Fatal("clobbered existing file", e)
				}
			}
		})
	}
}

func TestPublicationExclusionAdmissionIsBounded(t *testing.T) {
	ctx := context.Background()
	target, e := OpenRoot(ctx, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	if pub, e := OpenPublicationExcluding(ctx, target, make([]*Root, maxPublicationExclusions+1), filepath.Join(t.TempDir(), "report")); e == nil {
		pub.Close()
		t.Fatal("unbounded exclusions")
	}
	if pub, e := OpenPublicationExcluding(ctx, target, []*Root{target}, filepath.Join(t.TempDir(), "report")); e == nil {
		pub.Close()
		t.Fatal("duplicate/anchor cycle")
	}
}
