package nativefs

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPublicationExplicitOutsideOriginalExclusivelyPublishes(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native publication")
	}
	ctx := context.Background()
	owner, e := OpenOwnedDirectory(ctx, filepath.Join(t.TempDir(), "state"), true)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	output := filepath.Join(t.TempDir(), "owned.bundle")
	pub, e := OpenPublication(ctx, owner.ReadRoot(), output)
	if e != nil {
		t.Fatal(e)
	}
	defer pub.Close()
	if _, e := pub.Write([]byte("owned payload")); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Lstat(output); !os.IsNotExist(e) {
		t.Fatal("partial export visible as completed output", e)
	}
	if e := pub.Commit(); e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(output)
	if e != nil || string(data) != "owned payload" {
		t.Fatal("actual published bytes absent", e)
	}
}
func TestPublicationAncestorOutputStillProtectsOriginalState(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native publication")
	}
	ctx := context.Background()
	base := t.TempDir()
	cache := filepath.Join(base, "cache")
	if e := os.Mkdir(cache, 0700); e != nil {
		t.Fatal(e)
	}
	state := filepath.Join(cache, "state")
	owner, e := OpenOwnedDirectory(ctx, state, true)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	if e := owner.WriteControl(ctx, "canary", []byte("source")); e != nil {
		t.Fatal(e)
	}
	for _, dir := range []string{base, cache} {
		pub, e := OpenPublication(ctx, owner.ReadRoot(), filepath.Join(dir, "snapshot.bundle"))
		if e != nil {
			t.Fatal("safe ancestor rejected", e)
		}
		if _, e := pub.Write([]byte("outside")); e != nil {
			pub.Close()
			t.Fatal(e)
		}
		if e := pub.Commit(); e != nil {
			pub.Close()
			t.Fatal(e)
		}
		pub.Close()
		file, e := owner.ReadRoot().OpenInput(ctx, "canary", 6)
		if e != nil {
			t.Fatal("known output mutation invalidated original state", e)
		}
		file.Close()
	}
}

func TestPublicationCannotClobberOrEnterForbiddenRoot(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native publication")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state")
	owner, e := OpenOwnedDirectory(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	if pub, e := OpenPublication(ctx, owner.ReadRoot(), filepath.Join(path, "not-allowed")); e == nil {
		pub.Close()
		t.Fatal("export entered state root")
	}
	output := filepath.Join(t.TempDir(), "result")
	pub, e := OpenPublication(ctx, owner.ReadRoot(), output)
	if e != nil {
		t.Fatal(e)
	}
	defer pub.Close()
	pub.Write([]byte("new"))
	if e := os.WriteFile(output, []byte("canary"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := pub.Commit(); e == nil {
		t.Fatal("late existing output replaced")
	}
	data, e := os.ReadFile(output)
	if e != nil || string(data) != "canary" {
		t.Fatal("existing user output clobbered", e)
	}
}
