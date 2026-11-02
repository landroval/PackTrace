package intelstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"packtrace/internal/nativefs"
)

func TestStoreCopiedMarkerDoesNotGrantNativeOwnership(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned Linux/Windows store")
	}
	ctx := context.Background()
	parent := t.TempDir()
	a, b := filepath.Join(parent, "a"), filepath.Join(parent, "b")
	for _, p := range []string{a, b} {
		s, err := Open(ctx, p, CreateOwned)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(filepath.Join(a, "store.json"))
	if err != nil || os.WriteFile(filepath.Join(b, "store.json"), data, 0600) != nil {
		t.Fatal("owned marker copy")
	}
	if s, err := Open(ctx, b, ReadOnly); !errors.Is(err, ErrBinding) || s != nil {
		t.Fatal("copied marker granted ownership", err)
	}
}

func TestStoreExternalSeparationAndClosedTarget(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned Linux/Windows store")
	}
	ctx := context.Background()
	parent := t.TempDir()
	targetPath, state := filepath.Join(parent, "target"), filepath.Join(parent, "state")
	if os.Mkdir(targetPath, 0700) != nil {
		t.Fatal("target fixture")
	}
	s, err := Open(ctx, state, CreateOwned)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	target, err := nativefs.OpenRoot(ctx, targetPath)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	s, err = OpenExternal(ctx, target, state)
	if err != nil {
		t.Fatal("external store unavailable", err)
	}
	defer s.Close()
	if _, err := OpenExternal(ctx, target, targetPath); err == nil {
		t.Fatal("target admitted as state")
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.root.OwnedIdentity(ctx); err == nil {
		t.Fatal("closed target retained external authority")
	}
}

func TestStoreRejectsTargetContainedState(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned Linux/Windows store")
	}
	ctx := context.Background()
	parent := t.TempDir()
	state := filepath.Join(parent, "state")
	s, err := Open(ctx, state, CreateOwned)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	target, err := nativefs.OpenRoot(ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if _, err := OpenExternal(ctx, target, state); err == nil {
		t.Fatal("contained state admitted")
	}
}
